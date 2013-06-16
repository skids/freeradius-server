/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file rlm_ddds.c
 * @brief Implementation of draft-ietf-radext-dynamic-discovery
 *
 * @copyright 2013  Brian S. Julin <bjulin@clarku.edu>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include "rbtree.h"
#include <unbound.h>

/* Mutable state for a DDDS discovery */
typedef struct ddds_state {
	int in_flight;		/* How many DNS replies we are expecting. */
	time_t last_launch;	/* Used to detect missing responses       */
	time_t last_used;	/* Used when deciding whether to expire.  */
	time_t top_time;	/* Handles TTL of "well-known" NAPTR      */

	/*
	 * 	These arrays handle NAPTR RRs retrieved from DNS.  Entries
	 *	form a tree which is searched depth-first.  We only store
	 *	the limbs which we are currently searching -- when
	 *	backtracking the old limbs are deleted.  We only store
	 *	records which match our service criteria, sorted.
	 *
	 *	CNAME/DNAME aliases for NAPTR queries are also kept here,
	 *	and are treated as if they were a single-item limb.
	 *
	 *	The first branch starts at index 0, but the branch is
	 *	sorted backwards.  This allows us to insert a synthetic
	 *	NAPTR record at index 0 representing the fallback SRV
	 *	lookup specified by draft-ietf-radext-dynamic-discovery.
	 *
	 * TODO: dynamically allocate at least the DNS owner names,
	 * because they can chew up a goodly amount of RAM.  Perhaps
	 * rearrange tables into structs (there are arguments pro/con both
	 * ways per data locality.)  That can all wait until after
	 * a robust test suite is in effect.
	 */
#define MAX_NAPTRS 32	/* Limit on number of NAPTRs on all followed limbs */

	/* Set if this slot is used */
#define NAPTR_USED (1)
	/* Set if this entry is the first item in a sorted list */
#define NAPTR_FORE (2)
	/* Set if this entry is the parent to the next level of the tree */
#define NAPTR_DIVE (4)
	/* Set if this entry is terminal; assume A/AAAA unless NAPTR_SRV */
#define NAPTR_TERM (8)
	/* Set if this entry is a SRV */
#define NAPTR_SRV (16 | NAPTR_TERM)
	/* Set if this entry is synthetic */
#define NAPTR_SYNTH (32 | NAPTR_TERM | NAPTR_USED)
	int nflags[MAX_NAPTRS];       /* See above */
	time_t ntimes[MAX_NAPTRS];    /* For TTL handling */
	char nnames[MAX_NAPTRS][256]; /* Null terminated, max 253 */

	/*
	 *	If a SRV is arrived at through a CNAME/DNAME alias, this keeps
	 *	track of the alias canonical name.  Also used with CNAMEs for
	 *	A/AAAA records if our SRV record is synthetic.  Note that other
	 *	than through synthetic SRVs, A/AAAA records cannot be arrived
	 *	at through aliases, it is explicitly banned in RFC 2782.
	 */
	char srv_cname[256];

	/*
	 *	These arrays handle the SRV RRset retrieved for the currently
	 *	followed SRV record.  This could be a synthesized entry in the
	 *	case of a NAPTR "a" flag, the rfc2782 fallback SRV A target,
	 *	or when the instance specifies direct A record lookup.
	 */
#define MAX_SRVS 16
	int sports[MAX_SRVS];	/* per RFC2782, but -1 means empty */
	int sprios[MAX_SRVS];	/* per RFC2782, but -1 synthetic */
	int sweights[MAX_SRVS]; /* per RFC2782 */
	char snames[MAX_SRVS][256]; /* Null terminated, max 253 */

	time_t atimes[MAX_SRVS];/* TTL expirations for child A RRsets */
	int aidxs[MAX_SRVS];	/* Index into as, below */
	int alens[MAX_SRVS];	/* Consecutive entries in as, -1 => pending */

	/* As above, for AAAA records. */
	time_t aaaatimes[MAX_SRVS];
	int aaaaidxs[MAX_SRVS];
	int aaaalens[MAX_SRVS];

	/* Storage for A/AAAA addresses */
#define MAX_A_RRS 64
	struct in_addr as[MAX_A_RRS];

#define MAX_AAAA_RRS 32
	struct in6_addr aaaas[MAX_AAAA_RRS];

} ddds_state_t;

/*
 *	The immutable area used as a key in the rbtree.  Right now, this is
 *	just the result of the well-known rule, a.k.a. the realm name for
 *	most use cases.  It could also allow per-query service-name selection
 *	in the future.
 */
typedef struct ddds_query {
	char owner[254];	/* The realm name we are looking up */
} ddds_query_t;


/*
 *	Main structure for managing one DDNS search.  We keep an rbtree of
 * 	them.  Each structure has an immutable area used as a unique key, and
 *	a mutable area that may be modified when the rbtree lock is held
 *	(and hence the item may not be deleted.)  The rbtree code never
 *	touches the mutable area, so this should be safe.
 */
typedef struct ddds_top {
	ddds_query_t query; /* Immutable.  Used by rbtree code as key. */
	ddds_state_t state; /* Mutable.  Results and interim state.    */
} ddds_top_t;

/* Convenience functions */
static void nuke_as(ddds_top_t *top, int idx, int len)
{
	memset(&top->state.as[idx], 0, sizeof(top->state.as[0]) * len);
}

static void nuke_aaaas(ddds_top_t *top, int idx, int len)
{
	memset(&top->state.aaaas[idx], 0, sizeof(top->state.aaaas[0]) * len);
}

/*
 *	Glue callbacks for storing ddds_top_t in an rbtree
 */
static int ddds_top_compare_query (void const * one, void const * two)
{
	ddds_top_t const *a = one;
	ddds_top_t const *b = two;

	return memcmp(&a->query, &b->query, sizeof(ddds_query_t));
}

static void ddds_top_free (void *data)
{
	talloc_free(data);
}

/*
 *      Structure for module configuration
 */
typedef struct rlm_ddds_t {
	/* DO NOT MOVE THESE TWO MEMBERS.  HACKERY IN PROGRESS. */
	char *unbound;		/* name2 of unbound listener to use. */
	struct ub_ctx* ubctx;	/* context of that unbound listener. */

	rbtree_t *tops;		/* All our searches and results */
	char *name2;		/* We need to know our own name */

	/* Options */

        char const *wkr_xlat;
	char *srv_proto;
	char *srv_service;
	char *naptr_proto;
	char *naptr_service;
	int naptr_port;
	int must_dnssec;
	int want_v4;
	int want_v6;
	int want_naptr;
	int want_srv;
	int fallback;
	int negative_ttl;
        int min_ttl;
        int max_ttl;
	int expiry_ttl;
	int deadbeat_ttl;

	/* for now, for debugging. */
	pthread_t pthread;

} rlm_ddds_t;

/*
 *	These structures are used as a callback contexts where we have only
 *	one pointer to play with.
 */
struct tuple_inst_top {
	rlm_ddds_t *inst;
	ddds_top_t *top;
	struct ub_result fake_result;	/* explained in ub_ask */
};

struct tuple_inst_ubresult {
	rlm_ddds_t *inst;
	int err;
	struct ub_result *result;
};


/*
 *      A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER mod_config[] = {
  	{"wkr_xlat", PW_TYPE_STRING_PTR,
	 offsetof(rlm_ddds_t, wkr_xlat), NULL, "%{tolower:%{idn:%{Realm}}}" },
	{"unbound", PW_TYPE_STRING_PTR,
	 offsetof(rlm_ddds_t, unbound), NULL, "unbound" },
	{"must_dnssec", PW_TYPE_BOOLEAN,
	 offsetof(rlm_ddds_t, must_dnssec), NULL, "no" },
	{"srv_service", PW_TYPE_STRING_PTR,
	 offsetof(rlm_ddds_t, srv_service), NULL, "radiustls" },
	{"srv_proto", PW_TYPE_STRING_PTR,
	 offsetof(rlm_ddds_t, srv_proto), NULL, "tcp" },
	{"naptr_service", PW_TYPE_STRING_PTR,
	 offsetof(rlm_ddds_t, naptr_service), NULL, "aaa+auth" },
	{"naptr_proto", PW_TYPE_STRING_PTR,
	 offsetof(rlm_ddds_t, naptr_proto), NULL, "radius.tls" },
	{"naptr_port", PW_TYPE_INTEGER,
	 offsetof(rlm_ddds_t, naptr_port), NULL, "2083" },
	{"ipv4", PW_TYPE_BOOLEAN, offsetof(rlm_ddds_t, want_v4), NULL, "yes" },
	{"ipv6", PW_TYPE_BOOLEAN, offsetof(rlm_ddds_t, want_v6), NULL, "no" },
	{"naptr", PW_TYPE_BOOLEAN,
	 offsetof(rlm_ddds_t, want_naptr), NULL, "yes" },
	{"srv", PW_TYPE_BOOLEAN,
	 offsetof(rlm_ddds_t, want_srv), NULL, "yes" },
	{"fallback", PW_TYPE_INTEGER,
	 offsetof(rlm_ddds_t, fallback), NULL, "0" },
	{"negative_ttl", PW_TYPE_INTEGER,
	 offsetof(rlm_ddds_t, negative_ttl), NULL, "300" },
	{"min_ttl", PW_TYPE_INTEGER,
	 offsetof(rlm_ddds_t, min_ttl), NULL, "60" },
	{"max_ttl", PW_TYPE_INTEGER,
	 offsetof(rlm_ddds_t, max_ttl), NULL, "3600" },
	{"expiry_ttl", PW_TYPE_INTEGER,
	 offsetof(rlm_ddds_t, expiry_ttl), NULL, "21600" },
	{"deadbeat_ttl", PW_TYPE_INTEGER,
	 offsetof(rlm_ddds_t, deadbeat_ttl), NULL, "180" },

	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	Convert labels as found in an NAPTR or SRV to a hostname
 *	Result is written to memory pointed to by "out" which must
 *	be > 253 bytes long.
 */
static int rrlabels_tostr(char *rr, char *out) {
	int offset = 0;

	/*
	 *	TODO: verify that unbound results always use this label format,
	 *	and review the specs on this label format for nuances.
	 */
	while (1) {
		int count;

		count = *((unsigned char *)(rr));
		if (count > 63 || offset + count + 1 > 253) {
			*out = '\0';
			return -1;
		}
		if (count == 0) {
			break;
		}
		rr++;
		memcpy(out + offset, rr, count);
		rr += count;
		offset += count;
		*(out + offset++) = '.';
	}
	*(out + offset) = '\0';
	return offset + 1;
}

static void ub_cb(void *my_arg, int err, struct ub_result *result);

/* Wrapper for ub_resolve_async that passes a threadsafe tuple. */
static int ub_ask(rlm_ddds_t *inst, char *name, int t, int c,
		  ddds_top_t *top, ub_callback_t cb, int* id)
{
	struct tuple_inst_top *cbctx;
	int res;

	/*
	 *	The inst cannot be carried in the top because the inst
	 *	is needed to find the rbtree to search for and lock the
	 *	top to prevent it from being deleted while we work on it.
	 *
	 *	So we need to send a tuple.  And, it cannot reside on
	 *	the stack, because threads.
	 *
	 *	Furthermore, if the callback is called with "err" set,
	 *	"result" will be NULL.
	 *
	 *	Not providing a ub_result structure during such a failure
	 *	means we have to redundantly remember exactly the query that
	 *	caused the failure.  Even for OOM things, unbound should
	 *	really alloc its minimum needs to perform a callback with a
	 *	result structure and error out at the ub_resolve* callsite
	 *	instead if it cannot.
	 */
	cbctx = talloc_zero(inst, struct tuple_inst_top);
	if (!cbctx) {
	oom:
		ERROR("Out of memory sending DNS query");
		return -1;
	}
	cbctx->top = top;
	cbctx->inst = inst;
	cbctx->fake_result.qname = talloc_strdup(cbctx, name);
	if (!cbctx->fake_result.qname) {
		talloc_free(cbctx);
		goto oom;
	}
	cbctx->fake_result.qtype = t;
	cbctx->fake_result.qclass = c;
	cbctx->fake_result.ttl = inst->negative_ttl;

	switch (t) {
	case 1:
		DEBUG2("Asking DNS for IPv4 addresses of '%s'", name);
		break;
	case 28:
		DEBUG2("Asking DNS for IPv6 addresses of '%s'", name);
		break;
	case 33:
		DEBUG2("Asking DNS for any SRV records in '%s'", name);
		break;
	case 35:
		DEBUG2("Asking DNS for any NAPTR records in '%s'", name);
		break;
	default:
		ERROR("Spurious record type %i (owner '%s')", t, name);
		return -1;
	}

	res = ub_resolve_async(inst->ubctx, name, t, c, cbctx, cb, id);
	if (!res) {
		/* The free of cbctx is the responsibility of ub_cb now. */
		struct timeval now;
		gettimeofday(&now, NULL);
		top->state.in_flight++;
		top->state.last_launch = now.tv_sec;

		return 0;
	}
	DEBUG("Problem launching DNS query: %s", ub_strerror(res));
	talloc_free(cbctx);
	return -1;
}

/*
 *	When a discovery becomes invalid due to well-known or intermediate RR
 *	expiry, and the fix is not already in progress, it comes here.  This
 *	launches a DNS query for the RR at the last cursor.
 *
 *	Note this is only for expired SRV and NAPTR records, and not for
 *	the well-known NAPTR.
 *
 *	This assumes that plumb_naptr has already processed the top to
 *	place the cursors where they should be.
 */
static int top_triage(rlm_ddds_t *inst, ddds_top_t *top)
{
	int idx, dive;

	for (dive = -1, idx = 0; idx < MAX_NAPTRS; idx++) {
		if (!(top->state.nflags[idx] & NAPTR_USED)) {
			break;
		}
		if (top->state.nflags[idx] & NAPTR_DIVE) {
			dive = idx;
		}
	}
	if (dive < 0) {
		ub_ask(inst, top->query.owner, 35, 1, top, ub_cb, NULL);
	}
	else if (!(top->state.nflags[dive] & NAPTR_TERM)) {
		ub_ask(inst, top->state.nnames[dive], 35, 1, top, ub_cb, NULL);
	}
	else if ((top->state.nflags[dive] & NAPTR_SRV) == NAPTR_SRV) {
		ub_ask(inst, top->state.nnames[dive], 33, 1, top, ub_cb, NULL);
	}
	else {
		/* Should not happen.  Should be handled as synth SRV. */
		ERROR("FIXME: Found expired NAPTR with 'a' flag.");
	}
	return 0;
}

/*
 *	Baseline the state of a DDDS search.
 */
static void top_reset(rlm_ddds_t *inst, ddds_top_t *top, int used)
{
	struct timeval now;
	int del = 0;

	gettimeofday(&now, NULL);

	top->state.top_time = now.tv_sec + inst->max_ttl - 1;
	if (used) {
		top->state.last_used = now.tv_sec;
	}
	top->state.last_launch = now.tv_sec;

	if ((inst->want_srv || !inst->want_naptr) &&
	    (253 > 4 + strlen(inst->srv_proto) + strlen(inst->srv_service))) {

		/*
		 * Place a synthetic NAPTR RR at the top of the result.
		 * It represents the backup default SRV lookup.
		 */
		top->state.ntimes[0] = now.tv_sec + inst->max_ttl;
		top->state.nflags[0] = NAPTR_SYNTH | NAPTR_SRV;
		top->state.nnames[0][0] = '\0';
		strcat(top->state.nnames[0], "_");
		strcat(top->state.nnames[0], inst->srv_service);
		strcat(top->state.nnames[0], "._");
		strcat(top->state.nnames[0], inst->srv_proto);
		strcat(top->state.nnames[0], ".");
		strcat(top->state.nnames[0], top->query.owner);

		/*
		 * If we are not doing S-NAPTR, but we are doing SRV,
		 * mark this entry as descended, and top-of-limb.
		 */
		if (!inst->want_naptr) {
			top->state.nflags[0] |= NAPTR_DIVE | NAPTR_FORE;
		}
		del = 1;
	}
	for (; del < MAX_NAPTRS; del++) {
		top->state.nflags[del] = 0;
	}

	del = 0;
	if (!inst->want_srv && !inst->want_naptr) {
		/* Add a permanent synthetic SRV RR */
		top->state.sprios[0] = -1;
		top->state.sweights[0] = -1;
		top->state.sports[0] = inst->fallback;
		strcpy(top->state.snames[0], top->query.owner);
		top->state.alens[0] = -1;
		top->state.aidxs[0] = -1;
		top->state.aaaalens[0] = -1;
		top->state.aaaaidxs[0] = -1;
		del++;
	}
	/* Initialize the SRV records as incomplete/unused */
	for (; del < MAX_SRVS; del++) {
		top->state.sprios[del] = 0;
		top->state.sports[del] = -1;
		top->state.alens[del] = -1;
		top->state.aidxs[del] = -1;
		top->state.aaaalens[del] = -1;
		top->state.aaaaidxs[del] = -1;
	}
	/* Clear out the storage space for A/AAAA values */
	nuke_as(top, 0, MAX_A_RRS);
	nuke_aaaas(top, 0, MAX_AAAA_RRS);
}

/*
 * NOTE: Unqualified section numbers in this comment block refer to
 * draft-ietf-radext-dynamic-discovery-06.
 *
 * Section 2 lacks a fully explicit definition for RFC 3958 section
 * 3.1.2.  Further, section 2.3.4 is open to multiple interpretations,
 * and RFC 3403 Section 3 leaves certain details to inference.
 *
 * We make some best guesses as follows:
 *
 * 1) Section 2.3.5. mandates the termination of the discovery
 *    process after three seconds, with fallback to static configuration.
 *    If said static configuration is to reject the request, however,
 *    in many environments the client will automatically retry some
 *    seconds or minutes later.  It is therefore useful to continue
 *    the algorithm in the hopes that a positive result may be obtained
 *    before that time, allowing followup requests from the client
 *    to succeed promptly.  We presume this is acceptable behavior, as
 *    long as requests that wait for 3 seconds are always routed through
 *    the static configuration for as long as no positive result is available.
 *
 * 2) Specifications are not clear as to how to proceed if TTLs,
 *    either positive or negative, expire during the execution of
 *    the algorithm due to DNS delays; Section 2.3.4 only specifies that
 *    they apply when considering the re-use of results for additional
 *    user sessions.  RFC3403 Section 3 does specify that records
 *    that are "relied upon" will cause a restart of the algorithm
 *    if their TTL has expired during a backtrack, but says nothing
 *    of initial descent.  We check TTLs during initial descent in addition
 *    to backtracks.  Also, while it is not explicitly stated in RFC3403
 *    Section 3 that a negative result which has caused a previous skip
 *    of a branch of the NAPTR tree is "relied upon", we assume that
 *    this is the case since the algorithm would have otherwise
 *    descended and might have terminated in the skipped branch.
 *
 * 3) Because of the potential for temporal loops to form in the
 *    multi-stage discovery algorithm, we assume it is reasonable to
 *    damp unreasonably short TTL values, both positive and negative,
 *    by applying a minimum TTL override.  The justification for this
 *    is because strategies that rely on low or zero TTL to load balance
 *    are superseded in applications where SRV and/or roundrobin selection
 *    between multiple A/AAAA records are properly supported.  Worth note,
 *    an expired draft, draft-ietf-speermint-srv-naptr-use, suggests that
 *    SRV and NAPTR TTLs be kept relatively high.  We rely on minimum
 *    TTL overrides for DNS records as well as a minimum TTL for negative
 *    "host-caching" of subordinate SERVFAIL results which did not
 *    "terminate the algorithm" and so are not covered in 2.3.5.
 *
 * 4) Since restarting the algorithm "from the top" after a TTL expiry
 *    yields the same result due to DNS caching as rolling the algorithm
 *    back to the most significant expired entry, we assume we are OK
 *    to do so rather than re-querying the same values out of DNS caches.
 */

/*
 *	Find the first unused NAPTR slot, validating TTLs as we go.
 *
 *	Returns: The index of the first unused NAPTR slot or -2.
 *
 *	In the latter case one or more TTLs have expired and the query
 *	that was passed in is not one which would refresh the most
 *	"relied upon" expired TTL.  This means the query needs to go
 *	to top_triage so new DNS traffic can be launched.
 *
 *	Here is how this works with synthetic RRs
 *
 *      1) In the case of a synthetic NAPTR RR, nothing unusual
 *	happens: These are always on the first limb and the
 *	synthetic NAPTR RR will be replaced when top_time expires.
 *
 *	2) In the case of a synthetic SRV RR that was auto-created by
 *	descent into an "a" NAPTR RR, the synthetic SRV RR is created
 *	with a TTL that will guarantee that the parent NAPTR expires
 *	first, and it will simply be created again if and when that
 *	RR is descended in the renewed parent NAPTR.
 *
 *      3) In the case of a synthetic SRV RR caused by fallback SRV
 *	lookup after a real SRV lookup fails, the SRV RR will inherit
 *	the negative TTL of the failing SRV response.  When that
 *	expires, the original SRV will be tried again.
 *
 *	4) In the case of a synthetic SRV placed when both SRV and
 *	NAPTR lookups are disabled, this is just a combination of
 *	2) and 3) above.
 */
static int plumb_naptr(rlm_ddds_t *inst, ddds_top_t *top, int type, char const *owner)
{
	int idx, tidx, lidx, checkttl;
	int *flags = top->state.nflags;

	struct timeval now;
	gettimeofday(&now, NULL);

	/*
	 *	Check the well-known NAPTR for expiry.
	 */
	if (top->state.top_time < now.tv_sec) {
		top_reset(inst, top, 0);

		/* Are we loading a new top NAPTR right now? */
		if (type == 35 && !strcmp(owner, top->query.owner)) {
			DEBUG2("Top NAPTR renewing for '%s'", owner);
			return ((flags[0] & NAPTR_SYNTH) == NAPTR_SYNTH);
		}

		if (inst->want_naptr) {
			DEBUG2("Top NAPTR expired for '%s'", top->query.owner);
			return -2;
		}
		else if (inst->want_srv) {
			DEBUG2("Simulated parent expiry of SRV '%s' for '%s'",
			       top->state.nnames[0], top->query.owner);
			return -2;
		}
	}

	for (checkttl = idx = 0; idx < MAX_NAPTRS; idx++) {
		if (!(flags[idx] & NAPTR_USED)) {
			break;
		}
		if (flags[idx] & NAPTR_DIVE) {
			checkttl = 1;
		}
		if (checkttl && top->state.ntimes[idx] < now.tv_sec) {
			flags[idx] &= ~NAPTR_DIVE;
			goto rollback;
		}
		if (flags[idx] & NAPTR_FORE) {
			checkttl = 0;
		}
	}
	return idx;

 rollback:

	/* Find the start of the limb */
	lidx = idx;
	while(!(flags[lidx] & NAPTR_FORE) && lidx < MAX_NAPTRS) {
		lidx++;
	}
	rad_assert(lidx < MAX_NAPTRS);

	/* Find the first expired RR on this limb */
	tidx = lidx;
	while(top->state.ntimes[tidx] > now.tv_sec) {
		tidx--;
	}
	rad_assert(tidx >= idx);
	flags[tidx] |= NAPTR_DIVE;

	/* Clean out all entries that depended on the expired RR. */
	while(++lidx < MAX_NAPTRS) {
		flags[lidx] = 0;
	}

#if 1
	/* TODO: delete this. */
	do {
	  int cnt;
	  time_t *times = top->state.ntimes;
	  DEBUG("ROLLED BACK:");
	  for (cnt = 0; cnt < MAX_NAPTRS; cnt++) {
	    DEBUG("NAPTR:\t%x\t%i\t%s", flags[cnt], (int)times[cnt],
		  top->state.nnames[cnt]);
	  }
	} while (0);
#endif

	/* If we are currently loading this RR, proceed normally. */
	if (type && !strcmp(owner, top->state.nnames[tidx]) &&
	    ((type == 35 && !(flags[tidx] & NAPTR_TERM)) ||
	     (type == 33 && ((flags[tidx] & NAPTR_SRV) == NAPTR_SRV)))) {
		return ++tidx;
	}
	DEBUG2("Intermediate RR '%s' expired for DDDS of '%s'",
	       top->state.nnames[tidx], top->query.owner);
	return -2;
}

static time_t clamp_ttl(rlm_ddds_t *inst, time_t ttl)
{
	if (inst->max_ttl < ttl) {
		return (time_t)inst->max_ttl;
	}
	if (ttl < inst->min_ttl) {
		return (time_t)inst->min_ttl;
	}
	return ttl;
}

/*	Process A/AAAA results	*/
static int do_as(rlm_ddds_t *inst, ddds_top_t *top, struct ub_result *ub, int bad)
{
	int idx, cnt, aidx, nidx, ri;
	unsigned char *rr;
	time_t *atimes = top->state.atimes;
	time_t *aaaatimes = top->state.aaaatimes;
	int *alens = top->state.alens;
	int *aaaalens = top->state.aaaalens;
	int *aidxs = top->state.aidxs;
	int *aaaaidxs = top->state.aaaaidxs;
	time_t ttl;
	int j, k, n;

	struct timeval now;
	gettimeofday(&now, NULL);

	ttl = clamp_ttl(inst, ub->ttl);

	/* Check the NAPTR tree for NAPTR/SRV timeouts.	*/
        nidx = plumb_naptr(inst, top, ub->qtype, ub->qname);
	if (nidx < 0) {
		return nidx;
	}

	/* Find our parent SRV parent NAPTR */
	while (--nidx) {
		if (top->state.nflags[nidx] & NAPTR_DIVE) {
			break;
		}
	}
	rad_assert(nidx >= 0);

	/*
	 *	Re-launch queries for any expired A/AAAA results,
	 *      but not for the same RR as we have in the result.
	 */
	for (idx = 0; (idx < MAX_SRVS
		      && top->state.sports[idx] != -1); idx++) {

		if (inst->want_v4 && atimes[idx] < now.tv_sec
		    && alens[idx] >= 0
		    && (ub->qtype != 1
			|| strcmp(top->query.owner, top->state.snames[idx]))) {

			DEBUG2("SRV '%s' child A '%s' timeout for '%s'",
			       top->state.nnames[nidx],
			       top->state.snames[idx],
			       top->query.owner);

			/* Clear expired addresses */
			if (alens[idx] > 0) {
				rad_assert(aidxs[idx] > -1);
				nuke_as(top, aidxs[idx], alens[idx]);
			}

			/* Mark as pending */
			alens[idx] = -1;
			aidxs[idx] = -1;

			/* Send a new query */
			ub_ask(inst, top->state.snames[idx],
			       1, 1, top, ub_cb, NULL);
		}

		if (inst->want_v6 && aaaatimes[idx] < now.tv_sec
		    && aaaalens[idx] >= 0
		    && (ub->qtype != 28
			|| strcmp(top->query.owner,top->state.snames[idx]))) {

			DEBUG2("SRV '%s' child AAAA '%s' timeout for '%s'",
			       top->state.nnames[nidx],
			       top->state.snames[idx],
			       top->query.owner);

			/* Clear expired addresses */
			if (aaaalens[idx] > 0) {
				rad_assert(aaaaidxs[idx] > -1);
				nuke_aaaas(top, aaaaidxs[idx], aaaalens[idx]);
			}

			/* Mark as pending */
			aaaalens[idx] = -1;
			top->state.aaaaidxs[idx] = -1;

			/* Send a new query */
			ub_ask(inst, top->state.snames[idx],
			       28, 1, top, ub_cb, NULL);
		}
	}

	/* Deal with aliased results. */
	if (ub->canonname) {
		/* Is this a real SRV or synthetic/fallback? */
		if (top->state.sprios[0] == -1
		    && !strcmp(ub->qname, top->state.snames[0])) {
			/* Synthetic: pretend the cname was for the SRV. */
			strcpy(top->state.srv_cname, ub->canonname);
		}
		else {
			/* Enforce RFC2782: SRV RRs cannot point to aliases */
			WDEBUG("Bad SRV RR '%s' of '%s' points to alias '%s'",
			       ub->qname, top->query.owner, ub->canonname);
			bad = 1;
			goto pedigree;
		}
	}

	/* Consolidate the A records to fill in gaps left by expiry. */
	aidx = 0;
 again:
	for (idx = 0; idx < MAX_SRVS; idx++) {
		if (top->state.sports[idx] == -1) {
			break;
		}
		if (aidxs[idx] == aidx) {
			aidx += alens[idx];
			goto again;
		}
	}
	/* No SRV claims this index.  Find the next claimed one. */
	for (j = 0; j < MAX_SRVS; j++) {
		if (top->state.sports[j] == -1 || aidxs[j] < 0) {
			continue;
		}
		if (aidxs[j] > aidx) break;
	}
	if (j >= MAX_SRVS) {
		/* Rest of the array is unclaimed.  Make sure it is clear. */
		nuke_as(top, aidx, MAX_A_RRS - aidx);
	}
	else {
		k = aidxs[j];
		for (; j < MAX_SRVS; j++) {
			if (top->state.sports[j] == -1) {
				break;
			}
			if (aidx < aidxs[j] && aidxs[j] < k) {
				k = aidxs[j];
			}
		}
		n = k - aidx;
		/* Close the gap in the array of addresses */
		memmove(&top->state.as[aidx], &top->state.as[k],
			sizeof(top->state.as[0]) * (MAX_A_RRS - k));
		nuke_as(top, aidx + MAX_A_RRS - k, k - aidx);
		/* Adjust the links. */
		for (j = 0; j < MAX_SRVS; j++) {
			if (top->state.sports[j] == -1) {
				break;
			}
			if (aidxs[j] > aidx) {
				aidxs[j] -= n;
			}
		}
		goto again;
	}

	/* Consolidate the AAAA records to fill in gaps left by expiry. */
	aidx = 0;
aaaagain:
        for (idx = 0; idx < MAX_SRVS; idx++) {
		if (top->state.sports[idx] == -1) {
			break;
		}
		if (aaaaidxs[idx] == aidx) {
			aidx += aaaalens[idx];
			goto aaaagain;
		}
	}
	/* No SRV claims this index.  Find the next claimed one. */
	for (j = 0; j < MAX_SRVS; j++) {
		if (top->state.sports[j] == -1 || aaaaidxs[j] < 0) {
			continue;
		}
		if (aaaaidxs[j] > aidx) break;
	}
	if (j >= MAX_SRVS) {
		/* Rest of the array is unclaimed.  Make sure it is clear. */
		nuke_aaaas(top, aidx, MAX_AAAA_RRS - aidx);
	}
	else {
		k = aaaaidxs[j];
		for (; j < MAX_SRVS; j++) {
			if (top->state.sports[j] == -1) {
				break;
			}
			if (aidx < aaaaidxs[j] && aaaaidxs[j] < k) {
				k = aaaaidxs[j];
			}
		}
		n = k - aidx;
		/* Close the gap in the array of addresses */
		memmove(&top->state.aaaas[aidx], &top->state.aaaas[k],
			sizeof(top->state.aaaas[0]) * (MAX_AAAA_RRS - k));
		nuke_aaaas(top, aidx + MAX_AAAA_RRS - k, k - aidx);
		/* Adjust the links. */
		for (j = 0; j < MAX_SRVS; j++) {
			if (top->state.sports[j] == -1) {
				break;
			}
			if (aaaaidxs[j] > aidx) {
				aaaaidxs[j] -= n;
			}
		}
		goto aaaagain;
	}

 pedigree:
	/* Find a matching SRV.  Assumes idx is one past the last used SRV. */
	while(--idx >= 0) {
		if (strcmp(top->state.snames[idx], ub->qname)) {
			continue;
		}
		if (!bad &&
		    ((alens[idx] > 0 && ub->qtype == 1) ||
		     (aaaalens[idx] > 0 && ub->qtype == 28))) {
			DEBUG2("Already knew addresses of '%s'", ub->qname);
			return 0;
		}
		break;
	}
	/* The response was for something we do not need anymore. */
	if (idx < 0) {
		DEBUG("Orphaned A/AAAA RRset for %s ignored", ub->qname);
		return 0;
	}

	if (!bad) {
		goto good;
	}

 bad:
	/*
	 *	Install just a TTL with no addresses, remove pending mark from
	 *	entries. Note there can be multiple SRVs referencing the same
	 *	addresses.
	 *
	 *	The idx should already be at the matching SRV closest to the
	 *	bottom.
	 */
	while (idx >= 0) {
		if (!strcmp(top->state.snames[idx], ub->qname)) {
			if (ub->qtype == 1) {
				if (alens[idx] > 0) {
					rad_assert(aidxs[idx] > -1);
					nuke_as(top, aidxs[idx], alens[idx]);
				}
				atimes[idx] = now.tv_sec + ttl;
				alens[idx] = 0;
				aidxs[idx] = -1;
			}
			if (ub->qtype == 28) {
				if (aaaalens[idx] > 0) {
					rad_assert(aaaaidxs[idx] > -1);
					nuke_aaaas(top, aaaaidxs[idx],
						   aaaalens[idx]);
				}
				aaaatimes[idx] = now.tv_sec + ttl;
				aaaalens[idx] = 0;
				aaaaidxs[idx] = -1;
			}
		}
		idx--;
	}

	/* TODO: remove this, label, and dump code. */
	goto debugdump;

	return 0;

 good:
	/* The RRset is wanted, so find a place to store it */
	for (aidx = 0; 1; aidx++) {
		if (ub->qtype == 1) {
			if (aidx > MAX_A_RRS ||
			    top->state.as[aidx].s_addr == INADDR_ANY) {
				break;
			}
		}
		else if (ub->qtype == 28) {
			if (aidx > MAX_AAAA_RRS ||
			    IN6_IS_ADDR_UNSPECIFIED(&top->state.aaaas[aidx])) {
		       		break;
			}
		}
		else {
			/* Should not happen, but infinite loops evil. */
			break;
		}
	}

	/* Store it, being careful not to run off the end of the array */
	for (cnt = ri = 0; (rr = (unsigned char *)ub->data[ri]); ri++){
		if (ub->qtype == 1) {
			if (aidx + cnt >= MAX_A_RRS) {
				WDEBUG("Too many A RRs for '%s' of '%s'",
				       ub->qname, top->query.owner);
				goto bad;
			}
			/* TODO: other checks such as this */
			if (!(*(rr) | *(rr+1) | *(rr+2) | *(rr+3))) {
				WDEBUG("A RR '%s' of '%s' yields anycast",
				       ub->qname, top->query.owner);
				goto bad;
			}
			/*
			 *	TODO: ignore eponymic addresses.
			 *	Could be done by lb code instead.
			 */
			memcpy(&top->state.as[aidx + cnt], rr,
			       sizeof(struct in_addr));
		}
		if (ub->qtype == 28) {
			if (aidx + cnt >= MAX_AAAA_RRS) {
				WDEBUG("Too many AAAA RRs for '%s' of '%s'",
				       ub->qname, top->query.owner);
				goto bad;
			}
			/* TODO: clean this up */
			if (!(*(rr) | *(rr+1) | *(rr+2) | *(rr+3) |
			      *(rr+4) | *(rr+5) | *(rr+6) | *(rr+7) |
			      *(rr+8) | *(rr+9) | *(rr+10) | *(rr+11) |
			      *(rr+12) | *(rr+13) | *(rr+14) | *(rr+15))) {
				WDEBUG("AAAA RR '%s' of '%s' yields anycast",
				       ub->qname, top->query.owner);
				goto bad;
			}
			/* TODO: checks as above and v6 specific */
			memcpy(&top->state.aaaas[aidx + cnt], rr,
			       sizeof(struct in6_addr));
		}
		cnt++;
	}

	/* Link the current SRV and any other matching SRVs to the result. */
	while(idx >= 0) {
		if (strcmp(top->state.snames[idx], ub->qname)) {
			idx--;
			continue;
		}
		if (ub->qtype == 1) {
			if (cnt) {
				top->state.aidxs[idx] = aidx;
			}
			top->state.alens[idx] = cnt;
			top->state.atimes[idx] = now.tv_sec + ttl;
		}
		if (ub->qtype == 28) {
			if (cnt) {
				top->state.aaaaidxs[idx] = aidx;
			}
			top->state.aaaalens[idx] = cnt;
			top->state.aaaatimes[idx] = now.tv_sec + ttl;
		}
		idx--;
	}

	/* TODO: remove this and above goto. */
 debugdump:

#if 0
	do {
		int i, j;
		for (i = 0; i < MAX_SRVS; i++) {
		  if (top->state.sports[i] == -1) { break; }
		  DEBUG("SRV[%i]\t%i\t%i\t%s:%i",i,top->state.sprios[i],
			top->state.sweights[i],
			top->state.snames[i], top->state.sports[i]);
		  for (j = 0; j < top->state.alens[i]; j++) {
		    DEBUG("A: %x", (uint32_t)top->state.as[top->state.aidxs[i] + j].s_addr);
		  }
		  for (j = 0; j < top->state.aaaalens[i]; j++) {
		    DEBUG("A: %x:%x:%x:%x",
		      top->state.aaaas[top->state.aidxs[i] + j].s6_addr32[0],
		      top->state.aaaas[top->state.aidxs[i] + j].s6_addr32[1],
		      top->state.aaaas[top->state.aidxs[i] + j].s6_addr32[2],
		      top->state.aaaas[top->state.aidxs[i] + j].s6_addr32[3]
			  );
		  }
		}
	} while(0);
#endif
#if 0
	do {
	  int i;
	  for (i = 0; i < MAX_A_RRS; i += 8) {
	    DEBUG("A: %x %x %x %x %x %x %x %x",
		  (uint32_t)top->state.as[i].s_addr,
		  (uint32_t)top->state.as[i+1].s_addr,
		  (uint32_t)top->state.as[i+2].s_addr,
		  (uint32_t)top->state.as[i+3].s_addr,
		  (uint32_t)top->state.as[i+4].s_addr,
		  (uint32_t)top->state.as[i+5].s_addr,
		  (uint32_t)top->state.as[i+6].s_addr,
		  (uint32_t)top->state.as[i+7].s_addr);
	  }
	} while(0);
#endif

	return 0;
}

/*
 *	Check whether any of RRs for a realm have expired.
 *	Also check whether a query has been in-flight or unused too long.
 */
static int top_check(void *context, void *Data)
{
	rlm_ddds_t *inst = context;
	ddds_top_t *top = Data;
	struct timeval now;
	int idx, nidx;
	int *aidxs =  top->state.aidxs;
	int *alens =  top->state.alens;
	int *aaaaidxs =  top->state.aaaaidxs;
	int *aaaalens =  top->state.aaaalens;

	gettimeofday(&now,NULL);

	if (top->state.last_used + inst->expiry_ttl < now.tv_sec) {
		DEBUG("TODO: need to delete '%s' from rbtree while locked",
		      top->query.owner);
	}

	nidx = plumb_naptr(inst, top, 0, "");
	if (nidx < 0) {
		/* Something timed out.  Triage, but check deadbeat first. */
		if (top->state.in_flight &&
		    top->state.last_launch + inst->deadbeat_ttl < now.tv_sec) {
			/* This is not expected to ever actually happen. */
			ERROR("DNS client stalled for '%s'", top->query.owner);
			top->state.in_flight = 0;
		}
		top_triage(inst, top);
		return 0;
        }

	for(idx = 0; (idx < MAX_SRVS
			    && top->state.sports[idx] != -1); idx++) {
		/*
		 *	Note if two or more SRVs point to the same name, the
		 *	storage gets wiped more than once, and we are
		 *	temporarily in an inconsistent state.  That's OK,
		 *	we are consistent by the time we release the lock.
		 */
		if (top->state.alens[idx] != -1 && inst->want_v4) {
			if (now.tv_sec > top->state.atimes[idx]) {
				DEBUG2("A RRSet '%s' timed out for '%s'",
				       top->state.snames[idx],
				       top->query.owner);
				if (top->state.aidxs[idx] != -1) {
					nuke_as(top, aidxs[idx], alens[idx]);
				}
				aidxs[idx] = -1;
				alens[idx] = -1;
				ub_ask(inst, top->state.snames[idx],
				       1, 1, top, ub_cb, NULL);
			}
		}
		if (top->state.aaaalens[idx] != -1 && inst->want_v6) {
			if (now.tv_sec > top->state.aaaatimes[idx]) {
				DEBUG2("AAAA RRSet '%s' timed out for '%s'",
				       top->state.snames[idx],
				       top->query.owner);
				if (top->state.aaaaidxs[idx] != -1) {
					nuke_aaaas(top, aaaaidxs[idx],
						   aaaalens[idx]);
				}
				aaaaidxs[idx] = -1;
				aaaalens[idx] = -1;
				ub_ask(inst, top->state.snames[idx],
				       28, 1, top, ub_cb, NULL);
			}
		}
	}
	return 0;
}

/* Put successful SRV query results into the state. */
static int new_srvs(UNUSED rlm_ddds_t *inst, ddds_top_t *top, struct ub_result *ub)
{
	int idx = 0;
	int cnt, nidx;
	int ri;
	unsigned char *rr;
	int ttl;
	int sorted;
	struct timeval now;

	gettimeofday(&now, NULL);
	ttl = clamp_ttl(inst, ub->ttl);

	/* Check the NAPTR tree for timeouts, and find our parent. */
        nidx = plumb_naptr(inst, top, ub->qtype, ub->qname);
	if (nidx < 0) {
		return nidx;
	}
	while (--nidx >= 0) {
		if (top->state.nflags[nidx] & NAPTR_DIVE) {
			break;
		}
	}
	rad_assert(nidx >= 0);

	top->state.ntimes[nidx] = now.tv_sec + ttl;

	/* If we got here through an alias, remember that. */
	if (ub->canonname) {
		strcpy(top->state.srv_cname, ub->canonname);
	} else {
		top->state.srv_cname[0] = '\0';
	}

	/* Store the RRs matching our criteria.  Also check sanity. */
	for (cnt = 0, ri = 0; (rr = (unsigned char *)ub->data[ri]); ri++) {
		top->state.sprios[cnt] = (*(rr) << 8) | *(rr+1);
		rr += 2;
		top->state.sweights[cnt] = (*(rr) << 8) | *(rr+1);
		rr += 2;
		top->state.sports[cnt] = (*(rr) << 8) | *(rr+1);
		rr += 2;

		/* In the meantime use parent TTL, JIC */
		top->state.atimes[cnt] = now.tv_sec + ttl;
		top->state.aaaatimes[cnt] = now.tv_sec + ttl;

		/* TODO: can we and do we want to filter these? */

		/* TODO: empty or otherwise invalid owner? */
		if (rrlabels_tostr((char *)rr,
				   top->state.snames[cnt]) < 0) {
			DEBUG("Format violation in SRV '%s' for '%s'",
			      ub->qname, top->query.owner);
			continue;
		}

		if (!cnt && !strcmp(top->state.snames[cnt], ".")
		    && !ub->data[ri + 1]) {
			/* RFC2782: A single SRV RR owner "." == not here. */
			DEBUG3("Definitively empty SRV '%s' for '%s'",
			       ub->qname, top->query.owner);
			return -1;
		}

		if (++cnt > MAX_SRVS - 1) {
			ri++;
			break;
		}
	}
	/* Did we exceed the array? */
	if (ub->data[ri]) {
		WDEBUG("SRV '%s' for '%s' has too many RRs",
		       ub->qname, top->query.owner);
		return -1;
	}
	/* Mark the first unused entry, if any. */
	if (cnt < MAX_SRVS) {
		top->state.sports[cnt] = -1;
	}

	/* Bubblesort them.  Should be fast enough for sane DDDS databases */
	do {
		int i;
		sorted = 1;
		for (i = 0; i < cnt - 1; i++) {
			int tmp;
			char nt[256];
			if (top->state.sprios[i] > top->state.sprios[i+1]) {
				continue;
			}
			if (top->state.sweights[i] >=
			    top->state.sweights[i+1]) {
				if (top->state.sprios[i] ==
				    top->state.sprios[i+1]) {
					continue;
				}
			}
			sorted = 0;

			/* Swap adjacent entries.  Uninit fields skipped. */
			tmp = top->state.sprios[i];
			top->state.sprios[i] = top->state.sprios[i + 1];
			top->state.sprios[i + 1] = tmp;
			tmp = top->state.sweights[i];
			top->state.sweights[i] = top->state.sweights[i + 1];
			top->state.sweights[i + 1] = tmp;
			tmp = top->state.sports[i];
			top->state.sports[i] = top->state.sports[i + 1];
			top->state.sports[i + 1] = tmp;
			memcpy(nt, top->state.snames[idx + i], 256);
			memcpy(top->state.snames[idx + i],
			       top->state.snames[idx + i + 1], 256);
			memcpy(top->state.snames[idx + i + 1], nt, 256);
		}
	} while (sorted == 0);

	do {
		int i;
		for (i = 0; i < cnt; i++) {
		  DEBUG("SRV[%i]\t%i\t%i\t%s:%i",i,top->state.sprios[i],
			top->state.sweights[i],
			top->state.snames[i], top->state.sports[i]);
		}
		if (cnt < MAX_SRVS) {
		  DEBUG("next prio/port %i/%i", top->state.sprios[i],
			top->state.sports[i]);
		}
	} while(0);

	/* Mark all A/AAAA records as pending/unassigned */
	while(cnt--) {
		top->state.alens[cnt] = -1;
		top->state.aaaalens[cnt] = -1;
		top->state.aidxs[cnt] = -1;
		top->state.aaaaidxs[cnt] = -1;
	}
	/* Clear the A/AAAA storage areas */
	nuke_as(top, 0, MAX_A_RRS);
	nuke_aaaas(top, 0, MAX_AAAA_RRS);

	return 0;
}

/*
 * Add successful NAPTR query results to the search tree.
 * Returns the index of the next NAPTR to look into.
 * Or -2 if there was TTL rollback that requires further action.
 * Or -3 if a backtrack is needed.
 */
static int new_naptr(rlm_ddds_t *inst, ddds_top_t *top, struct ub_result *ub)
{
	int idx = 0;
	int aidx, cnt, ri;
	unsigned char *rr;
	int *flags = top->state.nflags;
	time_t *times = top->state.ntimes;
	int sorted;
	int orders[MAX_NAPTRS];
	int prefs[MAX_NAPTRS];
	int ttl;
	struct timeval now;

	gettimeofday(&now, NULL);
	ttl = clamp_ttl(inst, ub->ttl);

        idx = plumb_naptr(inst, top, ub->qtype, ub->qname);
	if (idx < 0) {
		return idx;
	}

	/* Is this the "well-known" NAPTR? */
	if (idx == 0 ||
	    (idx == 1 &&
	     ((top->state.nflags[0] & NAPTR_SYNTH) == NAPTR_SYNTH))) {
		top->state.top_time = now.tv_sec + ttl;
		/* Overwrite the default NAPTR if we actually get RRs */
		idx = 0;
	}

	if (idx >= MAX_NAPTRS) {
		cnt = idx;
	toomany:
		WDEBUG("Too many NAPTR RRs for %s", top->query.owner);
		idx = -1; /* Will be return code. */
		aidx = cnt;
		goto installttl;
	}

	/*
	 *	Store the RRs matching our criteria.  Also check sanity.
	 *
	 *	Note that other application NAPTRs may be mixed in, so if
	 *	anything looks weird we just ignore it, though we will
	 *	emit some debug messages for egregious RFC3403 violations.
	 *
	 *	We could do better on that and complain more when we can
	 *	tell that an RR *is* for our application and violates
	 *	RFC3598 or draft-ietf-radext-dynamic-discovery.
	 */
	for (cnt = ri = 0; (rr = (unsigned char *)ub->data[ri]); ri++) {
		unsigned char *tmpptr;
		unsigned char f = '\0';
		size_t tmp;
		int len;

		/* TODO: do we need to check ub->len[] for truncation? */

		orders[cnt] = ((*rr) << 8) | *(rr + 1);
		rr += 2;
		prefs[cnt] = ((*rr) << 8) | *(rr + 1);
		rr += 2;
		if (*rr) {
			/* NAPTR Flags field has content; Should be one char */
			if (*rr != 1) {
				continue;
			}
			rr++;
			f = *rr | 0x20; /* RFC3403 4.1: Case insensitive */
			if (f != 'a' && f != 's') {
				/*
				 * RFC 3958 6.4: only "A" or "S" allowed
				 *
				 * TODO: the RFC does not explicitly forbid
				 * "AS" in 6.4.  It probably means to.
				 * Admins can define two records if they
				 * really want to do that.
				 */
				continue;
			}
		}
		rr++;
		len = *rr;
		if (len > 63) {
		badformat:
			DEBUG("Format violation in NAPTR RR for %s",
			      ub->qname);
			continue;
		}
		rr++;
		tmp = strlen(inst->naptr_service);
		len -= tmp;
		if (len < 0) {
			continue;
		}
		if (strncasecmp((char *)rr, inst->naptr_service, tmp)) {
			continue;
		}
		rr += tmp;

		/* Match against any of the protocols. */
		if (!len && !strlen(inst->naptr_proto)) {
			goto matched;
		}
		if (!len) {
			continue;
		}
		if (*rr != ':') {
			continue;
		}
	again:
		rr++;
		len--;
		tmp = strlen(inst->naptr_proto);
		if (len < (int)tmp) {
			continue;
		}
		if (!strncasecmp((char *)rr, inst->naptr_proto, tmp) &&
		    (len == (int)tmp || *(rr + tmp) == ':')) {
			rr += len;
			goto matched;
		}
		tmpptr = memchr(rr, ':', len);
		if (!tmpptr) {
			continue;
		}
		len -= tmpptr - rr;
		rr = tmpptr;
		goto again;

	matched:
		/* OK, not really.  First make sure the regexp is empty. */
		if (*rr) {
			continue; /* RFC 3958 Section 5 violation */
		}
		rr++;

		/* See if we can fit it. */
		if (idx + cnt >= MAX_NAPTRS) {
			goto toomany;
		}

		flags[idx + cnt] = NAPTR_USED;
		/* Handle the special case of CNAME/DNAME aliases. */
		if (cnt == 0 && ub->canonname) {
			times[idx] = now.tv_sec + ttl;
			flags[idx] |= NAPTR_FORE | NAPTR_DIVE;
			strcpy(top->state.nnames[idx], ub->canonname);
			idx++;
		}
		flags[idx + cnt] = NAPTR_USED;
		if (f) {
			flags[idx + cnt] |= NAPTR_TERM;
			if (f == 's') {
				flags[idx + cnt] |= NAPTR_SRV;
			}
		}
		top->state.nnames[idx + cnt][0] = '\0';
		/*
		 * TODO: we may need to preserve default NAPTR depending
		 * on how newer drafts decide to deal with the following
		 * failure modes.  If so we need to test the unpack above
		 * in the filtering section before we modify the entry.
		 */
		if (rrlabels_tostr((char *)rr,
				   top->state.nnames[idx + cnt]) < 0) {
			goto badformat;
		}
		if (!strlen(top->state.nnames[idx + cnt])) {
			goto badformat;
		}
		/* In the meantime, use placeholder TTL of the parent RRset. */
		top->state.ntimes[idx + cnt] = now.tv_sec + ttl;
		cnt++;
	}

	/* Bubblesort them.  Should be fast enough for sane DDDS databases */
	do {
		int i;
		sorted = 1;
		for (i = 0; i < cnt - 1; i++) {
			int tmp;
			time_t tt;
			char nt[256];
			if (orders[i] > orders[i+1]) {
				continue;
			}
			if (prefs[i] >= prefs[i+1]) {
				/* TODO: additional criteria sort? */
				if (orders[i] == orders[i+1]) {
					continue;
				}
			}
			sorted = 0;

			/* Swap adjacent entries */
			tmp = orders[i];
			orders[i] = orders[i + 1];
			orders[i + 1] = tmp;
			tmp = prefs[i];
			prefs[i] = prefs[i + 1];
			prefs[i + 1] = tmp;
			tmp = flags[idx + i];
			flags[idx + i] = flags[idx + i + 1];
			flags[idx + i + 1] = tmp;
			tt = times[idx + i];
			times[idx + i] = times[idx + i + 1];
			times[idx + i + 1] = tt;
			memcpy(nt, top->state.nnames[idx + i], 256);
			memcpy(top->state.nnames[idx + i],
			       top->state.nnames[idx + i + 1], 256);
			memcpy(top->state.nnames[idx + i + 1], nt, 256);
		}
	} while (sorted == 0);

	/* Did we come up empty-handed after filtering? */
	if (!cnt) {
		/* Should we use the default NAPTR? */
		if (idx == 0 && (flags[0] & NAPTR_SYNTH) == NAPTR_SYNTH) {
			DEBUG2("Using default NAPTR for '%s'",
			       top->query.owner);
			cnt = 1;
		}
	}
	if (cnt) {
		/* Place the tree structure marker and cursor */
		idx += cnt - 1;
		flags[idx] |= NAPTR_FORE | NAPTR_DIVE;
	}

	/* Go back and find our parent. */
	aidx = idx;
 installttl:
	while (--aidx >= 0) {
		if (flags[aidx] & NAPTR_DIVE) {
			break;
		}
	}
	if (aidx >= 0) {
		/* Keep track of positive TTL */
		times[aidx] = now.tv_sec + ttl;
	}

	if (!cnt) {
		/* RFC 3958 Section 2.2.4. */
		DEBUG("Backtracking '%s' due to no matching RRs for '%s'",
		      top->query.owner, top->state.nnames[aidx]);
		return -3;
	}

	/* TODO: delete this */
	DEBUG("Top %s expires at %li", top->query.owner, top->state.top_time);
	for (cnt = 0; cnt < MAX_NAPTRS; cnt++) {
	  DEBUG("NAPTR:\t%x\t%i\t%s", flags[cnt], (int)times[cnt],
		top->state.nnames[cnt]);
	  if (!(flags[cnt] & NAPTR_USED) && cnt > 5) {
	  	break;
	  }
	}

	return idx;
}

/*
 *	"Backtrack" along former NAPTR query results due to a failure.
 *
 *	This proceeds along limbs in the opposite direction to TTL timeouts,
 *	which we will call "rollbacks".  Both rollbacks and backtracks will
 *	fail upward toward the NAPTR tree root when a whole limb is discarded.
 *
 *	Negative TTLs are promoted up the tree.  When an entire limb
 *	backtracks, the soonest of all expirations on the limb is applied to
 *	the parent, unless the parent expiration is sooner.  This includes
 *	the top branch and the well-known expiry.  The ttl passed in should
 *	be that of the result causing the backtrack.
 *
 *	Returns:
 *	index of next NAPTR to follow,
 *	or -1 if backtracking is exhausted (wait for TTL expiry to resume.)
 *	or -2 if a TTL expiry was detected.
 */
static int backtrack_naptr(UNUSED rlm_ddds_t *inst, ddds_top_t *top, int ttl)
{
	int idx, del;
	time_t min_time, q_time;
	int *flags = top->state.nflags;
        struct timeval now;

        gettimeofday(&now, NULL);
	ttl = clamp_ttl(inst, ttl);

	/* Find the last cursor. */
	for (del = MAX_NAPTRS - 1; del >= 0; del--) {
		if (flags[del] & NAPTR_DIVE) {
			break;
		}
	}

	/* No cursor or a synthetic NAPTR.  Just install negative TTL. */
	if (!inst->want_naptr || del < 0) {
		if (top->state.top_time > now.tv_sec + ttl) {
			top->state.top_time = now.tv_sec + ttl;
		}
		return -1;
	}

	/* TTL expiry/rollback takes precedence to backtracking. */
        idx = plumb_naptr(inst, top, 0, top->query.owner);
 	if (idx < 0) {
		return idx;
	}

	/*
	 * TODO:
	 * Cannot happen with qtype 0 passed to plumb_naptr above.
	 * Kept in case we want to get fancier here.
	 */
#if 0
	/* If TTL expiry/rollback moved the cursor, we are done. */
	if (!(flags[del] & NAPTR_DIVE)) {
		while (!(flags[--idx] & NAPTR_DIVE)) {
			if (idx == 0) {
				return -1;
			}
		}
		return idx;
	}
#endif

	/* Current result negative TTL sets an upper bar on expiry */
	q_time = now.tv_sec + ttl;
again:
	/*
	 * Rewind to a descent cursor, if we are not already there.
	 * Keep track of the minimum TTL of all passed-over RRs.
	 */
	min_time = q_time;
	while (--idx >= 0) {
		if (min_time > top->state.ntimes[idx]) {
			min_time = top->state.ntimes[idx];
		}
		if (flags[idx] & NAPTR_DIVE) {
			break;
		}
	}

	/* Are we trying to backtrack from the top/last? */
	if (idx <= 0) {
	exhausted:
		if (top->state.top_time > now.tv_sec + ttl) {
			top->state.top_time = now.tv_sec + ttl;
		}
		return -1;
	}

	/* Remove the cursor */
	flags[idx] &= ~NAPTR_DIVE;
	/* Install the current result expiry. */
	top->state.ntimes[idx] = q_time;

	/* "backtrack" to next item on branch */
	idx--;

	/* Did we just back up past the top? */
        if (idx < 0) {
		goto exhausted;
        }

	/* Is this level of the tree exhausted? */
	if (flags[idx] & NAPTR_FORE) {
		/* Proceed as if we just got an RR for our parent. */
		q_time = min_time;
		idx++;
		goto again;
	}

	flags[idx] |= NAPTR_DIVE;

	/* Fast forward to the first unused or first-in-branch entry */
	for (del = idx + 1; del < MAX_NAPTRS; del++) {
		if (!(flags[del] & NAPTR_USED) || (flags[del] & NAPTR_FORE)) {
			break;
		}
	}
	rad_assert(del < MAX_NAPTRS);

	/* If a first-in-branch entry, go one more to find recyclables */
	if (flags[del] & NAPTR_USED) {
		del++;
	}

	/* Mark any remaining entries available for re-use. */
	while (del < MAX_NAPTRS) {
		if (!flags[del]) {
			break;
		}
		flags[del] = 0;
		del++;
	}

	/* Tell the caller where to resume processing. */
	return idx;
}

/*
 *	Emit debug logs for any errors from a DNS query.
 *	Returns 0 if no error and hence no log emitted, -1 otherwise.
 */
static int log_dns_error(rlm_ddds_t *inst, struct ub_result *ub, int err) {
	char buf[16];

	switch (ub->qtype) {
	case 1:
		strcpy(buf, "A");
		break;
	case 28:
		strcpy(buf, "AAAA");
		break;
	case 33:
		strcpy(buf, "SRV");
		break;
	case 35:
		strcpy(buf, "NAPTR");
		break;
	default:
		if (ub->qtype >= 0 || ub->qtype < 65536) {
			sprintf(buf, "(type %i)", ub->qtype);
		}
		else {
			strcpy(buf, "(?)");
		}
	}

	if (err) {
		DEBUG("Query type %i for %s called back with error: %s",
		      ub->qtype, ub->qname, ub_strerror(err));
		return -1;
	}
	if (ub->bogus) {
		DEBUG("Bogus DNS response (for %s query '%s'): %s",
		      buf, ub->qname, ub->why_bogus);
		return -1;
	}
	if (!ub->secure && inst->must_dnssec) {
		DEBUG2("Insecure DNS response for %s query '%s'",
		       buf, ub->qname);
		return -1;
	}
	if (ub->nxdomain) {
		if (ub->canonname) {
			DEBUG2("NXDOMAIN for alias '%s' to '%s'",
			       ub->qname, ub->canonname);
		} else {
			DEBUG2("NXDOMAIN for %s query '%s'", buf, ub->qname);
		}
		return -1;
	}

	if (!ub->havedata) {
		if (ub->canonname) {
			DEBUG2("Empty result for alias '%s' to '%s'",
			       ub->qname, ub->canonname);
		}
		else {
			DEBUG2("Empty result for %s query '%s'",
			       buf, ub->qname);
		}
		return -1;
	}
	return 0;
}

/*
 *	All DNS responses eventually make it through layers to here.
 *
 *	This is called only when inst.tops lock is held.
 *
 *	The return code is actually rather meaningless in callback
 *	context, but left in for readability/debugging.
 */
static int ub_cb_rbtree_cb(void *Data, void *context)
{
	struct tuple_inst_ubresult *c = context;
	struct ub_result *result = c->result;
	rlm_ddds_t *inst = c->inst;
	ddds_top_t *top = Data;
	int i, res;
	int bad;
	int triage = 0;
        struct timeval now;
	int *flags = top->state.nflags;

	if (top->state.in_flight) {
		top->state.in_flight--;
	}

	/*
	 *	Ensure any NAPTR or SRV responses are not unwanted.
	 *	We have to do this in case the algorithm moves on
	 *	and a late response arrives.
	 */
	if (result->qtype == 35 || result->qtype == 33) {
		/* Find the cursor */
		for (res = MAX_NAPTRS - 1; res >= 0; res--) {
			if (flags[res] & NAPTR_DIVE) {
				break;
			}
		}
		if (res < 0){
			/* No cursor.  Well-known NAPTR is acceptable. */
			if (strcmp(result->qname, top->query.owner)
			    || result->qtype != 35) {
				return -1;
			}
		} else {
			/* Were we expecting NAPTR RRs? */
			if (result->qtype == 35
			    && (flags[res] & NAPTR_TERM)) {
				return -1;
			}
			/* Were we expecting SRV RRs? */
			if (result->qtype == 33
			    && (flags[res] & NAPTR_SRV) != NAPTR_SRV) {
				return -1;
			}
			/* Do the RR and cursor have the same owner? */
			if (strcmp(result->qname, top->state.nnames[res])) {
				return -1;
			}
		}
	}

	/* Consolidate sundry failure modes. */
	bad = (c->err || result->bogus || result->nxdomain ||
	       (!result->havedata) || (!result->secure && inst->must_dnssec));
	if (bad) {
		log_dns_error(inst, result, c->err);
	}

        gettimeofday(&now, NULL);

	/* Handle answers to NAPTR queries. */
	if (result->qtype == 35) {
		/*
		 * When want_srv is set we are supposed to resort to
		 * a default SRV (per draft-ietf-radext-dynamic-discovery)
		 * lookup when:
		 *
		 * 1) If after filtering for service and protocol there
		 *    are no RRs remaining in the first NAPTR query.
		 * 2) If the first NAPTR query returns no results, but
		 *    not if "name resolution returns with error."
		 *
		 * It is less than clear what constitutes "no results"
		 * and what constitutes an error -- moreso when DNSSec
		 * failure modes are considered.
		 *
		 * So these criteria may change.
		 */
	  	if (inst->want_srv && (result->nxdomain || !result->havedata)
		    && !(flags[1] & NAPTR_USED)) {
			rad_assert((flags[0] & NAPTR_SYNTH) == NAPTR_SYNTH);
			/* This takes care of 2) above */
			res = 0;
			flags[0] |= NAPTR_DIVE | NAPTR_FORE;
			DEBUG2("Using default NAPTR for '%s' due to DNS empty",
			       top->query.owner);
		}
	  	else if (bad) {
		backtrack:
			res = backtrack_naptr(inst, top, result->ttl);
			if (res != -1) {
				triage = 1;
			}
			goto badresult;
		}
		else {
			res = new_naptr(inst, top, result);
			if (res == -2) {
				triage = 1;
				goto triage;
			}
			if (res == -3) {
				goto backtrack;
			}
			if (res < 0) {
				/*
				 * Leave the query abandoned.  It will be
				 * retried when something expires.
				 */
				return res;
			}
		}

		if (!(flags[res] & NAPTR_DIVE)) {
			DEBUG("TODO: expected a DIVE");
			return -1;
		}

		/* TODO: consolidate with triage here? */
		if (!(flags[res] & NAPTR_TERM)) {
			/* Descend into the next NAPTR level */
			ub_ask(inst, top->state.nnames[res],
			       35, 1, top, ub_cb, NULL);
			return 0;
		}
		else if ((flags[res] & NAPTR_SRV) == NAPTR_SRV) {
			/* Found an "s" terminator.  Go get a SRV. */
			ub_ask(inst, top->state.nnames[res],
			       33, 1, top, ub_cb, NULL);
			return 0;
		}
		else {
			/* Found an "a" terminator.  Make a synthetic SRV. */
		        strcpy(top->state.snames[0],
			       top->state.nnames[res]);
			top->state.sports[0] = inst->naptr_port;
			top->state.ntimes[res] = now.tv_sec + inst->max_ttl;

		synth_srv:
			top->state.sprios[0] = -1;
			top->state.sweights[0] = -1;

			/* Mark the synthetic SRV as incomplete */
			top->state.alens[0] = -1;
			top->state.aaaalens[0] = -1;
			top->state.aidxs[0] = -1;
			top->state.aaaaidxs[0] = -1;

			/* Truncate additional SRV entries. */
			top->state.sports[1] = -1;

			/* Free up the A/AAAA storage space. */
			nuke_as(top, 0, MAX_A_RRS);
			nuke_aaaas(top, 0, MAX_AAAA_RRS);

			/* Send the A/AAAA queries. */
			if (inst->want_v4) {
				ub_ask(inst, top->state.snames[0],
				       1, 1, top, ub_cb, NULL);
			}
			if (inst->want_v6) {
				ub_ask(inst, top->state.snames[0],
				       28, 1, top, ub_cb, NULL);
			}

			/* We could have come here via fallback.  Emit debug */
			if (bad) goto badresult;
			return 0;
		}
	}

	/* Handle answers to SRV queries. */
	if (result->qtype == 33) {
		if (bad) {
			char *target;
			/*
			 *	When there is no fallback, NAPTR and SRV
			 *	failures do the same thing.
			 */
			if (!inst->fallback) {
				goto backtrack;
			}

			/*
			 *	Before resorting to fallback, see if any
			 *	NAPTRs have expired.
			 */
			res = plumb_naptr(inst, top, 33, result->qname);
			if (res < 0) {
				triage = 1;
				goto badresult;
			}
			/* Find our parent. */
			while (--res >= 0) {
				if (flags[res] & NAPTR_DIVE) {
					break;
				}
			}
			rad_assert(res >= 0);

			/*
			 * 	Try to construct a fallback owner.
			 *	If anything looks unusual, do not fall back.
			 */
			if (*(result->qname) != '_') {
				goto backtrack;
			}
			target = strchr(result->qname, '.');
			if (!target || *(target + 1) != '_') {
				goto backtrack;
			}
			target = strchr(target + 1, '.');
			if (!target || !(strlen(target) > 1)) {
				goto backtrack;
			}
			target++;

			DEBUG2("Using fallback A/AAAA lookup for '%s' of '%s'",
			       result->qname, top->query.owner);

			/* Add a synthetic SRV.  Use negative TTL. */
			strcpy(top->state.snames[0], target);
			top->state.sports[0] = inst->fallback;
			top->state.ntimes[res] =
				now.tv_sec + clamp_ttl(inst, result->ttl);

			goto synth_srv;
		}

		res = new_srvs(inst, top, result);
		if (res == -2) {
			triage = 1;
			goto triage;
		}
		if (res < 0) {
			/*
			 *	Leave the query abandoned.  It will be
			 *	retried when lb code complains, or
			 *	TTLs time out.
			 */
			return res;
		}

		/*
		 *	Launch queries for A and/or AAAA records.
		 *
		 *	The same name may appear more than once.  For now,
		 *	we just rely on the unbound cache to make that fast,
		 *	rather than detecting duplicates.
		 */
		for (i = 0; ((top->state.sports[i] != -1)
			     && (i < MAX_SRVS)); i++) {
			if (inst->want_v4) {
				ub_ask(inst, top->state.snames[i],
				       1, 1, top, ub_cb, NULL);
			}
			if (inst->want_v6) {
				ub_ask(inst, top->state.snames[i],
				       28, 1, top, ub_cb, NULL);
			}
		}
		return 0;
	}

	if (result->qtype == 28 && !(inst->want_v6)) {
		DEBUG("Got an AAAA answer, but do not want IPv6.");
		/* Should not happen. Otherwise harmless. */
		return 0;
	}

	if (result->qtype == 1 && !(inst->want_v4)) {
		DEBUG("Got an A answer, but do not want IPv4.");
		/* Should not happen. Otherwise harmless. */
		return 0;
	}

	/* Handle answers to A/AAAA queries. */
	if (result->qtype == 1 || result->qtype == 28) {
		if (bad) {
			res = do_as(inst, top, result, 1);
			if (res == -2) {
				triage = 1;
			}
			goto badresult;
		}
		res = do_as(inst, top, result, 0);
		if (res == -2) {
			triage = 1;
			goto triage;
		}
		return 0;
	}

 badresult:
	if (bad) {
	triage:
		if (triage) {
			top_triage(inst, top);
		}
		return -1;
	}
	return 0;
}

static void ub_cb(void *my_arg, int err, struct ub_result *result)
{
	struct tuple_inst_top *ubctx = (struct tuple_inst_top *)my_arg;
	struct tuple_inst_ubresult rbctx;

	rbctx.inst = ubctx->inst;
	rbctx.err = err;
	if (!err) {
		rbctx.result = result;
	} else {
		rbctx.result = &ubctx->fake_result;
	}

	/* Lock the top.  Then do our work.  Then unlock it. */
	if (!rbtree_lock_finddata(rbctx.inst->tops, ubctx->top,
				  ub_cb_rbtree_cb, &rbctx,
				  ddds_top_compare_query)) {
		DEBUG2("Got DNS result for deleted query.");
	}
	if (!err) {
		ub_resolve_free(result);
	}
	talloc_free(ubctx);
}

/*
 *	Send an initial query into the DNS resolver.  Subsequent queries
 *	will be launched only in response to other queries.
 *
 *	Should be called only when the rbtree lock is held.
 *
 *	Should be called only when the query is not already in flight.
 */
static int ddds_top_ask(rlm_ddds_t *inst, ddds_top_t *top)
{
	ddds_query_t *q = &top->query;
	char *owner = q->owner;
	int res = -1;
	struct timeval now;

	gettimeofday(&now, NULL);

	if (inst->want_naptr) {
		res = ub_ask(inst, owner, 35, 1, top, ub_cb, NULL);
	}
	else if (inst->want_srv && (top->state.nflags[0] | NAPTR_USED)) {
		/* We have a synthetic S-NAPTR, and we are using SRVs. */
		res = ub_ask(inst, top->state.nnames[0],
			     33, 1, top, ub_cb, NULL);
	}
	else if (inst->fallback && top->state.sprios[0] == -1) {
		/* We have a synthetic SRV, and are using A/AAAA fallback. */
		if (inst->want_v4) {
			res = ub_ask(inst, owner, 1, 1, top, ub_cb, NULL);
		}
		if (inst->want_v6) {
			res = ub_ask(inst, owner, 28, 1, top, ub_cb, NULL);
		}
	}
	else {
		ERROR("FIXME.  New top not initialized correctly.");
		return -1;
	}
	if (res) {
		ERROR("Problem launching initial query for '%s': %s",
		      owner, ub_strerror(res));
		return -1;
	}
	return 0;
}

/*
 *	Callback from inside rbtree lock to send initial query for a top.
 */
static int top_ask_cb(void *Data, void *context)
{
	ddds_top_t *top = Data;
	rlm_ddds_t *inst = context;

	top->state.in_flight = 0;
	ddds_top_ask(inst, top);

	return 0;
}

/*
 *	Creates a new top query holder
 */
static ddds_top_t *top_alloc(rlm_ddds_t *inst, char const *owner)
{
	ddds_top_t *top;

	if (253 < 4 + strlen(inst->srv_proto) + strlen(inst->srv_service)) {
		if (inst->want_srv) {
			if (inst->want_naptr) {
				DEBUG2("Fallback SRV owner too long.");
				/* Use S-NAPTR without SRV */
			}
			else {
				ERROR("SRV owner too long: _%s._%s.%s",
				      inst->srv_proto, inst->srv_service,
				      owner);
				return NULL;
			}
		}
	}

	top = talloc_zero(inst, ddds_top_t);
	if (!top) {
		DEBUG2("Out of memory.");
		return NULL;
	}
	strcpy(top->query.owner, owner);

	top_reset(inst, top, 1);

	return top;
}

/*
 * Hackery to link to proto_unbound instances.
 */
typedef struct unbound_listen_t {
	listen_socket_t fake_socket;
	struct ub_ctx *ub;
	char const *name2;
} unbound_listen_t;


/*
 * Take a snapshot of a top while locked by rbtree.
 *
 * This will make sure to prune off any expired data before returning
 * it.  If expiry is detected, new queries will be launched but not
 * waited on -- caller should do the waiting based on .in_flight.
 */
static int top_copy_cb(void *Data, void *context)
{
	ddds_top_t *from = Data;
	struct tuple_inst_top *to = context; /* Do not use fake_result */
	int all_expired;

	struct timeval now;
	gettimeofday(&now, NULL);

	from->state.last_used = now.tv_sec;

	/* Do not alter while packets are in flight */
	if (from->state.in_flight) {
		goto copy;
	}

	all_expired = (now.tv_sec > from->state.top_time);

	if (plumb_naptr(to->inst, from, 0, "") < 0) {
		/* top has now been purged of expired SRV/NAPTR RRs */
		if (all_expired) {
			ddds_top_ask(to->inst, from);
		}
		else {
			top_triage(to->inst, from);
		}
	}

	/* TODO: validate A/AAAA TTLs and consequences of that */

 copy:
	memcpy(to->top, from, sizeof(ddds_top_t));

	return 0;
}

/*
 *	Pack DDDS results into RADIUS attributes which can be used
 *	by the pool/lb/tls code to establish new connections or choose
 *	existing ones.
 *
 *	We use the following attributes, all but the first of which exist
 *	solely for this purpose.  Most attributes occur the same number of
 *	times and the whole batch should be read as a table with attributes
 *	defining the fields/columns and indexes defining the rows.
 *
 *	Home-Server-Pool: contains a string unique per pool.  That is,
 *	the string may appear more than one time -- all entries with the
 *	same string should be considered part of the same pool.  Entries
 *	are sorted primarily by a field in this attribute, in order of
 *	preference, so the first listings with the same value in this string
 *	define the first group of servers to try, and the second would only be
 *	used if those prove incapable, etc.  The value contains the full module
 *	name of the ddds instance (e.g. "ddds.name2"), followed by a colon,
 *	followed by a unique (by pool) integer, followed by a colon,
 *	followed by the result of the well-known rule.  This latter
 *	part may be used in RADSec certificate validation as appropriate
 *	to the federation PKI scheme.
 *
 *	Dynamic-Pool-Weight: The cumulative probability with which this
 *	particular service should be chosen.  In the absence of any server
 *	affinity strategy, a random RADIUS integer should be chosen, then
 *	compared to each Dynamic-Pool-Weight in the order in which they
 *	appear.  When an entry is reached for which Dynamic-Pool-Weight
 *	is less then or equal to the randomly chosen number, that entry
 *	should be tried.  The last entry in a pool is always 2^32-1.
 *
 *	Dynamic-Pool-IP-Address, Dynamic-Pool-IPv6-Address: only one of
 *	these entries per row will have a value.  The other will be set
 *	to INADDR_ANY or the unspecified IPv6 address, respectively.
 *	This address is to be used to contact this server.
 *
 *	Dynamic-Pool-IP-Protocol: for now will be either TCP or UDP.
 *
 *	Dynamic-Pool-Port: This TCP/UDP port should be used to contact the
 *	server.  Whether or not to use TLS should be inferred from this value
 *	for now in the normal manner.  The upper unused bits of this value are
 *	reserved for flags in case that system of inference fails us.
 *
 *	Dynamic-Pool-Host-Name: This is the final host name which yeilded
 *	the address in Dynamic-Pool-IP-Address/Dynamic-Pool-IPv6-Address.
 *	Depending on the federation PKI scheme, it may be useful for
 *	RADSec certificate validation.  It should be used when logging
 *	server-specific events related to this server.
 *
 *	Dynamic-Pool-Alias1/Dynamic-Pool-Alias2: These strings are not
 *      part of the table.  They are populated when CNAME/DNAME aliases
 *	or NAPTR hops that are encountered during NAPTR or SRV resolution.
 *	Dynamic-Pool-Alias2 will sometimes contain a single value with
 *	an alias encountered in a response to an SRV query, encountered
 *	during A/AAAA resolution that happenned as a fallback after a SRV
 *	lookup failure, or an alias encountered during A/AAAA resolution
 *	resulting from an S-NAPTR with an "a" flag.  Dynamic-Pool-Alias1
 *	will contain many values showing all owners including CNAME/DNAME
 *	aliases encountered during intermediate NAPTR lookups.  Note
 *	that A/AAAA aliases encountered when looked up due to a SRV are
 *	ignored because they are illegal.  These strings are provided in
 *	case they are needed for PKI validation purposes.
 *
 *	NOTE: The *top here is a copy of the rbtree item which we will
 *	be throwing away.  So we can scratchpad with it if needed.
 */
static void map_avp(rlm_ddds_t *inst, ddds_top_t *top, int pidx,
		    int weight, in_addr_t ipv4, struct in6_addr *ipv6,
		    int port, char *owner, REQUEST *request)
{
 	VALUE_PAIR      *vp, **vps;
	char pname[512];
	int size;

	vps = &request->config_items;

	size = snprintf(pname, 512,
			"ddds.%s:%i:%s", inst->name2, pidx, top->query.owner);
	rad_assert(size < 512);
	vp = radius_paircreate(request, vps, PW_HOME_SERVER_POOL, 0);
	vp->vp_strvalue = talloc_strdup(vp, pname);

	vp = radius_paircreate(request, vps, PW_DYNAMIC_POOL_HOST_NAME, 0);
	vp->vp_strvalue = talloc_strdup(vp, owner);

	vp = radius_paircreate(request, vps, PW_DYNAMIC_POOL_WEIGHT, 0);
	vp->vp_integer = weight;

	vp = radius_paircreate(request, vps, PW_DYNAMIC_POOL_IP_ADDRESS, 0);
	vp->vp_ipaddr = ipv4;
	vp = radius_paircreate(request, vps, PW_DYNAMIC_POOL_IPV6_ADDRESS, 0);
	if (ipv6) {
		vp->vp_ipv6addr = *ipv6;
	}
	else {
		vp->vp_ipv6addr = in6addr_any;
	}

	/* TODO: glean this from inst->srv_proto and whatnot */
	vp = radius_paircreate(request, vps, PW_DYNAMIC_POOL_IP_PROTOCOL, 0);
	vp->vp_integer = 6;

	vp = radius_paircreate(request, vps, PW_DYNAMIC_POOL_PORT, 0);
	vp->vp_integer = port;
}

static void pool_map(rlm_ddds_t *inst, ddds_top_t *top, int pidx, REQUEST *request)
{
	int idx;
	unsigned int accum = 0;
	int weight_sum = 0;
	int len_sum = 0;

	/*
	 * If a use case arises, we will need to rework this.
	 */
	rad_assert(MAX_SRVS < 128);

	/* Find aggregate values */
	for (idx = pidx; idx >= 0; idx--) {
		if (top->state.sprios[idx] != top->state.sprios[pidx]) {
			break;
		}
		/* Skip over any entries that failed resolution */
		if (top->state.aaaalens[idx] <= 0
		    && top->state.alens[idx] <= 0) {
			continue;
		}
		/*
		 *	RFC2782 gives a somewhat defective algorithm for
		 *	ensuring weight 0 gets hit sometimes, but rarely.
		 *
		 *	We simply add one to each weight to get a similar
		 *	effect.  We can do this because our ints have bits
		 *	to spare.  It isn't perfect for tiny weights but
		 *	most DNS admins know to use lumps of 10 or so.
		 */
		weight_sum += top->state.sweights[idx] + 1;

		if (top->state.alens[idx] > 0) {
			len_sum += top->state.alens[idx];
		}
		if (top->state.aaaalens[idx] > 0) {
			len_sum += top->state.aaaalens[idx];
		}
	}
	if (!len_sum || !weight_sum) {
		/* This entire priority rung failed resolution. */
		return;
	}
	rad_assert(weight_sum > 0);
	rad_assert(weight_sum <= MAX_SRVS * 65536);

	/* TODO: Is it worth it to merge dups? */
	for (idx = pidx; idx >= 0; idx--) {
		uint64_t q;
		int aidx;
		int len;

		if (top->state.sprios[idx] != top->state.sprios[pidx]) {
			break;
		}
		/* Skip over any entries that failed resolution */
		len = top->state.alens[idx];
		if (len < 0) {
			len = top->state.aaaalens[idx];
		}
		else {
			if (top->state.aaaalens[idx] > 0) {
				len += top->state.aaaalens[idx];
			}
		}
		if (len <= 0) {
			continue;
		}

		q = 4294967296;
		q *= top->state.sweights[idx] + 1;
		q /= len;
		q /= weight_sum;
		for (aidx = 0; aidx < top->state.alens[idx]; aidx++) {
			accum += q;
			if (--len_sum < 1) {
				accum = 4294967295;
			}
			map_avp(inst, top, pidx, accum,
				top->state.as[top->state.aidxs[idx]
					      + aidx].s_addr,
				NULL,
				top->state.sports[idx],
				top->state.snames[idx],
				request);
		}
		for (aidx = 0; aidx < top->state.aaaalens[idx]; aidx++) {
			accum += q;
			if (--len_sum < 1) {
				accum = 4294967295;
			}
			map_avp(inst, top, pidx, accum, INADDR_ANY,
				&top->state.aaaas[top->state.aaaaidxs[idx]
						  + aidx],
				top->state.sports[idx],
				top->state.snames[idx],
				request);
		}
	}
}

static void top_map(rlm_ddds_t *inst, ddds_top_t *top, REQUEST *request)
{
 	VALUE_PAIR      *vp, **vps;
	int pool;
	int idx;

	/* Handle synthetic SRV */
	if (top->state.sprios[0] == -1) {
		top->state.sweights[0] = 0;
		pool_map(inst, top, 0, request);
		return;
	}
	/* Sorted already by prio/weight in reverse order.  Find end. */
	for (idx = 0; idx < MAX_SRVS; idx++) {
		if (top->state.sports[idx] == -1) {
			break;
		}
	}
	if (idx >= MAX_SRVS) {
		/* No results. */
		return;
	}
	pool = 65536;
	while (idx >= 0) {
		if (pool != top->state.sprios[idx]) {
		  pool = top->state.sprios[idx];
		  pool_map(inst, top, idx, request);
		}
		idx--;
	}

	vps = &request->config_items;

	for (idx = 0; idx < MAX_NAPTRS; idx++) {
		if (!(top->state.nflags[idx] & NAPTR_USED)) {
			break;
		}
		if (top->state.nflags[idx] & NAPTR_DIVE) {
			vp = radius_paircreate(request, vps,
					       PW_DYNAMIC_POOL_ALIAS1, 0);
			vp->vp_strvalue =
				talloc_strdup(vp, top->state.nnames[idx]);
		}
	}

	vp = radius_paircreate(request, vps, PW_DYNAMIC_POOL_ALIAS2, 0);
	vp->vp_strvalue = talloc_strdup(vp, top->state.srv_cname);
}

/*
 * Kick off a DDDS resolution, or use a cached one.
 */
static rlm_rcode_t mod_autz(void *instance, REQUEST *request)
{
	struct tuple_inst_top tuple;
	rad_listen_t *l;
	rlm_ddds_t *inst = instance;
	ddds_top_t *top;
	char idn[254];
	struct timeval now;
	int new = 0;
	int try;

	/* Hackery to find an unbound client.  Probably will change. */
	if (!inst->ubctx) {
		fr_ipaddr_t zeroed_ipaddr;

		memset(&zeroed_ipaddr, 0, sizeof(zeroed_ipaddr));

		/* Find an unbound listener.  Just to get the list really. */
		l = listener_find_byipaddr(&zeroed_ipaddr, 0, IPPROTO_MAX);
		while (l) {
			unbound_listen_t *u;
			if (l->type != RAD_LISTEN_UNBOUND) {
				l = l->next;
				continue;
			}
			u = l->data;
			if (strcmp(u->name2, inst->unbound)) {
				l = l->next;
				continue;
			}
			inst->ubctx = u->ub;
			l = l->next;
		}
		if (!inst->ubctx) return RLM_MODULE_FAIL;
	}

	if (radius_xlat(idn, 254, request, inst->wkr_xlat, NULL, NULL)
	    < 1) {
		return RLM_MODULE_FAIL;
	}

	tuple.inst = inst;
	tuple.top = top = top_alloc(inst, idn);
	if (!top) {
		return RLM_MODULE_FAIL;
	}

	gettimeofday(&now, NULL);

	/* Check if we have recently worked on this domain owner */
	if (!rbtree_lock_finddata(inst->tops, top, top_copy_cb,
				  &tuple, ddds_top_compare_query)) {
		/*
		 *	We need to start a new top.
		 */
		if (!rbtree_insert(inst->tops, top)) {
			ddds_top_t const *dup;

			/* Apparently someone else did as well. */
			dup = rbtree_lock_finddata(inst->tops, top,
						   top_copy_cb,
						   &tuple,
						   ddds_top_compare_query);
			if (!dup) {
				/* Or not. Hard to see this happenning ever. */
			hosed:
				ERROR("FIXME: spurious rbtree activity");
				return RLM_MODULE_FAIL;
			}
		} else {
			/* Create a new copy, we gave ours to the tree. */
			tuple.top = top = top_alloc(inst, idn);
			if (!top) {
				return RLM_MODULE_FAIL;
			}
			/* This should not have gotten deleted from tree. */
			if (!rbtree_lock_finddata(inst->tops, top,
						  top_copy_cb, &tuple,
						  ddds_top_compare_query)) {
			      goto hosed;
			}
			new = 1;
		}
	}

	/*
	 *	Now *top is a nonvolatile copy of what was in the rbtree, and
	 *	the query has been launched unless it was complete and recent,
	 *	with two exceptions:
	 *
	 *	1) if the query was in flight already.  Just in
	 *	case something wedged up, which should not happen even with
	 *	SERVFAILs, we consider re-launching queries.
	 *
	 *	2) The query is brand new.  We could have just created it
	 *	expired, but the logs read better if we do it by hand.
	 *
	 *	Handle those cases.
	 */
	if (top->state.in_flight &&
	    now.tv_sec - top->state.last_launch > inst->deadbeat_ttl) {
		/* Queries have stalled without completion. */
		DEBUG("Retrying stalled DDDS for '%s'", top->query.owner);
		rbtree_lock_finddata(inst->tops, top,
				     top_ask_cb, inst,
				     ddds_top_compare_query);
	}
	else if (!top->state.in_flight && new) {
		DEBUG2("Starting new DDDS lookup for '%s'.", top->query.owner);
		rbtree_lock_finddata(inst->tops, top,
                                     top_ask_cb, inst,
                                     ddds_top_compare_query);
	}

	/* Perhaps wait for results. */
	try = 0;
	do {
		useconds_t tries[6] =
			{ 100000, 100000, 200000, 400000, 700000, 1500000 };

		rbtree_lock_finddata(inst->tops, top, top_copy_cb, &tuple,
                                     ddds_top_compare_query);
		if (!top->state.in_flight || try >= 6) {
			break;
		}
		/*
		 *	So we wait.  Take another look at 0.1, 0.2, 0.4, 0.8,
		 *	1.5, and 3 seconds, then give up.  3 seconds is the
		 *	limit specified in draft-ietf-radext-dynamic-discovery.
		 */
		DEBUG("Waiting %i us", tries[try]);
		usleep(tries[try]);
		try++;
		/* In case we do not have threads */
		ub_process(inst->ubctx);
	} while (1);
	/* TODO: review/choose appropriate RLM_MODULE_ return codes. */
	if (try >= 6) {
		/* We cannot use results while DDDS has packets in flight. */
		DEBUG("DDDS for %s was too slow.", top->query.owner);
		return RLM_MODULE_NOOP;
	}
	top_map(inst, top, request);
	debug_pair_list(request->config_items);
	return RLM_MODULE_UPDATED;
}

/* Called periodically to check for expiring DNS TTLs or stalls */
static void *walk_tops_loop(void *handle)
{
	rlm_ddds_t *inst = handle;
	while(1) {
		rbtree_walk(inst->tops, InOrder, top_check, inst);
		DEBUG("TICK");
		usleep(10000000);
	}
	return NULL;
}

static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_ddds_t *inst = instance;

	if (strlen(inst->srv_proto) > 15) {
		ERROR("srv_proto longer than 15 characters");
		return -1;
	}
	if (strlen(inst->srv_service) > 15) {
		ERROR("srv_service longer than 15 characters");
		return -1;
	}

	if (strlen(inst->naptr_proto) > 31) {
		ERROR("naptr_proto longer than 31 characters");
		return -1;
	}
	if (strlen(inst->naptr_service) > 31) {
		ERROR("naptr_service longer than 31 characters");
		return -1;
	}

	if (!(inst->want_v4 || inst->want_v6)) {
		ERROR("At least one of ipv4/ipv6 must be chosen");
		return -1;
	}
	if (!(inst->want_naptr || inst->want_srv || inst->fallback)) {
		ERROR("At least one of naptr/srv/fallback must be chosen");
		return -1;
	}

	if (!strlen(inst->unbound)) {
		ERROR("Must specify the subname of an unbound listener");
		return -1;
	}

	if (inst->min_ttl < 15) {
		ERROR("Reducing min_ttl this low could cause DNS floods");
	}

	if (inst->max_ttl < inst->min_ttl) {
		ERROR("Maximum TTL must be more than minimum TTL");
	}

	if (inst->expiry_ttl < 600) {
		ERROR("DDDS expiry time inadvisably low");
	}

	if (inst->negative_ttl < inst->min_ttl) {
		ERROR("Default negative TTL smaller than minimum TTL");
	}

	if (inst->deadbeat_ttl < inst->min_ttl) {
		ERROR("Deadbeat TTL smaller than minimum TTL");
	}

	inst->name2 = talloc_strdup(inst, cf_section_name2(conf));

	inst->tops = rbtree_create(ddds_top_compare_query, ddds_top_free,
				   RBTREE_FLAG_LOCK);
	if (!inst->tops) {
		return -1;
	}

	/* TODO: find a way to join the main event loop. */
	pthread_create(&inst->pthread, 0, walk_tops_loop, inst);

	return 0;
}

static int mod_detach(void *instance)
{
	rlm_ddds_t *inst = instance;

	rbtree_free(inst->tops);

	return 0;
}

module_t rlm_ddds = {
	RLM_MODULE_INIT,
	"ddds",
	RLM_TYPE_THREAD_UNSAFE,		/* type.  For now. */
	sizeof(rlm_ddds_t),
	mod_config,			/* CONF_PARSER */
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
	{
		NULL,		 	/* authentication */
		mod_autz,		/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
#ifdef WITH_COA
		, NULL,
		NULL
#endif
	},
};
