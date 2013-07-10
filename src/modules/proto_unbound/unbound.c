/*
 * unbound.c	Handle embedded libunbound DNS clients.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2013  The FreeRADIUS server project
 * Copyright 2013  Brian S. Julin <bjulin@clarku.edu>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <unbound.h>

/*
 * This is a bit of a hack.  The easiest way to get into the unexposed
 * global event loop fdset with minimal changes to the core is to pretend
 * to be a "protocol" -- but we do not actually A) use a socket, as the
 * protocol code expects, or B) actually process any authentication-like
 * requests.  We just need to allow DNS requests to spin through their
 * callback chains in the background.
 *
 * How the core can better accomodate needs like these from modules is up
 * in the air.  Exposing the static "el" from process.c as an extern would
 * be another, albeit anarchistic, way, or event.h could define a way to
 * start a persistant event loop either as a subloop of "el" or as a
 * child thread.  A small advantage to doing it as a "protocol" is that we get
 * to glom onto the config parsing infrastructure for "listen" directives
 * and thus associate ourselves to individual servers.
 */

typedef struct unbound_listen_t {
	listen_socket_t fake_socket;
	struct ub_ctx *ub;
	char const *name2;
} unbound_listen_t;

static int unbound_print(rad_listen_t const *this, char *buffer, size_t bufsize) {
	snprintf(buffer, bufsize,
		 "embedded unbound fd #%i for async DNS responses", this->fd);
	return 0;
}

static int unbound_parse_ctx(CONF_SECTION *cs, rad_listen_t *this)
{
	char const *value = "unbound.conf";
	unbound_listen_t *f;
	struct ub_ctx *ub;
	int res;
	CONF_PAIR *cp = NULL;
	char const *name2 = "unbound";

	if (cf_section_sub_find(cs, "unbound")) {
		cs = cf_section_sub_find(cs, "unbound");
		if (cf_section_name2(cs)) {
			name2 = cf_section_name2(cs);
		}
		cp = cf_pair_find(cs, "filename");
	}

	if (cp) {
		value = cf_pair_value(cp);
		if (!value) {
			cf_log_err_cs(cs, "No unbound config filename given");
			return -1;
		}
	}

        ub = ub_ctx_create();
        if(!ub) {
		return -1;
        }

        /* TODO: Try this out when not threaded; it should fork instead. */
#ifdef HAVE_PTHREAD_H
        res = ub_ctx_async(ub, 1);
#else
        res = ub_ctx_async(ub, 0);
#endif

	/*
	 * TODO: Dealing with the "-s" option will be a problem that
	 * will have to be dealt with by the modules using this, because
	 * entirely different API calls are used for syncronous DNS resolution.
	 */

        if(res) {
        bail:
		ERROR("unbound: %s", ub_strerror(res));
		ub_ctx_delete(ub);
		return -1;
        }

        /*
	 * TODO: unbound not very graceful when ! -e unbound.conf
         * It lets the thread output the "file not found" error
         * and then just returns "syntax error" in the ub_strerror,
         * then the thread does not clean up well.
         */
	res = ub_ctx_config(ub, value);
	if (res) {
		goto bail;
	}

        /*
	 * TODO: set unbound logging dest to match rest of server,
	 * unless it was explicitly specified in the above conf.
	 * That is, assuming we can glean that from ub_ctx_get_option
	 * or maybe we can use ub_ctx_set_option beforehand and the
	 * config file will override it.
	 */

	this->fd = ub_fd(ub);
	if (this->fd < 0) {
		goto bail;
	}

	f = this->data;
	f->ub = ub;
	f->name2 = name2;

	/* Fill out sock to avoid problems with e.g. listener_find_byipaddr */
	f->fake_socket.proto = IPPROTO_MAX;

	return 0;
}

static void unbound_free_ctx(rad_listen_t *this)
{
	unbound_listen_t *f = (unbound_listen_t *)this->data;
	ub_ctx_delete((struct ub_ctx *)f->ub);
	talloc_free(this->data);
}

/*
 *	Run callbacks initiated by a libunbound client context.
 */
static int unbound_process(rad_listen_t *this)
{
	unbound_listen_t *f = (unbound_listen_t *)this->data;
	struct ub_ctx *ctx = f->ub;
	int err;

	err = ub_process(ctx);
	if (err) {
		ERROR("Unbound error: ub_process: %s", ub_strerror(err));
		return 0;
	}
	return 1;
}

fr_protocol_t proto_unbound = {
	RLM_MODULE_INIT,
	"unbound",
	sizeof(unbound_listen_t),
	NULL,
	unbound_parse_ctx,
	unbound_free_ctx,
	unbound_process,
	NULL,
	unbound_print,
	NULL,
	NULL
};
