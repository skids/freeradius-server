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
 * @brief Proof of concept implementation of draft-ietf-radext-dynamic-discovery
 *
 * @copyright 2013  Brian S. Julin <bjulin@clarku.edu>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <unbound.h>

/*
 *      Structure for module configuration
 */
typedef struct rlm_ddds_t {
        char const *realm_encode_xlat;
} rlm_ddds_t;

/*
 *      A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER mod_config[] = {
	{"realm_encode_xlat", PW_TYPE_STRING, offsetof(rlm_ddds_t, realm_encode_xlat), NULL, "idn" },
	{ NULL, -1, 0, NULL, NULL }
};

/*
 *      Stub to test with
 */
static rlm_rcode_t mod_autz(void *instance, REQUEST *request)
{
	rlm_ddds_t *inst = instance;

	radlog_request(L_DBG_LVL_1, L_INFO, request, "got:");
	vp_listdebug(request->config_items);

	return RLM_MODULE_NOOP;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_ddds_t *inst = instance;

	return 0;
}

module_t rlm_ddds = {
	RLM_MODULE_INIT,
	"ddds",
	RLM_TYPE_THREAD_UNSAFE,		/* type.  For now. */
	sizeof(rlm_ddds_t),
	mod_config,			/* CONF_PARSER */
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
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
