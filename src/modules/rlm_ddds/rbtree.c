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
 * @file rbtree.c
 * @brief Hackery emulating a new rbtree function ddds would use
 *
 * @copyright 2013  Brian S. Julin <bjulin@clarku.edu>
 */
RCSID("$Id$")

#include "rbtree.h"
#include <freeradius-devel/radiusd.h>

/*
 *	Find a data item and perform a callback on it while the rbtree is
 *	locked, then unlock the rbtree.
 *
 *	We emulate this using the available rbtree_walk function.  Could be
 *	done more efficiently and provided in libradius.
 *
 *	Still return the data, to preserve API look and feel.
 */

static int shim_callback(void *context, void *Data)
{
	struct shim_ctx *ctx = context;
	if (ctx->Compare(ctx->KeyData, Data)) return 0;

	/* Found */
	ctx->realcallback(Data, ctx->realctx);
	ctx->KeyData = Data;
	return 1;
}

/*
 *	We need Compare passed in because rbtree_t is opaque here.
 */
void const*rbtree_lock_finddata(rbtree_t *tree, void const *Data, int (*callback)(void *, void *), void *context, int (*Compare)(void const *, void const *))
{
  	struct shim_ctx ctx;

	ctx.Compare = Compare;
        ctx.KeyData = Data;
        ctx.realctx = context;
        ctx.realcallback = callback;

	if (rbtree_walk(tree, PreOrder, shim_callback, &ctx)) {
		return ctx.KeyData;
	}
	return NULL;
}

/*
 *	TODO: we also have need of a version of rbtree_walk that allows us
 *	to delete the current node as we walk (and continue walking
 *	afterwards) based on the return value of the callback.
 */
