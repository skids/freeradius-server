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
RCSIDH(rlm_ddds_rbtree_h, "$Id$")

#include <freeradius-devel/radiusd.h>

struct shim_ctx {
	int (*Compare)(void const *, void const *);
	void const *KeyData;
	void *realctx;
	int (*realcallback)(void *, void *);
};

void const*rbtree_lock_finddata(rbtree_t *tree, void const *Data, int (*callback)(void *, void *), void *context, int (*Compare)(void const *, void const *));
