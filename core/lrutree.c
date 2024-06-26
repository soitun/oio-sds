/*
OpenIO SDS core library
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2024 OVH SAS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include "lrutree.h"
#include "tree.h"
#include "oioext.h"
#include "internals.h"

#define REMOVE_NODE(_tree, _node) \
	do { \
		gpointer k = NULL, v = NULL; \
		if (_steal(_tree, &k, &v, _node)) { \
			if (k && _tree->kfree) _tree->kfree(k); \
			if (v && _tree->vfree) _tree->vfree(v); \
		} \
	} while (0);

struct _node_s
{
	RB_ENTRY(_node_s) entry;
	struct _node_s *prev;
	struct _node_s *next;

	gint64 atime;
	gpointer k;
	gpointer v;
};

struct lru_tree_s
{
	GCompareFunc kcmp;
	GDestroyNotify kfree;
	GDestroyNotify vfree;
	guint32 flags;

	gint64 count;

	// Red-Black tree 'by key'
	RB_HEAD(_tree_s, _node_s) base;

	// LRU double-ended queue
	struct _node_s *first;
	struct _node_s *last;
};

/* Nodes handling ---------------------------------------------------------- */

static void
_node_cleanup(struct lru_tree_s *lt, struct _node_s *node)
{
	if (lt->vfree && node->v)
		lt->vfree(node->v);
	if (lt->kfree && node->k)
		lt->kfree(node->k);
	node->k = node->v = NULL;
}

static int
_node_compare(gpointer u, const struct _node_s *n0, const struct _node_s *n1)
{
	struct lru_tree_s *lt = u;
	return lt->kcmp(n0->k, n1->k);
}

static struct _node_s*
_node_create(gpointer k, gpointer v)
{
	struct _node_s *n = g_slice_new0(struct _node_s);
	n->k = k;
	n->v = v;
	return n;
}

static void
_node_destroy(struct lru_tree_s *lt, struct _node_s *node)
{
	_node_cleanup(lt, node);
	g_slice_free(struct _node_s, node);
}

static void
_node_update(struct lru_tree_s *lt, struct _node_s *node, gpointer k,
		gpointer v)
{
	_node_cleanup(lt, node);
	node->k = k;
	node->v = v;
}

static void
_node_deq_extract(struct lru_tree_s *lt, struct _node_s *node)
{
	// special case if the node is first or last
	if (lt->first == node)
		lt->first = node->next;
	if (lt->last == node)
		lt->last = node->prev;

	// Now do local ring removal
	if (node->prev)
		node->prev->next = node->next;
	if (node->next)
		node->next->prev = node->prev;

	node->next = node->prev = NULL;
}

static void
_node_deq_push_front(struct lru_tree_s *lt, struct _node_s *node)
{
	if (!lt->first) {
		node->prev = node->next = NULL;
		lt->first = lt->last = node;
	}
	else {
		node->prev = NULL;
		node->next = lt->first;
		lt->first->prev = node;
		lt->first = node;
	}
}

/* Red-Black tree handling ------------------------------------------------- */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

RB_PROTOTYPE_STATIC(_tree_s, _node_s, entry, _node_compare);

RB_GENERATE_STATIC(_tree_s, _node_s, entry, _node_compare);

#pragma GCC diagnostic pop

/* Main structure handling ------------------------------------------------- */

struct lru_tree_s*
lru_tree_create(GCompareFunc cmp, GDestroyNotify kfree, GDestroyNotify vfree,
		guint32 options)
{
	struct lru_tree_s *lt = g_slice_new0(struct lru_tree_s);
	lt->kcmp = cmp;
	lt->kfree = kfree;
	lt->vfree = vfree;
	lt->flags = options;
	RB_INIT(&(lt->base));

	return lt;
}

void
lru_tree_destroy(struct lru_tree_s *lt)
{
	if (!lt)
		return;

	while (lt->first) {
		struct _node_s *n = lt->first;
		if (NULL != (lt->first = n->next))
			lt->first->prev = NULL;
		_node_destroy(lt, n);
	}

	g_slice_free(struct lru_tree_s, lt);
}

void
lru_tree_insert(struct lru_tree_s *lt, gpointer k, gpointer v)
{
	struct _node_s fake, *node;

	EXTRA_ASSERT(lt != NULL);
	EXTRA_ASSERT(k != NULL);
	EXTRA_ASSERT(v != NULL);

	fake.k = k;
	if (!(node = RB_FIND(_tree_s, lt, &(lt->base), &fake))) {
		node = _node_create(k, v);
		RB_INSERT(_tree_s, lt, &(lt->base), node);
		++ lt->count;
		_node_deq_push_front(lt, node);
		node->atime = oio_ext_monotonic_time();
	}
	else {
		_node_update(lt, node, k, v);
		if (!(lt->flags & LTO_NOUTIME)) {
			_node_deq_extract(lt, node);
			_node_deq_push_front(lt, node);
			node->atime = oio_ext_monotonic_time();
		}
	}
}

gpointer
lru_tree_get(struct lru_tree_s *lt, gconstpointer k)
{
	EXTRA_ASSERT(lt != NULL);
	EXTRA_ASSERT(k != NULL);

	const struct _node_s fake = {.k = (gpointer)k };
	struct _node_s *node = RB_FIND(_tree_s, lt, &(lt->base), &fake);

	if (!node)
		return NULL;

	if (!(lt->flags & LTO_NOATIME)) {
		_node_deq_extract(lt, node);
		_node_deq_push_front(lt, node);
		node->atime = oio_ext_monotonic_time();
	}

	return node->v;
}

gboolean
lru_tree_remove(struct lru_tree_s *lt, gconstpointer k)
{
	struct _node_s fake, *node;

	EXTRA_ASSERT(lt != NULL);
	EXTRA_ASSERT(k != NULL);

	fake.k = (gpointer) k;
	if (!(node = RB_FIND(_tree_s, lt, &(lt->base), &fake)))
		return FALSE;

	RB_REMOVE(_tree_s, &(lt->base), node);
	_node_deq_extract(lt, node);
	-- lt->count;

	_node_destroy(lt, node);
	return TRUE;
}

static gboolean
_steal(struct lru_tree_s *lt, gpointer *pk, gpointer *pv, struct _node_s *node)
{
	EXTRA_ASSERT(pk != NULL);
	EXTRA_ASSERT(pv != NULL);

	if (!node)
		return FALSE;

	// steal the values
	*pk = node->k;
	*pv = node->v;

	node->k = node->v = NULL;
	RB_REMOVE(_tree_s, &(lt->base), node);
	_node_deq_extract(lt, node);
	_node_destroy(lt, node);
	-- lt->count;

	return TRUE;
}

gpointer
lru_tree_steal(struct lru_tree_s *lt, gconstpointer k)
{
	struct _node_s fake, *node;

	EXTRA_ASSERT(lt != NULL);
	EXTRA_ASSERT(k != NULL);

	fake.k = (gpointer) k;
	if (!(node = RB_FIND(_tree_s, lt, &(lt->base), &fake)))
		return NULL;

	gpointer pk = NULL, pv = NULL;
	_steal(lt, &pk, &pv, node);
	if (lt->kfree && pk)
		lt->kfree(pk);

	return pv;
}

void
lru_tree_foreach(struct lru_tree_s *lt, GTraverseFunc h, gpointer hdata)
{
	EXTRA_ASSERT(lt != NULL);
	EXTRA_ASSERT(h != NULL);

	for (struct _node_s *node = lt->first; node; node = node->next) {
		if (h(node->k, node->v, hdata))
			return;
	}
}

gpointer
lru_tree_get_oldest_key(struct lru_tree_s *lt){
	if (lt->last)
		return lt->last->k;
	return NULL;
}

gint64
lru_tree_count(struct lru_tree_s *lt)
{
	EXTRA_ASSERT(lt != NULL);
	return lt->count;
}

static void
_remove_last(struct lru_tree_s *lt)
{
	REMOVE_NODE(lt, lt->last);
}

guint
lru_tree_remove_older (struct lru_tree_s *lt, gint64 oldest)
{
	EXTRA_ASSERT(lt != NULL);
	guint removed = 0;
	while (lt->last && lt->last->atime < oldest) {
		_remove_last(lt);
		++ removed;
	}
	return removed;
}

guint
lru_tree_remove_exceeding (struct lru_tree_s *lt, guint count)
{
	EXTRA_ASSERT(lt != NULL);
	guint removed = 0;
	while (lt->last && lt->count > count) {
		_remove_last(lt);
		++ removed;
	}
	return removed;
}

guint
lru_tree_remove_matching(struct lru_tree_s *lt,
		GTraverseFunc filter, gpointer fdata)
{
	EXTRA_ASSERT(lt != NULL);
	guint removed = 0;
	for (struct _node_s *node = lt->first; node; ) {
		if (filter(node->k, node->v, fdata)) {
			struct _node_s *to_del = node;
			node = node->next;
			REMOVE_NODE(lt, to_del);
			removed++;
		} else {
			node = node->next;
		}
	}
	return removed;
}

void
lru_tree_foreach_older_steal(struct lru_tree_s *lt,
		GTraverseFunc func, gpointer hdata, gint64 oldest, guint max)
{
	EXTRA_ASSERT(lt != NULL);
	while (lt->last && lt->last->atime < oldest && max-- > 0) {
		gpointer key = NULL, val = NULL;
		if (_steal(lt, &key, &val, lt->last)) {
			func(key, val, hdata);
		}
	}
}
