/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2020-2025 OVH SAS

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

#include <errno.h>

#include "metautils.h"

struct service_update_policies_s
{
	GMutex lock;
	GTree *tree_elements;
};

/*! @private */
struct element_s
{
	gchar *tagname;
	gchar *tagvalue;
	guint replicas;
	guint reqdist;
	enum service_update_policy_e howto_update;
};

/*! @private */
struct kv_s
{
	const gchar *name;
	enum service_update_policy_e policy;
};

/* ------------------------------------------------------------------------- */

static void
_element_clean_tag(struct element_s *e)
{
	if (!e)
		return ;
	oio_str_clean (&e->tagname);
	oio_str_clean (&e->tagvalue);
}

static void
_element_destroy(struct element_s *e)
{
	if (!e)
		return;
	_element_clean_tag(e);
	g_free(e);
}

static GError*
_get_from_array(const gchar *name, struct kv_s *pkv,
		enum service_update_policy_e *result)
{
	if (name && *name && pkv) {
		for (; pkv->name ;pkv++) {
			if (!strcmp(pkv->name, name)) {
				*result = pkv->policy;
				return NULL;
			}
		}
	}

	return NEWERROR(0, "Invalid policy");
}

static GError*
_get_by_name(const gchar *name, enum service_update_policy_e *result)
{
	static struct kv_s byname[] = {
		{"KEEP", SVCUPD_KEEP},
		{"REPLACE", SVCUPD_REPLACE},
		{"APPEND", SVCUPD_APPEND},
		{NULL, SVCUPD_KEEP},
	};

	return _get_from_array(name, byname, result);
}

static GTree *
_new_tree(void)
{
	return g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free,
			(GDestroyNotify)_element_destroy);
}

/* ------------------------------------------------------------------------- */

struct service_update_policies_s *
service_update_policies_create(void)
{
	struct service_update_policies_s *result = g_malloc0(sizeof(*result));
	g_mutex_init(&result->lock);
	result->tree_elements = _new_tree();
	return result;
}

void
service_update_policies_destroy(struct service_update_policies_s *pol)
{
	if (!pol)
		return;

	g_mutex_clear(&pol->lock);

	if (pol->tree_elements) {
		g_tree_destroy(pol->tree_elements);
		pol->tree_elements = NULL;
	}

	g_free(pol);
}

static enum service_update_policy_e
service_howto_update2(struct service_update_policies_s *pol,
		const struct hashstr_s *htype)
{
	struct element_s *el;
	enum service_update_policy_e policy;

	EXTRA_ASSERT(pol != NULL);
	EXTRA_ASSERT(htype != NULL);

	policy = SVCUPD_KEEP;
	g_mutex_lock(&pol->lock);
	if (NULL != (el = g_tree_lookup(pol->tree_elements, htype)))
		policy = el->howto_update;
	g_mutex_unlock(&pol->lock);

	return policy;
}

enum service_update_policy_e
service_howto_update(struct service_update_policies_s *pol, const gchar *type)
{
	const gchar *dot;
	struct hashstr_s *htype;

	EXTRA_ASSERT(pol != NULL);
	EXTRA_ASSERT(type != NULL);

	if (NULL != (dot = strchr(type, '.')))
		HASHSTR_ALLOCA_LEN(htype, type, (dot-type));
	else
		HASHSTR_ALLOCA(htype, type);

	return service_howto_update2(pol, htype);
}

static gboolean
_service_update_policies_dumper(gpointer k, gpointer v, gpointer u) {
	register GString *gstr = u;
	register struct element_s *el = v;

	if (gstr->len > 0)
		g_string_append_c(gstr, ';');
	g_string_append_len(gstr, hashstr_str(k), hashstr_len(k));
	g_string_append_c(gstr, '=');
	g_string_append(gstr, service_update_policy_to_string(el->howto_update));
	g_string_append_printf(gstr, "|%u|%u", el->replicas, el->reqdist);
	if (el->tagname && el->tagvalue)
		g_string_append_printf(gstr, "|%s=%s", el->tagname, el->tagvalue);
	return FALSE;
}

gchar *
service_update_policies_dump(struct service_update_policies_s *pol)
{
	GString *out = g_string_sized_new(128);
	g_mutex_lock(&pol->lock);
	g_tree_foreach(pol->tree_elements, _service_update_policies_dumper, out);
	g_mutex_unlock(&pol->lock);

	return g_string_free(out, FALSE);
}

const char *
service_update_policy_to_string (enum service_update_policy_e p)
{
	switch (p) {
		case SVCUPD_KEEP:
			return "KEEP";
		case SVCUPD_APPEND:
			return "APPEND";
		case SVCUPD_REPLACE:
			return "REPLACE";
		default:
			return "***invalid***";
	}
}

/* ------------------------------------------------------------------------- */

static struct element_s *
configure_kv(GTree *tree, const gchar *name,
		enum service_update_policy_e policy)
{
	struct element_s *el;
	struct hashstr_s *hname;

	HASHSTR_ALLOCA(hname, name);

	el = g_tree_lookup(tree, hname);

	if (!el) {
		el = g_malloc0(sizeof(*el));
		el->replicas = 1;
		el->reqdist = 0;
		g_tree_insert(tree, hashstr_dup(hname), el);
	}

	el->howto_update = policy;
	return el;
}

static  GError*
configure_strkv(GTree *tree, gchar *name)
{
	enum service_update_policy_e policy = SVCUPD_KEEP;
	gchar *value, *tagname = NULL, *tagvalue = NULL;
	guint step, reqdist = 0, replicas = 1;

	if (!(value = strchr(name, '=')))
		return NEWERROR(0, "Invalid value");

	*(value ++) = '\0';

	if (!*name)
		return NEWERROR(0, "Empty name");
	if (!*value)
		return NEWERROR(0, "Empty value");

	// Look for arguments
	gchar *p, *next;
	for (p=value,step=0; p && *p ;step++,p=next) {
		gchar *eq, *end;
		guint64 r64;

		// Find the argument's end
		if (NULL != (next = strchr(p, '|')))
			*(next++) = '\0';
		if (*p == '|')
			continue;

		switch (step) {
			case 0: // POLNAME
				break;
			case 1: // REPLICAS
				end = NULL;
				r64 = g_ascii_strtoull(p, &end, 10);
				if (r64 == G_MAXUINT64 && errno == ERANGE)
					return NEWERROR(0, "Replicas count overflow");
				if (r64 > 65536)
					return NEWERROR(0, "Replicas count overflow");
				if (!r64 || end == p)
					return NEWERROR(0, "Invalid replicas count (zero not allowed)");
				else if (end && *end != '\0')
					return NEWERROR(0, "Unexpected extra chars in replicas count");
				replicas = r64;
				break;
			case 2: // REQDIST
				end = NULL;
				r64 = g_ascii_strtoull(p, &end, 10);
				if (r64 == G_MAXUINT64 && errno == ERANGE)
					return NEWERROR(0, "Distance overflow");
				if (r64 > 65536)
					return NEWERROR(0, "Distance overflow");
				if (end && *end != '\0')
					return NEWERROR(0, "Unexpected extra chars in distance");
				reqdist = r64;
				break;
			case 3: // TAG FILTER
				if (NULL != (eq = strchr(p, '='))) {
					*(eq++) = '\0';
					tagname = p;
					tagvalue = eq;
				}
				break;
			default: // ignored
				break;
		}
	}

	GError *err;
	if (NULL != (err = _get_by_name(value, &policy)))
		return err;

	struct element_s *el = configure_kv(tree, name, policy);
	_element_clean_tag(el);
	if (tagname)
		el->tagname = g_strdup(tagname);
	if (tagvalue)
		el->tagvalue = g_strdup(tagvalue);
	el->replicas = replicas;
	el->reqdist = reqdist;

	return NULL;
}

static GError*
configure_newtree(GTree *tree, const gchar *cfg)
{
	const gchar *start = cfg;

	while (start && *start) {
		GError *err;
		gchar *str;
		const gchar *end;

		if (!(end = strchr(start, ';'))) {
			str = g_strstrip(g_strdup(start));
			start = NULL;
		}
		else {
			str = g_strstrip(g_strndup(start, end-start));
			start = end + 1;
		}

		err = *str ? configure_strkv(tree, str) : NULL;
		g_free(str);
		if (NULL != err)
			return err;
	}

	return NULL;
}

GError*
service_update_reconfigure(struct service_update_policies_s *pol,
		const gchar *cfg)
{
	GError *err;
	GTree *newtree, *oldtree;

	newtree = _new_tree();

	err = configure_newtree(newtree, cfg);
	if (NULL != err) {
		g_tree_destroy(newtree);
		return err;
	}

	g_mutex_lock(&pol->lock);
	oldtree = pol->tree_elements;
	pol->tree_elements = newtree;
	g_mutex_unlock(&pol->lock);

	if (oldtree)
		g_tree_destroy(oldtree);
	return NULL;
}

static guint
service_howmany_replicas2(struct service_update_policies_s *pol,
		struct hashstr_s *htype)
{
	struct element_s *el;
	guint count = 1;

	EXTRA_ASSERT(pol != NULL);
	EXTRA_ASSERT(htype != NULL);

	if (pol && htype) {
		g_mutex_lock(&pol->lock);
		if (NULL != (el = g_tree_lookup(pol->tree_elements, htype)))
			count = el->replicas;
		g_mutex_unlock(&pol->lock);
	}

	return count;
}

guint
service_howmany_replicas(struct service_update_policies_s *pol,
		const gchar *type)
{
	struct hashstr_s *htype = NULL;

	EXTRA_ASSERT(pol != NULL);
	EXTRA_ASSERT(type != NULL);

	if (pol && type) {
		const gchar *dot;
		if (NULL != (dot = strchr(type, '.')))
			HASHSTR_ALLOCA_LEN(htype, type, (dot-type));
		else
			HASHSTR_ALLOCA(htype, type);
	}

	return service_howmany_replicas2(pol, htype);
}

gboolean
service_update_tagfilter2(struct service_update_policies_s *pol,
		const struct hashstr_s *htype, gchar **pname, gchar **pvalue)
{
	struct element_s *el;
	gboolean rc = FALSE;

	EXTRA_ASSERT(pol != NULL);
	EXTRA_ASSERT(htype != NULL);

	g_mutex_lock(&pol->lock);
	if (NULL != (el = g_tree_lookup(pol->tree_elements, htype))) {
		if (el->tagname) {
			if (pname)
				oio_str_replace (pname, el->tagname);
			if (pvalue)
				oio_str_replace (pvalue, el->tagvalue);
			rc = TRUE;
		}
	}
	g_mutex_unlock(&pol->lock);

	return rc;
}

gboolean
service_update_tagfilter(struct service_update_policies_s *pol,
		const gchar *type, gchar **pname, gchar **pvalue)
{
	const gchar *dot;
	struct hashstr_s *htype;

	EXTRA_ASSERT(pol != NULL);
	EXTRA_ASSERT(type != NULL);

	if (NULL != (dot = strchr(type, '.')))
		HASHSTR_ALLOCA_LEN(htype, type, (dot-type));
	else
		HASHSTR_ALLOCA(htype, type);

	return service_update_tagfilter2(pol, htype, pname, pvalue);
}

gchar*
m2v2_policy_encode(const gchar* current, const gchar* target)
{
	EXTRA_ASSERT(current != NULL);

	if (target != NULL && g_strcmp0(current, target) != 0) {
		return g_strdup_printf("%s>%s", current, target);
	}
	return g_strdup(current);
}

void
m2v2_policy_decode(const GString* policy, gchar** current, gchar** target)
{
	if (policy == NULL || policy->str == NULL) {
		if (current != NULL) *current = NULL;
		if (target != NULL) *target = NULL;
		return;
	}

	// Find transitional marker index
	gsize i = 0;
	for (i = 0; i < policy->len; ++i) {
		if (policy->str[i] == '>') {
			break;
		}
	}
	if (current != NULL) {
		*current = g_strndup(policy->str, i);
	}

	if (target != NULL) {
		if (i == policy ->len) {
			*target = g_strndup(policy->str, i);
		} else {
			*target = g_strndup(&(policy->str[i + 1]), policy->len - i - 1);
		}
	}
}
