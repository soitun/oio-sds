/*
OpenIO SDS core library
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

#include <core/oiovar.h>

#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/internals.h>

enum oio_var_type_e {
	OIO_VARTYPE_gboolean,
	OIO_VARTYPE_guint,
	OIO_VARTYPE_guint32,
	OIO_VARTYPE_guint64,
	OIO_VARTYPE_gint,
	OIO_VARTYPE_gint32,
	OIO_VARTYPE_gint64,
	OIO_VARTYPE_gdouble,
	OIO_VARTYPE_time_t,
	OIO_VARTYPE_string,
};

union oio_var_pointer_u {
	gboolean *b;
	guint *u;
	guint32 *u32;
	guint64 *u64;
	gint *i;
	gint32 *i32;
	gint64 *i64;
	gdouble *d;
	time_t *t;

	gchar *str;
};

union oio_var_default_u {
	gboolean b;
	guint u;
	guint32 u32;
	guint64 u64;
	gint i;
	gint32 i32;
	gint64 i64;
	gdouble d;
	time_t t;

	gchar *str;
};

struct oio_var_record_s {
	/* which C-type is it ? */
	enum oio_var_type_e type : 16;

	/* what physical reality is it? */
	enum oio_var_kind_e kind : 16;

	const char *name;
	const char *description;
	/* actual pointer to the variable */
	union oio_var_pointer_u ptr;
	/* default value when not specified */
	union oio_var_default_u def;
	union oio_var_default_u min;
	union oio_var_default_u max;

	guint8 flag_readonly;
};

static volatile guint var_init = 0;
static GMutex var_lock = {};
static GSList *var_records = NULL;
static GTree *var_aliases = NULL;

void _oio_var_constructor (void);

void __attribute__ ((constructor)) _oio_var_constructor (void) {
	if (g_atomic_int_compare_and_exchange(&var_init, 0, 1)) {
		g_mutex_init(&var_lock);
		var_aliases = g_tree_new_full(oio_str_cmp3, NULL, g_free, g_free);
	}
}

void
oio_var_register_alias(const char *name, const char *alias)
{
	_oio_var_constructor();
	g_mutex_lock(&var_lock);
	g_assert(NULL == g_tree_lookup(var_aliases, alias));
	g_tree_insert(var_aliases, g_strdup(alias), g_strdup(name));
	g_mutex_unlock(&var_lock);
}

static void
_register_record(const struct oio_var_record_s *rec)
{
	_oio_var_constructor();
	g_mutex_lock(&var_lock);
	var_records = g_slist_append(var_records, oio_memdup(rec, sizeof(*rec)));
	g_mutex_unlock(&var_lock);
}

#define DEFINE_REGISTRATION_FUNC(Type,Field) \
void oio_var_register_##Type( \
		Type *p, \
		enum oio_var_kind_e kind, const char *n, const char *d, \
		Type def, Type min, Type max) { \
	struct oio_var_record_s rec = {0}; \
	rec.type = OIO_VARTYPE_##Type; \
	rec.kind = kind; \
	rec.name = n; \
	rec.description = d; \
	rec.ptr.Field = p; \
	*(rec.ptr.Field) = rec.def.Field = def; \
	rec.min.Field = min; \
	rec.max.Field = max; \
	_register_record(&rec); \
}

void
oio_var_register_gboolean(gboolean *p,
		const char *n, const char *d,
		gboolean def)
{
	struct oio_var_record_s rec = {0};
	rec.kind = OIO_VARKIND_size;
	rec.type = OIO_VARTYPE_gboolean;
	rec.name = n;
	rec.description = d;
	rec.ptr.b = p;
	*(rec.ptr.b) = rec.def.b = def;
	_register_record(&rec);
}

void
oio_var_register_string(gchar *p,
		const char *n, const char *descr,
		const gchar *def, gsize limit)
{
	struct oio_var_record_s rec = {0};
	rec.kind = OIO_VARKIND_size;
	rec.type = OIO_VARTYPE_string;
	rec.name = n;
	rec.description = descr;
	rec.ptr.str = p;
	rec.min.u = limit;
	rec.max.u = limit;
	g_strlcpy(rec.ptr.str, def, rec.max.u);
	rec.def.str = (char *) def;
	_register_record(&rec);
}

DEFINE_REGISTRATION_FUNC(guint,u);
DEFINE_REGISTRATION_FUNC(guint32,u32);
DEFINE_REGISTRATION_FUNC(guint64,u64);
DEFINE_REGISTRATION_FUNC(gint,i);
DEFINE_REGISTRATION_FUNC(gint32,i32);
DEFINE_REGISTRATION_FUNC(gint64,i64);
DEFINE_REGISTRATION_FUNC(gdouble,d);
DEFINE_REGISTRATION_FUNC(time_t,t);

static void
_record_set(struct oio_var_record_s *rec, union oio_var_default_u v)
{
	switch (rec->type) {
		case OIO_VARTYPE_gboolean:
			*(rec->ptr.b) = v.b;
			return;
		case OIO_VARTYPE_guint:
			*(rec->ptr.u) = CLAMP(v.u, rec->min.u, rec->max.u);
			return;
		case OIO_VARTYPE_guint32:
			*(rec->ptr.u32) = CLAMP(v.u32, rec->min.u32, rec->max.u32);
			return;
		case OIO_VARTYPE_guint64:
			*(rec->ptr.u64) = CLAMP(v.u64, rec->min.u64, rec->max.u64);
			return;
		case OIO_VARTYPE_gint:
			*(rec->ptr.i) = CLAMP(v.i, rec->min.i, rec->max.i);
			return;
		case OIO_VARTYPE_gint32:
			*(rec->ptr.i32) = CLAMP(v.i32, rec->min.i32, rec->max.i32);
			return;
		case OIO_VARTYPE_gint64:
			*(rec->ptr.i64) = CLAMP(v.i64, rec->min.i64, rec->max.i64);
			return;
		case OIO_VARTYPE_gdouble:
			*(rec->ptr.d) = CLAMP(v.d, rec->min.d, rec->max.d);
			return;
		case OIO_VARTYPE_time_t:
			*(rec->ptr.t) = CLAMP(v.t, rec->min.t, rec->max.t);
			return;
		case OIO_VARTYPE_string:
			g_strlcpy(rec->ptr.str, v.str, rec->max.u);
			return;
	}
	g_assert_not_reached();
}

#define Kilo 1000LL
#define Mega 1000LL * Kilo
#define Giga 1000LL * Mega
#define Tera 1000LL * Giga
#define Peta 1000LL * Tera

#define Kibi 1024LL
#define Mebi 1024LL * Kibi
#define Gibi 1024LL * Mebi
#define Tebi 1024LL * Gibi
#define Pebi 1024LL * Tebi

static gint64
_size_modifier (const char *unit)
{
	static struct _conversion_s {
		const char unit[4];
		const gint64 value;
	} units[] = {
		{"k", Kilo},
		{"M", Mega},
		{"G", Giga},
		{"T", Tera},
		{"P", Peta},
		{"ki", Kibi},
		{"Mi", Mebi},
		{"Gi", Gibi},
		{"Ti", Tebi},
		{"Pi", Pebi},
		{"", 0},
	};
	if (!oio_str_is_set(unit))
		return 1;
	for (struct _conversion_s *pu=units; pu->unit[0] ;++pu) {
		if (!strcmp(pu->unit, unit))
			return pu->value;
	}
	return 0;
}

static gint64
_epoch_modifier(const char *unit)
{
	static struct _conversion_s {
		const char unit[4];
		const gint64 value;
	} units[] = {
		{"s", 1},
		{"m", 60},       /* 60 seconds */
		{"h", 3600},     /* 60 minutes */
		{"d", 86400},    /* 24 hours */
		{"w", 604800},   /* 7 days */
		{"M", 2419200},  /* 4 weeks */
		{"", 0},
	};
	if (!oio_str_is_set(unit))
		return 1;
	for (struct _conversion_s *pu=units; pu->unit[0] ;++pu) {
		if (!strcmp(pu->unit, unit))
			return pu->value;
	}
	return 0;
}

static gint64
_time_modifier(const char *unit)
{
	static struct _conversion_s {
		const char unit[4];
		const gint64 value;
	} units[] = {
		{"ms", G_TIME_SPAN_MILLISECOND},
		{"s", G_TIME_SPAN_SECOND},
		{"m", G_TIME_SPAN_MINUTE},
		{"h", G_TIME_SPAN_HOUR},
		{"d", G_TIME_SPAN_DAY},
		{"w", 7 * G_TIME_SPAN_DAY},
		{"M", 28 * G_TIME_SPAN_DAY},
		{"", 0},
	};
	if (!oio_str_is_set(unit))
		return 1;
	for (struct _conversion_s *pu=units; pu->unit[0] ;++pu) {
		if (!strcmp(pu->unit, unit))
			return pu->value;
	}
	return 0;
}

static gint64
_unit(struct oio_var_record_s *rec, const char *end)
{
	switch (rec->kind) {
		case OIO_VARKIND_time:
			return _time_modifier(end);
		case OIO_VARKIND_size:
			return _size_modifier(end);
		case OIO_VARKIND_epoch:
			return _epoch_modifier(end);
		default:
			g_assert_not_reached();
			return 0;
	}
}

static void
_record_set_to_value(struct oio_var_record_s *rec, const char *value,
		const gboolean readonly)
{
	/* don't touch the value if the variable is already set to readonly
	 * and we are not forcing its value */
	if (!readonly && rec->flag_readonly)
		return;
	rec->flag_readonly = (readonly != 0);

	/* bound the value to the limits configured at the build-time */
	gint64 i64, unit;
	guint64 u64;
	gchar *end = NULL;
	union oio_var_default_u v = rec->def;

	switch (rec->type) {
		case OIO_VARTYPE_gboolean:
			v.b = oio_str_parse_bool(value, rec->def.b);
			break;

		case OIO_VARTYPE_guint:
			u64 = g_ascii_strtoull(value, &end, 10);
			unit = _unit(rec, end);
			if (unit > 0) {
				u64 *= unit;
				v.u = MIN(u64, G_MAXUINT);
			}

			break;
		case OIO_VARTYPE_guint32:
			u64 = g_ascii_strtoull(value, &end, 10);
			unit = _unit(rec, end);
			if (unit > 0) {
				u64 *= unit;
				v.u32 = MIN(u64, G_MAXUINT32);
			}
			break;
		case OIO_VARTYPE_guint64:
			u64 = g_ascii_strtoull(value, &end, 10);
			unit = _unit(rec, end);
			if (unit > 0)
				v.u64 = u64 * unit;
			break;

		case OIO_VARTYPE_gint:
			i64 = g_ascii_strtoll(value, &end, 10);
			unit = _unit(rec, end);
			if (unit > 0) {
				i64 *= unit;
				v.i = CLAMP(i64, G_MININT, G_MAXINT);
			}
			break;
		case OIO_VARTYPE_gint32:
			i64 = g_ascii_strtoll(value, &end, 10);
			unit = _unit(rec, end);
			if (unit > 0) {
				i64 *= unit;
				v.i32 = CLAMP(i64, G_MININT32, G_MAXINT32);
			}
			break;
		case OIO_VARTYPE_gint64:
			i64 = g_ascii_strtoll(value, &end, 10);
			unit = _unit(rec, end);
			if (unit > 0)
				v.i64 = i64 * unit;
			break;

		case OIO_VARTYPE_gdouble:
			v.d = g_ascii_strtod(value, NULL);
			break;

		case OIO_VARTYPE_time_t:
			u64 = g_ascii_strtoull(value, &end, 10);
			unit = _unit(rec, end);
			if (!end || !*end)
				v.t = u64;
			break;

		case OIO_VARTYPE_string:
			v.str = g_alloca(rec->max.u);
			g_snprintf(v.str, rec->max.u, "%s", value);
			break;
	}

	return _record_set(rec, v);
}

static struct oio_var_record_s *
_LOCKED_lookup_record(const gchar *name)
{
	for (GSList *l=var_records; l ;l=l->next) {
		if (!l->data)
			continue;
		struct oio_var_record_s *rec = l->data;
		if (!strcmp(rec->name, name)) {
			return rec;
		}
	}

	return NULL;
}

static gboolean
_LOCKED_value_named_variable(const char *name, const char *value,
		const gboolean readonly)
{
	struct oio_var_record_s *rec = _LOCKED_lookup_record(name);
	if (!rec)
		return FALSE;
	_record_set_to_value(rec, value, readonly);
	return TRUE;
}

static void
_warn_deprecated(const char *name, const char *alias)
{
	GRID_NOTICE("DEPRECATED variable used [%s], consider [%s] instead",
			alias, name);
}

struct _cache_ns_s {
	const char *ns;
	struct oio_cfg_handle_s *cfg;
};

static gboolean
_value_all_aliases_runner(gchar *alias, gchar *name, gpointer i)
{
	struct _cache_ns_s *_cache_ns2 = i;
	gchar *value = oio_cfg_handle_get(_cache_ns2->cfg, _cache_ns2->ns, alias);
	if (value) {
		(void) _LOCKED_value_named_variable(name, value, FALSE);
		_warn_deprecated(name, alias);
		g_free(value);
	}
	return FALSE;
}

static void
_LOCKED_value_all_aliases(struct oio_cfg_handle_s *cfg, const char *ns)
{
	struct _cache_ns_s _cache_ns = {ns, cfg};
	g_tree_foreach(var_aliases,
			(GTraverseFunc)_value_all_aliases_runner, &_cache_ns);
}

static void
_LOCKED_value_all_variables(struct oio_cfg_handle_s *cfg, const char *ns)
{
	for (GSList *l=var_records; l ;l=l->next) {
		if (!l->data)
			continue;
		struct oio_var_record_s *rec = l->data;
		gchar *value = oio_cfg_handle_get(cfg, ns, rec->name);
		if (value) {
			_record_set_to_value(rec, value, FALSE);
			g_free(value);
		}
	}
}

void
oio_var_value_all_with_config(struct oio_cfg_handle_s *cfg, const char *ns)
{
	EXTRA_ASSERT(var_init != 0);
	EXTRA_ASSERT(cfg != NULL);
	EXTRA_ASSERT(ns != NULL);

	g_mutex_lock(&var_lock);
	_LOCKED_value_all_aliases(cfg, ns);
	_LOCKED_value_all_variables(cfg, ns);
	g_mutex_unlock(&var_lock);
}

static gboolean
_value_one(const char *name, const char *value, const gboolean readonly)
{
	EXTRA_ASSERT(var_init != 0);
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(value != NULL);

	gboolean rc = FALSE;
	g_mutex_lock(&var_lock);
	/* First try with a real variable name, and if not foundcheck if the name
	 * is not an alias to another. */
	if (!(rc = _LOCKED_value_named_variable(name, value, readonly))) {
		const gchar *real_name = g_tree_lookup(var_aliases, name);
		if (real_name) {
			rc = _LOCKED_value_named_variable(real_name, value, readonly);
			_warn_deprecated(real_name, name);
		}
	}
	g_mutex_unlock(&var_lock);
	return rc;
}

/* The only fonction that set 'readonly' and override any previous already
 * readonly variable. Destined to be called for CLI options */
gboolean
oio_var_fix_one(const char *name, const char *value)
{
	return _value_one(name, value, TRUE);
}

gboolean
oio_var_value_one(const char *name, const char *value)
{
	return _value_one(name, value, FALSE);
}

void
oio_var_list_all_ext(void (*hook) (const char *k, const char *v, void *u),
		void *udata)
{
	gint64 i64;

	if (!hook)
		return;

	g_mutex_lock(&var_lock);
	for (GSList *l=var_records; l ;l=l->next) {
		if (!l->data)
			continue;
		struct oio_var_record_s *rec = l->data;
		gchar tmp[256];
		switch (rec->type) {
			case OIO_VARTYPE_gboolean:
				g_strlcpy(tmp, *(rec->ptr.b)?"on":"off", sizeof(tmp));
				break;
			case OIO_VARTYPE_guint:
				g_snprintf(tmp, sizeof(tmp), "%u", *(rec->ptr.u));
				break;
			case OIO_VARTYPE_guint32:
				g_snprintf(tmp, sizeof(tmp), "%"G_GUINT32_FORMAT, *(rec->ptr.u32));
				break;
			case OIO_VARTYPE_guint64:
				g_snprintf(tmp, sizeof(tmp), "%"G_GUINT64_FORMAT, *(rec->ptr.u64));
				break;
			case OIO_VARTYPE_gint:
				g_snprintf(tmp, sizeof(tmp), "%i", *(rec->ptr.i));
				break;
			case OIO_VARTYPE_gint32:
				g_snprintf(tmp, sizeof(tmp), "%"G_GINT32_FORMAT, *(rec->ptr.i32));
				break;
			case OIO_VARTYPE_gint64:
				g_snprintf(tmp, sizeof(tmp), "%"G_GINT64_FORMAT, *(rec->ptr.i64));
				break;
			case OIO_VARTYPE_gdouble:
				g_snprintf(tmp, sizeof(tmp), "%f", *(rec->ptr.d));
				break;
			case OIO_VARTYPE_time_t:
				i64 = *(rec->ptr.t);
				g_snprintf(tmp, sizeof(tmp), "%"G_GINT64_FORMAT, i64);
				break;
			case OIO_VARTYPE_string:
				g_snprintf(tmp, sizeof(tmp), "%s", rec->ptr.str);
				break;
		}
		(*hook)(rec->name, tmp, udata);
	}
	g_mutex_unlock(&var_lock);
}

static void
_call_2_args_hook(const char *k, const char *v, void *udata)
{
	void (*hook) (const char *k, const char *v) = udata;
	hook(k, v);
}

void
oio_var_list_all(void (*hook) (const char *k, const char *v))
{
	oio_var_list_all_ext(_call_2_args_hook, hook);
}

static void
_append_kv_comma(const char *k, const char *v, void *u)
{
	GString *gstr = u;
	if (gstr->len > 1)
		g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair(gstr, k, v);
}

GString*
oio_var_list_as_json(void)
{
	EXTRA_ASSERT(var_init != 0);

	GString *gstr = g_string_sized_new (4096);
	g_string_append_c (gstr, '{');
	oio_var_list_all_ext(_append_kv_comma, gstr);
	g_string_append_c (gstr, '}');

	return gstr;
}

gboolean
oio_var_value_with_files(const char *ns, gboolean sys, GSList *files)
{
	EXTRA_ASSERT(var_init != 0);
	gboolean known = FALSE;

	/* Init with the system config */
	if (sys) {
		struct oio_cfg_handle_s *cfg = oio_cfg_cache_create();
		if (oio_cfg_handle_has_ns(cfg, ns)) {
			known = TRUE;
			oio_var_value_all_with_config(cfg, ns);
		}
		oio_cfg_handle_clean(cfg);
	}

	/* override with specific files */
	for (GSList *l = files; l ; l = l->next) {
		if (!l->data)
			continue;
		struct oio_cfg_handle_s *cfg =
			oio_cfg_cache_create_fragment(l->data);
		if (oio_cfg_handle_has_ns(cfg, ns)) {
			known = TRUE;
			oio_var_value_all_with_config(cfg, ns);
		}
		oio_cfg_handle_clean(cfg);
	}

	return known;
}

void
oio_var_reset_all(void)
{
	EXTRA_ASSERT(var_init != 0);
	g_mutex_lock(&var_lock);
	for (GSList *l=var_records; l ;l=l->next) {
		if (!l->data)
			continue;
		struct oio_var_record_s *rec = l->data;
		if (!rec->flag_readonly)
			_record_set(rec, rec->def);
	}
	g_mutex_unlock(&var_lock);
}

gchar*
oio_var_get_string(const char *v)
{
	EXTRA_ASSERT(var_init != 0);
	g_mutex_lock(&var_lock);
	gchar *rc = g_strdup(v);
	g_mutex_unlock(&var_lock);
	return rc;
}

