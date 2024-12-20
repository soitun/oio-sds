/*
OpenIO SDS core library
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

#include <core/oioext.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/vfs.h>

// DO NOT REMOVE! It is required for "major" and "minor" since glibc 2.24.
#include <sys/sysmacros.h>

#include <core/oio_core.h>
#include <core/client_variables.h>

#include "internals.h"

#define PREPEND(Result,List) do { \
	next = (List)->next; \
	List->next = (Result); \
	(Result) = List; \
	List = next; \
} while (0)

time_hook_f oio_time_monotonic = NULL;
time_hook_f oio_time_real = NULL;

static GSList* gslist_merge_random (GSList *l1, GSList *l2) {
	GSList *next, *result = NULL;
	GRand *r = oio_ext_local_prng ();
	while (l1 || l2) {
		if (l1 && l2) {
			if (g_rand_boolean(r))
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		} else {
			if (l1)
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		}
	}
	return result;
}

static void gslist_split_in_two (GSList *src, GSList **r1, GSList **r2) {
	GSList *next, *l1 = NULL, *l2 = NULL;
	while (src) {
		if (src)
			PREPEND(l1, src);
		if (src)
			PREPEND(l2, src);
	}
	*r1 = l1, *r2 = l2;
}

GSList *oio_ext_gslist_shuffle (GSList *src) {
	GSList *l1=NULL, *l2=NULL;

	gslist_split_in_two(src, &l1, &l2);
	return gslist_merge_random(
		(l1 && l1->next) ? oio_ext_gslist_shuffle(l1) : l1,
		(l2 && l2->next) ? oio_ext_gslist_shuffle(l2) : l2);
}

void oio_ext_array_shuffle (gpointer *array, gsize len) {
	GRand *r = oio_ext_local_prng ();
	while (len-- > 1) {
		guint32 i = g_rand_int_range (r, 0, len+1);
		if (i == len)
			continue;
		gpointer tmp = array[i];
		array[i] = array[len];
		array[len] = tmp;
	}
}

gsize oio_ext_array_partition (gpointer *array, gsize len,
		gboolean (*predicate)(gconstpointer)) {
	EXTRA_ASSERT (array != NULL);
	EXTRA_ASSERT (predicate != NULL);

	if (!len || !predicate)
		return 0;

	/* qualify each item, so that we call the predicate only once */
	guchar *good = g_malloc0 (len);

	guchar any = 0;
	for (gsize i=0; i<len; i++) {
		good[i] = 0 != ((*predicate) (array[i]));
		any |= good[i];
	}

	/* partition the items, the predicate==TRUE first */
	if (any) {
		for (gsize i=0; i<len; i++) {
			if (good[i])
				continue;
			/* swap the items */
			gchar *tmp = array[len-1];
			array[len-1] = array[i];
			array[i] = tmp;
			/* swap the qualities */
			gboolean b = good[len-1];
			good[len-1] = good[i];
			good[i] = b;

			-- len;
			-- i;
		}
	} else
		len = 0;

	g_free (good);
	return len;
}

GError *oio_ext_extract_json (struct json_object *obj,
		struct oio_ext_json_mapping_s *tab) {
	EXTRA_ASSERT (tab != NULL);
	for (struct oio_ext_json_mapping_s *p=tab; p->out ;p++)
		*(p->out) = NULL;
	if (!obj || !json_object_is_type(obj, json_type_object))
		return BADREQ("Not an object");
	for (struct oio_ext_json_mapping_s *p=tab; p->out ;p++) {
		struct json_object *o = NULL;
		if (!json_object_object_get_ex(obj, p->name, &o) || !o) {
			if (!p->mandatory)
				continue;
			return BADREQ("Missing field [%s]", p->name);
		}
		if (!json_object_is_type(o, p->type))
			return BADREQ("Invalid type for field [%s]", p->name);
		*(p->out) = o;
	}
	return NULL;
}

void ** oio_ext_array_concat (void **t0, void **t1) {
	GPtrArray *tmp = g_ptr_array_new();
	if (t0) for (void **p=t0; *p ;++p) g_ptr_array_add(tmp, *p);
	if (t1) for (void **p=t1; *p ;++p) g_ptr_array_add(tmp, *p);
	g_ptr_array_add(tmp, NULL);
	return g_ptr_array_free(tmp, FALSE);
}

/* -------------------------------------------------------------------------- */

/** @private */
struct oio_ext_local_s {
	GRand *prng;
	/** Deadline for the request, in monotonic microseconds. */
	gint64 deadline;
	/** Request originates from an administration tool. */
	guint8 is_admin;
	/** Request wants to talk only to the master service
	 * (in case of master/slave replication). */
	guint8 force_master;

	/** Request identified from swift.
	 * Used to redirect rawx request to internal
	 * rawx service if the request is not from swift.
	*/
	guint8 end_user_request;
	/** Request ask for TLS usage (RAWX only at this time. */
	guint8 upgrade_to_tls;
	gchar *user_agent;
	gchar *force_versioning;
	guint8 simulate_versioning;
	/** Request originates from a redirect from a root container. */
	guint8 is_shard_redirection;
	/** If the caller sets a region, the backend service must check it is
	 * in the same region before answering. */
	gchar *region;
	gchar *root_hexid;
	gchar **shared_properties;
	gint64 db_wait;
	gchar reqid[LIMIT_LENGTH_REQID];
	GHashTable *perfdata;
	guint8 allow_long_timeout;

	GPtrArray *urlerrorv;
};

static void _local_free(gpointer p) {
	struct oio_ext_local_s *l = p;
	if (!l)
		return;
	if (l->prng) {
		g_rand_free (l->prng);
		l->prng = NULL;
	}
	if (l->user_agent) {
		g_free(l->user_agent);
		l->user_agent = NULL;
	}
	if (l->force_versioning) {
		g_free(l->force_versioning);
		l->force_versioning = NULL;
	}
	if (l->perfdata) {
		g_hash_table_destroy(l->perfdata);
		l->perfdata = NULL;
	}
	if (l->urlerrorv) {
		g_ptr_array_unref(l->urlerrorv);
	}
	g_free (l);
}

static GPrivate th_local_key = G_PRIVATE_INIT(_local_free);

static struct oio_ext_local_s *_local_get (void) {
	return g_private_get(&th_local_key);
}

static struct oio_ext_local_s *_local_ensure (void) {
	struct oio_ext_local_s *l = _local_get ();
	if (!l) {
		l = g_malloc0 (sizeof(*l));
		g_private_replace (&th_local_key, l);
	}
	return l;
}

GRand *oio_ext_local_prng (void) {
	struct oio_ext_local_s *l = _local_ensure ();
	if (!l->prng) {
		union {
			void *p;
			guint32 u[2];
			gint64 i;
		} b;
		guint32 seeds[3];
		b.i = g_get_monotonic_time ();
		seeds[0] = b.u[0] ^ getpid();
		seeds[1] = b.u[1];
		seeds[2] = g_random_int ();
		b.p = g_thread_self();
		seeds[1] = (seeds[1] ^ b.u[0]) ^ b.u[1];
		l->prng = g_rand_new_with_seed_array (seeds, 3);
	}
	return l->prng;
}

gint64 oio_ext_get_db_wait(void) {
	struct oio_ext_local_s *l = _local_ensure();
	return l->db_wait;
}

void oio_ext_incr_db_wait(gint64 delta) {
	struct oio_ext_local_s *l = _local_ensure();
	l->db_wait += delta;
}

void oio_ext_reset_db_wait(void) {
	struct oio_ext_local_s *l = _local_ensure();
	l->db_wait = 0;
}

const char *oio_ext_get_reqid (void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return oio_str_is_set(l->reqid) ? l->reqid : NULL;
}

const char *oio_ext_set_reqid(const char *reqid) {
	struct oio_ext_local_s *l = _local_ensure ();
	l->reqid[0] = '\0';
	if (oio_str_is_set(reqid))
		g_strlcpy(l->reqid, reqid, sizeof(l->reqid));
	return l->reqid;
}

const char *oio_ext_set_random_reqid(void) {
#ifdef HAVE_EXTRA_DEBUG
	GRID_DEBUG(
			"%s is deprecated, please call oio_ext_set_prefixed_random_reqid",
			__FUNCTION__);
#endif
	return oio_ext_set_prefixed_random_reqid(NULL);
}

const char *oio_ext_set_prefixed_random_reqid(const char *prefix) {
	struct {
		pid_t pid:16;
		guint8 buf[14];
	} bulk;
	bulk.pid = getpid();

	char hex[33];
	size_t plen = 0;
	if (prefix != NULL) {
		plen = MIN(strlen(prefix), 16);
		strncpy(hex, prefix, plen);
	}
	oio_buf_randomize(bulk.buf, sizeof(bulk.buf) - plen/2);
	oio_str_bin2hex((guint8*)&bulk, sizeof(bulk), hex+plen, sizeof(hex) - plen);
	return oio_ext_set_reqid(hex);
}

const char *
oio_ext_ensure_reqid(const char *prefix)
{
	const char *reqid = oio_ext_get_reqid();
	if (reqid)
		return reqid;
	return oio_ext_set_prefixed_random_reqid(prefix);
}

gint64 oio_ext_get_deadline(void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return l->deadline > 0 ? l->deadline : 0;
}

void oio_ext_set_deadline(gint64 deadline) {
	struct oio_ext_local_s *l = _local_ensure ();
	l->deadline = deadline > 0 ? deadline : 0;
}

gboolean oio_ext_is_admin (void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return BOOL(l->is_admin);
}

void oio_ext_set_admin (const gboolean admin) {
	struct oio_ext_local_s *l = _local_ensure ();
	l->is_admin = BOOL(admin);
}

gboolean oio_ext_has_force_master(void) {
	const struct oio_ext_local_s *l = _local_ensure();
	return BOOL(l->force_master);
}

void oio_ext_set_force_master(const gboolean force_master) {
	struct oio_ext_local_s *l = _local_ensure();
	l->force_master = BOOL(force_master);
}

gboolean oio_ext_is_end_user_request(void) {
	const struct oio_ext_local_s *l = _local_ensure();
	return BOOL(l->end_user_request);
}

void oio_ext_set_end_user_request(const gboolean end_user_request) {
	struct oio_ext_local_s *l = _local_ensure();
	l->end_user_request = BOOL(end_user_request);
}

gboolean oio_ext_has_upgrade_to_tls() {
	const struct oio_ext_local_s *l = _local_ensure();
	return BOOL(l->upgrade_to_tls);
}

void oio_ext_set_upgrade_to_tls(const gboolean upgrade_to_tls) {
	struct oio_ext_local_s *l = _local_ensure();
	l->upgrade_to_tls = BOOL(upgrade_to_tls);
}

const gchar *oio_ext_get_user_agent(void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return l->user_agent;
}

void oio_ext_set_user_agent(const gchar *user_agent) {
	struct oio_ext_local_s *l = _local_ensure();
	if (l->user_agent) {
		g_free(l->user_agent);
	}
	l->user_agent = g_strdup(user_agent);
}

const gchar *oio_ext_get_force_versioning(void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return l->force_versioning;
}

void oio_ext_set_force_versioning(const gchar *force_versioning) {
	struct oio_ext_local_s *l = _local_ensure();
	if (l->force_versioning) {
		g_free(l->force_versioning);
	}
	l->force_versioning = g_strdup(force_versioning);
}

gboolean oio_ext_has_simulate_versioning(void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return BOOL(l->simulate_versioning);
}

void oio_ext_set_simulate_versioning(const gboolean simulate_versioning) {
	struct oio_ext_local_s *l = _local_ensure();
	l->simulate_versioning = BOOL(simulate_versioning);
}

gboolean oio_ext_is_shard_redirection(void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return BOOL(l->is_shard_redirection);
}

void oio_ext_set_is_shard_redirection(const gboolean is_shard_redirection) {
	struct oio_ext_local_s *l = _local_ensure();
	l->is_shard_redirection = BOOL(is_shard_redirection);
}

const gchar *oio_ext_get_region(void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return l->region;
}

void oio_ext_set_region(const gchar *region) {
	struct oio_ext_local_s *l = _local_ensure();
	if (l->region) {
		g_free(l->region);
		l->region = NULL;
	}
	l->region = g_strdup(region);
}

const gchar *oio_ext_get_root_hexid(void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return l->root_hexid;
}

void oio_ext_set_root_hexid(const gchar *root_hexid) {
	struct oio_ext_local_s *l = _local_ensure();
	if (l->root_hexid) {
		g_free(l->root_hexid);
		l->root_hexid = NULL;
	}
	l->root_hexid = g_strdup(root_hexid);
}

gchar **oio_ext_get_shared_properties(void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return l->shared_properties;
}

void oio_ext_set_shared_properties(gchar **shared_properties) {
	struct oio_ext_local_s *l = _local_ensure();
	if (l->shared_properties) {
		g_strfreev(l->shared_properties);
	}
	l->shared_properties = shared_properties;
}

GPtrArray *oio_ext_get_urlerrorv(void) {
	struct oio_ext_local_s *l = _local_ensure();
	return l->urlerrorv;
}

void oio_ext_set_urlerrorv(GPtrArray *urlerrorv) {
	struct oio_ext_local_s *l = _local_ensure();
	if (l->urlerrorv) {
		g_ptr_array_unref(l->urlerrorv);
	}
	l->urlerrorv = urlerrorv;
}

GHashTable *oio_ext_get_perfdata(void) {
	struct oio_ext_local_s *l = _local_ensure();
	return l->perfdata;
}

GHashTable *oio_ext_enable_perfdata(gboolean enabled) {
	struct oio_ext_local_s *l = _local_ensure();
	if (enabled && !l->perfdata) {
		l->perfdata = g_hash_table_new_full(
				g_str_hash, g_str_equal, g_free, NULL);
	} else if (!enabled && l->perfdata) {
		g_hash_table_destroy(l->perfdata);
		l->perfdata = NULL;
	}
	return l->perfdata;
}

void oio_ext_add_perfdata(const gchar *key, gint64 value) {
	struct oio_ext_local_s *l = _local_ensure();
	if (l->perfdata) {
		gint64 old = GPOINTER_TO_INT(g_hash_table_lookup(l->perfdata, key));
		g_hash_table_insert(l->perfdata,
				g_strdup(key), GINT_TO_POINTER(old + value));
	}
}

gboolean oio_ext_is_allowed_to_do_long_timeout(void) {
	const struct oio_ext_local_s *l = _local_ensure ();
	return BOOL(l->allow_long_timeout);
}

void oio_ext_allow_long_timeout(const gboolean allow_long_timeout) {
	struct oio_ext_local_s *l = _local_ensure();
	l->allow_long_timeout = BOOL(allow_long_timeout);
}

/* -------------------------------------------------------------------------- */

# ifdef HAVE_BACKTRACE
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wcpp"
#warning "Backtrace enabled"
#pragma GCC diagnostic pop
#include <execinfo.h>
#define STACK_MAX 8

GError * oio_error_debug (GQuark gq, int code, const char *fmt, ...) {
	void *frames[STACK_MAX];
	int nbframes = backtrace(frames, STACK_MAX);

	GString *gs = g_string_new("");
	char **strv = backtrace_symbols (frames, nbframes);
	if (strv) {
		for (int i=1; i<nbframes ;i++) {
			if (gs->len)
				g_string_append_c (gs, ',');
			char *s, *start = strv[i];
			if (NULL != (s = strchr(start, '(')))
				start = s+1;
			if (NULL != (s = strchr(start, '+')))
				*s = 0;
			if (NULL != (s = strchr(start, ')')))
				*s = 0;
			g_string_append (gs, start);
		}
		free (strv);
	}

	va_list args;
	va_start (args, fmt);
	GError *err = g_error_new_valist (gq, code, fmt, args);
	va_end (args);

	g_prefix_error (&err, "[%s] ", gs->str);
	g_string_free (gs, TRUE);
	return err;
}
#endif

gint64 oio_ext_real_time (void) {
#ifdef HAVE_EXTRA_DEBUG
	if (oio_time_real)
		return (*oio_time_real)();
#endif
	return g_get_real_time();
}

gint64 oio_ext_monotonic_time (void) {
#ifdef HAVE_EXTRA_DEBUG
	if (oio_time_monotonic)
		return (*oio_time_monotonic)();
#endif
	return g_get_monotonic_time();
}

time_t oio_ext_real_seconds (void) {
	return oio_ext_real_time () / G_TIME_SPAN_SECOND;
}

time_t oio_ext_monotonic_seconds (void) {
	return oio_ext_monotonic_time () / G_TIME_SPAN_SECOND;
}

void oio_ext_init_test (int *argc, char ***argv) {
	g_test_init (argc, argv, NULL);

	char *sep = strrchr ((*argv)[0], '/');
	g_set_prgname (sep ? sep+1 : (*argv)[0]);

	oio_log_lazy_init ();
	oio_log_init_level(GRID_LOGLVL_INFO);
	oio_log_init_level_from_env("G_DEBUG_LEVEL");
	g_log_set_default_handler(oio_log_stderr, NULL);
	oio_ext_set_prefixed_random_reqid("oio-test-");
	oio_var_value_with_files(g_getenv("OIO_NS"), TRUE, NULL);
}

/* -------------------------------------------------------------------------- */

/** @private */
struct maj_min_idle_s {
	guint major, minor;
	gint64 last_update;
	unsigned long long last_total_time;
	gdouble idle;
};

/** @private */
struct path_maj_min_s {
	gint64 last_update;
	int major;
	int minor;
	gchar path[];
};

static GSList *io_cache = NULL;
static GMutex io_lock = {0};

static GSList *majmin_cache = NULL;
static GMutex majmin_lock = {0};

void _constructor_idle_cache (void);
void _destructor_idle_cache (void);

static void _free_majmin_idle_list (GSList *l) {
	g_slist_free_full (l, (GDestroyNotify)g_free);
}

void __attribute__ ((constructor)) _constructor_idle_cache (void) {
	static volatile guint lazy_init = 1;
	if (lazy_init) {
		if (g_atomic_int_compare_and_exchange(&lazy_init, 1, 0)) {
			g_mutex_init (&io_lock);
			g_mutex_init (&majmin_lock);
		}
	}
}

void __attribute__ ((destructor)) _destructor_idle_cache (void) {
	_constructor_idle_cache ();

	g_mutex_lock (&io_lock);
	_free_majmin_idle_list (io_cache);
	io_cache = NULL;
	g_mutex_unlock (&io_lock);

	g_mutex_lock (&majmin_lock);
	g_slist_free_full (majmin_cache, g_free);
	majmin_cache = NULL;
	g_mutex_unlock (&majmin_lock);
}

static gdouble _compute_io_idle (guint major, guint minor) {
	_constructor_idle_cache ();

	gboolean found = FALSE;
	gdouble idle = 0.01;
	struct maj_min_idle_s *out = NULL;

	g_mutex_lock (&io_lock);
	gint64 now = oio_ext_monotonic_time ();

	/* locate the info in the cache */
	for (GSList *l=io_cache; l && !out ;l=l->next) {
		struct maj_min_idle_s *p = l->data;
		if (p && p->major == major && p->minor == minor)
			out = p;
	}
	if (!out) {
		out = g_malloc0 (sizeof(struct maj_min_idle_s));
		out->major = major;
		out->minor = minor;
		out->idle = 1.0;
		io_cache = g_slist_prepend (io_cache, out);
	}

	/* check its validity and reload if necessary */
	if (!out->last_update || (now - out->last_update) > _refresh_io_idle) {
		FILE *fst = fopen ("/proc/diskstats", "r");
		while (fst && !feof(fst) && !ferror(fst)) {
			char line[1024], name[256];
			guint fmajor = 0, fminor = 0;
			unsigned long long int
				rd = 0, rd_merged = 0, rd_sectors = 0, rd_time = 0,
				wr = 0, wr_merged = 0, wr_sectors = 0, wr_time = 0,
				total_progress = 0, total_time = 0, total_iotime = 0;
			if (!fgets (line, 1024, fst))
				break;
			int rc = sscanf (line, "%u %u %s %llu %llu %llu %llu %llu"
					"%llu  %llu %llu %llu %llu %llu",
					&fmajor, &fminor, name,
					&rd, &rd_merged, &rd_sectors, &rd_time,
					&wr, &wr_merged, &wr_sectors, &wr_time,
					&total_progress, &total_time, &total_iotime);
			if (rc != 0 && fmajor == major && fminor == minor) {
				/* Since the instant the current value of `now` has been
				 * evaluated, we spent some time to open file, scan through
				 * it, etc. This might take longer than you think on an
				 * overloaded host. So we take the value right after the
				 * moment we found the line matching our device.
				 * So that there were no I/O ops counted since then, there
				 * is little chance of finding more I/O time that actual
				 * time. */
				now = oio_ext_monotonic_time ();

				gdouble spent = total_time - out->last_total_time; /* in ms */
				gdouble elapsed = now - out->last_update; /* in us */
				elapsed /= G_TIME_SPAN_MILLISECOND; /* in ms */
				out->idle = 1.0 - (spent / elapsed);
				out->idle = MAX(0.0, out->idle);
				out->last_update = now;
				out->last_total_time = total_time;
				found = TRUE;
				break;
			}
		}
		if (fst) {
			fclose(fst);
			if (!found)
				GRID_DEBUG("Device with major=%u minor=%u "
						"not found in /proc/diskstats",
						major, minor);
		} else {
			GRID_DEBUG("Failed to open /proc/diskstats: %s",
					strerror(errno));
		}
	}

	/* collect the up-to-date value */
	if (out) {
		idle = out->idle;
	}

	/* purge obsolete and exceeding entries of the cache */
	GSList *kept = NULL, *trash = NULL;
	for (GSList *l=io_cache; l ;l=l->next) {
		struct maj_min_idle_s *p = l->data;
		if ((now - p->last_update) > G_TIME_SPAN_HOUR)
			trash = g_slist_prepend (trash, p);
		else
			kept = g_slist_prepend (kept, p);
	}
	g_slist_free (io_cache);
	_free_majmin_idle_list (trash);
	io_cache = kept;
	g_mutex_unlock (&io_lock);

	return idle;
}

static int _get_major_minor (const gchar *path, guint *pmaj, guint *pmin) {
	_constructor_idle_cache ();

	struct path_maj_min_s *out = NULL;

	g_mutex_lock (&majmin_lock);
	gint64 now = oio_ext_monotonic_time ();
	/* ensure an entry exists */
	for (GSList *l=majmin_cache; l && !out; l=l->next) {
		struct path_maj_min_s *p = l->data;
		if (p && !strcmp(path, p->path))
			out = p;
	}
	if (!out) {
		const size_t len = strlen(path);
		out = g_malloc0 (sizeof(struct path_maj_min_s) + len + 1);
		memcpy(out->path, path, len + 1);
		majmin_cache = g_slist_prepend (majmin_cache, out);
	}

	/* maybe refresh it */
	if (!out->last_update || (now - out->last_update) > _refresh_major_minor) {
		struct stat st = {0};
		if (0 != stat(out->path, &st)) {
			out = NULL;
		} else {
			out->major = (guint) major(st.st_dev);
			out->minor = (guint) minor(st.st_dev);
			out->last_update = now;
		}
	}

	/* collect the up-to-date value */
	if (out) {
		*pmaj = out->major;
		*pmin = out->minor;
	}

	/* now purge the expired items */
	GSList *kept = NULL, *trash = NULL;
	for (GSList *l=majmin_cache; l; l=l->next) {
		struct path_maj_min_s *p = l->data;
		if ((now - p->last_update) > G_TIME_SPAN_HOUR)
			trash = g_slist_prepend (trash, p);
		else
			kept = g_slist_prepend (kept, p);
	}
	g_slist_free_full (trash, g_free);
	g_slist_free (majmin_cache);
	majmin_cache = kept;
	g_mutex_unlock (&majmin_lock);

	return out != NULL;
}

gdouble oio_sys_io_idle (const char *vol) {
	guint maj = 0, min = 0;
	if (_get_major_minor(vol, &maj, &min))
		return _compute_io_idle(maj, min);
	return 0.01;
}

gdouble oio_sys_space_idle (const char *vol) {
	struct statfs sfs = {0};
	if (statfs(vol, &sfs) < 0)
		return 0.0;
	gdouble free_inodes_d = sfs.f_ffree,
			total_inodes_d = sfs.f_files,
			free_blocks_d = sfs.f_bavail,
			total_blocks_d = sfs.f_blocks;
	// Inode count is not always available (e.g. with btrfs)
	gdouble inode_ratio = (total_inodes_d > 0.0)? free_inodes_d / total_inodes_d : 1.0;
	gdouble block_ratio = (total_blocks_d > 0.0)? free_blocks_d / total_blocks_d : 1.0;
	return MIN(inode_ratio, block_ratio);
}

gdouble oio_sys_cpu_idle (void) {
	static gdouble ratio_idle = 0.01;
	static guint64 last_sum = 0;
	static guint64 last_idle = 0;
	static gint64 last_update = 0;
	static GMutex lock;
	static volatile guint lazy_init = 1;

	if (lazy_init) {
		if (g_atomic_int_compare_and_exchange(&lazy_init, 1, 0)) {
			g_mutex_init (&lock);
		}
	}

	gdouble out;

	g_mutex_lock (&lock);
	gint64 now = oio_ext_monotonic_time ();
	if (!last_update || ((now - last_update) > _refresh_cpu_idle)) {
		FILE *fst = fopen ("/proc/stat", "r");
		while (fst && !feof(fst) && !ferror(fst)) {
			char line[1024];
			if (!fgets (line, 1024, fst))
				break;
			if (!g_str_has_prefix(line, "cpu "))
				continue;
			char *p = g_strstrip(line + 4);
			long long unsigned int user = 0, _nice = 0, sys = 0, _idle = 0,
				 _wait = 0, irq = 0, soft = 0, steal = 0, guest = 0,
				 guest_nice = 0;
			/* TODO linux provides 10 fields since Linux 2.6.33,
			 * and we should check the Linux version to manage the
			 * old style with 7 fields for earlier releases. */
			int rc = sscanf(p, "%llu %llu %llu %llu %llu %llu %llu %llu"
					" %llu %llu", &user, &_nice, &sys, &_idle, &_wait, &irq,
					&soft, &steal, &guest, &guest_nice);
			if (rc != 0) {
				guint64 sum = user + _nice + sys + _idle + _wait + irq + soft
					+ steal + guest + guest_nice;
				if (sum > last_sum && _idle > last_idle)
					ratio_idle = ((gdouble)(_idle - last_idle)) /
						((gdouble)(sum - last_sum));
				last_sum = sum;
				last_idle = _idle;
				last_update = now;
			}
			break;
		}
		if (fst)
			fclose (fst);
	}
	out = MAX(0.0, ratio_idle);
	g_mutex_unlock (&lock);

	return out;
}

gboolean oio_ext_rand_boolean (void) {
	return g_rand_boolean (oio_ext_local_prng ());
}

gdouble oio_ext_rand_double (void) {
	return g_rand_double (oio_ext_local_prng());
}

guint32 oio_ext_rand_int (void) {
	return g_rand_int (oio_ext_local_prng ());
}

gint32 oio_ext_rand_int_range (gint32 low, gint32 up) {
	return g_rand_int_range (oio_ext_local_prng (), low, up);
}

