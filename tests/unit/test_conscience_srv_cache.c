/*
Copyright (C) 2026 OVH SAS

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

#include <glib.h>

#ifndef HAVE_EXTRA_ASSERT
#define HAVE_EXTRA_ASSERT 1
#endif

/* Rename server.c's main() to avoid conflict with the test main(). */
int conscience_main(int, char **);  /* forward decl to suppress -Wmissing-prototypes */
#define main conscience_main
#include "../../cluster/module/server.c"
#undef main

/* --- helpers --------------------------------------------------------------- */

static struct conscience_srvtype_s *
_create_test_srvtype(const gchar *name)
{
	struct conscience_srvtype_s *srvtype = g_malloc0(sizeof(*srvtype));
	g_rw_lock_init(&srvtype->rw_lock);
	g_strlcpy(srvtype->type_name, name, sizeof(srvtype->type_name));
	srvtype->services_ht = g_hash_table_new(hash_service_id, NULL);
	return srvtype;
}

static void
_destroy_test_srvtype(struct conscience_srvtype_s *srvtype)
{
	g_hash_table_destroy(srvtype->services_ht);
	g_rw_lock_clear(&srvtype->rw_lock);
	g_free(srvtype);
}

static struct conscience_srv_s *
_create_test_srv(struct conscience_srvtype_s *srvtype)
{
	struct conscience_srv_s *srv = g_malloc0(sizeof(*srv));
	srv->srvtype = srvtype;
	srv->tags = g_ptr_array_new();
	srv->cache = NULL;
	g_strlcpy(srv->description, "127.0.0.1:6000", sizeof(srv->description));
	return srv;
}

static void
_destroy_test_srv(struct conscience_srv_s *srv)
{
	conscience_srv_clean_udata(srv);
	if (srv->tags)
		g_ptr_array_free(srv->tags, TRUE);
	g_free(srv);
}

/* --- stress test helpers --------------------------------------------------- */

/* Shared flag: set to FALSE to stop the stress threads. */
static volatile gint _stress_keep_running = 1;

/* Stress reader thread: repeatedly reads srv->cache via the production
 * conscience_run_srvtypes → _prepare_cached path.
 * With the bug (READER lock), _task_expire can free srv->cache while this
 * thread is in the middle of _prepare_cached → use-after-free / crash. */
static gpointer
_stress_reader_thread(gpointer data UNUSED)
{
	(void)data;
	while (g_atomic_int_get(&_stress_keep_running)) {
		GByteArray *body = g_byte_array_new();
		GError *err = conscience_run_srvtypes("rawx", _prepare_cached, body);
		g_byte_array_free(body, TRUE);
		if (err)
			g_clear_error(&err);
	}
	return NULL;
}

/* Stress writer thread: repeatedly calls _task_expire() which frees and
 * rebuilds every expired service's cache.  Yields between iterations so
 * readers also get scheduled (avoids writer starvation with the fix). */
static gpointer
_stress_writer_thread(gpointer data UNUSED)
{
	(void)data;
	while (g_atomic_int_get(&_stress_keep_running)) {
		_task_expire(NULL);
		/* Yield so reader threads can acquire the lock too.
		 * Without this, the writer can starve readers when the fix
		 * (WRITER lock) is in place, causing the test to hang. */
		g_thread_yield();
	}
	return NULL;
}

/* --- deterministic lock-type detection helpers ----------------------------- */

/* Shared atomics for the lock-type detection test */
static volatile gint _lock_detect_ready = 0;
static volatile gint _lock_detect_started = 0;
static volatile gint _lock_detect_entered = 0;

/* Detector thread: waits for main thread to hold a reader lock on
 * srvtype->rw_lock, then calls _task_expire() which acquires a lock
 * on the same srvtype.
 *   Bug (READER lock): enters immediately — readers don't block readers.
 *   Fix (WRITER lock): blocks — writer waits for all readers to release. */
static gpointer
_lock_type_detector_thread(gpointer data UNUSED)
{
	(void)data;
	/* Wait for main thread to hold the reader lock */
	while (!g_atomic_int_get(&_lock_detect_ready))
		g_thread_yield();

	/* Signal that we are about to call _task_expire */
	g_atomic_int_set(&_lock_detect_started, 1);

	/* _task_expire acquires srvtype->rw_lock (reader or writer per bug/fix) */
	_task_expire(NULL);

	/* If we reach here, the lock was acquired (and released). */
	g_atomic_int_set(&_lock_detect_entered, 1);
	return NULL;
}


/* Test _prepare_cached with a NULL cache: should serialize from scratch.
 *
 * Scenario: A service has no cached serialized data (cache == NULL).
 * Expected behavior: _prepare_cached should serialize the service info from
 * scratch, populating the body with service data.
 * Pass condition: body->len > 0 (serialization succeeded)
 */
static void
test_prepare_cached_null_cache(void)
{
	struct conscience_srvtype_s *srvtype = _create_test_srvtype("rawx");
	struct conscience_srv_s *srv = _create_test_srv(srvtype);
	g_assert_null(srv->cache);

	GByteArray *body = g_byte_array_new();
	gboolean rc = _prepare_cached(srv, body);

	g_assert_true(rc);
	g_assert_cmpuint(body->len, >, 0);

	g_byte_array_free(body, TRUE);
	_destroy_test_srv(srv);
	_destroy_test_srvtype(srvtype);
}

/* Test _prepare_cached with a valid, non-empty cache.
 *
 * Scenario: A service already has cached serialized data.
 * Expected behavior: _prepare_cached should use the cached copy directly
 * without re-serializing, providing the exact cached bytes to the body.
 * Pass condition: body->len == payload size and content matches exactly
 * (cache hit optimization working)
 */
static void
test_prepare_cached_valid_cache(void)
{
	struct conscience_srvtype_s *srvtype = _create_test_srvtype("rawx");
	struct conscience_srv_s *srv = _create_test_srv(srvtype);

	/* Populate the cache with known data. */
	const guint8 payload[] = {0x30, 0x80, 0xAA, 0xBB, 0x00, 0x00};
	srv->cache = g_byte_array_new();
	g_byte_array_append(srv->cache, payload, sizeof(payload));

	GByteArray *body = g_byte_array_new();
	gboolean rc = _prepare_cached(srv, body);

	g_assert_true(rc);
	g_assert_cmpuint(body->len, ==, sizeof(payload));
	g_assert_cmpmem(body->data, body->len, payload, sizeof(payload));

	g_byte_array_free(body, TRUE);
	_destroy_test_srv(srv);
	_destroy_test_srvtype(srvtype);
}

/* Test _prepare_cached with an empty cache.
 *
 * Scenario: A service has allocated cache storage but it's empty (len == 0).
 * Expected behavior: _prepare_cached checks "if (cached)" → TRUE (non-NULL),
 * then checks "if (cached->len > 0)" → FALSE (empty), so it falls through
 * to the fallback path and regenerates the serialization from scratch.
 * Pass condition: body->len > 0 (regeneration happened despite empty cache)
 */
static void
test_prepare_cached_empty_cache(void)
{
	struct conscience_srvtype_s *srvtype = _create_test_srvtype("rawx");
	struct conscience_srv_s *srv = _create_test_srv(srvtype);
	srv->cache = g_byte_array_new();  /* empty, len == 0 */

	GByteArray *body = g_byte_array_new();
	gboolean rc = _prepare_cached(srv, body);

	g_assert_true(rc);
	/* Empty cache triggers fallback serialization → body gets populated. */
	g_assert_cmpuint(body->len, >, 0);

	g_byte_array_free(body, TRUE);
	_destroy_test_srv(srv);
	_destroy_test_srvtype(srvtype);
}

/* Deterministic test: verify _task_expire uses a WRITER lock on srvtype->rw_lock.
 *
 * CONTEXT — THE BUG
 * _task_expire() iterates all service types and, for each expired service,
 * calls conscience_srvtype_zero_expired() → _conscience_srv_prepare_cache()
 * which frees srv->cache (via conscience_srv_clean_udata) and immediately
 * reallocates it.  These are WRITE operations on shared data.
 *
 * Meanwhile, conscience_run_srvtypes() (the reader path used by HTTP
 * handlers) acquires the same srvtype->rw_lock as a READER and iterates
 * services, accessing srv->cache through _prepare_cached().
 *
 * The bug: _task_expire() originally acquired srvtype->rw_lock with
 * g_rw_lock_reader_lock instead of g_rw_lock_writer_lock.  With a
 * READER lock, multiple readers CAN run concurrently, so a reader can
 * be iterating srv->cache at the exact moment _task_expire frees it
 * → use-after-free.
 *
 * HOW THIS TEST REPRODUCES THE ERROR
 * Instead of hoping for a crash, we deterministically detect whether
 * _task_expire acquires a READER or WRITER lock:
 *
 *  1. Initialize the conscience infrastructure and register one rawx
 *     service with score_expiration = 0 (expires on every check).
 *
 *  2. The subprocess main thread acquires srvtype->rw_lock as a READER
 *     (simulating an in-flight conscience_run_srvtypes call).
 *
 *  3. A detector thread is spawned.  It calls _task_expire(), which
 *     internally tries to lock the same srvtype->rw_lock.
 *       – If _task_expire uses a READER lock (bug):  the lock is shared
 *         with the main thread, so _task_expire enters immediately and
 *         the detector sets _lock_detect_entered = TRUE.
 *       – If _task_expire uses a WRITER lock (fix):  the writer lock
 *         cannot be acquired while the main thread holds a reader lock,
 *         so the detector blocks.
 *
 *  4. After a 500 ms wait the main thread checks _lock_detect_entered.
 *     It then releases the reader lock so the detector can finish.
 *
 *  5. g_assert_false(_lock_detect_entered):
 *       – Bug  (READER lock): TRUE  → assertion fires → subprocess aborts
 *       – Fix  (WRITER lock): FALSE → subprocess exits normally
 *
 * The outer test uses g_test_trap_subprocess / g_test_trap_assert_passed
 * so that a subprocess abort (bug present) makes the whole test FAIL.
 */
static void
test_task_expire_uses_writer_lock(void)
{
	if (g_test_subprocess()) {
		_cs_set_defaults();
		oio_server_namespace = "OPENIO";

		struct conscience_srvtype_s *srvtype = conscience_get_srvtype("rawx", TRUE);
		g_assert_nonnull(srvtype);
		srvtype->score_expiration = 0;  /* Expire every check */

		/* Register one service so _task_expire has something to process */
		struct service_info_s si = {0};
		g_strlcpy(si.ns_name, oio_server_namespace, sizeof(si.ns_name));
		g_strlcpy(si.type, "rawx", sizeof(si.type));
		g_assert_true(grid_string_to_addrinfo("127.0.0.1:6000", &si.addr));
		si.put_score.value = 100;
		si.put_score.timestamp = 0;
		si.get_score.value = 100;
		si.get_score.timestamp = 0;
		si.tags = g_ptr_array_new();

		struct service_info_dated_s *sid = push_service(&si);
		if (sid)
			service_info_dated_free(sid);
		g_ptr_array_free(si.tags, TRUE);

		/* Reset detection flags */
		g_atomic_int_set(&_lock_detect_ready, 0);
		g_atomic_int_set(&_lock_detect_started, 0);
		g_atomic_int_set(&_lock_detect_entered, 0);

		/* Hold a READER lock — this is what conscience_run_srvtypes does */
		g_rw_lock_reader_lock(&srvtype->rw_lock);

		/* Start detector thread */
		GThread *detector = g_thread_new("lock-detector",
				_lock_type_detector_thread, NULL);
		g_assert_nonnull(detector);

		/* Tell detector the reader lock is held */
		g_atomic_int_set(&_lock_detect_ready, 1);

		/* Wait for detector to actually begin _task_expire */
		while (!g_atomic_int_get(&_lock_detect_started))
			g_thread_yield();

		/* Give 500 ms for _task_expire to try acquiring the lock */
		g_usleep(500000);

		gboolean writer_got_in = g_atomic_int_get(&_lock_detect_entered);

		/* Release so the detector thread can finish (avoids deadlock) */
		g_rw_lock_reader_unlock(&srvtype->rw_lock);
		g_thread_join(detector);

		/* With bug  (READER lock): writer_got_in is TRUE  → assert fires → subprocess aborts
		 * With fix  (WRITER lock): writer_got_in is FALSE → returns normally */
		g_assert_false(writer_got_in);
		return;
	}

	g_test_trap_subprocess(NULL, 10000000, 0);  /* 10 s timeout */
	g_test_trap_assert_passed();
}

/* Stress test: concurrent readers and writers on the service cache.
 *
 * This test attempts to trigger the actual use-after-free crash caused by
 * the READER-lock bug in _task_expire.  It spawns reader threads that call
 * conscience_run_srvtypes() → _prepare_cached() (reads srv->cache) and a
 * writer thread that calls _task_expire() (frees and re-creates srv->cache).
 *
 * The race window inside _prepare_cached is:
 *     GByteArray *cached = srv->cache;   ← local pointer copy
 *     if (cached) {
 *         cached = g_byte_array_ref(cached);  ← use-after-free if freed
 * If _task_expire runs between the pointer copy and g_byte_array_ref, the
 * reader dereferences freed memory.
 *
 * NOTE: This crash is NOT guaranteed.  glibc's malloc does not unmap freed
 * small allocations, so the freed memory often still contains valid-looking
 * bytes and the dereference silently succeeds.  The crash depends on malloc
 * reusing the freed block in time.  Building with AddressSanitizer
 * (-fsanitize=address) makes the crash deterministic because ASan poisons
 * freed memory.
 *
 * With the fix (WRITER lock): readers and writers are properly serialized,
 * no use-after-free is possible → test always passes.
 *
 * With the bug (READER lock): readers and writers run concurrently,
 * use-after-free may crash the subprocess → test may fail.
 *
 * Because this test is non-deterministic, the deterministic lock-type
 * detection test (test_task_expire_uses_writer_lock) is the authoritative
 * check.  This stress test is kept as an additional safety net that may
 * catch the bug on lucky scheduling or under ASan.
 */
static void
test_expire_cache_stress(void)
{
	if (g_test_subprocess()) {
		_cs_set_defaults();
		oio_server_namespace = "OPENIO";

		struct conscience_srvtype_s *srvtype = conscience_get_srvtype("rawx", TRUE);
		g_assert_nonnull(srvtype);
		srvtype->score_expiration = 0;  /* Expire on every check */

		/* Register several services to widen the iteration window */
		for (int i = 0; i < 10; i++) {
			gchar addr_str[64];
			g_snprintf(addr_str, sizeof(addr_str), "127.0.0.%d:6000", i + 1);

			struct service_info_s si = {0};
			g_strlcpy(si.ns_name, oio_server_namespace, sizeof(si.ns_name));
			g_strlcpy(si.type, "rawx", sizeof(si.type));
			g_assert_true(grid_string_to_addrinfo(addr_str, &si.addr));
			si.put_score.value = 100;
			si.put_score.timestamp = 0;
			si.get_score.value = 100;
			si.get_score.timestamp = 0;
			si.tags = g_ptr_array_new();

			struct service_info_dated_s *sid = push_service(&si);
			if (sid)
				service_info_dated_free(sid);
			g_ptr_array_free(si.tags, TRUE);
		}

		g_atomic_int_set(&_stress_keep_running, 1);

		/* 4 readers + 1 writer for 2 seconds */
		#define STRESS_N_READERS 4
		#define STRESS_DURATION_US (2 * G_USEC_PER_SEC)

		GThread *readers[STRESS_N_READERS];
		for (int i = 0; i < STRESS_N_READERS; i++) {
			gchar name[32];
			g_snprintf(name, sizeof(name), "stress-r%d", i);
			readers[i] = g_thread_new(name, _stress_reader_thread, NULL);
			g_assert_nonnull(readers[i]);
		}
		GThread *writer = g_thread_new("stress-w", _stress_writer_thread, NULL);
		g_assert_nonnull(writer);

		g_usleep(STRESS_DURATION_US);
		g_atomic_int_set(&_stress_keep_running, 0);

		for (int i = 0; i < STRESS_N_READERS; i++)
			g_thread_join(readers[i]);
		g_thread_join(writer);

		#undef STRESS_N_READERS
		#undef STRESS_DURATION_US
		return;
	}

	g_test_trap_subprocess(NULL, 10000000, 0);  /* 10 s timeout */
	g_test_trap_assert_passed();
}

/* --- main ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc, argv);

	/* Needed by conscience_srv_fill_srvinfo_header -> g_strlcpy(ns_name, ...) */
	oio_server_namespace = "OPENIO";

	g_test_add_func("/conscience/cache/null_cache",
		test_prepare_cached_null_cache);
	g_test_add_func("/conscience/cache/valid_cache",
		test_prepare_cached_valid_cache);
	g_test_add_func("/conscience/cache/empty_cache",
		test_prepare_cached_empty_cache);
	g_test_add_func("/conscience/cache/task_expire_uses_writer_lock",
		test_task_expire_uses_writer_lock);
	g_test_add_func("/conscience/cache/expire_cache_stress",
		test_expire_cache_stress);

	return g_test_run();
}