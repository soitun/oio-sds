/*
OpenIO SDS core library
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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

#include <core/oiolog.h>

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>

#include <core/oiostr.h>

#include "internals.h"

int oio_log_level_default = 0x7F;

int oio_log_level = 0x7F;

int oio_log_flags = 0;

guint16
oio_log_thread_id(GThread *thread)
{
	union {
		void *p;
		guint16 u[4];
	} bulk;
	bulk.u[0] = bulk.u[1] = bulk.u[2] = bulk.u[3] = 0;
	bulk.p = thread;
	return (bulk.u[0] ^ bulk.u[1]) ^ (bulk.u[2] ^ bulk.u[3]);
}

guint16
oio_log_current_thread_id(void)
{
	return oio_log_thread_id(g_thread_self());
}

const gchar*
oio_log_lvl2str(GLogLevelFlags lvl)
{
	switch (lvl & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:
			return "ERROR";
		case G_LOG_LEVEL_CRITICAL:
			return "CRITICAL";
		case G_LOG_LEVEL_WARNING:
			return "WARNING";
		case G_LOG_LEVEL_MESSAGE:
			return "NOTICE";
		case G_LOG_LEVEL_INFO:
			return "INFO";
		case G_LOG_LEVEL_DEBUG:
			return "DEBUG";
	}

	switch (lvl >> G_LOG_LEVEL_USER_SHIFT) {
		case 0:
		case 1:
			return "ERROR";
		case 2:
			return "WARNING";
		case 4:
			return "NOTICE";
		case 8:
			return "INFO";
		case 16:
			return "DEBUG";
		case 32:
			return "TR0";
		default:
			return "TR1";
	}
}

int
oio_log_lvl2severity(GLogLevelFlags lvl)
{
	switch (lvl & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:
			return LOG_ERR;
		case G_LOG_LEVEL_CRITICAL:
			return LOG_ERR;
		case G_LOG_LEVEL_WARNING:
			return LOG_WARNING;
		case G_LOG_LEVEL_MESSAGE:
			return LOG_NOTICE;
		case G_LOG_LEVEL_INFO:
		case G_LOG_LEVEL_DEBUG:
			return LOG_INFO;
		default:
			break;
	}

	switch (lvl >> G_LOG_LEVEL_USER_SHIFT) {
		case 0:
		case 1:
			return LOG_ERR;
		case 2:
			return LOG_WARNING;
		case 4:
			return LOG_NOTICE;
		case 8:
			return LOG_INFO;
		default:
			return LOG_DEBUG;
	}
}

int
oio_log_domain2facility(const char *dom)
{
	if (!dom)
		return 0;
	switch (*dom) {
		case 'a':
			return strcmp(dom, "access") ? LOG_LOCAL0 : LOG_LOCAL1;
		case 'o':
			return strcmp(dom, "out") ? LOG_LOCAL0 : LOG_LOCAL2;
		default:
			return LOG_LOCAL0;
	}
}

#define REAL_LEVEL(L)   (guint32)((L) >> G_LOG_LEVEL_USER_SHIFT)
#define ALLOWED_LEVEL() REAL_LEVEL(oio_log_level)

static gboolean
glvl_allowed(register GLogLevelFlags lvl)
{
	return (lvl & 0x7F)
		|| (ALLOWED_LEVEL() >= REAL_LEVEL(lvl));
}

static guint8 map_valid_ascii[256] = {0};

void _constructor_map_valid_ascii (void);

void __attribute__ ((constructor))
_constructor_map_valid_ascii (void)
{
	/* 0 remains 0, and the array is already zero'ed */
	for (int i=1; i<256 ;i++) {
		map_valid_ascii[i] = (g_ascii_isspace(i) || !g_ascii_isprint(i))
			? (guint8)' ' : (guint8)i;
	}
}

static void
_purify_in_place(register gchar *s)
{
	for (; *s ; s++)
		*s = map_valid_ascii[(guint8)*s];
	*(s-1) = '\n';
}

void oio_log_noop(const gchar *d UNUSED, GLogLevelFlags l UNUSED,
		const gchar *m UNUSED, gpointer u UNUSED) { }

void
oio_log_syslog(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data UNUSED)
{
	if (!glvl_allowed(log_level))
		return;

	/* Rough estimation that should be enough in most cases */
	GString *gstr = g_string_sized_new(512);
	const gchar *x_ovh_token = g_getenv("OIO_LOG_X_OVH_TOKEN");
	if (x_ovh_token && *x_ovh_token) {
		g_string_append_static(gstr, "X-OVH-TOKEN:");
		g_string_append(gstr, x_ovh_token);
		g_string_append_c(gstr, '\t');
	}

	g_string_append_printf(gstr, "pid:%d\ttid:%04X", getpid(), oio_log_current_thread_id());

	const int facility = oio_log_domain2facility(log_domain);
	g_string_append_static(gstr, "\tlog_level:");
	g_string_append(gstr, oio_log_lvl2str(log_level));
	switch (facility) {
		case LOG_LOCAL1:
			g_string_append_static(gstr, "\tlog_type:access\t");
			break;
		case LOG_LOCAL2:
			g_string_append_static(gstr, "\tlog_type:out\tmessage:");
			break;
		default:
			if (log_domain && *log_domain) {
				g_string_append_static(gstr, "\tlog_domain:");
				g_string_append(gstr, log_domain);
			}
			g_string_append_static(gstr, "\tlog_type:log\tmessage:");
	}
    /*
     * message is already LTSV encoded with access logs (LOG_LOCAL1)
     * that is why "message:" is not added to those logs
     */
	g_string_append(gstr, message);

	const int severity = oio_log_lvl2severity(log_level);
	syslog(facility|severity, "%.*s", (int)gstr->len, gstr->str);
	g_string_free(gstr, TRUE);
}

void
oio_log_event_syslog(const gchar *log_domain UNUSED, GLogLevelFlags log_level,
	const gchar *message, gpointer user_data)
{
	if (!glvl_allowed(log_level)) {
		return;
	}

	GString *gstr = g_string_sized_new(1024);

	gchar* token = (gchar*)user_data;
	g_string_append_static(gstr, "X-OVH-TOKEN:");
	g_string_append(gstr, token);
	g_string_append_c(gstr, '\t');

	g_string_append(gstr, message);

	const int severity = oio_log_lvl2severity(log_level);
	syslog(LOG_LOCAL0|severity, "%.*s", (int)gstr->len, gstr->str);
	g_string_free(gstr, TRUE);
}

static void
_logger_stderr(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data UNUSED)
{
	GString *gstr = g_string_sized_new(512);

	g_string_append_printf(gstr, "%" G_GINT64_FORMAT " %d %04X ",
			g_get_monotonic_time(), getpid(), oio_log_current_thread_id());

	if (!log_domain || !*log_domain)
		log_domain = "-";

	const int facility = oio_log_domain2facility(log_domain);
	switch (facility) {
		case LOG_LOCAL1:
			g_string_append_static(gstr, "acc ");
			g_string_append(gstr, oio_log_lvl2str(log_level));
			break;
		case LOG_LOCAL2:
			g_string_append_static(gstr, "out ");
			g_string_append(gstr, oio_log_lvl2str(log_level));
			break;
		default:
			g_string_append_static(gstr, "log ");
			g_string_append(gstr, oio_log_lvl2str(log_level));
			g_string_append_c(gstr, ' ');
			g_string_append(gstr, log_domain);
	}

	g_string_append_c(gstr, ' ');
	g_string_append(gstr, message);

	g_string_append_c(gstr, '\n');

	_purify_in_place(gstr->str);

	/* send the buffer */
	fwrite(gstr->str, gstr->len, 1, stderr);
	g_string_free(gstr, TRUE);
}

void
oio_log_stderr(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	if (!glvl_allowed(log_level))
		return;
	_logger_stderr(log_domain, log_level, message, user_data);
}

void
oio_log_verbose(void)
{
	oio_log_level = (oio_log_level*2)+1;
}

void
oio_log_verbose_default(void)
{
	oio_log_level_default = (oio_log_level_default * 2) + 1;
	oio_log_level = oio_log_level_default;
}

void
oio_log_init_level(int l)
{
	oio_log_level_default = oio_log_level = (l?(l|0x7F):0);
}

void
oio_log_init_level_from_env(const gchar *k)
{
	const gchar *v = g_getenv(k);
	if (v) {
		switch (g_ascii_toupper(*v)) {
			case 'T':
				oio_log_init_level(GRID_LOGLVL_TRACE2);
				return;
			case 'D':
				oio_log_init_level(GRID_LOGLVL_DEBUG);
				return;
			case 'I':
				oio_log_init_level(GRID_LOGLVL_INFO);
				return;
			case 'N':
				oio_log_init_level(GRID_LOGLVL_NOTICE);
				return;
			case 'W':
				oio_log_init_level(GRID_LOGLVL_WARN);
				return;
			case 'E':
				oio_log_init_level(GRID_LOGLVL_ERROR);
				return;
		}
	}
}

void
oio_log_reset_level(void)
{
	oio_log_level = oio_log_level_default;
}

void
oio_log_quiet(void)
{
	oio_log_init_level(0);
}

void
oio_log_lazy_init (void)
{
	static volatile guint lazy_init = 1;
	if (lazy_init) {
		if (g_atomic_int_compare_and_exchange(&lazy_init, 1, 0)) {
			g_log_set_default_handler(oio_log_noop, NULL);
			oio_log_init_level(GRID_LOGLVL_ERROR);
		}
	}
}

static void
_handler_wrapper(const gchar *d UNUSED, GLogLevelFlags l,
		const gchar *m UNUSED, gpointer u)
{
	if (!glvl_allowed(l))
		return;

	oio_log_handler_f handler = u;
	switch (oio_log_lvl2severity(l)) {
		case LOG_ERR:
			return handler(OIO_LOG_ERROR, "%s", m);
		case LOG_WARNING:
			return handler(OIO_LOG_WARNING, "%s", m);
		case LOG_INFO:
			return handler(OIO_LOG_INFO, "%s", m);
		default:
			return handler(OIO_LOG_DEBUG, "%s", m);
	}
}

void
oio_log_set_handler (oio_log_handler_f handler)
{
	EXTRA_ASSERT(handler != NULL);
	g_log_set_default_handler(_handler_wrapper, handler);
}

