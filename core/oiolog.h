/*
OpenIO SDS core library
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2024 OVH SAS

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

#ifndef OIO_SDS__core_oiolog_h
# define OIO_SDS__core_oiolog_h 1

# include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

# define GRID_LOGLVL_TRACE2 (64 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_TRACE  (32 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_DEBUG  (16 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_INFO   (8  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_NOTICE (4  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_WARN   (2  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_ERROR  (1  << G_LOG_LEVEL_USER_SHIFT)

/* enablers */
# ifdef HAVE_EXTRA_DEBUG
#  define GRID_TRACE2_ENABLED() (oio_log_level > GRID_LOGLVL_TRACE2)
#  define GRID_TRACE_ENABLED()  (oio_log_level > GRID_LOGLVL_TRACE)
# else
#  define GRID_TRACE2_ENABLED() (0)
#  define GRID_TRACE_ENABLED()  (0)
# endif

# define GRID_DEBUG_ENABLED()  (oio_log_level > GRID_LOGLVL_DEBUG)
# define GRID_INFO_ENABLED()   (oio_log_level > GRID_LOGLVL_INFO)
# define GRID_NOTICE_ENABLED() (oio_log_level > GRID_LOGLVL_NOTICE)
# define GRID_WARN_ENABLED()   (oio_log_level > GRID_LOGLVL_WARN)
# define GRID_ERROR_ENABLED()  (oio_log_level > 0)

/* new macros */
# ifdef HAVE_EXTRA_DEBUG
#  define GRID_TRACE2(FMT, ...) if (oio_log_level > GRID_LOGLVL_TRACE2)\
		g_log(G_LOG_DOMAIN, GRID_LOGLVL_TRACE2, FMT, ##__VA_ARGS__)
#  define GRID_TRACE(FMT,...)   if (oio_log_level > GRID_LOGLVL_TRACE)\
		g_log(G_LOG_DOMAIN, GRID_LOGLVL_TRACE, FMT, ##__VA_ARGS__)
# else
#  define GRID_TRACE2(FMT,...)
#  define GRID_TRACE(FMT,...)
# endif
# define GRID_DEBUG(FMT,...)   do { \
	if (GRID_DEBUG_ENABLED()) \
		g_log(G_LOG_DOMAIN, (GLogLevelFlags) GRID_LOGLVL_DEBUG, FMT, ##__VA_ARGS__); \
} while (0)
# define GRID_INFO(FMT,...)    g_log(G_LOG_DOMAIN, (GLogLevelFlags) GRID_LOGLVL_INFO, FMT, ##__VA_ARGS__)
# define GRID_NOTICE(FMT,...)  g_log(G_LOG_DOMAIN, (GLogLevelFlags) GRID_LOGLVL_NOTICE, FMT, ##__VA_ARGS__)
# define GRID_WARN(FMT,...)    g_log(G_LOG_DOMAIN, (GLogLevelFlags) GRID_LOGLVL_WARN, FMT, ##__VA_ARGS__)
# define GRID_ERROR(FMT,...)   g_log(G_LOG_DOMAIN, (GLogLevelFlags) GRID_LOGLVL_ERROR, FMT, ##__VA_ARGS__)

# define INCOMING(FMT,...) g_log("access", (GLogLevelFlags) GRID_LOGLVL_INFO, FMT, ##__VA_ARGS__)

/* oio_log_outgoing is a server-size variable auto-generated by confgen.py */
# define OUTGOING(FMT,...) do { \
	if (oio_log_outgoing) { \
		g_log("out", GRID_LOGLVL_INFO, FMT, ##__VA_ARGS__); \
	} \
} while (0)

/** Cruising debug level.
 * Should not be altered by the application after the program has started. */
extern int oio_log_level_default;

/** Current (transitional) debug level.
 * May be altered by the application, signals, etc. */
extern int oio_log_level;

/**
 * @deprecated
 * @todo TODO(jfs) Remove in next releases (requires the ABI increment)
 */
extern int oio_log_flags;

void oio_log_lazy_init (void);

void oio_log_verbose(void);

void oio_log_verbose_default(void);

void oio_log_quiet(void);

void oio_log_reset_level (void);

void oio_log_init_level(int l);

void oio_log_init_level_from_env(const gchar *k);

/** Writes the layed out message to stderr (not fd=2) with complete and
 * compact layout. */
void oio_log_stderr(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data);

/** Does nothing */
void oio_log_noop(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data);

/** Send the mesage though /dev/syslog, with simple layout */
void oio_log_syslog(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data);

void oio_log_event_syslog(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data);

guint16 oio_log_thread_id(GThread *thread);

guint16 oio_log_current_thread_id(void);

enum oio_log_level_e {
	OIO_LOG_ERROR = 0,
	OIO_LOG_WARNING = 1,
	OIO_LOG_INFO = 2,
	OIO_LOG_DEBUG = 3,
};

typedef void (*oio_log_handler_f) (enum oio_log_level_e lvl, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

void oio_log_set_handler (oio_log_handler_f handler);

const gchar* oio_log_lvl2str(GLogLevelFlags lvl);

int oio_log_lvl2severity(GLogLevelFlags lvl);

int oio_log_domain2facility(const char *dom);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core_oiolog_h*/
