/*
OpenIO SDS server
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2022-2024 OVH SAS

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

#ifndef OIO_SDS__server__network_server_h
# define OIO_SDS__server__network_server_h 1

# include <server/slab.h>

struct network_server_s;
struct network_client_s;
struct network_transport_s;

/* To be defined by the application instantiating the transport */
struct transport_client_context_s;

enum {
	RC_ERROR,
	RC_NODATA,
	RC_NOTREADY,
	RC_PROCESSED,
};

typedef void (*network_transport_cleaner_f) (
			struct transport_client_context_s*);

struct network_transport_s
{
	/* Associate private data to the  */
	struct transport_client_context_s *client_context;

	network_transport_cleaner_f clean_context;

	/* Be notified that a piece of data is ready */
	int (*notify_input)  (struct network_client_s *);
	void (*notify_error)  (struct network_client_s *);
	gboolean waiting_for_close;
};

enum network_client_event_e {
	CLT_READ=0X01,
	CLT_WRITE=0X02,
	CLT_ERROR=0X04
};

struct network_client_s
{
	int fd;
	enum network_client_event_e events;
	struct network_server_s *server;

	int flags;
	struct { /* monotonic timers */
		gint64 cnx;
		gint64 evt_out;
		gint64 evt_in;
	} time;

	/* Pending input */
	struct data_slab_sequence_s input;
	/* Pending output */
	struct data_slab_sequence_s output;
	/* What to do with pending data */
	struct network_transport_s transport;
	GError *current_error;

	struct network_client_s *prev; /*!< DO NOT USE */
	struct network_client_s *next; /*!< DO NOT USE */

	gchar local_name[128];
	gchar peer_name[128];
};

extern GQuark gq_count_all;
extern GQuark gq_time_all;
extern GQuark gq_count_ioerror;
extern GQuark gq_time_ioerror;
extern GQuark gq_count_unexpected;
extern GQuark gq_time_unexpected;
extern GQuark gq_count_overloaded;
extern GQuark gq_time_overloaded;

struct network_server_s * network_server_init(void);

/** Get the total memory usage (RSS) of the process, in bytes. */
gint64 network_server_get_memory_usage(struct network_server_s *srv);

/** Test if request memory usage is under server_request_max_memory.
 * If too much memory is used, returns FALSE. */
gboolean network_server_has_free_memory(struct network_server_s *srv, guint64 how_much);

/** Test if request memory usage is under server_request_max_memory,
 * increase the counter by how_much, and return TRUE.
 * If too much memory is used, returns FALSE without touching the counter. */
gboolean network_server_request_memory(struct network_server_s *srv, guint64 how_much);

/** Decrease the counter by how_much. */
void network_server_release_memory(struct network_server_s *srv, guint64 how_much);

/* Re-set the limits of the server with the values stored in the central
 * configuration facility */
void network_server_reconfigure(struct network_server_s *srv);

/* must be called PRIOR to network_server_open_servers */
void network_server_allow_udp(struct network_server_s *srv);

typedef void (*network_transport_factory) (gpointer u,
		struct network_client_s *clt);

void network_server_bind_host(struct network_server_s *srv,
		const gchar *url, gpointer factory_udata,
		network_transport_factory factory);

/* returns a NULL-terminated array of strings, containing the actual IP:PORT
 * the server has been bond to, in the order they have been declared.
 * @param srv MUST be a valid server
 * @return a valid (but maybe empty) array of string, NULL terminated. Free it
 *         with g_strfreev() */
gchar** network_server_endpoints (struct network_server_s *srv);

int network_server_first_udp (struct network_server_s *srv);

void network_server_close_servers(struct network_server_s *srv);

/** Tell if the server has pending connections (active or inactive). */
gboolean network_server_has_connections(struct network_server_s *srv);

GError * network_server_open_servers(struct network_server_s *srv);

GError * network_server_run(struct network_server_s *srv,
		void (*on_reload)(void));

void network_server_stop(struct network_server_s *srv);

void network_server_clean(struct network_server_s *srv);
void network_server_postfork_clean(struct network_server_s *srv);

/* -------------------------------------------------------------------------- */

void network_client_allow_input(struct network_client_s *clt, gboolean v);

/** Configure a statsd client which will log all incoming requests */
void network_server_configure_statsd(struct network_server_s *srv,
		const gchar *service_type, const gchar *statsd_host, gint statsd_port);

/** Increment a (statsd) statistic */
void network_server_incr_stat(struct network_server_s *srv, gchar *metric_name);

/** Send a (statsd) gauge value. Integer expected. */
void network_server_send_gauge(struct network_server_s *srv, gchar *metric_name,
		guint64 value);

/** Send a (statsd) timing statistic. Microseconds expected. */
void network_server_send_timing(struct network_server_s *srv, gchar *metric_name,
		gint64 micros);

void network_client_close_output(struct network_client_s *clt, int now);

int network_client_send_slab(struct network_client_s *client,
		struct data_slab_s *slab);

#endif /*OIO_SDS__server__network_server_h*/
