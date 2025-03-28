/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo_remote_variables.h>

#include "sqliterepo.h"
#include "sqlx_remote.h"
#include "internals.h"

static GByteArray*
_pack_RESTORE(const struct sqlx_name_s *name, GByteArray *dump,
		const gchar *local_addr, gint64 deadline)
{
	GByteArray *encoded = sqlx_pack_RESTORE(
			name, dump->data, dump->len, local_addr, deadline);
	g_byte_array_unref(dump);
	return encoded;
}

GError *
peer_restore(const gchar *target, struct sqlx_name_s *name,
		GByteArray *dump, const gchar *local_addr, gint64 deadline)
{
	GError *err = NULL;

	if (!target) {
		g_byte_array_unref(dump);
		return NULL;
	}

	GByteArray *encoded = _pack_RESTORE(name, dump, local_addr,
			oio_clamp_deadline(oio_election_replicate_timeout_req, deadline));
	struct gridd_client_s *client = gridd_client_create(target, encoded, NULL, NULL);
	g_byte_array_unref(encoded);

	if (!client)
		return NEWERROR(CODE_INTERNAL_ERROR, "Failed to create client to [%s], bad address?", target);

	gridd_client_set_timeout_cnx(client,
			oio_clamp_timeout(oio_election_replicate_timeout_cnx, deadline));
	gridd_client_set_timeout(client,
			oio_clamp_timeout(oio_election_replicate_timeout_req, deadline));

	gridd_client_start(client);
	if (!(err = gridd_client_loop(client)))
		err = gridd_client_error(client);
	gridd_client_free(client);
	return err;
}

GError *
peers_restore(gchar **targets, struct sqlx_name_s *name,
		GByteArray *dump, const gchar *local_addr, gint64 deadline)
{
	GError *err = NULL;

	if (!targets || !targets[0]) {
		g_byte_array_unref(dump);
		return SYSERR("RESTORE failed [%s][%s]: no target to restore on",
				name->base, name->type);
	}

	GByteArray *encoded = _pack_RESTORE(name, dump, local_addr,
			oio_clamp_deadline(oio_election_replicate_timeout_req, deadline));
	struct gridd_client_s **clients = gridd_client_create_many(
			targets, encoded, NULL, NULL);
	g_byte_array_unref(encoded);
	if (!clients) {
		return SYSERR("RESTORE: failed to create replication clients, "
				"see service logs for more information.");
	}

	gridd_clients_set_timeout_cnx(clients,
			oio_clamp_timeout(oio_election_replicate_timeout_cnx, deadline));
	gridd_clients_set_timeout(clients,
			oio_clamp_timeout(oio_election_replicate_timeout_req, deadline));

	gridd_clients_start(clients);
	if (!(err = gridd_clients_loop(clients)))
		err = gridd_clients_error(clients);
	gridd_clients_free(clients);

	if (err) {
		g_prefix_error(&err, "RESTORE failed [%s][%s]: (%d) ",
				name->base, name->type, err->code);
	}
	return err;
}

GError *
peer_dump(const gchar *target, struct sqlx_name_s *name, gboolean chunked,
		gint check_type, peer_dump_cb callback, gpointer cb_arg,
		gint64 deadline)
{
	struct gridd_client_s *client;
	GByteArray *encoded;
	GError *err = NULL;

	gboolean on_reply(gpointer ctx, guint status UNUSED, MESSAGE reply) {
		GError *err2 = NULL;
		gsize bsize = 0;
		gint64 remaining = -1;
		(void) ctx;

		err2 = metautils_message_extract_strint64(reply, "remaining", FALSE,
				&remaining);
		if (err2 != NULL) {
			GRID_ERROR("Failed to extract 'remaining': (%d) %s (reqid=%s)",
					err2->code, err2->message, oio_ext_get_reqid());
			g_clear_error(&err2);
			return FALSE;
		}

		void *b = metautils_message_get_BODY(reply, &bsize);
		if (b && bsize) {
			GByteArray *dump = g_byte_array_new();
			g_byte_array_append(dump, b, bsize);
			err2 = callback(dump, remaining, cb_arg);
		}
		if (err2 != NULL) {
			GRID_ERROR("Failed to use result of dump: (%d) %s",
					err2->code, err2->message);
			g_clear_error(&err2);
			return FALSE;
		}
		return TRUE;
	}

	GRID_TRACE2("%s(%s,%p,%d,%p,%p)", __FUNCTION__, target, name, chunked,
			callback, cb_arg);

	if (!target)
		return SYSERR("No target URL");

	encoded = sqlx_pack_DUMP(name, chunked, check_type,
			oio_clamp_deadline(3600.0, deadline));
	client = gridd_client_create(target, encoded, NULL, on_reply);
	g_byte_array_unref(encoded);

	if (!client)
		return SYSERR("Failed to create client to [%s], bad address?", target);

	/* set a long timeout to allow moving large meta2 bases */
	gridd_client_set_timeout_cnx(client, oio_clamp_timeout(1.0, deadline));
	gridd_client_set_timeout(client, oio_clamp_timeout(3600.0, deadline));

	gridd_client_start(client);
	if (!(err = gridd_client_loop(client))) {
		err = gridd_client_error(client);
	}

	gridd_client_free(client);

	return err;
}
