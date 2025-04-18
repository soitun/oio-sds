/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__meta2v2__meta2_macros_h
# define OIO_SDS__meta2v2__meta2_macros_h 1

# ifndef M2V2_ADMIN_PREFIX_SYS
# define M2V2_ADMIN_PREFIX_SYS SQLX_ADMIN_PREFIX_SYS "m2."
# endif

# ifndef M2V2_ADMIN_PREFIX_USER
# define M2V2_ADMIN_PREFIX_USER SQLX_ADMIN_PREFIX_USER
# endif

# ifndef M2V2_ADMIN_VERSION
# define M2V2_ADMIN_VERSION M2V2_ADMIN_PREFIX_SYS "version"
# endif

# ifndef M2V2_ADMIN_QUOTA
# define M2V2_ADMIN_QUOTA M2V2_ADMIN_PREFIX_SYS "quota"
# endif

# ifndef M2V2_ADMIN_SIZE
# define M2V2_ADMIN_SIZE M2V2_ADMIN_PREFIX_SYS "usage"
# endif

# ifndef M2V2_ADMIN_OBJ_COUNT
# define M2V2_ADMIN_OBJ_COUNT M2V2_ADMIN_PREFIX_SYS "objects"
# endif

# ifndef M2V2_ADMIN_SHARD_COUNT
# define M2V2_ADMIN_SHARD_COUNT M2V2_ADMIN_PREFIX_SYS "shards"
# endif

# ifndef M2V2_ADMIN_DAMAGED_OBJECTS
# define M2V2_ADMIN_DAMAGED_OBJECTS M2V2_ADMIN_PREFIX_SYS "objects.damaged"
# endif

# ifndef M2V2_ADMIN_MISSING_CHUNKS
# define M2V2_ADMIN_MISSING_CHUNKS M2V2_ADMIN_PREFIX_SYS "chunks.missing"
# endif

# ifndef M2V2_ADMIN_PREFIX_SHARDING
# define M2V2_ADMIN_PREFIX_SHARDING M2V2_ADMIN_PREFIX_SYS "sharding."
# endif

# ifndef M2V2_ADMIN_SHARDING_STATE
# define M2V2_ADMIN_SHARDING_STATE M2V2_ADMIN_PREFIX_SHARDING "state"
# endif

# ifndef M2V2_ADMIN_SHARDING_TIMESTAMP
# define M2V2_ADMIN_SHARDING_TIMESTAMP M2V2_ADMIN_PREFIX_SHARDING "timestamp"
# endif

# ifndef M2V2_ADMIN_SHARDING_MASTER
# define M2V2_ADMIN_SHARDING_MASTER M2V2_ADMIN_PREFIX_SHARDING "master"
# endif

# ifndef M2V2_ADMIN_SHARDING_QUEUE
# define M2V2_ADMIN_SHARDING_QUEUE M2V2_ADMIN_PREFIX_SHARDING "queue"
# endif

# ifndef M2V2_ADMIN_SHARDING_ROOT
# define M2V2_ADMIN_SHARDING_ROOT M2V2_ADMIN_PREFIX_SHARDING "root"
# endif

# ifndef M2V2_ADMIN_SHARDING_LOWER
# define M2V2_ADMIN_SHARDING_LOWER M2V2_ADMIN_PREFIX_SHARDING "lower"
# endif

# ifndef M2V2_ADMIN_SHARDING_UPPER
# define M2V2_ADMIN_SHARDING_UPPER M2V2_ADMIN_PREFIX_SHARDING "upper"
# endif

# ifndef M2V2_ADMIN_SHARDING_PREVIOUS_LOWER
# define M2V2_ADMIN_SHARDING_PREVIOUS_LOWER M2V2_ADMIN_SHARDING_LOWER ".previous"
# endif

# ifndef M2V2_ADMIN_SHARDING_PREVIOUS_UPPER
# define M2V2_ADMIN_SHARDING_PREVIOUS_UPPER M2V2_ADMIN_SHARDING_UPPER ".previous"
# endif

# ifndef M2V2_ADMIN_SHARDING_COPIES
# define M2V2_ADMIN_SHARDING_COPIES M2V2_ADMIN_PREFIX_SHARDING "copies"
# endif

# ifndef M2V2_ADMIN_SHARDING_CLEANED_TABLES
# define M2V2_ADMIN_SHARDING_CLEANED_TABLES M2V2_ADMIN_PREFIX_SHARDING "tables.cleaned"
# endif

# ifndef M2V2_ADMIN_PREFIX_DRAINING
# define M2V2_ADMIN_PREFIX_DRAINING M2V2_ADMIN_PREFIX_SYS "draining."
# endif

# ifndef M2V2_ADMIN_DRAINING_STATE
# define M2V2_ADMIN_DRAINING_STATE M2V2_ADMIN_PREFIX_DRAINING "state"
# endif

# ifndef M2V2_ADMIN_DRAINING_MARKER
# define M2V2_ADMIN_DRAINING_MARKER M2V2_ADMIN_PREFIX_DRAINING "marker"
# endif

# ifndef M2V2_ADMIN_DRAINING_OBJ_COUNT
# define M2V2_ADMIN_DRAINING_OBJ_COUNT M2V2_ADMIN_PREFIX_DRAINING "objects"
# endif

# ifndef M2V2_ADMIN_DRAINING_TIMESTAMP
# define M2V2_ADMIN_DRAINING_TIMESTAMP M2V2_ADMIN_PREFIX_DRAINING "timestamp"
# endif

# ifndef M2V2_ADMIN_CTIME
# define M2V2_ADMIN_CTIME M2V2_ADMIN_PREFIX_SYS "ctime"
# endif

# ifndef M2V2_ADMIN_BUCKET_NAME
# define M2V2_ADMIN_BUCKET_NAME M2V2_ADMIN_PREFIX_SYS "bucket.name"
# endif

#ifndef M2V2_ADMIN_BUCKET_OBJECT_LOCK_ENABLED
#define M2V2_ADMIN_BUCKET_OBJECT_LOCK_ENABLED  M2V2_ADMIN_PREFIX_SYS \
	"bucket.objectlock.enabled"
#endif

# ifndef M2V2_ADMIN_VERSIONING_POLICY
# define M2V2_ADMIN_VERSIONING_POLICY M2V2_ADMIN_PREFIX_SYS "policy.version"
# endif

# ifndef M2V2_ADMIN_STORAGE_POLICY
# define M2V2_ADMIN_STORAGE_POLICY M2V2_ADMIN_PREFIX_SYS "policy.storage"
# endif

# ifndef M2V2_ADMIN_KEEP_DELETED_DELAY
# define M2V2_ADMIN_KEEP_DELETED_DELAY M2V2_ADMIN_PREFIX_SYS "keep_deleted_delay"
# endif

# ifndef M2V2_ADMIN_DELETE_EXCEEDING_VERSIONS
# define M2V2_ADMIN_DELETE_EXCEEDING_VERSIONS M2V2_ADMIN_VERSIONING_POLICY ".delete_exceeding"
# endif

# ifndef META2_INIT_FLAG
# define META2_INIT_FLAG M2V2_ADMIN_PREFIX_SYS "init"
# endif

# ifndef META2_EVENTS_PREFIX
# define META2_EVENTS_PREFIX "storage"
# endif

#define OBJ_PROP_LEGAL_HOLD_STATUS  "x-object-sysmeta-s3api-legal-hold-status"
#define OBJ_PROP_BYPASS_GOVERNANCE  "x-object-sysmeta-s3api-retention-bypass-governance"
#define OBJ_PROP_RETAIN_UNTILDATE   "x-object-sysmeta-s3api-retention-retainuntildate"
#define OBJ_PROP_RETENTION_MODE     "x-object-sysmeta-s3api-retention-mode"

#define OBJ_LOCK_ABORT_PATTERN      "object locked:"

// trigger conditions
#define TRIGGER_LEGAL_HOLD_NAME "trigger_objectlock_legal_hold"
#define TRIGGER_RETAIN_UNTIL_NAME "trigger_objectlock_retain_until"

#define LEGAL_HOLD_ON "SELECT 1 FROM properties pr WHERE " \
	"pr.alias=old.alias AND pr.version=old.version AND pr.key='" OBJ_PROP_LEGAL_HOLD_STATUS "'" \
	" AND CAST(pr.value AS TEXT) = 'ON'"

#define DELETED_FLAG "SELECT 1 FROM aliases WHERE " \
	"alias=old.alias AND version=old.version AND " \
	"CAST(old.content AS TEXT)='DELETED'"

#define CLEANING_ROOT "SELECT 1 FROM admin WHERE " \
	"k='" M2V2_ADMIN_SHARD_COUNT "' AND CAST(v AS INTEGER)>0"

#define SHARD_OUT_OF_RANGE \
	"(SELECT 1 FROM admin " \
	 "WHERE k='" M2V2_ADMIN_SHARDING_ROOT "' " \
	 "AND ((SELECT 1 FROM admin AS ad " \
		   "WHERE ad.k='" M2V2_ADMIN_SHARDING_LOWER "' " \
		   "AND CAST(ad.v AS TEXT) != '>' " \
		   "AND '>'||old.alias <= CAST(ad.v AS TEXT)) "\
		  "OR (SELECT 1 FROM admin AS ad " \
			  "WHERE ad.k='" M2V2_ADMIN_SHARDING_UPPER "'" \
			  "AND CAST(ad.v AS TEXT) != '<' " \
			  "AND '<'||old.alias > CAST(ad.v AS TEXT))))"

#define BYPASS_GOVERNANCE \
	"SELECT 1 FROM properties AS pr " \
	"WHERE pr.version=old.version "\
	"AND pr.alias=old.alias "\
	"AND pr.key='" OBJ_PROP_BYPASS_GOVERNANCE "' "\
	"AND CAST(pr.value AS TEXT)='True' "\
	"AND (SELECT 1 FROM properties AS pr " \
		 "WHERE pr.version=old.version " \
		 "AND pr.alias=old.alias "\
		 "AND pr.key='" OBJ_PROP_RETENTION_MODE "' " \
		 "AND CAST(pr.value AS TEXT)='GOVERNANCE')"

#define DISABLE_TRIGGERS \
	"INSERT OR REPLACE INTO admin VALUES ('disable_triggers', '1')"

#define DISABLED_TRIGGERS \
	"SELECT 1 FROM admin WHERE k='disable_triggers' AND v='1'"

/* Due to the way replication is done, it is risky to delete rows from the
 * admin table, it is safer to overwrite with something "false". */
#define ENABLE_TRIGGERS \
	"INSERT OR REPLACE INTO admin VALUES ('disable_triggers', '0')"

#define RETAIN_UNTIL_CONDITION \
	"SELECT 1 FROM properties AS pr " \
	"WHERE pr.version=old.version " \
	"AND pr.alias=old.alias " \
	"AND pr.key='" OBJ_PROP_RETAIN_UNTILDATE "' " \
	"AND ((strftime('%Y-%m-%dT%H:%M:%SZ','now') < CAST(pr.value AS TEXT)))"

#define TRIGGER_LEGAL_HOLD \
	"CREATE TRIGGER IF NOT EXISTS " TRIGGER_LEGAL_HOLD_NAME \
	" BEFORE DELETE ON aliases BEGIN " \
	"SELECT CASE WHEN " \
	 "NOT EXISTS (" DISABLED_TRIGGERS ") " \
	 "AND (NOT EXISTS (" CLEANING_ROOT " OR " SHARD_OUT_OF_RANGE ")) " \
	 "AND NOT EXISTS (" DELETED_FLAG ") " \
	 "AND EXISTS (" LEGAL_HOLD_ON ") " \
	"THEN RAISE (abort,'" \
	OBJ_LOCK_ABORT_PATTERN " deletion prevented by legal hold') " \
	"END; END;"

#define TRIGGER_RETAIN_UNTIL \
	"CREATE TRIGGER IF NOT EXISTS " TRIGGER_RETAIN_UNTIL_NAME \
	" BEFORE DELETE ON aliases BEGIN " \
	"SELECT CASE WHEN " \
	 "NOT EXISTS (" DISABLED_TRIGGERS ") " \
	 "AND (NOT EXISTS (" CLEANING_ROOT " OR " SHARD_OUT_OF_RANGE")) " \
	 "AND ((NOT EXISTS (" BYPASS_GOVERNANCE ")) " \
		  "AND NOT EXISTS (" DELETED_FLAG ") " \
		  "AND EXISTS (" RETAIN_UNTIL_CONDITION ")) " \
	"THEN RAISE (abort,'" \
	OBJ_LOCK_ABORT_PATTERN " deletion prevented by retain-until-date') " \
	"END; END;"


#define DROP_TRIGGER_LEGAL_HOLD "DROP TRIGGER IF EXISTS "\
	TRIGGER_LEGAL_HOLD_NAME ";"
#define DROP_TRIGGER_RETAIN_UNTIL "DROP TRIGGER IF EXISTS "\
	TRIGGER_RETAIN_UNTIL_NAME ";"

// Lifecycle tag
// Special key tag used to know the processed objects by any previous lifecycle
// rule
#define LIFECYCLE_SPECIAL_KEY_TAG "__processed_lifecycle"

// Lifecycle User-Agent
#define LIFECYCLE_USER_AGENT "lifecycle-action"

/* -------------------------------------------------------------------------- */

# define NAME_MSGNAME_M2V2_CREATE             "M2_CREATE"
# define NAME_MSGNAME_M2V2_DESTROY            "M2_DESTROY"
# define NAME_MSGNAME_M2V2_FLUSH              "M2_FLUSH"
# define NAME_MSGNAME_M2V2_PURGE_CONTENT      "M2_CPURGE"
# define NAME_MSGNAME_M2V2_PURGE_CONTAINER    "M2_BPURGE"
# define NAME_MSGNAME_M2V2_DEDUP              "M2_DEDUP"
# define NAME_MSGNAME_M2V2_PUT                "M2_PUT"
# define NAME_MSGNAME_M2V2_BEANS              "M2_PREP"
# define NAME_MSGNAME_M2V2_APPEND             "M2_APPEND"
# define NAME_MSGNAME_M2V2_GET                "M2_GET"
# define NAME_MSGNAME_M2V2_POLICY_TRANSITION  "M2_POLTRANS"
# define NAME_MSGNAME_M2V2_CONTENT_DRAIN      "M2_DRAIN"
# define NAME_MSGNAME_M2V2_CONTAINER_DRAIN    "M2_BDRAIN"
# define NAME_MSGNAME_M2V2_DEL                "M2_DEL"
# define NAME_MSGNAME_M2V2_TRUNC              "M2_TRUNC"
# define NAME_MSGNAME_M2V2_LIST               "M2_LST"
# define NAME_MSGNAME_M2V2_LCHUNK             "M2_LCHUNK"
# define NAME_MSGNAME_M2V2_LHID               "M2_LHID"
# define NAME_MSGNAME_M2V2_LHHASH             "M2_LHHASH"
# define NAME_MSGNAME_M2V2_ISEMPTY            "M2_EMPTY"
# define NAME_MSGNAME_M2V2_PROP_SET           "M2_PSET"
# define NAME_MSGNAME_M2V2_PROP_GET           "M2_PGET"
# define NAME_MSGNAME_M2V2_PROP_DEL           "M2_PDEL"
# define NAME_MSGNAME_M2V2_RAW_DEL            "M2_RAWDEL"
# define NAME_MSGNAME_M2V2_RAW_ADD            "M2_RAWADD"
# define NAME_MSGNAME_M2V2_RAW_SUBST          "M2_RAWSUBST"
# define NAME_MSGNAME_M2V1_TOUCH_CONTENT      "M2_CTOUCH"
# define NAME_MSGNAME_M2V1_TOUCH_CONTAINER    "M2_BTOUCH"
# define NAME_MSGNAME_M2V2_FIND_SHARDS        "M2_CSFIND"
# define NAME_MSGNAME_M2V2_PREPARE_SHARDING   "M2_CSPREP"
# define NAME_MSGNAME_M2V2_MERGE_SHARDING     "M2_CSRMERGE"
# define NAME_MSGNAME_M2V2_UPDATE_SHARD       "M2_CSUPD"
# define NAME_MSGNAME_M2V2_LOCK_SHARDING      "M2_CSLOCK"
# define NAME_MSGNAME_M2V2_REPLACE_SHARDING   "M2_CSREPL"
# define NAME_MSGNAME_M2V2_CLEAN_SHARDING     "M2_CSCLEAN"
# define NAME_MSGNAME_M2V2_SHOW_SHARDING      "M2_CSGET"
# define NAME_MSGNAME_M2V2_ABORT_SHARDING     "M2_CSABORT"
# define NAME_MSGNAME_M2V2_CHECKPOINT         "M2_CHECKPOINT"
# define NAME_MSGNAME_M2V2_SHARDS_IN_RANGE    "M2_CSRANGE"
# define NAME_MSGNAME_M2V2_APPLY_LIFECYCLE    "M2_LCPREP"
# define NAME_MSGNAME_M2V2_CREATE_LIFECYCLE_VIEWS  "M2_LCVIEW"

/* -------------------------------------------------------------------------- */

#define M2V2_FLAG_NODELETED        0x00000001
#define M2V2_FLAG_ALLVERSION       0x00000002
#define M2V2_FLAG_NOPROPS          0x00000004
#define M2V2_FLAG_MPUMARKER_ONLY   0x00000008
#define M2V2_FLAG_ALLPROPS         0x00000010

/* when listing */
#define M2V2_FLAG_HEADERS          0x00000020

/* when getting an alias, do not follow the foreign keys toward
 * headers, contents and chunks. */
#define M2V2_FLAG_NORECURSION      0x00000080

/* when getting an alias, ignores the version in the URL and
 * return the latest alias only. */
#define M2V2_FLAG_LATEST           0x00000100

/* flush the properties */
#define M2V2_FLAG_FLUSH            0x00000200

/* Ask the meta2 to redirect if not MASTER, even if the request is Read-Only */
#define M2V2_FLAG_MASTER           0x00000400

/* Ask the meta2 to open the database locally */
#define M2V2_FLAG_LOCAL            0x00000800

/* Request N spare chunks which should not be on provided blacklist */
#define M2V2_SPARE_BY_BLACKLIST "SPARE_BLACKLIST"

struct m2v2_create_params_s
{
	const char *storage_policy; /**< Will override the (maybe present) stgpol property. */
	const char *version_policy; /**< idem for the verpol property. */
	const char *peers; /**< Peers to replicate the database to. */

	/** A NULL-terminated sequence of strings where:
	 * properties[i*2] is the i-th key and
	 * properties[(i*2)+1] is the i-th value */
	gchar **properties;
	gboolean local; /**< Do not try to replicate, do not call get_peers() */
};

enum m2v2_destroy_flag_e
{
	/* send a destruction event */
	M2V2_DESTROY_EVENT = 0x01,
	M2V2_DESTROY_FLUSH = 0x02,
	M2V2_DESTROY_FORCE = 0x04,
};

/* Sharding ----------------------------------------------------------------- */

enum sharding_state_e {
	// Common states for container to shard/shrink
	EXISTING_SHARD_STATE_SAVING_WRITES = 1,
	EXISTING_SHARD_STATE_LOCKED,
	EXISTING_SHARD_STATE_SHARDED,
	EXISTING_SHARD_STATE_ABORTED,
	// Container to shrink
	EXISTING_SHARD_STATE_WAITING_MERGE,
	EXISTING_SHARD_STATE_MERGING,

	// New shard
	NEW_SHARD_STATE_APPLYING_SAVED_WRITES = 128,
	NEW_SHARD_STATE_CLEANING_UP,
	NEW_SHARD_STATE_CLEANED_UP,
};

#define SHARDING_IN_PROGRESS(S) ( \
		   (S) \
		&& (S) != EXISTING_SHARD_STATE_SHARDED \
		&& (S) != NEW_SHARD_STATE_CLEANED_UP \
		&& (S) != EXISTING_SHARD_STATE_ABORTED)

/* Draining ----------------------------------------------------------------- */

enum draining_state_e {
	// Container to drain
	DRAINING_STATE_NEEDED = 1,
	DRAINING_STATE_IN_PROGRESS,
};

#endif /*OIO_SDS__meta2v2__meta2_macros_h*/
