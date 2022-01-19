# Copyright (C) 2021-2022 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import re
import struct
from functools import wraps
import fdb

from six import text_type

from werkzeug.exceptions import NotFound, Conflict, BadRequest
from oio.common.exceptions import OioException
from oio.common.constants import BUCKET_PROP_REPLI_ENABLED
from oio.common.timestamp import Timestamp
from oio.common.easy_value import int_value, boolean_value, float_value, \
    debinarize
from oio.common.exceptions import ServiceBusy
from oio.account.common_fdb import CommonFdb

fdb.api_version(CommonFdb.FDB_VERSION)


def catch_service_errors(func):
    """
    :raises `ServiceBusy`: in case of a fdb service error
    """

    @wraps(func)
    def catch_service_errors_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (fdb.FDBError, ValueError) as err:
            raise ServiceBusy(message=str(err))

    return catch_service_errors_wrapper


class AccountBackendFdb(object):
    """
    Foundationdb backend for account service.
    """

    # This regex comes from https://stackoverflow.com/a/50484916
    #
    # The first group looks ahead to ensure that the match
    # is between 3 and 63 characters long.
    #
    # The next group (?!^(\d+\.)+\d+$) looks ahead to forbid matching
    # bucket names that look like IP addresses.
    #
    # <The last group matches zero or more labels followed by a dot *
    buckets_pattern = re.compile(
        r"""(?=^.{3,63}$)   # first group
        (?!^(\d+\.)+\d+$) # second
        (^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)* #third
        ([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)""", re.X)

    # Default batch size, this value could be divided by 2 if time of refresh
    # by batch is too long
    BATCH_SIZE = 10000

    # Default subspaces prefixes

    ACCOUNTS_KEY_PREFIX = 'accounts'
    ACCOUNT_KEY_PREFIX = 'account'
    BUCKET_KEY_PREFIX = 'bucket'
    BUCKET_LIST_PREFIX = 'buckets'
    CONTAINERS_LIST_PREFIX = 'containers'
    CONTAINER_LIST_PREFIX = 'container'
    # Remaining keys for deletex containers prefix
    CTS_TO_DELETE_LIST_PREFIX = 'deleted-container'
    # Metadata prefix
    METADATA_PREFIX = 'metadata'
    # Prefix for bucket db
    BUCKET_RESERVE_PREFIX = 's3bucket'
    # Stats & metric prefix
    METRICS_PREFIX = 'metrics'

    # Timeout for bucket reservation
    TIMEOUT = 60

    def init_db(self, event_model='gevent'):
        """
        This method makes connexion to fdb database. It could be called
        any time in mono process, but in case we fork processes it should be
        called after forking in gunicorn.
        This is the reason why this task is not done inside constructor.
        """
        self.fdb_file = self.conf.get('fdb_file',
                                      CommonFdb.DEFAULT_FDB)
        try:
            if self.db is None:
                self.db = fdb.open(self.fdb_file, event_model=event_model)
        except Exception as exc:
            self.logger.error("can't open fdb file: %s exception %s",
                              self.fdb_file, exc)
            raise
        try:
            self.namespace = fdb.directory.create_or_open(
                                    self.db, (self.main_namespace_name,))
            self.acct_space = self.namespace.create_or_open(
                                self.db,
                                self.account_prefix)
            self.accts_space = self.namespace.create_or_open(
                                self.db,
                                self.accounts_prefix)
            self.container_space = self.namespace.create_or_open(
                                    self.db,
                                    self.container_list_prefix)
            self.containers_index_space = self.namespace.create_or_open(
                                            self.db,
                                            self.containers_list_prefix)
            self.ct_to_delete_space = self.namespace.create_or_open(
                                        self.db,
                                        self.ct_to_delete_prefix)
            self.bucket_db_space = self.namespace.create_or_open(
                                    self.db,
                                    self.reserve_bucket_prefix)
            self.bucket_space = self.namespace.create_or_open(
                                    self.db,
                                    self.bucket_prefix)
            self.buckets_index_space = self.namespace.create_or_open(
                                    self.db,
                                    self.buckets_list_prefix)
            self.metadata_space = self.namespace.create_or_open(
                                    self.db,
                                    self.metadata_prefix)
            self.metrics_space = self.namespace.create_or_open(
                                    self.db,
                                    self.metrics_prefix)
        except Exception as exc:
            self.logger.warning("Directory create exception %s", exc)
            raise

    def __init__(self, conf, logger):
        self.db = None
        self.conf = conf
        self.logger = logger
        self.fdb_file = None
        self.autocreate = boolean_value(conf.get('autocreate'), True)
        self.time_window_clear_deleted = \
            float_value(self.conf.get('time_window_clear_deleted'), 60.0)
        self.main_namespace_name = self.conf.get('main_namespace_name',
                                                 CommonFdb.MAIN_NAMESPACE)
        self.accounts_prefix = conf.get('accounts_prefix',
                                        self.ACCOUNTS_KEY_PREFIX)
        self.account_prefix = conf.get('account_prefix',
                                       self.ACCOUNT_KEY_PREFIX)
        self.bucket_prefix = conf.get('bucket_prefix',
                                      self.BUCKET_KEY_PREFIX)
        self.buckets_list_prefix = conf.get('bucket_list_prefix',
                                            self.BUCKET_LIST_PREFIX)
        self.container_list_prefix = conf.get('container_list_prefix',
                                              self.CONTAINER_LIST_PREFIX)
        self.containers_list_prefix = conf.get('containers_list_prefix',
                                               self.CONTAINERS_LIST_PREFIX)
        self.ct_to_delete_prefix = conf.get('containers_to_delete_prefix',
                                            self.CTS_TO_DELETE_LIST_PREFIX)
        self.metadata_prefix = conf.get('metadata_prefix',
                                        self.METADATA_PREFIX)
        self.metrics_prefix = conf.get('metrics_prefix',
                                       self.METRICS_PREFIX)
        self.reserve_bucket_prefix = conf.get('reserve_bucket_prefix',
                                              self.BUCKET_RESERVE_PREFIX)

    def _seconds_to_us(self, timestamp):
        return int(timestamp * 1000000)

    def _us_to_seconds(self, timestamp):
        return timestamp / 1000000

    @catch_service_errors
    def create_account(self, account_id, **kwargs):
        """
        Create account account_id
        """
        if not account_id:
            return None
        # get ctime is only used for migration
        now = kwargs.get('ctime') or Timestamp().timestamp
        now_us = self._seconds_to_us(now)
        status = self._create_account(self.db, self.accts_space,
                                      self.acct_space, account_id, now_us)
        if not status:
            return None

        return account_id

    @catch_service_errors
    def delete_account(self, req_account_id, **kwargs):
        if not req_account_id:
            return None

        status = self._delete_account(self.db, req_account_id)
        if status is None:
            self.logger.info('account to delete %s not found', req_account_id)
        elif not status:
            self.logger.info('account to delete %s not empty', req_account_id)
        else:
            self.logger.info('account deleted %s', req_account_id)
        return status

    @catch_service_errors
    def get_account_metadata(self, req_account_id, **kwargs):
        if not req_account_id:
            return None
        account_id = self._val_element(self.db, self.acct_space,
                                       req_account_id, 'id')
        if account_id is None:
            self.logger.info('metadata account %s not found', account_id)
            return None

        account_id = account_id.decode('utf-8')
        meta = self._get_metada(self.db, account_id)
        return debinarize(meta)

    def cast_fields(self, info):
        """
        Cast dict entries to the type they are supposed to be.
        """
        for what in (b'bytes', b'objects'):
            try:
                info[what] = int_value(struct.unpack('<q', info.get(what))[0],
                                       0)
            except (TypeError, ValueError):
                pass
        for what in (b'ctime', b'mtime'):
            try:
                info[what] = self._us_to_seconds(
                                struct.unpack('<Q', info.get(what))[0])
            except (TypeError, ValueError):
                pass
        for what in (BUCKET_PROP_REPLI_ENABLED.encode('utf-8'), ):
            try:
                val = info.get(what)
                decoded = val.decode('utf-8') if val is not None else None
                info[what] = boolean_value(decoded)
            except (TypeError, ValueError):
                pass

    @catch_service_errors
    def get_bucket_info(self, bname, account=None, **kwargs):
        """
        Get all available information about a bucket.
        """
        if not bname:
            return None
        info = self._bucket_info(self.db, bname, account=account)
        if not info:
            return None
        return info

    @fdb.transactional
    def _bucket_info(self, tr, bname, account=None):
        if not account:
            account = tr[self.bucket_db_space.pack((bname, 'account'))]
            if not account.present():
                raise BadRequest('Missing account param or an owner')
            account = account.decode('utf-8')

        b_space = self.bucket_space[account][bname]
        b_range = b_space.range()
        iterator = tr.get_range(b_range.start, b_range.stop)
        info = {}
        for key, value in iterator:
            field, *policy = b_space.unpack(key)
            if policy:
                if len(policy) == 1:
                    details = info.setdefault(f"{field}-details", {})
                    details[policy[0]] = struct.unpack('<q', value)[0]
                else:
                    self.logger.warning('Unknown key: "%s"', key)
            elif field in ('bytes', 'objects'):
                info[field] = struct.unpack('<q', value)[0]
            elif field in ('mtime',):
                info[field] = self._us_to_seconds(
                    struct.unpack('<Q', value)[0])
            elif field in (BUCKET_PROP_REPLI_ENABLED):
                info[field] = boolean_value(value.decode('utf-8'))
            else:
                info[field] = value.decode('utf-8')
        return info

    @catch_service_errors
    def get_container_info(self, account_id, cname, **kwargs):
        """
        Get all available information about a container, including some
        information coming from the bucket it belongs to.
        """
        if not cname:
            return None
        info = self._container_info(self.db, account_id, cname)
        if not info:
            return None
        replication_enabled = None
        if info.get('bucket'):
            replication_enabled = self._val_element(
                self.db, self.bucket_space[account_id], info.get('bucket'),
                BUCKET_PROP_REPLI_ENABLED)
            if replication_enabled:
                replication_enabled = replication_enabled.decode('utf-8')
        info[BUCKET_PROP_REPLI_ENABLED] = boolean_value(replication_enabled)
        return info

    @fdb.transactional
    def _container_info(self, tr, account, container):
        container_space = self.container_space[account][container]
        container_range = container_space.range()
        iterator = tr.get_range(container_range.start, container_range.stop)
        info = {}
        for key, value in iterator:
            field, *policy = container_space.unpack(key)
            if policy:
                if len(policy) == 1:
                    details = info.setdefault(f"{field}-details", {})
                    details[policy[0]] = struct.unpack('<q', value)[0]
                else:
                    self.logger.warning('Unknown key: "%s"', key)
            elif field in ('bytes', 'objects'):
                info[field] = struct.unpack('<q', value)[0]
            elif field in ('mtime',):
                info[field] = self._us_to_seconds(
                    struct.unpack('<Q', value)[0])
            else:
                info[field] = value.decode('utf-8')
        return info

    @catch_service_errors
    def update_account_metadata(self, account_id, metadata, to_delete=None,
                                **kwargs):
        if not account_id:
            return None

        _acct_id = self._val_element(self.db, self.acct_space,
                                     account_id, 'id')

        if _acct_id is None:
            if self.autocreate:
                self.create_account(account_id)
            else:
                return None

        if not metadata and not to_delete:
            return account_id
        self._manage_metadata(self.db, self.metadata_space, account_id,
                              metadata, to_delete)

        return account_id

    @catch_service_errors
    def update_bucket_metadata(self, bname, metadata, to_delete=None,
                               account=None, **kwargs):
        """
        Update (or delete) bucket metadata.

        :param metadata: dict of entries to set (or update)
        :param to_delete: iterable of keys to delete
        """
        if not account:
            account = self.db[self.bucket_db_space.pack((bname, 'account'))]
            if not account:
                raise BadRequest('Missing account param or an owner')
            account = account.decode('utf-8')

        self._manage_metadata(self.db, self.bucket_space[account], bname,
                              metadata, to_delete)

        info = self._multi_get(self.db, self.bucket_space[account], bname)
        if not info:
            return None

        self.cast_fields(info)
        return info

    @catch_service_errors
    def info_account(self, req_account_id, **kwargs):
        """
        get account infos: containers, metadata and buckets
        """
        if not req_account_id:
            self.logger.info('No account id')
            return None

        if not self._is_element(self.db, self.accts_space, req_account_id):
            self.logger.info('Account %s doesn\'t exist', req_account_id)
            return None
        info = self._account_info(self.db, req_account_id)
        if not info:
            self.logger.warning('Account  %s infos not found', req_account_id)
            return None

        metadata = self._multi_get(self.db, self.metadata_space,
                                   req_account_id)
        info['metadata'] = debinarize(metadata)
        return info

    @fdb.transactional
    def _account_info(self, tr, account_id):
        info = {}

        acct_space = self.acct_space[account_id]
        a_range = acct_space.range()
        iterator = tr.get_range(a_range.start, a_range.stop)
        for key, value in iterator:
            field, *region = acct_space.unpack(key)
            if region:
                if len(region) <= 2:
                    details = info.setdefault('regions', {}).setdefault(
                        region[0], {})
                    if len(region) == 2:
                        details = details.setdefault(f"{field}-details", {})
                        field = region[1]  # polciy
                    details[field] = struct.unpack('<q', value)[0]
                else:
                    self.logger.warning('Unknown key: "%s"', key)
            elif field in ('bytes', 'objects', 'containers', 'buckets'):
                info[field] = struct.unpack('<q', value)[0]
            elif field in ('ctime', 'mtime'):
                info[field] = self._us_to_seconds(
                    struct.unpack('<Q', value)[0])
            else:
                info[field] = value.decode('utf-8')
        return info

    @catch_service_errors
    def list_accounts(self, **kwargs):
        """
        Get the list of all accounts.
        """
        accounts = self._list_accounts(self.db)
        return debinarize(accounts)

    @catch_service_errors
    def update_container(self, account_id, cname, mtime, dtime,
                         object_count, bytes_used,
                         bucket_name=None, autocreate_account=None,
                         autocreate_container=True, **kwargs):
        if not account_id or not cname:
            raise BadRequest("Missing account or container")

        if autocreate_account is None:
            autocreate_account = self.autocreate

        if mtime is None:
            mtime = 0
        else:
            mtime = Timestamp(mtime).timestamp
        if dtime is None:
            dtime = 0
        else:
            dtime = Timestamp(dtime).timestamp
        if object_count is None:
            object_count = 0
        if bytes_used is None:
            bytes_used = 0

        # ctime = kwargs.get('ctime') or None
        # If no bucket name is provided, set it to ''
        bucket_name = bucket_name or ''
        now = Timestamp().timestamp
        # bucket region
        region = kwargs.get('region')
        # dict object details per storage class
        objects_details = kwargs.get('objects_details') or {}
        bytes_details = kwargs.get('bytes_details') or {}

        # read mtime & dtime
        ct_space = self.container_space[account_id]
        cts_space = self.containers_index_space[account_id]

        new_mtime = self._seconds_to_us(mtime)
        new_dtime = self._seconds_to_us(dtime)
        now = self._seconds_to_us(now)

        status = self._update_container(self.db, cts_space, ct_space,
                                        account_id, cname, bucket_name,
                                        new_mtime, new_dtime, now,
                                        autocreate_account,
                                        autocreate_container, object_count,
                                        bytes_used, region,
                                        objects_details, bytes_details)

        return status

    @catch_service_errors
    def list_buckets(self, account_id, limit=1000, marker=None,
                     end_marker=None, prefix=None, **kwargs):
        """
        Get the list of buckets of the specified account.

        :returns: the list of buckets (with metadata), and the next
            marker (in case the list is truncated).
        """
        if prefix is None:
            prefix = ''

        bs_space = self.buckets_index_space[account_id]

        raw_list, next_marker = self._raw_listing_m1(
            self.db, account_id,  bs_space, limit, prefix,
            marker, end_marker)

        output = list()
        for bucket in raw_list:
            bdict = {
                'name': bucket[0],
                'objects': bucket[1],
                'bytes': bucket[2],
                'mtime': self._us_to_seconds(bucket[3])
            }
            output.append(bdict)
        return output, next_marker

    @catch_service_errors
    def list_containers(self, account_id, limit=1000, marker=None,
                        end_marker=None, prefix=None, **kwargs):
        if prefix is None:
            prefix = ''
        ct_index_space = self.containers_index_space[account_id]
        ct_space = self.container_space[account_id]
        raw_list, _ = self._raw_listing(
            self.db, ct_index_space, ct_space, limit, prefix,
            marker, end_marker)

        return raw_list

    @catch_service_errors
    def status(self, **kwargs):
        status = {'account_count': 0}
        if self.db is not None:
            s_range = self.accts_space.range()
            iterator = self.db.get_range(s_range.start, s_range.stop,
                                         reverse=False)
            count = 0
            for _, _ in iterator:
                count += 1
            status['account_count'] = count
            self.logger.debug('status: %s', status)
        else:
            self.logger.error('Failed to check connect to fdb server')
            raise OioException('Connection failed to db')
        return status

    @catch_service_errors
    def refresh_bucket(self, bucket_name, **kwargs):
        """
        Refresh the counters of a bucket. Recompute them from the counters
        of all shards (containers).
        """
        batch_size = kwargs.get("batch_size", self.BATCH_SIZE)
        marker = None
        account_id = self._val_element(self.db, self.bucket_db_space,
                                       bucket_name, 'account')
        if account_id is None:
            return

        account_id = account_id.decode('utf-8')
        bucket_space = self.bucket_space[account_id][bucket_name]

        containers = self._list_containers(self.db, account_id, bucket_name)

        sharded_marker = None
        if containers is not None:
            for el in containers:
                while True:
                    next_marker = self._refresh_sharded_ct(
                        self.db, account_id, el, sharded_marker, batch_size)
                    if next_marker is None or next_marker == sharded_marker:
                        break

                    sharded_marker = next_marker

        marker = None
        # refresh based on non sharded or root containers
        while True:
            marker = self._refresh_bucket(self.db, bucket_space, bucket_name,
                                          account_id, batch_size, marker)
            if marker in (None, 'no_bucket'):
                break

        if text_type(marker).endswith("no_account"):
            raise NotFound("Account not found for bucket" % bucket_name)
        if text_type(marker).endswith("no_bucket"):
            raise NotFound("Bucket %s not found" % bucket_name)

    @catch_service_errors
    def refresh_account(self, account_id, **kwargs):
        if not account_id:
            raise BadRequest("Missing account")
        self._refresh_account(self.db, account_id)

    @catch_service_errors
    def flush_account(self, account_id, **kwargs):
        if not account_id:
            raise BadRequest("Missing account")

        if not self._is_element(self.db, self.accts_space, account_id):
            raise NotFound(account_id)

        self._flush_account(self.db, account_id)

    @catch_service_errors
    def reserve_bucket(self, account_id, bucket_name, **kwargs):
        timeout = kwargs.get('timeout', self.TIMEOUT)
        if account_id is None:
            return {'reserved': 0}
        reserved = self._reserve_bucket(self.db, bucket_name, account_id,
                                        timeout)
        return {'reserved': reserved}

    @fdb.transactional
    def _reserve_bucket(self, tr, bucket_name, account_id, timeout):
        space_ = self.bucket_db_space[bucket_name]
        timestamp = 0
        if tr[space_.pack(('account',))].present():
            return 0

        reservation_timestamp = tr[space_.pack(('timestamp',))]
        now = Timestamp().timestamp
        now_us = self._seconds_to_us(now)
        if reservation_timestamp.present():
            timestamp = struct.unpack('<Q', reservation_timestamp.value)[0]
            if self._us_to_seconds(timestamp) + timeout < now:
                tr[space_.pack(('timestamp',))] = struct.pack('<Q', now_us)
                return 1
            else:
                # Some other reservation is ongoing
                return 0
        else:
            tr[space_.pack(('timestamp',))] = struct.pack('<Q', now_us)
            return 1

    @catch_service_errors
    def release_bucket(self, bucket_name, **kwargs):
        reserved_space = self.bucket_db_space[bucket_name]
        self._release_bucket(self.db, reserved_space)
        return True

    @fdb.transactional
    def _release_bucket(self, tr, space):
        tr.clear_range_startswith(space)

    @catch_service_errors
    def set_bucket_owner(self, account_id, bucket_name, **kwargs):
        self._set_bucket_owner(self.db, account_id, bucket_name)

    @fdb.transactional
    def _set_bucket_owner(self, tr, account_id, bucket_name):
        reserved_space = self.bucket_db_space[bucket_name]
        tr[reserved_space.pack(('account',))] = bytes(account_id, 'utf-8')
        del tr[reserved_space.pack(('timestamp',))]

    @catch_service_errors
    def get_bucket_owner(self, bucket_name, **kwargs):
        account = self._val_element(self.db, self.bucket_db_space,
                                    bucket_name, 'account')
        if account is None:
            return {'account': None}
        else:
            account_ = account.decode('utf-8')
            return {'account': account_}

    @catch_service_errors
    def info_metrics(self, output_type, **kwargs):
        # generic metrics:
        # number of accounts
        # number of buckets per region
        # number of containers per region
        # number of objects per region /storage policy
        metrics = self._info_metrics(self.db)
        if output_type == 'prometheus':
            return self._format_metrics(metrics)
        else:
            return metrics

    def _format_metrics(self, metrics):
        prom_output = []
        prom_output.append(f"obsto_accounts {metrics['accounts']}")
        for region, region_details in metrics['regions'].items():
            for counter, counter_value in region_details.items():
                if counter.endswith('-details'):
                    counter = counter[:-8]
                    for policy, policy_value in counter_value.items():
                        prom_output.append(
                            f"obsto_{counter}{{region=\"{region}\","
                            f"policy=\"{policy}\"}} {policy_value}")
                else:
                    prom_output.append(
                        f"obsto_{counter}{{region=\"{region}\"}} "
                        f"{counter_value}")
        return '\n'.join(prom_output)

    @fdb.transactional
    def _info_metrics(self, tr):
        metrics_range = self.metrics_space.range()
        iterator = tr.get_range(metrics_range.start, metrics_range.stop,
                                streaming_mode=fdb.StreamingMode.want_all)
        metrics = {
            'accounts': 0,
            'regions': {}
        }
        for key, value in iterator:
            field, *region = self.metrics_space.unpack(key)
            if not region:
                metrics[field] = struct.unpack('<q', value)[0]
            elif len(region) <= 2:
                details = metrics['regions'].setdefault(region[0], {})
                if len(region) == 2:
                    details = details.setdefault(f"{field}-details", {})
                    field = region[1]  # polciy
                details[field] = struct.unpack('<q', value)[0]
            else:
                self.logger.warning('Unknown key: "%s"', key)
        return metrics

    @fdb.transactional
    def _increment(self, tr, counter, incr_by=1):
        tr.add(counter, struct.pack('<q', incr_by))

    @fdb.transactional
    def _decrement(self, tr, counter, decr_by=-1):
        tr.add(counter, struct.pack('<q', decr_by))

    @fdb.transactional
    def _flush_account(self, tr, account_id):
        # Reset stats
        account_space = self.acct_space[account_id]
        for field in ('bytes', 'objects', 'containers', 'buckets'):
            tr[account_space.pack((field,))] = struct.pack('<q', 0)
            details_space = account_space[field]
            details_range = details_space.range()
            # Update metrics
            iterator = tr.get_range(details_range.start, details_range.stop)
            for key, value in iterator:
                key = account_space.unpack(key)
                value = struct.unpack('<q', value)[0]
                self._decrement(tr, self.metrics_space.pack(key), -value)
            # Remove details by region
            tr.clear_range(details_range.start, details_range.stop)
        # Delete containers
        containers_range = self.containers_index_space[account_id].range()
        tr.clear_range(containers_range.start, containers_range.stop)
        container_range = self.container_space[account_id].range()
        tr.clear_range(container_range.start, container_range.stop)
        # Delete deleted containers
        deleted_containers_range = self.ct_to_delete_space[account_id].range()
        tr.clear_range(deleted_containers_range.start,
                       deleted_containers_range.stop)
        # Delete buckets
        buckets_range = self.buckets_index_space[account_id].range()
        tr.clear_range(buckets_range.start, buckets_range.stop)
        bucket_range = self.bucket_space[account_id].range()
        tr.clear_range(bucket_range.start, bucket_range.stop)
        # TODO(adu): Update mtime

    @fdb.transactional
    def _create_account(self, tr, accts_space, acct_space, account_id, now):

        if self._is_element(tr, accts_space, account_id):
            return False
        tr[accts_space.pack((account_id,))] = b'1'
        tr[acct_space.pack((account_id, 'id'))] = \
            bytes(account_id, 'utf-8')
        tr[acct_space.pack((account_id, 'bytes'))] = struct.pack('<q', 0)
        tr[acct_space.pack((account_id, 'objects'))] = struct.pack('<q', 0)
        tr[acct_space.pack((account_id, 'containers'))] = struct.pack('<q', 0)
        tr[acct_space.pack((account_id, 'buckets'))] = struct.pack('<q', 0)
        tr[acct_space.pack((account_id, 'ctime'))] = struct.pack('<Q', now)
        tr[acct_space.pack((account_id, 'mtime'))] = struct.pack('<Q', now)

        # metrics
        self._increment(tr, self.metrics_space.pack(('accounts',)))
        return True

    @fdb.transactional
    def _delete_account(self, tr, req_account_id):

        account_id = self._val_element(tr, self.acct_space,
                                       req_account_id, 'id')
        if account_id is None:
            return None
        account_id = account_id.decode('utf-8')

        ct_account_space = self.container_space[account_id]
        s_range = ct_account_space.range()
        iterator = tr.get_range(s_range.start, s_range.stop,
                                reverse=False)
        for _, _ in iterator:
            return False

        tr.clear_range_startswith(self.acct_space[account_id])
        tr.clear_range_startswith(self.accts_space[account_id])
        tr.clear_range_startswith(self.ct_to_delete_space[account_id])
        tr.clear_range_startswith(self.metadata_space[account_id])
        tr.clear_range_startswith(self.containers_index_space[account_id])
        self._decrement(tr, self.metrics_space.pack(('accounts',)))
        return True

    @fdb.transactional
    def _list_accounts(self, tr):
        # iterate over the whole 'accounts:' subspace
        iterator = tr.get_range_startswith(self.accts_space)
        res = list()
        for key, _ in iterator:
            account_id = self.accts_space.unpack(key)[0]
            res.append(account_id)
        return res

    @fdb.transactional
    def _refresh_account(self, tr, account_id):
        if not self._is_element(tr, self.accts_space, account_id):
            raise NotFound(account_id)

        ct_space = self.container_space[account_id]
        s_range = ct_space.range()

        iterator = tr.get_range(s_range.start, s_range.stop, reverse=False)
        sum_bytes = 0
        sum_objects = 0
        for key, val in iterator:
            _, field, *policy_region = ct_space.unpack(key)
            if policy_region:
                continue
            if field == 'bytes':
                sum_bytes += struct.unpack('<q', val)[0]
            if field == 'objects':
                sum_objects += struct.unpack('<q', val)[0]

        tr[self.acct_space.pack((account_id, 'bytes'))] = \
            struct.pack('<q', sum_bytes)
        tr[self.acct_space.pack((account_id, 'objects'))] = \
            struct.pack('<q', sum_objects)

    @fdb.transactional
    def _update_container(self, tr, cts_space, ct_space, account_id, cname,
                          bucket_name, new_mtime, new_dtime, now,
                          autocreate_account, autocreate_container,
                          new_total_objects, new_total_bytes, region,
                          objects_details, bytes_details):
        creation = False
        to_delete_space = self.ct_to_delete_space[account_id]

        account_exists = self._is_element(tr, self.accts_space, account_id)
        if not account_exists:
            if autocreate_account:
                self._create_account(tr, self.accts_space, self.acct_space,
                                     account_id, now)
            else:
                raise NotFound("Account %s not found" % account_id)
        if not autocreate_container:
            container_exists = tr[ct_space.pack((cname, 'name'))].present()
            if not container_exists:
                raise NotFound("Container %s not found" % cname)
        deleted_time = 0
        dtime = 0
        delete_cname_time = tr[to_delete_space.pack((cname,))]
        if delete_cname_time.present():
            deleted_time = struct.unpack('<Q', delete_cname_time.value)[0]
        # real update
        if tr[ct_space.pack((cname, 'name'))].present():
            mtime_field = tr[ct_space.pack((cname, 'mtime'))]
            mtime = struct.unpack('<Q', mtime_field.value)[0]
            nb_objects_field = tr[ct_space.pack((cname, 'objects'))]
            nb_bytes_field = tr[ct_space.pack((cname, 'bytes'))]
            nb_objects = 0
            nb_bytes = 0
            if nb_objects_field.present():
                nb_objects = struct.unpack('<q', nb_objects_field.value)[0]
            if nb_bytes_field.present():
                nb_bytes = struct.unpack('<q', nb_bytes_field.value)[0]
        # event update interleaved with container delete
        elif new_mtime < deleted_time:
            raise Conflict('No update needed, '
                           'event older than last container update')
        else:  # real creation
            mtime = 0
            nb_objects = 0
            nb_bytes = 0
            creation = True

        if not autocreate_container and dtime >= mtime:
            raise NotFound("Container %s not found" % cname)

        region = self._get_region(tr, account_id, cname, region)
        current_bucket_name = self._val_element(tr, ct_space, cname, 'bucket')

        old_mtime = mtime
        inc_objects = 0
        inc_bytes = 0
        deltas = None
        deleted = False
        if new_mtime <= mtime and \
           new_dtime <= dtime:
            raise Conflict("No update needed, "
                           "event older than last container update")

        if new_mtime > mtime:
            mtime = new_mtime
        if new_dtime > dtime:
            dtime = new_dtime

        if dtime >= mtime:
            mtime = dtime
            # Protect against "minus zero".
            if nb_objects != 0:
                inc_objects -= nb_objects
            if nb_bytes != 0:
                inc_bytes -= nb_bytes
            deltas = self._update_ct_stats_policy(
                tr, account_id, cname, {}, {})

            # remove container cname from container:account
            # and from containers:account
            container_range = ct_space[cname].range()
            tr.clear_range(container_range.start, container_range.stop)
            tr.clear(cts_space.pack((cname,)))
            tr[to_delete_space.pack((cname,))] = struct.pack('<Q', dtime)

            # decrement account and metrics
            self._decrement(tr, self.acct_space[account_id].pack(
                ('containers',)))
            self._decrement(tr, self.acct_space[account_id].pack(
                ('containers', region)))
            self._decrement(tr, self.metrics_space.pack(
                ('containers', region)))
            # clean ct_to_delete_space
            self._clear_deleted_containers(tr, account_id, now)

            deleted = True

        elif mtime > old_mtime:
            inc_objects = new_total_objects - int(nb_objects)
            inc_bytes = new_total_bytes - int(nb_bytes)
            tr[ct_space.pack((cname, 'objects'))] = \
                struct.pack('<q', new_total_objects)
            tr[ct_space.pack((cname, 'bytes'))] = \
                struct.pack('<q', new_total_bytes)
            tr[cts_space.pack((cname,))] = b'1'
            tr[ct_space.pack((cname, 'name'))] = bytes(str(cname), 'utf-8')
            tr.max(ct_space.pack((cname, 'mtime')), struct.pack('<Q', mtime))
            tr[ct_space.pack((cname, 'region'))] = bytes(region, 'utf-8')

            if creation:
                # delete old dtime
                tr.clear(self.ct_to_delete_space.pack((account_id, cname)))
                # increment account and metrics
                self._increment(tr, self.acct_space[account_id].pack(
                    ('containers',)))
                self._increment(tr, self.acct_space[account_id].pack(
                    ('containers', region)))
                self._increment(tr, self.metrics_space.pack(
                    ('containers', region)))

        else:
            raise Conflict("No update needed, "
                           "event older than last container update")

        # increase account and metrics stats
        if inc_objects != 0:
            self._increment(
                tr, self.acct_space.pack((account_id, 'objects')), inc_objects)
            self._increment(
                tr, self.acct_space.pack((account_id, 'objects', region)),
                inc_objects)
            self._increment(
                tr, self.metrics_space.pack(('objects', region)),
                inc_objects)
        if inc_bytes != 0:
            self._increment(
                tr, self.acct_space.pack((account_id, 'bytes')), inc_bytes)
            self._increment(
                tr, self.acct_space.pack((account_id, 'bytes', region)),
                inc_bytes)
            self._increment(
                tr, self.metrics_space.pack(('bytes', region)),
                inc_bytes)
        tr.max(self.acct_space.pack((account_id, 'mtime')),
               struct.pack('<Q', max(mtime, dtime)))

        if not deleted:
            deltas = self._update_ct_stats_policy(
                tr, account_id, cname, objects_details, bytes_details)

        # incr / decr relative values
        for policy, dict_field in deltas.items():
            for field, value in dict_field.items():
                if value > 0:
                    self._increment(tr, self.metrics_space.pack(
                                    (field, region, policy)),
                                    value)
                    self._increment(tr, self.acct_space[account_id].pack(
                                    (field, region, policy)),
                                    value)
                else:
                    self._decrement(tr, self.metrics_space.pack(
                                    (field, region, policy)),
                                    value)
                    self._decrement(tr, self.acct_space[account_id].pack(
                                    (field, region, policy)),
                                    value)

        if not bucket_name and current_bucket_name is not None:
            # Use the bucket name already registered when it is not given
            bucket_name = current_bucket_name.decode('utf-8')
        if bucket_name:
            bucket_account = account_id
            if account_id.startswith('.shards_'):
                bucket_account = account_id[8:]

            bucket_already_exists = tr[self.bucket_space.pack(
                (bucket_account, bucket_name, 'mtime'))].present()

            # FIXME(FVE): this may no be needed anymore
            # This container is not yet associated with this bucket.
            # We must add all the totals in case the container
            # already existed but didn't know its parent bucket.
            if not deleted and current_bucket_name is None:
                inc_objects = new_total_objects
                inc_bytes = new_total_bytes

            container_name = cname
            if deleted:
                if not bucket_already_exists:
                    return
                #  Delete the bucket if it's the root container
                if bucket_account == account_id \
                        and bucket_name == container_name:
                    tr.clear(self.buckets_index_space.pack(
                        (bucket_account, bucket_name)))
                    tr.clear(self.buckets_index_space.pack(
                        (region, bucket_account, bucket_name)))
                    # Also delete the bucket
                    bucket_range = self.bucket_space[bucket_account][
                        bucket_name].range()
                    tr.clear_range(bucket_range.start, bucket_range.stop)

                    # decrements account and metrics
                    self._decrement(tr, self.acct_space[bucket_account].pack(
                                ('buckets',)))
                    self._decrement(tr, self.acct_space[bucket_account].pack(
                                ('buckets', region)))
                    self._decrement(tr, self.metrics_space.pack(
                                ('buckets', region)))
                    return

                # We used to return here. But since we delete shard before
                # cleaning them, we need to fix counters first.

            # For container holding MPU segments, we do not want to count
            # each segment as an object. But we still want to consider
            # their size.
            is_segment = False
            if '+segments' in container_name:
                inc_objects = 0
                is_segment = True

            # Check if a refresh bucket is in progress
            # No lock is needed as add operation is atomic
            # local marker = redis.call("HGET", bucket_lock, "marker")

            # Increment the counters if needed.
            # if marker == false or container_name <= marker then
            if tr[self.bucket_space.pack((bucket_account, bucket_name,
               'objects'))].present():
                tr.add(self.bucket_space.pack(
                    (bucket_account, bucket_name, 'objects')),
                        struct.pack('<q', inc_objects))
            else:
                tr[self.bucket_space.pack(
                    (bucket_account, bucket_name, 'objects'))] = \
                        struct.pack('<q', inc_objects)

            if tr[self.bucket_space.pack((bucket_account, bucket_name,
               'bytes'))].present():
                tr.add(self.bucket_space.pack(
                    (bucket_account, bucket_name, 'bytes')),
                       struct.pack('<q', inc_bytes))
            else:
                tr[self.bucket_space.pack(
                    (bucket_account, bucket_name, 'bytes'))] = \
                        struct.pack('<q', inc_bytes)

            tr[self.bucket_space.pack(
                (bucket_account, bucket_name, 'region'))] = \
                region.encode('utf-8')

            # Update the modification time.
            tr.max(self.bucket_space.pack(
                (bucket_account, bucket_name, 'mtime')),
                struct.pack('<Q', max(mtime, dtime)))

            self._update_bucket_per_policy(tr, bucket_name, bucket_account,
                                           is_segment, deltas)

            if deleted:
                return 'deleted'
            # Set the bucket owner.
            tr[self.bucket_space.pack(
                (bucket_account, bucket_name, 'account'))] = \
                bucket_account.encode('utf-8')

            # Update container info
            tr[ct_space.pack((cname, 'bucket'))] = \
                bytes(str(bucket_name), 'utf-8')

            # Create bucket
            if not bucket_already_exists:
                tr[self.buckets_index_space.pack(
                    (bucket_account, bucket_name))] = b'1'
                tr[self.buckets_index_space.pack(
                    (region, bucket_account, bucket_name))] = b'1'
                # increments account and metrics
                if creation:
                    self._increment(tr, self.acct_space[bucket_account].pack(
                        ('buckets',)))
                    self._increment(tr, self.acct_space[bucket_account].pack(
                        ('buckets', region)))
                    self._increment(tr, self.metrics_space.pack(
                        ('buckets', region)))
        return 'updated'

    @fdb.transactional
    def _get_region(self, tr, account_id, ct_name, region):
        if region:
            return region
        region = self._val_element(tr, self.container_space[account_id],
                                   ct_name, 'region')
        if region is not None:
            return region.decode('utf-8')
        raise BadRequest('Missing region')

    @fdb.transactional
    def _update_ct_stats_policy(self, tr, account_id, cname,
                                objs_per_policy, bytes_per_policy):
        """
        Read current values for given container and per policy
        Compute deltas, update values then return deltas
        """
        current_values = dict()
        deltas = dict()
        c_space = self.container_space[account_id][cname]
        for policy, value in objs_per_policy.items():
            if policy not in current_values.keys():
                current_values[policy] = {}
            if policy not in deltas:
                deltas[policy] = {}
            nb_obj_ct = tr[c_space.pack(('objects', policy))]
            nb_obj_ct_val = 0
            if nb_obj_ct.present():
                nb_obj_ct_val = struct.unpack('<q', nb_obj_ct.value)[0]
            current_values[policy]['objects'] = nb_obj_ct_val

            delta = value - current_values[policy]['objects']
            if value > 0 and delta != 0:
                deltas[policy]['objects'] = delta
                tr[c_space.pack(('objects', policy))] = \
                    struct.pack('<q', value)

        for policy, value in bytes_per_policy.items():
            if policy not in current_values.keys():
                current_values[policy] = {}
            if policy not in deltas:
                deltas[policy] = {}
            nb_bytes_ct = tr[c_space.pack(('bytes', policy))]
            nb_bytes_ct_val = 0
            if nb_bytes_ct.present():
                nb_bytes_ct_val = struct.unpack('<q', nb_bytes_ct.value)[0]
            current_values[policy]['bytes'] = nb_bytes_ct_val

            delta = value - current_values[policy]['bytes']
            # update values only when needed
            if value > 0 and delta != 0:
                deltas[policy]['bytes'] = delta
                tr[c_space.pack(('bytes', policy))] = \
                    struct.pack('<q', value)

        # empty policies that are not present in objs_per_policy
        reg_range = c_space.range()
        res = tr.get_range(reg_range.start, reg_range.stop)

        # gather data to deduce from metrics
        for key, val in res:
            field, *policy = c_space.unpack(key)
            if policy and field in ('bytes', 'objects'):
                pol = policy[0]
                if pol and pol not in objs_per_policy:
                    if pol not in deltas:
                        deltas[pol] = {}
                    deltas[pol][field] = - struct.unpack('<q', val)[0]
        # clear not present policies for given container
        policies_to_clear = list()
        for key, val in res:
            field, *policy = c_space.unpack(key)
            if policy:
                pol = policy[0]
                if pol and pol not in objs_per_policy and \
                   pol not in policies_to_clear:
                    policies_to_clear.append(pol)
        for pol in policies_to_clear:
            tr.clear_range_startswith(c_space.pack(('bytes', pol)))
            tr.clear_range_startswith(c_space.pack(('objects', pol)))

        return deltas

    @fdb.transactional
    def _update_bucket_per_policy(self, tr, bucket_name, account_id,
                                  is_segment, deltas):
        """
        Update objects/bytes per policy for given bucket
        """
        bucket_obj_space = self.bucket_space[account_id][bucket_name]
        # incr / decr relative values
        for policy, dict_field in deltas.items():
            for field, value in dict_field.items():
                if is_segment and field == 'objects':
                    continue
                if value > 0:
                    self._increment(tr, bucket_obj_space.pack(
                                    (field, policy)), value)
                else:
                    self._decrement(tr, bucket_obj_space.pack(
                                    (field, policy)), value)

    @fdb.transactional
    def _raw_listing(self, tr, index_space, main_space, limit, prefix,
                     marker, end_marker):
        start = index_space.range().start
        stop = index_space.range().stop

        min_k = None
        max_k = stop

        orig_marker = marker
        results = list()
        beyond_prefix = False
        if prefix is None:
            prefix = ''

        if marker:
            marker = fdb.KeySelector.first_greater_or_equal(
                        index_space.pack((marker,)))

        while len(results) < limit and not beyond_prefix:
            min_k = start
            max_k = stop
            local_limit = (limit - len(results) + 1)

            if prefix:
                max_k = stop
                min_k = fdb.KeySelector.first_greater_or_equal(
                    index_space.pack((prefix,)))

            if marker and (not prefix or
                           tr.get_key(marker) >= tr.get_key(min_k)):
                min_k = marker

            if end_marker and (not prefix
                               or end_marker <= prefix + b'\xff'):
                max_k = fdb.KeySelector.last_less_or_equal(
                            index_space.pack((end_marker,)))

            iterator = tr.snapshot.get_range(min_k, max_k, limit=local_limit,
                                             reverse=False)

            empty = True
            for key, _ in iterator:
                ctr = index_space.unpack(key)[0]
                if len(results) >= limit:
                    break
                if prefix and not ctr.startswith(prefix):
                    beyond_prefix = True
                    # No more items
                    marker = None
                    break
                if end_marker:
                    marker = fdb.KeySelector.first_greater_or_equal(
                                index_space.pack((end_marker,)))
                else:
                    marker = fdb.KeySelector.first_greater_than(
                                index_space.pack((ctr,)))

                # don't include marker
                if orig_marker == ctr:
                    continue

                nb_objects = 0
                nb_bytes = 0
                mtime = 0
                ct_space = main_space[ctr]
                ct_range = ct_space.range()
                ct_it = tr.get_range(ct_range.start,
                                     ct_range.stop, reverse=False)
                for ct_key, a_value in ct_it:
                    a_key, *pol = ct_space.unpack(ct_key)
                    if pol:
                        continue
                    if a_key == 'objects':
                        nb_objects = struct.unpack('<q', a_value)[0]
                    if a_key == 'bytes':
                        nb_bytes = struct.unpack('<q', a_value)[0]
                    if a_key == 'mtime':
                        mtime = self._us_to_seconds(
                                    struct.unpack('<Q', a_value)[0])
                results.append([ctr, nb_objects, nb_bytes, 0, mtime])

                empty = False
            if empty:
                break
        return results, orig_marker

    @fdb.transactional
    def _raw_listing_m1(self, tr, account_id, key_space, limit,
                        prefix, marker, end_marker):

        start = key_space.range().start
        stop = key_space.range().stop

        min_k = None
        max_k = stop

        orig_marker = next_marker = marker
        results = list()
        beyond_prefix = False
        if prefix is None:
            prefix = ''

        if marker:
            marker = fdb.KeySelector.first_greater_or_equal(
                        key_space.pack((marker,)))

        while len(results) < limit and not beyond_prefix:
            min_k = start
            max_k = stop
            local_limit = (limit - len(results) + 1)

            if prefix:
                max_k = stop
                min_k = fdb.KeySelector.first_greater_or_equal(
                    key_space.pack((prefix,)))

            if marker and (not prefix or
                           tr.get_key(marker) >= tr.get_key(min_k)):
                min_k = marker

            if end_marker and (not prefix
                               or end_marker <= prefix + b'\xff'):
                max_k = fdb.KeySelector.last_less_or_equal(
                            key_space.pack((end_marker,)))

            iterator = tr.snapshot.get_range(min_k, max_k, limit=local_limit,
                                             reverse=False)

            empty = True
            for key, _ in iterator:
                ctr = key_space.unpack(key)[0]
                if len(results) >= limit:
                    break
                if prefix and not ctr.startswith(prefix):
                    beyond_prefix = True
                    # No more items
                    marker = None
                    break
                if end_marker:
                    marker = fdb.KeySelector.first_greater_or_equal(
                                key_space.pack((end_marker,)))
                else:
                    marker = fdb.KeySelector.first_greater_than(
                                key_space.pack((ctr,)))

                # don't include marker
                if orig_marker == ctr:
                    continue

                nb_objects = 0
                nb_bytes = 0
                mtime = 0
                next_marker = ctr
                bucket_space = self.bucket_space[account_id][ctr]
                bucket_range = bucket_space.range()
                bucket_it = tr.get_range(bucket_range.start,
                                         bucket_range.stop, reverse=False)
                for bucket_key, a_value in bucket_it:
                    a_key = bucket_space.unpack(bucket_key)[0]
                    if a_key == 'objects':
                        nb_objects = struct.unpack('<q', a_value)[0]
                    if a_key == 'bytes':
                        nb_bytes = struct.unpack('<q', a_value)[0]
                    if a_key == 'mtime':
                        mtime = struct.unpack('<Q', a_value)[0]
                results.append([ctr, nb_objects, nb_bytes, mtime])

                empty = False
            if empty:
                break
        return results, next_marker

    @fdb.transactional
    def _is_element(self, tr, space, key):
        return tr[space.pack((key,))].present()

    @fdb.transactional
    def _val_element(self, tr, space, id_x, key):
        val = tr[space.pack((id_x, key))]
        if val.present():
            return val
        return None

    @fdb.transactional
    def _multi_get(self, tr, multi_space, index):
        pairs = tr[multi_space.range((index,))]
        info = {}
        for key, val in pairs:
            unpacked_key = (multi_space.unpack(key)[-1])
            info[bytes(unpacked_key, 'utf-8')] = val
        return info

    @fdb.transactional
    def _get_metada(self, tr, req_account_id):
        account_id = self._val_element(tr, self.acct_space,
                                       req_account_id, 'id')
        if account_id is None:
            return None
        meta = self._multi_get(tr, self.metadata_space,
                               account_id.decode('utf-8'))
        return meta

    @fdb.transactional
    def _manage_metadata(self, tr, space, id_x, metadata, to_delete):
        if to_delete:
            for element in to_delete:
                tr.clear_range_startswith(
                    space.pack((id_x, element)))

        if metadata:
            for key, value in metadata.items():
                tr[space.pack((id_x, key))] = \
                    bytes(str(value), 'utf-8')

    @fdb.transactional
    def _refresh_bucket(self, tr, bucket_key, bucket_name, account_id,
                        batch_size, marker):
        new_marker = None
        sum_bytes = 0
        sum_objects = 0
        count = 0
        if tr[bucket_key.pack(('account',))].present() is None:
            return 'no_bucket'

        ckey_prefix = self.container_space[account_id]

        # get_range is fetching data in batchs, the default mode for
        # streaming_mode is iterator which is efficient.
        # fdb.StreamingMode.want_all could be used
        start = ckey_prefix.range().start
        if marker is not None:
            start = fdb.KeySelector.first_greater_or_equal(
                    ckey_prefix.pack((marker,)))

        stop = ckey_prefix.range().stop
        iterator = tr.snapshot.get_range(start, stop, reverse=False)
        if marker is None:
            tr[bucket_key['bytes']] = struct.pack('<q', sum_bytes)
            tr[bucket_key['objects']] = struct.pack('<q', sum_objects)

        for key, val in iterator:
            container, unpacked_key, *pol = ckey_prefix.unpack(key)
            if marker == container:
                continue
            if pol:
                continue
            if unpacked_key not in ('bytes', 'objects'):
                continue

            # check if bucket exists
            check_bucket = tr[ckey_prefix.pack((container, 'bucket'))]
            if check_bucket.present() and \
               check_bucket.decode('utf-8') \
               == bucket_name:

                if unpacked_key == 'bytes':
                    sum_bytes += struct.unpack('<q', val)[0]
                if unpacked_key == 'objects' and \
                   container.find('+segments') == -1:
                    sum_objects += struct.unpack('<q', val)[0]
                    count += 1
            new_marker = container

            if count == 2 * batch_size:
                break
        tr.add(bucket_key['bytes'], struct.pack('<q', sum_bytes))
        tr.add(bucket_key['objects'], struct.pack('<q', sum_objects))

        return new_marker

    @fdb.transactional
    def _refresh_sharded_ct(self, tr, account_id, cname, marker, batch_size):
        # detect if container is sharded without requesting state
        account_exists = self._is_element(tr, self.accts_space, account_id)
        if not account_exists:
            return None
        sharded_account_id = '.shards_' + account_id
        sharded_account_exists = self._is_element(tr, self.accts_space,
                                                  sharded_account_id)
        if not sharded_account_exists:
            return None

        ct_space = self.container_space[account_id]
        ckey_prefix = self.container_space[sharded_account_id]

        orig_marker = marker
        new_marker = None
        count = 0
        stop = ckey_prefix.range().stop

        start_marker = cname if marker is None else marker
        start_ct = fdb.KeySelector.first_greater_than(
                ckey_prefix.pack((start_marker,)))

        iterator = tr.snapshot.get_range(start_ct, stop, reverse=False)
        sum_bytes = 0
        sum_objects = 0

        ended = True
        found = False

        for key, val in iterator:
            container, unpacked_key = ckey_prefix.unpack(key)
            if unpacked_key not in ('bytes', 'objects'):
                continue
            composed_cname = container.split('-')
            # remove last digits
            composed_cname.pop()

            timestamp = composed_cname.pop()
            if len(timestamp) != 16:
                self.logger.warning('malformed cname: %s %s', container,
                                    timestamp)
            hash_id = composed_cname.pop()
            if len(timestamp) != 64:
                self.logger.warning('malformed cname: %s hash_id %s',
                                    container, hash_id)
            truncated_cname = '-'.join(composed_cname)
            if cname != truncated_cname:
                continue

            new_marker = container
            if count >= 2 * batch_size:
                ended = False
                break

            found = True

            if unpacked_key == 'bytes':
                sum_bytes += struct.unpack('<q', val)[0]
            if unpacked_key == 'objects' and \
               container.find('+segments') == -1:
                sum_objects += struct.unpack('<q', val)[0]

            count += 1

        if found:
            if orig_marker is None:
                tr[ct_space.pack((cname, 'objects'))] = struct.pack('<q', 0)
                tr[ct_space.pack((cname, 'bytes'))] = struct.pack('<q', 0)

            tr.add(ct_space.pack((cname, 'objects')),
                   struct.pack('<q', sum_objects))
            tr.add(ct_space.pack((cname, 'bytes')),
                   struct.pack('<q', sum_bytes))
        else:
            new_marker = None
        if ended:
            new_marker = None

        return new_marker

    @fdb.transactional
    def _list_containers(self, tr, account_id, bucket_name):
        containers = list()
        ct_space = self.container_space[account_id]
        start = ct_space.range().start
        stop = ct_space.range().stop

        iterator = tr.snapshot.get_range(start, stop, reverse=False)
        for key, _ in iterator:
            container = ct_space.unpack(key)[0]
            if bucket_name is None:
                if container not in containers:
                    containers.append(container)
            else:
                read_bucket_name = tr[ct_space.pack((container, 'bucket'))]
                if read_bucket_name.present() and \
                   read_bucket_name.decode('utf-8') == bucket_name:
                    if container not in containers:
                        containers.append(container)
        return containers

    @fdb.transactional
    def _clear_deleted_containers(self, tr, account_id, now):
        to_delete_space = self.ct_to_delete_space[account_id]
        start = to_delete_space.range().start
        stop = to_delete_space.range().stop
        iterator = tr.get_range(start, stop)
        for key, value in iterator:
            val = struct.unpack('<Q', value)[0]
            if val + self._seconds_to_us(self.time_window_clear_deleted) < now:
                ct_name = to_delete_space.unpack(key)[0]
                del tr[to_delete_space.pack((ct_name,))]
