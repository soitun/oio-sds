# -*- coding: utf-8 -*-

# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

import eventlet
import fdb
import logging
import os
import random
import struct

from nose.plugins.attrib import attr
from pathlib import Path
from tests.utils import BaseTestCase, random_str
from testtools.testcase import ExpectedException
from time import sleep, time
from werkzeug.exceptions import Conflict

from oio.account.backend_fdb import AccountBackendFdb
from oio.account.common_fdb import CommonFdb
from oio.common.timestamp import Timestamp


fdb.api_version(CommonFdb.FDB_VERSION)


@attr('no_thread_patch')
class TestAccountBackend(BaseTestCase):
    def setUp(self):
        logger = logging.getLogger('test')

        super(TestAccountBackend, self).setUp()

        if os.path.exists(CommonFdb.DEFAULT_FDB):
            fdb_file = CommonFdb.DEFAULT_FDB
        else:
            fdb_file = str(Path.home())+'/.oio/sds/conf/OPENIO-fdb.cluster'
        self.account_conf = {
                'fdb_file': fdb_file}
        self.backend = AccountBackendFdb(self.account_conf, logger)
        self.backend.init_db(None)
        self.backend.db.clear_range(b'\x00', b'\xfe')
        self.beanstalkd0.drain_tube('oio-preserved')

    @classmethod
    def _monkey_patch(cls):
        eventlet.patcher.monkey_patch(os=False, thread=False)

    def _encode_value(self, key, value):
        if key[0] in ('ctime', 'mtime'):
            value = struct.pack('<Q', int(float(value) * 1000000))
        elif key[0] in ('bytes', 'objects', 'containers', 'buckets',
                        'accounts'):
            value = struct.pack('<q', int(value))
        else:
            value = value.encode('utf-8')
        return value

    def _items_info_expected_items_info(self, items_info):
        expected_info_info = {}
        for item, info in items_info.items():
            if not isinstance(info, dict):
                expected_info_info[item] = self._encode_value(item, info)
                continue
            expected_info = {}
            for key, value in info.items():
                expected_info[key] = self._encode_value(key, value)
            expected_info_info[item] = expected_info
        return expected_info_info

    def _check_backend(self, metrics_info, accounts_info, buckets_info,
                       containers_info, deleted_containers_info):
        metrics_info = self._items_info_expected_items_info(metrics_info)
        accounts_info = self._items_info_expected_items_info(accounts_info)
        buckets_info = self._items_info_expected_items_info(buckets_info)
        containers_info = self._items_info_expected_items_info(containers_info)
        expected_deleted_containers_info = {}
        for (account, container), dtime in deleted_containers_info.items():
            expected_deleted_containers_info[(account, container)] = \
                struct.pack('<Q', int(float(dtime) * 1000000))
        deleted_containers_info = expected_deleted_containers_info

        # Check deleted containers info
        deleted_containers_range = self.backend.ct_to_delete_space.range()
        iterator = self.backend.db.get_range(
            deleted_containers_range.start, deleted_containers_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        current_deleted_containers_info = {}
        for key, value in iterator:
            key = self.backend.ct_to_delete_space.unpack(key)
            current_deleted_containers_info[key] = value
        self.assertDictEqual(deleted_containers_info,
                             current_deleted_containers_info)
        for (account, container) in containers_info:
            self.assertNotIn((account, container),
                             current_deleted_containers_info)

        # Check containers info
        container_range = self.backend.container_space.range()
        iterator = self.backend.db.get_range(
            container_range.start, container_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        current_containers_info = {}
        for key, value in iterator:
            account, container, *key = self.backend.container_space.unpack(key)
            info = current_containers_info.setdefault((account, container), {})
            info[tuple(key)] = value
        for (account, container), info in containers_info.items():
            current_mtime = current_containers_info[
                (account, container,)].pop(('mtime',))
            mtime = info.pop(('mtime',), None)
            if mtime is not None:
                self.assertEqual(mtime, current_mtime)
            else:
                current_mtime = struct.unpack('<q', current_mtime)[0]
                self.assertGreater(current_mtime, 0)
        self.assertDictEqual(containers_info, current_containers_info)
        for (account, container) in deleted_containers_info:
            self.assertNotIn((account, container), current_containers_info)

        # Check containers listing
        containers_range = self.backend.containers_index_space.range()
        iterator = self.backend.db.get_range(
            containers_range.start, containers_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        current_containers = set()
        for key, value in iterator:
            account, container = \
                self.backend.containers_index_space.unpack(key)
            self.assertEqual(b'1', value)
            current_containers.add((account, container))
        self.assertSetEqual(set(containers_info), current_containers)
        for (account, container) in deleted_containers_info:
            self.assertNotIn((account, container), current_containers)

        # Check buckets info
        bucket_range = self.backend.bucket_space.range()
        iterator = self.backend.db.get_range(
            bucket_range.start, bucket_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        current_buckets_info = {}
        for key, value in iterator:
            account, bucket, *key = self.backend.bucket_space.unpack(key)
            info = current_buckets_info.setdefault((account, bucket), {})
            info[tuple(key)] = value
        for (account, bucket), info in buckets_info.items():
            current_mtime = current_buckets_info[
                (account, bucket,)].pop(('mtime',))
            mtime = info.pop(('mtime',), None)
            if mtime is not None:
                self.assertEqual(mtime, current_mtime)
            else:
                current_mtime = struct.unpack('<q', current_mtime)[0]
                self.assertGreater(current_mtime, 0)
        self.assertDictEqual(buckets_info, current_buckets_info)

        # Check buckets listing
        buckets_range = self.backend.buckets_index_space.range()
        iterator = self.backend.db.get_range(
            buckets_range.start, buckets_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        current_buckets = set()
        current_region_buckets = set()
        for key, value in iterator:
            key = self.backend.buckets_index_space.unpack(key)
            self.assertEqual(b'1', value)
            if len(key) == 2:
                account, bucket = key
                current_buckets.add((account, bucket))
            elif len(key) == 3:
                region, account, bucket = key
                self.assertEqual(buckets_info[(account, bucket)][('region',)],
                                 region.encode('utf-8'))
                current_region_buckets.add((account, bucket))
            else:
                self.fail(f"Unknown key: '{key}'")
        self.assertSetEqual(set(buckets_info), current_buckets)
        self.assertSetEqual(set(buckets_info), current_region_buckets)

        # Check accounts info
        account_range = self.backend.acct_space.range()
        iterator = self.backend.db.get_range(
            account_range.start, account_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        current_accounts_info = {}
        for key, value in iterator:
            account, *key = self.backend.acct_space.unpack(key)
            info = current_accounts_info.setdefault((account,), {})
            info[tuple(key)] = value
        for (account,), info in accounts_info.items():
            current_ctime = current_accounts_info[(account,)].pop(('ctime',))
            ctime = info.pop(('ctime',), None)
            if ctime is not None:
                self.assertEqual(ctime, current_ctime)
            else:
                current_ctime = struct.unpack('<q', current_ctime)[0]
                self.assertGreater(current_ctime, 0)
            current_mtime = current_accounts_info[(account,)].pop(('mtime',))
            mtime = info.pop(('mtime',), None)
            if mtime is not None:
                self.assertEqual(mtime, current_mtime)
            else:
                current_mtime = struct.unpack('<q', current_mtime)[0]
                self.assertGreater(current_mtime, 0)
        self.assertDictEqual(accounts_info, current_accounts_info)

        # Check accounts listing
        accounts_range = self.backend.accts_space.range()
        iterator = self.backend.db.get_range(
            accounts_range.start, accounts_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        current_accounts = set()
        for key, value in iterator:
            account, = self.backend.accts_space.unpack(key)
            self.assertEqual(b'1', value)
            current_accounts.add((account,))
        self.assertSetEqual(set(accounts_info), current_accounts)

        # Check metrics info
        metrics_range = self.backend.metrics_space.range()
        iterator = self.backend.db.get_range(
            metrics_range.start, metrics_range.stop,
            streaming_mode=fdb.StreamingMode.want_all)
        current_metrics_info = {}
        for key, value in iterator:
            key = self.backend.metrics_space.unpack(key)
            current_metrics_info[key] = value
        self.assertDictEqual(metrics_info, current_metrics_info)

    def test_create_account(self):
        account_id = 'a'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        self.assertEqual(self.backend.create_account(account_id), None)

    def test_update_account_metadata(self):
        account_id = 'test_not_yet_created'

        # create meta for non existing account => as auto_create is true
        # this will create the account

        self.backend.update_account_metadata(account_id, {'x': '1'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('x', metadata)
        self.assertEqual(metadata['x'], '1')

        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # first meta
        self.backend.update_account_metadata(account_id, {'a': '1'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('a', metadata)
        self.assertEqual(metadata['a'], '1')

        # second meta
        self.backend.update_account_metadata(account_id, {'b': '2'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('a', metadata)
        self.assertEqual(metadata['a'], '1')
        self.assertIn('b', metadata)
        self.assertEqual(metadata['b'], '2')

        # update first meta
        self.backend.update_account_metadata(account_id, {'a': '1b'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('a', metadata)
        self.assertEqual(metadata['a'], '1b')
        self.assertIn('b', metadata)
        self.assertEqual(metadata['b'], '2')

        # delete second meta
        self.backend.update_account_metadata(account_id, None, ['b'])
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('a', metadata)
        self.assertEqual(metadata['a'], '1b')
        self.assertNotIn('b', metadata)

    def test_list_account(self):

        # Create and check if in list
        account_id = 'test_list'
        self.backend.create_account(account_id)
        account_list = self.backend.list_accounts()
        self.assertIn(account_id, account_list)

        # Check the result of a nonexistent account
        self.assertFalse("Should_not_exist" in account_list)

    def test_info_account(self):
        region = 'localhost'
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['id'], account_id)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)
        self.assertEqual(info['containers'], 0)
        self.assertTrue(info['ctime'])

        # first container
        self.backend.update_container(
            account_id, 'c1', Timestamp().timestamp, 0, 1, 1, region=region)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)

        # second container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c2', Timestamp().timestamp, 0, 0, 0, region=region)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 2)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)

        # update second container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c2', Timestamp().timestamp, 0, 1, 1)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 2)
        self.assertEqual(info['objects'], 2)
        self.assertEqual(info['bytes'], 2)

        # delete first container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c1', 0, Timestamp().timestamp, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)

        # delete second container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c2', 0, Timestamp().timestamp, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 0)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)

    def test_update_after_container_deletion(self):
        region = 'localhost'
        account_id = 'test-%06x' % int(time())
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # Container create event, sent immediately after creation
        self.backend.update_container(
            account_id, 'c1', Timestamp().timestamp, None, None, None,
            region=region)

        # Container update event
        self.backend.update_container(
            account_id, 'c1', Timestamp().timestamp, None, 3, 30)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 3)
        self.assertEqual(info['bytes'], 30)

        # Container is flushed, but the event is deferred
        flush_timestamp = Timestamp().normal

        sleep(.00001)
        # Container delete event, sent immediately after deletion
        self.backend.update_container(
            account_id, 'c1', None, Timestamp().timestamp, None, None)

        # Deferred container update event (with lower timestamp)
        self.assertRaises(
            Conflict,
            self.backend.update_container,
            account_id, 'c1', flush_timestamp, None, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 0)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)

    def test_delete_container(self):
        region = 'localhost'
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {
                ('accounts',): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

        # initial container
        name = 'c'
        old_mtime = Timestamp(time() - 1).normal
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name): {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0
                }
            },
            {}
        )
        self._check_backend(*backend_info)

        # delete event
        sleep(.00001)
        dtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, dtime, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 0
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): dtime,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('containers', region): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {
                (account_id, name): dtime
            }
        )
        self._check_backend(*backend_info)

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, mtime, dtime, 0, 0,
                                          region=region)
        self._check_backend(*backend_info)

        # old event
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, old_mtime, 0, 0, 0,
                                          region=region)
        self._check_backend(*backend_info)

    def test_utf8_container(self):
        region = 'localhost'
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {
                ('accounts',): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

        # create container
        name = u'La fête à la maison'
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name): {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0
                }
            },
            {}
        )
        self._check_backend(*backend_info)

        # ensure it appears in listing
        listing = self.backend.list_containers(
            account_id, marker='', prefix='', limit=100)
        self.assertIn(name, [entry[0] for entry in listing])

        # delete container
        sleep(.00001)
        dtime = Timestamp().normal
        self.backend.update_container(account_id, name, 0, dtime, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 0
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): dtime,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('containers', region): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {
                (account_id, name): dtime
            }
        )
        self._check_backend(*backend_info)

        # ensure it has been removed
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, 0, dtime, 0, 0,
                                          region=region)
        self._check_backend(*backend_info)

    def test_update_container(self):
        region = 'localhost'
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {
                ('accounts',): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

        # initial container
        name = '"{<container \'&\' name>}"'
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name): {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0
                }
            },
            {}
        )
        self._check_backend(*backend_info)

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                          region=region)
        self._check_backend(*backend_info)

        # New event
        sleep(.00001)
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name): {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0
                }
            },
            {}
        )
        self._check_backend(*backend_info)

        # Old event
        old_mtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, old_mtime, 0, 0, 0,
                                          region=region)
        self._check_backend(*backend_info)

        # Old delete event
        dtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, 0, dtime, 0, 0,
                                          region=region)
        self._check_backend(*backend_info)

        # New delete event
        sleep(.00001)
        dtime = Timestamp().normal
        self.backend.update_container(account_id, name, 0, dtime, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 0
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): dtime,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('containers', region): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {
                (account_id, name): dtime
            }
        )
        self._check_backend(*backend_info)

        # New event
        sleep(.00001)
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name): {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0
                }
            },
            {}
        )
        self._check_backend(*backend_info)

    def test_list_containers(self):
        region = 'localhost'
        account_id = 'test'

        self.backend.create_account(account_id)
        for cont1 in range(4):
            for cont2 in range(125):
                name = '%d-%04d' % (cont1, cont2)
                self.backend.update_container(
                    account_id, name, Timestamp().timestamp, 0, 0, 0,
                    region=region)

        for cont in range(125):
            name = '2-0051-%04d' % cont
            self.backend.update_container(
                account_id, name, Timestamp().timestamp, 0, 0, 0,
                region=region)

        for cont in range(125):
            name = '3-%04d-0049' % cont
            self.backend.update_container(
                account_id, name, Timestamp().timestamp, 0, 0, 0,
                region=region)

        listing = self.backend.list_containers(
            account_id, marker='', limit=100)
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0099')

        listing = self.backend.list_containers(
            account_id, marker='', end_marker='0-0050', limit=100)
        self.assertEqual(len(listing), 50)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0049')

        listing = self.backend.list_containers(
            account_id, marker='0-0099', limit=100)
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0][0], '0-0100')
        self.assertEqual(listing[-1][0], '1-0074')

        listing = self.backend.list_containers(
            account_id, marker='1-0074', limit=55)
        self.assertEqual(len(listing), 55)
        self.assertEqual(listing[0][0], '1-0075')
        self.assertEqual(listing[-1][0], '2-0004')

        listing = self.backend.list_containers(
            account_id, marker='', prefix='0-01', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '0-0100')
        self.assertEqual(listing[-1][0], '0-0109')

        listing = self.backend.list_containers(
            account_id, marker='', prefix='0-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0009')

        listing = self.backend.list_containers(
            account_id, marker='2-0051-0000', prefix='2-0051-001', limit=16)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '2-0051-0010')
        self.assertEqual(listing[-1][0], '2-0051-0019')

        listing = self.backend.list_containers(
            account_id, marker='2-0050', prefix='2-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '2-0051')
        self.assertEqual(listing[-1][0], '2-0051-0008')

        listing = self.backend.list_containers(
            account_id, marker='3-0045', prefix='2-', limit=10)
        self.assertEqual(len(listing), 0)

        name = '3-0049-'
        self.backend.update_container(
            account_id, name, Timestamp().timestamp, 0, 0, 0, region=region)
        listing = self.backend.list_containers(
            account_id, marker='3-0048', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c[0] for c in listing],
                         ['3-0048-0049', '3-0049', '3-0049-', '3-0049-0049',
                          '3-0050', '3-0050-0049', '3-0051', '3-0051-0049',
                          '3-0052', '3-0052-0049'])

    def test_refresh_account(self):
        region = 'localhost'
        account_id = random_str(16)

        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {
                ('accounts',): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

        total_bytes = 0
        total_objects = 0
        containers = 0
        containers_info = {}

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(100)
            nb_objets = random.randrange(100)
            self.backend.update_container(
                account_id, name, mtime, 0, nb_objets, nb_bytes,
                region=region)
            total_bytes += nb_bytes
            total_objects += nb_objets
            containers += 1
            containers_info[(account_id, name)] = {
                ('name',): name,
                ('region',): region,
                ('mtime',): mtime,
                ('bytes',): nb_bytes,
                ('objects',): nb_objets
            }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): total_bytes,
                ('objects', region): total_objects,
                ('containers', region): containers
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): total_bytes,
                    ('bytes', region): total_bytes,
                    ('objects',): total_objects,
                    ('objects', region): total_objects,
                    ('containers',): containers,
                    ('containers', region): containers,
                    ('buckets',): 0
                }
            },
            {},
            containers_info,
            {}
        )
        self._check_backend(*backend_info)

        # Add an other account to check if it is not affected
        account_id2 = random_str(16)
        mtime2 = Timestamp().normal
        self.backend.update_container(account_id2, name, mtime2, 0, 12, 42,
                                      region=region)
        containers_info[(account_id2, name)] = {
            ('name',): name,
            ('region',): region,
            ('mtime',): mtime2,
            ('bytes',): 42,
            ('objects',): 12
        }
        backend_info = (
            {
                ('accounts',): 2,
                ('bytes', region): total_bytes + 42,
                ('objects', region): total_objects + 12,
                ('containers', region): containers + 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): total_bytes,
                    ('bytes', region): total_bytes,
                    ('objects',): total_objects,
                    ('objects', region): total_objects,
                    ('containers',): containers,
                    ('containers', region): containers,
                    ('buckets',): 0
                },
                (account_id2,): {
                    ('id',): account_id2,
                    ('bytes',): 42,
                    ('bytes', region): 42,
                    ('objects',): 12,
                    ('objects', region): 12,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            containers_info,
            {}
        )
        self._check_backend(*backend_info)

        # change values
        account_space = self.backend.acct_space[account_id]
        self.assertEqual(struct.pack('<q', total_bytes),
                         self.backend.db[account_space.pack(('bytes',))])
        self.assertEqual(struct.pack('<q', total_objects),
                         self.backend.db[account_space.pack(('objects',))])
        self.backend.db[account_space.pack(('bytes',))] = struct.pack('<q', 1)
        self.backend.db[account_space.pack(('objects',))] = \
            struct.pack('<q', 2)
        self.assertEqual(self.backend.db[account_space.pack(('bytes',))],
                         struct.pack('<q', 1))
        self.assertEqual(self.backend.db[account_space.pack(('objects',))],
                         struct.pack('<q', 2))

        self.backend.refresh_account(account_id)
        self._check_backend(*backend_info)

    # TODO(adu): Reffresh account with stats by policy and buckets

    def test_update_container_wrong_timestamp_format(self):
        region = 'localhost'
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {
                ('accounts',): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

        # initial container
        name = '"{<container \'&\' name>}"'
        mtime = "12456.0000076"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name): {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0
                }
            },
            {}
        )
        self._check_backend(*backend_info)

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                          region=region)
        self._check_backend(*backend_info)

        mtime = "0000012456.00005"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name): {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0
                }
            },
            {}
        )
        self._check_backend(*backend_info)

        mtime = "0000012456.00035"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0,
                                      region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name): {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 0,
                    ('objects',): 0
                }
            },
            {}
        )
        self._check_backend(*backend_info)

    def test_flush_account(self):
        region = 'localhost'
        account_id = random_str(16)

        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {
                ('accounts',): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

        total_bytes = 0
        total_objects = 0
        containers = 0
        containers_info = {}
        deleted_containers_info = {}

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(100)
            nb_objets = random.randrange(100)
            self.backend.update_container(
                account_id, name, mtime, 0, nb_objets, nb_bytes,
                region=region)
            if random.randrange(100) > 50:
                total_bytes += nb_bytes
                total_objects += nb_objets
                containers += 1
                containers_info[(account_id, name)] = {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): nb_bytes,
                    ('objects',): nb_objets
                }
            else:
                # with some deleted containers
                sleep(.00001)
                mtime = Timestamp().normal
                self.backend.update_container(
                    account_id, name, 0, mtime, 0, 0, region=region)
                deleted_containers_info[(account_id, name)] = mtime
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): total_bytes,
                ('objects', region): total_objects,
                ('containers', region): containers
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): total_bytes,
                    ('bytes', region): total_bytes,
                    ('objects',): total_objects,
                    ('objects', region): total_objects,
                    ('containers',): containers,
                    ('containers', region): containers,
                    ('buckets',): 0
                }
            },
            {},
            containers_info,
            deleted_containers_info
        )
        self._check_backend(*backend_info)

        # Add an other account to check if it is not affected
        account_id2 = random_str(16)
        mtime2 = Timestamp().normal
        self.backend.update_container(account_id2, name, mtime2, 0, 12, 42,
                                      region=region)
        containers_info[(account_id2, name)] = {
            ('name',): name,
            ('region',): region,
            ('mtime',): mtime2,
            ('bytes',): 42,
            ('objects',): 12
        }
        backend_info = (
            {
                ('accounts',): 2,
                ('bytes', region): total_bytes + 42,
                ('objects', region): total_objects + 12,
                ('containers', region): containers + 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): total_bytes,
                    ('bytes', region): total_bytes,
                    ('objects',): total_objects,
                    ('objects', region): total_objects,
                    ('containers',): containers,
                    ('containers', region): containers,
                    ('buckets',): 0
                },
                (account_id2,): {
                    ('id',): account_id2,
                    ('bytes',): 42,
                    ('bytes', region): 42,
                    ('objects',): 12,
                    ('objects', region): 12,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            containers_info,
            deleted_containers_info
        )
        self._check_backend(*backend_info)

        self.backend.flush_account(account_id)
        backend_info = (
            {
                ('accounts',): 2,
                ('bytes', region): 42,
                ('objects', region): 12,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                },
                (account_id2,): {
                    ('id',): account_id2,
                    ('bytes',): 42,
                    ('bytes', region): 42,
                    ('objects',): 12,
                    ('objects', region): 12,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id2, name): {
                    ('name',): name,
                    ('region',): region,
                    ('mtime',): mtime2,
                    ('bytes',): 42,
                    ('objects',): 12
                }
            },
            {}
        )
        self._check_backend(*backend_info)

    # TODO(adu): Flush account with stats by policy and buckets

    def test_refresh_bucket(self):
        region = 'localhost'
        account_id = random_str(16)
        bucket = random_str(16)

        self.assertEqual(self.backend.create_account(account_id), account_id)

        total_bytes = 0
        total_objects = 0

        # set bucket_db reservation
        self.backend.reserve_bucket(account_id, bucket)
        self.backend.set_bucket_owner(account_id, bucket)

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(100)
            total_bytes += nb_bytes
            nb_objets = random.randrange(100)
            total_objects += nb_objets
            self.backend.update_container(
                account_id, name, mtime, 0, nb_objets, nb_bytes,
                bucket_name=bucket, region=region)

        b_space = self.backend.bucket_space[account_id][bucket]

        # change values
        self.backend.db[b_space['bytes']] = struct.pack('<q', 1)
        self.backend.db[b_space['objects']] = struct.pack('<q', 2)

        res_bytes = self.backend.db[b_space['bytes']]
        res_objects = self.backend.db[b_space['objects']]

        res_bytes = int.from_bytes(res_bytes, byteorder='little')
        res_objects = int.from_bytes(res_objects, byteorder='little')

        self.assertEqual(res_bytes, 1)
        self.assertEqual(res_objects, 2)

        # force pagination
        self.backend.refresh_bucket(bucket)
        b_space = self.backend.bucket_space[account_id][bucket]

        res_bytes = self.backend.db[b_space['bytes']]
        res_objects = self.backend.db[b_space['objects']]
        res_bytes = struct.unpack('<q', res_bytes)[0]
        res_objects = struct.unpack('<q', res_objects)[0]

        self.assertEqual(res_bytes, total_bytes)
        self.assertEqual(res_objects, total_objects)

        # force pagination
        self.backend.refresh_bucket(bucket, batch_size=3)
        res_bytes = self.backend.db[b_space.pack(('bytes',))]
        res_objects = self.backend.db[b_space.pack(('objects',))]
        res_bytes = int.from_bytes(res_bytes, byteorder='little')
        res_objects = int.from_bytes(res_objects, byteorder='little')

        self.assertEqual(res_bytes, total_bytes)
        self.assertEqual(res_objects, total_objects)

    def test_refresh_bucket_by_batch(self):
        region = 'localhost'
        nb_obj_to_add = 5
        account_id = random_str(16)
        bucket = 'bucket-test-refresh'
        cname = 'ct-1'
        cname_not_in_bucket = 'ct-not-in-bucket'
        cname_not_sharded = 'ct-2'
        account_id = random_str(16)
        bucket_space = self.backend.bucket_space[account_id][bucket]

        data_lenth = 7
        data = random_str(data_lenth)

        # set bucket_db reservation
        self.backend.reserve_bucket(account_id, bucket)
        self.backend.set_bucket_owner(account_id, bucket)

        for ct in (cname, cname_not_in_bucket, cname_not_sharded):
            self.storage.container_create(account_id, ct)

            for i in range(nb_obj_to_add):
                file_name = str(i) + '-file'
                self.storage.object_create(account_id, ct,
                                           obj_name=file_name, data=data,
                                           chunk_checksum_algo=None)

        ct_in_bucket = (cname, cname_not_sharded)
        for ct in ct_in_bucket:
            self.backend.update_container(account_id, ct,
                                          Timestamp().timestamp,
                                          0, nb_obj_to_add,
                                          data_lenth * nb_obj_to_add,
                                          bucket_name=bucket, region=region)

        self.backend.update_container(account_id, cname_not_in_bucket,
                                      Timestamp().timestamp, 0, nb_obj_to_add,
                                      data_lenth * nb_obj_to_add,
                                      region=region)

        for batch in range(1, 6):
            # change values
            self.backend.db[bucket_space['bytes']] = \
                struct.pack('<q', 1)
            self.backend.db[bucket_space['objects']] = \
                struct.pack('<q', 2)

            self.backend.refresh_bucket(bucket, batch_size=batch)

            res_bytes = self.backend.db[bucket_space['bytes']]
            res_objects = self.backend.db[bucket_space['objects']]
            res_bytes = int.from_bytes(res_bytes, byteorder='little')
            res_objects = int.from_bytes(res_objects, byteorder='little')

            self.assertEqual(res_bytes,
                             len(ct_in_bucket) * data_lenth * nb_obj_to_add)
            self.assertEqual(res_objects, len(ct_in_bucket) * nb_obj_to_add)

    def test_update_bucket_metada(self):
        region = 'localhost'
        bname = 'metadata_'+random_str(8)
        metadata = {'owner': 'owner1', 'user': 'user1'}
        account_id = 'acct_'+random_str(8)

        # Test autocreate_account
        self.backend.update_container(
            account_id, bname, Timestamp().timestamp, 0, 0, 0,
            bucket_name=bname, autocreate_account=True, region=region)
        # set bucket_db reservation
        self.backend.reserve_bucket(account_id, bname)
        self.backend.set_bucket_owner(account_id, bname)
        # Test bucket metadata
        self.backend.update_bucket_metadata(bname, metadata)

        b_space = self.backend.bucket_space[account_id][bname]
        range = b_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        found = 0
        for key, val in res:
            key = b_space.unpack(key)[0]
            if key in metadata.keys() and val == bytes(metadata[key], 'utf-8'):
                found += 1

        self.assertEqual(found, len(metadata))

        # test bucket to_delete
        to_delete = ['owner']

        self.backend.update_bucket_metadata(bname, None, to_delete)
        range = b_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        found = 0
        for key, val in res:
            key = b_space.unpack(key)
            if key in to_delete:
                found += 1
        self.assertEqual(found, 0)

    def test_update_containers_with_policies(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {
                ('accounts',): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

        # initial container
        region = 'localhost'
        name1 = 'container1'
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, mtime, 0, 5, 41,
            objects_details={'THREECOPIES': 2, 'EC': 3}, region=region)
        container_info1 = {
            ('name',): name1,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 41,
            ('objects',): 5,
            ('objects', 'THREECOPIES'): 2,
            ('objects', 'EC'): 3
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 41,
                ('objects', region): 5,
                ('objects', region, 'THREECOPIES'): 2,
                ('objects', region, 'EC'): 3,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 41,
                    ('bytes', region): 41,
                    ('objects',): 5,
                    ('objects', region): 5,
                    ('objects', region, 'THREECOPIES'): 2,
                    ('objects', region, 'EC'): 3,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name1): container_info1
            },
            {}
        )
        self._check_backend(*backend_info)

        # recall with same values => no impact on stats (only mtime changes)
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, mtime, 0, 5, 41,
            objects_details={'THREECOPIES': 2, 'EC': 3})
        container_info1 = {
            ('name',): name1,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 41,
            ('objects',): 5,
            ('objects', 'THREECOPIES'): 2,
            ('objects', 'EC'): 3
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 41,
                ('objects', region): 5,
                ('objects', region, 'THREECOPIES'): 2,
                ('objects', region, 'EC'): 3,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 41,
                    ('bytes', region): 41,
                    ('objects',): 5,
                    ('objects', region): 5,
                    ('objects', region, 'THREECOPIES'): 2,
                    ('objects', region, 'EC'): 3,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name1): container_info1
            },
            {}
        )
        self._check_backend(*backend_info)

        # update another container
        name2 = 'container2'
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name2, mtime, 0, 7, 33,
            objects_details={"THREECOPIES": 3, "SINGLE": 4}, region=region)
        container_info2 = {
            ('name',): name2,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 33,
            ('objects',): 7,
            ('objects', 'THREECOPIES'): 3,
            ('objects', 'SINGLE'): 4
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 74,
                ('objects', region): 12,
                ('objects', region, 'THREECOPIES'): 5,
                ('objects', region, 'EC'): 3,
                ('objects', region, 'SINGLE'): 4,
                ('containers', region): 2
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 74,
                    ('bytes', region): 74,
                    ('objects',): 12,
                    ('objects', region): 12,
                    ('objects', region, 'THREECOPIES'): 5,
                    ('objects', region, 'EC'): 3,
                    ('objects', region, 'SINGLE'): 4,
                    ('containers',): 2,
                    ('containers', region): 2,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2
            },
            {}
        )
        self._check_backend(*backend_info)

        # update first container
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, mtime, 0, 1, 20,
            objects_details={"THREECOPIES": 1})
        container_info1 = {
            ('name',): name1,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 20,
            ('objects',): 1,
            ('objects', 'THREECOPIES'): 1
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 53,
                ('objects', region): 8,
                ('objects', region, 'THREECOPIES'): 4,
                ('objects', region, 'EC'): 0,
                ('objects', region, 'SINGLE'): 4,
                ('containers', region): 2
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 53,
                    ('bytes', region): 53,
                    ('objects',): 8,
                    ('objects', region): 8,
                    ('objects', region, 'THREECOPIES'): 4,
                    ('objects', region, 'EC'): 0,
                    ('objects', region, 'SINGLE'): 4,
                    ('containers',): 2,
                    ('containers', region): 2,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2
            },
            {}
        )
        self._check_backend(*backend_info)

        # delete first container
        dtime1 = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, 0, dtime1, 0, 0)
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 33,
                ('objects', region): 7,
                ('objects', region, 'THREECOPIES'): 3,
                ('objects', region, 'EC'): 0,
                ('objects', region, 'SINGLE'): 4,
                ('containers', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): dtime1,
                    ('bytes',): 33,
                    ('bytes', region): 33,
                    ('objects',): 7,
                    ('objects', region): 7,
                    ('objects', region, 'THREECOPIES'): 3,
                    ('objects', region, 'EC'): 0,
                    ('objects', region, 'SINGLE'): 4,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {},
            {
                (account_id, name2): container_info2
            },
            {
                (account_id, name1): dtime1
            }
        )
        self._check_backend(*backend_info)

        # delete second container
        dtime2 = Timestamp().timestamp
        self.backend.update_container(
            account_id, name2, 0, dtime2, 0, 0, region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 0,
                ('objects', region): 0,
                ('objects', region, 'THREECOPIES'): 0,
                ('objects', region, 'EC'): 0,
                ('objects', region, 'SINGLE'): 0,
                ('containers', region): 0
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): dtime2,
                    ('bytes',): 0,
                    ('bytes', region): 0,
                    ('objects',): 0,
                    ('objects', region): 0,
                    ('objects', region, 'THREECOPIES'): 0,
                    ('objects', region, 'EC'): 0,
                    ('objects', region, 'SINGLE'): 0,
                    ('containers',): 0,
                    ('containers', region): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {
                (account_id, name1): dtime1,
                (account_id, name2): dtime2
            }
        )
        self._check_backend(*backend_info)

        self.backend.delete_account(account_id)
        backend_info = (
            {
                ('accounts',): 0,
                ('bytes', region): 0,
                ('objects', region): 0,
                ('objects', region, 'THREECOPIES'): 0,
                ('objects', region, 'EC'): 0,
                ('objects', region, 'SINGLE'): 0,
                ('containers', region): 0
            },
            {},
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

    def test_update_containers_with_buckets(self):
        region = 'localhost'
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {
                ('accounts',): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

        # initial container
        name1 = 'bucket1'
        bucket_name1 = 'bucket1'
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, mtime, 0, 5, 41,
            objects_details={'THREECOPIES': 2, 'EC': 3},
            bucket_name=bucket_name1, region=region)
        container_info1 = {
            ('name',): name1,
            ('bucket',): bucket_name1,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 41,
            ('objects',): 5,
            ('objects', 'THREECOPIES'): 2,
            ('objects', 'EC'): 3
        }
        bucket_info1 = {
            ('account',): account_id,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 41,
            ('objects',): 5,
            ('objects', 'THREECOPIES'): 2,
            ('objects', 'EC'): 3
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 41,
                ('objects', region): 5,
                ('objects', region, 'THREECOPIES'): 2,
                ('objects', region, 'EC'): 3,
                ('containers', region): 1,
                ('buckets', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 41,
                    ('bytes', region): 41,
                    ('objects',): 5,
                    ('objects', region): 5,
                    ('objects', region, 'THREECOPIES'): 2,
                    ('objects', region, 'EC'): 3,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 1,
                    ('buckets', region): 1
                }
            },
            {
                (account_id, bucket_name1): bucket_info1
            },
            {
                (account_id, name1): container_info1
            },
            {}
        )
        self._check_backend(*backend_info)

        # recall with same values => no impact on stats (only mtime changes)
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, mtime, 0, 5, 41,
            objects_details={'THREECOPIES': 2, 'EC': 3})
        container_info1 = {
            ('name',): name1,
            ('bucket',): bucket_name1,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 41,
            ('objects',): 5,
            ('objects', 'THREECOPIES'): 2,
            ('objects', 'EC'): 3
        }
        bucket_info1 = {
            ('account',): account_id,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 41,
            ('objects',): 5,
            ('objects', 'THREECOPIES'): 2,
            ('objects', 'EC'): 3
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 41,
                ('objects', region): 5,
                ('objects', region, 'THREECOPIES'): 2,
                ('objects', region, 'EC'): 3,
                ('containers', region): 1,
                ('buckets', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 41,
                    ('bytes', region): 41,
                    ('objects',): 5,
                    ('objects', region): 5,
                    ('objects', region, 'THREECOPIES'): 2,
                    ('objects', region, 'EC'): 3,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 1,
                    ('buckets', region): 1
                }
            },
            {
                (account_id, bucket_name1): bucket_info1
            },
            {
                (account_id, name1): container_info1
            },
            {}
        )
        self._check_backend(*backend_info)

        # update another container
        name2 = 'bucket2'
        bucket_name2 = 'bucket2'
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name2, mtime, 0, 7, 33,
            objects_details={"THREECOPIES": 3, "SINGLE": 4},
            bucket_name=bucket_name2, region=region)
        container_info2 = {
            ('name',): name2,
            ('bucket',): bucket_name2,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 33,
            ('objects',): 7,
            ('objects', 'THREECOPIES'): 3,
            ('objects', 'SINGLE'): 4
        }
        bucket_info2 = {
            ('account',): account_id,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 33,
            ('objects',): 7,
            ('objects', 'THREECOPIES'): 3,
            ('objects', 'SINGLE'): 4
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 74,
                ('objects', region): 12,
                ('objects', region, 'THREECOPIES'): 5,
                ('objects', region, 'EC'): 3,
                ('objects', region, 'SINGLE'): 4,
                ('containers', region): 2,
                ('buckets', region): 2
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 74,
                    ('bytes', region): 74,
                    ('objects',): 12,
                    ('objects', region): 12,
                    ('objects', region, 'THREECOPIES'): 5,
                    ('objects', region, 'EC'): 3,
                    ('objects', region, 'SINGLE'): 4,
                    ('containers',): 2,
                    ('containers', region): 2,
                    ('buckets',): 2,
                    ('buckets', region): 2
                }
            },
            {
                (account_id, bucket_name1): bucket_info1,
                (account_id, bucket_name2): bucket_info2
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2
            },
            {}
        )
        self._check_backend(*backend_info)

        # update first container
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, mtime, 0, 1, 20,
            objects_details={"THREECOPIES": 1})
        container_info1 = {
            ('name',): name1,
            ('bucket',): bucket_name1,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 20,
            ('objects',): 1,
            ('objects', 'THREECOPIES'): 1
        }
        bucket_info1 = {
            ('account',): account_id,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 20,
            ('objects',): 1,
            ('objects', 'THREECOPIES'): 1,
            ('objects', 'EC'): 0
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 53,
                ('objects', region): 8,
                ('objects', region, 'THREECOPIES'): 4,
                ('objects', region, 'EC'): 0,
                ('objects', region, 'SINGLE'): 4,
                ('containers', region): 2,
                ('buckets', region): 2
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 53,
                    ('bytes', region): 53,
                    ('objects',): 8,
                    ('objects', region): 8,
                    ('objects', region, 'THREECOPIES'): 4,
                    ('objects', region, 'EC'): 0,
                    ('objects', region, 'SINGLE'): 4,
                    ('containers',): 2,
                    ('containers', region): 2,
                    ('buckets',): 2,
                    ('buckets', region): 2
                }
            },
            {
                (account_id, bucket_name1): bucket_info1,
                (account_id, bucket_name2): bucket_info2
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2
            },
            {}
        )
        self._check_backend(*backend_info)

        # delete first container
        dtime1 = Timestamp().timestamp
        self.backend.update_container(account_id, name1, 0, dtime1, 0, 0)
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 33,
                ('objects', region): 7,
                ('objects', region, 'THREECOPIES'): 3,
                ('objects', region, 'EC'): 0,
                ('objects', region, 'SINGLE'): 4,
                ('containers', region): 1,
                ('buckets', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): dtime1,
                    ('bytes',): 33,
                    ('bytes', region): 33,
                    ('objects',): 7,
                    ('objects', region): 7,
                    ('objects', region, 'THREECOPIES'): 3,
                    ('objects', region, 'EC'): 0,
                    ('objects', region, 'SINGLE'): 4,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 1,
                    ('buckets', region): 1
                }
            },
            {
                (account_id, bucket_name2): bucket_info2
            },
            {
                (account_id, name2): container_info2
            },
            {
                (account_id, name1): dtime1
            }
        )
        self._check_backend(*backend_info)

        # delete second container
        dtime2 = Timestamp().timestamp
        self.backend.update_container(
            account_id, name2, 0, dtime2, 0, 0,
            bucket_name=bucket_name2, region=region)
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region): 0,
                ('objects', region): 0,
                ('objects', region, 'THREECOPIES'): 0,
                ('objects', region, 'EC'): 0,
                ('objects', region, 'SINGLE'): 0,
                ('containers', region): 0,
                ('buckets', region): 0
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): dtime2,
                    ('bytes',): 0,
                    ('bytes', region): 0,
                    ('objects',): 0,
                    ('objects', region): 0,
                    ('objects', region, 'THREECOPIES'): 0,
                    ('objects', region, 'EC'): 0,
                    ('objects', region, 'SINGLE'): 0,
                    ('containers',): 0,
                    ('containers', region): 0,
                    ('buckets',): 0,
                    ('buckets', region): 0
                }
            },
            {},
            {},
            {
                (account_id, name1): dtime1,
                (account_id, name2): dtime2
            }
        )
        self._check_backend(*backend_info)

        self.backend.delete_account(account_id)
        backend_info = (
            {
                ('accounts',): 0,
                ('bytes', region): 0,
                ('objects', region): 0,
                ('objects', region, 'THREECOPIES'): 0,
                ('objects', region, 'EC'): 0,
                ('objects', region, 'SINGLE'): 0,
                ('containers', region): 0,
                ('buckets', region): 0
            },
            {},
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

    def test_bucket_with_several_containers(self):
        region = 'localhost'
        account_id = 'test-1'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {
                ('accounts',): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('bytes',): 0,
                    ('objects',): 0,
                    ('containers',): 0,
                    ('buckets',): 0
                }
            },
            {},
            {},
            {}
        )
        self._check_backend(*backend_info)

        # First, create +segments
        name1 = 'bucket+segments'
        bucket_name = 'bucket'
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, mtime, 0, 8, 108,
            bytes_details={'pol1': 7, 'pol2': 101},
            objects_details={'pol1': 3, 'pol2': 5},
            bucket_name=bucket_name, region=region)
        container_info1 = {
            ('name',): name1,
            ('bucket',): bucket_name,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 108,
            ('bytes', 'pol1'): 7,
            ('bytes', 'pol2'): 101,
            ('objects',): 8,
            ('objects', 'pol1'): 3,
            ('objects', 'pol2'): 5
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region,): 108,
                ('bytes', region, 'pol1'): 7,
                ('bytes', region, 'pol2'): 101,
                ('objects', region,): 8,
                ('objects', region, 'pol1'): 3,
                ('objects', region, 'pol2'): 5,
                ('containers', region): 1,
                ('buckets', region): 1
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): mtime,
                    ('bytes',): 108,
                    ('bytes', region,): 108,
                    ('bytes', region, 'pol1'): 7,
                    ('bytes', region, 'pol2'): 101,
                    ('objects',): 8,
                    ('objects', region,): 8,
                    ('objects', region, 'pol1'): 3,
                    ('objects', region, 'pol2'): 5,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 1,
                    ('buckets', region): 1
                }
            },
            {
                (account_id, bucket_name): {
                    ('account',): account_id,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 108,
                    ('bytes', 'pol1'): 7,
                    ('bytes', 'pol2'): 101,
                    ('objects',): 0,
                }
            },
            {
                (account_id, name1): container_info1
            },
            {}
        )
        self._check_backend(*backend_info)

        # Second, create the root
        name2 = 'bucket'
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id, name2, mtime, 0, 28, 68,
            bytes_details={'pol1': 27, 'pol2': 41},
            objects_details={'pol1': 11, 'pol2': 17},
            bucket_name=bucket_name, region=region)
        container_info2 = {
            ('name',): name2,
            ('bucket',): bucket_name,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 68,
            ('bytes', 'pol1'): 27,
            ('bytes', 'pol2'): 41,
            ('objects',): 28,
            ('objects', 'pol1'): 11,
            ('objects', 'pol2'): 17
        }
        account_info = {
            ('id',): account_id,
            ('mtime',): mtime,
            ('bytes',): 176,
            ('bytes', region,): 176,
            ('bytes', region, 'pol1'): 34,
            ('bytes', region, 'pol2'): 142,
            ('objects',): 36,
            ('objects', region,): 36,
            ('objects', region, 'pol1'): 14,
            ('objects', region, 'pol2'): 22,
            ('containers',): 2,
            ('containers', region): 2,
            ('buckets',): 1,
            ('buckets', region): 1
        }
        backend_info = (
            {
                ('accounts',): 1,
                ('bytes', region,): 176,
                ('bytes', region, 'pol1'): 34,
                ('bytes', region, 'pol2'): 142,
                ('objects', region,): 36,
                ('objects', region, 'pol1'): 14,
                ('objects', region, 'pol2'): 22,
                ('containers', region): 2,
                ('buckets', region): 1
            },
            {
                (account_id,): account_info
            },
            {
                (account_id, bucket_name): {
                    ('account',): account_id,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 176,
                    ('bytes', 'pol1'): 34,
                    ('bytes', 'pol2'): 142,
                    ('objects',): 28,
                    ('objects', 'pol1'): 11,
                    ('objects', 'pol2'): 17
                }
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2
            },
            {}
        )
        self._check_backend(*backend_info)

        # Third, create a shard
        shards_account_id = '.shards_' + account_id
        name3 = 'bucket-0'
        mtime = Timestamp().timestamp
        self.backend.update_container(
            shards_account_id, name3, mtime, 0, 12, 42,
            bytes_details={'pol1': 30, 'pol2': 12},
            objects_details={'pol1': 5, 'pol2': 7},
            bucket_name=bucket_name, region=region)
        container_info3 = {
            ('name',): name3,
            ('bucket',): bucket_name,
            ('region',): region,
            ('mtime',): mtime,
            ('bytes',): 42,
            ('bytes', 'pol1'): 30,
            ('bytes', 'pol2'): 12,
            ('objects',): 12,
            ('objects', 'pol1'): 5,
            ('objects', 'pol2'): 7
        }
        backend_info = (
            {
                ('accounts',): 2,
                ('bytes', region,): 218,
                ('bytes', region, 'pol1'): 64,
                ('bytes', region, 'pol2'): 154,
                ('objects', region,): 48,
                ('objects', region, 'pol1'): 19,
                ('objects', region, 'pol2'): 29,
                ('containers', region): 3,
                ('buckets', region): 1
            },
            {
                (account_id,): account_info,
                (shards_account_id,): {
                    ('id',): shards_account_id,
                    ('bytes',): 42,
                    ('bytes', region,): 42,
                    ('bytes', region, 'pol1'): 30,
                    ('bytes', region, 'pol2'): 12,
                    ('objects',): 12,
                    ('objects', region,): 12,
                    ('objects', region, 'pol1'): 5,
                    ('objects', region, 'pol2'): 7,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0
                }
            },
            {
                (account_id, bucket_name): {
                    ('account',): account_id,
                    ('region',): region,
                    ('mtime',): mtime,
                    ('bytes',): 218,
                    ('bytes', 'pol1'): 64,
                    ('bytes', 'pol2'): 154,
                    ('objects',): 40,
                    ('objects', 'pol1'): 16,
                    ('objects', 'pol2'): 24
                }
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2,
                (shards_account_id, name3): container_info3
            },
            {}
        )
        self._check_backend(*backend_info)

        # Delete shard
        dtime3 = Timestamp().timestamp
        self.backend.update_container(
            shards_account_id, name3, 0, dtime3, 0, 0,
            bucket_name=bucket_name, region=region)
        shard_account_info = {
            ('id',): shards_account_id,
            ('mtime',): dtime3,
            ('bytes',): 0,
            ('bytes', region,): 0,
            ('bytes', region, 'pol1'): 0,
            ('bytes', region, 'pol2'): 0,
            ('objects',): 0,
            ('objects', region,): 0,
            ('objects', region, 'pol1'): 0,
            ('objects', region, 'pol2'): 0,
            ('containers',): 0,
            ('containers', region): 0,
            ('buckets',): 0
        }
        backend_info = (
            {
                ('accounts',): 2,
                ('bytes', region,): 176,
                ('bytes', region, 'pol1'): 34,
                ('bytes', region, 'pol2'): 142,
                ('objects', region,): 36,
                ('objects', region, 'pol1'): 14,
                ('objects', region, 'pol2'): 22,
                ('containers', region): 2,
                ('buckets', region): 1
            },
            {
                (account_id,): account_info,
                (shards_account_id,): shard_account_info
            },
            {
                (account_id, bucket_name): {
                    ('account',): account_id,
                    ('region',): region,
                    ('mtime',): dtime3,
                    ('bytes',): 176,
                    ('bytes', 'pol1'): 34,
                    ('bytes', 'pol2'): 142,
                    ('objects',): 28,
                    ('objects', 'pol1'): 11,
                    ('objects', 'pol2'): 17
                }
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2
            },
            {
                (shards_account_id, name3): dtime3
            }
        )
        self._check_backend(*backend_info)

        # Delete root
        dtime2 = Timestamp().timestamp
        self.backend.update_container(
            account_id, name2, 0, dtime2, 0, 0,
            bucket_name=bucket_name, region=region)
        backend_info = (
            {
                ('accounts',): 2,
                ('bytes', region,): 108,
                ('bytes', region, 'pol1'): 7,
                ('bytes', region, 'pol2'): 101,
                ('objects', region,): 8,
                ('objects', region, 'pol1'): 3,
                ('objects', region, 'pol2'): 5,
                ('containers', region): 1,
                ('buckets', region): 0
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): dtime2,
                    ('bytes',): 108,
                    ('bytes', region,): 108,
                    ('bytes', region, 'pol1'): 7,
                    ('bytes', region, 'pol2'): 101,
                    ('objects',): 8,
                    ('objects', region,): 8,
                    ('objects', region, 'pol1'): 3,
                    ('objects', region, 'pol2'): 5,
                    ('containers',): 1,
                    ('containers', region): 1,
                    ('buckets',): 0,
                    ('buckets', region): 0
                },
                (shards_account_id,): shard_account_info
            },
            {},
            {
                (account_id, name1): container_info1
            },
            {
                (account_id, name2): dtime2,
                (shards_account_id, name3): dtime3
            }
        )
        self._check_backend(*backend_info)

        # Delete +segments
        dtime1 = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, 0, dtime1, 0, 0,
            bucket_name=bucket_name, region=region)
        backend_info = (
            {
                ('accounts',): 2,
                ('bytes', region,): 0,
                ('bytes', region, 'pol1'): 0,
                ('bytes', region, 'pol2'): 0,
                ('objects', region,): 0,
                ('objects', region, 'pol1'): 0,
                ('objects', region, 'pol2'): 0,
                ('containers', region): 0,
                ('buckets', region): 0
            },
            {
                (account_id,): {
                    ('id',): account_id,
                    ('mtime',): dtime1,
                    ('bytes',): 0,
                    ('bytes', region,): 0,
                    ('bytes', region, 'pol1'): 0,
                    ('bytes', region, 'pol2'): 0,
                    ('objects',): 0,
                    ('objects', region,): 0,
                    ('objects', region, 'pol1'): 0,
                    ('objects', region, 'pol2'): 0,
                    ('containers',): 0,
                    ('containers', region): 0,
                    ('buckets',): 0,
                    ('buckets', region): 0
                },
                (shards_account_id,): shard_account_info
            },
            {},
            {},
            {
                (account_id, name1): dtime1,
                (account_id, name2): dtime2,
                (shards_account_id, name3): dtime3
            }
        )
        self._check_backend(*backend_info)
