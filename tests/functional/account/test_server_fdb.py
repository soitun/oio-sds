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

import os
import time
import simplejson as json
from pathlib import Path

from nose.plugins.attrib import attr

from werkzeug.test import Client
from werkzeug.wrappers import Response

import fdb

from oio.account.server import create_app
from oio.common.exceptions import NotFound
from oio.common.timestamp import Timestamp
from tests.utils import BaseTestCase
from oio.account.common_fdb import CommonFdb

fdb.api_version(CommonFdb.FDB_VERSION)


@attr('no_thread_patch')
class TestAccountServerBase(BaseTestCase):
    def setUp(self):
        super(TestAccountServerBase, self).setUp()
        if os.path.exists(CommonFdb.DEFAULT_FDB):
            self.fdb_file = CommonFdb.DEFAULT_FDB
        else:
            self.fdb_file = \
                str(Path.home()) + f'/.oio/sds/conf/{self.ns}-fdb.cluster'
        conf = {
            'fdb_file': self.fdb_file,
            'allow_empty_policy_name': 'False'
        }

        self.account_id = 'test'
        self.acct_app = create_app(conf)
        self.acct_app.backend.init_db()
        self.acct_app.iam.init_db()
        self.acct_app.backend.db.clear_range(b'\x00', b'\xfe')
        self.app = Client(self.acct_app, Response)

    @classmethod
    def _monkey_patch(cls):
        import eventlet
        eventlet.patcher.monkey_patch(os=False, thread=False)

    def _create_account(self, account_id):
        resp = self.app.put('/v1.0/account/create',
                            query_string={"id": account_id})
        self.assertIn(resp.status_code, (201, 202))

    def _flush_account(self, account_id):
        self.app.post('/v1.0/account/flush',
                      query_string={"id": account_id})

    def _delete_account(self, account_id):
        self.app.post('/v1.0/account/delete',
                      query_string={"id": account_id})


class TestAccountServer(TestAccountServerBase):
    """
    Test account-related features of the account service.
    """

    def setUp(self):
        super(TestAccountServer, self).setUp()
        self._create_account(self.account_id)

    def tearDown(self):
        try:
            self._flush_account(self.account_id)
            self._delete_account(self.account_id)
        except NotFound:
            pass
        return super().tearDown()

    def test_status(self):
        resp = self.app.get('/status')
        self.assertEqual(resp.status_code, 200)
        status = self.json_loads(resp.data.decode('utf-8'))
        self.assertGreater(status['account_count'], 0)

    def test_account_list(self):
        resp = self.app.get('/v1.0/account/list')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(self.account_id, resp.data.decode('utf-8'))
        self.assertNotIn('Should_no_exist', resp.data)

    def test_account_info(self):
        resp = self.app.get('/v1.0/account/show',
                            query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode('utf-8'))

        for field in ("ctime", "objects", "bytes", "containers", "metadata"):
            self.assertIn(field, data)

        self.assertGreaterEqual(data['objects'], 0)
        self.assertGreaterEqual(data['containers'], 0)
        self.assertGreaterEqual(data['bytes'], 0)

    def test_account_update(self):
        data = {'metadata': {'foo': 'bar'}, 'to_delete': []}
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/update',
                            data=data, query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 204)

    def test_account_container_update(self):
        params = {
            'id': self.account_id,
            'container': 'foo',
            'region': 'localhost'
        }
        data = {
            'mtime': Timestamp().normal,
            'objects': 0,
            'bytes': 0
        }
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=data, query_string=params)
        self.assertEqual(resp.status_code, 200)

    def test_account_containers(self):
        args = {'id': self.account_id}
        resp = self.app.get('/v1.0/account/containers',
                            query_string=args)
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode('utf-8'))
        for field in ("ctime", "mtime", "bytes", "objects", "containers",
                      "buckets", "metadata", "listing", "truncated"):
            self.assertIn(field, data)
        self.assertEqual(data['bytes'], 0)
        self.assertEqual(data['objects'], 0)
        self.assertEqual(data['containers'], 0)
        self.assertEqual(data['buckets'], 0)
        self.assertDictEqual(data['metadata'], {})
        self.assertListEqual(data['listing'], [])
        self.assertFalse(data['truncated'])

    def test_account_container_reset(self):
        params = {
            'id': self.account_id,
            'container': 'foo',
            'region': 'localhost'
        }
        data = {
            'mtime': Timestamp().normal,
            'objects': 12,
            'bytes': 42
        }
        dataj = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=dataj, query_string=params)

        data = {
            'mtime': Timestamp().normal
        }
        dataj = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/reset',
                            data=dataj, query_string=params)
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get('/v1.0/account/containers',
                            query_string={'id': self.account_id,
                                          'prefix': 'foo'})
        resp = self.json_loads(resp.data)
        for container in resp["listing"]:
            name, nb_objects, nb_bytes, _, mtime = container
            if not name.startswith('foo'):
                self.fail("No prefix foo: %s" % name)
            if name == 'foo':
                self.assertEqual(0, nb_objects)
                self.assertEqual(0, nb_bytes)
                self.assertEqual(float(data['mtime']), mtime)
                return
        self.fail("No container foo")

    def test_account_refresh(self):
        params = {
            'id': self.account_id,
            'container': 'foo',
            'region': 'localhost'
        }
        data = {
            'mtime': Timestamp().normal,
            'objects': 12,
            'bytes': 42
        }
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=data, query_string=params)

        resp = self.app.post('/v1.0/account/refresh',
                             query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get('/v1.0/account/show',
                            query_string={'id': self.account_id})
        resp = self.json_loads(resp.data)
        self.assertEqual(resp["bytes"], 42)
        self.assertEqual(resp["objects"], 12)

    def test_account_flush(self):
        params = {
            'id': self.account_id,
            'container': 'foo',
            'region': 'localhost'
        }
        data = {
            'mtime': Timestamp().normal,
            'objects': 12,
            'bytes': 42
        }
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=data, query_string=params)

        resp = self.app.post('/v1.0/account/flush',
                             query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get('/v1.0/account/show',
                            query_string={'id': self.account_id})
        resp = self.json_loads(resp.data)
        self.assertEqual(resp["bytes"], 0)
        self.assertEqual(resp["objects"], 0)

        resp = self.app.get('/v1.0/account/containers',
                            query_string={'id': self.account_id})
        resp = self.json_loads(resp.data)
        self.assertEqual(len(resp["listing"]), 0)

    def test_change_container_region(self):
        """
        Ensure we can change the region of a container not linked
        to any bucket.
        """
        # Add a new container
        account_params = {
            'id': self.account_id
        }
        container_params = {
            'id': self.account_id,
            'container': 'foo',
            'region': 'localhost'
        }
        data = {
            'mtime': Timestamp().timestamp,
            'objects': 12,
            'bytes': 42,
            'objects-details': {
                'SINGLE': 5,
                'TWOCOPIES': 7
            },
            'bytes-details': {
                'SINGLE': 30,
                'TWOCOPIES': 12
            }
        }
        dataj = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=dataj, query_string=container_params)
        self.assertEqual(200, resp.status_code)
        resp = self.app.get('/v1.0/account/container/show',
                            query_string=container_params)
        resp = self.json_loads(resp.data)
        self.assertEqual('LOCALHOST', resp['region'])
        resp = self.app.get('/v1.0/account/show', query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp['bytes'])
        self.assertEqual(12, resp['objects'])
        self.assertEqual(1, resp['containers'])
        self.assertEqual(0, resp['buckets'])
        self.assertDictEqual({
            'LOCALHOST': {
                'objects-details': {
                    'SINGLE': 5,
                    'TWOCOPIES': 7
                },
                'bytes-details': {
                    'SINGLE': 30,
                    'TWOCOPIES': 12
                },
                'shards': 0,
                'containers': 1,
                'buckets': 0
            }
        }, resp['regions'])

        # Update the container with a new region
        container_params['region'] = 'test'
        data['mtime'] = data['mtime'] + 1
        dataj = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=dataj, query_string=container_params)
        self.assertEqual(200, resp.status_code)
        resp = self.app.get('/v1.0/account/container/show',
                            query_string=container_params)
        resp = self.json_loads(resp.data)
        self.assertEqual('TEST', resp['region'])
        resp = self.app.get('/v1.0/account/show', query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp['bytes'])
        self.assertEqual(12, resp['objects'])
        self.assertEqual(1, resp['containers'])
        self.assertEqual(0, resp['buckets'])
        self.assertDictEqual({
            'LOCALHOST': {
                'objects-details': {
                    'SINGLE': 0,
                    'TWOCOPIES': 0
                },
                'bytes-details': {
                    'SINGLE': 0,
                    'TWOCOPIES': 0
                },
                'shards': 0,
                'containers': 0,
                'buckets': 0
            },
            'TEST': {
                'objects-details': {
                    'SINGLE': 5,
                    'TWOCOPIES': 7
                },
                'bytes-details': {
                    'SINGLE': 30,
                    'TWOCOPIES': 12
                },
                'shards': 0,
                'containers': 1,
                'buckets': 0
            }
        }, resp['regions'])

    def test_change_container_region_without_changing_bucket_region(self):
        """
        Ensure we cannot change the region of a container
        if it's different from the bucket it is linked to.
        """
        # Create a new bucket
        account_params = {
            'id': self.account_id
        }
        bucket_params = {
            'id': 'foo',
            'account': self.account_id,
            'region': 'localhost'
        }
        resp = self.app.put('/v1.0/bucket/create', query_string=bucket_params)
        self.assertEqual(201, resp.status_code)
        container_params = {
            'id': self.account_id,
            'container': 'foo',
            'region': 'localhost'
        }
        # Add a new container in the bucket with the same region
        data = {
            'mtime': Timestamp().timestamp,
            'objects': 12,
            'bytes': 42,
            'objects-details': {
                'SINGLE': 5,
                'TWOCOPIES': 7
            },
            'bytes-details': {
                'SINGLE': 30,
                'TWOCOPIES': 12
            },
            'bucket': 'foo'
        }
        dataj = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=dataj, query_string=container_params)
        self.assertEqual(200, resp.status_code)
        resp = self.app.get('/v1.0/account/container/show',
                            query_string=container_params)
        resp = self.json_loads(resp.data)
        self.assertEqual('LOCALHOST', resp['region'])
        expected_container_info = resp
        resp = self.app.get('/v1.0/bucket/show',
                            query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertEqual('LOCALHOST', resp['region'])
        expected_bucket_info = resp
        resp = self.app.get('/v1.0/account/show', query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp['bytes'])
        self.assertEqual(12, resp['objects'])
        self.assertEqual(1, resp['containers'])
        self.assertEqual(1, resp['buckets'])
        self.assertDictEqual({
            'LOCALHOST': {
                'objects-details': {
                    'SINGLE': 5,
                    'TWOCOPIES': 7
                },
                'bytes-details': {
                    'SINGLE': 30,
                    'TWOCOPIES': 12
                },
                'shards': 0,
                'containers': 1,
                'buckets': 1
            }
        }, resp['regions'])
        expected_account_info = resp

        # Update the container with a new region
        container_params['region'] = 'test'
        data['mtime'] = data['mtime'] + 1
        dataj = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=dataj, query_string=container_params)
        # Because the container is linked to a bucket in another region,
        # the request should fail
        self.assertEqual(409, resp.status_code)
        resp = self.app.get('/v1.0/account/container/show',
                            query_string=container_params)
        resp = self.json_loads(resp.data)
        self.assertDictEqual(expected_container_info, resp)
        resp = self.app.get('/v1.0/bucket/show',
                            query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertDictEqual(expected_bucket_info, resp)
        resp = self.app.get('/v1.0/account/show', query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertDictEqual(expected_account_info, resp)

    def test_change_bucket_region(self):
        """
        Ensure we can change the region of a bucket and its container
        (if we change the region of the bucket first).
        """
        # Create a new bucket
        account_params = {
            'id': self.account_id
        }
        bucket_params = {
            'id': 'foo',
            'account': self.account_id,
            'region': 'localhost'
        }
        resp = self.app.put('/v1.0/bucket/create', query_string=bucket_params)
        self.assertEqual(201, resp.status_code)
        container_params = {
            'id': self.account_id,
            'container': 'foo',
            'region': 'localhost'
        }
        # Add a new container in the bucket with the same region
        data = {
            'mtime': Timestamp().timestamp,
            'objects': 12,
            'bytes': 42,
            'objects-details': {
                'SINGLE': 5,
                'TWOCOPIES': 7
            },
            'bytes-details': {
                'SINGLE': 30,
                'TWOCOPIES': 12
            },
            'bucket': 'foo'
        }
        dataj = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=dataj, query_string=container_params)
        self.assertEqual(200, resp.status_code)
        resp = self.app.get('/v1.0/account/container/show',
                            query_string=container_params)
        resp = self.json_loads(resp.data)
        self.assertEqual('LOCALHOST', resp['region'])
        resp = self.app.get('/v1.0/bucket/show',
                            query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertEqual('LOCALHOST', resp['region'])
        resp = self.app.get('/v1.0/account/show', query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp['bytes'])
        self.assertEqual(12, resp['objects'])
        self.assertEqual(1, resp['containers'])
        self.assertEqual(1, resp['buckets'])
        self.assertDictEqual({
            'LOCALHOST': {
                'objects-details': {
                    'SINGLE': 5,
                    'TWOCOPIES': 7
                },
                'bytes-details': {
                    'SINGLE': 30,
                    'TWOCOPIES': 12
                },
                'shards': 0,
                'containers': 1,
                'buckets': 1
            }
        }, resp['regions'])

        # Change the bucket region
        resp = self.app.put('/v1.0/bucket/update',
                            data=json.dumps({'metadata': {'region': 'test'}}),
                            query_string=bucket_params)
        self.assertEqual(204, resp.status_code)
        container_params['region'] = 'test'
        data['mtime'] = data['mtime'] + 1
        dataj = json.dumps(data)
        resp = self.app.get('/v1.0/bucket/show',
                            query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertEqual('TEST', resp['region'])
        self.assertEqual(0, resp['bytes'])
        self.assertEqual(0, resp['objects'])
        resp = self.app.get('/v1.0/account/show', query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp['bytes'])
        self.assertEqual(12, resp['objects'])
        self.assertEqual(1, resp['containers'])
        self.assertEqual(1, resp['buckets'])
        self.assertDictEqual({
            'LOCALHOST': {
                'objects-details': {
                    'SINGLE': 5,
                    'TWOCOPIES': 7
                },
                'bytes-details': {
                    'SINGLE': 30,
                    'TWOCOPIES': 12
                },
                'shards': 0,
                'containers': 1,
                'buckets': 0
            },
            'TEST': {
                'objects-details': {},
                'bytes-details': {},
                'shards': 0,
                'containers': 0,
                'buckets': 1
            }
        }, resp['regions'])
        # Update the container with the new region
        resp = self.app.put('/v1.0/account/container/update',
                            data=dataj, query_string=container_params)
        # Because the container has the same new region as the bucket,
        # the request should succeed
        self.assertEqual(200, resp.status_code)
        resp = self.app.get('/v1.0/account/container/show',
                            query_string=container_params)
        resp = self.json_loads(resp.data)
        self.assertEqual('TEST', resp['region'])
        resp = self.app.get('/v1.0/bucket/show',
                            query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertEqual('TEST', resp['region'])
        self.assertEqual(42, resp['bytes'])
        self.assertEqual(12, resp['objects'])
        resp = self.app.get('/v1.0/account/show', query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp['bytes'])
        self.assertEqual(12, resp['objects'])
        self.assertEqual(1, resp['containers'])
        self.assertEqual(1, resp['buckets'])
        self.assertDictEqual({
            'LOCALHOST': {
                'objects-details': {
                    'SINGLE': 0,
                    'TWOCOPIES': 0
                },
                'bytes-details': {
                    'SINGLE': 0,
                    'TWOCOPIES': 0
                },
                'shards': 0,
                'containers': 0,
                'buckets': 0
            },
            'TEST': {
                'objects-details': {
                    'SINGLE': 5,
                    'TWOCOPIES': 7
                },
                'bytes-details': {
                    'SINGLE': 30,
                    'TWOCOPIES': 12
                },
                'shards': 0,
                'containers': 1,
                'buckets': 1
            }
        }, resp['regions'])


IAM_POLICY_FULLACCESS = """{
    "Statement": [
        {
            "Sid": "FullAccess",
            "Action": [
                "s3:*"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        }
    ]
}
"""


class TestIamServer(TestAccountServerBase):
    """
    Test IAM-related features of the account service.
    """

    def setUp(self):
        super(TestIamServer, self).setUp()
        self.user1 = self.account_id + ':user1'
        self.user2 = self.account_id + ':user2'

    def tearDown(self):
        super(TestIamServer, self).tearDown()

    def test_put_user_policy(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)

    def test_put_user_policy_no_body(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'})
        self.assertIn(b'Missing policy document', resp.data)
        self.assertEqual(resp.status_code, 400)

    def test_put_user_policy_no_name(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b'policy name cannot be empty', resp.data)

    def test_put_user_policy_invalid_name(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'invalid:policy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertIn(b'policy name does not match', resp.data)
        self.assertEqual(resp.status_code, 400)

    def test_put_user_policy_not_json(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data='FullAccess')
        self.assertIn(b'policy is not JSON-formatted', resp.data)
        self.assertEqual(resp.status_code, 400)

    def test_put_user_policy_wrong_method(self):
        resp = self.app.get('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 405)

    def _compare_policies(self, expected, actual):
        exp_st = expected.get('Statement', {})
        act_st = actual.get('Statement', {})
        self.assertEqual(exp_st[0], act_st[0])

    def test_get_user_policy(self):
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        resp = self.app.get('/v1.0/iam/get-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'})
        self.assertEqual(resp.status_code, 200)
        expected = json.loads(IAM_POLICY_FULLACCESS)
        actual = json.loads(resp.data.decode('utf-8'))
        self._compare_policies(expected, actual)

    def test_get_user_policy_no_name(self):
        resp = self.app.get('/v1.0/iam/get-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        # XXX: for backward compatibility reasons, we accept to load
        # a policy with no name.
        self.assertIn(b'not found', resp.data)
        self.assertEqual(resp.status_code, 404)

    def test_get_user_policy_not_existing(self):
        resp = self.app.get('/v1.0/iam/get-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'missing'})
        self.assertIn(b'not found', resp.data)
        self.assertEqual(resp.status_code, 404)

    def test_list_user_policies(self):
        # First policy
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertEqual(actual['PolicyNames'], ['mypolicy'])

        # Second policy
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mysecondpolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))

        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertEqual(actual['PolicyNames'], ['mypolicy', 'mysecondpolicy'])

    def test_list_user_policies_no_policies(self):
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertFalse(actual['PolicyNames'])

    def test_list_users(self):
        # First user
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-users',
                            query_string={'account': self.account_id})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('Users', actual)
        self.assertEqual(actual['Users'], [self.user1])

        # Second user
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user2,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-users',
                            query_string={'account': self.account_id})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('Users', actual)
        self.assertEqual(actual['Users'], [self.user1, self.user2])

    def test_list_users_no_user(self):
        resp = self.app.get('/v1.0/iam/list-users',
                            query_string={'account': self.account_id})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('Users', actual)
        self.assertFalse(actual['Users'])

    def test_delete_user_policy(self):
        # Put a bunch of policies
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mypolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.put('/v1.0/iam/put-user-policy',
                            query_string={'account': self.account_id,
                                          'user': self.user1,
                                          'policy-name': 'mysecondpolicy'},
                            data=IAM_POLICY_FULLACCESS.encode('utf-8'))
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertEqual(actual['PolicyNames'], ['mypolicy', 'mysecondpolicy'])

        # Delete the policies
        resp = self.app.delete('/v1.0/iam/delete-user-policy',
                               query_string={'account': self.account_id,
                                             'user': self.user1,
                                             'policy-name': 'mypolicy'})
        self.assertEqual(resp.status_code, 204)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertEqual(actual['PolicyNames'], ['mysecondpolicy'])
        resp = self.app.delete('/v1.0/iam/delete-user-policy',
                               query_string={'account': self.account_id,
                                             'user': self.user1,
                                             'policy-name': 'mysecondpolicy'})
        self.assertEqual(resp.status_code, 204)
        resp = self.app.get('/v1.0/iam/list-user-policies',
                            query_string={'account': self.account_id,
                                          'user': self.user1})
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode('utf-8'))
        self.assertIn('PolicyNames', actual)
        self.assertFalse(actual['PolicyNames'])

    def test_delete_user_policy_not_existing(self):
        resp = self.app.delete('/v1.0/iam/delete-user-policy',
                               query_string={'account': self.account_id,
                                             'user': self.user1,
                                             'policy-name': 'mypolicy'})
        self.assertEqual(resp.status_code, 204)


class TestAccountMetrics(TestAccountServerBase):
    """
    Test account-related features of the account service.
    """

    def setUp(self):
        super(TestAccountMetrics, self).setUp()

    def test_metrics_nb_accounts(self):
        resp = self.app.get('/metrics')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 0,
            'regions': {}
        }, resp)

        for i in range(2):
            account_id = 'acct1-' + str(i)
            self._create_account(account_id)
        resp = self.app.get('/metrics')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 2,
            'regions': {}
        }, resp)

        self._delete_account('acct1-0')
        resp = self.app.get('/metrics')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 1,
            'regions': {}
        }, resp)

        self._delete_account('acct1-1')
        resp = self.app.get('/metrics')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 0,
            'regions': {}
        }, resp)

    def test_metrics_nb_containers(self):
        self._create_account(self.account_id)
        resp = self.app.get('/metrics')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 1,
            'regions': {}
        }, resp)

        # create  and delete some containers
        # check to send headers for region, storage class
        params = {
            'id': self.account_id,
            'container': 'ct1',
            'region': 'localhost'
        }
        data = {
            'mtime': time.time(),
            'objects': 1,
            'bytes': 20
        }
        data = json.dumps(data)
        resp = self.app.put(
            '/v1.0/account/container/update', data=data, query_string=params)
        resp = self.app.get('/metrics')
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 1,
            'regions': {
                'LOCALHOST': {
                    'containers': 1,
                    'shards': 0,
                    'buckets': 0,
                    'bytes-details': {},
                    'objects-details': {},
                }
            }
        }, resp)

        data = {
            'dtime': time.time()
        }
        data = json.dumps(data)
        self.app.post(
            '/v1.0/account/container/delete', data=data, query_string={
                'id': self.account_id,
                'container': 'ct1'
            })
        resp = self.app.get('/metrics')
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 1,
            'regions': {
                'LOCALHOST': {
                    'containers': 0,
                    'shards': 0,
                    'buckets': 0,
                    'bytes-details': {},
                    'objects-details': {},
                }
            }
        }, resp)

    def test_metrics_nb_objects_bytes(self):
        self._create_account(self.account_id)
        resp = self.app.get('/metrics')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 1,
            'regions': {}
        }, resp)

        # add some data
        params = {
            'id': self.account_id,
            'container': 'ct1',
            'region': 'localhost'
        }
        data = {
            'mtime': Timestamp().normal,
            'objects': 3,
            'bytes': 40,
            'objects-details': {"class1": 1, "class2": 2},
            'bytes-details': {"class1": 30, "class2": 10}
        }
        data = json.dumps(data)
        self.app.put('/v1.0/account/container/update',
                     data=data, query_string=params)
        resp = self.app.get('/metrics')
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 1,
            'regions': {
                'LOCALHOST': {
                    'containers': 1,
                    'shards': 0,
                    'buckets': 0,
                    'objects-details': {
                        'class1': 1,
                        'class2': 2
                    },
                    'bytes-details': {
                        'class1': 30,
                        'class2': 10
                    },
                }
            }
        }, resp)

        params = {
            'id': self.account_id,
            'container': 'ct2',
            'region': 'localhost'
        }
        data = {
            'mtime': Timestamp().normal,
            'objects': 6, 'bytes': 21,
            'objects-details': {"class2": 1, "class3": 5},
            'bytes-details': {"class2": 10, "class3": 11}
        }
        data = json.dumps(data)
        self.app.put('/v1.0/account/container/update',
                     data=data, query_string=params)
        resp = self.app.get('/metrics')
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 1,
            'regions': {
                'LOCALHOST': {
                    'containers': 2,
                    'shards': 0,
                    'buckets': 0,
                    'objects-details': {
                        'class1': 1,
                        'class2': 3,
                        'class3': 5
                    },
                    'bytes-details': {
                        'class1': 30,
                        'class2': 20,
                        'class3': 11
                    },
                }
            }
        }, resp)

    def test_recompute(self):
        self._create_account(self.account_id)
        resp = self.app.get('/metrics')
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 1,
            'regions': {}
        }, resp)

        params = {
            'id': self.account_id,
            'container': 'foo',
            'region': 'localhost'
        }
        data = {
            'mtime': Timestamp().normal,
            'objects': 6,
            'bytes': 21,
            'objects-details': {"class2": 1, "class3": 5},
            'bytes-details': {"class2": 10, "class3": 11}
        }
        data = json.dumps(data)
        resp = self.app.put('/v1.0/account/container/update',
                            data=data, query_string=params)
        resp = self.app.get('/metrics',
                            query_string={'id': self.account_id})
        resp = self.json_loads(resp.data)

        resp = self.app.post('/metrics/recompute')
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get('/metrics',
                            query_string={'id': self.account_id})
        resp = self.json_loads(resp.data)
        self.assertDictEqual({
            'accounts': 1,
            'regions': {
                'LOCALHOST': {
                    'containers': 1,
                    'shards': 0,
                    'buckets': 0,
                    'objects-details': {
                        'class2': 1,
                        'class3': 5
                    },
                    'bytes-details': {
                        'class2': 10,
                        'class3': 11
                    },
                }
            }
        }, resp)
