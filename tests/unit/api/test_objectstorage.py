# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

# pylint: disable=protected-access

import json
import random
import unittest
from io import IOBase
from os.path import basename
from tempfile import NamedTemporaryFile

from mock import ANY
from mock import MagicMock as Mock

from oio.api.object_storage import ObjectStorageApi
from oio.common import exceptions
from oio.common.constants import CONTAINER_HEADERS, OBJECT_HEADERS, REQID_HEADER
from oio.common.decorators import handle_container_not_found, handle_object_not_found
from oio.common.green import get_watchdog
from oio.common.storage_functions import _sort_chunks
from tests.unit.api import FakeApiResponse, FakeStorageApi
from tests.utils import random_str


def chunk(suffix, position, score=100, host="1.2.3.4:6000"):
    return {
        "url": f"http://{host}/{suffix}",
        "pos": str(position),
        "size": 32,
        "hash": "0" * 32,
        "score": score,
    }


def extend(base, inc):
    base.update(inc)
    return base


class ObjectStorageTest(unittest.TestCase):
    def setUp(self):
        self.fake_endpoint = "http://1.2.3.4:8000"
        self.fake_account_endpoint = "http://1.2.3.4:8080"
        self.watchdog = get_watchdog(called_from_main_application=True)
        self.api = FakeStorageApi(
            "NS",
            endpoint=self.fake_endpoint,
            account_endpoint=self.fake_account_endpoint,
            watchdog=self.watchdog,
        )
        self.account = "test"
        self.container = "fake"
        reqid = random_str(32)
        self.headers = {REQID_HEADER: reqid}
        self.common_kwargs = {
            "headers": self.headers,
            "reqid": reqid,
            "watchdog": self.watchdog,
        }
        self.policy = "THREECOPIES"
        self.uri_base = self.fake_endpoint + "/v3.0/NS"

    def test_handle_container_not_found(self):
        @handle_container_not_found
        def test(self, account, container):
            raise exceptions.NotFound("No container")

        container = random_str(32)
        self.assertRaises(
            exceptions.NoSuchContainer, test, self, self.account, container
        )

    def test_handle_object_not_found(self):
        @handle_object_not_found
        def test(self, account, container, obj):
            raise exceptions.NotFound("No object")

        obj = random_str(32)
        self.assertRaises(
            exceptions.NoSuchObject, test, self, self.account, self.container, obj
        )

    def test_container_list(self):
        resp = FakeApiResponse()
        name = random_str(32)
        marker = random_str(32)
        end_marker = random_str(32)
        prefix = random_str(32)
        limit = random.randint(1, 1000)
        region = "localhost"
        body = {"listing": [[name, 0, 0, 0]]}
        fake_endpoint = "fake_endpoint"
        self.api.account._direct_request = Mock(return_value=(resp, body))
        self.api.account.endpoint = None
        self.api.account._get_service_addresses = Mock(return_value=[fake_endpoint])
        containers = self.api.container_list(
            self.account,
            limit=limit,
            marker=marker,
            prefix=prefix,
            end_marker=end_marker,
            region=region,
            **self.common_kwargs,
        )
        params = {
            "id": self.account,
            "prefix": prefix,
            "marker": marker,
            "end_marker": end_marker,
            "limit": limit,
            "region": region,
            "bucket": None,
        }
        uri = "http://%s/v1.0/account/containers" % fake_endpoint
        self.api.account._direct_request.assert_called_once_with(
            "GET", uri, params=params, autocreate=True, **self.common_kwargs
        )
        self.assertEqual(len(containers), 1)

    def test_object_list(self):
        api = self.api
        marker = random_str(32)
        delimiter = random_str(32)
        end_marker = random_str(32)
        prefix = random_str(32)
        limit = random.randint(1, 1000)
        name0 = random_str(32)
        name1 = random_str(32)
        resp_body = {"objects": [{"name": name0}, {"name": name1}]}
        resp = FakeApiResponse()
        resp.headers = {}
        api.container._direct_request = Mock(return_value=(resp, resp_body))
        listing = api.object_list(
            self.account,
            self.container,
            limit=limit,
            marker=marker,
            prefix=prefix,
            delimiter=delimiter,
            end_marker=end_marker,
            **self.common_kwargs,
        )
        uri = "%s/container/list" % self.uri_base
        params = {
            "acct": self.account,
            "ref": self.container,
            "marker": marker,
            "max": limit,
            "delimiter": delimiter,
            "prefix": prefix,
            "end_marker": end_marker,
            "properties": False,
            "chunks": False,
        }
        api.container._direct_request.assert_called_once_with(
            "GET", uri, params=params, autocreate=True, path=ANY, **self.common_kwargs
        )
        self.assertEqual(len(listing["objects"]), 2)

    def test_container_show(self):
        api = self.api
        resp = FakeApiResponse()
        name = random_str(32)
        cont_size = random.randint(1, 1000)
        resp.headers = {CONTAINER_HEADERS["size"]: cont_size}
        api.container._direct_request = Mock(return_value=(resp, {}))
        info = api.container_show(self.account, name, **self.common_kwargs)
        uri = "%s/container/show" % self.uri_base
        params = {"acct": self.account, "ref": name}
        api.container._direct_request.assert_called_once_with(
            "GET", uri, params=params, autocreate=True, **self.common_kwargs
        )
        self.assertEqual(info, {})

    def test_container_show_not_found(self):
        api = self.api
        api.container._direct_request = Mock(
            side_effect=exceptions.NotFound("No container")
        )
        name = random_str(32)
        self.assertRaises(
            exceptions.NoSuchContainer, api.container_show, self.account, name
        )

    def test_container_create(self):
        api = self.api
        resp = FakeApiResponse()
        resp.status = 201
        api.container._direct_request = Mock(return_value=(resp, None))

        name = random_str(32)
        result = api.container_create(self.account, name, **self.common_kwargs)
        self.assertEqual(result, True)

        uri = "%s/container/create" % self.uri_base
        params = {"acct": self.account, "ref": name}
        self.headers["x-oio-action-mode"] = "autocreate"
        data = json.dumps({"properties": {}, "system": {}})
        api.container._direct_request.assert_called_once_with(
            "POST",
            uri,
            params=params,
            data=data,
            autocreate=True,
            region=None,
            **self.common_kwargs,
        )

    def test_container_create_exist(self):
        api = self.api
        resp = FakeApiResponse()
        resp.status = 204
        api.container._direct_request = Mock(return_value=(resp, None))

        name = random_str(32)
        result = api.container_create(self.account, name)
        self.assertEqual(result, False)

    def test_container_delete(self):
        api = self.api

        resp = FakeApiResponse()
        resp.status_code = 204
        api.container._direct_request = Mock(return_value=(resp, None))
        api.directory.unlink = Mock(return_value=None)
        name = random_str(32)
        api.container_delete(self.account, name, **self.common_kwargs)

        uri = "%s/container/destroy" % self.uri_base
        params = {"acct": self.account, "ref": name}
        api.container._direct_request.assert_called_once_with(
            "POST", uri, params=params, autocreate=True, **self.common_kwargs
        )

    def test_container_delete_not_empty(self):
        api = self.api

        api.container._direct_request = Mock(side_effect=exceptions.Conflict(""))
        api.directory.unlink = Mock(return_value=None)
        name = random_str(32)

        self.assertRaises(
            exceptions.ContainerNotEmpty, api.container_delete, self.account, name
        )

    def test_container_update(self):
        api = self.api

        name = random_str(32)
        key = random_str(32)
        value = random_str(32)
        meta = {key: value}
        resp = FakeApiResponse()
        api.container._direct_request = Mock(return_value=(resp, None))
        api.container_set_properties(self.account, name, meta, **self.common_kwargs)

        data = json.dumps({"properties": meta, "system": {}})
        uri = "%s/container/set_properties" % self.uri_base
        params = {"acct": self.account, "ref": name}
        api.container._direct_request.assert_called_once_with(
            "POST", uri, data=data, params=params, autocreate=True, **self.common_kwargs
        )

    def test_object_show(self):
        api = self.api
        name = random_str(32)
        size = random.randint(1, 1000)
        content_hash = random_str(32)
        content_type = random_str(32)
        resp = FakeApiResponse()
        resp.headers = {
            OBJECT_HEADERS["name"]: name,
            OBJECT_HEADERS["size"]: str(size),
            OBJECT_HEADERS["hash"]: content_hash,
            OBJECT_HEADERS["mime_type"]: content_type,
        }
        api.container._direct_request = Mock(return_value=(resp, {"properties": {}}))
        obj = api.object_show(self.account, self.container, name, **self.common_kwargs)

        uri = "%s/content/get_properties" % self.uri_base
        params = {
            "acct": self.account,
            "ref": self.container,
            "path": name,
            "version": None,
        }
        api.container._direct_request.assert_called_once_with(
            "POST", uri, params=params, data=None, autocreate=True, **self.common_kwargs
        )
        self.assertIsNotNone(obj)

    def test_object_create_no_data(self):
        api = self.api
        name = random_str(32)
        self.assertRaises(
            exceptions.MissingData,
            api.object_create,
            self.account,
            self.container,
            obj_name=name,
        )

    def test_object_create_no_name(self):
        api = self.api
        self.assertRaises(
            exceptions.MissingName,
            api.object_create,
            self.account,
            self.container,
            data="x",
        )

    def test_object_create_missing_file(self):
        api = self.api
        name = random_str(32)
        self.assertRaises(
            exceptions.FileNotFound,
            api.object_create,
            self.account,
            self.container,
            name,
        )

    def test_object_create_from_file(self):
        self.api._object_create = Mock(return_value=None)
        src = NamedTemporaryFile()
        self.api.object_create_ext(self.account, self.container, file_or_path=src)
        self.api._object_create.assert_called_once()
        call_args = self.api._object_create.call_args
        self.assertIs(call_args[0][0], self.account)
        self.assertIs(call_args[0][1], self.container)
        self.assertEqual(call_args[0][2], basename(src.name))
        self.assertIs(call_args[0][3], src)

    def test_object_create_from_file_path(self):
        self.api._object_create = Mock(return_value=None)
        src = NamedTemporaryFile()
        self.api.object_create_ext(self.account, self.container, file_or_path=src.name)
        self.api._object_create.assert_called_once()
        call_args = self.api._object_create.call_args
        self.assertIs(call_args[0][0], self.account)
        self.assertIs(call_args[0][1], self.container)
        self.assertEqual(call_args[0][2], basename(src.name))
        self.assertIsInstance(call_args[0][3], IOBase)
        self.assertEqual(call_args[0][3].name, src.name)

    def test_object_create_from_iterable(self):
        class DataGen(object):
            def __init__(self):
                self.data = "abcd"
                self.pos = 0

            def __iter__(self):
                return self

            def next(self):
                if self.pos >= len(self.data):
                    raise StopIteration()
                self.pos += 1
                return self.data[self.pos - 1]

        self.api._object_create = Mock(return_value=None)
        name = random_str(32)
        self.api.object_create_ext(
            self.account, self.container, data=DataGen(), obj_name=name
        )
        self.api._object_create.assert_called_once()
        call_args = self.api._object_create.call_args
        from oio.common.utils import GeneratorIO

        self.assertIs(call_args[0][0], self.account)
        self.assertIs(call_args[0][1], self.container)
        self.assertIs(call_args[0][2], name)
        self.assertIsInstance(call_args[0][3], GeneratorIO)

    def test_object_create_from_string(self):
        self.api._object_create = Mock(return_value=None)
        name = random_str(32)
        self.api.object_create_ext(
            self.account, self.container, data=name, obj_name=name
        )
        self.api._object_create.assert_called_once()
        call_args = self.api._object_create.call_args
        self.assertIs(call_args[0][0], self.account)
        self.assertIs(call_args[0][1], self.container)
        self.assertIs(call_args[0][2], name)
        from io import IOBase

        self.assertIsInstance(call_args[0][3], IOBase)

    def test_object_create_properties_callback(self):
        obj_meta_in = {
            "id": None,
            "version": 1,
            "properties": {},
            "policy": "whatever",
            "mime_type": None,
            "chunk_method": None,
        }
        obj_meta_ext = {"a": "a"}
        self.api._object_prepare = Mock(return_value=(obj_meta_in, None, None))
        self.api._object_upload = Mock(return_value=([], 0, None))
        resp = FakeApiResponse()
        self.api.container._direct_request = Mock(return_value=(resp, None))
        name = "fake"
        props_cb = Mock(return_value=obj_meta_ext)
        _, _, _, obj_meta_out = self.api.object_create_ext(
            self.account,
            self.container,
            data=name.encode("utf-8"),
            obj_name=name,
            properties_callback=props_cb,
        )
        props_cb.assert_called_once()
        self.assertEqual(obj_meta_ext, obj_meta_out["properties"])

    def test_object_create_properties_callback_failure(self):
        obj_meta_in = {
            "id": None,
            "version": 1,
            "properties": {},
            "policy": "whatever",
            "mime_type": None,
            "chunk_method": None,
        }
        self.api._blob_client = Mock()
        self.api._object_prepare = Mock(return_value=(obj_meta_in, None, None))
        self.api._object_upload = Mock(return_value=([], 0, None))
        resp = FakeApiResponse()
        self.api.container._direct_request = Mock(return_value=(resp, None))
        name = "fake"
        props_cb = Mock(return_value="type error")
        self.assertRaises(
            TypeError,
            self.api.object_create_ext,
            self.account,
            self.container,
            data=name.encode("utf-8"),
            obj_name=name,
            properties_callback=props_cb,
        )

    def test_object_set_properties(self):
        api = self.api

        name = random_str(32)
        key = random_str(32)
        value = random_str(32)
        meta = {key: value}
        resp = FakeApiResponse()
        api.container._direct_request = Mock(return_value=(resp, None))
        api.object_set_properties(
            self.account, self.container, name, meta, **self.common_kwargs
        )

        data = {"properties": meta}
        data = json.dumps(data)
        uri = "%s/content/set_properties" % self.uri_base
        params = {"acct": self.account, "ref": self.container, "path": name}
        api.container._direct_request.assert_called_once_with(
            "POST", uri, data=data, params=params, autocreate=True, **self.common_kwargs
        )

    def test_object_del_properties(self):
        resp = FakeApiResponse()
        self.api.container._direct_request = Mock(return_value=(resp, None))
        self.api.object_del_properties(
            self.account, self.container, "a", ["a"], version="17", **self.common_kwargs
        )
        uri = "%s/content/del_properties" % self.uri_base
        params = {
            "acct": self.account,
            "ref": self.container,
            "path": "a",
            "version": "17",
        }
        self.api.container._direct_request.assert_called_once_with(
            "POST",
            uri,
            data=json.dumps(["a"]),
            params=params,
            autocreate=True,
            **self.common_kwargs,
        )

    def test_object_delete(self):
        api = self.api
        name = random_str(32)
        resp_body = [chunk("AAAA", "0"), chunk("BBBB", "1"), chunk("CCCC", "2")]
        resp = FakeApiResponse()
        api.container._direct_request = Mock(return_value=(resp, resp_body))

        api.object_delete(self.account, self.container, name, **self.common_kwargs)

        uri = "%s/content/delete" % self.uri_base
        params = {"acct": self.account, "ref": self.container, "path": name}
        api.container._direct_request.assert_called_once_with(
            "POST", uri, params=params, data="{}", autocreate=True, **self.common_kwargs
        )

    def test_object_delete_not_found(self):
        api = self.api
        name = random_str(32)
        api.container._direct_request = Mock(
            side_effect=exceptions.NotFound("No object")
        )
        self.assertRaises(
            exceptions.NoSuchObject,
            api.object_delete,
            self.account,
            self.container,
            name,
        )

    def test_object_touch(self):
        self.api.container._direct_request = Mock()
        self.api.object_touch(
            self.account, self.container, "obj", version="31", **self.common_kwargs
        )
        uri = "%s/content/touch" % self.uri_base
        params = {
            "acct": self.account,
            "ref": self.container,
            "path": "obj",
            "version": "31",
        }
        self.api.container._direct_request.assert_called_once_with(
            "POST", uri, params=params, autocreate=True, **self.common_kwargs
        )

    def test_sort_chunks(self):
        raw_chunks = [
            chunk("AAAA", "0"),
            chunk("BBBB", "0", score=12),
            chunk("CCCC", "1", score=42),
            chunk("DDDD", "1"),
            chunk("EEEE", "2", score=20),
            chunk("FFFF", "2", score=50),
        ]
        chunks = _sort_chunks(raw_chunks, False)
        sorted_chunks = {
            0: [
                extend(chunk("AAAA", "0"), {"offset": 0}),
                extend(chunk("BBBB", "0", score=12), {"offset": 0}),
            ],
            1: [
                extend(chunk("DDDD", "1"), {"offset": 32}),
                extend(chunk("CCCC", "1", score=42), {"offset": 32}),
            ],
            2: [
                extend(chunk("FFFF", "2", score=50), {"offset": 64}),
                extend(chunk("EEEE", "2", score=20), {"offset": 64}),
            ],
        }
        self.assertDictEqual(sorted_chunks, chunks)

        raw_chunks = [
            chunk("AAAA", "0.0", score=0),
            chunk("BBBB", "0.1", score=-1),
            chunk("CCCC", "0.2", score=0),
            chunk("DDDD", "1.0", score=-1),
            chunk("EEEE", "1.1", score=0),
            chunk("FFFF", "1.2", score=-1),
        ]
        chunks = _sort_chunks(raw_chunks, True)
        sorted_chunks = {
            0: [
                extend(chunk("AAAA", "0.0", score=0), {"num": 0, "offset": 0}),
                extend(chunk("CCCC", "0.2", score=0), {"num": 2, "offset": 0}),
                extend(chunk("BBBB", "0.1", score=-1), {"num": 1, "offset": 0}),
            ],
            1: [
                extend(chunk("EEEE", "1.1", score=0), {"num": 1, "offset": 32}),
                extend(chunk("DDDD", "1.0", score=-1), {"num": 0, "offset": 32}),
                extend(chunk("FFFF", "1.2", score=-1), {"num": 2, "offset": 32}),
            ],
        }
        self.assertDictEqual(sorted_chunks, chunks)

        # Some chunks have a lower score because we want them sorted AFTER.
        # Indeed, EC chunks are not sorted by subposition, but by score.
        # And there is some kind of randomization for close scores, hence
        # the 20 percent gap.
        raw_chunks = [
            chunk("AAAA", "0.0"),
            chunk("BBBB", "0.1", 80),
            chunk("AAAA", "0.0"),
            chunk("DDDD", "1.0"),
            chunk("EEEE", "1.1", 80),
            chunk("EEEE", "1.1", 80),
        ]
        chunks = _sort_chunks(raw_chunks, True)
        sorted_chunks = {
            0: [
                extend(chunk("AAAA", "0.0"), {"num": 0, "offset": 0}),
                extend(chunk("BBBB", "0.1", 80), {"num": 1, "offset": 0}),
            ],
            1: [
                extend(chunk("DDDD", "1.0"), {"num": 0, "offset": 32}),
                extend(chunk("EEEE", "1.1", 80), {"num": 1, "offset": 32}),
            ],
        }
        self.maxDiff = 8000
        self.assertDictEqual(sorted_chunks, chunks)

    def test_sort_chunks_duplicates(self):
        self.maxDiff = 8000
        raw_chunks = [
            chunk("AAAA", "0.0"),
            chunk("BBBB", "0.1", 80),
            chunk("AAAA", "0.0", 59, host="1.2.3.5:6001"),
            chunk("DDDD", "1.0"),
            chunk("EEEE", "1.1", 80),
            chunk("EEEE", "1.1", 59, host="1.2.3.5:6001"),
        ]
        chunks = _sort_chunks(raw_chunks, True, keep_duplicates=True)
        sorted_chunks = {
            0: [
                extend(chunk("AAAA", "0.0"), {"num": 0, "offset": 0}),
                extend(chunk("BBBB", "0.1", 80), {"num": 1, "offset": 0}),
                extend(
                    chunk("AAAA", "0.0", 59, host="1.2.3.5:6001"),
                    {"num": 0, "offset": 0},
                ),
            ],
            1: [
                extend(chunk("DDDD", "1.0"), {"num": 0, "offset": 32}),
                extend(chunk("EEEE", "1.1", 80), {"num": 1, "offset": 32}),
                extend(
                    chunk("EEEE", "1.1", 59, host="1.2.3.5:6001"),
                    {"num": 1, "offset": 32},
                ),
            ],
        }
        self.assertDictEqual(sorted_chunks, chunks)

        chunks = _sort_chunks(raw_chunks, True, keep_duplicates=False)  # default
        sorted_chunks = {
            0: [
                extend(chunk("AAAA", "0.0"), {"num": 0, "offset": 0}),
                extend(chunk("BBBB", "0.1", 80), {"num": 1, "offset": 0}),
            ],
            1: [
                extend(chunk("DDDD", "1.0"), {"num": 0, "offset": 32}),
                extend(chunk("EEEE", "1.1", 80), {"num": 1, "offset": 32}),
            ],
        }
        self.assertDictEqual(sorted_chunks, chunks)

    def test_container_refresh_conflict(self):
        self.api.account.container_reset = Mock(
            side_effect=exceptions.Conflict("No update needed")
        )
        self.assertRaises(
            exceptions.Conflict,
            self.api.container_refresh,
            self.account,
            self.container,
        )

    def test_object_create_patch_kwargs(self):
        """
        Check that the patch_kwargs decorator does its job on object_create.
        """
        kwargs = {x: "test" for x in ObjectStorageApi.EXTRA_KEYWORDS}
        # Pass kwargs to class constructor
        api = ObjectStorageApi(
            "NS",
            endpoint=self.fake_endpoint,
            account_endpoint=self.fake_account_endpoint,
            dummy_keyword="dummy_value",
            **kwargs,
        )
        self.assertNotIn("dummy_keyword", api._global_kwargs)
        for k, v in kwargs.items():
            self.assertIn(k, api._global_kwargs)
            self.assertEqual(v, api._global_kwargs[k])

        # Verify that kwargs are forwarded to method call
        api._object_create = Mock()
        api.object_create_ext(
            self.account, self.container, data="data", obj_name="dummy"
        )
        api._object_create.assert_called_with(
            self.account,
            self.container,
            "dummy",
            ANY,
            ANY,
            append=ANY,
            headers=ANY,
            key_file=ANY,
            policy=ANY,
            properties=ANY,
            extra_properties=ANY,
            pre_commit_hook=ANY,
            reqid=ANY,
            properties_callback=ANY,
            **kwargs,
        )

    def test_container_flush_not_found_1(self):
        self.api.object_list = Mock(side_effect=exceptions.NotFound("No container"))
        self.assertRaises(
            exceptions.NoSuchContainer,
            self.api.container_flush,
            self.account,
            self.container,
        )

    def test_container_flush_not_found_2(self):
        self.api.object_list = Mock(return_value={"objects": [{"name": "test"}]})
        self.api.object_delete_many = Mock(
            side_effect=exceptions.NotFound("No container")
        )
        self.assertRaises(
            exceptions.NoSuchContainer,
            self.api.container_flush,
            self.account,
            self.container,
        )

    def test_container_flush_empty(self):
        self.api.object_list = Mock(return_value={"objects": []})
        self.api.container_flush(self.account, self.container)
