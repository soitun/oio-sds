# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2026 OVH SAS
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

import time

from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import random_str


class ServiceListTest(CliTestCase):
    def _meta2_list_containers(self, meta2, account):
        opts = self.get_format_opts()
        output = self.openio_admin(
            "meta2 list containers %s %s --oio-account %s" % (meta2, opts, account)
        )
        return output.split("\n")

    def test_meta2_list_containers(self):
        container = "meta2_list_containers_" + random_str(3)
        reqid = request_id("mlc")
        self.storage.container_create(self.account, container, reqid=reqid)
        output = self.storage.directory.list(self.account, container)
        meta2s = []
        for srv in output["srv"]:
            if srv["type"] == "meta2":
                meta2s.append(srv["host"])

        event = self.wait_for_kafka_event(
            reqid=reqid,
            timeout=5.0,
            types=(EventTypes.CONTAINER_NEW,),
        )
        self.assertIsNotNone(event)

        # The rdir index is updated asynchronously. Poll until the index is up to date.
        fullname = self.account + "/" + container
        deadline = time.time() + 10.0
        for meta2 in meta2s:
            while fullname not in self._meta2_list_containers(meta2, self.account):
                self.assertLess(
                    time.time(),
                    deadline,
                    f"{fullname} not found in rdir for {meta2}",
                )
                time.sleep(0.5)

        reqid = request_id("mlc")
        output = self.storage.container_delete(self.account, container, reqid=reqid)
        event = self.wait_for_kafka_event(
            reqid=reqid,
            timeout=5.0,
            types=(EventTypes.CONTAINER_DELETED,),
        )
        self.assertIsNotNone(event)

        deadline = time.time() + 10.0
        for meta2 in meta2s:
            while fullname in self._meta2_list_containers(meta2, self.account):
                self.assertLess(
                    time.time(),
                    deadline,
                    f"{fullname} still in rdir for {meta2} after deletion",
                )
                time.sleep(0.5)

    def test_rawx_list_containers(self):
        container = "rawx_list_containers_" + random_str(3)
        obj = random_str(6)
        reqid = request_id("rlc")
        self.storage.object_create(
            self.account, container, data="test data", obj_name=obj, reqid=reqid
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            timeout=5.0,
            types=(EventTypes.CHUNK_NEW,),
        )
        self.assertIsNotNone(event)

        output = self.storage.object_locate(self.account, container, obj)
        opts = self.get_format_opts(fields=["Name"])
        fullname = "/".join((self.account, container))
        rawx_list = [x["url"][7:-65] for x in output[1]]
        for rawx in rawx_list:
            output = self.openio_admin("rawx list containers %s %s" % (rawx, opts))
            self.assertIn(fullname, output.split("\n"))

        reqid = request_id("rlc")
        self.storage.object_delete(self.account, container, obj, reqid=reqid)
        event = self.wait_for_kafka_event(
            reqid=reqid,
            timeout=15.0,
            types=(EventTypes.CHUNK_DELETED,),
        )
        self.assertIsNotNone(event)
        for rawx in rawx_list:
            output = self.openio_admin("rawx list containers %s %s" % (rawx, opts))
            self.assertNotIn(fullname, output.split("\n"))
