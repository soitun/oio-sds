# Copyright (C) 2024 OVH SAS
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

import json
import tempfile
from oio.common.easy_value import true_value
from oio.common.kafka import DEFAULT_REPLICATION_TOPIC
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import random_str


class ReplicationRecoveryTest(CliTestCase):
    """Functional tests for replication recovery."""

    def setUp(self):
        super(ReplicationRecoveryTest, self).setUp()
        self.wait_for_score(("rawx", "meta2"), score_threshold=1, timeout=5.0)

    def _test_recovery_tool(self, is_deletion=False):
        account = self.account_from_env()
        obj = "test-repli-recovery" + random_str(6)
        container_src = "container" + random_str(6) + "-src"
        container_dst = "container" + random_str(6) + "-dst"
        self.bucket_client.bucket_create(container_src, account)
        self.openio(f"container create {container_src} --bucket-name {container_src}")
        self.openio(f"container set --versioning -1 {container_src}")
        self.clean_later(container_src, account)
        # Add replication conf to the source
        repli_conf = {
            "role": "arn:aws:iam::repliRecoveryRole:role/repliRecoveryId",
            "rules": {
                "ReplicationRule-1": {
                    "ID": "ReplicationRule-1",
                    "Priority": 1,
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {},
                    "Destination": {"Bucket": f"arn:aws:s3:::{container_dst}"},
                }
            },
            "replications": {f"arn:aws:s3:::{container_dst}": ["ReplicationRule-1"]},
            "deletions": {f"arn:aws:s3:::{container_dst}": ["ReplicationRule-1"]},
            "use_tags": False,
        }
        props = {"X-Container-Sysmeta-S3Api-Replication": json.dumps(repli_conf)}
        self.storage.container_set_properties(account, container_src, properties=props)
        reqid = request_id()
        # Create an object
        self.storage.object_create_ext(
            account,
            container_src,
            obj_name=obj,
            data=b"Something",
            reqid=reqid,
            replication_destinations=container_dst,
            replication_replicator_id="repliRecoveryId",
            replication_role_project_id="repliRecoveryRole",
            properties={
                "x-object-sysmeta-s3api-acl": "myuseracls",
                "x-object-sysmeta-s3api-replication-status": "PENDING",
            },
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_NEW,),
        )
        self.assertIsNotNone(event)
        self.assertEqual(container_dst, event.repli["destinations"])
        self.assertEqual("repliRecoveryId", event.repli["replicator_id"])
        self.assertEqual("repliRecoveryRole", event.repli["src_project_id"])
        if is_deletion:
            reqid = request_id()
            self.storage.object_delete(
                account,
                container_src,
                obj=obj,
                reqid=reqid,
                replication_destinations=container_dst,
                replication_replicator_id="repliRecoveryId",
                replication_role_project_id="repliRecoveryRole",
                properties={
                    "x-object-sysmeta-s3api-replication-status": "PENDING",
                },
            )
            event = self.wait_for_kafka_event(
                reqid=reqid,
                types=(EventTypes.CONTENT_NEW,),
            )
            self.assertIsNotNone(event)
            for d in event.data:
                deleted = d.get("deleted")
                if deleted is not None:
                    if is_deletion:
                        self.assertTrue(true_value(deleted))
                    else:
                        self.assertFalse(true_value(deleted))
                    break
        # Write replication recovery tool configuration file
        with tempfile.NamedTemporaryFile() as f:
            conf_content = f"""
[replication-recovery]
namespace = {self._cls_conf["namespace"]}
log_facility = LOG_LOCAL0
log_level = INFO
log_address = /dev/log
syslog_prefix = OIO,OPENIO,replication-recovery,1
# kafka endpoints
broker_endpoint = {self._cls_conf["kafka_endpoints"]}
"""
            f.write(conf_content.encode())
            f.flush()
            self.openio(
                f"replication recovery {f.name} {container_src} --pending", coverage=""
            )

        event = self.wait_for_kafka_event(
            types=(EventTypes.CONTENT_NEW,),
            fields={
                "account": account,
                "user": container_src,
            },
            topics=[DEFAULT_REPLICATION_TOPIC],
            timeout=60,
            origin="s3-replication-recovery",
        )
        self.assertIsNotNone(event)
        self.assertEqual(container_dst, event.repli["destinations"])
        self.assertEqual("repliRecoveryId", event.repli["replicator_id"])
        self.assertEqual("repliRecoveryRole", event.repli["src_project_id"])
        self.assertIsNotNone(event)
        found = False
        for d in event.data:
            deleted = d.get("deleted")
            if deleted is not None:
                if is_deletion:
                    self.assertTrue(true_value(deleted))
                    break
                else:
                    self.assertFalse(true_value(deleted))
            key = d.get("key")
            if key and key == "x-object-sysmeta-s3api-acl":
                self.assertEqual("myuseracls", d["value"])
                found = True
                break
        if not is_deletion:
            self.assertTrue(found)

    def test_replication_recovery_content_new(self):
        self._test_recovery_tool()

    def test_replication_recovery_content_delete(self):
        self._test_recovery_tool(is_deletion=True)
