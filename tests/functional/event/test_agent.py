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

import tempfile
import time
from multiprocessing import Queue

from oio.common.configuration import load_namespace_conf
from oio.common.easy_value import int_value
from oio.common.kafka import DEFAULT_ENDPOINT, DEFAULT_TOPIC
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.event.kafka_agent import KafkaEventWorker
from oio.event.kafka_consumer import KafkaConsumerPool
from tests.utils import BaseTestCase


class TestEventAgentDelete(BaseTestCase):
    CONF = {
        "topic": "oio-delete-127.0.0.1-even",
        "group_id": "event-agent-delete",
        "event_queue_type": "per_service",
        "rdir_connection_timeout": 0.5,
        "rdir_read_timeout": 5.0,
        "log_facility": "LOG_LOCAL0",
        "log_level": "INFO",
        "log_address": "/dev/log",
    }
    handlers_conf = """

[handler:storage.content.deleted]
pipeline = content_cleaner preserve

[handler:storage.content.drained]
pipeline = content_cleaner preserve

[filter:content_cleaner]
use = egg:oio#content_cleaner

# These values are changed only for testing purposes.
# The default values are good for most use cases.
concurrency = 4
pool_connections = 16
pool_maxsize = 16
timeout = 4.5

[filter:log]
use = egg:oio#logger
log_format=topic:%(topic)s    event:%(event)s

[filter:preserve]
# Preserve all events in the oio-preserved topic. This filter is intended
# to be placed at the end of each pipeline, to allow tests to check an
# event has been handled properly.
use = egg:oio#notify
topic = oio-preserved
broker_endpoint = {endpoint}
"""

    def setUp(self):
        super(TestEventAgentDelete, self).setUp()
        self.test_conf = self.CONF.copy()
        namespace = self.conf["namespace"]
        namespace_lower = namespace.lower()
        ns_conf = load_namespace_conf(namespace)
        nb_rawx = len(self.conf["services"]["rawx"])
        event_queue_ids = ";".join(
            f"{namespace_lower}-rawx-{i}" for i in range(1, 1 + nb_rawx)
        )
        # Update event agent conf values
        self.test_conf.update(
            {
                "namespace": namespace,
                "event_queue_ids": event_queue_ids,
                "workers": nb_rawx,
                "concurrency": nb_rawx + 2,
            }
        )
        # Configuration from dedicated file
        self.workers = int_value(self.test_conf.get("workers"), 1)

        # Configuration either from dedicated file or central file (in that order)
        self.endpoint = self.test_conf.get(
            "broker_endpoint", ns_conf.get("event-agent", DEFAULT_ENDPOINT)
        )
        self.topic = self.test_conf.get(
            "topic", ns_conf.get("events.kafka.topic", DEFAULT_TOPIC)
        )
        self.group_id = self.test_conf.get(
            "group_id", ns_conf.get("events.kafka.group_id", "event-agent")
        )
        self.created_objects = []

    def tearDown(self):
        super().tearDown()
        self._service("oio-rawx.target", "start", wait=3)
        self._service("oio-event-agent-delete.target", "start", wait=3)

    def create_objects(self, cname, n_obj=10, reqid=None):
        self.clean_later(cname)
        for i in range(n_obj):
            name = f"event-agent-object-test-{i:0>5}"
            self.storage.object_create(
                self.account,
                cname,
                obj_name=name,
                data=b"yes",
                policy="THREECOPIES",
                reqid=reqid,
            )
            self.created_objects.append(name)
        for i in range(n_obj * 3):
            _event = self.wait_for_kafka_event(
                reqid=reqid,
                types=(EventTypes.CHUNK_NEW,),
                timeout=10.0,
            )
            self.assertIsNotNone(_event, f"Received events {i}/{n_obj}")

    def test_event_agent_delete_producer_usage(self):
        """Check that producers connection errors
        from delete event agent are avoided.
        """
        cname = f"event-agent-delete-{time.time()}"
        create_reqid = request_id("event-agent-delete-chunk-")
        self.create_objects(cname, 10, reqid=create_reqid)
        # Stop treating chunks delete events
        self.logger.debug("Stopping the event system responsible for delete events")
        self._service("oio-event-agent-delete.target", "stop", wait=5)
        # Stop rawx services
        self._service("oio-rawx.target", "stop", wait=5)
        # Delete objects created
        for obj in self.created_objects:
            self.storage.object_delete(self.account, cname, obj=obj)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf") as temp:
            temp.write(self.handlers_conf.format(endpoint=self.endpoint))
            temp.flush()
            self.test_conf["handlers_conf"] = temp.name
            self.pool = KafkaConsumerPool(
                self.test_conf,
                self.endpoint,
                self.topic,
                worker_class=KafkaEventWorker,
                group_id=self.group_id,
                logger=self.logger,
                processes=self.workers,
            )
            errors = Queue()

            def start_worker(worker_id):
                self.pool._workers[worker_id] = self.pool.worker_class(
                    self.pool.topic,
                    self.pool.logger,
                    self.pool._events_queue,
                    self.pool._offsets_queue,
                    worker_id,
                    *self.pool.worker_args,
                    app_conf=self.pool.conf,
                    **self.pool.worker_kwargs,
                )

                def error():
                    errors.put(worker_id)
                    return SystemError("Broker does not respond")

                self.pool._workers[worker_id]._connect_producer = error
                self.pool.logger.info(
                    "Spawning worker %s %d",
                    self.pool.worker_class.__name__,
                    worker_id,
                )
                self.pool._workers[worker_id].start()

            def run_for_180_s():
                "Run workers for 180s"
                nb_processes = self.pool.processes + 1
                worker_factories = {"feeder": self.pool._start_feeder}

                self.pool._workers = {w: None for w in range(nb_processes)}
                self.pool._workers["feeder"] = None
                counter = 0
                max_time = 180
                while counter < max_time:
                    for worker_id, instance in self.pool._workers.items():
                        if instance is None or not instance.is_alive():
                            if instance:
                                self.pool.logger.info(
                                    "Joining dead worker %s", worker_id
                                )
                                instance.join()
                            factory = worker_factories.get(worker_id, start_worker)
                            factory(worker_id)
                    time.sleep(1)
                    counter += 1
                for worker_id, worker in self.pool._workers.items():
                    self.pool.logger.info("Stopping worker %s", worker_id)
                    worker.stop()
                for worker in self.pool._workers.values():
                    worker.join()
                self.pool.logger.info("All workers stopped")

            # Start a kafka consumer pool on oio-delete topic
            self.pool.run = run_for_180_s
            self.pool.run()
            # No errors should be in the queue as producer
            # error are not expected from the worker
            self.assertTrue(errors.empty())
