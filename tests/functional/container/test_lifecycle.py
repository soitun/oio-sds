# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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
import random
import time
from datetime import datetime, timedelta, timezone

from oio.common.client import ProxyClient
from oio.common.kafka import DEFAULT_ENDPOINT, DEFAULT_LIFECYCLE_TOPIC, KafkaConsumer
from oio.common.utils import cid_from_name, request_id
from oio.container.lifecycle import (
    LIFECYCLE_PROPERTY_KEY,
    TAGGING_KEY,
    ContainerLifecycle,
)
from oio.directory.admin import AdminClient
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import BaseTestCase, random_str

DEFAULT_GROUP_ID_TEST = "event-agent-test"


class Helper(object):
    def __init__(self, api, account, container):
        self.api = api
        self.account = account
        self.container = container

    def enable_versioning(self):
        self.api.container_set_properties(
            self.account, self.container, system={"sys.m2.policy.version": "-1"}
        )
        self.api.container_set_properties(
            self.account, self.container, system={"sys.policy.version": "-1"}
        )


class BaseClassLifeCycle(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(BaseTestCase, cls).setUpClass()
        group_id = f"{DEFAULT_GROUP_ID_TEST}-{random_str(8)}"
        cls._cls_kafka_consumer = KafkaConsumer(
            DEFAULT_ENDPOINT,
            [DEFAULT_LIFECYCLE_TOPIC],
            group_id,
            logger=cls._cls_logger,
            app_conf=cls._cls_conf,
            kafka_conf={
                "enable.auto.commit": True,
                "auto.offset.reset": "latest",
            },
        )

    def setUp(self):
        super(BaseClassLifeCycle, self).setUp()
        self.api = self.storage
        self.account = "test_lifecycle"
        self.container = "lifecycle-" + random_str(4)
        self.api.container_create(self.account, self.container)
        self.clean_later(self.container)
        self.lifecycle = ContainerLifecycle(self.api, self.account, self.container)
        self.helper = Helper(self.api, self.account, self.container)

    def tearDown(self):
        super(BaseClassLifeCycle, self).tearDown()

    def _upload_something(
        self, prefix="", random_length=4, data=None, name=None, size=None, **kwargs
    ):
        name = name or (prefix + random_str(random_length))
        data = data or (random_str(8))
        self.api.object_create(
            self.account, self.container, obj_name=name, data=data, **kwargs
        )
        obj_meta = self.api.object_show(self.account, self.container, name)
        obj_meta["container"] = self.container
        if size is not None:
            obj_meta["size"] = size
        return obj_meta


class TestContainerLifecycle(BaseClassLifeCycle):
    @staticmethod
    def _time_to_date(timestamp=None):
        if timestamp is None:
            timestamp = time.time()
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp))

    def _enable_versioning(self):
        if not self.api.container_create(
            self.account, self.container, system={"sys.m2.policy.version": "-1"}
        ):
            self.api.container_set_properties(
                self.account, self.container, system={"sys.policy.version": "-1"}
            )

    def test_load_from_container_property(self):
        source = """{"Rules":
            {"id1":{
                "Status":"Enabled","Expiration":{"Days":11},
                "Filter":{"Prefix":"test","ObjectSizeGreaterThan":101}
                }
            }
        }"""
        props = {LIFECYCLE_PROPERTY_KEY: source}
        self.api.container_set_properties(
            self.account, self.container, properties=props
        )
        self.lifecycle.load()

    def test_save_to_container_property(self):
        source = """{"Rules":
            {"id1":{
                "Status":"Enabled","Expiration":{"Days":11},
                "Filter":{"Prefix":"test","ObjectSizeGreaterThan":101}
                }
            }
        }"""

        self.lifecycle.load_json(source)
        self.lifecycle.save()
        json_conf = self.lifecycle.get_configuration()
        self.assertEqual(
            source.replace(" ", "").replace("\n", ""),
            json_conf.replace(" ", "").replace("\n", ""),
        )


class TestLifecycleConform(CliTestCase, BaseClassLifeCycle):
    def setUp(self):
        super(TestLifecycleConform, self).setUp()
        self.batch_size = 2
        self.to_match = {}
        self.not_to_match = {}
        self.to_match_markers = {}
        self.lifecycle = ContainerLifecycle(self.api, self.account, self.container)
        self.proxy_client = ProxyClient(
            self.conf, pool_manager=self.api.container.pool_manager, logger=self.logger
        )
        admin_args = {}
        admin_args["force_master"] = False
        self.admin_client = AdminClient(self.conf, logger=self.logger, **admin_args)
        self.helper = Helper(self.api, self.account, self.container)
        self.prefix = "doc"
        self.data_short = "test"
        self.data_middle = "test some data"
        self.data_long = "some long data oustide max conditions"

        self.action = "Expiration"
        self.action_config = {"Expiration": {"Days": 11}}

        self.versioning_enabled = False
        self.number_of_versions = 1
        self.expected_to_cycle = {}

        self.conditions = {
            "prefix": self.prefix,
            "greater": 10,
            "lesser": 20,
            "tag1": {"key1": "value1"},
            "tag2": {"key2": "value2"},
            "tag3": {"key3": "value1"},
        }
        self.number_match = random.randint(2, 3)
        self.number_not_match = random.randint(2, 3)

        self.not_match_tag_set = """
            <Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <TagSet><Tag><Key>excluded-key</Key><Value>value1</Value></Tag>
            </Tagset></Tagging>"""

        # dict to store rules and actions
        self.rules = {}

    def tearDown(self):
        super(TestLifecycleConform, self).tearDown()

    def _init_match_rules(self):
        for rule, actions in self.rules.items():
            self.to_match[rule] = {}
            self.not_to_match[rule] = {}
            self.to_match_markers[rule] = {}
            for action in actions:
                self.to_match[rule][action] = []
                self.not_to_match[rule][action] = []
                self.to_match_markers[rule][action] = []

    def _copy_db(self):
        self.cid = cid_from_name(self.account, self.container)

        status = self.admin_client.election_status(
            "meta2", account=self.account, reference=self.container
        )
        slaves = status.get("slaves", [])
        if slaves:
            self.peer_to_use = slaves[0]
        else:
            self.peer_to_use = status.get("master", [])

        params = {"type": "meta2", "cid": self.cid, "suffix": "lifecycle"}
        json_peers = {"from": self.peer_to_use, "to": self.peer_to_use, "local": 1}

        resp, body = self.proxy_client._request(
            "POST", "/admin/copy", params=params, json=json_peers
        )
        self.assertEqual(resp.status, 204)

    def _check_and_apply(self, source, nothing_to_match=False):
        if not nothing_to_match:
            self.assertIsNot(len(self.to_match), 0)
        self._copy_db()
        time.sleep(1)
        self._exec_rules_via_sql_query(source)

    def _check_event(self, elements_to_match, event):
        elem_to_remove = None
        found = False
        for elem in elements_to_match:
            version = int(elem["version"])
            if (
                elem["name"] == event.data["object"]
                and version == event.data["version"]
                and int(elem["mtime"]) == event.data["mtime"]
            ):
                found = True
                elem_to_remove = elem
                break

        return [found, elem_to_remove]

    def _get_action_parameters(self, act_type, act):
        days = None
        date = None
        delete_marker = None
        if act_type == "Expiration":
            days = act.get("Days")
            date = act.get("Date")
            delete_marker = act.get("ExpiredObjectDeleteMarker")
        elif act_type == "Transitions":
            days = act.get("Days")
            date = act.get("Date")
        return [days, date, delete_marker]

    def _check_query_events(
        self,
        queries,
        action,
        action_type,
        view_queries,
        newer_non_current_versions,
        policy,
        last_rule_action,
        rule_id,
    ):
        for key_query, val_query in queries.items():
            offset = 0
            while True:
                sql_query = val_query
                if action in (
                    "NoncurrentVersionExpiration",
                    "NoncurrentVersionTransitions",
                ):
                    sql_query = f"{sql_query} limit 100" f" offset {offset} "
                else:
                    sql_query = (
                        f"{sql_query} limit {self.batch_size} " f" offset {offset} "
                    )

                kwargs = {}
                params = {"cid": self.cid, "service_id": self.peer_to_use}
                data = {}
                data["action"] = action
                data["suffix"] = "lifecycle"
                if offset == 0 and (key_query == "base" or key_query == "marker"):
                    create_views_data = {}
                    create_views_data["suffix"] = "lifecycle"
                    for key, val in view_queries.items():
                        create_views_data[key] = val
                    resp, body = self.proxy_client._request(
                        "POST",
                        "/container/lifecycle/views/create",
                        params=params,
                        json=create_views_data,
                        **kwargs,
                    )
                    self.assertEqual(resp.status, 204)

                if key_query == "marker":
                    data["is_markers"] = 1
                data["query"] = sql_query
                data["query_set_tag"] = val_query
                data["policy"] = policy
                data["batch_size"] = self.batch_size
                data["rule_id"] = rule_id
                if last_rule_action:
                    # Don't use last_action , delete of copy will be managed by crawlers
                    # data["last_action"] = 1
                    pass

                reqid = request_id()
                if action in (
                    "NoncurrentVersionExpiration",
                    "NoncurrentVersionTransitions",
                ):
                    params["action_type"] = "noncurrent"
                else:
                    params["action_type"] = "current"

                resp, body = self.proxy_client._request(
                    "POST",
                    "/container/lifecycle/apply",
                    params=params,
                    reqid=reqid,
                    json=data,
                    **kwargs,
                )

                self.assertEqual(resp.status, 204)
                count = int(resp.getheader("x-oio-count", 0))
                offset += count
                count_events = 0
                if action in ("Expiration", "Transition"):
                    exptected_events = (
                        count * self.expected_to_cycle[rule_id][action_type]
                    )
                else:
                    exptected_events = self.expected_to_cycle[rule_id][action_type]

                while count_events < exptected_events:
                    event = self.wait_for_kafka_event(
                        types=(EventTypes.LIFECYCLE_ACTION,)
                    )
                    self.assertIsNotNone(event)
                    self.assertEqual(event.event_type, "storage.lifecycle.action")
                    self.assertEqual(event.data["account"], self.account)
                    self.assertEqual(event.data["container"], self.container)

                    elements_to_match = ()

                    if (
                        key_query == "marker"
                        or len(self.to_match_markers[rule_id][action_type]) > 0
                    ):
                        elements_to_match = self.to_match_markers[rule_id][action_type]
                    else:
                        elements_to_match = self.to_match[rule_id][action_type]

                    [found, elem_to_remove] = self._check_event(
                        elements_to_match, event
                    )
                    if not found:
                        # For debug
                        print("elements_to_match:", elements_to_match)
                        print("event.data:", event.data)
                    self.assertEqual(found, True)
                    list_of_bool = [
                        True
                        for elem in self.not_to_match[rule_id][action_type]
                        if event.data["object"]
                        and event.data["version"] in elem.values()
                    ]
                    self.assertEqual(any(list_of_bool), False)
                    elements_to_match.remove(elem_to_remove)

                    self.assertEqual(event.data["action"], action)
                    count_events += 1

                if count == 0:
                    break

    def _is_last_action_last_rule(self, rules, actions, count_rules, count_actions):
        if (count_rules == len(rules) - 1) and (count_actions == len(actions) - 1):
            return True
        else:
            return False

    def _get_actions(self, rule):
        actions = {}
        expiration = rule.get("Expiration", None)
        transitions = rule.get("Transitions", [])
        noncureent_expiration = rule.get("NoncurrentVersionExpiration", None)
        noncurrent_transitions = rule.get("NoncurrentVersionTranstitions", [])
        if expiration is not None:
            actions["Expiration"] = [expiration]
        if len(transitions) > 0:
            actions["Transitions"] = transitions
        if noncureent_expiration is not None:
            actions["NoncurrentVersionExpiration"] = [noncureent_expiration]
        if len(noncurrent_transitions) > 0:
            actions["NoncurrentVersionTranstitions"] = noncurrent_transitions

        return actions

    def _exec_rules_via_sql_query(self, source):
        lc = ContainerLifecycle(self.api, self.account, self.container)
        lc.load_json(source)
        lc.save()
        json_dict = json.loads(source)

        count_rules = 0
        count_actions = 0
        for rule_id, rule in json_dict["Rules"].items():
            rule["ID"] = rule_id
            actions = self._get_actions(rule)
            for act_type, act_list in actions.items():
                for act in act_list:
                    days_in_sec = None
                    base_sql_query = None
                    non_current = False
                    newer_non_current_versions = 0
                    non_current_days = 0
                    policy = ""
                    queries = {}
                    view_queries = {}
                    action = ""
                    days = None
                    date = None
                    delete_marker = None
                    if act_type == "NoncurrentVersionExpiration":
                        newer_non_current_versions = act.get(
                            "NewerNoncurrentVersions", 0
                        )
                        non_current_days = act["NoncurrentDays"]
                        non_current = True
                        action = "NoncurrentVersionExpiration"
                    elif act_type == "NoncurrentVersionTransitions":
                        newer_non_current_versions = act.get(
                            "NewerNoncurrentVersions", 0
                        )
                        non_current_days = act["NoncurrentDays"]
                        policy = act["StorageClass"]
                        non_current = True
                        action = "NoncurrentVersionTransition"
                    elif act_type == "Expiration":
                        action = "Expiration"
                    elif act_type == "Transitions":
                        policy = act["StorageClass"]
                        action = "Transition"
                    else:
                        print("Unsupported action type", act_type)
                        return

                    days, date, delete_marker = self._get_action_parameters(
                        act_type, act
                    )
                    # TODO(check if versioning is enabled on client side)
                    # Versioning and NoncurrentVersions
                    # For tests(non_current_days_in_sec set to 0)
                    # non_current_days_in_sec = 86400 * non_current_days
                    non_current_days_in_sec = 0 * non_current_days

                    if self.versioning_enabled:
                        if non_current:
                            non_current_days_in_sec = non_current_days_in_sec
                            noncurrent_view = lc.create_noncurrent_view(
                                rule, non_current_days_in_sec
                            )
                            current_view = lc.create_common_views(
                                "current_view", rule, non_current_days_in_sec
                            )

                            view_queries["noncurrent_view"] = noncurrent_view
                            view_queries["current_view"] = current_view
                            queries["base"] = lc.noncurrent_query(
                                newer_non_current_versions
                            )
                        # versioning for Expiration/Transition
                        else:
                            delete_marker_view = lc.create_common_views(
                                "marker_view",
                                rule,
                                deleted=True,
                            )
                            vesioned_view = lc.create_common_views(
                                "versioned_view",
                                rule,
                                non_current_days_in_sec,
                                deleted=None,
                            )

                            noncurrent_view = lc.create_noncurrent_view(
                                rule, non_current_days_in_sec
                            )

                            view_queries["marker_view"] = delete_marker_view
                            view_queries["versioned_view"] = vesioned_view
                            view_queries["noncurrent_view"] = noncurrent_view

                            if delete_marker:
                                queries["marker"] = lc.markers_query()
                            if delete_marker is None:
                                queries["base"] = lc.build_sql_query(
                                    rule, non_current_days_in_sec, None, False, True
                                )
                                # queries["marker"] = el.filter.markers_query()

                    else:  # non versioned
                        if days is not None:
                            days_in_sec = 0 * days
                        base_sql_query = lc.build_sql_query(rule, days_in_sec, date)
                        queries["base"] = base_sql_query

                    last_rule_action = 0
                    self._check_query_events(
                        queries,
                        action,
                        act_type,
                        view_queries,
                        newer_non_current_versions,
                        policy,
                        last_rule_action,
                        rule_id,
                    )
                    count_actions += 1
                    self.assertEqual(len(self.to_match[rule_id][act_type]), 0)
                    self.assertEqual(len(self.to_match_markers[rule_id][act_type]), 0)

            count_rules += 1


class TestLifecycleConformExpiration(TestLifecycleConform):
    def setUp(self):
        super(TestLifecycleConformExpiration, self).setUp()
        self.action = "Expiration"
        self.rule_id = "rule-expiration"

        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []
        self._init_match_rules()

        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}
        self.expected_to_cycle[self.rule_id][self.action] = 1

    def tearDown(self):
        super(TestLifecycleConformExpiration, self).tearDown()

    def test_apply_prefix(self):
        source = (
            """
            {"Rules":
                {"""
            f'"{self.rule_id}":'
            """
                    {
                    "Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{"Prefix":"a"}
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/")
            self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/")
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_apply_tag(self):
        # ["tag1"]
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        source = (
            """
            {"Rules":
                { """
            f'"{self.rule_id}":'
            """  {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        { "Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_apply_prefix_and_greater(self):
        data_short = "some data"
        data_long = "some data and more"
        middle = (len(data_short) + len(data_long)) // 2

        source = (
            """
            {"Rules": {
                """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"a", "ObjectSizeGreaterThan":"""
            f"{middle}"
            """}
                    }
                }
            }"""
        )
        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )

        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_long)
            self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_short)
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_short)
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_long)
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source)

    def test_apply_prefix_and_lesser(self):
        data_short = "some data"
        data_long = "some data and more"
        middle = (len(data_short) + len(data_long)) // 2

        source = (
            """
            {"Rules": {
                """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{
                        "Prefix":"a/", "ObjectSizeLessThan":"""
            f"{middle}"
            """          }
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_long)
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_match):
            obj_meta = self._upload_something(prefix="a/", data=data_short)
            self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_short)
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(prefix="b/", data=data_long)
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def _upload_expected_combine1(self):
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

    def test_combine1(self):
        # ["prefix', 'greater"]

        val = self.conditions["prefix"]
        greater = self.conditions["greater"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{
                        "Prefix":"""
            f'"{val}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """         }
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        self._upload_expected_combine1()

        self._check_and_apply(source)

    def test_combine2(self):
        # ["prefix", "lesser"]

        prefix = self.conditions["prefix"]
        lesser = self.conditions["lesser"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "ObjectSizeLessThan":"""
            f"{lesser}"
            """}
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = prefix + str(j) + "2" + random_str(5)
            obj_meta = self._upload_something(
                name=name, data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine3(self):
        # ["prefix", "tag1"]
        prefix = self.conditions["prefix"]
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine4(self):
        # [prefix, tag1, tag2]
        val = self.conditions["prefix"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{val}"'
            """, "Tags":
                            ["""
            f"{json.dumps(self.conditions['tag1'])}"
            ""","""
            f"{json.dumps(self.conditions['tag2'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine5(self):
        # ["prefix", "tag1", "tag2", "tag3"]

        prefix = self.conditions["prefix"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "Tags":
                            ["""
            f"{json.dumps(self.conditions['tag1'])}"
            ""","""
            f"{json.dumps(self.conditions['tag2'])}"
            ""","""
            f"{json.dumps(self.conditions['tag3'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "j" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    prefix=self.prefix,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine6(self):
        # ["prefix", "tag2", "tag3"]

        prefix = self.conditions["prefix"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            ""","""
            f"{json.dumps(self.conditions['tag3'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source)

    def test_combine7(self):
        # ["prefix", "greater", "lesser", "tag1"])
        prefix = self.conditions["prefix"]
        greater = self.conditions["greater"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}",'
            """"ObjectSizeLessThan":"""
            f"{lesser},"
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source)

    def test_combine8(self):
        # ["greater', 'lesser"]
        greater = self.conditions["greater"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeLessThan":"""
            f"{lesser},"
            """"ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source)

    def test_combine9(self):
        # ["greater", "lesser", "tag1"])
        greater = self.conditions["greater"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeLessThan":"""
            f"{lesser},"
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_middle, random_length=4
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine10(self):
        # ["greater", "tag2"]
        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine11(self):
        # ["greater", "tag1", "tag2"]
        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine12(self):
        # ["greater", "tag1", "tag2", "tag3"]
        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine13(self):
        # ["greater", "tag2"', "tag3"]
        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]
                        }
                    }
                }
            }"""
        )
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine14(self):
        # ["lesser", "tag1"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeLessThan":"""
            f"{lesser},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "2" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine15(self):
        # ["lesser", "tag1", "tag2"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeLessThan":"""
            f"{lesser},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "2" + random_str(5)
            obj_meta = self._upload_something(
                name=name,
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "3" + random_str(5)
            obj_meta = self._upload_something(
                name=name,
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine16(self):
        # ["lesser", "tag1", "tag2", "tag3"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeLessThan":"""
            f"{lesser},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine17(self):
        # ["lesser", "tag2", "tag3"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"ObjectSizeLessThan":"""
            f"{lesser},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]}
                    }
                }
            }"""
        )
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(7),
                data=self.data_middle,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_combine18(self):
        # ["tag1", "tag2"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.assertIsNot(len(self.to_match), 0)

        self._check_and_apply(source)

    def test_combine19(self):
        # ["tag1", "tag2", "tag3"])
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            f",{json.dumps(self.conditions['tag2'])}"
            f",{json.dumps(self.conditions['tag3'])}"
            """]}
                    }
                }
            }"""
        )
        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        key = list(self.conditions["tag3"].keys())[0]
        val = self.conditions["tag3"][key]

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=6,
                properties={TAGGING_KEY: self.not_match_tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)


class TestLifecycleConformTransition(TestLifecycleConformExpiration):
    def setUp(self):
        super(TestLifecycleConformTransition, self).setUp()
        self.action = "Transitions"
        self.rule_id = "rule-transitions"
        self.action_config = {
            "Transitions": [{"Days": 11, "StorageClass": "STANDARD_IA"}]
        }

        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []

        self._init_match_rules()
        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}
        self.expected_to_cycle[self.rule_id][self.action] = 1

    def tearDown(self):
        super(TestLifecycleConformTransition, self).tearDown()


class TestLifecycleConformExpirationDate(TestLifecycleConformExpiration):
    def setUp(self):
        super(TestLifecycleConformExpirationDate, self).setUp()
        self.action = "Expiration"
        self.rule_id = "rule-expiration-date"

        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []
        self._init_match_rules()

        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}
        self.expected_to_cycle[self.rule_id][self.action] = 1

        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        self.action_config = {"Expiration": {"Date": f"{now_str}"}}

    def tearDown(self):
        super(TestLifecycleConformExpirationDate, self).tearDown()

    def test_non_expired_object(self):
        # ["prefix", "tag1"], but date is not reached
        now = datetime.now()
        next_time = now + timedelta(days=1)
        next_day = next_time.strftime("%Y-%m-%dT%H:%M:%S.%f %z")[:-3]
        self.action_config = {"Expiration": {"Date": f"{next_day}"}}

        prefix = self.conditions["prefix"]
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )

                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source, nothing_to_match=True)


class TestLifecycleConformExpirationVersioning(TestLifecycleConformExpiration):
    def setUp(self):
        super(TestLifecycleConformExpirationVersioning, self).setUp()
        self.versioning_enabled = True
        self.number_of_versions = 3

        self.rule_id = "rule-expiration-versioning"

        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []
        self._init_match_rules()

        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}
        self.expected_to_cycle[self.rule_id][self.action] = 1

    # Current version is delete marker but there are other versions
    # No action to do
    def test_delete_marker_1(self):
        # ['greater', 'tag2']

        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        greater = self.conditions["greater"]
        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.api.object_delete(self.account, self.container, obj_meta["name"])

        self._check_and_apply(source, True)

    # Current version is delete marker and is only the version
    # action remove delete marker
    def test_delete_marker_2(self):
        self.number_match = 2
        # ['prefix']

        prefix = self.conditions["prefix"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"prefix":"""
            f'"{prefix}"'
            """
                        }
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="a" + prefix,
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        delete_markers = []
        names = []
        for j in range(self.number_match):
            name = prefix + str(j) + random_str(5)
            names.append(name)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            # insert delete marker
            self.api.object_delete(self.account, self.container, name)

        time.sleep(0.1)
        for el in self.not_to_match[self.rule_id][self.action]:
            self.api.object_delete(
                self.account, self.container, el["name"], el["version"]
            )
        for name in names:
            objects = self.api.object_list(
                self.account, self.container, prefix=name, deleted=True, versions=True
            )
            delete_markers.append(objects["objects"][0])

        self.to_match_markers[self.rule_id][self.action] = delete_markers
        self._check_and_apply(source, nothing_to_match=True)

    # Create some objects where:
    # current version matchs the filter but not the only version => match
    # current version doesn't match but some previous matchs => no match
    # current version is delete marker but not the only version => no match
    # current version doesn' match and there is a delete marker => no match
    # current version is delete maker and the olny version => match
    def test_mix_current_versions_and_markers(self):
        # ['prefix', 'tag1']

        prefix = self.conditions["prefix"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"Prefix":"""
            f'"{prefix}",'
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"

        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = self.prefix + str(j) + "0" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                # Insert delete marker but not the last version for 1 object
                if j == 0 and i == 0:
                    time.sleep(0.01)
                    self.api.object_delete(self.account, self.container, name)
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = self.prefix + str(j) + "1" + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        names = []
        # the last version a delete marker, and not the only version
        for j in range(self.number_match):
            name = self.prefix + str(j) + "2" + random_str(5)
            names.append(name)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )

                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.api.object_delete(self.account, self.container, name)

        self._check_and_apply(source)


class TestLifecycleNonCurrentVersionExpiration(TestLifecycleConform):
    def setUp(self):
        super(TestLifecycleNonCurrentVersionExpiration, self).setUp()
        self.versioning_enabled = True
        self.number_of_versions = 4
        self.newer_non_current_versions = 1
        self.action = "NoncurrentVersionExpiration"

        self.rule_id = "rule-noncurrentexpiration"
        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []
        self._init_match_rules()

        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}

        self.action_config = {
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 1,
                "NewerNoncurrentVersions": self.newer_non_current_versions,
            }
        }

        self.not_to_match_versions = []
        self.expected_to_cycle[self.rule_id][self.action] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )

    def tearDown(self):
        super(TestLifecycleNonCurrentVersionExpiration, self).tearDown()

    def _upload_expected_combine1(self):
        # match only n non current versions per object
        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)
        return total_count_expected

    def test_cycle_versions_combine1(self):
        # ['prefix', 'greater']
        # match only 2 non current versions per object
        prefix = self.conditions["prefix"]
        greater = self.conditions["greater"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                    }
                }
            }"""
        )

        self.expected_to_cycle[self.rule_id][
            self.action
        ] = 2  # 2 version per object (1 object per batch)
        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        self._upload_expected_combine1()
        self._check_and_apply(source)

    def test_cycle_versions_combine2(self):
        # ["prefix", "lesser"]
        # match only 2 non current versions per object
        prefix = self.conditions["prefix"]
        lesser = self.conditions["lesser"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "ObjectSizeLessThan":"""
            f"{lesser}"
            """}
                    }
                }
            }"""
        )
        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        # 2 version per object (1 object per batch)
        self.expected_to_cycle[self.rule_id][self.action] = 2

        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=6
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)
        self._check_and_apply(source)

    def test_cycle_versions_combine3(self):
        # ["prefix", "tag1"]
        prefix = self.conditions["prefix"]
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        self.expected_to_cycle[self.rule_id][self.action] = 2

        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=5,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)
        self._check_and_apply(source)

    def test_cycle_versions_combine4(self):
        # [prefix, tag1, tag2]
        val = self.conditions["prefix"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{val}"'
            """, "Tags":
                            ["""
            f"{json.dumps(self.conditions['tag1'])}"
            ""","""
            f"{json.dumps(self.conditions['tag2'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        self.expected_to_cycle[self.rule_id][self.action] = 2

        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=5,
                    properties={TAGGING_KEY: self.not_match_tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)
        self._check_and_apply(source)

    def test_cycle_versions_combine7(self):
        # ["prefix", "greater", "lesser", "tag1"])

        prefix = self.conditions["prefix"]
        greater = self.conditions["greater"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}",'
            """"ObjectSizeLessThan":"""
            f"{lesser},"
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_not_match):
            name = "not-prefix-" + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_short,
                    random_length=5,
                    properties={TAGGING_KEY: tag_set},
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_middle,
                random_length=4,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix="not-prefix-" + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_middle,
                random_length=4,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=self.prefix + random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source)

    def test_cycle_versions_combine8(self):
        # ["greater', 'lesser"]

        greater = self.conditions["greater"]
        lesser = self.conditions["lesser"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeLessThan":"""
            f"{lesser},"
            """"ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_middle, random_length=4
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)
        self._check_and_apply(source)

    def test_cycle_versions_combine9(self):
        # ["greater", "lesser", "tag1"])

        greater = self.conditions["greater"]
        lesser = self.conditions["lesser"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeLessThan":"""
            f"{lesser},"
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag1'])}"
            """]}
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""
        key = list(self.conditions["tag1"].keys())[0]
        val = self.conditions["tag1"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_middle, random_length=4
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5), data=self.data_short, random_length=5
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6), data=self.data_long, random_length=6
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_middle,
                    random_length=4,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(5),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(6),
                data=self.data_long,
                random_length=6,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_cycle_versions_combine10(self):
        # ["greater", "tag2"]
        greater = self.conditions["greater"]

        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":
                        {"""
            """"ObjectSizeGreaterThan":"""
            f"{greater},"
            """"Tags":["""
            f"{json.dumps(self.conditions['tag2'])}"
            """]
                        }
                    }
                }
            }"""
        )

        tag_set = """<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
             <TagSet>"""

        key = list(self.conditions["tag2"].keys())[0]
        val = self.conditions["tag2"][key]
        tag_set = f"{tag_set}<Tag><Key>{key}</Key><Value>{val}"
        tag_set = f"{tag_set}</Value></Tag>"
        tag_set = f"{tag_set} " """</TagSet></Tagging>"""

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()

        for _ in range(self.number_not_match):
            obj_meta = self._upload_something(
                prefix=random_str(4),
                data=self.data_short,
                random_length=5,
                properties={TAGGING_KEY: tag_set},
            )
            self.not_to_match[self.rule_id][self.action].append(obj_meta)

        for j in range(self.number_match):
            name = str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name,
                    data=self.data_long,
                    random_length=6,
                    properties={TAGGING_KEY: tag_set},
                )
                if i < self.expected_to_cycle[self.rule_id][self.action]:
                    self.to_match[self.rule_id][self.action].append(obj_meta)

        self._check_and_apply(source)

    def test_cycle_zero_newer_non_current(self):
        # ['prefix', 'greater']
        # Total versions per object is 4: one current and 0 newer non current
        # So 3 versions to match
        self.newer_non_current_versions = 0

        self.not_to_match_versions = []

        self.expected_to_cycle[self.rule_id][self.action] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )

        self.action_config = {
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 1,
                "NewerNoncurrentVersions": self.newer_non_current_versions,
            }
        }

        val = self.conditions["prefix"]
        greater = self.conditions["greater"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{
                        "Prefix":"""
            f'"{val}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """         }
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        self._upload_expected_combine1()
        self._check_and_apply(source)

    def test_cycle_several_newer_non_current(self):
        # ['prefix', 'greater']
        # Total versions per object is 4: one current and 3 newer
        # So no version to cycle
        self.newer_non_current_versions = 3
        self.action_config = {
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 1,
                "NewerNoncurrentVersions": self.newer_non_current_versions,
            }
        }

        val = self.conditions["prefix"]
        greater = self.conditions["greater"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{
                        "Prefix":"""
            f'"{val}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """         }
                    }
                }
            }"""
        )

        self.not_to_match_versions = []

        self.expected_to_cycle[self.rule_id][self.action] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )
        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        self._upload_expected_combine1()
        self._check_and_apply(source, nothing_to_match=True)

    def test_cycle_also_several_newer_non_current(self):
        # ['prefix', 'greater']
        # Total versions per object is 4: one current and 4 newer
        # So no version to cycle
        self.newer_non_current_versions = 4

        self.action_config = {
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 1,
                "NewerNoncurrentVersions": self.newer_non_current_versions,
            }
        }

        val = self.conditions["prefix"]
        greater = self.conditions["greater"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{
                        "Prefix":"""
            f'"{val}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """         }
                    }
                }
            }"""
        )

        self.not_to_match_versions = []
        self.expected_to_cycle[self.rule_id][self.action] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        self._upload_expected_combine1()
        self._check_and_apply(source, nothing_to_match=True)


class TestLifecycleConformExpiredDelete(TestLifecycleConform):
    def setUp(self):
        super(TestLifecycleConformExpiredDelete, self).setUp()
        self.versioning_enabled = True
        self.number_of_versions = 3
        self.action = "Expiration"
        self.rule_id = "rule-expiration-deletemarker"
        self.rules[self.rule_id] = {}
        self.rules[self.rule_id][self.action] = []
        self._init_match_rules()

        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule_id] = {}
        self.expected_to_cycle[self.rule_id][self.action] = 1

        self.action_config = {"Expiration": {"ExpiredObjectDeleteMarker": True}}

    def test_expired_delete_marker_true(self):
        """
        Add some versions of object, add delete marker
        remove all previous versions
        The only remaining version is the delete marker
        Check that event is sent to expire delete marker
        """
        # ['prefix']
        prefix = "documents/"
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{
                        "Prefix":"""
            f'"{prefix}"'
            """         }
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        self.number_match = 1
        for j in range(self.number_match):
            name = prefix + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.api.object_delete(self.account, self.container, name)
            for el in self.not_to_match[self.rule_id][self.action]:
                self.api.object_delete(
                    self.account, self.container, el["name"], version=el["version"]
                )

            objects = self.api.object_list(
                self.account, self.container, deleted=True, versions=True
            )
            self.to_match_markers[self.rule_id][self.action] = objects["objects"]
        self._check_and_apply(source, nothing_to_match=True)

    def test_expired_delete_marker_false(self):
        """Add some versions of object, add delete marker then
        remove all previous versions
        The only remaining version is the delete marker
        Check that event is not sent as ExpiredObjectDeleteMarker is false
        """
        # ['prefix']
        prefix = "documents/"
        self.action_config = {"Expiration": {"ExpiredObjectDeleteMarker": False}}
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule_id}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action}":'
            f"{json.dumps(self.action_config[self.action])},"
            """
                    "Filter":{
                        "Prefix":"""
            f'"{prefix}"'
            """         }
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        self.number_match = 1
        for j in range(self.number_match):
            name = prefix + str(j) + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                self.not_to_match[self.rule_id][self.action].append(obj_meta)
            self.api.object_delete(self.account, self.container, name)
            for el in self.not_to_match[self.rule_id][self.action]:
                self.api.object_delete(
                    self.account, self.container, el["name"], version=el["version"]
                )

            objects = self.api.object_list(
                self.account, self.container, deleted=True, versions=True
            )
            self.not_to_match[self.rule_id][self.action] = objects["objects"]
        self._check_and_apply(source, nothing_to_match=True)


class TestLifecycleNonCurrentVersionConflict(TestLifecycleConform):
    """
    Test two conflict rules and verify that events are sent one by
    predominant rule
    """

    def setUp(self):
        super(TestLifecycleNonCurrentVersionConflict, self).setUp()
        self.versioning_enabled = True
        self.number_of_versions = 4
        self.newer_non_current_versions = 1
        self.action1 = "NoncurrentVersionExpiration"
        self.action2 = "NoncurrentVersionTransitions"

        self.action_config_exp = {
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 1,
                "NewerNoncurrentVersions": self.newer_non_current_versions,
            }
        }

        self.action_config_trs = {
            "NoncurrentVersionTransitions": [
                {
                    "NoncurrentDays": 1,
                    "NewerNoncurrentVersions": self.newer_non_current_versions,
                    "StorageClass": "STANDARD_IA",
                }
            ]
        }

        self.rule1 = "rule1"
        self.rule2 = "rule2"

        self.rules = {
            self.rule1: {self.action1},
            self.rule2: {self.action2},
        }

        self._init_match_rules()

        self.not_to_match_versions = []
        self.expected_to_cycle[self.rule1] = {}
        self.expected_to_cycle[self.rule2] = {}

        self.expected_to_cycle[self.rule1][self.action1] = (
            self.number_of_versions - self.newer_non_current_versions - 1
        )

        self.expected_to_cycle[self.rule2][self.action2] = 0

    def tearDown(self):
        super(TestLifecycleConform, self).tearDown()

    def _upload_expected_combine1(self):
        # match only n non current versions per object
        self.numbr_match = 2
        total_count_expected = 0
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for _ in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule1][self.action1].append(obj_meta)
        for j in range(self.number_match):
            name = self.prefix + str(j) + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i < self.expected_to_cycle[self.rule1][self.action1]:
                    self.to_match[self.rule1][self.action1].append(obj_meta)
                    total_count_expected += 1
                else:
                    # non current to retain
                    self.not_to_match_versions.append(obj_meta)

                if i == self.number_of_versions - 1:  # current version
                    self.not_to_match_versions.append(obj_meta)

        # nothing to match for rule2
        self.to_match[self.rule2][self.action2] = []
        return total_count_expected

    def test_conflict_noncurrent(self):
        # ["prefix", "greater"]
        # match only 2 non current versions per object
        # As the rules conflit:check that  Expiration sends events but
        # Transitions doesn't

        prefix = self.conditions["prefix"]
        greater = self.conditions["greater"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule1}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action1}":'
            f"{json.dumps(self.action_config_exp[self.action1])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                },
                """
            f'"{self.rule2}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action2}":'
            f"{json.dumps(self.action_config_trs[self.action2])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                    }
                }
            }"""
        )

        # 2 version per object (1 object per batch)
        self.expected_to_cycle[self.rule1][self.action1] = 2
        self.expected_to_cycle[self.rule2][self.action2] = 0  #
        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        self._upload_expected_combine1()
        self._check_and_apply(source)


class TestLifecycleExpirationConflict(TestLifecycleConform):
    """
    Test two conflict rules Expiraton/Trainsition and verify that events are sent one by
    predominant rule
    """

    def setUp(self):
        super(TestLifecycleExpirationConflict, self).setUp()
        self.versioning_enabled = True
        self.action1 = "Expiration"
        self.action2 = "Transitions"

        self.action_config_exp = {"Expiration": {"Days": 1}}

        self.action_config_trs = {
            "Transitions": [{"Days": 1, "StorageClass": "STANDARD_IA"}]
        }

        self.rule1 = "rule1"
        self.rule2 = "rule2"
        self.rules = {
            self.rule1: {self.action1},
            self.rule2: {self.action2},
        }

        self._init_match_rules()

        self.not_to_match_versions = []
        self.expected_to_cycle = {}
        self.expected_to_cycle[self.rule1] = {}
        self.expected_to_cycle[self.rule2] = {}
        self.expected_to_cycle[self.rule1][self.action1] = 1
        self.expected_to_cycle[self.rule2][self.action2] = 0

    def tearDown(self):
        super(TestLifecycleConform, self).tearDown()

    def _upload_expected_combine1(self):
        # match only n non current versions per object
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule1][self.action1].append(obj_meta)

        for _ in range(self.number_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule1][self.action1].append(obj_meta)

        # nothing to match for rule2
        self.to_match[self.rule2][self.action2] = []

    def test_conflict_current(self):
        # ["prefix", "greater"]
        # match only 2 non current versions per object
        # As the rules conflit:check that  Expiration sends events but
        # Transitions doesn't
        prefix = self.conditions["prefix"]
        greater = self.conditions["greater"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule1}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action1}":'
            f"{json.dumps(self.action_config_exp[self.action1])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                },
                """
            f'"{self.rule2}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action2}":'
            f"{json.dumps(self.action_config_trs[self.action2])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                    }
                }
            }"""
        )

        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        self._upload_expected_combine1()
        self._check_and_apply(source)


class TestLifecycleTransitionConflict(TestLifecycleConform):
    """
    Test two conflict rules Expiraton/Transtion and verify that events are sent one by
    predominant rule
    """

    def setUp(self):
        super(TestLifecycleTransitionConflict, self).setUp()
        self.versioning_enabled = True
        self.action1 = "Transitions"
        self.action2 = "Transitions"

        self.action_config_trs1 = {
            "Transitions": [{"Days": 1, "StorageClass": "STANDARD_IA"}]
        }

        self.action_config_trs2 = {
            "Transitions": [{"Days": 1, "StorageClass": "ARCHIVE"}]
        }

        self.rule1 = "rule1"
        self.rule2 = "rule2"
        self.rules = {
            self.rule1: {self.action1},
            self.rule2: {self.action2},
        }

        self._init_match_rules()

        self.not_to_match_versions = []
        self.expected_to_cycle[self.rule1] = {}
        self.expected_to_cycle[self.rule2] = {}

    def tearDown(self):
        super(TestLifecycleTransitionConflict, self).tearDown()

    def _upload_expected_combine1(self):
        # match only n non current versions per object
        for _ in range(self.number_not_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_short, random_length=5
                )
                self.not_to_match[self.rule1][self.action1].append(obj_meta)

        for _ in range(self.number_match):
            name = self.prefix + random_str(5)
            for i in range(self.number_of_versions):
                obj_meta = self._upload_something(
                    name=name, data=self.data_long, random_length=6
                )
                if i == self.number_of_versions - 1:
                    self.to_match[self.rule1][self.action1].append(obj_meta)

        # nothing to match for rule2
        self.to_match[self.rule2][self.action2] = []

    def test_conflict_current(self):
        # ["prefix", "greater"]
        # match only 2 non current versions per object
        # As the rules conflit:check that  Expiration sends events but
        # Transitions doesn't
        prefix = self.conditions["prefix"]
        greater = self.conditions["greater"]
        source = (
            """
            {"Rules":
                {  """
            f'"{self.rule1}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action1}":'
            f"{json.dumps(self.action_config_trs1[self.action1])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                },
                """
            f'"{self.rule2}":'
            """
                    {"Status":"Enabled","""
            f'"{self.action2}":'
            f"{json.dumps(self.action_config_trs2[self.action2])},"
            """
                    "Filter":
                        {"Prefix":"""
            f'"{prefix}"'
            """, "ObjectSizeGreaterThan":"""
            f"{greater}"
            """}
                    }
                }
            }"""
        )

        self.expected_to_cycle[self.rule1][self.action1] = 1  # 1 current per object
        self.expected_to_cycle[self.rule2][self.action2] = 0
        self.api.container_set_properties(
            self.account, self.container, properties={LIFECYCLE_PROPERTY_KEY: source}
        )
        if self.versioning_enabled:
            self.helper.enable_versioning()
        self._upload_expected_combine1()
        self._check_and_apply(source)
