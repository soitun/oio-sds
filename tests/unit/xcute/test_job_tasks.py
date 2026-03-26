# Copyright (C) 2026 OVH SAS
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
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from werkzeug.test import Client as WerkzeugClient

from oio.common.exceptions import NotFound
from oio.xcute.client import XcuteClient
from oio.xcute.common.backend import XcuteBackend
from oio.xcute.server import XcuteServer

# ---------------------------------------------------------------------------
# Tests for XcuteBackend.list_running_tasks
# ---------------------------------------------------------------------------


class TestListRunningTasks(unittest.TestCase):
    """Unit tests for XcuteBackend.list_running_tasks."""

    def setUp(self) -> None:
        self.backend = XcuteBackend.__new__(XcuteBackend)
        self.backend.logger = MagicMock()
        # Simulate key template set by generate_lua_scripts
        self.backend.key_tasks_running = "xcute:tasks:running:%s"
        self.backend.key_job_info = "xcute:job:info:%s"
        self._mock_client: MagicMock = MagicMock()
        self.backend.get_slave_conn = MagicMock(return_value=self._mock_client)

    def _set_job_exists(self, job_id: str) -> None:
        """Make _get_job_info return a non-empty dict for job_id."""
        self.backend._get_job_info = MagicMock(return_value={"job.id": job_id})

    def _set_job_missing(self) -> None:
        self.backend._get_job_info = MagicMock(return_value={})

    def test_returns_sorted_task_ids(self) -> None:
        self._set_job_exists("job-1")
        self._mock_client.smembers.return_value = {b"task-c", b"task-a", b"task-b"}

        result: list[str] = self.backend.list_running_tasks("job-1")

        self.assertEqual(["task-a", "task-b", "task-c"], result)

    def test_returns_empty_list_when_no_tasks(self) -> None:
        self._set_job_exists("job-1")
        self._mock_client.smembers.return_value = set()

        result: list[str] = self.backend.list_running_tasks("job-1")

        self.assertEqual([], result)

    def test_queries_correct_redis_key(self) -> None:
        self._set_job_exists("job-42")
        self._mock_client.smembers.return_value = set()

        self.backend.list_running_tasks("job-42")

        self._mock_client.smembers.assert_called_once_with("xcute:tasks:running:job-42")

    def test_raises_not_found_for_unknown_job(self) -> None:
        self._set_job_missing()

        with self.assertRaises(Exception):
            # The ResponseError("no_job") is translated to NotFound by the decorator;
            # here we just verify it raises rather than returning an empty list.
            self.backend.list_running_tasks("ghost-job")

    def test_uses_slave_conn_by_default(self) -> None:
        self._set_job_exists("job-1")
        self._mock_client.smembers.return_value = set()

        self.backend.list_running_tasks("job-1")

        self.backend.get_slave_conn.assert_called_once_with(force_master=False)

    def test_force_master_forwarded(self) -> None:
        self._set_job_exists("job-1")
        self._mock_client.smembers.return_value = set()

        self.backend.list_running_tasks("job-1", force_master=True)

        self.backend.get_slave_conn.assert_called_once_with(force_master=True)


# ---------------------------------------------------------------------------
# Tests for XcuteServer.on_job_tasks
# ---------------------------------------------------------------------------


class TestXcuteServerJobTasks(unittest.TestCase):
    """Unit tests for XcuteServer.on_job_tasks."""

    def setUp(self) -> None:
        with patch("oio.xcute.server.XcuteBackend") as mock_backend_cls:
            self.mock_backend: MagicMock = MagicMock()
            mock_backend_cls.return_value = self.mock_backend
            self.server: XcuteServer = XcuteServer({"xcute_type": "internal"})
        self.client: WerkzeugClient = WerkzeugClient(self.server)
        self.mock_backend.list_running_tasks.return_value = []

    def test_returns_200_with_json(self) -> None:
        self.mock_backend.list_running_tasks.return_value = ["task-1", "task-2"]

        response = self.client.get("/v1.0/xcute/job/tasks?id=job-1")

        self.assertEqual(200, response.status_code)
        self.assertIn("application/json", response.content_type)
        body: dict[str, Any] = json.loads(response.data)
        self.assertIn("tasks", body)
        self.assertEqual(["task-1", "task-2"], body["tasks"])

    def test_job_id_forwarded_to_backend(self) -> None:
        self.client.get("/v1.0/xcute/job/tasks?id=job-xyz")

        self.mock_backend.list_running_tasks.assert_called_once_with(
            "job-xyz", force_master=False
        )

    def test_force_master_forwarded(self) -> None:
        self.client.get("/v1.0/xcute/job/tasks?id=job-1&force_master=True")

        call_kwargs: dict[str, Any] = self.mock_backend.list_running_tasks.call_args[1]
        self.assertTrue(call_kwargs["force_master"])

    def test_missing_job_id_returns_400(self) -> None:
        response = self.client.get("/v1.0/xcute/job/tasks")
        self.assertEqual(400, response.status_code)

    def test_unknown_job_returns_404(self) -> None:
        self.mock_backend.list_running_tasks.side_effect = NotFound("no_job")

        response = self.client.get("/v1.0/xcute/job/tasks?id=ghost")

        self.assertEqual(404, response.status_code)

    def test_empty_task_list_returns_200(self) -> None:
        response = self.client.get("/v1.0/xcute/job/tasks?id=job-1")
        self.assertEqual(200, response.status_code)
        body: dict[str, Any] = json.loads(response.data)
        self.assertEqual([], body["tasks"])


# ---------------------------------------------------------------------------
# Tests for XcuteClient.job_tasks
# ---------------------------------------------------------------------------


class TestXcuteClientJobTasks(unittest.TestCase):
    """Unit tests for XcuteClient.job_tasks."""

    def setUp(self) -> None:
        self.client: XcuteClient = XcuteClient.__new__(XcuteClient)
        self.client.xcute_request = MagicMock()
        self._set_response({"tasks": []})

    def _set_response(self, data: dict[str, Any]) -> None:
        self.client.xcute_request.return_value = (None, data)

    def test_gets_job_tasks_endpoint(self) -> None:
        self.client.job_tasks("job-1")
        args: tuple[Any, ...] = self.client.xcute_request.call_args[0]
        self.assertEqual("job-1", args[0])
        self.assertEqual("GET", args[1])
        self.assertEqual("/job/tasks", args[2])

    def test_default_force_master_is_false(self) -> None:
        self.client.job_tasks("job-1")
        params: dict[str, Any] = self.client.xcute_request.call_args[1]["params"]
        # force_master=False is coerced to None before sending
        self.assertIsNone(params["force_master"])

    def test_force_master_forwarded(self) -> None:
        self.client.job_tasks("job-1", force_master=True)
        params: dict[str, Any] = self.client.xcute_request.call_args[1]["params"]
        self.assertTrue(params["force_master"])

    def test_returns_response_data(self) -> None:
        expected: dict[str, Any] = {"tasks": ["task-a", "task-b"]}
        self._set_response(expected)
        result: dict[str, Any] = self.client.job_tasks("job-1")
        self.assertEqual(expected, result)
