# -*- coding: utf-8 -*-

# Copyright (C) 2023-2026 OVH SAS
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

# pylint: disable=no-member

import time
from typing import Any
from urllib.parse import urlparse

import pytest

from oio.common.exceptions import Forbidden
from oio.xcute.client import XcuteClient
from oio.xcute.common.job import XcuteJobStatus
from tests.utils import BaseTestCase


class XcuteTest(BaseTestCase):
    def _cleanup_jobs(self):
        # Clean old jobs
        try:
            data = self.xcute_client.job_list()
            for job in data["jobs"]:
                for i in range(6):
                    if i != 0:
                        # Wait for the job to complete.
                        time.sleep(1)
                    try:
                        self.xcute_client.job_delete(job["job"]["id"])
                        break
                    except Exception as exc2:
                        self.logger.info(
                            "Failed to delete job %s: %s", job["job"]["id"], exc2
                        )
        except Exception as exc:
            self.logger.info("Failed to delete jobs: %s", exc)

        # Check there is no leftovers
        data = self.xcute_client.job_list()
        self.assertEqual(0, len(data["jobs"]), f"Still {data} not deleted")

    def setUp(self):
        super().setUp()
        self.xcute_client = XcuteClient({"namespace": self.ns})
        # Some tests may let some jobs.
        self._cleanup_jobs()

    def tearDown(self):
        # Remove created jobs.
        self._cleanup_jobs()
        super().tearDown()

    def _wait_for_job_status(self, job_id, status, wait_time=15):
        """
        Wait for a xcute job_id to reach a given status.
        wait_time in seconds.
        """
        for _ in range(wait_time * 2):
            time.sleep(0.5)
            job_show = self.xcute_client.job_show(job_id)
            if job_show["job"]["status"] == status:
                return job_show
        else:
            self.fail(f"Xcute job {job_id} did not reach status {status}")


class TestXcuteJobs(XcuteTest):
    def _create_jobs(self, nb):
        jobs = []
        job_types = ["tester", "rawx-decommission", "rdir-decommission"]
        for i in range(nb):
            job_type = job_types[i % len(job_types)]
            job = self.xcute_client.job_create(
                job_type,
                job_config={
                    "params": {
                        "service_id": str(i),
                        "end": 0,
                    }
                },
                put_on_hold_if_locked=True,
            )
            jobs.append(job)
        jobs.reverse()  # The most recent jobs are listed first
        return jobs

    def test_list_jobs_with_limit(self):
        jobs = self._create_jobs(6)

        # The last N jobs
        for limit in range(1, len(jobs) + 1):
            data = self.xcute_client.job_list(limit=limit)
            self.assertListEqual(
                [job["job"]["id"] for job in jobs[:limit]],
                [job["job"]["id"] for job in data["jobs"]],
            )
            self.assertTrue(data["truncated"])
            self.assertEqual(jobs[limit - 1]["job"]["id"], data["next_marker"])

        # All jobs
        data = self.xcute_client.job_list(limit=len(jobs) + 1)
        self.assertListEqual(
            [job["job"]["id"] for job in jobs],
            [job["job"]["id"] for job in data["jobs"]],
        )
        self.assertFalse(data["truncated"])
        self.assertNotIn("next_marker", data)

    def test_list_jobs_with_limit_and_type(self):
        jobs = self._create_jobs(6)
        tester_jobs = [job for job in jobs if job["job"]["type"] == "tester"]
        self.assertGreater(len(tester_jobs), 0)

        # The last N tester jobs
        for limit in range(1, len(tester_jobs) + 1):
            data = self.xcute_client.job_list(limit=limit, job_type="tester")
            self.assertListEqual(
                [job["job"]["id"] for job in tester_jobs[:limit]],
                [job["job"]["id"] for job in data["jobs"]],
            )
            self.assertTrue(data["truncated"])
            self.assertEqual(tester_jobs[limit - 1]["job"]["id"], data["next_marker"])

        # All tester jobs
        data = self.xcute_client.job_list(limit=len(tester_jobs) + 1, job_type="tester")
        self.assertListEqual(
            [job["job"]["id"] for job in tester_jobs],
            [job["job"]["id"] for job in data["jobs"]],
        )
        self.assertFalse(data["truncated"])
        self.assertNotIn("next_marker", data)

    def test_list_jobs_with_marker(self):
        jobs = self._create_jobs(20)

        for i in range(len(jobs)):
            marker = jobs[i]["job"]["id"]
            data = self.xcute_client.job_list(marker=marker)
            self.assertListEqual(
                [job["job"]["id"] for job in jobs[i + 1 :]],
                [job["job"]["id"] for job in data["jobs"]],
            )
            self.assertFalse(data["truncated"])
            self.assertNotIn("next_marker", data)

    @pytest.mark.flaky(reruns=2)
    def test_create_with_lock(self):
        """
        A job is created (with at least one task) then, we try to create another job
        with the same lock, it should be forbidden.
        Timing is a little tricky, the first job is still in WAITING state but if it
        starts too soon, the second job might be authorized. Hence the flaky tag,
        even if "chez moi ça marche".
        """
        # We need to create an object in order to have at least 1 task to execute.
        chunks, _, _ = self.storage.object_create(
            self.account,
            "test_create_with_lock",
            obj_name="test_create_with_lock",
            data=b"yes",
            policy="THREECOPIES",
        )
        rawx_id = urlparse(chunks[0]["url"]).netloc

        def create_job():
            return self.xcute_client.job_create(
                "rawx-decommission",
                job_config={
                    "params": {
                        "service_id": rawx_id,
                    }
                },
            )

        # Create the first job
        job = create_job()

        # The second job should not be started
        with self.assertRaises(Forbidden) as error:
            create_job()
        expected_msg = (
            f"A job ({job['job']['id']}) with the same lock "
            f"(rawx/{rawx_id}) is already in progress (HTTP 403)"
        )
        self.assertEqual(expected_msg, str(error.exception))

    def test_retry_all_tasks(self):
        """
        All tasks should always retry, but job can still be completed (with all
        tasks in error).
        """
        nb_task = 5
        job = self.xcute_client.job_create(
            "tester",
            job_config={
                "params": {
                    "lock": "lock",
                    "service_id": "0",
                    "end": nb_task,
                    "retry_percentage": 100,
                }
            },
        )
        job_show = self._wait_for_job_status(job["job"]["id"], "FINISHED")
        self.assertEqual(nb_task, job_show["errors"]["XcuteExpiredRetryTask"])
        self.assertEqual(nb_task, job_show["errors"]["total"])
        self.assertEqual({}, job_show["results"])

    @pytest.mark.flaky(reruns=2)
    def test_retry_some_tasks(self):
        """
        All tasks should always retry, but job can still be completed (with all
        tasks in error).
        This test is marked as flaky as some randomness is present (a task has 50%
        chance of succeeding/retrying, but if all tasks succeed or retried, then the
        test will fail.
        """
        # The lower, instable is the test.
        # The higher, longer is the test.
        nb_task = 32
        job = self.xcute_client.job_create(
            "tester",
            job_config={
                "params": {
                    "lock": "lock",
                    "service_id": "0",
                    "end": nb_task,
                    "retry_percentage": 50,
                }
            },
        )
        job_show = self._wait_for_job_status(job["job"]["id"], "FINISHED")
        # At least one retry at the end
        self.assertTrue(job_show["errors"]["XcuteExpiredRetryTask"] > 0)
        # All errors are due to retries (expired)
        self.assertEqual(
            job_show["errors"]["XcuteExpiredRetryTask"], job_show["errors"]["total"]
        )
        # At least one result at the end
        self.assertTrue(job_show["results"]["counter"] > 0)

        self.assertEqual(
            nb_task,
            job_show["results"]["counter"]
            + job_show["errors"]["XcuteExpiredRetryTask"],
        )

        # Get the first delayed event
        event = self.wait_for_event(
            prefix_reqid=job["job"]["id"],
            types=["xcute.tasks"],
            delayed=True,
        )
        self.assertIsNotNone(event)
        # Should always be true for xcute events
        self.assertTrue(event.data["do_not_expire"])
        # Not all tasks are present in a delayed
        self.assertTrue(len(event.data["source_event"]["data"]["tasks"]) < nb_task)
        self.assertTrue(len(event.data["source_event"]["data"]["tasks"]) > 0)
        # Extra data (added via the XcuteExpiredRetryTask exception) is present
        for task in event.data["source_event"]["data"]["tasks"].items():
            self.assertEqual(f"foobar-{task[0]}", task[1]["extra"])

    def test_big_payload(self):
        """
        Generate a job where batch of tasks will be too big, it will require to be cut
        in multiple smaller batches.
        """
        nb_task = 64
        job = self.xcute_client.job_create(
            "tester",
            job_config={
                "params": {
                    "lock": "lock",
                    "service_id": "0",
                    "end": nb_task,
                    "big_payload": True,
                }
            },
        )
        job_show = self._wait_for_job_status(job["job"]["id"], "FINISHED")
        self.assertEqual(job_show["results"]["counter"], nb_task)
        self.assertEqual(job_show["errors"]["total"], 0)

    def test_list_jobs_with_exact_lock(self) -> None:
        """Listing with an exact lock value should return only matching jobs."""
        locks: list[str] = ["rawx/node-0", "rawx/node-1", "rdir/node-0"]
        for lock in locks:
            self.xcute_client.job_create(
                "tester",
                job_config={"params": {"lock": lock, "end": 0}},
            )

        data: dict[str, Any] = self.xcute_client.job_list(job_lock="rawx/node-0")
        self.assertEqual(1, len(data["jobs"]))
        self.assertEqual("rawx/node-0", data["jobs"][0]["job"]["lock"])

    def test_list_jobs_with_wildcard_lock(self) -> None:
        """Listing with a wildcard lock pattern should match multiple jobs."""
        rawx_locks: list[str] = ["rawx/node-0", "rawx/node-1"]
        rdir_lock: str = "rdir/node-0"
        for lock in rawx_locks:
            self.xcute_client.job_create(
                "tester",
                job_config={"params": {"lock": lock, "end": 0}},
            )
        self.xcute_client.job_create(
            "tester",
            job_config={"params": {"lock": rdir_lock, "end": 0}},
        )

        # Wildcard prefix: only rawx/* jobs
        data: dict[str, Any] = self.xcute_client.job_list(job_lock="rawx/*")
        listed_locks: set[str] = {j["job"]["lock"] for j in data["jobs"]}
        self.assertEqual(set(rawx_locks), listed_locks)

        # Wildcard all: all 3 jobs
        data_all: dict[str, Any] = self.xcute_client.job_list(job_lock="*/node-0")
        all_locks: set[str] = {j["job"]["lock"] for j in data_all["jobs"]}
        self.assertEqual({"rawx/node-0", "rdir/node-0"}, all_locks)


class TestXcuteJobListFilters(XcuteTest):
    """Functional tests for XcuteClient.job_list filter parameters.

    Covers: job_status (single and multiple), age, prefix, and combinations.
    """

    def _create_finished_job(self, lock: str) -> dict[str, Any]:
        """Create a zero-task tester job and wait for FINISHED."""
        job: dict[str, Any] = self.xcute_client.job_create(
            "tester",
            job_config={"params": {"lock": lock, "end": 0}},
        )
        self._wait_for_job_status(job["job"]["id"], "FINISHED")
        return job

    def _create_running_job(self, lock: str) -> dict[str, Any]:
        """Create a long-running tester job and wait for it to reach RUNNING."""
        job: dict[str, Any] = self.xcute_client.job_create(
            "tester",
            job_config={"params": {"lock": lock, "end": 256}},
        )
        self._wait_for_job_status(job["job"]["id"], "RUNNING")
        return job

    # ------------------------------------------------------------------
    # Status filter
    # ------------------------------------------------------------------

    def test_list_jobs_status_finished_returns_finished_jobs(self) -> None:
        """job_list(job_status=FINISHED) returns only FINISHED jobs."""
        job: dict[str, Any] = self._create_finished_job(lock="test/status-finished")

        data: dict[str, Any] = self.xcute_client.job_list(
            job_status=XcuteJobStatus.FINISHED
        )

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertIn(job["job"]["id"], ids)
        for j in data["jobs"]:
            self.assertEqual(XcuteJobStatus.FINISHED, j["job"]["status"])

    def test_list_jobs_status_excludes_non_matching(self) -> None:
        """job_list(job_status=FAILED) does not return FINISHED jobs."""
        job: dict[str, Any] = self._create_finished_job(lock="test/status-exclude")

        data: dict[str, Any] = self.xcute_client.job_list(
            job_status=XcuteJobStatus.FAILED
        )

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertNotIn(job["job"]["id"], ids)

    def test_list_jobs_multi_status_returns_all_matching(self) -> None:
        """job_list with a list of statuses returns jobs matching any of them."""
        job1: dict[str, Any] = self._create_finished_job(lock="test/multi-status")
        job2: dict[str, Any] = self._create_running_job(lock="test/multi-status")

        data: dict[str, Any] = self.xcute_client.job_list(
            job_status=[XcuteJobStatus.FINISHED, XcuteJobStatus.RUNNING]
        )

        self.assertEqual(2, len(data["jobs"]))
        job1_result = data["jobs"][1]
        job2_result = data["jobs"][0]
        self.assertEqual(job1["job"]["id"], job1_result["job"]["id"])
        self.assertEqual(XcuteJobStatus.FINISHED, job1_result["job"]["status"])
        self.assertEqual(job2["job"]["id"], job2_result["job"]["id"])
        self.assertEqual(XcuteJobStatus.RUNNING, job2_result["job"]["status"])

        self._wait_for_job_status(job2["job"]["id"], "FINISHED")

    def test_list_jobs_multi_status_returns_partial_matching(self) -> None:
        """job_list with a list of statuses returns jobs matching only FINISHED."""
        job1: dict[str, Any] = self._create_finished_job(lock="test/multi-status")
        job2: dict[str, Any] = self._create_running_job(lock="test/multi-status")

        data: dict[str, Any] = self.xcute_client.job_list(
            job_status=[XcuteJobStatus.FINISHED, XcuteJobStatus.FAILED]
        )

        self.assertEqual(1, len(data["jobs"]))
        job1_result = data["jobs"][0]
        self.assertEqual(job1["job"]["id"], job1_result["job"]["id"])
        self.assertEqual(XcuteJobStatus.FINISHED, job1_result["job"]["status"])

        self._wait_for_job_status(job2["job"]["id"], "FINISHED")

    def test_list_jobs_no_status_returns_all_jobs(self) -> None:
        """job_list without job_status includes jobs regardless of status."""
        job: dict[str, Any] = self._create_finished_job(lock="test/no-status")

        data: dict[str, Any] = self.xcute_client.job_list()

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertIn(job["job"]["id"], ids)

    # ------------------------------------------------------------------
    # Age filter
    # ------------------------------------------------------------------

    def test_list_jobs_age_zero_includes_recent_jobs(self) -> None:
        """age=0 matches any job regardless of how recent it is."""
        job: dict[str, Any] = self._create_finished_job(lock="test/age-zero")

        data: dict[str, Any] = self.xcute_client.job_list(job_age=0)

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertIn(job["job"]["id"], ids)

    def test_list_jobs_large_age_excludes_recent_jobs(self) -> None:
        """age=365*24*3600 excludes jobs created just now."""
        job: dict[str, Any] = self._create_finished_job(lock="test/age-large")

        data: dict[str, Any] = self.xcute_client.job_list(job_age=365 * 24 * 3600)

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertNotIn(job["job"]["id"], ids)

    # ------------------------------------------------------------------
    # Type filter
    # ------------------------------------------------------------------

    def test_list_jobs_type_returns_only_matching_jobs(self) -> None:
        """job_list(job_type=...) returns only jobs of that type."""
        job_tester: dict[str, Any] = self.xcute_client.job_create(
            "tester",
            job_config={"params": {"lock": "test/type-tester", "end": 0}},
            put_on_hold_if_locked=True,
        )
        self._wait_for_job_status(job_tester["job"]["id"], "FINISHED")

        data: dict[str, Any] = self.xcute_client.job_list(job_type="tester")

        self.assertGreater(len(data["jobs"]), 0)
        for j in data["jobs"]:
            self.assertEqual("tester", j["job"]["type"])

    def test_list_jobs_type_excludes_non_matching(self) -> None:
        """job_list(job_type=rawx-decommission) excludes tester jobs."""
        job: dict[str, Any] = self.xcute_client.job_create(
            "tester",
            job_config={"params": {"lock": "test/type-exclude", "end": 0}},
            put_on_hold_if_locked=True,
        )
        self._wait_for_job_status(job["job"]["id"], "FINISHED")

        data: dict[str, Any] = self.xcute_client.job_list(job_type="rawx-decommission")

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertNotIn(job["job"]["id"], ids)

    # ------------------------------------------------------------------
    # Prefix filter
    # ------------------------------------------------------------------

    def test_list_jobs_prefix_returns_only_matching_jobs(self) -> None:
        """job_list(prefix=...) returns only jobs whose ID starts with that prefix."""
        job: dict[str, Any] = self._create_finished_job(lock="test/prefix")
        job_id: str = job["job"]["id"]
        # Job IDs are YYYYMMDDHHMMSS...  Use the first 8 chars (date) as prefix.
        prefix: str = job_id[:8]

        data: dict[str, Any] = self.xcute_client.job_list(prefix=prefix)

        for j in data["jobs"]:
            self.assertTrue(
                j["job"]["id"].startswith(prefix),
                f"Job {j['job']['id']} does not start with prefix {prefix!r}",
            )

    # ------------------------------------------------------------------
    # Lock filter
    # ------------------------------------------------------------------

    def test_list_jobs_exact_lock_returns_only_matching(self) -> None:
        """job_list(job_lock=...) returns only jobs with that exact lock."""
        job_match: dict[str, Any] = self._create_finished_job(lock="rawx/node-0")
        job_other: dict[str, Any] = self._create_finished_job(lock="rawx/node-1")

        data: dict[str, Any] = self.xcute_client.job_list(job_lock="rawx/node-0")

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertIn(job_match["job"]["id"], ids)
        self.assertNotIn(job_other["job"]["id"], ids)

    def test_list_jobs_wildcard_lock_matches_pattern(self) -> None:
        """job_list(job_lock='rawx/*') matches all rawx jobs but not rdir ones."""
        job_rawx0: dict[str, Any] = self._create_finished_job(lock="rawx/lock-wc-0")
        job_rawx1: dict[str, Any] = self._create_finished_job(lock="rawx/lock-wc-1")
        job_rdir: dict[str, Any] = self._create_finished_job(lock="rdir/lock-wc-0")

        data: dict[str, Any] = self.xcute_client.job_list(job_lock="rawx/*")

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertIn(job_rawx0["job"]["id"], ids)
        self.assertIn(job_rawx1["job"]["id"], ids)
        self.assertNotIn(job_rdir["job"]["id"], ids)

    def test_list_jobs_no_lock_returns_all(self) -> None:
        """job_list without job_lock includes jobs regardless of their lock."""
        job_rawx: dict[str, Any] = self._create_finished_job(lock="rawx/lock-none")
        job_rdir: dict[str, Any] = self._create_finished_job(lock="rdir/lock-none")

        data: dict[str, Any] = self.xcute_client.job_list()

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertIn(job_rawx["job"]["id"], ids)
        self.assertIn(job_rdir["job"]["id"], ids)

    # ------------------------------------------------------------------
    # Combined filters
    # ------------------------------------------------------------------

    def test_list_jobs_status_and_lock(self) -> None:
        """Combining job_status and job_lock narrows the result set."""
        job_rawx: dict[str, Any] = self._create_finished_job(lock="rawx/filter-combo")
        job_rdir: dict[str, Any] = self._create_finished_job(lock="rdir/filter-combo")

        data: dict[str, Any] = self.xcute_client.job_list(
            job_status=XcuteJobStatus.FINISHED,
            job_lock="rawx/*",
        )

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertIn(job_rawx["job"]["id"], ids)
        self.assertNotIn(job_rdir["job"]["id"], ids)

    def test_list_jobs_status_and_age(self) -> None:
        """Combining job_status and age=0 returns only terminal jobs."""
        job: dict[str, Any] = self._create_finished_job(lock="test/status-age")

        data: dict[str, Any] = self.xcute_client.job_list(
            job_status=XcuteJobStatus.FINISHED,
            job_age=0,
        )

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertIn(job["job"]["id"], ids)
        for j in data["jobs"]:
            self.assertEqual(XcuteJobStatus.FINISHED, j["job"]["status"])

    def test_list_jobs_status_age_and_lock(self) -> None:
        """All three filters combined match only the intended job."""
        job_match: dict[str, Any] = self._create_finished_job(lock="rawx/triple-filter")
        job_other: dict[str, Any] = self._create_finished_job(lock="rdir/triple-filter")

        data: dict[str, Any] = self.xcute_client.job_list(
            job_status=XcuteJobStatus.FINISHED,
            job_lock="rawx/*",
            job_age=0,
        )

        ids: list[str] = [j["job"]["id"] for j in data["jobs"]]
        self.assertIn(job_match["job"]["id"], ids)
        self.assertNotIn(job_other["job"]["id"], ids)

    # ------------------------------------------------------------------
    # force_master
    # ------------------------------------------------------------------

    def test_list_jobs_force_master_returns_same_result(self) -> None:
        """force_master=True should return the same jobs as without it."""
        job: dict[str, Any] = self._create_finished_job(lock="test/force-master")

        data_default: dict[str, Any] = self.xcute_client.job_list()
        data_master: dict[str, Any] = self.xcute_client.job_list(force_master=True)

        ids_default: set[str] = {j["job"]["id"] for j in data_default["jobs"]}
        ids_master: set[str] = {j["job"]["id"] for j in data_master["jobs"]}
        self.assertIn(job["job"]["id"], ids_master)
        self.assertEqual(ids_default, ids_master)
