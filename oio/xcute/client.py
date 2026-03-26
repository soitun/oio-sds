# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2026 OVH SAS
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

from typing import Any

from oio.common.service_client import ServiceClient


class XcuteClient(ServiceClient):
    """Simple client API for the xcute service."""

    def __init__(self, conf, xcute_type=None, **kwargs):
        if not xcute_type:
            xcute_type = "internal"
        service_slot = f"xcute_{xcute_type}"
        super(XcuteClient, self).__init__(
            "xcute",
            conf,
            service_slot=service_slot,
            request_prefix="v1.0/xcute",
            **kwargs,
        )

    def xcute_request(self, job_id, *args, **kwargs):
        params = kwargs.setdefault("params")
        if params is None:
            params = {}
            kwargs["params"] = params
        if job_id:
            params["id"] = job_id
        return self.service_request(*args, **kwargs)

    def job_list(
        self,
        limit: int | None = None,
        prefix: str | None = None,
        marker: str | None = None,
        job_status: str | list[str] | None = None,
        job_type: str | None = None,
        job_lock: str | None = None,
        job_age: int | None = None,
        force_master: bool = False,
    ) -> dict[str, Any]:
        _, data = self.xcute_request(
            None,
            "GET",
            "/job/list",
            params={
                "limit": limit,
                "prefix": prefix,
                "marker": marker,
                "status": job_status,
                "type": job_type,
                "lock": job_lock,
                "age": job_age,
                "force_master": force_master or None,
            },
        )
        return data

    def job_create(self, job_type, job_config=None, put_on_hold_if_locked=False):
        _, data = self.xcute_request(
            None,
            "POST",
            "/job/create",
            params={"type": job_type, "put_on_hold_if_locked": put_on_hold_if_locked},
            json=job_config,
        )
        return data

    def job_show(self, job_id, force_master=False):
        _, data = self.xcute_request(
            job_id,
            "GET",
            "/job/show",
            params={"force_master": force_master or None},
        )
        return data

    def job_pause(self, job_id):
        _, data = self.xcute_request(job_id, "POST", "/job/pause")
        return data

    def job_resume(self, job_id):
        _, data = self.xcute_request(job_id, "POST", "/job/resume")
        return data

    def job_update(self, job_id, job_config=None):
        _, data = self.xcute_request(job_id, "POST", "/job/update", json=job_config)
        return data

    def job_abort(self, job_id):
        _, data = self.xcute_request(job_id, "POST", "/job/abort")
        return data

    def job_delete(self, job_id):
        self.xcute_request(job_id, "DELETE", "/job/delete")

    def job_tasks(self, job_id: str, force_master: bool = False) -> dict[str, Any]:
        _, data = self.xcute_request(
            job_id,
            "GET",
            "/job/tasks",
            params={"force_master": force_master or None},
        )
        return data

    def lock_list(self, force_master=False):
        _, data = self.xcute_request(
            None,
            "GET",
            "/lock/list",
            params={"force_master": force_master or None},
        )
        return data

    def lock_show(self, lock, force_master=False):
        _, data = self.xcute_request(
            None,
            "GET",
            "/lock/show",
            params={"lock": lock, "force_master": force_master or None},
        )
        return data
