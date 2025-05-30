# Copyright (C) 2022-2025 OVH SAS
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

from oio.api.base import MultiEndpointHttpApi
from oio.common.configuration import load_namespace_conf
from oio.common.constants import TIMEOUT_KEYS
from oio.common.decorators import ensure_headers, patch_kwargs
from oio.common.easy_value import float_value
from oio.common.exceptions import OioException, OioNetworkException, OioProtocolError
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient


class ServiceClient(MultiEndpointHttpApi):
    """Simple client API for the specified service type."""

    def __init__(
        self,
        service_type,
        conf,
        endpoint=None,
        proxy_endpoint=None,
        request_prefix="",
        refresh_delay=3600.0,
        location=None,
        logger=None,
        **kwargs,
    ):
        """
        Initialize a client for the specified service type.

        :param service_type: service type to request
        :type service_type: `str`
        :param conf: dictionary with at least the namespace name
        :type conf: `dict`
        :param endpoint: URL of an service of specified service type
        :type endpoint: `str`
        :param proxy_endpoint: URL of the proxy
        :type proxy_endpoint: `str`
        :param request_prefix: text to insert in between endpoint and
            requested URL
        :type request_prefix: `str`
        :param refresh_delay: time between refreshes of the service endpoint
        :type refresh_delay: `float` seconds
        :param logger:
        """
        self.location = location
        self.netloc = None
        # Look for an endpoint in the application configuration
        if not endpoint:
            endpoint = conf.get(f"{service_type}_url", None)
        # Look for an endpoint in the namespace configuration
        if not endpoint:
            namespace = conf.get("namespace")
            if namespace:
                ns_conf = load_namespace_conf(namespace, failsafe=True)
                endpoint = ns_conf.get(service_type)
        if endpoint:
            scheme = "http"
            split_endpoint = endpoint.split("://", 1)
            if len(split_endpoint) > 1:
                scheme = split_endpoint[0]
            self.netloc = split_endpoint[-1]
            endpoint = "://".join((scheme, self.netloc))

        self.logger = logger or get_logger(conf)

        super().__init__(endpoint=endpoint, service_type=service_type, **kwargs)

        kwargs.pop("pool_manager", None)
        self.conscience = ConscienceClient(
            conf,
            endpoint=proxy_endpoint,
            logger=self.logger,
            pool_manager=self.pool_manager,
            **kwargs,
        )

        self._global_kwargs = {
            tok: float_value(tov, None)
            for tok, tov in kwargs.items()
            if tok in TIMEOUT_KEYS
        }

        self.request_prefix = request_prefix.lstrip("/")
        if self.endpoint:
            self.endpoint = "/".join((self.endpoint, self.request_prefix))
            refresh_delay = -1.0
        self._refresh_delay = refresh_delay
        self._refresh_delay_after_error = refresh_delay / 10.0
        self._next_refresh = 0.0

    def _get_service_addresses(self, **kwargs):
        """
        Fetch IP and port of services of specified service type from Conscience.

        In case this instance has a defined location, return all addresses sorted
        by distance and score.
        """
        if self.location:
            all_services = self.conscience.all_services(
                self.service_type, requester_location=self.location, **kwargs
            )
            all_services.sort(
                reverse=True, key=lambda s: s["score"] / (s.get("distance") or 0.5)
            )
            addresses = [s["addr"] for s in all_services if s["score"] > 0]
            if not addresses:
                raise OioException(
                    f"None of the {len(all_services)} {self.service_type} "
                    "services has a score > 0"
                )
        else:
            instance = self.conscience.next_instance(self.service_type, **kwargs)
            addresses = [instance.get("addr")]
        return addresses

    def _schedule_endpoint_refresh(self, now=None, quickly=False):
        """
        Schedule the next endpoint refresh.

        :param quickly: schedule it earlier than the standard delay
        """
        delay = self._refresh_delay_after_error if quickly else self._refresh_delay
        if delay >= 0.0:
            self._next_refresh = (now or time.monotonic()) + delay

    def _rotate_endpoints(self, last_error=None, now=None):
        """
        Rotate the internal endpoint list and schedule the next endpoint refresh.
        """
        super()._rotate_endpoints(last_error=last_error)
        # The _rotate_endpoints method can be called by the parent class, this
        # is why we do the scheduling here and not in the calling function.
        self._schedule_endpoint_refresh(now=now, quickly=True)

    def _refresh_endpoint(self, now=None, last_error=None, **kwargs):
        """
        Refresh service endpoint.
        """
        try:
            endpoint_addresses = self._get_service_addresses(**kwargs)
            self._endpoints[:] = [
                "/".join(("http:/", ea, self.request_prefix))
                for ea in endpoint_addresses
            ]
            self._schedule_endpoint_refresh(now=now, quickly=False)
        except OioException as exc:
            # No endpoint in the list: we cannot continue.
            if len(self._endpoints) < 1:
                raise

            # If the refresh was not triggered by an error, we can continue
            # using the current endpoint. Though, we re-schedule an endpoint refresh:
            # quicker than the standard delay, but not immediately.
            if not last_error:
                self._schedule_endpoint_refresh(now=now, quickly=True)
                raise

            self.logger.warning(
                "Failed to refresh %s addresses (%s), rotating the known list",
                self.service_type,
                exc,
            )
            self._rotate_endpoints(last_error=last_error, now=now)

    def _maybe_refresh_endpoint(self, **kwargs):
        """
        Refresh service endpoint if delay has been reached or there is no endpoint.
        """
        if self._refresh_delay < 0.0 and self.endpoint:
            return
        now = time.monotonic()
        if now < self._next_refresh and self.endpoint:
            return

        try:
            self._refresh_endpoint(now, **kwargs)
            return
        except OioNetworkException as exc:
            if not self.endpoint:
                # Cannot use the previous one
                raise
            self.logger.warning(
                "Failed to refresh %s endpoint: %s", self.service_type, exc
            )
        except OioException:
            if not self.endpoint:
                # Cannot use the previous one
                raise
            self.logger.exception("Failed to refresh %s endpoint", self.service_type)
        return

    @patch_kwargs
    @ensure_headers
    def service_request(self, method, action, use_cache=False, **kwargs):
        """Make a request to the service of specified service type."""
        self._maybe_refresh_endpoint()

        read_request = method in ("GET", "HEAD")
        if read_request and not use_cache:
            kwargs["headers"]["X-No-Cache"] = "1"

        already_retried = False
        while True:
            try:
                resp, body = self._request(method, action, **kwargs)
                return resp, body
            except OioNetworkException as exc:
                if self._refresh_delay >= 0.0:
                    self.logger.info(
                        "Refreshing %s endpoint after error %s", self.service_type, exc
                    )
                    try:
                        self._refresh_endpoint(last_error=exc)
                    except Exception as exc2:
                        self.logger.warning(
                            "Failed to refresh %s endpoint: %s",
                            self.service_type,
                            exc2,
                        )
                if read_request and not already_retried:
                    # Only try once on read requests
                    # (specially for the protocol errors).
                    # For write requests, the request may have been running
                    # in the background. A retry may return an error.
                    if isinstance(exc, OioProtocolError):
                        already_retried = True
                    if already_retried:
                        self.logger.info(
                            "Retry %s request after error %s", self.service_type, exc
                        )
                        continue
                raise
