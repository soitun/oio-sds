# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2024 OVH SAS
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

from oio.common import exceptions
from oio.common.client import ProxyClient
from oio.common.json import json
from oio.directory.admin import service_id_to_string


class DirectoryClient(ProxyClient):
    """
    Mid-level client for OpenIO SDS service directory (meta0, meta1).
    """

    def __init__(self, conf, **kwargs):
        super(DirectoryClient, self).__init__(
            conf, request_prefix="/reference", **kwargs
        )

    def _make_params(
        self, account=None, reference=None, service_type=None, cid=None, service_id=None
    ):
        if cid:
            params = {"cid": cid}
        else:
            params = {"acct": account, "ref": reference}
        if service_type:
            params["type"] = service_type
        if service_id:
            params["service_id"] = service_id_to_string(service_id)
        return params

    def create(self, account=None, reference=None, properties=None, **kwargs):
        """
        Create a reference (a service container).

        :param account: name of the account where the reference must be created
        :param reference: name of the reference to create
        :param properties: dictionary of properties to set on the reference
        :type properties: `dict`
        :returns: True if the reference has been created,
            False if it already existed
        """
        params = self._make_params(account, reference)
        if not properties:
            properties = dict()
        data = json.dumps({"properties": properties})
        resp, body = self._request(
            "POST", "/create", params=params, data=data, **kwargs
        )
        if resp.status not in (201, 202):
            raise exceptions.from_response(resp, body)
        return resp.status == 201

    def has(self, account=None, reference=None, cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        try:
            self._request("GET", "/has", params=params, **kwargs)
        except exceptions.NotFound:
            return False
        return True

    def list(
        self,
        account=None,
        reference=None,
        cid=None,
        service_type=None,
        service_id=None,
        **kwargs,
    ):
        """
        List the services linked to the reference.
        """
        params = self._make_params(
            account, reference, cid=cid, service_type=service_type
        )
        if service_id:
            params["service_id"] = service_id
        _resp, body = self._request("GET", "/show", params=params, **kwargs)
        return body

    def delete(self, account=None, reference=None, cid=None, **kwargs):
        """
        Delete a reference.
        """
        params = self._make_params(account, reference, cid=cid)
        _resp, _body = self._request("POST", "/destroy", params=params, **kwargs)

    def destroy(self, *args, **kwargs):
        """
        :deprecated: use `delete`
        """
        return self.delete(*args, **kwargs)

    def get_properties(
        self, account=None, reference=None, properties=None, cid=None, **kwargs
    ):
        """
        Get properties for a reference.
        """
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(properties or list())
        _resp, body = self._request(
            "POST", "/get_properties", data=data, params=params, **kwargs
        )
        return body

    def set_properties(
        self, account=None, reference=None, properties=None, cid=None, **kwargs
    ):
        """
        Set properties for a reference.
        """
        params = self._make_params(account, reference, cid=cid)
        if not properties:
            properties = dict()
        data = json.dumps({"properties": properties})
        _resp, _body = self._request(
            "POST", "/set_properties", data=data, params=params, **kwargs
        )

    def del_properties(
        self, account=None, reference=None, properties=None, cid=None, **kwargs
    ):
        """
        Delete properties for a reference.
        """
        params = self._make_params(account, reference, cid=cid)
        properties = properties or list()
        # Build a serializable list in case properties is a view.
        data = json.dumps([k for k in properties])
        _resp, _body = self._request(
            "POST", "/del_properties", data=data, params=params, **kwargs
        )

    def link(
        self,
        account=None,
        reference=None,
        service_type=None,
        cid=None,
        autocreate=False,
        **kwargs,
    ):
        """
        Poll and associate a new service to the reference.
        """
        params = self._make_params(account, reference, service_type, cid=cid)
        _resp, _body = self._request(
            "POST", "/link", params=params, autocreate=autocreate, **kwargs
        )

    def unlink(
        self, account=None, reference=None, service_type=None, cid=None, **kwargs
    ):
        """
        Remove an associated service from the reference
        """
        params = self._make_params(account, reference, service_type, cid=cid)
        _resp, _body = self._request("POST", "/unlink", params=params, **kwargs)

    def renew(
        self, account=None, reference=None, service_type=None, cid=None, **kwargs
    ):
        """
        Re-poll and re-associate a set of services to the reference.
        Will increment the sequence number.
        """
        params = self._make_params(account, reference, service_type, cid=cid)
        _resp, _body = self._request("POST", "/renew", params=params, **kwargs)

    def force(
        self,
        account=None,
        reference=None,
        service_type=None,
        services=None,
        cid=None,
        autocreate=False,
        replace=False,
        **kwargs,
    ):
        """
        Associate the specified services to the reference.

        :param replace: do not require the list of services
            of the specified type to be empty, overwrite it.
        :type replace: `bool`
        """
        params = self._make_params(account, reference, service_type, cid=cid)
        if replace:
            params["replace"] = "yes"
        data = json.dumps(services)
        _resp, _body = self._request(
            "POST", "/force", data=data, params=params, autocreate=autocreate, **kwargs
        )
