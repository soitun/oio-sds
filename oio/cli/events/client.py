# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
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

from logging import getLogger

from oio.event.client import EventClient

LOG = getLogger(__name__)

API_NAME = "event"


def make_client(instance):
    """
    Build an EventClient that will be added as "event"
    field of `instance`.

    :param instance: an instance of ClientManager
    :returns: an instance of EventClient
    """
    client = EventClient(instance.cli_conf())
    return client
