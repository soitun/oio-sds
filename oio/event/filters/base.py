# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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


from oio.common.exceptions import OioException
from oio.common.logger import get_logger


class Filter(object):
    def __init__(self, app, conf, logger=None):
        self.app = app
        self.app_env = app.app_env
        self.conf = conf
        self.logger = logger or self.app_env.get("logger") or get_logger(conf)
        self.init()

    def init(self):
        pass

    def process(self, env, cb):
        return self.app(env, cb)

    def __call__(self, env, cb):
        res = self.process(env, cb)
        if res is not None:
            raise OioException(
                f"Unexpected return value when filter {self.__class__.__name__} "
                f"processed an event: {res}"
            )
