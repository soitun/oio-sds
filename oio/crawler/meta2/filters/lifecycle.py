# Copyright (C) 2021 OVH SAS
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

from oio.common.json import json
from oio.common.easy_value import int_value
from oio.crawler.common.base import Filter
from oio.crawler.meta2.meta2db import Meta2DB
from oio.container.lifecycle import etree, ContainerLifecycle,\
    DaysActionFilter, DateActionFilter
from oio.event.beanstalk import BeanstalkdSender
from oio.common.client import ProxyClient
from oio.common import exceptions
from oio.common.exceptions import BadRequest


class Lifecycle(Filter):
    """
    Log info for for given container.
    """

    NAME = 'Lifecycle'

    def init(self):
        self.successes = 0
        self.errors = 0
        self.api = self.app_env['api']
        beanstalkd_tube = self.conf.get('beanstalkd_tube',
                                        'oio-lifecycle')
        beanstalkd_addr = 'beanstalk://127.0.0.1:6005'
        self.sender = BeanstalkdSender(beanstalkd_addr, beanstalkd_tube,
                                       self.logger)
        self.retry_delay = int_value(self.conf.get('retry_delay'), 30)
        self.proxy_client = ProxyClient(
                self.conf, pool_manager=self.api.container.pool_manager,
                logger=self.logger)

    def process(self, env, cb):
        try:
            meta2db = Meta2DB(self.app_env, env)
            user_lifecycle = meta2db.user
            self.logger.info('Got container %s lifecycle %s', meta2db.cid,
                             user_lifecycle)

            if user_lifecycle:
                account, container = self.api.resolve_cid(meta2db.cid)
                kwargs = {}
                params = {'cid': meta2db.cid}
                params['local'] = 1
                data = {}
                try:
                    resp, body = self.proxy_client._request(
                        'POST', '/container/lifecycle-copy',
                        params=params, json=data, **kwargs)
                    if resp.status != 204:
                        raise exceptions.from_response(resp, body)
                    lc = ContainerLifecycle(self.api, account, container, logger=self.logger)
                    lc.load_xml(user_lifecycle['user.X-Container-Sysmeta-S3Api-Lifecycle'])
                    for el in lc.rules:
                        for act in el.actions:
                            days = ''
                            date = ''
                            if isinstance(act.filter, DaysActionFilter):
                                days = act.filter.days
                            if isinstance(act.filter, DateActionFilter):
                                date = act.fitler.date

                            #TODO convert days or date to seconds
                            days_in_sec = int(days) * 86400
                            sql_query = el.filter.to_sql_query(days_in_sec)
                            print('laa sql_query:', sql_query)
                            kwargs = {}
                            params = {'cid': meta2db.cid}
                            data = []
                            tmp_data = {}
                            tmp_data['cid'] = meta2db.cid
                            tmp_data['lower'] = '>'
                            tmp_data['upper'] = '<'
                            tmp_data['metadata'] = {}
                            tmp_data['metadata']['action'] = 'expiration'
                            tmp_data['metadata']['query'] = sql_query
                            tmp_data['metadata']['days'] = days
                            tmp_data['metadata']['date'] = '2023:01:01'
                            data.append(tmp_data)
                            try:
                                resp, body = self.proxy_client._request(
                                    'POST', '/container/lifecycle-copy',
                                    params=params, json=data, **kwargs)
                            except BadRequest:
                                raise
                except BadRequest:
                    raise
                except Exception as exc:
                    self.logger.warning(
                        'Failed to make lifecycle local '
                        'copy cid = %s msg %s', meta2db.cid, exc)

            self.successes += 1
        except Exception:
            self.errors += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            'successes': self.successes,
            'errors': self.errors
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def lifecycle_filter(app):
        return Lifecycle(app, conf)
    return lifecycle_filter
