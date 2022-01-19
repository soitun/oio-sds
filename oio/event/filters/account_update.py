# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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


from oio.common.constants import REQID_HEADER, CONNECTION_TIMEOUT, \
    READ_TIMEOUT, HIDDEN_ACCOUNTS
from oio.common.exceptions import ClientException, OioException, OioTimeout
from oio.common.utils import request_id
from oio.event.evob import Event, EventError, EventTypes
from oio.event.filters.base import Filter
from oio.common.configuration import load_namespace_conf


CONTAINER_EVENTS = [
    EventTypes.CONTAINER_STATE,
    EventTypes.CONTAINER_NEW,
    EventTypes.CONTAINER_DELETED]


class AccountUpdateFilter(Filter):
    """
    Fill in the account service with information coming from meta2 services
    (number of objects in a container, etc.) and meta1 services
    (a container has been created or removed).
    """

    def init(self):
        self.account = self.app_env['account_client']
        self.connection_timeout = float(self.conf.get('connection_timeout',
                                                      CONNECTION_TIMEOUT))
        self.read_timeout = float(self.conf.get('read_timeout',
                                                READ_TIMEOUT))
        try:
            self.region = self.conf.get('ns_conf').get('region')
        except KeyError:
            raise OioException("Missing region key in namespace conf")

    def process(self, env, beanstalkd, cb):
        event = Event(env)
        headers = {
            REQID_HEADER: event.reqid or request_id('account-update-')
        }

        try:
            if event.env.get('url').get('account') in HIDDEN_ACCOUNTS:
                pass
            elif event.event_type in CONTAINER_EVENTS:
                mtime = event.when / 1000000.0  # convert to seconds
                data = event.data
                url = event.env.get('url')
                body = dict()
                body['bucket'] = data.get('bucket')
                body['region'] = self.region
                for k1, k2 in (('objects', 'object-count'),
                               ('bytes', 'bytes-count')):
                    body[k1] = data.get(k2, 0)
                for key in ('bytes-details', 'objects-details'):
                    value = data.get(key)
                    if value:
                        body[key] = value
                if event.event_type in (EventTypes.CONTAINER_STATE,
                                        EventTypes.CONTAINER_NEW):
                    body['mtime'] = mtime
                elif event.event_type == EventTypes.CONTAINER_DELETED:
                    body['dtime'] = mtime
                self.account.container_update(
                    url.get('account'), url.get('user'), body,
                    connection_timeout=self.connection_timeout,
                    read_timeout=self.read_timeout, headers=headers)
            elif event.event_type == EventTypes.ACCOUNT_SERVICES:
                url = event.env.get('url')
                if isinstance(event.data, list):
                    # Legacy format: list of services
                    new_services = event.data
                else:
                    # New format: dictionary with new and deleted services
                    new_services = event.data.get('services') or list()
                m2_services = [x for x in new_services
                               if x.get('type') == 'meta2']
                if not m2_services:
                    # No service in charge, container has been deleted.
                    # But we will also receive a CONTAINER_DELETED event,
                    # so we don't have anything to do here.
                    pass
                else:
                    try:
                        self.account.account_create(
                            url.get('account'),
                            connection_timeout=self.connection_timeout,
                            read_timeout=self.read_timeout, headers=headers)
                    except OioTimeout as exc:
                        # The account will be autocreated by the next event,
                        # just warn and continue.
                        self.logger.warning(
                            'Failed to create account %s (reqid=%s): %s',
                            url.get('account'), headers[REQID_HEADER], exc)
        except OioTimeout as exc:
            msg = 'account update failure: %s' % str(exc)
            resp = EventError(event=Event(env), body=msg)
            return resp(env, beanstalkd, cb)
        except ClientException as exc:
            if (exc.http_status == 409
                    and "No update needed" in exc.message):
                self.logger.info(
                    "Discarding event %s (job_id=%s, reqid=%s): %s",
                    event.event_type, event.job_id,
                    headers[REQID_HEADER], exc.message)
            else:
                msg = 'account update failure: %s' % str(exc)
                resp = EventError(event=Event(env), body=msg)
                return resp(env, beanstalkd, cb)
        return self.app(env, beanstalkd, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    ns_conf = load_namespace_conf(conf.get('namespace'), failsafe=True)
    conf['ns_conf'] = ns_conf

    def account_filter(app):
        return AccountUpdateFilter(app, conf)
    return account_filter
