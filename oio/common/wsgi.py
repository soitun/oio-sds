# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

from gunicorn.app.base import BaseApplication
from gunicorn.glogging import Logger
from werkzeug.wrappers import Request, Response
from werkzeug.utils import escape
from werkzeug.exceptions import HTTPException, InternalServerError, \
    ServiceUnavailable, BadRequest

from oio.common.exceptions import ServiceBusy
from oio.common.utils import CPU_COUNT
from oio.common.configuration import read_conf
from oio.common.logger import get_logger


class Application(BaseApplication):
    access_log_fmt = '%(bind0)s %(h)s:%({remote}p)s %(m)s %(s)s %(D)s ' + \
                     '%(B)s %(l)s %({x-oio-req-id}i)s %(U)s?%(q)s'

    def __init__(self, app, conf, logger_class=None):
        self.conf = conf
        self.application = app
        self.logger_class = logger_class
        super(Application, self).__init__()

    def load_config(self):
        bind = '%s:%s' % (self.conf.get('bind_addr', '127.0.0.1'),
                          self.conf.get('bind_port', '8000'))
        self.cfg.set('bind', bind)
        self.cfg.set('backlog', self.conf.get('backlog', 2048))
        self.cfg.set('workers', self.conf.get('workers', CPU_COUNT))
        self.cfg.set('worker_class', self.conf.get('worker_class', 'eventlet'))
        self.cfg.set('worker_connections', self.conf.get(
            'worker_connections', 1000))
        self.cfg.set('syslog_prefix', self.conf.get('syslog_prefix', ''))
        log_addr = self.conf.get('log_address', '/dev/log')
        if '://' not in log_addr:
            log_addr = "unix://" + log_addr
        self.cfg.set('syslog_addr', log_addr)
        self.cfg.set('syslog', True)
        self.cfg.set('keepalive', 30)
        self.cfg.set('access_log_format', self.conf.get('access_log_format',
                                                        self.access_log_fmt))
        self.cfg.set('proc_name',
                     self.conf.get('proc_name',
                                   self.application.__class__.__name__))
        self.cfg.set('logger_class', self.logger_class)

    def load(self):
        return self.application


class ServiceLogger(Logger):

    def atoms(self, resp, req, environ, request_time):
        atoms = super(ServiceLogger, self).atoms(resp, req, environ,
                                                 request_time)
        # We may bind on several addresses and ports but I don't
        # know how to identify for which one we are logging
        index = 0
        for bind in self.cfg.bind:
            atoms['bind%d' % index] = bind
            index += 1
        return atoms

    def access(self, resp, req, environ, request_time):
        # do not log status requests
        if environ.get('PATH_INFO', '/') != '/status':
            super(ServiceLogger, self).access(resp, req, environ, request_time)


class WerkzeugApp(object):

    def __init__(self, url_map=None, logger=None):
        self.url_map = url_map
        self.logger = logger or get_logger(None)

    def dispatch_request(self, req):
        adapter = self.url_map.bind_to_environ(req.environ)
        try:
            endpoint, params = adapter.match()
            resp = getattr(self, 'on_' + endpoint)(req, **params)
        except HTTPException as exc:
            resp = exc
        except ServiceBusy as exc:
            if self.logger:
                self.logger.error(str(exc))
            resp = ServiceUnavailable(
                "Could not satisfy the request: %s" % exc)
        except ValueError as exc:
            resp = BadRequest(description=str(exc))
        except Exception as exc:
            if self.logger:
                self.logger.exception('ERROR Unhandled exception in request')
            resp = InternalServerError('Unmanaged error: %s' % exc)
        if isinstance(resp, HTTPException) and not resp.response:
            resp.response = Response(escape(resp.description), resp.code)
        return resp

    def wsgi_app(self, environ, start_response):
        req = Request(environ)
        resp = self.dispatch_request(req)
        return resp(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)


def init_request_processor(conf_file, app_name, app_factory, *args, **kwargs):
    conf = read_conf(conf_file, app_name)
    if 'logger' in kwargs:
        logger = kwargs.pop('logger')
    else:
        logger = get_logger(conf, app_name,
                            verbose=kwargs.pop('verbose', False))
    app = app_factory(conf)
    return (app, conf, logger, app_name)
