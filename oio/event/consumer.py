# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

import os
import signal
import sys
import time

import greenlet

from oio.account.client import AccountClient
from oio.common.easy_value import float_value, int_value
from oio.common.exceptions import ClientException, ExplicitBury, OioNetworkException
from oio.common.green import Timeout, eventlet, get_watchdog, greenthread
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.statsd import get_statsd
from oio.common.utils import drop_privileges
from oio.event.beanstalk import Beanstalk, ConnectionError, ResponseError
from oio.event.evob import is_retryable, is_success
from oio.event.loader import loadhandlers
from oio.rdir.client import RdirClient

SLEEP_TIME = 1
ACCOUNT_SERVICE_TIMEOUT = 60
ACCOUNT_SERVICE = "account"
DEFAULT_TUBE = "oio"

BEANSTALK_RECONNECTION = 2.0
# default release delay (in seconds)
RELEASE_DELAY = 15


def _eventlet_stop(client, server, beanstalk):
    try:
        try:
            client.wait()
        finally:
            beanstalk.close()
    except greenlet.GreenletExit:
        pass
    except Exception:
        greenthread.kill(server, *sys.exc_info())


class StopServe(Exception):
    pass


class Worker(object):
    SIGNALS = [getattr(signal, "SIG%s" % x) for x in "HUP QUIT INT TERM CHLD".split()]

    def __init__(self, ppid, conf, logger):
        self.ppid = ppid
        self.conf = conf
        self.started = False
        self.aborted = False
        self.alive = True
        self.logger = logger

    @property
    def pid(self):
        return os.getpid()

    def run(self):
        raise NotImplementedError()

    def init(self):
        drop_privileges(self.conf.get("user", "openio"))

        self.init_signals()

        self.started = True
        # main loop
        self.run()

    def init_signals(self):
        [signal.signal(s, signal.SIG_DFL) for s in self.SIGNALS]
        signal.signal(signal.SIGQUIT, self.handle_quit)
        signal.signal(signal.SIGTERM, self.handle_exit)
        signal.signal(signal.SIGINT, self.handle_quit)
        signal.siginterrupt(signal.SIGTERM, False)

    def handle_exit(self, sig, frame):
        self.alive = False

    def handle_quit(self, sig, frame):
        self.alive = False
        eventlet.sleep(0.1)
        sys.exit(0)

    def parent_alive(self):
        if self.ppid != os.getppid():
            self.logger.warn("parent changed, shutting down")
            return False
        return True


def _stop(client, server):
    try:
        client.wait()
    except greenlet.GreenletExit:
        pass
    except Exception:
        greenthread.kill(server, *sys.exc_info())


class EventWorker(Worker):
    def __init__(self, *args, **kwargs):
        super(EventWorker, self).__init__(*args, **kwargs)
        # Environment that will be passed between Handler an Filter instances
        self.app_env = {"logger": self.logger}
        self.concurrency = 1
        self.graceful_timeout = 1
        self.tube = None

        template = self.conf.get("log_request_format")
        if template is not None:
            self.logger_request = get_logger(self.conf, name="request", fmt=template)
        else:
            self.logger_request = None

        self.statsd = get_statsd(conf=self.conf)

    def init(self):
        self.concurrency = int_value(self.conf.get("concurrency"), 10)
        self.tube = self.conf.get("tube", DEFAULT_TUBE)
        acct_refresh_interval = float_value(
            self.conf.get("acct_refresh_interval"), 3600.0
        )
        rdir_refresh_interval = float_value(
            self.conf.get("rdir_refresh_interval"), 3600.0
        )
        self.app_env["account_client"] = AccountClient(
            self.conf,
            logger=self.logger,
            refresh_delay=acct_refresh_interval,
            pool_connections=3,  # 1 account, 1 proxy, 1 extra
        )
        rdir_kwargs = {k: v for k, v in self.conf.items() if k.startswith("rdir_")}
        self.app_env["rdir_client"] = RdirClient(
            self.conf,
            logger=self.logger,
            pool_maxsize=self.concurrency,  # 1 cnx per greenthread per host
            cache_duration=rdir_refresh_interval,
            **rdir_kwargs,
        )
        self.app_env["watchdog"] = get_watchdog(called_from_main_application=True)

        if "handlers_conf" not in self.conf:
            raise ValueError("'handlers_conf' path not defined in conf")
        self.handlers = loadhandlers(
            self.conf.get("handlers_conf"), global_conf=self.conf, app=self
        )

        for opt in ("acct_update", "rdir_update", "retries_per_second", "batch_size"):
            if opt in self.conf:
                self.logger.warn("Deprecated option: %s", opt)

        super(EventWorker, self).init()

    def notify(self):
        """TODO"""
        pass

    def safe_decode_job(self, job_id, data):
        try:
            env = json.loads(data)
            env["job_id"] = job_id
            return env
        except json.JSONDecodeError as exc:
            self.logger.warn("Failed to decode job %s: %s", job_id, exc)
            return None
        except Exception:
            self.logger.exception("Failed to decode job %s", job_id)
            return None

    def run(self):
        coros = []
        queue_url = self.conf.get("queue_url", "beanstalk://127.0.0.1:11300")

        server_gt = greenthread.getcurrent()

        for url in queue_url.split(";"):
            for _ in range(self.concurrency):
                beanstalk = Beanstalk.from_url(url)
                gt = eventlet.spawn(self.handle, beanstalk)
                gt.link(_eventlet_stop, server_gt, beanstalk)
                coros.append(gt)
                beanstalk, gt = None, None

        while self.alive:
            self.notify()
            try:
                eventlet.sleep(1.0)
            except AssertionError:
                self.alive = False
                break

        self.notify()
        try:
            with Timeout(self.graceful_timeout) as t:
                [c.kill(StopServe()) for c in coros]
                [c.wait() for c in coros]
        except Timeout as te:
            if te != t:
                raise
            [c.kill() for c in coros]

    def handle(self, beanstalk):
        conn_error = False
        try:
            if self.tube:
                beanstalk.use(self.tube)
                beanstalk.watch(self.tube)
            while True:
                try:
                    job_id, data = beanstalk.reserve()
                    if conn_error:
                        self.logger.warn("beanstalk reconnected")
                        conn_error = False
                except ConnectionError:
                    if not conn_error:
                        self.logger.warn("beanstalk connection error")
                        conn_error = True
                    eventlet.sleep(BEANSTALK_RECONNECTION)
                    continue
                event = self.safe_decode_job(job_id, data)
                if not event:
                    self.logger.warn("Burying event %s: %s", job_id, "malformed")
                    beanstalk.bury(job_id)
                else:
                    try:
                        self.process_event(job_id, event, beanstalk)
                    except (ClientException, OioNetworkException) as exc:
                        self.logger.warn(
                            "Burying event %s (%s): %s", job_id, event.get("event"), exc
                        )
                        beanstalk.bury(job_id)
                    except ExplicitBury:
                        self.logger.info(
                            "Burying event %s (%s)", job_id, event.get("event")
                        )
                        beanstalk.bury(job_id)
                    except StopServe:
                        self.logger.info(
                            "Releasing event %s (%s): stopping",
                            job_id,
                            event.get("event"),
                        )
                        beanstalk.release(job_id)
                    except Exception:
                        self.logger.exception("Burying event %s: %s", job_id, event)
                        beanstalk.bury(job_id)
        except StopServe:
            pass

    def log_and_statsd(self, start, status, _extra):
        default_extra = {
            "request_id": "-",
            "tube": "-",
            "topic": "-",
            "event": "-",
        }

        extra = {**default_extra, **_extra}

        extra["duration"] = time.monotonic() - start
        extra["status"] = status
        if self.logger_request is not None:
            self.logger_request.info("", extra=extra)

        event = extra["event"].replace(".", "-")
        self.statsd.timing(
            f"openio.event.{extra['tube']}.{event}.{extra['status']}.duration",
            extra["duration"] * 1000,
        )

    def process_event(self, job_id, event, beanstalk):
        start = time.monotonic()

        replacements = {
            "request_id": event.get("request_id"),
            "tube": self.tube,
            "topic": self.tube,
            "event": event.get("event"),
        }

        handler = self.get_handler(event)
        if not handler:
            self.logger.warn("no handler found for %r" % event)
            self.log_and_statsd(start, 404, replacements)
            beanstalk.delete(job_id)
            return

        event["queue_connector"] = beanstalk

        def cb(status, msg, **kwargs):
            if is_success(status):
                try:
                    beanstalk.delete(job_id)
                except ResponseError as err:
                    self.logger.warn(
                        "Job %s succeeded but was not deleted: %s", job_id, err
                    )
            elif is_retryable(status):
                self.logger.warn(
                    "event %s handling failure (release with delay): %s", job_id, msg
                )
                try:
                    beanstalk.release(job_id, delay=RELEASE_DELAY)
                except ResponseError as err:
                    self.logger.error(
                        "Job %s failed and could not be rescheduled: %s", job_id, err
                    )
            else:
                self.logger.warn("event %s handling failure (bury): %s", job_id, msg)
                try:
                    beanstalk.bury(job_id)
                except ResponseError as err:
                    self.logger.error(
                        "Job %s failed and could not be buried: %s", job_id, err
                    )

            self.log_and_statsd(start, status, replacements)

        handler(event, cb)

    def get_handler(self, event):
        return self.handlers.get(event.get("event"), None)
