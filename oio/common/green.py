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

import logging
import time
import warnings
from datetime import datetime, timedelta

import eventlet
import eventlet.hubs as eventlet_hubs  # noqa
from eventlet import (  # noqa  # noqa
    GreenPile,
    GreenPool,
    Queue,
    Timeout,
    greenthread,
    patcher,
    sleep,
)
from eventlet.event import Event  # noqa
from eventlet.green import socket, thread, threading  # noqa
from eventlet.green.httplib import (  # noqa
    _UNKNOWN,
    HTTPConnection,
    HTTPResponse,
    HTTPSConnection,
)
from eventlet.queue import Empty, LifoQueue, LightQueue  # noqa
from eventlet.semaphore import Semaphore  # noqa

from oio.common.utils import ratelimit


def eventlet_monkey_patch():
    # XXX: we used to disable "os" monkey-patching here.
    eventlet.monkey_patch()


logging.thread = eventlet.green.thread
logging.threading = threading
logging._lock = logging.threading.RLock()


class OioTimeout(Timeout):
    """Wrapper over eventlet.Timeout with better __str__."""

    msg_prefix = ""

    def __str__(self):
        return "%stimeout %s" % (
            self.__class__.msg_prefix,
            super(OioTimeout, self).__str__(),
        )


class ConnectionTimeout(OioTimeout):
    msg_prefix = "Connection "


class SourceReadTimeout(OioTimeout):
    msg_prefix = "Source read "


class ChunkWriteTimeout(OioTimeout):
    msg_prefix = "Chunk write "


class ChunkReadTimeout(OioTimeout):
    msg_prefix = "Chunk read "


def eventlet_yield():
    """Switch to another eventlet coroutine."""
    sleep(0)


def get_hub():
    return "poll"


def ratelimit_validate_policy(policy):
    """
    Validate a policy. The following rules are checked:
    - Each partition has a positive max_rate.
    - The start date of each partition is 0 or positive.
    - The start date of each partition is lower than 24h.

    An example of a simple policy would be:
    [
        (datetime.timedelta(0), 3),
    ]

    Which would be a policy to have a constant max_rate of 3. A more complex
    policy would be:
    [
        (datetime.timedelta(0, 1800), 10),  #  0h30 to  6h45
        (datetime.timedelta(0, 24300), 2),  #  6h45 to  9h45
        (datetime.timedelta(0, 35100), 5),  #  9h45 to 15h30
        (datetime.timedelta(0, 55800), 3),  # 15h30 to 20h00
        (datetime.timedelta(0, 72000), 8),  # 20h00 to  0h30
    ]

    :param policy: A list containing the policy that follows the
                   aforementioned description.
    :type policy: `list`
    :raises: `ValueError` if one of the rules is not respected.
    """
    if not policy:
        raise ValueError("Policy must contain at least one rate")

    min_time = timedelta(0)
    max_time = timedelta(hours=24)

    for entry in policy:
        if len(entry) < 2:
            raise ValueError("Ratelimit entries must be 2-tuples")
        if entry[0] < min_time:
            raise ValueError("Start time cannot be negative")
        if entry[0] >= max_time:
            raise ValueError("Start time cannot be more than 24 hours")
        if entry[1] < 0:
            raise ValueError("Rate must be zero or positive")

    policy.sort()
    return True


def ratelimit_function_curr_rate(curr_date, policy):
    """
    Given a validated policy and a datetime, return the applicable max_rate

    :param curr_date: The current date
    :type curr_date datetime
    :param policy: An array representing a validated policy
    :return: The applicable max_rate (elements per second)
    """
    curr_partition = policy[-1]
    # We have a partition, first occurrence is the only one.
    if len(policy) > 1:
        for partition in policy:
            if (curr_date - partition[0]).date() < curr_date.date():
                break
            curr_partition = partition
    else:
        curr_partition = policy[0]

    return curr_partition[1]


def ratelimit_function_next_rate(curr_date, policy):
    """
    Given a current date and a policy, calculate the date at which the next
    rate change is scheduled.

    (Could be useful if the rate limited operation is fast, and as such we
    would want to cache the next rate date so that instead of selecting the
    rate each op, we'd just compare to a timestamp and return a cached value,
    which in the current implementation would make it go from a for loop with
    several comparisons to about a single comparison)

    :param curr_date: The current datetime
    :type curr_date: `datetime`
    :param policy: A list representing a validated policy.
    :returns: the next scheduled rate and the `datetime` object for the next
              scheduled rate change.
    """
    next_day = False
    for partition in policy:
        curr_partition = partition
        if (curr_date - partition[0]).date() < curr_date.date():
            break
    else:
        curr_partition = policy[0]
        next_day = True
    next_date = datetime(curr_date.year, curr_date.month, curr_date.day)
    next_date += curr_partition[0]
    if next_day:
        next_date += timedelta(days=1)
    return curr_partition[1], next_date


def ratelimit_policy_from_string(policy_str):
    """
    :rtype: `list` of 2-tuples with a `datetime.timedelta` and an integer.
    """
    policy = list()
    if ";" not in policy_str:
        try:
            td = timedelta(0)
            rate = int(policy_str)
        except ValueError as err:
            raise ValueError("Unparsable rate limit '%s': %s" % (policy_str, err))
        policy.append((td, rate))
        return policy
    changes = policy_str.split(";")
    for change in changes:
        try:
            time_str, rate_str = change.split(":", 1)
            hour_str, min_str = time_str.split("h", 1)
            td = timedelta(hours=int(hour_str), minutes=int(min_str))
            rate = int(rate_str)
        except ValueError as err:
            raise ValueError("Unparsable rate change '%s': %s" % (change, err))
        policy.append((td, rate))
    policy.sort()
    return policy


def ratelimit_function_build(policy):
    """
    Given a policy, return a customized wrapper around ratelimit for a
    time aware rate limiter.
    :param policy: An array representing a rate limiting policy as described
                    by ratelimit_validate_policy.
    :return: A callable function similar in signature to ratelimit but that
             ignores all parameters other than the first one.
    """
    if isinstance(policy, str):
        policy = ratelimit_policy_from_string(policy)
    ratelimit_validate_policy(policy)

    def _ratelimiter(run_time, _max_rate=None, increment=1, rate_buffer=5):
        """
        The ratelimit wrapper that takes into account the custom policy, and
        ignores all the other parameters other than run_time
        :param run_time: The last time the operation was executed in seconds.
        """
        time_time = time.time()
        curr_date = datetime.fromtimestamp(time_time)

        return ratelimit(
            run_time,
            ratelimit_function_curr_rate(
                curr_date=curr_date, policy=_ratelimiter.policy
            ),
            increment,
            rate_buffer,
            time_time,
        )

    _ratelimiter.policy = policy

    return _ratelimiter


class ContextPool(GreenPool):
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        for coroutine in list(self.coroutines_running):
            coroutine.kill()


# We don't really want to duplicate swift's code, but we don't want to add it
# as a dependency either. Let's just try to import it, and fallback on the
# local implementation.
try:
    from swift.common.utils import Watchdog, WatchdogTimeout
except ImportError:

    class Watchdog(object):
        """
        Implements a watchdog to efficiently manage concurrent timeouts.
        Compared to eventlet.timeouts.Timeout, it reduces the number of context
        switching in eventlet by avoiding to schedule actions (throw an
        Exception),
        then unschedule them if the timeouts are cancelled.
        1. at T+0, request timeout(10)
            => watchdog greenlet sleeps 10 seconds
        2. at T+1, request timeout(15)
            => the timeout will expire after the current, no need to wake up
               the watchdog greenlet
        3. at T+2, request timeout(5)
            => the timeout will expire before the first timeout, wake up the
               watchdog greenlet to calculate a new sleep period
        4. at T+7, the 3rd timeout expires
            => the exception is raised, then the greenlet watchdog sleep(3) to
               wake up for the 1st timeout expiration
        """

        def __init__(self):
            # key => (timeout, timeout_at, caller_greenthread, exception)
            self._timeouts = dict()
            self._evt = Event()
            self._next_expiration = None
            self._run_gth = None

        def start(self, timeout, exc, timeout_at=None):
            """
            Schedule a timeout action
            :param timeout: duration before the timeout expires
            :param exc: exception to throw when the timeout expire, must
                        inherit from eventlet.timeouts.Timeout
            :param timeout_at: allow to force the expiration timestamp
            :return: id of the scheduled timeout, needed to cancel it
            """
            if self._run_gth is None:
                raise ValueError("Watchdog green thread not started!")
            if not timeout_at:
                timeout_at = time.time() + timeout
            gth = eventlet.greenthread.getcurrent()
            timeout_definition = (timeout, timeout_at, gth, exc)
            key = id(timeout_definition)
            self._timeouts[key] = timeout_definition
            # Wake up the watchdog loop only when there is a new shorter
            # timeout
            if self._next_expiration is None or self._next_expiration > timeout_at:
                # There could be concurrency on .send(), so wrap it in a try
                try:
                    if not self._evt.ready():
                        self._evt.send()
                except AssertionError:
                    pass
            return key

        def stop(self, key):
            """
            Cancel a scheduled timeout
            :param key: timeout id, as returned by start()
            """
            try:
                if key in self._timeouts:
                    del self._timeouts[key]
            except KeyError:
                pass

        def spawn(self):
            """
            Start the watchdog greenthread.
            """
            if self._run_gth is None:
                self._run_gth = eventlet.spawn(self.run)

        def run(self):
            while True:
                self._run()

        def _run(self):
            now = time.time()
            self._next_expiration = None
            if self._evt.ready():
                self._evt.reset()
            for k, (timeout, to_at, gth, exc) in list(self._timeouts.items()):
                if to_at <= now:
                    try:
                        if k in self._timeouts:
                            del self._timeouts[k]
                    except KeyError:
                        pass
                    e = exc()
                    e.seconds = timeout
                    eventlet.hubs.get_hub().schedule_call_global(0, gth.throw, e)
                else:
                    if self._next_expiration is None or self._next_expiration > to_at:
                        self._next_expiration = to_at
            if self._next_expiration is None:
                sleep_duration = self._next_expiration
            else:
                sleep_duration = self._next_expiration - now
            self._evt.wait(sleep_duration)

    class WatchdogTimeout(object):
        """
        Context manager to schedule a timeout in a Watchdog instance
        """

        def __init__(self, watchdog, timeout, exc, timeout_at=None):
            """
            Schedule a timeout in a Watchdog instance
            :param watchdog: Watchdog instance
            :param timeout: duration before the timeout expires
            :param exc: exception to throw when the timeout expire, must
                        inherit from eventlet.timeouts.Timeout
            :param timeout_at: allow to force the expiration timestamp
            """
            self.watchdog = watchdog
            self.key = watchdog.start(timeout, exc, timeout_at=timeout_at)

        def __enter__(self):
            pass

        def __exit__(self, type, value, traceback):
            self.watchdog.stop(self.key)


__WATCHDOG = None


def get_watchdog(called_from_main_application=False):
    """
    Get the global Watchdog instance.

    This method should not be called from anywhere except from the main
    method of your program. Prefer passing the Watchdog instance to the
    constructor of any class which needs it. If you call it anyway, your
    code won't be usable by other applications which have their own
    Watchdog instance (e.g. swift).
    """
    if not called_from_main_application:
        warnings.simplefilter("once")
        warnings.warn(
            "Calling get_watchdog() is a bad idea. The watchdog "
            "instance should be passed as parameter.",
            stacklevel=2,
        )
    global __WATCHDOG
    if __WATCHDOG is None:
        __WATCHDOG = Watchdog()
        __WATCHDOG.spawn()
    return __WATCHDOG
