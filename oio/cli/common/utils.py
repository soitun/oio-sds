# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023-2026 OVH SAS
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

from argparse import Action


class KeyValueAction(Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is None:
            setattr(namespace, self.dest, {})

        if "=" in values:
            getattr(namespace, self.dest, {}).update([values.split("=", 1)])
        else:
            getattr(namespace, self.dest, {}).pop(values, None)


class ValueFormatStoreTrueAction(Action):
    """Same as 'store_true', but also set 'formatter' field to 'value'"""

    def __init__(self, option_strings, dest, nargs=0, **kwargs):
        super(ValueFormatStoreTrueAction, self).__init__(
            option_strings, dest, nargs=nargs, **kwargs
        )

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, True)
        setattr(namespace, "formatter", "value")


class ValueCheckStoreTrueAction(Action):
    """Same as 'store_true', but also set 'aggregated' field to 'true'"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        setattr(namespace, "check", True)


_DURATION_UNITS: dict[str, int] = {
    "year": 365 * 24 * 3600,
    "month": 30 * 24 * 3600,
    "week": 7 * 24 * 3600,
    "day": 24 * 3600,
    "hour": 3600,
    "minute": 60,
    "second": 1,
}


def parse_duration(value: str) -> int:
    """
    Parse a human-readable duration string into seconds.

    Accepted formats: "<n> year[s]", "<n> month[s]", "<n> week[s]",
    "<n> day[s]", "<n> hour[s]", "<n> minute[s]", "<n> second[s]".
    A plain integer is also accepted and treated as seconds.
    """
    import re

    value = value.strip()
    try:
        return int(value)
    except ValueError:
        pass
    m: re.Match[str] | None = re.fullmatch(
        r"(\d+)\s+(year|month|week|day|hour|minute|second)s?", value, re.IGNORECASE
    )
    if not m:
        from argparse import ArgumentTypeError

        raise ArgumentTypeError(
            f"Invalid duration {value!r}. "
            "Expected e.g. '3 months', '1 week', '16 days', '5 hours', "
            "'10 minutes', '30 seconds'."
        )
    return int(m.group(1)) * _DURATION_UNITS[m.group(2).lower()]


def format_detailed_scores(srv):
    return " ".join(
        [
            f"{k[len('scores') :]}={v}"
            for k, v in srv.get("scores", {}).items()
            if k.startswith("score.")
        ]
    )
