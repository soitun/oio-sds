# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2026 OVH SAS
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

import argparse
from datetime import datetime

from oio.cli import ShowOne, flat_dict_from_dict
from oio.cli.common.utils import parse_duration
from oio.xcute.common.job import XcuteJobStatus
from oio.xcute.jobs import CUSTOMER_JOB_TYPES, INTERNAL_JOB_TYPES

# Ordered from most specific to least specific.
# Input formats accept human-readable separators; output formats match job ID prefixes.
_DATE_PREFIX_FORMATS: list[tuple[str, str]] = [
    ("%Y-%m-%dT%H:%M:%S", "%Y%m%d%H%M%S"),
    ("%Y-%m-%dT%H:%M", "%Y%m%d%H%M"),
    ("%Y-%m-%dT%H", "%Y%m%d%H"),
    ("%Y-%m-%d", "%Y%m%d"),
    ("%Y-%m", "%Y%m"),
    ("%Y", "%Y"),
]


class XcuteCommand:
    def __init__(self, *args, **kwargs):
        self.job_types = INTERNAL_JOB_TYPES
        super().__init__(*args, **kwargs)

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def xcute(self):
        xcute_type = getattr(self, "xcute_type", None)
        if xcute_type == "customer":
            return self.app.client_manager.xcute_customer_client
        return self.app.client_manager.xcute_client


class JobListingCommand(XcuteCommand):
    """
    Mixin for xcute commands that list and filter jobs (JobList, JobClean).
    Provides argument parsing helpers shared by both commands.
    """

    DEFAULT_JOB_AGE: int | None = None
    STATUS_CHOICES = XcuteJobStatus.ALL

    def _add_job_listing_arguments(
        self, parser: argparse.ArgumentParser
    ) -> argparse.ArgumentParser:
        """Add common job-listing/filtering arguments shared by JobList and JobClean."""
        parser.add_argument(
            "--date",
            help="Filter jobs with the specified job date (%%Y-%%m-%%dT%%H:%%M:%%S)",
        )
        parser.add_argument(
            "--type",
            choices=self.job_types.keys(),
            help="Filter jobs with the specified job type",
        )
        parser.add_argument(
            "--lock",
            help="Filter jobs with the specified job lock (wildcards allowed)",
        )
        parser.add_argument(
            "--marker",
            metavar="<marker>",
            help="Marker for paging",
        )
        parser.add_argument(
            "--limit",
            metavar="<limit>",
            type=int,
            default=1000,
            help="Limit the number of results (default: 1000)",
        )
        _duration_help = (
            "Accepts a human-readable duration such as '1 year', '3 months', "
            "'2 weeks', '16 days', '5 hours', '10 minutes', "
            "or a plain integer in seconds."
        )
        if self.DEFAULT_JOB_AGE is not None:
            default_days = self.DEFAULT_JOB_AGE // (24 * 3600)
            age_help = (
                f"Minimum age for jobs to be eligible (default: {default_days} days). "
                + _duration_help
            )
        else:
            age_help = "Only list jobs older than this age. " + _duration_help
        parser.add_argument(
            "--age",
            dest="age",
            type=parse_duration,
            metavar="<duration>",
            default=self.DEFAULT_JOB_AGE,
            help=age_help,
        )
        parser.add_argument(
            "--status",
            choices=self.STATUS_CHOICES,
            dest="status",
            action="append",
            help="Filter jobs with the specified job status (repeatable)",
        )
        return parser

    def _build_list_prefix(self, parsed_args: argparse.Namespace) -> str | None:
        if not parsed_args.date:
            return None
        for input_fmt, output_fmt in _DATE_PREFIX_FORMATS:
            try:
                return datetime.strptime(parsed_args.date, input_fmt).strftime(
                    output_fmt
                )
            except ValueError:
                continue
        raise ValueError("Wrong date format")


class CustomerCommand:
    """Extend an XcuteCommand to make it a customer-related command."""

    def __init__(self, *args, **kwargs):
        self.xcute_type = "customer"
        super().__init__(*args, **kwargs)
        self.job_types = CUSTOMER_JOB_TYPES


class XcuteJobStartCommand(XcuteCommand, ShowOne):
    """
    Class holding common parameters for xcute commands starting jobs.
    """

    JOB_CLASS = None

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "--put-on-hold-if-locked",
            default=False,
            help="""
                If the lock is already used,
                put the job on hold until the lock is released.
                """,
            action="store_true",
        )
        return parser

    def get_job_config(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        job_config = self.get_job_config(parsed_args)
        job_info = self.xcute.job_create(
            self.JOB_CLASS.JOB_TYPE,
            job_config=job_config,
            put_on_hold_if_locked=parsed_args.put_on_hold_if_locked,
        )
        return zip(*sorted(flat_dict_from_dict(parsed_args, job_info).items()))


class XcuteRdirCommand(XcuteJobStartCommand):
    """
    Class holding rdir-related parameters.
    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)

        parser.add_argument(
            "--rdir-fetch-limit",
            type=int,
            help=(
                "Maximum number of entries returned in each rdir response. "
                f"(default={self.JOB_CLASS.DEFAULT_RDIR_FETCH_LIMIT})"
            ),
        )
        parser.add_argument(
            "--rdir-timeout",
            type=float,
            help=(
                "Timeout for rdir operations, in seconds. "
                f"(default={self.JOB_CLASS.DEFAULT_RDIR_TIMEOUT})"
            ),
        )

        return parser
