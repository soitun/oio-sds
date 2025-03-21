# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2024 OVH SAS
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

import uuid

from tests.functional.cli import CliTestCase


class ElectionTest(CliTestCase):
    """Functional tests for containers."""

    NAME = uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.openio("container create " + cls.NAME)

    @classmethod
    def tearDownClass(cls):
        cls.openio("container delete " + cls.NAME)
        super().tearDownClass()

    def test_election_leave(self):
        self.openio("election leave meta2 " + self.NAME)

    def test_election_ping(self):
        self.openio("election ping meta2 " + self.NAME)

    def test_election_status(self):
        self.openio("election status --timeout 45.0 meta2 " + self.NAME)

    def test_election_debug(self):
        self.openio("election debug meta2 " + self.NAME)
