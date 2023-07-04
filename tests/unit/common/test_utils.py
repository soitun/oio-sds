# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
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

import unittest

from oio.common.constants import (
    CHUNK_SUFFIX_CORRUPT,
    CHUNK_SUFFIX_PENDING,
    MAX_STRLEN_CHUNKID,
    MIN_STRLEN_CHUNKID,
)
from oio.common.utils import (
    is_chunk_id_valid,
    oio_versionid_to_str_versionid,
    rotate_list,
    str_versionid_to_oio_versionid,
)
from tests.utils import random_id


# pylint: disable=protected-access
class TestUtils(unittest.TestCase):
    def test_valid_chunk_id(self):
        for n in range(MIN_STRLEN_CHUNKID, MAX_STRLEN_CHUNKID + 1):
            chunk_id = random_id(n)
            self.assertTrue(is_chunk_id_valid(chunk_id))

    def test_chunk_id_with_wrong_paths(self):
        # All chunks following chunk_ids are incorrect
        # False should be returned if the chunk_id is not valid

        chunk_id = random_id(MIN_STRLEN_CHUNKID - 1)
        self.assertFalse(is_chunk_id_valid(chunk_id))

        chunk_id = random_id(MAX_STRLEN_CHUNKID + 1)
        self.assertFalse(is_chunk_id_valid(chunk_id))

        chunk_id = random_id(MAX_STRLEN_CHUNKID) + CHUNK_SUFFIX_PENDING
        self.assertFalse(is_chunk_id_valid(chunk_id))

        chunk_id = random_id(MAX_STRLEN_CHUNKID) + CHUNK_SUFFIX_CORRUPT
        self.assertFalse(is_chunk_id_valid(chunk_id))

        chunk_id = random_id(MIN_STRLEN_CHUNKID) + CHUNK_SUFFIX_PENDING
        self.assertFalse(is_chunk_id_valid(chunk_id))

        chunk_id = random_id(MIN_STRLEN_CHUNKID) + CHUNK_SUFFIX_CORRUPT
        self.assertFalse(is_chunk_id_valid(chunk_id))

        chunk_id = random_id(MAX_STRLEN_CHUNKID)[:-1] + "G"  # not hexdigit
        self.assertFalse(is_chunk_id_valid(chunk_id))

    def test_rotate_list(self):
        mylist = [1, 2, 3, 4]
        self.assertListEqual([2, 3, 4, 1], rotate_list(mylist))
        self.assertListEqual([4, 1, 2, 3], rotate_list(mylist, shift=-1))
        self.assertListEqual([3, 4, 1, 2], rotate_list(mylist, shift=2))
        rotate_list(mylist, inplace=True)
        self.assertListEqual([2, 3, 4, 1], mylist)

    def test_str_versionid_to_oio_versionid(self):
        self.assertEqual(None, str_versionid_to_oio_versionid("null"))
        self.assertEqual(123456, str_versionid_to_oio_versionid("0.123456"))

    def test_oio_versionid_to_str_versionid(self):
        self.assertEqual("null", oio_versionid_to_str_versionid(None))
        self.assertEqual("0.123456", oio_versionid_to_str_versionid(123456))
