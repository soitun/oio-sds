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


from oio.crawler.common.crawler import Crawler, CrawlerWorker
from oio.crawler.rawx.chunk_wrapper import ChunkWrapper, is_success, is_error


class RawxWorker(CrawlerWorker):
    """
    Rawx Worker responsible for a single volume.
    """

    SERVICE_TYPE = 'rawx'

    def __init__(self, conf, volume_path, logger=None, api=None):
        super(RawxWorker, self).__init__(conf, volume_path)

    def cb(self, status, msg):
        if is_success(status):
            pass
        elif is_error(status):
            self.logger.warning('Rawx volume_id=%s handling failure: %s',
                                self.volume_id, msg)
        else:
            self.logger.warning('Rawx volume_id=%s status=%d msg=%s',
                                self.volume_id, status, msg)

    def process_path(self, path):

        chunk = ChunkWrapper({})
        chunk.volume_id = self.volume_id
        chunk.volume_path = self.volume
        chunk.chunk_id = path.rsplit('/', 1)[-1]
        chunk.chunk_path = path

        try:
            self.pipeline(chunk.env, self.cb)
            self.successes += 1
        except Exception:
            self.errors += 1
            self.logger.exception('Failed to apply pipeline')
        self.scanned_since_last_report += 1


class RawxCrawler(Crawler):

    SERVICE_TYPE = 'rawx'

    def __init__(self, conf, conf_file=None, **kwargs):
        super(RawxCrawler, self).__init__(conf, conf_file=conf_file)

    def _init_volume_workers(self):
        self.volume_workers = [
            RawxWorker(self.conf, volume, logger=self.logger, api=self.api)
            for volume in self.volumes]
