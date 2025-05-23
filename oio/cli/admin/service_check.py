# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2025 OVH SAS
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

from oio.cli import Lister
from oio.cli.admin.common import MultipleServicesCommandMixin
from oio.cli.admin.item_check import ItemCheckCommand
from oio.crawler.integrity import Target

CID_PREFIX_COUNT = 65536


class BaseCheckCommand(Lister):
    """
    Base class for all check commands.
    """

    columns = ("Status", "Errors")
    SRV = None

    def __init__(self, *args, **kwargs):
        super(BaseCheckCommand, self).__init__(*args, **kwargs)
        self._zkcnxstr = None
        self.catalog = None
        self.live = None

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(BaseCheckCommand, self).get_parser(prog_name)
        parser.add_argument(
            "--catalog", type=str, help="Load service catalog from file."
        )
        return parser

    def load_catalog(self, parsed_args):
        # Load the live services
        self.live = self.load_live_services()
        self.live = tuple(self.live)
        self.logger.info("Catalog: loaded %d services", len(self.live))
        for type_, host, port, score in self.live:
            self.logger.debug("live> %s %s %d score=%d", type_, host, port, score)

        # Load a catalog of expected services
        self.catalog = list()
        if parsed_args.catalog:
            self.catalog = self.load_catalog_from_file(parsed_args.catalog)
        else:
            for type_, host, port, score in self.live:
                self.catalog.append((type_, host, port, score))
        self.catalog = tuple(self.catalog)
        self.logger.info("Catalog: loaded %d services", len(self.catalog))
        for type_, host, port, score in self.catalog:
            self.logger.debug("catalog> %s %s %d", type_, host, port)

    @staticmethod
    def filter_services(srv, srvtype):
        for type_, host, port, score in srv:
            if type_ == srvtype:
                yield type_, host, port, score

    def load_live_services(self):
        client = self.app.client_manager.conscience
        for srvtype in client.service_types():
            for srv in client.all_services(srvtype):
                ip, port = srv["addr"].split(":")
                yield str(srvtype), str(ip), int(port), int(srv["score"])

    def load_catalog_from_file(self, path):
        with open(path, "r") as fin:
            for line in fin:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    type_, host, port = line.split()
                    yield str(type_), str(host), int(port), 0
                except Exception as ex:
                    self.logger.exception("Failed to decode line: %s", ex)

    def zookeeper(self):
        if self._zkcnxstr:
            return self._zkcnxstr

        conf = self.app.client_manager.sds_conf
        self._zkcnxstr = conf.get("zookeeper.%s" % self.SRV, conf.get("zookeeper"))
        return self._zkcnxstr

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        self.load_catalog(parsed_args)
        return self.columns, self._take_action(parsed_args)


class Meta0Check(BaseCheckCommand):
    """
    Check the state of the meta0 services.

    Check registered instances in zookeeper.
    """

    SRV = "meta0"

    def _take_action(self, parsed_args):
        from oio.zk.client import get_connected_handles, get_meta0_paths

        self.logger.debug("Checking meta0 services")

        # TODO: tcp touch to the meta0 services

        # check they are registered in the ZK
        for zh in get_connected_handles(self.zookeeper(), logger=self.logger):
            for path in get_meta0_paths(zh, self.app.options.ns):
                try:
                    zk_registered = set()
                    for node in zh.get().get_children(path):
                        addr, _ = zh.get().get(path + "/" + node)
                        if addr is not None:
                            addr = addr.decode("utf-8")
                        zk_registered.add(addr)
                    known = set()

                    for _, host, port, score in self.filter_services(
                        self.catalog, "meta0"
                    ):
                        if score == 0:
                            self.success = False
                            yield ("Warn", "%s:%d is down" % (host, port))
                        known.add("%s:%d" % (host, port))
                    self.logger.info(
                        "meta0 known=%d zk_registered=%d",
                        len(known),
                        len(zk_registered),
                    )

                    for item in zk_registered - known:
                        self.success = False
                        yield ("Error", "%s unknown but present in zk" % item)

                    for item in known - zk_registered:
                        self.success = False
                        yield ("Error", "%s known but not present in zk" % item)
                except Exception as ex:
                    self.success = False
                    yield (
                        "Error",
                        "Failed to list the meta0 services from zookeeper: %s" % ex,
                    )
                finally:
                    zh.close()

        if self.success:
            yield ("OK", None)


class Meta1Check(BaseCheckCommand):
    """
    Check the state of meta1 services.

    Compare registered instances against deployed instances.
    """

    SRV = "meta1"

    def _take_action(self, parsed_args):
        # All the services must have been declared
        c0 = list(self.filter_services(self.catalog, self.SRV))
        l0 = list(self.filter_services(self.live, self.SRV))
        assert len(c0) == len(l0)
        self.logger.info("All meta1 services are alive.")

        # They also need a positive score
        for _, _, _, m1_score in l0:
            assert m1_score > 0
        self.logger.info("All meta1 services have a positive score.")
        yield ("OK", None)


class DirectoryCheck(BaseCheckCommand):
    """
    Check the directory has been fully bootstraped.

    Check all container prefixes are set, from oioproxy and meta0.
    Check all meta0 show the same information.
    Check all meta1 are assigned.
    """

    def _take_action(self, parsed_args):
        import subprocess

        from oio.common.json import json
        from oio.directory.meta0 import Meta0Client

        self.logger.debug("Checking the directory bootstrap.")

        # Get an official dump from the proxy, check its size
        m0 = Meta0Client({"namespace": self.app.options.ns})
        prefixes = m0.list()
        if len(prefixes) != CID_PREFIX_COUNT:
            raise ValueError(
                "Found %d entries in meta0, expected %d"
                % (len(prefixes), CID_PREFIX_COUNT)
            )
        self.logger.info("The proxy serves a full meta0 dump.")

        # contact each M0 to perform a check: any "get" command will
        # fail if the meta0 is not complete. Unfortunately we just have
        # oio-meta0-client to target a specific service.
        for _, host, port, _ in self.filter_services(self.catalog, "meta0"):
            url = "%s:%d" % (host, port)
            res = subprocess.check_output(["oio-meta0-client", url, "get", "0000"])
            self.logger.info(res)
        self.logger.info("All meta0 services are complete.")

        # contact each meta0 to check that all the dumps are identical
        dump0 = None
        first = None
        for _, host, port, _ in self.filter_services(self.catalog, "meta0"):
            url = "%s:%d" % (host, port)
            dump = subprocess.check_output(["oio-meta0-client", url, "list"])
            if dump0 is None:
                dump0 = dump
                first = url
            elif dump0 != dump:
                raise ValueError(
                    "The dump returned by meta0 %s differs from the dump returned by %s"
                    % (url, first)
                )
        self.logger.info("All meta0 services serve the same base.")

        # Check all the meta1 are concerned
        reverse_dump = set()
        for _, v in json.loads(dump0).items():
            for url in v:
                reverse_dump.add(url)
        m1 = {
            ":".join((descr[1], str(descr[2])))
            for descr in self.filter_services(self.catalog, "meta1")
        }
        if m1 != reverse_dump:
            raise ValueError(
                "Meta1 used but not visible: %s, meta1 visible but not used: %s"
                % (reverse_dump - m1, m1 - reverse_dump)
            )
        self.logger.info("All meta1 services have been assigned.")
        yield ("OK", None)


class RdirCheck(BaseCheckCommand):
    """
    Check rdir services.

    Verify that all rawx and meta2 services are assigned.
    Check registered rdir services against deployed rdir services.
    """

    def _take_action(self, parsed_args):
        from oio.rdir.client import RdirDispatcher

        self.logger.debug("Checking rdir services.")

        # Load the assigned rdir services
        client = RdirDispatcher({"namespace": self.app.options.ns})

        # rawx
        all_rawx, all_rdir = client.get_assignments("rawx")
        assert not any(r["rdir"] is None for r in all_rawx)
        self.logger.info("All rawx services have an rdir service assigned.")

        # meta2
        all_meta2, all_rdir = client.get_assignments("meta2")
        assert not any(r["rdir"] is None for r in all_meta2)
        self.logger.info("All meta2 services have an rdir service assigned.")

        # Compare with the number of expected services
        l0 = list(self.filter_services(self.live, "rdir"))
        c0 = list(self.filter_services(self.catalog, "rdir"))
        assert len(l0) == len(c0)
        assert len(l0) == len(all_rdir)
        self.logger.info("All rdir services are alive.")
        yield ("OK", None)


class RawxCheck(MultipleServicesCommandMixin, ItemCheckCommand):
    """
    Check all rawx chunks.

    Every chunk will also have his account, container and object quickly
    checked. This is similar to 'openio-admin chunk check' but for every
    chunk hosted by the service.

    Default output format is 'value'.
    """

    service_type = "rawx"
    columns = ("Chunk", "Status", "Errors")
    reqid_prefix = "ACLI-RC-"

    @property
    def formatter_default(self):
        return "value"

    def _format_results(self, checker):
        for target in checker.run():
            if target.type == "chunk":
                if not target.has_errors:
                    status = "OK"
                    msg = None
                else:
                    status = "error"
                    self.success = False
                    msg = target.latest_error_result().errors_to_str()
                yield (repr(target)[len("chunk=") :], status, msg)

    def get_parser(self, prog_name):
        parser = super(RawxCheck, self).get_parser(prog_name)
        MultipleServicesCommandMixin.patch_parser(self, parser)
        return parser

    def take_action(self, parsed_args):
        MultipleServicesCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args
        )
        return super(RawxCheck, self).take_action(parsed_args)

    def _take_action(self, parsed_args):
        for service in parsed_args.services:
            reqid = self.app.request_id(self.reqid_prefix)
            chunks = self.app.client_manager.rdir.chunk_fetch(service, reqid=reqid)
            for res in self.check_chunks(service, chunks, self.checker):
                yield res

    def check_chunks(self, service, chunks, checker):
        url = "http://" + service
        for chunk in chunks:
            checker.check(
                Target(
                    self.app.options.account,
                    chunk=url + "/" + chunk[1],
                    version=chunk[2]["version"],
                    obj=chunk[2]["path"],
                    content_id=chunk[2]["content_id"],
                    cid=chunk[0],
                )
            )
            for res in self._format_results(checker):
                yield res
