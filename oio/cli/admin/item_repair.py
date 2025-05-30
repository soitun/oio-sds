# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2024 OVH SAS
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

from cliff import lister

from oio.account.rebuilder import AccountRebuilder
from oio.cli.admin.common import (
    AccountCommandMixin,
    ContainerCommandMixin,
    ObjectCommandMixin,
    ToolCommandMixin,
)
from oio.container.repairer import ContainerRepairer
from oio.content.repairer import ContentRepairer


class ItemRepairCommand(ToolCommandMixin, lister.Lister):
    """
    Various parameters that apply to all repair commands.
    """

    columns = None
    repairer = None

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(ItemRepairCommand, self).get_parser(prog_name)
        ToolCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        ToolCommandMixin.check_and_load_parsed_args(self, self.app, parsed_args)
        self.logger.debug("take_action(%s)", parsed_args)

        return self.columns, self._take_action(parsed_args)

    def run(self, parsed_args):
        super(ItemRepairCommand, self).run(parsed_args)
        if not self.repairer.is_success():
            return 1


class AccountRepair(AccountCommandMixin, ItemRepairCommand):
    """
    Repair a account.

    The steps of the repair:
    recompute the counter of this account ;
    refresh the counter of all containers in this account.
    """

    tool_class = AccountRebuilder
    columns = ("Entry", "Status", "Errors")

    def get_parser(self, prog_name):
        parser = super(AccountRepair, self).get_parser(prog_name)
        AccountCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        accounts = []
        for account_name in parsed_args.accounts:
            account = {
                "namespace": self.app.options.ns,
                "account": account_name,
            }
            accounts.append(account)

        self.repairer = AccountRebuilder(
            self.tool_conf,
            accounts=accounts,
            logger=self.logger,
            watchdog=self.watchdog,
        )
        self.repairer.prepare_local_dispatcher()

        for item, _, error in self.repairer.run():
            if error is None:
                status = "OK"
            else:
                status = "error"
            yield (self.repairer.string_from_item(item), status, error)

    def take_action(self, parsed_args):
        AccountCommandMixin.check_and_load_parsed_args(self, self.app, parsed_args)
        return super(AccountRepair, self).take_action(parsed_args)


class ContainerRepair(ContainerCommandMixin, ItemRepairCommand):
    """
    Repair a container.

    The steps of the repair:
    rebuild all missing, lost databases;
    synchronize the databases;
    update the counters in the account service.
    """

    tool_class = ContainerRepairer
    columns = ("Container", "Status", "Errors")

    def get_parser(self, prog_name):
        parser = super(ContainerRepair, self).get_parser(prog_name)
        ContainerCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            "--no-rebuild-bases",
            action="store_false",
            dest="rebuild_bases",
            help="Don't rebuild the missing, lost bases. "
            f"(default={not self.tool_class.DEFAULT_REBUILD_BASES})",
        )
        parser.add_argument(
            "--no-sync-bases",
            action="store_false",
            dest="sync_bases",
            help="Don't synchronize its bases. "
            f"(default={not self.tool_class.DEFAULT_SYNC_BASES})",
        )
        parser.add_argument(
            "--no-update-account",
            action="store_false",
            dest="update_account",
            help=(
                "Don't update the counters for the account service. "
                f"(default={not self.tool_class.DEFAULT_UPDATE_ACCOUNT})"
            ),
        )
        return parser

    def _take_action(self, parsed_args):
        self.tool_conf["rebuild_bases"] = parsed_args.rebuild_bases
        self.tool_conf["sync_bases"] = parsed_args.sync_bases
        self.tool_conf["update_account"] = parsed_args.update_account

        containers = self.resolve_containers(self.app, parsed_args, no_id=True)
        containers_to_repair = []
        for account, container_name, _ in containers:
            container = {
                "namespace": self.app.options.ns,
                "account": account,
                "container": container_name,
            }
            containers_to_repair.append(container)

        self.repairer = ContainerRepairer(
            self.tool_conf,
            containers=containers_to_repair,
            logger=self.logger,
            watchdog=self.watchdog,
        )
        self.repairer.prepare_local_dispatcher()

        for item, _, error in self.repairer.run():
            if error is None:
                status = "OK"
            else:
                status = "error"
            yield (self.repairer.string_from_item(item), status, error)

    def take_action(self, parsed_args):
        ContainerCommandMixin.check_and_load_parsed_args(self, self.app, parsed_args)
        return super(ContainerRepair, self).take_action(parsed_args)


class ObjectRepair(ObjectCommandMixin, ItemRepairCommand):
    """
    Repair an object.

    The steps of the repair:
    rebuild all missing, lost or corrupt chunks ;
    update the counters for the account service.
    """

    tool_class = ContentRepairer
    columns = ("Object", "Status", "Errors")

    def get_parser(self, prog_name):
        parser = super(ObjectRepair, self).get_parser(prog_name)
        ObjectCommandMixin.patch_parser(self, parser)
        parser.add_argument(
            "--read-all-available-sources",
            action="store_true",
            help="For objects using erasure-coding, connect to all apparently "
            "available chunks, to have backups in case one of them is "
            "silently corrupt.",
        )
        parser.add_argument(
            "--rebuild-on-network-error",
            action="store_true",
            help="In case a chunk is not readable because of a network error "
            "(connection issue, or rawx service down), rebuild it elsewhere. "
            "Notice that if the service is just temporarily down, this will "
            "generate orphan chunks.",
        )
        return parser

    def _take_action(self, parsed_args):
        self.tool_conf["read_all_available_sources"] = (
            parsed_args.read_all_available_sources
        )
        self.tool_conf["rebuild_on_network_error"] = (
            parsed_args.rebuild_on_network_error
        )
        account, _, objects = self.resolve_objects(self.app, parsed_args)
        objects_to_repair = []
        for container, obj_name, version in objects:
            obj = {
                "namespace": self.app.options.ns,
                "account": account,
                "container": container,
                "name": obj_name,
                "version": version,
            }
            objects_to_repair.append(obj)

        self.repairer = ContentRepairer(
            self.tool_conf,
            objects=objects_to_repair,
            logger=self.logger,
            watchdog=self.watchdog,
        )
        self.repairer.prepare_local_dispatcher()

        for item, _, error in self.repairer.run():
            if error is None:
                status = "OK"
            else:
                status = "error"
            yield (self.repairer.string_from_item(item), status, error)

    def take_action(self, parsed_args):
        ObjectCommandMixin.check_and_load_parsed_args(self, self.app, parsed_args)
        return super(ObjectRepair, self).take_action(parsed_args)
