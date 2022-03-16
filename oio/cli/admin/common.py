# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022 OVH SAS
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

from oio.common.green import get_watchdog
from oio.common.utils import cid_from_name


class CommandMixin(object):

    @property
    def watchdog(self):
        """Get a reference to the main Watchdog instance."""
        return get_watchdog(called_from_main_application=True)

    def patch_parser(self, parser):
        raise NotImplementedError()

    def check_and_load_parsed_args(self, app, parsed_args):
        raise NotImplementedError()


class AccountCommandMixin(CommandMixin):
    """
    Add account-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'accounts',
            nargs='*',
            metavar='<account_name>',
            help='Name of the account to work on.'
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        if not parsed_args.accounts:
            parsed_args.accounts = [app.options.account]


class ContainerCommandMixin(CommandMixin):
    """
    Add container-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'containers',
            nargs='+',
            metavar='<container_name>',
            help='Name of the container to work on.'
        )
        parser.add_argument(
            '--cid',
            action='store_true',
            dest='is_cid',
            help="Interpret <container_name> as a container ID",
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        pass

    def resolve_containers(self, app, parsed_args, no_name=False, no_id=False):
        containers = list()
        if parsed_args.is_cid:
            for container_id in parsed_args.containers:
                account = None
                container_name = None
                if not no_name:
                    account, container_name = \
                        app.client_manager.storage.resolve_cid(container_id)
                if no_id:
                    container_id = None
                containers.append((account, container_name, container_id))
        else:
            for container_name in parsed_args.containers:
                account = app.options.account
                container_id = None
                if not no_id:
                    container_id = cid_from_name(account, container_name)
                if no_name:
                    account = None
                    container_name = None
                containers.append((account, container_name, container_id))
        return containers


class ObjectCommandMixin(CommandMixin):
    """
    Add object-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'container',
            metavar='<container_name>',
            help="Name or cid of the container to interact with."
        )
        parser.add_argument(
            'objects',
            metavar='<object_name>',
            nargs='*',
            help='Name of the object to work on.'
        )
        parser.add_argument(
            '--object-version',
            metavar='<version>',
            help=("Version of the object to work on. Can be used when only "
                  "one object is specified on command line.")
        )
        parser.add_argument(
            '--cid',
            action='store_true',
            dest='is_cid',
            help="Interpret <container_name> as a container ID",
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        pass

    def resolve_container(self, app, parsed_args, name=False):
        """
        Get CID (or account and container name) from parsed args.

        Resolve a CID into account and container name if required.
        """
        if parsed_args.is_cid:
            account = None
            container = None
            cid = parsed_args.container
            if name:
                account, container = \
                    app.client_manager.storage.resolve_cid(cid)
        else:
            account = app.client_manager.account
            container = parsed_args.container
            cid = cid_from_name(account, container)
            if not name:
                account = None
                container = None
        return account, container, cid


class ChunkCommandMixin(CommandMixin):
    """
    Add chunk-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'chunks',
            metavar='<chunk_url>',
            nargs='+',
            help='URL of the chunk to work on.'
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        pass


class SingleServiceCommandMixin(CommandMixin):
    """
    Add service-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'service',
            metavar='<service_id>',
            help=("ID of the service to work on."),
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        pass


class MultipleServicesCommandMixin(CommandMixin):
    """
    Add service-related arguments to a cliff command.
    """

    service_type = None

    def patch_parser(self, parser):
        parser.add_argument(
            'services',
            nargs='*',
            metavar='<service_id>',
            help=("ID of the service to work on. "
                  "If no service is specified, work on all."),
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        """
        Load IDs of services.
        """
        if not parsed_args.services:
            parsed_args.services = [
                s['id'] for s in app.client_manager.conscience.all_services(
                    self.service_type)]


class ProxyCommandMixin(CommandMixin):
    """
    Add proxy-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'service',
            metavar='<service_id>',
            nargs='?',
            help=("ID of the proxy to work on. "
                  "If not specified, use the local one."),
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        pass


class ToolCommandMixin(CommandMixin):
    """
    Add tool-related arguments to a cliff command.
    """

    tool_conf = dict()
    tool_class = None
    distributed = False

    def patch_parser(self, parser):
        parser.add_argument(
            '--report-interval', type=int,
            help='Report interval in seconds. '
                 '(default=%d)'
                 % self.tool_class.DEFAULT_REPORT_INTERVAL)
        parser.add_argument(
            '--items-per-second', type=int,
            help='Max items per second. '
                 '(default=%d)'
                 % self.tool_class.DEFAULT_ITEM_PER_SECOND)
        if self.distributed:  # distributed
            distributed_tube_help = """
The beanstalkd tube to use to send the items to rebuild. (default=%s)
""" % self.tool_class.DEFAULT_DISTRIBUTED_BEANSTALKD_WORKER_TUBE
            parser.add_argument(
                '--distributed-tube',
                help=distributed_tube_help)
        else:  # local
            parser.add_argument(
                '--concurrency', type=int,
                help='Number of coroutines to spawn. '
                     '(default=%d)' % self.tool_class.DEFAULT_CONCURRENCY)

    def check_and_load_parsed_args(self, app, parsed_args):
        self.tool_conf.update(app.client_manager.client_conf)
        self.tool_conf['report_interval'] = parsed_args.report_interval
        self.tool_conf['items_per_second'] = parsed_args.items_per_second
        if self.distributed:  # distributed
            self.tool_conf['distributed_beanstalkd_worker_tube'] = \
                parsed_args.distributed_tube
        else:  # local
            self.tool_conf['concurrency'] = parsed_args.concurrency
