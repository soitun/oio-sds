# Copyright (C) 2021-2022 OVH SAS
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


import time
from logging import getLogger

from oio.cli import Lister, ShowOne
from oio.common.easy_value import int_value
from oio.common.utils import cid_from_name
from oio.container.sharding import ContainerSharding
from oio.common.constants import M2_PROP_ACCOUNT_NAME, \
    M2_PROP_CONTAINER_NAME, M2_PROP_OBJECTS, M2_PROP_SHARDING_STATE, \
    M2_PROP_SHARDING_TIMESTAMP, SHARDING_STATE_NAME


class ContainerShardingCommandMixin(object):
    """Command taking a container as parameter"""

    def patch_parser_container_sharding(self, parser):
        parser.add_argument(
            'container',
            metavar='<container>',
            help=("Name of the container to interact with.\n")
        )
        parser.add_argument(
            '--cid',
            dest='is_cid',
            default=False,
            help="Interpret container as a CID",
            action='store_true'
        )

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


class CleanContainerSharding(ContainerShardingCommandMixin, Lister):
    """
    Remove from the container the objects which are outside of the shard range.
    """

    log = getLogger(__name__ + '.CleanContainerSharding')

    def get_parser(self, prog_name):
        parser = super(CleanContainerSharding, self).get_parser(prog_name)
        self.patch_parser_container_sharding(parser)
        parser.add_argument(
            '--attempts',
            type=int,
            default=1,
            help='Number of attempts for each clean up request. (default: 1)'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        container_sharding = ContainerSharding(
            self.app.client_manager.sds_conf,
            logger=self.app.client_manager.logger)
        container_sharding.clean_container(
            None, None, cid=cid, attempts=parsed_args.attempts)
        return ('Status', ), [('Ok', )]


class FindContainerSharding(ContainerShardingCommandMixin, Lister):
    """Find the distribution of shards."""

    log = getLogger(__name__ + '.FindContainerSharding')

    @staticmethod
    def patch_parser(parser):
        parser.add_argument(
            '--strategy',
            choices=ContainerSharding.STRATEGIES,
            help="""
            What strategy to use to shard a container.
            (default: %s)
            """ % ContainerSharding.DEFAULT_STRATEGY
        )
        parser.add_argument(
            '--partition',
            type=str,
            help="""
            [shard-with-partition]
            Percentage distribution of the shards size.
            (default: %s)
            """ % ','.join((str(part)
                            for part in ContainerSharding.DEFAULT_PARTITION))
        )
        parser.add_argument(
            '--threshold',
            type=int,
            help="""
            [shard-with-partition]
            Number of objects in a container from which sharding is applied.
            (default: %d)
            """ % ContainerSharding.DEFAULT_SHARD_SIZE
        )
        parser.add_argument(
            '--shard-size',
            type=int,
            help="""
            [shard-with-size|rebalance]
            Number of objects expected in the shards to find.
            (default: %d)
            """ % ContainerSharding.DEFAULT_SHARD_SIZE
        )
        return parser

    def get_parser(self, prog_name):
        parser = super(FindContainerSharding, self).get_parser(prog_name)
        self.patch_parser_container_sharding(parser)
        parser.add_argument(
            '--all',
            action='store_true',
            help="""
            Use all existing shards to find shards for the root container.
            """
        )
        return self.patch_parser(parser)

    @staticmethod
    def prepare_startegy(parsed_args):
        strategy_params = dict()
        if parsed_args.partition is not None:
            strategy_params['partition'] = parsed_args.partition
        if parsed_args.threshold is not None:
            strategy_params['threshold'] = parsed_args.threshold
        if parsed_args.shard_size is not None:
            strategy_params['shard_size'] = parsed_args.shard_size
        return parsed_args.strategy, strategy_params

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        strategy, strategy_params = self.prepare_startegy(parsed_args)
        container_sharding = ContainerSharding(
            self.app.client_manager.sds_conf,
            logger=self.app.client_manager.logger)
        if parsed_args.all:
            found_shards = container_sharding.find_all_shards(
                None, None, root_cid=cid,
                strategy=strategy, strategy_params=strategy_params)
        else:
            found_shards = container_sharding.find_shards(
                None, None, cid=cid,
                strategy=strategy, strategy_params=strategy_params)

        columns = ('Index', 'Lower', 'Upper', 'Count')
        if parsed_args.formatter == 'json':
            columns = ('index', 'lower', 'upper', 'count')

        return (columns,
                ((shard['index'], shard['lower'], shard['upper'],
                  shard['count']) for shard in found_shards))


class ReplaceContainerSharding(ContainerShardingCommandMixin, Lister):
    """Replace current shard(s) with the new shards."""

    log = getLogger(__name__ + '.ReplaceContainerSharding')

    def get_parser(self, prog_name):
        parser = super(ReplaceContainerSharding, self).get_parser(prog_name)
        self.patch_parser_container_sharding(parser)
        parser.add_argument(
            'shards',
            metavar='<shards>',
            help="""
            Shard ranges.
            JSON Syntax:
            [{"index": 0, "lower": "", "upper": "sharding"},
             {"index": 1, "lower": "sharding", "upper": ""}]
            """
        )
        parser.add_argument(
            '--from-file',
            action='store_true',
            help="""
            Consider <configuration> as a path to a file.
            """
        )
        parser.add_argument(
            '--enable',
            default=False,
            action='store_true',
            help="""
            Enable the sharding for this container.
            """
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help="""
            Replace all current shards with new shards.
            """
        )
        parser.add_argument(
            '--no-preclean-new-shards',
            default=True,
            action='store_false',
            dest='preclean_new_shards',
            help="""
            Disable the cleaning of the copy before creating the new shard.
            """
        )
        parser.add_argument(
            '--preclean-timeout',
            default=ContainerSharding.DEFAULT_PRECLEAN_TIMEOUT,
            type=float,
            help="""
            Maximum amount of time the sharding process is allowed
            to pre-clean shard copie (default: %f).
            """ % ContainerSharding.DEFAULT_PRECLEAN_TIMEOUT
        )
        parser.add_argument(
            '--create-shard-timeout',
            default=ContainerSharding.DEFAULT_CREATE_SHARD_TIMEOUT,
            type=float,
            help="""
            Maximum amount of time the sharding process is allowed
            to create new shard (default: %f).
            """ % ContainerSharding.DEFAULT_CREATE_SHARD_TIMEOUT
        )
        parser.add_argument(
            '--save-writes-timeout',
            default=ContainerSharding.DEFAULT_SAVE_WRITES_TIMEOUT,
            type=float,
            help="""
            Maximum amount of time the sharding process is allowed
            to save writes before applying them directly
            to the new shards (default: %f).
            """ % ContainerSharding.DEFAULT_SAVE_WRITES_TIMEOUT
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account, container, _ = self.resolve_container(
            self.app, parsed_args, name=True)
        if parsed_args.from_file:
            with open(parsed_args.shards, 'r') as file_:
                new_shards = file_.read()
        else:
            new_shards = parsed_args.shards

        modified = False
        container_sharding = ContainerSharding(
            self.app.client_manager.sds_conf,
            preclean_new_shards=parsed_args.preclean_new_shards,
            preclean_timeout=parsed_args.preclean_timeout,
            create_shard_timeout=parsed_args.create_shard_timeout,
            save_writes_timeout=parsed_args.save_writes_timeout,
            logger=self.app.client_manager.logger)
        new_shards = container_sharding.format_shards(new_shards, are_new=True)
        if parsed_args.all:
            modified = container_sharding.replace_all_shards(
                account, container, new_shards, enable=parsed_args.enable)
        else:
            modified = container_sharding.replace_shard(
                account, container, new_shards, enable=parsed_args.enable)

        return ('Modified', ), [(str(modified), )]


class FindAndReplaceContainerSharding(ContainerShardingCommandMixin, Lister):
    """
    Find the distribution of shards
    and replace current shard(s) with the new shards.
    """

    log = getLogger(__name__ + '.FindAndReplaceContainerSharding')

    def get_parser(self, prog_name):
        parser = super(FindAndReplaceContainerSharding, self).get_parser(
            prog_name)

        self.patch_parser_container_sharding(parser)
        parser = FindContainerSharding.patch_parser(parser)
        parser.add_argument(
            '--enable',
            default=False,
            action='store_true',
            help='Enable the sharding for this container'
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help="""
            Use all existing shards to find shards for the root container.
            And replace all current shards with these found shards.
            """
        )
        parser.add_argument(
            '--no-preclean-new-shards',
            default=True,
            action='store_false',
            dest='preclean_new_shards',
            help="""
            Disable the cleaning of the copy before creating the new shard.
            """
        )
        parser.add_argument(
            '--preclean-timeout',
            default=ContainerSharding.DEFAULT_PRECLEAN_TIMEOUT,
            type=float,
            help="""
            Maximum amount of time the sharding process is allowed
            to pre-clean shard copie (default: %f).
            """ % ContainerSharding.DEFAULT_PRECLEAN_TIMEOUT
        )
        parser.add_argument(
            '--create-shard-timeout',
            default=ContainerSharding.DEFAULT_CREATE_SHARD_TIMEOUT,
            type=float,
            help="""
            Maximum amount of time the sharding process is allowed
            to create new shard (default: %f).
            """ % ContainerSharding.DEFAULT_CREATE_SHARD_TIMEOUT
        )
        parser.add_argument(
            '--save-writes-timeout',
            default=ContainerSharding.DEFAULT_SAVE_WRITES_TIMEOUT,
            type=float,
            help="""
            Maximum amount of time the sharding process is allowed
            to save writes before applying them directly
            to the new shards (default: %f).
            """ % ContainerSharding.DEFAULT_SAVE_WRITES_TIMEOUT
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account, container, _ = self.resolve_container(
            self.app, parsed_args, name=True)
        strategy, strategy_params = FindContainerSharding.prepare_startegy(
            parsed_args)

        modified = False
        container_sharding = ContainerSharding(
            self.app.client_manager.sds_conf,
            preclean_new_shards=parsed_args.preclean_new_shards,
            preclean_timeout=parsed_args.preclean_timeout,
            create_shard_timeout=parsed_args.create_shard_timeout,
            save_writes_timeout=parsed_args.save_writes_timeout,
            logger=self.app.client_manager.logger)
        if parsed_args.all:
            found_shards = container_sharding.find_all_shards(
                account, container,
                strategy=strategy, strategy_params=strategy_params)
            modified = container_sharding.replace_all_shards(
                account, container, found_shards, enable=parsed_args.enable)
        else:
            found_shards = container_sharding.find_shards(
                account, container,
                strategy=strategy, strategy_params=strategy_params)
            modified = container_sharding.replace_shard(
                account, container,
                found_shards, enable=parsed_args.enable)

        return ('Modified', ), [(str(modified), )]


class ShrinkContainerSharding(ContainerShardingCommandMixin, Lister):
    """
    Shrink the number of shards by merging the given shards.
    """

    log = getLogger(__name__ + '.ShrinkContainerSharding')

    def get_parser(self, prog_name):
        parser = super(ShrinkContainerSharding, self).get_parser(
            prog_name)
        self.patch_parser_container_sharding(parser)
        parser.add_argument(
            'shards',
            metavar='<shards>',
            help="""
            Shard ranges to merge.
            JSON Syntax:
            [{"index": 0, "lower": "", "upper": "sharding", "cid": "F09AE7A55960614ACB29E95F92F94A918242BB1CEDBECA3B9BA2392809B046A0"},
             {"index": 1, "lower": "sharding", "upper": "", "cid": "48E322BD62CE646640E8573F7FE23E4F0F109EC6DC12D582ACACE466347B3322"}]
            """  # noqa: E501
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        modified = False
        container_sharding = ContainerSharding(
            self.app.client_manager.sds_conf,
            logger=self.app.client_manager.logger)
        shards = container_sharding.format_shards(
            parsed_args.shards, partial=True)
        modified = container_sharding.shrink_shards(shards, root_cid=cid)

        return ('Modified', ), [(str(modified), )]


class FindAndShrinkContainerSharding(ContainerShardingCommandMixin, Lister):
    """
    Find the smaller neighboring shard to shrink the number of shards
    by merging the specified shard with the neighboring shard.
    """

    log = getLogger(__name__ + '.FindAndShrinkContainerSharding')

    def get_parser(self, prog_name):
        parser = super(FindAndShrinkContainerSharding, self).get_parser(
            prog_name)
        self.patch_parser_container_sharding(parser)
        parser.add_argument(
            'shard',
            metavar='<shard>',
            help="""
            Shard range to merge with the smaller neighboring shard.
            JSON Syntax:
            {"index": 1, "lower": "sharding", "upper": ""}
            """
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        modified = False
        container_sharding = ContainerSharding(
            self.app.client_manager.sds_conf,
            logger=self.app.client_manager.logger)
        shard = container_sharding.format_shard(parsed_args.shard)
        shard, neighboring_shard = \
            container_sharding.find_smaller_neighboring_shard(
                shard, root_cid=cid)
        shards = list()
        shards.append(shard)
        if neighboring_shard is not None:
            shards.append(neighboring_shard)
        modified = container_sharding.shrink_shards(shards, root_cid=cid)

        return ('Modified', ), [(str(modified), )]


class ShowContainerSharding(ContainerShardingCommandMixin, Lister):
    """Show current shards."""

    log = getLogger(__name__ + '.ShowContainerSharding')

    def get_parser(self, prog_name):
        parser = super(ShowContainerSharding, self).get_parser(prog_name)
        self.patch_parser_container_sharding(parser)
        parser.add_argument(
            '--counts',
            action='store_true',
            help='Display the object count in each shard'
        )
        return parser

    def _take_action(self, parsed_args):
        _, _, cid = self.resolve_container(self.app, parsed_args)
        container_sharding = ContainerSharding(
            self.app.client_manager.sds_conf,
            logger=self.app.client_manager.logger)
        shards = container_sharding.show_shards(None, None, root_cid=cid)
        for shard in shards:
            shard_info = (shard['index'], shard['lower'], shard['upper'],
                          shard['cid'])
            if parsed_args.counts:
                meta = self.app.client_manager.storage.\
                    container_get_properties(None, None, cid=shard['cid'])
                shard_info += (meta['system'].get(M2_PROP_OBJECTS, 0),)
            yield shard_info

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        columns = ('Index', 'Lower', 'Upper', 'CID')
        if parsed_args.counts:
            columns += ('Count',)

        return (columns, self._take_action(parsed_args))


class IsOrphanShard(ContainerShardingCommandMixin, ShowOne):
    """
    Tell if the specified container is an orphan shard.

    Conditions:
    - the container metadata has a sharding.state field
    - the sharding.timestamp is old
    - the container does not appear in the technical sharding account
    """

    columns = ('account', 'container', 'cid',
               M2_PROP_SHARDING_STATE[len('sys.m2.'):],
               M2_PROP_SHARDING_TIMESTAMP[len('sys.m2.'):],
               'is_orphan', 'action_taken')

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.patch_parser_container_sharding(parser)
        parser.add_argument(
            '--autoremove',
            action='store_true',
            help='Delete the container if it is an orphan shard'
        )
        parser.add_argument(
            '--grace-delay',
            type=int,
            default=ContainerSharding.DEFAULT_SAVE_WRITES_TIMEOUT * 10,
            help=('Delay in seconds after which we consider there is no '
                  'sharding activity on the container')
        )

        return parser

    def take_action(self, parsed_args):
        _, _, cid = self.resolve_container(self.app, parsed_args)
        obsto = self.app.client_manager.storage
        container_sharding = ContainerSharding(
            self.app.client_manager.sds_conf,
            logger=self.app.client_manager.logger,
            pool_manager=self.app.client_manager.pool_manager)
        raw_meta = obsto.container_get_properties(
            None, None, cid=cid, force_master=True)
        account = raw_meta['system'].get(M2_PROP_ACCOUNT_NAME)
        container = raw_meta['system'].get(M2_PROP_CONTAINER_NAME)
        root_cid, meta = container_sharding.meta_to_shard(raw_meta)
        sharding_state = int_value(
            raw_meta['system'].get(M2_PROP_SHARDING_STATE), 0)
        sharding_timestamp = int_value(
            raw_meta['system'].get(M2_PROP_SHARDING_TIMESTAMP), 0) / 1000000
        recent_change = (time.time() - sharding_timestamp
                         < parsed_args.grace_delay)

        action_taken = None
        is_orphan = False

        if root_cid and sharding_state and not recent_change:
            # First page of shards whose "upper" is higher than our "lower"
            registered = list(container_sharding.show_shards(
                None, None, root_cid=root_cid,
                marker=meta["lower"], no_paging=False, force_master=True))
            is_orphan = cid not in [c['cid'] for c in registered]

        if is_orphan and parsed_args.autoremove:
            try:
                obsto.container_delete(None, None, cid=cid, force=True)
                action_taken = 'Deleted'
            except Exception as exc:
                action_taken = f'Tried to delete, but: {exc}'

        return self.columns, [account, container, cid,
                              SHARDING_STATE_NAME.get(sharding_state),
                              sharding_timestamp,
                              is_orphan,
                              action_taken]
