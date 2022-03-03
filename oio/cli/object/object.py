# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

from six import iteritems
import os
from logging import getLogger

from oio.common.json import json
from oio.cli import Command, Lister, ShowOne
from oio.common.utils import cid_from_name, depaginate
from oio.common.json import json as jsonlib


class ContainerCommandMixin(object):
    """Command taking a container name as parameter"""

    def patch_parser(self, parser):
        parser.add_argument(
            'container',
            metavar='<container>',
            help="Name or cid of the container to interact with."
        )
        parser.add_argument(
            '--cid',
            dest='is_cid',
            default=False,
            help="Interpret <container> as a CID",
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


class ObjectCommandMixin(ContainerCommandMixin):
    """Command taking an object name as parameter"""

    def patch_parser(self, parser):
        super(ObjectCommandMixin, self).patch_parser(parser)
        parser.add_argument(
            'object',
            metavar='<object>',
            help='Name of the object to manipulate.')
        parser.add_argument(
            '--object-version',
            type=int,
            default=None,
            metavar='version',
            help='Version of the object to manipulate.')


class ObjectsCommandMixin(ContainerCommandMixin):
    """Command taking an object name as parameter"""

    def patch_parser(self, parser):
        super(ObjectsCommandMixin, self).patch_parser(parser)
        parser.add_argument(
            'objects',
            nargs='+',
            metavar='<object>',
            help='Name of the objects to manipulate.')
        parser.add_argument(
            '--object-version',
            type=int,
            default=None,
            metavar='version',
            help='Version of the objects to manipulate.')

    def resolve_container(self, app, parsed_args, name=False):
        if len(parsed_args.objects) > 1 and parsed_args.object_version:
            raise Exception("Cannot specify a version for several objects")
        return super(ObjectsCommandMixin, self).resolve_container(
            app, parsed_args, name=name)


class CreateObject(ContainerCommandMixin, Lister):
    """Upload object"""

    log = getLogger(__name__ + '.CreateObject')

    def get_parser(self, prog_name):
        from oio.cli.common.utils import KeyValueAction

        parser = super(CreateObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        # TODO(mb): manage --opt and --no-opt
        parser.add_argument(
            '--no-autocreate',
            help=("Forbid autocreation of container if nonexistent"),
            action="store_false",
            dest="autocreate",
            default=True
        )
        parser.add_argument(
            'objects',
            metavar='<filename>',
            nargs='+',
            help='Local filename(s) to upload.'
        )
        parser.add_argument(
            '--name',
            metavar='<key>',
            default=[],
            action='append',
            help="Name of the object to create. "
                 "If not specified, use the basename of the uploaded file."
        )
        parser.add_argument(
            '--policy',
            metavar='<policy>',
            help='Storage policy'
        )
        parser.add_argument(
            '--property',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Property to add to the object(s)'
        )
        parser.add_argument(
            '--key-file',
            metavar='<key_file>',
            help='File containing application keys'
        )
        parser.add_argument(
            '--mime-type',
            metavar='<type>',
            help='Object MIME type',
            default=None
        )
        parser.add_argument(
            '--tls',
            action="store_true",
            help='Upgrade RAWX connection to TLS',
            default=False
        )
        parser.add_argument(
            '--perfdata-column',
            action="store_true",
            help='Add a column to display performance data',
            default=False
        )
        parser.add_argument(
            '--restore-drained',
            action="store_true",
            help='Restore a drained object (keeping its metadata)',
            default=False
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account, container, _ = self.resolve_container(
            self.app, parsed_args, name=True)
        policy = parsed_args.policy
        objs = parsed_args.objects
        names = parsed_args.name
        key_file = parsed_args.key_file
        autocreate = parsed_args.autocreate
        if key_file and key_file[0] != '/':
            key_file = os.getcwd() + '/' + key_file

        import io
        any_error = False
        properties = parsed_args.property
        results = []
        perfdata = self.app.client_manager.storage.perfdata
        for obj in objs:
            name = obj
            try:
                with io.open(obj, 'rb') as f:
                    name = names.pop(0) if names else os.path.basename(f.name)
                    data = self.app.client_manager.storage.object_create(
                        account, container,
                        file_or_path=f,
                        obj_name=name,
                        policy=policy,
                        properties=properties,
                        key_file=key_file,
                        mime_type=parsed_args.mime_type,
                        autocreate=autocreate,
                        tls=parsed_args.tls,
                        restore_drained=parsed_args.restore_drained)

                    res = (name, data[1], data[2].upper(), 'Ok')
                    if parsed_args.perfdata_column:
                        res += (json.dumps(perfdata, sort_keys=True,
                                indent=4),)

                    results.append(res)
            except KeyboardInterrupt:
                results.append((name, 0, None, 'Interrupted'))
                any_error = True
                break
            except Exception as exc:
                self.log.error('Failed to upload %s in %s: %s',
                               obj, container, exc)
                any_error = True
                results.append((name, 0, None, 'Failed'))

        listing = (obj for obj in results)
        columns = ('Name', 'Size', 'Hash', 'Status')
        if parsed_args.perfdata_column:
            columns += ('Perfdata',)
        if any_error:
            self.produce_output(parsed_args, columns, listing)
            raise Exception("Too many errors occurred")
        return columns, listing


class TouchObject(ObjectsCommandMixin, Command):
    """Touch an object in a container, re-triggers asynchronous treatments"""

    log = getLogger(__name__ + '.TouchObject')

    def get_parser(self, prog_name):
        parser = super(TouchObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        for obj in parsed_args.objects:
            self.app.client_manager.storage.object_touch(
                None, None, obj,
                version=parsed_args.object_version,
                cid=cid)


class DeleteObject(ObjectsCommandMixin, Lister):
    """Delete object from container"""

    log = getLogger(__name__ + '.DeleteObject')

    def get_parser(self, prog_name):
        parser = super(DeleteObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        results = []

        if len(parsed_args.objects) <= 1:
            deleted = self.app.client_manager.storage.object_delete(
                None, None, parsed_args.objects[0],
                version=parsed_args.object_version,
                cid=cid)
            results.append((parsed_args.objects[0], deleted))
        else:
            results = self.app.client_manager.storage.object_delete_many(
                None, None, parsed_args.objects, cid=cid)

        columns = ('Name', 'Deleted')
        res_gen = (r for r in results)
        return columns, res_gen


class ShowObject(ObjectCommandMixin, ShowOne):
    """Show information about an object"""

    log = getLogger(__name__ + '.ShowObject')

    def get_parser(self, prog_name):
        parser = super(ShowObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account, container, _ = self.resolve_container(
            self.app, parsed_args, name=True)
        obj = parsed_args.object

        data = self.app.client_manager.storage.object_show(
            account, container, obj,
            version=parsed_args.object_version)
        info = {'account': account,
                'container': container,
                'object': obj}
        conv = {'id': 'id', 'version': 'version', 'mime-type': 'mime_type',
                'size': 'length', 'hash': 'hash', 'ctime': 'ctime',
                'mtime': 'mtime', 'policy': 'policy',
                'chunk_method': 'chunk_method'}
        for key0, key1 in conv.items():
            info[key0] = data.get(key1, 'n/a')
        for k, v in iteritems(data['properties']):
            info['meta.' + k] = v
        return list(zip(*sorted(info.items())))


class SetObject(ObjectCommandMixin, Command):
    """Set object properties"""

    log = getLogger(__name__ + '.SetObject')

    def get_parser(self, prog_name):
        from oio.cli.common.utils import KeyValueAction

        parser = super(SetObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            '--property',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Property to add to this object'
        )
        parser.add_argument(
            '--tagging',
            metavar='<JSON object>',
            help='Replaces S3 tags on this object'
        )
        parser.add_argument(
            '--clear',
            default=False,
            help='Clear previous properties',
            action='store_true')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        obj = parsed_args.object
        properties = parsed_args.property
        if parsed_args.tagging:
            try:
                tags = jsonlib.loads(parsed_args.tagging)
                if not isinstance(tags, dict):
                    raise ValueError()
            except ValueError:
                from oio.common.exceptions import CommandError
                raise CommandError('--tags: Not a JSON object')
            tags_xml = '<Tagging><TagSet>'
            for k, v in tags.items():
                tags_xml += '<Tag><Key>%s</Key><Value>%s</Value></Tag>' \
                    % (k, v)
            tags_xml += '</TagSet></Tagging>'
            properties = properties or dict()
            from oio.container.lifecycle import TAGGING_KEY
            properties[TAGGING_KEY] = tags_xml
        self.app.client_manager.storage.object_set_properties(
            None, None, obj, properties,
            version=parsed_args.object_version,
            clear=parsed_args.clear,
            cid=cid)


class SaveObject(ObjectCommandMixin, Command):
    """Save object locally"""

    log = getLogger(__name__ + '.SaveObject')

    def get_parser(self, prog_name):
        parser = super(SaveObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            '--file',
            metavar='<filename>',
            help='Destination filename (defaults to object name)'
        )
        parser.add_argument(
            '--key-file',
            metavar='<key_file>',
            help='File containing application keys'
        )
        parser.add_argument(
            '--tls',
            action="store_true",
            help='Upgrade RAWX connection to TLS',
            default=False
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        obj = parsed_args.object
        key_file = parsed_args.key_file
        if key_file and key_file[0] != '/':
            key_file = os.getcwd() + '/' + key_file
        filename = parsed_args.file
        if not filename:
            filename = obj

        _meta, stream = self.app.client_manager.storage.object_fetch(
            None, None, obj,
            version=parsed_args.object_version,
            key_file=key_file,
            properties=False,
            cid=cid,
            tls=parsed_args.tls
        )
        if not os.path.exists(os.path.dirname(filename)):
            if len(os.path.dirname(filename)) > 0:
                os.makedirs(os.path.dirname(filename))
        with open(filename, 'wb') as ofile:
            for chunk in stream:
                ofile.write(chunk)


class ListObject(ContainerCommandMixin, Lister):
    """List objects in a container."""

    log = getLogger(__name__ + '.ListObject')

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(ListObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            '--prefix',
            metavar='<prefix>',
            help='Filter list using <prefix>'
        )
        parser.add_argument(
            '--delimiter',
            metavar='<delimiter>',
            help='Filter list using <delimiter>'
        )
        parser.add_argument(
            '--marker',
            metavar='<marker>',
            help='Marker for paging'
        )
        parser.add_argument(
            '--end-marker',
            metavar='<end-marker>',
            help='End marker for paging'
        )
        parser.add_argument(
            '--attempts',
            dest='attempts',
            type=int,
            default=0,
            help='Number of attempts for listing requests'
        )
        parser.add_argument(
            '--limit',
            metavar='<limit>',
            type=int,
            default=1000,
            help='Limit the number of objects returned (1000 by default)'
        )
        parser.add_argument(
            '--no-paging', '--full',
            dest='full_listing',
            default=False,
            help="List all objects without paging "
                 "(and set output format to 'value')",
            action=ValueFormatStoreTrueAction,
        )
        parser.add_argument(
            '--properties', '--long',
            dest='long_listing',
            default=False,
            help='List properties with objects',
            action="store_true"
        )
        parser.add_argument(
            '--versions', '--all-versions',
            dest='versions',
            default=False,
            help='List all objects versions (not only the last one)',
            action="store_true"
        )
        parser.add_argument(
            '--local',
            dest='local',
            default=False,
            action="store_true",
            help='Ask the meta2 to open a local database'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        kwargs = {}
        if parsed_args.prefix:
            kwargs['prefix'] = parsed_args.prefix
        if parsed_args.marker:
            kwargs['marker'] = parsed_args.marker
        if parsed_args.end_marker:
            kwargs['end_marker'] = parsed_args.end_marker
        if parsed_args.delimiter:
            kwargs['delimiter'] = parsed_args.delimiter
        if parsed_args.limit and not parsed_args.full_listing:
            kwargs['limit'] = parsed_args.limit
        if parsed_args.long_listing:
            kwargs['properties'] = True
        if parsed_args.versions:
            kwargs['versions'] = True
        if parsed_args.local:
            kwargs['local'] = True
        if parsed_args.attempts:
            kwargs['request_attempts'] = parsed_args.attempts

        _, _, cid = self.resolve_container(self.app, parsed_args)
        if parsed_args.full_listing:
            obj_gen = depaginate(
                self.app.client_manager.storage.object_list,
                listing_key=lambda x: x['objects'],
                marker_key=lambda x: x.get('next_marker'),
                truncated_key=lambda x: x['truncated'],
                account=None, container=None, cid=cid, **kwargs)
        else:
            resp = self.app.client_manager.storage.object_list(
                None, None, cid=cid, **kwargs)
            obj_gen = resp['objects']
            if resp.get('truncated'):
                self.log.info(
                    'Object listing has been truncated, next marker: %s',
                    resp.get('next_marker'))

        if parsed_args.long_listing:
            from oio.common.timestamp import Timestamp

            def _format_props(props):
                prop_list = ["%s=%s" % (k, v) for k, v
                             in props.items()]
                if parsed_args.formatter == 'table':
                    prop_string = "\n".join(prop_list)
                elif parsed_args.formatter in ('value', 'csv'):
                    prop_string = " ".join(prop_list)
                else:
                    prop_string = props
                return prop_string

            def _gen_results(objects):
                for obj in objects:
                    try:
                        result = (obj['name'], obj['size'],
                                  obj['hash'], obj['version'],
                                  obj['deleted'], obj['mime_type'],
                                  Timestamp(obj['mtime']).isoformat,
                                  obj['policy'],
                                  _format_props(obj.get('properties', {})))
                        yield result
                    except KeyError as exc:
                        self.success = False
                        self.log.warn("Bad object entry, missing '%s': %s",
                                      exc, obj)
            columns = ('Name', 'Size', 'Hash', 'Version', 'Deleted',
                       'Content-Type', 'Last-Modified', 'Policy', 'Properties')
        else:
            def _gen_results(objects):
                for obj in objects:
                    try:
                        yield (
                            obj['name'],
                            obj['size'] if not obj['deleted'] else 'deleted',
                            obj['hash'],
                            obj['version'])
                    except KeyError as exc:
                        self.success = False
                        self.log.warn("Bad object entry, missing %s: %s",
                                      exc, obj)
            columns = ('Name', 'Size', 'Hash', 'Version')
        results = _gen_results(obj_gen)
        return (columns, results)


class UnsetObject(ObjectCommandMixin, Command):
    """Unset object properties"""

    log = getLogger(__name__ + '.UnsetObject')

    def get_parser(self, prog_name):
        parser = super(UnsetObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            '--property',
            metavar='<key>',
            default=[],
            action='append',
            help='Property to remove from object')
        parser.add_argument(
            '--tagging',
            default=False,
            help='Clear previous S3 tags',
            action='store_true')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        obj = parsed_args.object
        properties = parsed_args.property or list()
        if parsed_args.tagging:
            from oio.container.lifecycle import TAGGING_KEY
            properties.append(TAGGING_KEY)
        self.app.client_manager.storage.object_del_properties(
            None, None, obj,
            properties,
            version=parsed_args.object_version,
            cid=cid)


class DrainObject(ContainerCommandMixin, Command):
    """\
Remove all the chunks of a content but keep the properties.
We can replace the data or the properties of the content
but no action needing the removed chunks are accepted\
"""

    log = getLogger(__name__ + '.DrainObject')

    def get_parser(self, prog_name):
        parser = super(DrainObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            'objects',
            metavar='<object>',
            nargs='+',
            help='Object(s) to drain'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        for obj in parsed_args.objects:
            self.app.client_manager.storage.object_drain(
                None, None, obj, cid=cid)


class LocateObject(ObjectCommandMixin, Lister):
    """Locate the parts of an object"""

    log = getLogger(__name__ + '.LocateObject')

    def get_parser(self, prog_name):
        parser = super(LocateObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            '--chunk-info',
            action='store_true',
            default=False,
            help='Display chunk size and hash as they are on persistent \
            storage. It sends request per chunk so it is likely to be slow.'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        obj = parsed_args.object

        data = self.app.client_manager.storage.object_locate(
            None, None, obj, cid=cid,
            version=parsed_args.object_version,
            chunk_info=parsed_args.chunk_info)

        if parsed_args.chunk_info:
            columns = ('Pos', 'Id', 'Metachunk size', 'Metachunk hash',
                       'Chunk size', 'Chunk hash')
            chunks = ((c['pos'], c['url'], c['size'], c['hash'],
                       c.get('chunk_size', 'n/a'), c.get('chunk_hash', 'n/a'))
                      for c in data[1])
        else:
            columns = ('Pos', 'Id', 'Metachunk size', 'Metachunk hash')
            chunks = ((c['pos'], c['url'], c['size'], c['hash'])
                      for c in data[1])

        return columns, chunks


class PurgeObject(ObjectCommandMixin, Command):
    """Purge exceeding object versions."""

    log = getLogger(__name__ + '.PurgeObject')

    def get_parser(self, prog_name):
        parser = super(PurgeObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            '--max-versions',
            metavar='<n>',
            type=int,
            help="""The number of versions to keep
 (overrides the container configuration).
 n<0 is unlimited number of versions (purge only deleted aliases).
 n=0 is 1 version.
 n>0 is n versions.
"""
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        _, _, cid = self.resolve_container(self.app, parsed_args)
        self.app.client_manager.storage.container.content_purge(
            None, None, parsed_args.object,
            maxvers=parsed_args.max_versions, cid=cid
        )


class LinkObject(ObjectCommandMixin, Command):
    """
    Make a shallow copy of an object (similar to a hardlink).
    """

    log = getLogger(__name__ + '.LinkObject')

    def get_parser(self, prog_name):
        from oio.cli.common.utils import KeyValueAction

        parser = super(LinkObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            '--dest-account', '--link-account',
            metavar='<destination account>',
            help='Name of the destination account.')
        parser.add_argument(
            '--dest-container', '--link-container',
            metavar='<destination container>',
            help=('Name of the destination container. If not specified, the '
                  'name of the destination container is the same as the source'
                  ' container.'))
        parser.add_argument(
            'dest_object',
            metavar='<destination object>',
            help='Name of the destination object.')
        parser.add_argument(
            '--content-id',
            metavar='<content ID>',
            help='Content ID.')
        parser.add_argument(
            '--dest-content-id', '--link-content-id',
            metavar='<destination content ID>',
            help='destination content ID.')
        parser.add_argument(
            '--property',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Property to add to the destination object.')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        directive = 'COPY'
        kwargs = {}

        account, container, _ = self.resolve_container(
            self.app, parsed_args, name=True)
        if parsed_args.property:
            directive = 'REPLACE'
            kwargs['properties'] = parsed_args.property
        if not parsed_args.dest_account:
            parsed_args.dest_account = account
        if not parsed_args.dest_container:
            parsed_args.dest_container = container

        self.app.client_manager.storage.object_link(
            account, container, parsed_args.object,
            parsed_args.dest_account, parsed_args.dest_container,
            parsed_args.dest_object, target_version=parsed_args.object_version,
            target_content_id=parsed_args.content_id,
            link_content_id=parsed_args.dest_content_id,
            properties_directive=directive, **kwargs)
