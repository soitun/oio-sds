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

from oio.common.green import eventlet, eventlet_yield, time, Empty, LightQueue

from greenlet import GreenletExit
from urllib.parse import unquote

from oio.common import exceptions
from oio.common.client import ProxyClient
from oio.common.constants import HEADER_PREFIX, M2_PROP_ACCOUNT_NAME, \
    M2_PROP_CONTAINER_NAME, M2_PROP_SHARDS, M2_PROP_SHARDING_ROOT, \
    M2_PROP_SHARDING_LOWER, M2_PROP_SHARDING_UPPER, STRLEN_CID
from oio.common.easy_value import boolean_value, int_value, is_hexa, true_value
from oio.common.exceptions import BadRequest, OioException, OioTimeout
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.utils import cid_from_name, depaginate
from oio.container.client import ContainerClient
from oio.directory.admin import AdminClient
from oio.event.beanstalk import Beanstalk, ResponseError


class SavedWritesApplicator(object):

    def __init__(self, sharding_client, parent_shard, new_shards,
                 logger=None, **kwargs):
        self.sharding_client = sharding_client
        self.logger = logger or get_logger(dict())
        url = parent_shard['sharding']['queue']
        tube = parent_shard['cid'] + '.sharding-' \
            + str(parent_shard['sharding']['timestamp'])
        self.logger.info('Connecting to beanstalk tube (URL=%s TUBE=%s)',
                         url, tube)
        self.beanstalk = Beanstalk.from_url(url)
        self.beanstalk.use(tube)
        self.beanstalk.watch(tube)
        self.new_shards = list()
        for new_shard in new_shards:
            self.new_shards.append(new_shard.copy())

        self.main_thread = None
        self.queue_is_empty = False
        self.flush_queries = False
        self.running = True

    def _update_new_shard(self, new_shard, buffer_size=1000, **kwargs):
        queue = new_shard['queue']
        last_queries = False
        buffer = list()
        while True:
            max_remaining = buffer_size
            try:
                queries = queue.get(block=False)
                if queries is None:
                    last_queries = True
                    max_remaining = 0
                else:
                    buffer += queries
            except Empty:
                if self.flush_queries and buffer:
                    max_remaining = 0
                else:
                    eventlet_yield()
                    continue

            while buffer and len(buffer) >= max_remaining:
                queries_to_sent = buffer[:buffer_size]
                buffer = buffer[buffer_size:]
                self.sharding_client._update_new_shard(
                    new_shard, queries_to_sent, **kwargs)

            if last_queries:
                if buffer:
                    raise OioException('Should never happen')
                return

    def _fetch_and_dispatch_queries(self, **kwargs):
        last_check = False
        while True:
            data = None
            try:
                job_id, data = self.beanstalk.reserve(timeout=0)
                self.queue_is_empty = False
                self.beanstalk.delete(job_id)
            except ResponseError as exc:
                if 'TIMED_OUT' in str(exc):
                    self.queue_is_empty = True
                    if not self.running:
                        if last_check:
                            for new_shard in self.new_shards:
                                new_shard['queue'].put(None)
                            return
                        last_check = True
                    else:
                        eventlet_yield()
                    continue
                raise

            if not data:
                continue
            data = json.loads(data)
            path = data.get('path')
            queries = data['queries']
            if not queries:
                continue

            relevant_queues = list()
            for new_shard in self.new_shards:
                if not path:
                    relevant_queues.append(new_shard['queue'])
                    continue
                if new_shard['lower'] and path <= new_shard['lower']:
                    continue
                if new_shard['upper'] and path > new_shard['upper']:
                    continue
                relevant_queues.append(new_shard['queue'])
            if not relevant_queues:
                raise OioException(
                    'The path does not belong to any of the shards')
            for relevant_queue in relevant_queues:
                relevant_queue.put(queries)

    def apply_in_background(self, **kwargs):
        for new_shard in self.new_shards:
            new_shard['queue'] = LightQueue()
            new_shard['thread'] = eventlet.spawn(
                self._update_new_shard, new_shard, **kwargs)
        self.main_thread = eventlet.spawn(
            self._fetch_and_dispatch_queries, **kwargs)

        # Let these threads start
        eventlet_yield()

    def wait_until_queue_is_almost_empty(self, timeout=30, **kwargs):
        start_time = time.time()
        while True:
            if self.queue_is_empty:
                for new_shard in self.new_shards:
                    shard_queue = new_shard.get('queue')
                    if shard_queue is not None and shard_queue.qsize() > 2:
                        break
                else:
                    return

            # Check if the timeout has not expired
            if time.time() - start_time > timeout:
                raise OioTimeout(
                    'After more than %d seconds, '
                    'the queue is still not nearly empty' % timeout)

            # In the meantime, let the other threads run
            eventlet_yield()

    def flush(self, **kwargs):
        self.flush_queries = True

    def close(self, timeout=10, **kwargs):
        self.running = False
        self.flush_queries = True
        success = True

        # Wait for the timeout to expire before killing all threads
        all_threads = list()
        if self.main_thread is not None:
            all_threads.append(self.main_thread)
        for new_shard in self.new_shards:
            shard_thread = new_shard.get('thread')
            if shard_thread is not None:
                all_threads.append(shard_thread)
        start_time = time.time()
        while True:
            if all((thread.dead for thread in all_threads)):
                break

            # Check if the timeout has not expired
            if time.time() - start_time > timeout:
                for thread in all_threads:
                    thread.kill()
                break

            # In the meantime, let the other threads run
            eventlet_yield()

        # Close the beanstalk connection
        try:
            self.beanstalk.close()
        except Exception as exc:
            self.logger.error('Failed to close beanstalk connection: %s', exc)
            success = False

        # Fetch all results of all threads.
        # These operations should not be blocking because
        # the threads terminated normally or the threads were killed.
        if self.main_thread is not None:
            try:
                self.main_thread.wait()
            except GreenletExit:
                self.logger.error(
                    'Failed to fetch and dispatch queries: '
                    'After more than %d seconds, '
                    'the thread is still not finished', timeout)
                success = False
            except Exception as exc:
                self.logger.error(
                    'Failed to fetch and dispatch queries: %s', exc)
                success = False
        for new_shard in self.new_shards:
            shard_thread = new_shard.get('thread')
            if shard_thread is None:
                continue
            try:
                shard_thread.wait()
            except GreenletExit:
                self.logger.error(
                    'Failed to update new shard (CID=%s): '
                    'After more than %d seconds, '
                    'the thread is still not finished',
                    new_shard['cid'], timeout)
                success = False
            except Exception as exc:
                self.logger.error(
                    'Failed to update new shard (CID=%s): %s',
                    new_shard['cid'], exc)
                success = False

        return success


class ContainerSharding(ProxyClient):

    DEFAULT_STRATEGY = 'shard-with-partition'
    DEFAULT_PARTITION = [50, 50]
    DEFAULT_SHARD_SIZE = 100000
    DEFAULT_SAVE_WRITES_TIMEOUT = 30

    def __init__(self, conf, logger=None, pool_manager=None, **kwargs):
        super(ContainerSharding, self).__init__(
            conf, request_prefix="/container/sharding", logger=logger,
            pool_manager=pool_manager, **kwargs)

        # Make sure to use up-to-date information
        self.force_master = True

        self.admin = AdminClient(
            self.conf, pool_manager=self.pool_manager, logger=self.logger,
            **kwargs)
        self.container = ContainerClient(
            self.conf, pool_manager=self.pool_manager, logger=self.logger,
            **kwargs)
        self.timeout = kwargs.get('save_writes_timeout',
                                  self.DEFAULT_SAVE_WRITES_TIMEOUT)

    def _make_params(self, account=None, reference=None, path=None,
                     cid=None, **kwargs):
        if cid:
            params = {'cid': cid}
        else:
            params = {'acct': account, 'ref': reference}
        if path:
            params.update({'path': path})
        return params

    def _meta_to_shard(self, meta):
        sys = meta['system']
        root_cid = sys.get(M2_PROP_SHARDING_ROOT)
        shard_lower = sys.get(M2_PROP_SHARDING_LOWER)
        shard_upper = sys.get(M2_PROP_SHARDING_UPPER)
        if not any([root_cid, shard_lower, shard_upper]):
            # Not a shard
            return None, None
        shard_account = sys.get(M2_PROP_ACCOUNT_NAME)
        shard_container = sys.get(M2_PROP_CONTAINER_NAME)
        if not all([root_cid, shard_account, shard_container, shard_lower,
                    shard_upper]):
            raise OioException('Missing shard information')
        if not shard_lower.startswith('>'):
            raise OioException('Lower malformed')
        if not shard_upper.startswith('<'):
            raise OioException('Upper malformed')
        shard = {
            'index': -1,
            'lower': shard_lower[1:],
            'upper': shard_upper[1:],
            'cid': cid_from_name(shard_account, shard_container),
            'metadata': None
        }
        return root_cid, shard

    def _check_shards(self, shards, are_new=False, partial=False, **kwargs):
        previous_shard = None
        for i, shard in enumerate(shards):
            shard = self._format_shard(shard, is_new=are_new, **kwargs)
            if shard['index'] != i:
                raise ValueError('Missing "index" %d' % i)

            if previous_shard is None:
                # first shard
                if not partial and shard['lower'] != '':
                    raise ValueError(
                        'Expected an empty "lower" for the first shard')
            elif shard['lower'] != previous_shard['upper']:
                raise ValueError(
                    'Expected the same "lower" as the "upper" '
                    'of the previous shard')

            # Send the shard when everything has been verified.
            # This is why it is necessary to send the previous one
            # and not the current.
            if previous_shard is not None:
                yield previous_shard
            previous_shard = shard

        if previous_shard is not None:
            # last shard
            if not partial and previous_shard['upper'] != '':
                raise ValueError(
                    'Expected an empty "upper" for the last shard')
            yield previous_shard

    def _format_shard(self, shard, is_new=False, **kwargs):
        if not isinstance(shard, dict):
            raise ValueError(
                'Expected an object to describe a shard range')
        formatted_shard = dict()

        shard_index = shard.get('index')
        if shard_index is None:
            raise ValueError('Expected an "index" in the shard range')
        try:
            shard_index = int(shard_index)
        except ValueError:
            raise ValueError('Expected a number for the "index"')
        if shard_index < 0:
            raise ValueError('Expected a positive number for the "index"')
        formatted_shard['index'] = shard_index

        shard_lower = shard.get('lower')
        if shard_lower is None:
            raise ValueError('Expected a "lower" in the shard range')
        if isinstance(shard_lower, bytes):
            shard_lower = shard_lower.decode('utf-8')
        elif not isinstance(shard_lower, str):
            raise ValueError('Expected a string for the "lower"')
        formatted_shard['lower'] = shard_lower

        shard_upper = shard.get('upper')
        if shard_upper is None:
            raise ValueError('Expected an "upper" in the shard range')
        if isinstance(shard_upper, bytes):
            shard_upper = shard_upper.decode('utf-8')
        elif not isinstance(shard_upper, str):
            raise ValueError('Expected a string for the "upper"')
        formatted_shard['upper'] = shard_upper

        if shard['lower'] != '' and shard['upper'] != '' \
                and shard['lower'] >= shard['upper']:
            raise ValueError('Expected an "upper" greater the "lower"')

        if not is_new:
            shard_cid = shard.get('cid')
            if shard_cid is None:
                raise ValueError('Expected a "cid" in the shard range')
            if isinstance(shard_cid, bytes):
                shard_cid = shard_cid.decode('utf-8')
            elif not isinstance(shard_cid, str):
                raise ValueError('Expected a string for the "cid"')
            if not is_hexa(shard_cid, size=STRLEN_CID):
                raise ValueError('Expected a container ID for the "cid"')
            formatted_shard['cid'] = shard_cid

        shard_metadata = shard.get('metadata')
        if shard_metadata is not None \
                and not isinstance(shard['metadata'], dict):
            raise ValueError('Expected a JSON object for the "metadata"')
        formatted_shard['metadata'] = shard_metadata

        shard_count = shard.get('count')
        if shard_count is None and shard_metadata:
            shard_count = shard_metadata.pop('count', None)
        if shard_count is not None:
            try:
                shard_count = int(shard_count)
            except ValueError:
                raise ValueError('Expected a number for the "count"')
            formatted_shard['count'] = shard_count

        return formatted_shard

    def format_shards(self, shards, are_new=False, **kwargs):
        if not isinstance(shards, list):
            try:
                shards = json.loads(shards)
                if not isinstance(shards, list):
                    raise ValueError()
            except (TypeError, ValueError):
                raise ValueError('Expected a list of shard ranges')
        formatted_shards = list()
        for shard in shards:
            formatted_shards.append(
                self._format_shard(shard, is_new=are_new, **kwargs))
        formatted_shards.sort(
            key=lambda formatted_shard: formatted_shard['index'])
        # Check all shards before returning the formatted shards
        return list(self._check_shards(
            formatted_shards, are_new=are_new, **kwargs))

    def _find_shards(self, shard, strategy, strategy_params=None, **kwargs):
        params = self._make_params(cid=shard['cid'], **kwargs)
        params['strategy'] = strategy
        resp, body = self._request('GET', '/find', params=params,
                                   json=strategy_params, **kwargs)
        if resp.status != 200:
            raise exceptions.from_response(resp, body)

        if not body.get('shard_ranges'):
            raise OioException('Missing found shards')
        return body

    def _find_shards_with_partition(self, shard, incomplete_shard=None,
                                    strategy_params=None, **kwargs):
        if strategy_params is None:
            strategy_params = dict()
        partition = strategy_params.get('partition')
        if not partition:
            partition = self.DEFAULT_PARTITION
        else:
            if isinstance(partition, str):
                partition = partition.split(',')
            partition = [float(part) for part in partition]
        threshold = int_value(strategy_params.get('threshold'),
                              self.DEFAULT_SHARD_SIZE)

        formatted_strategy_params = dict()
        formatted_strategy_params['partition'] = partition
        if threshold:
            formatted_strategy_params['threshold'] = threshold

        found_shards = self._find_shards(
            shard, 'shard-with-partition',
            strategy_params=formatted_strategy_params, **kwargs)
        return len(partition), None, found_shards['shard_ranges']

    def _find_shards_with_size(self, shard, incomplete_shard=None,
                               strategy_params=None, **kwargs):
        first_shard_size = None
        shard_size = int_value(strategy_params.get('shard_size'),
                               self.DEFAULT_SHARD_SIZE)
        if incomplete_shard is not None:
            first_shard_size = incomplete_shard.get('available')

        formatted_strategy_params = dict()
        formatted_strategy_params['shard_size'] = shard_size
        if first_shard_size:
            formatted_strategy_params['first_shard_size'] = first_shard_size

        found_shards = self._find_shards(
            shard, 'shard-with-size',
            strategy_params=formatted_strategy_params, **kwargs)
        return None, shard_size, found_shards['shard_ranges']

    STRATEGIES = {
        'shard-with-partition': _find_shards_with_partition,
        'shard-with-size': _find_shards_with_size,
        'rebalance': _find_shards_with_size
    }

    def _find_formatted_shards(self, shard, strategy=None, index=0, **kwargs):
        if strategy is None:
            strategy = self.DEFAULT_STRATEGY

        find_shards = self.STRATEGIES.get(strategy)
        if find_shards is None:
            raise OioException('Unknown sharding strategy')
        nb_shards, shard_size, found_shards = find_shards(
            self, shard, **kwargs)

        found_formatted_shards = list()
        for found_shard in found_shards:
            found_shard['index'] = index
            index += 1
            found_formatted_shard = self._format_shard(
                found_shard, is_new=True, **kwargs)
            found_formatted_shards.append(found_formatted_shard)
        return nb_shards, shard_size, found_formatted_shards

    def find_shards(self, account, container, **kwargs):
        fake_shard = {
            'index': -1,
            'lower': '',
            'upper': '',
            'cid': cid_from_name(account, container),
            'metadata': None
        }
        _, _, formatted_shards = self._find_formatted_shards(
            fake_shard, **kwargs)
        return self._check_shards(formatted_shards,
                                  are_new=True, partial=True, **kwargs)

    def _find_all_formatted_shards(self, root_account, root_container,
                                   strategy=None, **kwargs):
        no_shrinking = True
        if strategy is None:
            strategy = self.DEFAULT_STRATEGY
        if strategy == 'rebalance':
            no_shrinking = False

        current_shards = self.show_shards(root_account, root_container,
                                          **kwargs)

        incomplete_shard = None
        index = 0
        for current_shard in current_shards:
            # Find the possible new shards
            _, shard_size, found_shards = self._find_formatted_shards(
                current_shard, strategy=strategy, index=index,
                incomplete_shard=incomplete_shard, **kwargs)

            # If the last shard was too small,
            # merge this last shard with this first shard
            first_shard = found_shards[0]
            if incomplete_shard is not None:
                if incomplete_shard['upper'] != first_shard['lower']:
                    raise OioException('Shards do not follow one another')
                first_shard['lower'] = incomplete_shard['lower']
                first_shard['count'] = first_shard['count'] \
                    + incomplete_shard['count']

            # Return all found shards, except the last shard
            for found_shard in found_shards[:-1]:
                yield found_shard

            # If the last shard is the correct size,
            # return it immediately
            last_shard = found_shards[-1]
            if no_shrinking or shard_size is None \
                    or last_shard['count'] >= shard_size:
                index = last_shard['index'] + 1
                incomplete_shard = None
                yield last_shard
            else:
                index = last_shard['index']
                incomplete_shard = last_shard
                available = shard_size - incomplete_shard['count']
                if available > 0:
                    incomplete_shard['available'] = available

        if incomplete_shard is not None:
            yield incomplete_shard
            return
        if index > 0:
            return

        # Container not yet sharded
        current_shard = {
            'index': -1,
            'lower': '',
            'upper': '',
            'cid': cid_from_name(root_account, root_container),
            'metadata': None
        }
        _, _, found_shards = self._find_formatted_shards(
            current_shard, strategy=strategy, **kwargs)
        for found_shard in found_shards:
            yield found_shard

    def find_all_shards(self, root_account, root_container, **kwargs):
        formatted_shards = self._find_all_formatted_shards(
            root_account, root_container, **kwargs)
        return self._check_shards(formatted_shards, are_new=True, **kwargs)

    def _prepare_sharding(self, parent_shard, **kwargs):
        params = self._make_params(cid=parent_shard['cid'], **kwargs)
        resp, body = self._request('POST', '/prepare', params=params, **kwargs)
        if resp.status != 200:
            raise exceptions.from_response(resp, body)

        timestamp = int_value(body.get('timestamp'), None)
        if timestamp is not None:
            body['timestamp'] = timestamp
        else:
            raise OioException('Missing timestamp')
        return body

    def _create_shard(self, root_account, root_container, parent_shard,
                      shard, **kwargs):
        shard_account = '.shards_%s' % (root_account)
        shard_container = '%s-%s-%d-%d' % (
            root_container, parent_shard['cid'],
            parent_shard['sharding']['timestamp'],
            shard['index'])

        # Create shard container
        shard_info = shard.copy()
        shard_info['root'] = cid_from_name(root_account, root_container)
        shard_info['parent'] = parent_shard['cid']
        shard_info['timestamp'] = parent_shard['sharding']['timestamp']
        shard_info['master'] = parent_shard['sharding']['master']
        params = self._make_params(account=shard_account,
                                   reference=shard_container, **kwargs)
        resp, body = self._request('POST', '/create_shard', params=params,
                                   json=shard_info, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

        # Fill the shard info with the CID of the shard container
        shard['cid'] = cid_from_name(shard_account, shard_container)

    def _update_new_shard(self, new_shard, queries, **kwargs):
        if not queries:
            return

        params = self._make_params(cid=new_shard['cid'], **kwargs)
        resp, body = self._request('POST', '/update_shard', params=params,
                                   json=queries, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

    def _lock_parent(self, parent_shard, **kwargs):
        params = self._make_params(cid=parent_shard['cid'], **kwargs)
        resp, body = self._request('POST', '/lock', params=params, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

    def _replace_shards(self, root_account, root_container, shards, **kwargs):
        params = self._make_params(account=root_account,
                                   reference=root_container, **kwargs)
        resp, body = self._request('POST', '/replace', params=params,
                                   json=shards, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

    def _clean(self, shard, attempts=1, **kwargs):
        truncated = True
        while truncated:
            params = self._make_params(cid=shard['cid'], **kwargs)
            for i in range(attempts):
                try:
                    resp, body = self._request(
                        'POST', '/clean', params=params, **kwargs)
                    if resp.status != 204:
                        raise exceptions.from_response(resp, body)
                    break
                except BadRequest:
                    raise
                except Exception as exc:
                    if i >= attempts - 1:
                        raise
                    self.logger.warning(
                        'Failed to clean the container (CID=%s), '
                        'retrying...: %s', shard['cid'], exc)
            truncated = boolean_value(resp.getheader('x-oio-truncated'), False)

        try:
            self.admin.vacuum_base('meta2', cid=shard['cid'])
        except Exception as exc:
            self.logger.warning('Failed to vacuum container (CID=%s): %s',
                                shard['cid'], exc)

    def clean_container(self, account, container, cid=None, **kwargs):
        fake_shard = {
            'index': -1,
            'lower': '',
            'upper': '',
            'cid': cid or cid_from_name(account, container),
            'metadata': None
        }
        self._clean(fake_shard, **kwargs)

    def _safe_clean(self, shard, **kwargs):
        try:
            self._clean(shard, attempts=3, **kwargs)
        except Exception as exc:
            self.logger.warning(
                'Failed to clean the container (CID=%s): %s',
                shard['cid'], exc)

    def _show_shards(self, root_account, root_container, limit=None,
                     marker=None, **kwargs):
        params = self._make_params(account=root_account,
                                   reference=root_container, **kwargs)
        params.update({'max': limit, 'marker': marker})
        resp, body = self._request('GET', '/show', params=params, **kwargs)
        if resp.status != 200:
            raise exceptions.from_response(resp, body)
        body['truncated'] = true_value(
            resp.headers.get(HEADER_PREFIX + 'list-truncated'))
        marker_header = HEADER_PREFIX + 'list-marker'
        if marker_header in resp.headers:
            body['next_marker'] = unquote(resp.headers.get(marker_header))
        return body

    def _show_formatted_shards(self, root_account, root_container, **kwargs):
        shards = depaginate(
            self._show_shards,
            listing_key=lambda x: x['shard_ranges'],
            marker_key=lambda x: x.get('next_marker'),
            truncated_key=lambda x: x['truncated'],
            root_account=root_account,
            root_container=root_container,
            **kwargs)
        for i, shard in enumerate(shards):
            shard['index'] = i
            shard = self._format_shard(shard, **kwargs)
            yield shard

    def show_shards(self, root_account, root_container, **kwargs):
        formatted_shards = self._show_formatted_shards(
            root_account, root_container, **kwargs)
        return self._check_shards(formatted_shards, **kwargs)

    def _abort_sharding(self, parent_shard, **kwargs):
        params = self._make_params(cid=parent_shard['cid'], **kwargs)
        resp, body = self._request('POST', '/abort', params=params, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

    def _safe_abort_sharding(self, parent_shard, **kwargs):
        try:
            self._abort_sharding(parent_shard, **kwargs)
        except Exception as exc:
            self.logger.error(
                'Failed to abort sharding (CID=%s): %s',
                parent_shard['cid'], exc)

    def _shard_container(self, root_account, root_container,
                         parent_shard, new_shards, **kwargs):
        self.logger.info(
            'Sharding %s with %s', str(parent_shard), str(new_shards))
        parent_shard['sharding'] = None

        # Prepare the sharding for the container to shard
        # FIXME(adu): ServiceBusy or Timeout
        sharding_info = self._prepare_sharding(parent_shard, **kwargs)
        parent_shard['sharding'] = sharding_info

        # Create the new shards
        for new_shard in new_shards:
            self._create_shard(root_account, root_container, parent_shard,
                               new_shard, **kwargs)

        # Apply saved writes on the new shards in the background
        saved_writes_applicator = SavedWritesApplicator(
            self, parent_shard, new_shards, logger=self.logger, **kwargs)
        try:
            saved_writes_applicator.apply_in_background(**kwargs)
            saved_writes_applicator.wait_until_queue_is_almost_empty(
                timeout=self.timeout, **kwargs)
            saved_writes_applicator.flush(**kwargs)

            # When the queue is empty, lock the container to shard
            self._lock_parent(parent_shard)
        except Exception:
            # Immediately close the applicator
            saved_writes_applicator.close(timeout=0, **kwargs)
            raise

        # When the queue is empty again,
        # remplace the shards in the root container
        if not saved_writes_applicator.close(**kwargs):
            raise OioException('New shards could not be updated correctly')
        # FIXME(adu): ServiceBusy or Timeout
        self._replace_shards(root_account, root_container, new_shards,
                             **kwargs)
        parent_shard.pop('sharding', None)

        cleaners = list()
        root_cid = cid_from_name(root_account, root_container)
        if parent_shard['cid'] == root_cid:
            # Clean up root container
            root_shard = {
                'cid': root_cid
            }
            cleaners.append(eventlet.spawn(
                self._safe_clean, root_shard, **kwargs))
        else:
            # Delete parent shard
            try:
                self.container.container_delete(
                    cid=parent_shard['cid'], force=True, **kwargs)
            except Exception as exc:
                # "Create" an orphan shard
                self.logger.warning(
                    'Failed to delete old parent shard (CID=%s): %s',
                    parent_shard['cid'], exc)

        # Clean up new shards
        for new_shard in new_shards:
            cleaners.append(eventlet.spawn(
                self._safe_clean, new_shard, **kwargs))
        for cleaner in cleaners:
            cleaner.wait()

    def _rollback_sharding(self, parent_shard, new_shards, **kwargs):
        if 'sharding' not in parent_shard:
            # Sharding is complete, but not everything has been cleaned up
            self.logger.error(
                'Failed to clean up at the end of the sharding (CID=%s)',
                parent_shard['cid'])
            return

        if parent_shard['sharding'] is None:
            # Sharding hasn't even started
            return

        self.logger.error(
            'Failed to shard container (CID=%s), aborting...',
            parent_shard['cid'])
        self._safe_abort_sharding(parent_shard, **kwargs)
        for new_shard in new_shards:
            if 'cid' not in new_shard:
                # Shard doesn't exist yet
                continue
            self.logger.info(
                'Deleting new shard (CID=%s)', new_shard['cid'])
            try:
                self.container.container_delete(
                    cid=new_shard['cid'], force=True, **kwargs)
            except Exception as exc:
                # "Create" an orphan shard
                self.logger.warning(
                    'Failed to delete new shard (CID=%s): %s',
                    new_shard['cid'], exc)

        # Drain beanstalk tube
        beanstalk_url = parent_shard['sharding']['queue']
        beanstalk_tube = parent_shard['cid'] + '.sharding-' \
            + str(parent_shard['sharding']['timestamp'])
        self.logger.info(
            'Drain beanstalk tube (URL=%s TUBE=%s)',
            beanstalk_url, beanstalk_tube)
        try:
            beanstalk = Beanstalk.from_url(beanstalk_url)
            beanstalk.drain_tube(beanstalk_tube)
        except Exception as exc:
            self.logger.warning(
                'Failed to drain the beanstalk tube (URL=%s TUBE=%s): %s',
                beanstalk_url, beanstalk_tube, exc)

    def _almost_safe_shard_container(self, root_account, root_container,
                                     parent_shard, new_shards, **kwargs):
        try:
            self._shard_container(root_account, root_container,
                                  parent_shard, new_shards, **kwargs)
        except Exception:
            try:
                self._rollback_sharding(parent_shard, new_shards, **kwargs)
            except Exception:
                self.logger.exception(
                    'Failed to rollback sharding (CID=%s)',
                    parent_shard['cid'])
            raise

    def _shard_container_by_dichotomy(self, root_account, root_container,
                                      parent_shard, new_shards,
                                      max_new_shards_per_op=2, **kwargs):
        new_shards_size = len(new_shards)
        if new_shards_size <= max_new_shards_per_op:
            self._almost_safe_shard_container(
                root_account, root_container, parent_shard, new_shards,
                **kwargs)
            return

        sub_new_shards_list = list()
        tmp_new_shards = list()
        start_index = 0
        end_index = 0
        for i in range(max_new_shards_per_op):
            end_index += new_shards_size // max_new_shards_per_op
            if i < new_shards_size % max_new_shards_per_op:
                end_index += 1
            sub_new_shards = new_shards[start_index:end_index]
            sub_new_shards_list.append(sub_new_shards)
            start_index = end_index

            tmp_parent_shard = None
            if len(sub_new_shards) == 1:
                tmp_parent_shard = sub_new_shards[0]
            else:
                tmp_parent_shard = sub_new_shards[0].copy()
                tmp_parent_shard['upper'] = sub_new_shards[-1]['upper']
            tmp_new_shards.append(tmp_parent_shard)

        self._almost_safe_shard_container(
            root_account, root_container, parent_shard, tmp_new_shards,
            **kwargs)

        for i in range(max_new_shards_per_op):
            sub_new_shards = sub_new_shards_list[i]
            tmp_parent_shard = tmp_new_shards[i]
            if len(sub_new_shards) == 1:
                # No sharding to do
                continue
            self._shard_container_by_dichotomy(
                root_account, root_container, tmp_parent_shard, sub_new_shards,
                max_new_shards_per_op=max_new_shards_per_op,
                **kwargs)

    def replace_shard(self, account, container, new_shards,
                      enable=False, **kwargs):
        meta = self.container.container_get_properties(
            account, container, **kwargs)

        sys = meta['system']
        if int_value(sys.get(M2_PROP_SHARDS), 0):
            raise OioException('It is a root container')

        root_account = None
        root_container = None
        root_cid, current_shard = self._meta_to_shard(meta)
        if root_cid is None:
            # First sharding
            if not enable:
                raise ValueError(
                    'Sharding is not enabled for this container')
            root_account = account
            root_container = container
            current_shard = {
                'index': -1,
                'lower': '',
                'upper': '',
                'cid': cid_from_name(account, container),
                'metadata': None
            }
        else:
            root_meta = self.container.container_get_properties(
                cid=root_cid, **kwargs)
            root_sys = root_meta['system']
            root_account = root_sys.get(M2_PROP_ACCOUNT_NAME)
            root_container = root_sys.get(M2_PROP_CONTAINER_NAME)

        shards_for_sharding = list(self._check_shards(
            new_shards, are_new=True, partial=True, **kwargs))
        if not shards_for_sharding:
            raise OioException('Missing new shards')
        if shards_for_sharding[0]['lower'] != current_shard['lower']:
            raise OioException('Wrong first lower for the new shards')
        if shards_for_sharding[-1]['upper'] != current_shard['upper']:
            raise OioException('Wrong last upper for the new shards')
        if len(shards_for_sharding) == 1:
            # Shard doesn't change
            return False

        self._shard_container_by_dichotomy(
            root_account, root_container, current_shard, shards_for_sharding,
            **kwargs)
        return True

    def _sharding_replace_shards(self, root_account, root_container,
                                 current_shards, current_shard,
                                 new_shards, new_shard, **kwargs):
        tmp_new_shard = None
        shards_for_sharding = list()
        shards_for_sharding.append(new_shard)
        while True:
            try:
                new_shard = next(new_shards)
            except StopIteration:
                raise OioException('Should never happen')

            if current_shard['upper'] == new_shard['upper']:
                shards_for_sharding.append(new_shard)
                break
            elif current_shard['upper'] == '' \
                    or (new_shard['upper'] != '' and
                        current_shard['upper'] > new_shard['upper']):
                shards_for_sharding.append(new_shard)
            else:
                tmp_new_shard = new_shard.copy()
                tmp_new_shard['upper'] = current_shard['upper']
                shards_for_sharding.append(tmp_new_shard)
                break

        self._shard_container_by_dichotomy(
            root_account, root_container, current_shard, shards_for_sharding,
            **kwargs)

        if tmp_new_shard is None:
            # current_shard['upper'] == new_shard['upper']:
            if current_shard['upper'] == '':
                # all new shards have been created
                return None, None

            try:
                current_shard = next(current_shards)
            except StopIteration:
                raise OioException('Should never happen')
            try:
                new_shard = next(new_shards)
            except StopIteration:
                raise OioException('Should never happen')
        else:
            current_shard = tmp_new_shard
        return current_shard, new_shard

    def _shrinking_replace_shards(self, root_account, root_container,
                                  current_shards, current_shard,
                                  new_shards, new_shard, **kwargs):
        raise NotImplementedError('Shrinking not implemented')

    def replace_all_shards(self, root_account, root_container, new_shards,
                           **kwargs):
        current_shards = self.show_shards(
            root_account, root_container, **kwargs)
        new_shards = self._check_shards(new_shards, are_new=True, **kwargs)

        current_shard = None
        try:
            current_shard = next(current_shards)
        except StopIteration:
            raise ValueError(
                'No current shard for this container')
        new_shard = None
        try:
            new_shard = next(new_shards)
        except StopIteration:
            new_shard = {
                'index': -1,
                'lower': '',
                'upper': '',
                'cid': cid_from_name(root_account, root_container),
                'metadata': None
            }

        modified = False
        while current_shard is not None and new_shard is not None:
            # Sanity check
            if current_shard['lower'] != new_shard['lower']:
                raise OioException('Should never happen')

            if current_shard['upper'] == new_shard['upper']:
                # Shard doesn't change
                if current_shard['upper'] == '':
                    # All new shards have been created
                    current_shard = None
                    new_shard = None
                else:
                    try:
                        current_shard = next(current_shards)
                    except StopIteration:
                        raise OioException('Should never happen')
                    try:
                        new_shard = next(new_shards)
                    except StopIteration:
                        raise OioException('Should never happen')
                continue
            modified = True

            if current_shard['upper'] == '' \
                    or (new_shard['upper'] != '' and
                        current_shard['upper'] > new_shard['upper']):
                current_shard, new_shard = self._sharding_replace_shards(
                    root_account, root_container,
                    current_shards, current_shard,
                    new_shards, new_shard, **kwargs)
                # Sub-change is complete
                continue

            if new_shard['upper'] == '' \
                    or (current_shard['upper'] != '' and
                        current_shard['upper'] < new_shard['upper']):
                current_shard, new_shard = self._shrinking_replace_shards(
                    root_account, root_container,
                    current_shards, current_shard,
                    new_shards, new_shard, **kwargs)
                # Sub-change is complete
                continue

            raise OioException('Should never happen')
        return modified