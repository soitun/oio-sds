#!/usr/bin/env python

# Copyright (C) 2021-2022 OVH SAS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import argparse
from hashlib import blake2b
from oio.common.configuration import read_conf

from oio.account.backend_fdb import AccountBackendFdb
from oio.account.iam_fdb import FdbIamDb

from oio.account.backend import AccountBackend
from oio.account.iam import RedisIamDb

from oio.common.logger import get_logger
from oio.common.utils import parse_conn_str
from oio.common.redis_conn import RedisConnection


# Read from redis db and write to fdb db

DEFAULT_IAM_CONNECTION = 'redis://127.0.0.1:6379'


class RedisBucketDb(RedisConnection):
    """
    Reused class to get owner of bucket
    """

    def __init__(self, host=None, sentinel_hosts=None, sentinel_name=None,
                 prefix="s3bucket:", **kwargs):
        super(RedisBucketDb, self).__init__(
            host=host, sentinel_hosts=sentinel_hosts,
            sentinel_name=sentinel_name, **kwargs)
        self._prefix = prefix

    def _key(self, bucket):
        return self._prefix + bucket

    def get_owner(self, bucket):
        """
        Get the owner of a bucket.

        :returns: the name of the account owning the bucket or None
        """
        owner = self.conn_slave.get(self._key(bucket))
        return owner.decode('utf-8') if owner is not None else owner


def export_acct_cts_bucket(accounts):
    print("Export accounts/buckets")
    for acct in accounts:
        infos_account = backend_redis.info_account(acct)
        # print('info_accounts: ', infos_account)
        kwargs = {'ctime': infos_account['ctime']}
        created = backend_fdb.create_account(acct, **kwargs)
        if created is None:
            raise Exception("Failed to create account:" + acct)

        if 'metadata' in infos_account.keys():
            metadata = infos_account['metadata']
            success = backend_fdb.update_account_metadata(acct, metadata, {})

            if success is None:
                raise Exception("Failed to update metadata account:" + acct)

        # reserved here deserves an explanation:
        containers = reversed(sorted(backend_redis.list_containers(acct)))
        for ct in containers:
            # print('ct:', ct)
            ct_name = ct[0]
            ct_infos = backend_redis.get_container_info(acct, ct_name)
            # print('ct_infos:', ct_infos)

            params = {
                'account_id': acct,
                'cname': ct_name,
                'mtime': ct_infos[b'mtime'],
                'dtime': ct_infos[b'dtime'],
                'object_count': ct_infos[b'objects'],
                'bytes_used': ct_infos[b'bytes'],
                'region': location
            }
            if ct_infos[b'dtime'] == b'0':
                params['dtime'] = None

            if b'bucket' in ct_infos.keys():
                params['bucket_name'] = ct_infos[b'bucket'].decode('utf-8')
            try:
                backend_fdb.update_container(**params)
            except Exception as exc:
                raise Exception("Error, failed to create container:" + ct_name,
                                exc)

            bucket_params = {}
            if b'bucket' in ct_infos.keys():
                if b'replication_enabled' in ct_infos.keys() and \
                   ct_infos[b'replication_enabled']:
                    bucket_params['replication_enabled'] = True
                    backend_fdb.update_bucket_metadata(params['bucket_name'],
                                                       bucket_params)


def export_bucket_db(accounts):
    print('Export bucket_db')

    for acct in accounts:
        buckets = backend_redis.list_buckets(acct)

        if buckets:
            buckets_infos = buckets[0]
            for bucket in buckets_infos:
                bucket_name = bucket['name']
                # bk_infos = backend_redis.get_bucket_info(bucket_name)
                owner = bucket_db_redis.get_owner(bucket_name)

                if owner:
                    backend_fdb.reserve_bucket(bucket_name, owner)
                    backend_fdb.set_bucket_owner(bucket_name, owner)
                else:
                    raise Exception('Error: no owner bucket:' + bucket_name)


def export_iam(accounts):
    print('Export iam')
    for acct in accounts:
        users = iam_db_redis.list_users(acct)
        for user in users:
            # print('user:', user)
            policies = iam_db_redis.list_user_policies(acct, user)
            for policy in policies:
                policy_content = iam_db_redis.get_user_policy(acct, user,
                                                              policy)
                # print('policy_content:', policy_content)
                data = json.loads(policy_content)
                update_date = data['UpdateDate']
                iam_db_fdb.put_user_policy(acct, user, policy_content, policy,
                                           update_date=update_date)


def hash_redis():
    print('hash redis')
    dict_hash = dict()
    accounts = backend_redis.list_accounts()
    sorted_accounts = (sorted(accounts))
    hash_accounts = blake2b(
                    bytes('-'.join(sorted_accounts), 'utf-8')).hexdigest()
    dict_hash['accounts'] = hash_accounts
    for acct in sorted_accounts:
        # print('account:', acct)
        dict_hash[acct] = {}
        infos_account = backend_redis.info_account(acct)
        infos_account.pop('replication_enabled')
        print('info_account:', infos_account)
        sorted_account = dict(sorted(infos_account.items()))
        acct_fields = '-'.join([f'{key}-{value}' for key, value in
                               sorted_account.items()])
        acct_to_hash = '-'.join([acct, acct_fields])
        # print('hash_acct:', acct_to_hash)
        hash_account = blake2b(bytes(acct_to_hash, 'utf-8')).hexdigest()
        # print('hash_account:', hash_account)
        dict_hash[acct]['account'] = hash_account
        containers = backend_redis.list_containers(acct)
        # print('containers:', containers)

        extend_list = sum(containers, [])
        # print('extend_list:', extend_list)
        containers_to_hash = '-'.join(str(x) for x in extend_list)
        hash_containers = \
            blake2b(bytes(containers_to_hash, 'utf-8')).hexdigest()
        # print('hash_containers:', hash_containers)
        dict_hash[acct]['containers'] = hash_containers
        containers_info = acct
        for ct in containers:
            ct_name = ct[0]
            ct_infos = backend_redis.get_container_info(acct, ct_name)
            ct_infos.pop(bytes('dtime', 'utf-8'))
            # print('ct:', ct_infos)

            sorted_ct = dict(sorted(ct_infos.items()))
            ct_fields = []
            print('sorted_ct:', sorted_ct)
            for k, v in sorted_ct.items():
                print(k, v)
                if isinstance(v, int):
                    ct_fields.append('-'.join([ k.decode('utf-8') ,str(v)]))
                else:
                    ct_fields.append('-'.join([k.decode('utf-8') ,
                    v.decode('utf-8')]))

            #ct_fields = [f'{key}-{value}' for key, value in sorted_ct.items()]
            print('ct_fields:', ct_fields)
            ct_to_hash = '-'.join([str(x) for x in ct_fields])
            # print('ct_to_hash:', ct, ct_to_hash)

            containers_info = '-'.join([containers_info, ct_name, ct_to_hash])
            # print('containers_info:', containers_info)

            if b'bucket' in ct_infos.keys():
                pass

        hash_ct = blake2b(bytes(containers_info, 'utf-8')).hexdigest()
        print('containers_info:',containers_info, hash_ct)
        dict_hash[acct]['containers_info'] = hash_ct

        buckets = backend_redis.list_buckets(acct)

        buckets_to_hash = acct
        print('buckets_to_hash:', buckets_to_hash, buckets)
        if buckets:
            buckets_infos = buckets[0]
            print('buckets_infos:', buckets_infos)
            # print('buckets:',  type(buckets))
            bucket_to_hash = '-'.join(str(x) for x in buckets_infos)
            buckets_to_hash = '-'.join([buckets_to_hash, bucket_to_hash])
            # print('buckets:', buckets_infos, bucket_to_hash)

            for bucket in buckets_infos:
                bucket_name = bucket['name']
                bk_infos = backend_redis.get_bucket_info(bucket_name)
                sorted_bk_infos = dict(sorted(bk_infos.items()))
                owner = bucket_db_redis.get_owner(bucket_name)
                print('bk_infos:', bucket_name, sorted_bk_infos)
                bk_fields =[]
                for k, v in sorted_bk_infos.items():
                    print(k, v)
                    if isinstance(v, int):
                        bk_fields.append('-'.join([ k.decode('utf-8') ,str(v)]))
                    else:
                        bk_fields.append('-'.join([k.decode('utf-8') ,
                        v.decode('utf-8')]))
                bucket_inf_list = '-'.join([str(x) for x in bk_fields])
                #print('bklist:', owner, buckets_to_hash, bucket_inf_list)
                buckets_to_hash = '-'.join(['owner', owner, buckets_to_hash,
                                           bucket_inf_list])

            hash_buckets = blake2b(bytes(buckets_to_hash, 'utf-8')).hexdigest()
            print('buckets:', buckets_to_hash, hash_buckets)
            dict_hash[acct]['buckets'] = hash_buckets

        users = iam_db_redis.list_users(acct)
        # print('users:', users)
        users_to_hash = '-'.join(users)
        hash_users = blake2b(bytes(users_to_hash, 'utf-8')).hexdigest()
        # print('users_to_hash:' ,users_to_hash, hash_users)

        dict_hash[acct]['users'] = hash_users

        user_policies = acct
        for user in users:
            # print('user:', user)
            user_policies = '-'.join([user_policies, user])
            policies = iam_db_redis.list_user_policies(acct, user)
            for policy in policies:
                policy_content = iam_db_redis.get_user_policy(acct, user,
                                                              policy)
                user_policies = '-'.join([user_policies, policy,
                                         policy_content])

        hash_policies = blake2b(bytes(user_policies, 'utf-8')).hexdigest()
        # print('user_policies:', user_policies, hash_policies)
        dict_hash[acct]['policies'] = hash_policies
    return dict_hash


def hash_fdb():
    print('hash fdb')
    dict_hash = dict()
    accounts = backend_fdb.list_accounts()
    hash_accounts = blake2b(bytes('-'.join(accounts), 'utf-8')).hexdigest()
    dict_hash['accounts'] = hash_accounts
    for acct in accounts:
        # print('account:', acct)
        dict_hash[acct] = {}
        infos_account = backend_fdb.info_account(acct)
        infos_account.pop('regions')
        infos_account.pop('mtime')
        print('info_account:', infos_account)

        sorted_account = dict(sorted(infos_account.items()))
        acct_fields = '-'.join([f'{key}-{value}' for key, value in
                                sorted_account.items()])
        acct_to_hash = '-'.join([acct, acct_fields])
        # print('hash_acct:', acct_to_hash)
        hash_account = blake2b(bytes(acct_to_hash, 'utf-8')).hexdigest()
        # print('hash_account:', hash_account)
        dict_hash[acct]['account'] = hash_account
        containers = backend_fdb.list_containers(acct)
        # print('containers:', containers)

        extend_list = sum(containers, [])
        # print('extend_list:', extend_list)
        containers_to_hash = '-'.join(str(x) for x in extend_list)
        hash_containers = blake2b(
                            bytes(containers_to_hash, 'utf-8')).hexdigest()
        # print('hash_containers:', hash_containers)
        dict_hash[acct]['containers'] = hash_containers
        containers_info = acct
        for ct in containers:
            ct_name = ct[0]
            ct_infos = backend_fdb.get_container_info(acct, ct_name)
            ct_infos.pop('region')

            # print('ct:', ct_infos)
            sorted_ct = dict(sorted(ct_infos.items()))

            ct_fields = [f'{key}-{value}' for key, value in sorted_ct.items()]
            # print('ct_fields:', ct_fields)
            ct_to_hash = '-'.join([str(x) for x in ct_fields])
            # print('ct_to_hash:', ct, ct_to_hash)

            containers_info = '-'.join([containers_info, ct_name, ct_to_hash])
            # ('containers_info:', containers_info)

            if b'bucket' in ct_infos.keys():
                pass

        hash_ct = blake2b(bytes(containers_info, 'utf-8')).hexdigest()
        print('containers_info:',containers_info, hash_ct)
        dict_hash[acct]['containers_info'] = hash_ct

        buckets = backend_fdb.list_buckets(acct)
        buckets_to_hash = acct
        if buckets:
            buckets_infos = buckets[0]

            # print('buckets:',  type(buckets))
            bucket_to_hash = '-'.join(str(x) for x in buckets_infos)
            buckets_to_hash = '-'.join([buckets_to_hash, bucket_to_hash])
            # print('buckets:', buckets_infos, bucket_to_hash)

            for bucket in buckets_infos:
                bucket_name = bucket['name']
                bk_infos = backend_fdb.get_bucket_info(bucket_name)
                owner = backend_fdb.get_bucket_owner(bucket_name)

                # region field is not present in redis
                # remove it for comparaison:
                bk_infos.pop('region', None)
                print('bk_infos:', bucket_name, bk_infos)
                if not 'replication_enabled' in bk_infos.keys():
                    bk_infos['replication_enabled'] = False
                bk_fields =[]
                for k, v in bk_infos.items():
                    print(k, v)
                    bk_fields.append('-'.join([k , str(v)]))
                bucket_inf_list = '-'.join([str(x) for x in bk_fields])
                # print(owner, buckets_to_hash, bucket_inf_list)
                buckets_to_hash = '-'.join(['owner', owner, buckets_to_hash,
                                           bucket_inf_list])

            hash_buckets = blake2b(bytes(buckets_to_hash, 'utf-8')).hexdigest()
            print('buckets:', buckets_to_hash, hash_buckets)
            dict_hash[acct]['buckets'] = hash_buckets

        users = iam_db_fdb.list_users(acct)
        # print('users:', users)
        users_to_hash = '-'.join(users)
        hash_users = blake2b(bytes(users_to_hash, 'utf-8')).hexdigest()
        # print('users_to_hash:' ,users_to_hash, hash_users)

        dict_hash[acct]['users'] = hash_users

        user_policies = acct
        for user in users:
            # print('user:', user)
            user_policies = '-'.join([user_policies, user])
            policies = iam_db_fdb.list_user_policies(acct, user)
            for policy in policies:
                policy_content = iam_db_fdb.get_user_policy(acct, user, policy)
                user_policies = '-'.join([user_policies, policy,
                                          policy_content])

        hash_policies = blake2b(bytes(user_policies, 'utf-8')).hexdigest()
        # print('user_policies:', user_policies, hash_policies)
        dict_hash[acct]['policies'] = hash_policies
    return dict_hash


if __name__ == '__main__':
    descr = """
        Export data from redis to fdb database.
    """
    parser = argparse.ArgumentParser(description=descr)

    parser.add_argument(
        "--conf",
        metavar='<file>',
        default=[],
        help="Config file for redis and fdb")
    parser.add_argument(
        "--clean-fdb",
        default=False,
        action="store_true",
        help="Clean fdb database")

    parser.add_argument(
        "--location",
        required=True,
        help="Specify bucket location")
    args = parser.parse_args()

    if not args.conf:
        raise ValueError("Missing conf file")

    location = args.location
    conf_file = args.conf
    conf = read_conf(conf_file, 'account-export')
    logger = get_logger(conf)
    iam_conn = conf.get('iam.connection')

    bucket_db_conn = conf.get('bucketdb.connection')
    scheme, netloc, bucket_db_kwargs = parse_conn_str(bucket_db_conn)
    if scheme == 'redis+sentinel':
        bucket_db_kwargs['sentinel_hosts'] = netloc
    else:
        bucket_db_kwargs['host'] = netloc

    scheme, netloc, iam_kwargs = parse_conn_str(iam_conn)
    if scheme == 'redis+sentinel':
        iam_kwargs['sentinel_hosts'] = netloc
    else:
        iam_kwargs['host'] = netloc

    # Init fdb backend
    backend_fdb = AccountBackendFdb(conf, logger=logger)
    iam_db_fdb = FdbIamDb(conf, logger=logger, **iam_kwargs)
    backend_fdb.init_db()
    iam_db_fdb.init_db()

    if args.clean_fdb:
        backend_fdb.db.clear_range(b'\x00', b'\xfe')
        iam_db_fdb.db = None
        iam_db_fdb.init_db()

    # Init redis backend
    backend_redis = AccountBackend(conf)
    iam_db_redis = RedisIamDb(logger=logger, **iam_kwargs)

    bucket_db_redis = RedisBucketDb(**bucket_db_kwargs)

    # list accounts
    accounts = backend_redis.list_accounts()

    # accounts/buckets
    export_acct_cts_bucket(accounts)

    # bucket_db
    export_bucket_db(accounts)
    # iam
    export_iam(accounts)

    # hash redis infos
    hash_redis_infos = hash_redis()

    # hash fdb infos
    hash_fdb_infos = hash_fdb()

    # Dicts are ordered,a simple == could be sufficient for comparaison
    # However double checking could be need to  report some xor difference
    for key, value in hash_fdb_infos.items():
        if isinstance(value, dict):
            for k, v in value.items():
                if hash_fdb_infos[key][k] != hash_redis_infos[key][k]:
                    print('Diff key:', key, k, hash_fdb_infos[key][k],
                          hash_redis_infos[key][k])
                    raise Exception('diff found')
        else:
            if hash_fdb_infos[key] != hash_redis_infos[key]:
                print('Diff key:', key, value)
                raise Exception('diff found')

    # compare dict of hash
    hash_1 = blake2b(bytes(str(hash_redis_infos), 'utf-8')).hexdigest()
    hash_2 = blake2b(bytes(str(hash_fdb_infos), 'utf-8')).hexdigest()

    if(hash_1 == hash_2):
        print('hash ok')
    else:
        print('Difference in hash')
