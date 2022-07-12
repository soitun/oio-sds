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

import re
import time

import fdb
from fdb.tuple import unpack
from functools import wraps
from oio.common.easy_value import boolean_value

from oio.common.json import json
from oio.common.exceptions import ServiceBusy
from oio.account.common_fdb import CommonFdb
from oio.common.logger import get_logger

fdb.api_version(CommonFdb.FDB_VERSION)


def catch_service_errors(func):
    """
    :raises `ServiceBusy`: in case of a fdb service error
    """

    @wraps(func)
    def catch_service_errors_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (fdb.FDBError) as err:
            raise ServiceBusy(message=str(err))

    return catch_service_errors_wrapper


class FdbIamDb(object):
    """
    High-level API to save IAM rules in a foundationdb database.
    """

    IAM_KEY_PREFIX = 'iam'
    DEFAULT_ALLOW_EMPTY_POLICY_NAME = True

    def __init__(self, conf=None, logger=None, **kwargs):
        self.conf = conf
        self.logger = logger or get_logger(conf, 'IAM')

        self.main_namespace_name = conf.get(
            'main_namespace_name', CommonFdb.MAIN_NAMESPACE)
        self.iam_prefix = conf.get('iam_prefix', self.IAM_KEY_PREFIX)
        self.allow_empty_policy_name = boolean_value(
            conf.get('allow_empty_policy_name'),
            self.DEFAULT_ALLOW_EMPTY_POLICY_NAME)

        self.name_regex = re.compile(r'[\w+=,.@-]+')
        self.db = None
        self.namespace = None
        self.iam_space = None

    def init_db(self, event_model='gevent'):
        """
        This method makes connexion to fdb database. It could be called
        any time in mono process, but in case we fork processes it should be
        called after forking in gunicorn.
        This is the reason why this task is not done inside constructor.
        """
        if self.conf is None:
            self.fdb_file = CommonFdb.DEFAULT_FDB
        else:
            self.fdb_file = self.conf.get('fdb_file', CommonFdb.DEFAULT_FDB)

        try:
            if self.db is None:
                self.db = fdb.open(self.fdb_file, event_model=event_model)
        except Exception as exc:
            self.logger.error("can't open fdb file: %s exception %s",
                              self.fdb_file, exc)
            raise
        try:
            self.namespace = fdb.directory.create_or_open(
                self.db, (self.main_namespace_name,))
            self.iam_space = self.namespace.create_or_open(
                self.db, self.iam_prefix)
        except Exception as exc:
            self.logger.warning("Directory create exception  %s", exc)

    @catch_service_errors
    def delete_user_policy(self, account, user, policy_name=''):
        """
        Delete an IAM user policy.

        :rtype: bool
        :returns: True if the policy has been deleted, False if it was
            already deleted.
        """
        deleted = self._delete_user_policy(self.db, account, user, policy_name)
        return deleted

    @catch_service_errors
    def list_users(self, account):
        """
        Get the names of all IAM users of the specified account.
        """
        users = self._list_users(self.db, account)
        return users

    @catch_service_errors
    def list_user_policies(self, account, user):
        """
        Get the names of all the configured policies for the specified user.
        """
        policies = self._list_user_policies(self.db, account, user)
        return policies

    @catch_service_errors
    def load_merged_user_policies(self, account, user):
        """
        Merge all policies of the specified user into a single policy
        document.

        :rtype: dict
        :returns: a dictionary with one 'Statement' key with the list
            of all statements (not JSON)
        """
        all_statements = self._load_merged_user_policies(self.db, account,
                                                         user)
        if all_statements:
            return {'Statement': all_statements}
        else:
            return None

    @catch_service_errors
    def get_user_policy(self, account, user, policy_name=''):
        """
        Load an IAM policy for the specified user.

        :rtype: str
        """
        policy = self._get_user_policy(self.db, account, user, policy_name)
        return policy.decode('utf-8') if policy else None

    def load_rules_str_for_user(self, account, user):
        """
        Backward compatibility wrapper.
        """
        return self.get_user_policy(account, user)

    @catch_service_errors
    def put_user_policy(self, account, user, policy, policy_name='',
                        update_date=None):
        """
        Save an IAM policy for the specified user.

        :param policy: JSON-formatted string
        :type policy: str
        :param policy_name: name of the policy (empty string if not set)
        """
        if not isinstance(policy, str):
            raise TypeError("policy parameter must be a string")
        if not policy_name and not self.allow_empty_policy_name:
            raise ValueError('policy name cannot be empty')
        if policy_name and not self.name_regex.fullmatch(policy_name):
            raise ValueError('policy name does not match %s' % (
                self.name_regex.pattern))
        # XXX: we should also match user name, but unfortunately, when using
        # tempauth, user names have the ':' character between the project name
        # and the actual user name.
        try:
            policy_obj = json.loads(policy)

            # for export compatibliy
            if update_date is None:
                policy_obj['UpdateDate'] = time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                                         time.gmtime())
            else:
                policy_obj['UpdateDate'] = update_date
            # Strip spaces and new lines
            policy = json.dumps(policy_obj, separators=(',', ':'))
        except ValueError as err:
            raise ValueError('policy is not JSON-formatted: %s' % err)
        self._put_user_policy(self.db, account, user, policy_name, policy)

    def save_rules_str_for_user(self, account, user, rules):
        """
        Backward compatibility wrapper.
        """
        return self.put_user_policy(account, user, policy=rules)

    def _append_policy_statements(self, account, user, policy_name, policy,
                                  all_statements):
        """
        Decode the provide policy (JSON bytes) and append all of its
        statements to the list. Does nothing but logging if the policy
        cannot be decoded.
        """
        try:
            policy_obj = json.loads(policy.decode('utf-8'))
            statements = policy_obj.get('Statement')
            if not statements:
                self.logger.warning(
                    'policy %r for %s/%s has no Statement',
                    policy_name, account, user)
            else:
                all_statements.extend(statements)
        except ValueError as err:
            self.logger.warning(
                'policy %r for %s/%s is not JSON-formatted: %s',
                policy_name, account, user, err)

    @fdb.transactional
    def _delete_user_policy(self, tr, account, user, policy_name):
        if policy_name:
            tr.clear_range_startswith(
                self.iam_space.pack((account, user, policy_name)))
        else:
            tr.clear_range_startswith(self.iam_space.pack((account, user,)))
        return True

    @fdb.transactional
    def _list_users(self, tr, account):
        iterator = tr.get_range_startswith(self.iam_space.pack((account,)))
        users = list()
        for key, _ in iterator:
            _, _, user, _ = unpack(key)
            if user not in users:
                users.append(user)
        return users

    @fdb.transactional
    def _list_user_policies(self, tr, account, user):
        iterator = tr.get_range_startswith(
            self.iam_space.pack((account, user)))
        policies = list()
        for key, _ in iterator:
            _, _, _, policy = unpack(key)
            policies.append(policy)
        return policies

    @fdb.transactional
    def _load_merged_user_policies(self, tr, account, user):
        iterator = tr.get_range_startswith(
            self.iam_space.pack((account, user)))
        statements = list()
        for key, value in iterator:
            _, _, _, policy = unpack(key)
            if value is not None:
                if not policy:
                    if self.allow_empty_policy_name:
                        self._append_policy_statements(account, user, '',
                                                       value, statements)
                else:
                    self._append_policy_statements(account, user, policy,
                                                   value, statements)
        return statements

    @fdb.transactional
    def _get_user_policy(self, tr, account, user, policy_name):
        policy = tr[self.iam_space.pack((account, user, policy_name))]
        return policy if policy.present() else None

    @fdb.transactional
    def _put_user_policy(self, tr, acct, user, policy_name, policy):
        tr[self.iam_space.pack((acct, user, policy_name))] = \
            bytes(str(policy), 'utf-8')
