#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
---
module: bigiq_regkey_pool_licensor
short_description: License a BIG-IP from a BIG-IQ Regkey License Pool
description:
  - Using the BIG-IQ API to license a BIG-IP from a BIG-IQ Regkey License Pool.
version_added: "2.5"
options:
  name:
    description:
      - Name for this license activation
    required: True
    default: BIG-IP Regkey Licensor
  state:
    description:
      - State controlling license activation or revocation
    required: True
    default: present
  bigiq_hostname:
    description:
      - The BIG-IQ API endpoint
    required: True
    default: 192.168.245.1
  bigiq_username:
    description:
      - The username to username to use for BIG-IQ API session
    required: False
    default: admin
  bigiq_password:
    description:
      - The password to use for the BIG-IQ API session
    required: False
    default: admin
    no_log: True
  bigiq_license_pool_name:
    description:
      - The name or ID of the BIG-IQ license pool to find available Regkey
    required: True
    default: bigip-ve-pool-1
  bigip_management_ip:
    description:
      - The BIG-IP management IP to be activated
    required: True
    default: 192.168.245.1
  bigip_management_port:
    description:
      - The BIG-IP management TCP port for license activation
    required: False
    default: 443
  bigip_username:
    description:
      - The BIG-IP username for BIG-IQ to use for license activation
    required: False
    default: admin
  bigip_password:
    description:
      - The BIG-IP password for BIG-IQ to use for license activation
    required: False
    default: admin
    no_log: True
  check_mode:
    description:
      - Detects if the desired state is already present with alterations
    default: false
extends_documentation_fragment: f5
author:
  - John Gruber (@jgruber)
'''

EXAMPLES = r'''
- name: Create a ...
  bigiq_regkey_licensor:
    name: BIG-IP regkey pool licensor
    state: present
    bigiq_hostname: 192.168.245.1
    bigiq_username: admin
    bigiq_password: secret
    bigiq_license_pool_name: bigip-ve-pool-1
    bigip_management_ip: 192.168.245.5
    bigip_management_port: 443
    bigip_username: admin
    bigip_password: password
    check_mode: true
    delegate_to: localhost
'''

RETURN = r'''
pool_uuid:
  description: The BIG-IQ pool UUID
  returned: changed
  type: string
  sample: bacf5f10-1e64-445e-922d-12b6477ff040
regkey:
  description: The license regkey assigned.
  returned: changed
  type: string
  sample: XTHIS-ISXNO-TXAX-REAL-XKEYXX
license_uuid:
  description: The BIG-IQ license UUID
  returned: changed
  type: string
  sample: 99d5305e-008b-4613-b732-584e240fb1bd
'''

import logging

import requests

from time import sleep

from ansible.module_utils.basic import AnsibleModule


class F5ModuleError(Exception):
    pass


class PoolNotFoundException(Exception):
    ''' No Pool Found By Supplied Name '''
    pass


class MemberNotFoundException(Exception):
    ''' No Member Found By Management Address '''
    pass


class NoOfferingAvailable(Exception):
    ''' No RegKey Available in Pool '''
    pass


class LicenseActivationError(Exception):
    ''' Error During License Activation '''
    pass


class LicenseRevokeError(Exception):
    ''' Error During License Revocation '''


class F5BigIQHost(object):
    ''' BIG-IQ Host Session'''
    bigiq_host = None
    bigiq_username = None
    bigiq_password = None
    bigiq_timeout = 10

    def __init__(self, bigiq_host=None, bigiq_username=None,
                 bigiq_password=None, bigiq_timeout=10):
        self.bigiq_host = bigiq_host
        self.bigiq_username = bigiq_username
        self.bigiq_password = bigiq_password
        self.bigiq_timeout = bigiq_timeout

    def get_config(self):
        ''' Returns BIG-IQ host configuration '''
        config = {
            'bigiq_host': self.bigiq_host,
            'bigiq_username': self.bigiq_username,
            'bigiq_password': self.bigiq_password,
            'bigiq_timeout': self.bigiq_timeout
        }
        return config

    def get_bigiq_session(self):
        ''' Creates a Requests Session to the BIG-IQ host configured '''
        if requests.__version__ < '2.9.1':
            requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member
        bigiq = requests.Session()
        bigiq.verify = False
        bigiq.headers.update({'Content-Type': 'application/json'})
        bigiq.timeout = self.bigiq_timeout
        token_auth_body = {'username': self.bigiq_username,
                           'password': self.bigiq_password,
                           'loginProviderName': 'local'}
        login_url = "https://%s/mgmt/shared/authn/login" % (self.bigiq_host)
        response = bigiq.post(login_url,
                              json=token_auth_body,
                              verify=False,
                              auth=requests.auth.HTTPBasicAuth(
                                  self.bigiq_username, self.bigiq_password))
        response_json = response.json()
        bigiq.headers.update(
            {'X-F5-Auth-Token': response_json['token']['token']})
        bigiq.base_url = 'https://%s/mgmt/cm/device/licensing/pool' % \
            self.bigiq_host
        return bigiq


class F5BigIQLicensePoolMember(object):  # pylint: disable=too-many-instance-attributes
    ''' BIG-IQ Pool Member Licensing '''
    bigiq_license_pool_name = None
    bigip_management_ip = None
    bigip_username = None
    bigip_password = None
    bigip_management_port = 443
    bigip_timeout = 10
    license_attempts = 30
    error_delay = 10

    def __init__(self, bigiq_license_pool_name=None,  # pylint: disable=too-many-arguments
                 bigip_management_ip=None, bigip_username=None,
                 bigip_password=None, bigip_management_port=443,
                 bigip_timeout=10, license_attempts=30, error_delay=10):
        self.bigiq_license_pool_name = bigiq_license_pool_name
        self.bigip_management_ip = bigip_management_ip
        self.bigip_management_port = bigip_management_port
        self.bigip_username = bigip_username
        self.bigip_password = bigip_password
        self.bigip_timeout = bigip_timeout
        self.license_attempts = license_attempts
        self.error_delay = error_delay

    def get_config(self):
        ''' Returns BIG-IQ host configuration '''
        config = {
            'bigiq_license_pool_name': self.bigiq_license_pool_name,
            'bigip_management_ip': self.bigip_management_ip,
            'bigip_management_port': self.bigip_management_port,
            'bigip_username': self.bigip_username,
            'bigip_password': self.bigip_password,
            'bigip_timeout': self.bigip_timeout,
            'attempts': self.license_attempts,
            'error_delay': self.error_delay
        }
        return config

    def get_bigip_session(self):
        ''' Creates a Requests Session to the BIG-IP member configured '''
        if requests.__version__ < '2.9.1':
            requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member
        bigip = requests.Session()
        bigip.verify = False
        bigip.headers.update({'Content-Type': 'application/json'})
        bigip.timeout = self.bigip_timeout
        token_auth_body = {'username': self.bigip_username,
                           'password': self.bigip_password,
                           'loginProviderName': 'local'}
        login_url = "https://%s:%d/mgmt/shared/authn/login" % (
            self.bigip_management_ip, self.bigip_management_port)
        response = bigip.post(login_url,
                              json=token_auth_body,
                              verify=False,
                              auth=requests.auth.HTTPBasicAuth(
                                  self.bigip_username, self.bigip_password))
        response_json = response.json()
        bigip.headers.update(
            {'X-F5-Auth-Token': response_json['token']['token']})
        bigip.base_url = 'https://%s:%d/mgmt/tm/' % \
            (self.bigip_management_ip, self.bigip_management_port)
        return bigip


class RegkeyPoolLicensor(object):
    '''Workflows to support BIG-IQ regkey pools'''

    member_uuid = None
    regkey = None
    pool_uuid = None

    bigiq = None
    member = None

    def __init__(self, bigiq_host=None,
                 bigiq_pool_member=None):
        if not isinstance(bigiq_host, F5BigIQHost):
            raise AssertionError(str(
                'bigiq_host must be an instance of ',
                'f5_heat.licensors.bigiq.bigiq_host.F5BigIQHost'))
        self.bigiq = bigiq_host
        if not isinstance(bigiq_pool_member, F5BigIQLicensePoolMember):
            raise AssertionError(str(
                'bigiq_host must be an instance of ',
                'f5_heat.licensors.',
                'bigiq.bigiq_pool_member.F5BigIQLicensePoolMember'))
        self.member = bigiq_pool_member

    def activate_license(self):
        '''License BIG-IP from BIG-IQ Pool.
        :returns: member_uuid
        '''
        # premptively clean up any orphaned
        # member with the same bigip_management_ip
        biq = self.bigiq.get_bigiq_session()
        if not self.pool_uuid:
            self.pool_uuid = self._get_pool_id(
                biq, self.member.bigiq_license_pool_name)
        try:
            if not self.regkey:
                (self.regkey, self.member_uuid) = \
                    self._get_regkey_by_management_ip(
                        biq, self.pool_uuid, self.member.bigip_management_ip)
            self._revoke_member(
                biq, self.pool_uuid, self.regkey,
                self.member_uuid, self.member)
        except MemberNotFoundException:
            pass
        except NoOfferingAvailable:
            pass

        self.member_uuid = None
        self.regkey = self._get_first_available_regkey(biq, self.pool_uuid)
        (self.regkey, self.member_uuid) = self._activate_member(
            biq, self.pool_uuid, self.regkey, self.member)
        return self.member_uuid

    def revoke_license(self):
        '''Release license to BIG-IQ Pool.
        :returns: None
        '''
        try:
            biq = self.bigiq.get_bigiq_session()
            if not self.pool_uuid:
                self.pool_uuid = self._get_pool_id(
                    biq, self.member.bigiq_license_pool_name)
            if not self.regkey:
                (self.regkey, self.member_uuid) = \
                    self._get_regkey_by_management_ip(
                        biq, self.pool_uuid, self.member.bigip_management_ip)
            if self.member_uuid:
                self._revoke_member(biq, self.pool_uuid, self.regkey,
                                    self.member_uuid, self.member)
        except NoOfferingAvailable as noe:
            msg = 'request to release license %s for %s failed. %s' % (
                self.member_uuid,
                self.member.bigip_management_ip,
                noe.message)
            logging.error(msg)
            self.regkey = None
            self.member_uuid = None
            raise noe
        except MemberNotFoundException as mnfe:
            msg = 'request to release license %s for % failed because no \
                   allocated license was found.' % (
                self.member_uuid, self.member.bigip_management_ip)
            logging.error(msg)
            self.regkey = None
            self.member_uuid = None
            raise mnfe

        self.regkey = None
        self.member_uuid = None
        return None

    @classmethod
    def _revoke_member(cls, bigiq_session=None, pool_id=None, regkey=None,  # pylint: disable=too-many-arguments
                       member_id=None, member=None):
        ''' Revoke a license based
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: member_id: BIG-IQ pool Member ID
        :param: member: BIG-IP Pool Member object containing credentials
        :returns: None
        :raises: LicenseRevokeError
        :raises: NoRegKeyAvailable
        :raises: MemberNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
        # attempt to discover member_id if not set
        if not member_id:
            if not regkey:
                (regkey, member_id) = \
                    cls._get_regkey_by_management_ip(
                    bigiq_session, pool_id,
                    member.bigip_management_ip)
            else:
                member_id = \
                    cls._get_member_id(
                        bigiq_session, pool_id,
                        regkey, member.bigip_management_ip)
        # delete the member - only allow 404 errors raise others
        try:
            cls._delete_member(
                bigiq_session, pool_id, regkey, member_id,
                member.bigip_username, member.bigip_password
            )
        except requests.exceptions.HTTPError as httpex:
            if httpex.response.status_code != 404:
                raise httpex
        # query member state until it is no longer present
        attempts = member.license_attempts
        while True:
            if attempts == 0:
                break
            attempts -= 1
            try:
                cls._get_member_status(
                    bigiq_session, pool_id, regkey, member_id
                )
            except requests.exceptions.HTTPError as httpex:
                if httpex.response.status_code == 404:
                    return
                logging.error(str(
                    'error revoking license to %s:%s'
                    % (member.bigip_management_ip, httpex.message)))
                logging.error(str(
                    '%d remaining revocation attempts for %s'
                    % (attempts, member.bigip_management_ip)))
                sleep(member.error_delay)
        raise LicenseRevokeError(
            "error revoking existing license %s" % member.bigip_management_ip
        )

    @classmethod
    def _activate_member(cls, bigiq_session=None, pool_id=None,
                         regkey=None, member=None):
        ''' Activate a BIG-IP as a BIG-IQ license pool member
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool (optional)
        :param: member: BIG-IP Pool Member object containing credentials
        :returns: (Regkey string, Member ID string)
        :raises: requests.exceptions.HTTPError
        '''
        member_uuid = None
        try:
            member_uuid = cls._get_member_id(
                bigiq_session, pool_id, regkey, member.bigip_management_ip)
            return member_uuid
        except MemberNotFoundException:
            member_last_state = 'UNKNOWN'
            attempts = member.license_attempts
            while True:
                if attempts == 0:
                    raise LicenseActivationError(
                        "device %s activation state is %s" %
                        (member.bigip_management_ip, member_last_state)
                    )
                attempts -= 1
                try:
                    if not member_uuid:
                        if not regkey:
                            regkey = cls._get_first_available_regkey(
                                bigiq_session, pool_id)
                        member_uuid = \
                            cls._create_member(
                                bigiq_session, pool_id, regkey,
                                member.bigip_management_ip,
                                member.bigip_username, member.bigip_password)
                    member_last_state = \
                        cls._get_member_status(
                            bigiq_session, pool_id, regkey, member_uuid)
                    if member_last_state == 'LICENSED':
                        return (regkey, member_uuid)
                    else:
                        sleep(member.error_delay)
                except requests.exceptions.HTTPError as ex:
                    logging.error(str(
                        'error allocating license to %s: %s %s'
                        % (member.bigip_management_ip,
                           ex.request.method, ex.message)))
                    logging.error(str(
                        '%d remaining licensing attempts for %s'
                        % (attempts, member.bigip_management_ip)))
                    # force a new regkey from pool
                    member_uuid = None
                    regkey = None
                    sleep(member.error_delay)

    @staticmethod
    def _get_pool_id(bigiq_session, pool_name):
        ''' Get a BIG-IQ license pool by its pool name. Returns first
            match of the specific pool type.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_name: BIG-IQ pool name
        :returns: Pool ID string
        :raises: PoolNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = '%s/regkey/licenses?$select=id,kind,name' % \
            bigiq_session.base_url
        # Now need to check both name and uuid for match. Can't filter.
        # query_filter = '&$filter=name%20eq%20%27' + pool_name + '%27'
        # pools_url = "%s%s" % (pools_url, query_filter)
        response = bigiq_session.get(pools_url)
        response.raise_for_status()
        response_json = response.json()
        pools = response_json['items']
        for pool in pools:
            if pool['name'] == pool_name or pool['id'] == pool_name:
                if str(pool['kind']).find('pool:regkey') > 1:
                    return pool['id']
        raise PoolNotFoundException('No RegKey pool %s found' % pool_name)

    @staticmethod
    def _get_member_id(bigiq_session, pool_id, regkey, mgmt_ip):
        ''' Get a BIG-IQ license pool member ID by the pool ID and BIG-IP
            management IP address.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: mgmt_ip: BIG-IP management IP address
        :returns: Member ID string
        :raises: MemberNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = '%s/regkey/licenses' % bigiq_session.base_url
        offerings_url = '%s/%s/offerings' % (pools_url, pool_id)
        members_url = '%s/%s/members' % (offerings_url, regkey)
        response = bigiq_session.get(members_url)
        if response.status_code != 404:
            response.raise_for_status()
        response_json = response.json()
        members = response_json['items']
        for member in members:
            if member['deviceAddress'] == mgmt_ip:
                return member['id']
        raise MemberNotFoundException('No member %s found in pool %s' % (
            mgmt_ip, pool_id))

    @staticmethod
    def _get_member_status(bigiq_session, pool_id, regkey, member_id):
        ''' Get a BIG-IQ license pool member status.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: member_id: BIG-IP pool member ID
        :returns: Member state string
        :raises: requests.exceptions.HTTPError
        '''
        member_url = \
            '%s/regkey/licenses/%s/offerings/%s/members/%s?$select=status' % (
                bigiq_session.base_url, pool_id, regkey, member_id)
        response = bigiq_session.get(member_url)
        response.raise_for_status()
        response_json = response.json()
        return response_json['status']

    @staticmethod
    def _create_member(bigiq_session, pool_id, regkey, bigip_management_ip,  # pylint: disable=too-many-arguments
                       bigip_username, bigip_password):
        ''' Create a BIG-IP License Pool Member.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: bigip_management_ip: BIG-IP management IP
        :param: bigip_username: BIG-IP username
        :param: bigip_password: BIG-IP password
        :returns: Member ID string
        :raises: requests.exceptions.HTTPError
        '''
        members_url = '%s/regkey/licenses/%s/offerings/%s/members' % (
            bigiq_session.base_url, pool_id, regkey)
        member = {
            'deviceAddress': bigip_management_ip,
            'username': bigip_username,
            'password': bigip_password
        }
        response = bigiq_session.post(members_url,
                                      json=member)
        response.raise_for_status()
        response_json = response.json()
        return response_json['id']

    @staticmethod
    def _delete_member(bigiq_session, pool_id, regkey, member_id,  # pylint: disable=too-many-arguments
                       bigip_username, bigip_password):
        ''' Delete a BIG-IP License Pool Member.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: member_id: BIG-IQ member ID
        :param: bigip_username: BIG-IP username
        :param: bigip_password: BIG-IP password
        :returns: None
        :raises: requests.exceptions.HTTPError
        '''
        member_url = \
            '%s/regkey/licenses/%s/offerings/%s/members/%s' % (
                bigiq_session.base_url, pool_id, regkey, member_id)
        member = {
            'id': member_id,
            'username': bigip_username,
            'password': bigip_password
        }
        response = bigiq_session.delete(member_url,
                                        json=member)
        response.raise_for_status()

    @staticmethod
    def _get_regkey_by_management_ip(bigiq_session, pool_id, mgmt_ip):
        ''' Get regkey, member_id tuple by management IP address
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: mgmt_ip: BIG-IP management IP address
        :returns: (Regkey string, Member ID string)
        :raises: NoRegKeyAvailable
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = '%s/regkey/licenses' % bigiq_session.base_url
        offerings_url = '%s/%s/offerings' % (pools_url, pool_id)
        response = bigiq_session.get(offerings_url)
        response.raise_for_status()
        response_json = response.json()
        offerings = response_json['items']
        for offering in offerings:
            members_url = '%s/%s/members' % (
                offerings_url, offering['regKey'])
            response = bigiq_session.get(members_url)
            response.raise_for_status()
            response_json = response.json()
            members = response_json['items']
            for member in members:
                if member['deviceAddress'] == mgmt_ip:
                    return (offering['regKey'], member['id'])
        raise NoOfferingAvailable('No regkey has %s as a member' % mgmt_ip)

    @staticmethod
    def _get_first_available_regkey(bigiq_session, pool_id):
        ''' Get first regkey from pool without an assigned BIG-IP device
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :returns: Regkey string
        :raises: NoRegKeyAvailable
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = '%s/regkey/licenses' % bigiq_session.base_url
        offerings_url = '%s/%s/offerings' % (pools_url, pool_id)
        response = bigiq_session.get(offerings_url)
        response.raise_for_status()
        response_json = response.json()
        offerings = response_json['items']
        for offering in offerings:
            members_url = '%s/%s/members' % (
                offerings_url, offering['regKey'])
            response = bigiq_session.get(members_url)
            response.raise_for_status()
            response_json = response.json()
            if len(response_json['items']) == 0:
                return offering['regKey']
        raise NoOfferingAvailable('No RegKey available in pool %s' % pool_id)


class ModuleManager(object):

    def __init__(self, module=None):
        self.module = module

    def exec_module(self):
        result = dict(
            changed=False,
            pool_uuid='',
            regkey='',
            license_uuid='',
            warnings=dict()
        )
        state = self.module.params['state']

        if self.module.check_mode:
            try:
                biq = F5BigIQHost(bigiq_host=self.module.params['bigiq_hostname'],
                                  bigiq_username=self.module.params['bigiq_username'],
                                  bigiq_password=self.module.params['bigiq_password'])
                result['pool_uuid'] = RegkeyPoolLicensor._get_pool_id(  # pylint: disable=protected-access
                    biq.get_bigiq_session(),
                    self.module.params['bigiq_license_pool_name']
                )
                (result['regkey'], result['license_uuid']) = \
                    RegkeyPoolLicensor._get_regkey_by_management_ip(  # pylint: disable=protected-access
                        biq.get_bigiq_session(),
                        result['pool_uuid'],
                        self.module.params['bigip_management_ip'])
                if state == "absent":
                    result['warnings']['regkey_assigned'] = str(
                        "Regkey %s assigned to %s" % (
                            result['regkey'],
                            self.module.params['bigip_management_ip'])
                    )
                    result['warnings']['license_assigned'] = str(
                        "License %s assigned to %s" % (
                            result['license_uuid'],
                            self.module.params['bigip_management_ip']
                        )
                    )
            except PoolNotFoundException:
                result['warnings']['no_pool_found'] = str(
                    'There is no pool by the name %s' % self.module.params[
                        'bigiq_license_pool_name'])
                result['pool_uuid'] = str(
                    'NO POOL NAMED %s' % self.module.params[
                        'bigiq_license_pool_name'])
            except NoOfferingAvailable:
                if state == "present":
                    result['warnings']['no_regkey_available'] = \
                        'There is no regkey available'
                    result['regkey'] = str(
                        'NO REGEY AVAILABLE')
            except MemberNotFoundException:
                if state == "present":
                    result['warnings']['member_not_found'] = str(
                        'BIG-IP %s does not have an activated license'
                        % self.module.params['bigip_management_ip'])
                    result['license_uuid'] = 'UNASSIGNED'
            return result

        try:
            biq = F5BigIQHost(bigiq_host=self.module.params['bigiq_hostname'],
                              bigiq_username=self.module.params['bigiq_username'],
                              bigiq_password=self.module.params['bigiq_password'])
            member = F5BigIQLicensePoolMember(
                bigiq_license_pool_name=self.module.params[
                    'bigiq_license_pool_name'],
                bigip_management_ip=self.module.params[
                    'bigip_management_ip'],
                bigip_management_port=self.module.params[
                    'bigip_management_port'],
                bigip_username=self.module.params[
                    'bigip_username'],
                bigip_password=self.module.params[
                    'bigip_password'])
            licensor = RegkeyPoolLicensor(biq, member)
            if state == "present":
                licensor.activate_license()
                result['pool_uuid'] = licensor.pool_uuid
                result['regkey'] = licensor.regkey
                result['license_uuid'] = licensor.member_uuid
                result['changed'] = True
            elif state == "absent":
                licensor.revoke_license()
                result['pool_uuid'] = licensor.pool_uuid
                result['regkey'] = None
                result['license_uuid'] = None
                result['changed'] = True
        except Exception as ex:
            raise F5ModuleError(str(ex))
        return result


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(type='str', required=True),
            bigiq_hostname=dict(type='str', required=True),
            bigiq_username=dict(type='str', required=False),
            bigiq_password=dict(type='str', required=False, no_log=True),
            bigiq_license_pool_name=dict(type='str', required=True),
            bigip_management_ip=dict(type='str', required=True),
            bigip_management_port=dict(type='int', required=False),
            bigip_username=dict(type='str', required=False),
            bigip_password=dict(type='str', required=False, no_log=True),
            state=dict(
                default='present',
                choices=['present', 'absent']
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
