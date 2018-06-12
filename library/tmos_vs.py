#!/usr/bin/python

# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: tmos_vs
short_description: Create or Delete TMOS virtual hosts in IBM Cloud
version_added: "1.0"
author: "John Gruber (@jgruber)"
description:
   - Create or Delete TMOS virtual hosts in IBM Cloud
options:
   ibm_username:
     description:
        - The username from the IBM Cloud user account
   ibm_api_key:
     description:
        - The API key from the IBM Cloud user account
     required: true
   hourly:
     description:
       - The billing utilization period should be hourly vs monthly
     required: true
     default: true
   datacenter:
     description:
        - The IBM Cloud datacenter for the TMOS instance
     required: true
     default: dal09
   image_id:
     description:
        - The F5 Image ID to use for the TMOS disk image
   flavor_id:
     description:
        - The IBM Cloud flovor to use for the TMOS instance
     required: true
     default: B1_2X4X100
     choices:
       - B1_2X4X25
       - B1_2X8X25
       - B1_2X4X100
       - B1_2X8X100
       - B1_4X8X100
       - B1_4X16X100
       - B1_8X16X100
       - B1_8X32X100
       - B1_16X32X100
   hostname:
     description:
       - The hostname or this TMOS instance
     required: true
     default: f5bigip
   domain:
     description:
       - The domain or this TMOS instance
     required: true
     default: example.com
   local_disk:
     description:
       - Use a local disk verse san disk
     required: false
     default: false
   private:
     description:
       - Should this instance have only private networking
     required: false
     default: false
   private_vlan:
     description:
       - The VLAN ID in the selected datacenter
     required: false
     default: none
   private_subnet:
     description:
       - The Subnet ID on the private_vlan in the selected datacenter
     required: false
     default: none
   private_security_groups:
     description:
       - List of security group IDs for the private network
     required: false
     default: [475867, 475869]
   public_vlan:
     description:
       - The VLAN ID in the selected datacenter
     required: false
     default: none
   public_subnet:
     description:
       - The Subnet ID on the public_vlan in the selected datacenter
     required: false
     default: none
   public_security_groups:
     description:
       - List of security group IDs for the public network
     required: false
     default: [475867, 475869]
   nic_speed:
     description:
       - The mps speed for the private network can be 10,100,1000
     required: true
     choices: [10, 100, 1000]
     default: 1000
   ssh_keys:
     description:
       - List of SSH key IDs to inject for the TMOS root account
     required: false
     default: []
   userdata:
     description:
       - The userdata to include via cloud-init
     required: true
     default: none
   state:
     description:
       - Should the resource be present or absent.
     choices: [present, absent]
     default: present
'''

EXAMPLES = '''
- name: Create a virtual host testve1.gregkihn.biz
  tmos_vs:
    ibm_username: computeadmin@f5.com
    ibm_api_key: f6f1a779-3b92475c9b1a4bef8d658b312cc0658e9ec3
    billing: hourly
    datacenter: dal09
    image_id: 361312
    flavor_id: B1_2X4X100
    hostname: testve1
    domain: gregkihn.biz
    nic_speed: 1000
    ssh_keys:
      - 1103555
      - 1109871
    private_vlan: 1195877
    private_subnet: 1180877
    private_security_groups:
      - 175167
      - 175169
    public_security_groups:
      - 475867
      - 475869
    state: present

- name: Delete a virtual host testve1.gregkihn.biz
  tmos_vs:
    ibm_username: computeadmin@f5.com
    ibm_api_key: f6f1a779-3b92475c9b1a4bef8d658b312cc0658e9ec3
    hostname: testve1
    domain: gregkihn.biz
    state: absent
'''

import json
import requests
import urllib
import time

try:
    import SoftLayer
    HAS_SL = True
except ImportError:
    HAS_SL = False

from ansible.module_utils.basic import AnsibleModule


def process_object(ibm_username=None, ibm_api_key=None,
                   hourly=True, datacenter='dal09',
                   image_id=None, flavor_id='B1_2X4X100',
                   hostname='f5bigip', domain='example.com',
                   local_disk=False, private=False,
                   private_vlan=None, private_subnet=None,
                   private_security_groups=[475867, 475869],
                   public_vlan=None, public_subnet=None,
                   public_security_groups=[475867, 475869],
                   nic_speed=1000, userdata=None, ssh_keys=[],
                   state='present', **kwargs):
    vs_changed = False
    if state == 'present':
        if hostname and domain:
            vs_changed = validate_vs(
               ibm_username=ibm_username,
               ibm_api_key=ibm_api_key,
               hourly=hourly, datacenter=datacenter,
               image_id=image_id, flavor_id=flavor_id,
               hostname=hostname, domain=domain,
               local_disk=local_disk, private=private,
               private_vlan=private_vlan, private_subnet=private_subnet,
               private_security_groups=private_security_groups,
               public_vlan=public_vlan, public_subnet=public_subnet,
               public_security_groups=public_security_groups,
               nic_speed=nic_speed, userdata=userdata,
               ssh_keys=ssh_keys, **kwargs
            )
    else:
        if hostname and domain:
            vs_changed = delete_vs(
               ibm_username, ibm_api_key,
               hostname, domain
            )
    return vs_changed

def validate_vs(ibm_username=None, ibm_api_key=None,
                hourly=True, datacenter='dal09',
                image_id=None, flavor_id='B1_2X4X100',
                hostname='f5bigip', domain='example.com',
                local_disk=False, private=False,
                private_vlan=None, private_subnet=None,
                public_vlan=None, public_subnet=None,
                nic_speed=1000, userdata=None, ssh_keys=[],
                private_security_groups=[],
                public_security_groups=[],
                **kwargs):
    client = SoftLayer.Client(
        username=ibm_username, api_key=ibm_api_key)
    vs_mgr =  SoftLayer.managers.VSManager(client)
    image_mgr = SoftLayer.managers.ImageManager(client)
    image = image_mgr.get_image(image_id=image_id)
    vses = vs_mgr.list_instances(hostname=hostname, domain=domain)
    if len(vses) == 1:
        return False
    else:
        if not userdata:
            raise Exception('F5 TMOS userdata required')
        vs_def = {
            'blockDeviceTemplateGroup': {
                'globalIdentifier': image['globalIdentifier']
            },
            'datacenter': {
                'name': datacenter
            },
            'domain': domain,
            'hostname': hostname,
            'hourlyBillingFlag': hourly,
            'localDiskFlag': local_disk,
            'maxMemory': None,
            'networkComponents': [
                {'maxSpeed': nic_speed}
            ],
            'privateNetworkOnlyFlag': private,
            'startCpus': None,
            'supplementalCreateObjectOptions': {
                'bootMode': None,
                'flavorKeyName': flavor_id
            },
            'userData': [ {'value': userdata } ]
        }
        if ssh_keys:
            vs_def['sshKeys'] = []
            for key in ssh_keys:
                vs_def['sshKeys'].append({'id': key})
        if private_vlan:
            vs_def['primaryBackendNetworkComponent'] = { 
                'networkVlan': {'id': private_vlan} }
            if private_subnet:
                vs_def['primaryBackendNetworkComponent'][
                   'networkVlan']['primarySubnetId'] = private_subnet
        if private_security_groups:
            if not 'primaryBackendNetworkComponent' in vs_def:
                vs_def['primaryBackendNetworkComponent'] = {}
            vs_def['primaryBackendNetworkComponent'][
                   'securityGroupBindings'] = []
            for sg in private_security_groups:
                vs_def['primaryBackendNetworkComponent'][
                   'securityGroupBindings'].append(
                      {'securityGroup': {'id': sg}})
        if public_vlan:
            vs_def['primaryNetworkComponent'] = {
                'networkVlan': {'id': public_vlan} }
            if public_subnet:
                vs_def['primaryNetworkComponent'][
                   'networkVlan']['primarySubnetId'] = public_subnet
        if public_security_groups:
            if not 'primaryNetworkComponent' in vs_def:
                vs_def['primaryNetworkComponent'] = {}
            vs_def['primaryNetworkComponent'][
                   'securityGroupBindings'] = []
            for sg in public_security_groups:
                vs_def['primaryNetworkComponent'][
                   'securityGroupBindings'].append(
                      {'securityGroup': {'id': sg}})
        if private:
            del(vs_def['primaryNetworkComponent'])
        print(vs_def)
        vs_mgr.guest.createObject(vs_def)
        return True

def delete_vs(ibm_username, ibm_api_key, hostname, domain):
    client = SoftLayer.Client(
        username=ibm_username, api_key=ibm_api_key)

    vs_mgr = SoftLayer.managers.VSManager(client)
    vses = vs_mgr.list_instances(hostname=hostname, domain=domain)
    if len(images) == 0:
        return False
    for vs in vses:
        vs.cancel_instance(vs['id'])
    return True

def main():
    module = AnsibleModule(
        argument_spec=dict(
            ibm_username=dict(required=True),
            ibm_api_key=dict(required=True),
            hourly=dict(default=True),
            datacenter=dict(default='dal09'),
            image_id=dict(required=True),
            flavor_id=dict(required=True,
                           default='B1_2X4X100',
                           choices = [
                               'B1_2X4X25',
                               'B1_2X8X25',
                               'B1_2X4X100',
                               'B1_2X8X100',
                               'B1_4X8X100',
                               'B1_4X16X100',
                               'B1_8X16X100',
                               'B1_8X32X100',
                               'B1_16X32X100'
                          ]),
            hostname=dict(required=True, default='f5bigip'),
            domain=dict(required=True, default='example.com'),
            local_disk=dict(required=False, default=False),
            private=dict(required=False, default=False),
            private_vlan=dict(required=False, default=None),
            private_subnet=dict(required=False, default=None),
            private_security_groups=dict(
                required=False, default=[475867, 475869]),
            public_vlan=dict(required=False, default=None),
            public_subnet=dict(required=False, default=None),
            public_security_groups=dict(
                required=False, default=[475867, 475869]),
            nic_speed=dict(required=True, default=1000),
            ssh_keys=dict(required=False, default=[]),
            userdata=dict(required=True, default=None),
            state=dict(
                default='present', choices=['absent', 'present'])
        )
    )

    if not HAS_SL:
        module.fail_json(
            msg='softlayer python library required for this module')
    try:
        changed = process_object(**module.params)
        module.exit_json(changed=changed)
    except shade.OpenStackCloudException as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
