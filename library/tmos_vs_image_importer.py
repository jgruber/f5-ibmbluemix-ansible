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
module: tmos_vs_image_importer
short_description: Create or Delete TMOS Image from Object in IBM Swift
version_added: "1.0"
author: "John Gruber (@jgruber)"
description:
   - Create or Delete TMOS Image from Object in IBM Swift
options:
   ibm_username:
     description:
        - The username from the IBM Cloud user account
   ibm_cloud_api_key:
     description:
        - The API key from the IBM Cloud user account
     required: true
   swift_username:
     description:
        - The username to access the IBM Swift object service
     required: true
   swift_api_key:
     description:
        - The API key to access the IBM Swift object service
     required: true
   swift_cluster:
     description:
       - IBM Swift Cluster to access
     required: true
     default: dal05.objectstorage.softlayer.net
   container:
     description:
        - The name of the container in which to create the object
     required: true
   name:
     description:
        - Name to be give to the object. If omitted, operations will be on
          the entire container
     required: true
   disk_size:
     description:
        - The size in GB for this image should be 100 or 25
     choices: [100,25]
     default: 100
   state:
     description:
       - Should the resource be present or absent.
     choices: [present, absent]
     default: present
'''

EXAMPLES = '''
- name: Create a virtual host image named bigip.vhd
  tmos_vs_image_importer:
    ibm_username: storageadmin@f5.com
    ibm_api_key: f6f1a779-3b92475c9b1a4bef8d658b312cc0658e9ec3
    swift_username: IBMOS867530-9:storageadmin@f5.com
    swift_api_key: f6f1a779-3b92475c9b1a4bef8d658b312cc0658e9ec3
    swift_cluster: dal05.objectstorage.softlayer.net
    cluster: dal05.objectstorage.softlayer.net
    container: f5images
    name: bigip.vhd
    disk_size: 100
    state: present

- name: Delete a virtual host image named bigip.vhd
  tmos_vs_image_importer:
    ibm_username: storageadmin@f5.com
    ibm_api_key: f6f1a779-3b92475c9b1a4bef8d658b312cc0658e9ec3
    swift_username: IBMOS867530-9:storageadmin@f5.com
    swift_api_key: f6f1a779-3b92475c9b1a4bef8d658b312cc0658e9ec3
    swift_cluster: dal05.objectstorage.softlayer.net
    cluster: dal05.objectstorage.softlayer.net
    container: f5images
    name: bigip.vhd
    disk_size: 100
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
                   swift_username=None, swift_api_key=None,
                   swift_cluster='dal05.objectstorage.softlayer.net',
                   container='f5images', name='bigip.vhd',
                   state='present', **kwargs):
    image_changed = False
    if state == 'present':
        if name:
            image_changed = validate_image(
               ibm_username, ibm_api_key, swift_username,
               swift_api_key, swift_cluster, container, name
            )
    else:
        if name:
            image_changed = delete_image(
               ibm_username, ibm_api_key, name
            )
    return image_changed


def authenticate_swift(username, password, endpoint):
    headers = {
        'X-Storage-User': username,
        'X-Storage-Pass': password
    }
    url = "https://%s/auth/v1.0" % endpoint
    response = requests.get(url, headers=headers)
    storage_url = response.headers['X-Storage-Url']
    auth_token = response.headers['X-Auth-Token']
    return storage_url, auth_token


def list_swift_image(auth_token, storage_url,
                     swift_cluster, container, name):
    headers = {'X-Auth-Token': auth_token}
    url = "%s/%s?format=json" % (storage_url, container)
    response = requests.get(url, headers=headers)
    if response.status_code != 404:
        response.raise_for_status()
        images = response.json()
        for image in images:
            if image['name'] == name:
                return image
    else:
        return "No image found"

def validate_image(ibm_username, ibm_api_key, swift_username,
                   swift_api_key, swift_cluster, container,
                   name):
    client = SoftLayer.Client(
        username=ibm_username, api_key=ibm_api_key)
    vs_mgr = SoftLayer.managers.VSManager(client)
    image_mgr =  SoftLayer.managers.ImageManager(client)
    image_tmpl = client[
        'SoftLayer_Virtual_Guest_Block_Device_Template_Group']
    locs = client['SoftLayer_Location_Datacenter']
    images = image_mgr.list_private_images(name=name)
    image_changed = False
    image = None
    if len(images) == 1:
        image = images[0]
    else:
        (storage_url, auth_token) = \
        authenticate_swift(swift_username, swift_api_key, swift_cluster)

        obj_uri = "swift://%s@%s/%s/%s" % (
            swift_username[0: swift_username.find(':')],
            swift_cluster[0: swift_cluster.find('.')],
            container,
            name
        )
        image = image_tmpl.createFromExternalSource({
            'name': name,
            'note': "F5 TMOS Image %s" % name,
            'operatingSystemReferenceCode': 'CENTOS_7_64',
            'cloudInit': True,
            'uri': obj_uri
        })
        time.sleep(10)
        image_changed = True
    available_dcs = \
     locs.getDatacentersWithVirtualImageStoreServiceResourceRecord()
    image_dcs = image_tmpl.getObject(
        id=image['id'],mask='datacenters')['datacenters']
    for dc in image_dcs:
        if dc in available_dcs:
            available_dcs.remove(dc)
    dcids = []
    for dc in available_dcs:
        dcids.append({'id': dc['id']})
    if len(dcids) > 0:
        print("adding image %s to %s" % (image['name'], available_dcs))
        image_tmpl.addLocations(dcids, id=image['id'])
        image_changed = True
    return image_changed

def delete_image(ibm_username, ibm_api_key, name):
    client = SoftLayer.Client(
        username=ibm_username, api_key=ibm_api_key)
    image_mgr = image_mgr = SoftLayer.managers.ImageManager(client)
    images = image_mgr.list_private_images(name=name)
    if len(images) == 0:
        return False
    for image in images:
        image_mgr.delete_image(image['id'])
    return True

def main():
    module = AnsibleModule(
        argument_spec=dict(
            ibm_username=dict(required=True),
            ibm_api_key=dict(required=True),
            swift_username=dict(required=True),
            swift_api_key=dict(required=True),
            swift_cluster=dict(
                default='dal05.objectstorage.softlayer.net'),
            container=dict(required=True),
            name=dict(required=False, default=None),
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
