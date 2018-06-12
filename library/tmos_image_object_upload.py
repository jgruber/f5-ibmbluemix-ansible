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
module: tmos_image_object_upload
short_description: Create or Delete TMOS Image Object in IBM Swift
version_added: "1.0"
author: "John Gruber (@jgruber)"
description:
   - Create or Delete TMOS Image Object in IBM Swift
options:
   swift_username:
     description:
        - The username to access the IBM Swift object service
     required: true
   swift_api_key:
     description:
        - The API Key from the IBM Swift object service
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
     default: f5images
   name:
     description:
        - Name to be give to the object
     required: true
     default: bigip.vhd
   filename:
     description:
        - Path to local file to be uploaded
     required: true
   container_access:
     description:
        - desired container access level
     required: false
     choices: ['private', 'public']
     default: private
   state:
     description:
       - Should the resource be present or absent
     choices: [present, absent]
     default: present
'''

EXAMPLES = '''
- name: Create a object named bigip.vhd in the f5images container
  tmos_image_object_upload:
    swift_username: IBMOS867530-9:storageadmin@f5.com
    swift_api_key: f6f1a779-3b92475c9b1a4bef8d658b312cc0658e9ec3
    swift_cluster: dal05.objectstorage.softlayer.net
    container: f5images
    name: bigip.vhd
    filename: /tmp/BIGIP-13.1.0.3.0.0.5.vhd
    state: present

- name: Delete a object name bigip.vhd in the f5images container
  tmos_image_object_upload:
    swift_username: IBMOS867530-9:storageadmin@f5.com
    swift_api_key: f6f1a779-3b92475c9b1a4bef8d658b312cc0658e9ec3
    swift_cluster: dal05.objectstorage.softlayer.net
    container: f5images
    name: bigip.vhd
    state: absent
'''

import json
import math
import os
import requests
import time

try:
    import SoftLayer
    HAS_SL = True
except ImportError:
    HAS_SL = False

from ansible.module_utils.basic import AnsibleModule


def process_object(swift_username=None, swift_api_key=None,
                   swift_cluster='dal05.objectstorage.softlayer.net',
                   container='f5images', name='bigip.vhd',
                   filename=None, container_access='private',
                   state='present', **kwargs):
    if state == 'present':
        return validate_file(
            swift_username, swift_api_key, swift_cluster,
            container, name, filename, container_access
        )
    else:
        container_changed = False
        file_changed = False
        if name:
            file_changed = delete_file(
                swift_username, swift_api_key,
                swift_cluster, container, name
            )
        if container:
            container_changed = delete_container(
                swift_username, swift_api_key,
                swift_cluster, container
            )
        return (container_changed or file_changed)


def authenticate_swift(username, password, swift_cluster):
    headers = {
        'X-Storage-User': username,
        'X-Storage-Pass': password
    }
    url = "https://%s/auth/v1.0" % swift_cluster
    response = requests.get(url, headers=headers)
    storage_url = response.headers['X-Storage-Url']
    auth_token = response.headers['X-Auth-Token']
    return storage_url, auth_token

def list_container(swift_username, swift_api_key,
                   swift_cluster, container):
    (storage_url, auth_token) = authenticate_swift(
            swift_username, swift_api_key, swift_cluster)
    headers = {'X-Auth-Token': auth_token}
    url = "%s/%s?format=json" % (storage_url, container)
    response = requests.get(url, headers=headers)
    if response.status_code != 404:
        response.raise_for_status()
        return response.json()
    else:
        return "[]"

def curl_download_url(swift_username, swift_api_key, swift_cluster,
                      container, name):
    (storage_url, auth_token) = authenticate_swift(
            swift_username, swift_api_key, swift_cluster)
    cmd = "curl -H 'X-Auth-Token: %s' " % auth_token
    cmd += "-o '%s' " % name
    cmd += "%s/%s/%s" % (storage_url, container, name)
    return cmd

def validate_file(swift_username, swift_api_key, swift_cluster,
                  container, name, filename, container_access):
    (storage_url, auth_token) = authenticate_swift(
            swift_username, swift_api_key, swift_cluster)
    headers = {'X-Auth-Token': auth_token}
    url = "%s/%s?format=json" % (storage_url, container)
    container_list = requests.get(url, headers=headers)
    need_to_upload = True
    if container_list.status_code == 404:
        if container_access == 'public':
            headers['X-Container-Read'] = '*:*'
            headers['X-Container-Write'] = '*:*'
        create_response = requests.put(url, headers=headers)
        create_response.raise_for_status()
    else:
        files = container_list.json()
        for file in files:
            if file['name'] == name:
                need_to_upload = False
                continue
    if need_to_upload:
        upload_file_chunks(swift_username, swift_api_key, swift_cluster,
                           container, name, filename)
        return True
    return False

def upload_file_chunks(swift_username, swift_api_key, swift_cluster,
                       container, name, filename):
    (storage_url, auth_token) = authenticate_swift(
            swift_username, swift_api_key, swift_cluster)
    url = "%s/%s/%s" % (storage_url, container, name)
    file_size = os.path.getsize(filename)
    block_size = 1048576
    chunk_size = 2048 * block_size
    chunks = int(math.ceil(file_size / chunk_size))
    file = open(filename, 'rb')
    for i in range(0, chunks):
        (storage_url, auth_token) = authenticate_swift(
            swift_username, swift_api_key, swift_cluster)
        data = file.read(chunk_size)
        chunk_name = "chunk-{0:0>5}".format(i)
        chunk_url = "%s/%s" % (url, chunk_name)
        chunk_headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'identity',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': "'%s'" % chunk_size,
            'X-Auth-Token': auth_token
        }
        upload_response = requests.put(
            chunk_url, headers=chunk_headers, data=data)
        upload_response.raise_for_status()
    (storage_url, auth_token) = authenticate_swift(
        swift_username, swift_api_key, swift_cluster)
    manifest = "%s/%s" % (container, name)
    join_headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'identity',
        'Content-Type': 'application/octet-stream',
        'Content-Length': '0',
        'X-Auth-Token': auth_token,
        'X-Object-Manifest': manifest
    }
    join_response = requests.put(url, headers=join_headers)
    join_response.raise_for_status()

def delete_container(swift_username, swift_api_key,
                     swift_cluster, container):
    (storage_url, auth_token) = authenticate_swift(
            swift_username, swift_api_key, swift_cluster)
    headers = {'X-Auth-Token': auth_token}
    url = "%s/%s" % (storage_url, container)
    response = requests.delete(url, headers=headers)
    if response.status_code == 404 or response.status_code == 409:
        return False
    response.raise_for_status()
    return True

def delete_file(swift_username, swift_api_key,
                swift_cluster, container, name):
    (storage_url, auth_token) = authenticate_swift(
            swift_username, swift_api_key, swift_cluster)
    headers = {'X-Auth-Token': auth_token}
    url = "%s/%s?format=json" % (storage_url, container)
    response = requests.get(url, headers=headers)
    file_deleted = False
    if response.status_code != 404:
        response.raise_for_status()
        files = response.json()
        url = "%s/%s" % (storage_url, container)
        i = 0
        for fn in files:
            if fn['name'].startswith(name):
                file_url = "%s/%s" % (url, fn['name'])
                del_resp = requests.delete(file_url, headers=headers)
                del_resp.raise_for_status()
                file_deleted = True
            i += 1
    return file_deleted

def main():
    module = AnsibleModule(
        argument_spec=dict(
            swift_username=dict(required=True),
            swift_api_key=dict(required=True),
            swift_cluster=dict(
                default='dal05.objectstorage.softlayer.net'),
            container=dict(required=True),
            name=dict(required=True, default=None),
            filename=dict(required=True, default=None),
            container_access=dict(
                default='private', choices=['private', 'public']),
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
