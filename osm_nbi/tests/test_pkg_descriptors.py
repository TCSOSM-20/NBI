#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# For those usages not covered by the Apache License, Version 2.0 please
# contact: esousa@whitestack.com or alfonso.tiernosepulveda@telefonica.com
##

"""Contains database content needed for tests"""

__author__ = "Pedro de la Cruz Ramos, pedro.delacruzramos@altran.com"
__date__ = "2019-11-20"

db_vnfds_text = """
---
-   _admin:
        created: 1566823352.7154346
        modified: 1566823352.7154346
        onboardingState: ONBOARDED
        operationalState: ENABLED
        projects_read:
        - 25b5aebf-3da1-49ed-99de-1d2b4a86d6e4
        projects_write:
        - 25b5aebf-3da1-49ed-99de-1d2b4a86d6e4
        storage:
            descriptor: hackfest_3charmed_vnfd/hackfest_3charmed_vnfd.yaml
            folder: 7637bcf8-cf14-42dc-ad70-c66fcf1e6e77
            fs: local
            path: /app/storage/
            pkg-dir: hackfest_3charmed_vnfd
            zipfile: package.tar.gz
        type: vnfd
        usageState: NOT_IN_USE
        userDefinedData: {}
    _id: 7637bcf8-cf14-42dc-ad70-c66fcf1e6e77
    connection-point:
    -   id: vnf-mgmt
        name: vnf-mgmt
        short-name: vnf-mgmt
        type: VPORT
    -   id: vnf-data
        name: vnf-data
        short-name: vnf-data
        type: VPORT
    description: A VNF consisting of 2 VDUs connected to an internal VL, and one VDU
        with cloud-init
    id: hackfest3charmed-vnf
    internal-vld:
    -   id: internal
        internal-connection-point:
        -   id-ref: mgmtVM-internal
        -   id-ref: dataVM-internal
        name: internal
        short-name: internal
        type: ELAN
    logo: osm.png
    mgmt-interface:
        cp: vnf-mgmt
    monitoring-param:
    -   aggregation-type: AVERAGE
        id: monitor1
        name: monitor1
        vdu-monitoring-param:
            vdu-monitoring-param-ref: dataVM_cpu_util
            vdu-ref: dataVM
    name: hackfest3charmed-vnf
    scaling-group-descriptor:
    -   max-instance-count: 10
        name: scale_dataVM
        scaling-config-action:
        -   trigger: post-scale-out
            vnf-config-primitive-name-ref: touch
        -   trigger: pre-scale-in
            vnf-config-primitive-name-ref: touch
        scaling-policy:
        -   cooldown-time: 60
            name: auto_cpu_util_above_threshold
            scaling-criteria:
            -   name: cpu_util_above_threshold
                scale-in-relational-operation: LE
                scale-in-threshold: '15.0000000000'
                scale-out-relational-operation: GE
                scale-out-threshold: '60.0000000000'
                vnf-monitoring-param-ref: monitor1
            scaling-type: automatic
            threshold-time: 0
        vdu:
        -   count: 1
            vdu-id-ref: dataVM
    short-name: hackfest3charmed-vnf
    vdu:
    -   count: '1'
        cloud-init-file: cloud-config.txt
        id: mgmtVM
        image: hackfest3-mgmt
        interface:
        -   external-connection-point-ref: vnf-mgmt
            name: mgmtVM-eth0
            position: 1
            type: EXTERNAL
            virtual-interface:
                type: VIRTIO
        -   internal-connection-point-ref: mgmtVM-internal
            name: mgmtVM-eth1
            position: 2
            type: INTERNAL
            virtual-interface:
                type: VIRTIO
        internal-connection-point:
        -   id: mgmtVM-internal
            name: mgmtVM-internal
            short-name: mgmtVM-internal
            type: VPORT
        name: mgmtVM
        vm-flavor:
            memory-mb: '1024'
            storage-gb: '10'
            vcpu-count: 1
    -   count: '1'
        id: dataVM
        image: hackfest3-mgmt
        interface:
        -   internal-connection-point-ref: dataVM-internal
            name: dataVM-eth0
            position: 1
            type: INTERNAL
            virtual-interface:
                type: VIRTIO
        -   external-connection-point-ref: vnf-data
            name: dataVM-xe0
            position: 2
            type: EXTERNAL
            virtual-interface:
                type: VIRTIO
        internal-connection-point:
        -   id: dataVM-internal
            name: dataVM-internal
            short-name: dataVM-internal
            type: VPORT
        monitoring-param:
        -   id: dataVM_cpu_util
            nfvi-metric: cpu_utilization
        name: dataVM
        vm-flavor:
            memory-mb: '1024'
            storage-gb: '10'
            vcpu-count: 1
    version: '1.0'
    vnf-configuration:
        config-primitive:
        -   name: touch
            parameter:
            -   data-type: STRING
                default-value: <touch_filename2>
                name: filename
        initial-config-primitive:
        -   name: config
            parameter:
            -   name: ssh-hostname
                value: <rw_mgmt_ip>
            -   name: ssh-username
                value: ubuntu
            -   name: ssh-password
                value: osm4u
            seq: '1'
        -   name: touch
            parameter:
            -   name: filename
                value: <touch_filename>
            seq: '2'
        juju:
            charm: simple
"""

db_nsds_text = """
---
-   _admin:
        created: 1566823353.971486
        modified: 1566823353.971486
        onboardingState: ONBOARDED
        operationalState: ENABLED
        projects_read:
        - 25b5aebf-3da1-49ed-99de-1d2b4a86d6e4
        projects_write:
        - 25b5aebf-3da1-49ed-99de-1d2b4a86d6e4
        storage:
            descriptor: hackfest_3charmed_nsd/hackfest_3charmed_nsd.yaml
            folder: 8c2f8b95-bb1b-47ee-8001-36dc090678da
            fs: local
            path: /app/storage/
            pkg-dir: hackfest_3charmed_nsd
            zipfile: package.tar.gz
        usageState: NOT_IN_USE
        userDefinedData: {}
    _id: 8c2f8b95-bb1b-47ee-8001-36dc090678da
    constituent-vnfd:
    -   member-vnf-index: '1'
        vnfd-id-ref: hackfest3charmed-vnf
    -   member-vnf-index: '2'
        vnfd-id-ref: hackfest3charmed-vnf
    description: NS with 2 VNFs hackfest3charmed-vnf connected by datanet and mgmtnet
        VLs
    id: hackfest3charmed-ns
    logo: osm.png
    name: hackfest3charmed-ns
    short-name: hackfest3charmed-ns
    version: '1.0'
    vld:
    -   id: mgmt
        mgmt-network: true
        name: mgmt
        short-name: mgmt
        type: ELAN
        vim-network-name: mgmt
        vnfd-connection-point-ref:
        -   member-vnf-index-ref: '1'
            vnfd-connection-point-ref: vnf-mgmt
            vnfd-id-ref: hackfest3charmed-vnf
        -   member-vnf-index-ref: '2'
            vnfd-connection-point-ref: vnf-mgmt
            vnfd-id-ref: hackfest3charmed-vnf
    -   id: datanet
        name: datanet
        short-name: datanet
        type: ELAN
        vnfd-connection-point-ref:
        -   member-vnf-index-ref: '1'
            vnfd-connection-point-ref: vnf-data
            vnfd-id-ref: hackfest3charmed-vnf
        -   member-vnf-index-ref: '2'
            vnfd-connection-point-ref: vnf-data
            vnfd-id-ref: hackfest3charmed-vnf
"""
