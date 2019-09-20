# Copyright 2019 Preethika P(Tata Elxsi)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = "Preethika P,preethika.p@tataelxsi.co.in"

"""Excepted results for pmjob functions and prometheus"""


show_res = """
---
entries:
-   objectInstanceId: f48163a6-c807-47bc-9682-f72caef5af85
    performanceMetric: osm_users
    performanceValue:
        performanceValue:
            performanceValue: '1'
            vduName: test_metric-1-ubuntuvdu1-1
            vnfMemberIndex: '1'
        timestamp: 1573552141.409
-   objectInstanceId: f48163a6-c807-47bc-9682-f72caef5af85
    performanceMetric: osm_cpu_utilization
    performanceValue:
        performanceValue:
            performanceValue: '0.7622979249'
            vduName: test_metric-1-ubuntuvdu1-1
            vnfMemberIndex: '1'
        timestamp: 1573556383.439
-   objectInstanceId: f48163a6-c807-47bc-9682-f72caef5af85
    performanceMetric: osm_load
    performanceValue:
        performanceValue:
            performanceValue: '0'
            vduName: test_metric-1-ubuntuvdu1-1
            vnfMemberIndex: '1'
        timestamp: 1573552060.035
"""
prom_res = """
---
- - metric:
      __name__: osm_users
      instance: mon:8000
      job: prometheus
      ns_id: f48163a6-c807-47bc-9682-f72caef5af85
      vdu_name: test_metric-1-ubuntuvdu1-1
      vnf_member_index: '1'
    value:
    - 1573552141.409
    - '1'
- - metric:
      __name__: osm_load
      instance: mon:8000
      job: prometheus
      ns_id: f48163a6-c807-47bc-9682-f72caef5af85
      vdu_name: test_metric-1-ubuntuvdu1-1
      vnf_member_index: '1'
    value:
    - 1573552060.035
    - '0'
- - metric:
      __name__: osm_cpu_utilization
      instance: mon:8000
      job: prometheus
      ns_id: f48163a6-c807-47bc-9682-f72caef5af85
      vdu_name: test_metric-1-ubuntuvdu1-1
      vnf_member_index: '1'
    value:
    - 1573556383.439
    - '0.7622979249'
"""
cpu_utilization = """
---
status: success
data:
  resultType: vector
  result:
  - metric:
      __name__: osm_cpu_utilization
      instance: mon:8000
      job: prometheus
      ns_id: f48163a6-c807-47bc-9682-f72caef5af85
      vdu_name: test_metric-1-ubuntuvdu1-1
      vnf_member_index: '1'
    value:
    - 1573556383.439
    - '0.7622979249'
"""
users = """
---
status: success
data:
  resultType: vector
  result:
  - metric:
      __name__: osm_users
      instance: mon:8000
      job: prometheus
      ns_id: f48163a6-c807-47bc-9682-f72caef5af85
      vdu_name: test_metric-1-ubuntuvdu1-1
      vnf_member_index: '1'
    value:
    - 1573552141.409
    - '1'
"""
load = """
---
status: success
data:
  resultType: vector
  result:
  - metric:
      __name__: osm_load
      instance: mon:8000
      job: prometheus
      ns_id: f48163a6-c807-47bc-9682-f72caef5af85
      vdu_name: test_metric-1-ubuntuvdu1-1
      vnf_member_index: '1'
    value:
    - 1573552060.035
    - '0'
"""
empty = """
---
status: success
data:
  resultType: vector
  result: []
"""
