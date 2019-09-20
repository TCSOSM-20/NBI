# -*- coding: utf-8 -*-

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

import asyncio
import aiohttp
from http import HTTPStatus
from urllib.parse import quote
from osm_nbi.base_topic import EngineException

__author__ = "Vijay R S <vijay.r@tataelxsi.co.in>"


class PmJobsTopic():
    def __init__(self, db, host=None, port=None):
        self.db = db
        self.url = 'http://{}:{}'.format(host, port)
        self.nfvi_metric_list = ['cpu_utilization', 'average_memory_utilization', 'disk_read_ops',
                                 'disk_write_ops', 'disk_read_bytes', 'disk_write_bytes',
                                 'packets_dropped', 'packets_sent', 'packets_received']

    def _get_vnf_metric_list(self, ns_id):
        metric_list = self.nfvi_metric_list.copy()
        vnfr_desc = self.db.get_list("vnfrs", {"nsr-id-ref": ns_id})
        if not vnfr_desc:
            raise EngineException("NS not found with id {}".format(ns_id), http_code=HTTPStatus.NOT_FOUND)
        else:
            for vnfr in vnfr_desc:
                vnfd_desc = self.db.get_one("vnfds", {"_id": vnfr["vnfd-id"]}, fail_on_empty=True, fail_on_more=False)
                if vnfd_desc.get("vdu"):
                    for vdu in vnfd_desc['vdu']:
                        # Checks for vdu metric in vdu-configuration
                        if 'vdu-configuration' in vdu and 'metrics' in vdu['vdu-configuration']:
                            metric_list.extend([quote(metric['name']) 
                                               for metric in vdu["vdu-configuration"]["metrics"]])
                # Checks for vnf metric in vnf-configutaion
                if 'vnf-configuration' in vnfd_desc and 'metrics' in vnfd_desc['vnf-configuration']:
                    metric_list.extend([quote(metric['name']) for metric in vnfd_desc["vnf-configuration"]["metrics"]])
        metric_list = list(set(metric_list))
        return metric_list

    async def _prom_metric_request(self, ns_id, metrics_list):
        try:
            async with aiohttp.ClientSession() as session:
                data = []
                for metlist in metrics_list:
                    request_url = self.url+'/api/v1/query?query=osm_'+metlist+"{ns_id='"+ns_id+"'}"
                    async with session.get(request_url) as resp:
                        resp = await resp.json()
                        resp = resp['data']['result']
                        if resp:
                            data.append(resp)
                return data
        except aiohttp.client_exceptions.ClientConnectorError as e:
            raise EngineException("Connection to '{}'Failure: {}".format(self.url, e))

    def show(self, session, ns_id):
        metrics_list = self._get_vnf_metric_list(ns_id)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        prom_metric = loop.run_until_complete(self._prom_metric_request(ns_id, metrics_list))
        metric = {}
        metric_temp = []
        for index_list in prom_metric:
            for index in index_list:
                process_metric = {'performanceValue': {'performanceValue': {}}}
                process_metric['objectInstanceId'] = index['metric']['ns_id']
                process_metric['performanceMetric'] = index['metric']['__name__']
                process_metric['performanceValue']['timestamp'] = index['value'][0]
                process_metric['performanceValue']['performanceValue']['performanceValue'] = index['value'][1]
                process_metric['performanceValue']['performanceValue']['vnfMemberIndex'] \
                    = index['metric']['vnf_member_index']
                if 'vdu_name' not in index['metric']:
                    pass
                else:
                    process_metric['performanceValue']['performanceValue']['vduName'] = index['metric']['vdu_name']
                metric_temp.append(process_metric)
        metric['entries'] = metric_temp
        return metric
