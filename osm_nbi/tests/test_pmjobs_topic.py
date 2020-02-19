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

import asynctest
import yaml
import re
from aioresponses import aioresponses
from http import HTTPStatus
from osm_nbi.engine import EngineException
from osm_common.dbmemory import DbMemory
from osm_nbi.pmjobs_topics import PmJobsTopic
from osm_nbi.tests.test_db_descriptors import db_nsds_text, db_vnfds_text, db_nsrs_text, db_vnfrs_text
from osm_nbi.tests.pmjob_mocks.response import show_res, cpu_utilization, users, load, empty
# from osm_nbi.tests.pmjob_mocks.response import prom_res


class PmJobsTopicTest(asynctest.TestCase):

    def setUp(self):
        self.db = DbMemory()
        self.pmjobs_topic = PmJobsTopic(self.db, host="prometheus", port=9091)
        self.db.create_list("nsds", yaml.load(db_nsds_text, Loader=yaml.Loader))
        self.db.create_list("vnfds", yaml.load(db_vnfds_text, Loader=yaml.Loader))
        self.db.create_list("vnfrs", yaml.load(db_vnfrs_text, Loader=yaml.Loader))
        self.db.create_list("nsrs", yaml.load(db_nsrs_text, Loader=yaml.Loader))
        self.nsr = self.db.get_list("nsrs")[0]
        self.nsr_id = self.nsr["_id"]
        project_id = self.nsr["_admin"]["projects_write"]
        """metric_check_list contains the vnf metric name used in descriptor i.e users,load"""
        self.metric_check_list = ['cpu_utilization', 'average_memory_utilization', 'disk_read_ops',
                                  'disk_write_ops', 'disk_read_bytes', 'disk_write_bytes',
                                  'packets_dropped', 'packets_sent', 'packets_received', 'users', 'load']
        self.session = {"username": "admin", "project_id": project_id, "method": None,
                        "admin": True, "force": False, "public": False, "allow_show_user_project_role": True}

    def set_get_mock_res(self, mock_res, ns_id, metric_list):
        site = "http://prometheus:9091/api/v1/query?query=osm_metric_name{ns_id='nsr'}"
        site = re.sub(r'nsr', ns_id, site)
        for metric in metric_list:
            endpoint = re.sub(r'metric_name', metric, site)
            if metric == 'cpu_utilization':
                response = yaml.load(cpu_utilization, Loader=yaml.Loader)
            elif metric == 'users':
                response = yaml.load(users, Loader=yaml.Loader)
            elif metric == 'load':
                response = yaml.load(load, Loader=yaml.Loader)
            else:
                response = yaml.load(empty, Loader=yaml.Loader)
            mock_res.get(endpoint, payload=response)

    def test_get_vnf_metric_list(self):
        with self.subTest("Test case1 failed in test_get_vnf_metric_list"):
            metric_list = self.pmjobs_topic._get_vnf_metric_list(self.nsr_id)
            self.assertCountEqual(metric_list, self.metric_check_list,
                                  "VNF metric list is not correctly fetched")
        with self.subTest("Test case2 failed in test_get_vnf_metric_list"):
            wrong_ns_id = "88d90b0c-faff-4bbc-cccc-aaaaaaaaaaaa"
            with self.assertRaises(EngineException, msg="ns not found") as e:
                self.pmjobs_topic._get_vnf_metric_list(wrong_ns_id)
            self.assertEqual(e.exception.http_code, HTTPStatus.NOT_FOUND, "Wrong HTTP status code")
            self.assertIn("NS not found with id {}".format(wrong_ns_id),
                          str(e.exception), "Wrong exception text")

    # async def test_prom_metric_request(self):
    #     with self.subTest("Test case1 failed in test_prom"):
    #         prom_response = yaml.load(prom_res, Loader=yaml.Loader)
    #         with aioresponses() as mock_res:
    #             self.set_get_mock_res(mock_res, self.nsr_id, self.metric_check_list)
    #             result = await self.pmjobs_topic._prom_metric_request(self.nsr_id, self.metric_check_list)
    #         self.assertCountEqual(result, prom_response, "Metric Data is valid")
    #     with self.subTest("Test case2 failed in test_prom"):
    #         with self.assertRaises(EngineException, msg="Prometheus not reachable") as e:
    #             await self.pmjobs_topic._prom_metric_request(self.nsr_id, self.metric_check_list)
    #         self.assertIn("Connection to ", str(e.exception), "Wrong exception text")

    def test_show(self):
        with self.subTest("Test case1 failed in test_show"):
            show_response = yaml.load(show_res, Loader=yaml.Loader)
            with aioresponses() as mock_res:
                self.set_get_mock_res(mock_res, self.nsr_id, self.metric_check_list)
                result = self.pmjobs_topic.show(self.session, self.nsr_id)
            self.assertEqual(len(result['entries']), 3, "Number of metrics returned")
            self.assertCountEqual(result, show_response, "Response is valid")
        with self.subTest("Test case2 failed in test_show"):
            wrong_ns_id = "88d90b0c-faff-4bbc-cccc-aaaaaaaaaaaa"
            with aioresponses() as mock_res:
                self.set_get_mock_res(mock_res, wrong_ns_id, self.metric_check_list)
                with self.assertRaises(EngineException, msg="ns not found") as e:
                    self.pmjobs_topic.show(self.session, wrong_ns_id)
                self.assertEqual(e.exception.http_code, HTTPStatus.NOT_FOUND, "Wrong HTTP status code")
                self.assertIn("NS not found with id {}".format(wrong_ns_id), str(e.exception),
                              "Wrong exception text")
