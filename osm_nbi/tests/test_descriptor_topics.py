#! /usr/bin/python3
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

__author__ = "Pedro de la Cruz Ramos, pedro.delacruzramos@altran.com"
__date__ = "2019-11-20"

import unittest
from unittest import TestCase
from unittest.mock import Mock
from uuid import uuid4
from http import HTTPStatus
from copy import deepcopy
from time import time
from osm_common import dbbase, fsbase, msgbase
from osm_nbi import authconn
from osm_nbi.tests.test_pkg_descriptors import db_vnfds_text, db_nsds_text
from osm_nbi.descriptor_topics import VnfdTopic
from osm_nbi.engine import EngineException
from osm_common.dbbase import DbException
import yaml


test_pid = str(uuid4())
test_name = "test-user"
fake_session = {"username": test_name, "project_id": (test_pid,), "method": None,
                "admin": True, "force": False, "public": False, "allow_show_user_project_role": True}

db_vnfd_content = yaml.load(db_vnfds_text, Loader=yaml.Loader)[0]
db_nsd_content = yaml.load(db_nsds_text, Loader=yaml.Loader)[0]


def norm(str):
    """Normalize string for checking"""
    return ' '.join(str.strip().split()).lower()


def compare_desc(tc, d1, d2, k):
    """
    Compare two descriptors
    We need this function because some methods are adding/removing items to/from the descriptors
    before they are stored in the database, so the original and stored versions will differ
    What we check is that COMMON LEAF ITEMS are equal
    Lists of different length are not compared
    :param tc: Test Case wich provides context (in particular the assert* methods)
    :param d1,d2: Descriptors to be compared
    :param key/item being compared
    :return: Nothing
    """
    if isinstance(d1, dict) and isinstance(d2, dict):
        for key in d1.keys():
            if key in d2:
                compare_desc(tc, d1[key], d2[key], k+"[{}]".format(key))
    elif isinstance(d1, list) and isinstance(d2, list) and len(d1) == len(d2):
        for i in range(len(d1)):
            compare_desc(tc, d1[i], d2[i], k+"[{}]".format(i))
    else:
        tc.assertEqual(d1, d2, "Wrong descriptor content: {}".format(k))


class Test_VnfdTopic(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_name = "test-vnfd-topic"

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.db = Mock(dbbase.DbBase())
        self.fs = Mock(fsbase.FsBase())
        self.msg = Mock(msgbase.MsgBase())
        self.auth = Mock(authconn.Authconn(None, None, None))
        self.topic = VnfdTopic(self.db, self.fs, self.msg, self.auth)

    def test_new_vnfd(self):
        did = db_vnfd_content["_id"]
        self.fs.get_params.return_value = {}
        self.fs.file_exists.return_value = False
        self.fs.file_open.side_effect = lambda path, mode: open("/tmp/" + str(uuid4()), "a+b")
        test_vnfd = deepcopy(db_vnfd_content)
        del test_vnfd["_id"]
        del test_vnfd["_admin"]
        with self.subTest(i=1, t='Normal Creation'):
            self.db.create.return_value = did
            rollback = []
            did2, oid = self.topic.new(rollback, fake_session, {})
            db_args = self.db.create.call_args[0]
            msg_args = self.msg.write.call_args[0]
            self.assertEqual(len(rollback), 1, "Wrong rollback length")
            self.assertEqual(msg_args[0], self.topic.topic_msg, "Wrong message topic")
            self.assertEqual(msg_args[1], "created", "Wrong message action")
            self.assertEqual(msg_args[2], {"_id": did}, "Wrong message content")
            self.assertEqual(db_args[0], self.topic.topic, "Wrong DB topic")
            self.assertEqual(did2, did, "Wrong DB VNFD id")
            self.assertIsNotNone(db_args[1]["_admin"]["created"], "Wrong creation time")
            self.assertEqual(db_args[1]["_admin"]["modified"], db_args[1]["_admin"]["created"],
                             "Wrong modification time")
            self.assertEqual(db_args[1]["_admin"]["projects_read"], [test_pid], "Wrong read-only project list")
            self.assertEqual(db_args[1]["_admin"]["projects_write"], [test_pid], "Wrong read-write project list")
            tmp1 = test_vnfd["vdu"][0]["cloud-init-file"]
            tmp2 = test_vnfd["vnf-configuration"]["juju"]
            del test_vnfd["vdu"][0]["cloud-init-file"]
            del test_vnfd["vnf-configuration"]["juju"]
            try:
                self.db.get_one.side_effect = [{"_id": did, "_admin": db_vnfd_content["_admin"]}, None]
                self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                msg_args = self.msg.write.call_args[0]
                test_vnfd["_id"] = did
                self.assertEqual(msg_args[0], self.topic.topic_msg, "Wrong message topic")
                self.assertEqual(msg_args[1], "edited", "Wrong message action")
                self.assertEqual(msg_args[2], test_vnfd, "Wrong message content")
                db_args = self.db.get_one.mock_calls[0][1]
                self.assertEqual(db_args[0], self.topic.topic, "Wrong DB topic")
                self.assertEqual(db_args[1]["_id"], did, "Wrong DB VNFD id")
                db_args = self.db.replace.call_args[0]
                self.assertEqual(db_args[0], self.topic.topic, "Wrong DB topic")
                self.assertEqual(db_args[1], did, "Wrong DB VNFD id")
                admin = db_args[2]["_admin"]
                db_admin = db_vnfd_content["_admin"]
                self.assertEqual(admin["type"], "vnfd", "Wrong descriptor type")
                self.assertEqual(admin["created"], db_admin["created"], "Wrong creation time")
                self.assertGreater(admin["modified"], db_admin["created"], "Wrong modification time")
                self.assertEqual(admin["projects_read"], db_admin["projects_read"], "Wrong read-only project list")
                self.assertEqual(admin["projects_write"], db_admin["projects_write"], "Wrong read-write project list")
                self.assertEqual(admin["onboardingState"], "ONBOARDED", "Wrong onboarding state")
                self.assertEqual(admin["operationalState"], "ENABLED", "Wrong operational state")
                self.assertEqual(admin["usageState"], "NOT_IN_USE", "Wrong usage state")
                storage = admin["storage"]
                self.assertEqual(storage["folder"], did, "Wrong storage folder")
                self.assertEqual(storage["descriptor"], "package", "Wrong storage descriptor")
                compare_desc(self, test_vnfd, db_args[2], "VNFD")
            finally:
                test_vnfd["vdu"][0]["cloud-init-file"] = tmp1
                test_vnfd["vnf-configuration"]["juju"] = tmp2
        self.db.get_one.side_effect = lambda table, filter, fail_on_empty=None, fail_on_more=None:\
            {"_id": did, "_admin": db_vnfd_content["_admin"]}
        with self.subTest(i=2, t='Check Pyangbind Validation: required properties'):
            tmp = test_vnfd["id"]
            del test_vnfd["id"]
            try:
                with self.assertRaises(EngineException, msg="Accepted VNFD with a missing required property") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("Error in pyangbind validation: '{}'".format("id")),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                test_vnfd["id"] = tmp
        with self.subTest(i=3, t='Check Pyangbind Validation: additional properties'):
            test_vnfd["extra-property"] = 0
            try:
                with self.assertRaises(EngineException, msg="Accepted VNFD with an additional property") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("Error in pyangbind validation: {} ({})"
                                   .format("json object contained a key that did not exist", "extra-property")),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                del test_vnfd["extra-property"]
        with self.subTest(i=4, t='Check Pyangbind Validation: property types'):
            tmp = test_vnfd["short-name"]
            test_vnfd["short-name"] = {"key": 0}
            try:
                with self.assertRaises(EngineException, msg="Accepted VNFD with a wrongly typed property") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("Error in pyangbind validation: {} ({})"
                                   .format("json object contained a key that did not exist", "key")),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                test_vnfd["short-name"] = tmp
        with self.subTest(i=5, t='Check Input Validation: cloud-init'):
            with self.assertRaises(EngineException, msg="Accepted non-existent cloud_init file") as e:
                self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
            self.assertEqual(e.exception.http_code, HTTPStatus.BAD_REQUEST, "Wrong HTTP status code")
            self.assertIn(norm("{} defined in vnf[id={}]:vdu[id={}] but not present in package"
                               .format("cloud-init", test_vnfd["id"], test_vnfd["vdu"][0]["id"])),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=6, t='Check Input Validation: vnf-configuration[juju]'):
            del test_vnfd["vdu"][0]["cloud-init-file"]
            with self.assertRaises(EngineException, msg="Accepted non-existent charm in VNF configuration") as e:
                self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
            self.assertEqual(e.exception.http_code, HTTPStatus.BAD_REQUEST, "Wrong HTTP status code")
            self.assertIn(norm("{} defined in vnf[id={}] but not present in package".format("charm", test_vnfd["id"])),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=7, t='Check Input Validation: mgmt-interface'):
            del test_vnfd["vnf-configuration"]["juju"]
            tmp = test_vnfd["mgmt-interface"]
            del test_vnfd["mgmt-interface"]
            try:
                with self.assertRaises(EngineException, msg="Accepted VNFD without management interface") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("'{}' is a mandatory field and it is not defined".format("mgmt-interface")),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                test_vnfd["mgmt-interface"] = tmp
        with self.subTest(i=8, t='Check Input Validation: mgmt-interface[cp]'):
            tmp = test_vnfd["mgmt-interface"]["cp"]
            test_vnfd["mgmt-interface"]["cp"] = "wrong-cp"
            try:
                with self.assertRaises(EngineException,
                                       msg="Accepted wrong management interface connection point") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("mgmt-interface:cp='{}' must match an existing connection-point"
                                   .format(test_vnfd["mgmt-interface"]["cp"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                test_vnfd["mgmt-interface"]["cp"] = tmp
        with self.subTest(i=9, t='Check Input Validation: vdu[interface][external-connection-point-ref]'):
            tmp = test_vnfd["vdu"][0]["interface"][0]["external-connection-point-ref"]
            test_vnfd["vdu"][0]["interface"][0]["external-connection-point-ref"] = "wrong-cp"
            try:
                with self.assertRaises(EngineException,
                                       msg="Accepted wrong VDU interface external connection point reference") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("vdu[id='{}']:interface[name='{}']:external-connection-point-ref='{}'"
                                   " must match an existing connection-point"
                                   .format(test_vnfd["vdu"][0]["id"], test_vnfd["vdu"][0]["interface"][0]["name"],
                                           test_vnfd["vdu"][0]["interface"][0]["external-connection-point-ref"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                test_vnfd["vdu"][0]["interface"][0]["external-connection-point-ref"] = tmp
        with self.subTest(i=10, t='Check Input Validation: vdu[interface][internal-connection-point-ref]'):
            tmp = test_vnfd["vdu"][1]["interface"][0]["internal-connection-point-ref"]
            test_vnfd["vdu"][1]["interface"][0]["internal-connection-point-ref"] = "wrong-cp"
            try:
                with self.assertRaises(EngineException,
                                       msg="Accepted wrong VDU interface internal connection point reference") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("vdu[id='{}']:interface[name='{}']:internal-connection-point-ref='{}'"
                                   " must match an existing vdu:internal-connection-point"
                                   .format(test_vnfd["vdu"][1]["id"], test_vnfd["vdu"][1]["interface"][0]["name"],
                                           test_vnfd["vdu"][1]["interface"][0]["internal-connection-point-ref"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                test_vnfd["vdu"][1]["interface"][0]["internal-connection-point-ref"] = tmp
        with self.subTest(i=11, t='Check Input Validation: vdu[vdu-configuration][juju]'):
            test_vnfd["vdu"][0]["vdu-configuration"] = {"juju": {"charm": "wrong-charm"}}
            try:
                with self.assertRaises(EngineException, msg="Accepted non-existent charm in VDU configuration") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.BAD_REQUEST, "Wrong HTTP status code")
                self.assertIn(norm("{} defined in vnf[id={}]:vdu[id={}] but not present in package"
                                   .format("charm", test_vnfd["id"], test_vnfd["vdu"][0]["id"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                del test_vnfd["vdu"][0]["vdu-configuration"]
        with self.subTest(i=12, t='Check Input Validation: Duplicated VLD name'):
            test_vnfd["internal-vld"].append(deepcopy(test_vnfd["internal-vld"][0]))
            test_vnfd["internal-vld"][1]["id"] = "wrong-internal-vld"
            try:
                with self.assertRaises(EngineException, msg="Accepted duplicated VLD name") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("Duplicated VLD name '{}' in vnfd[id={}]:internal-vld[id={}]"
                                   .format(test_vnfd["internal-vld"][1]["name"], test_vnfd["id"],
                                           test_vnfd["internal-vld"][1]["id"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                del test_vnfd["internal-vld"][1]
        with self.subTest(i=13, t='Check Input Validation: internal-vld[internal-connection-point][id-ref])'):
            tmp = test_vnfd["internal-vld"][0]["internal-connection-point"][0]["id-ref"]
            test_vnfd["internal-vld"][0]["internal-connection-point"][0]["id-ref"] = "wrong-icp-id-ref"
            try:
                with self.assertRaises(EngineException, msg="Accepted non-existent internal VLD ICP id-ref") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("internal-vld[id='{}']:internal-connection-point='{}' must match an existing "
                                   "vdu:internal-connection-point"
                                   .format(test_vnfd["internal-vld"][0]["id"],
                                           test_vnfd["internal-vld"][0]["internal-connection-point"][0]["id-ref"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                test_vnfd["internal-vld"][0]["internal-connection-point"][0]["id-ref"] = tmp
        with self.subTest(i=14, t='Check Input Validation: internal-vld[ip-profile-ref])'):
            test_vnfd["ip-profiles"] = [{"name": "fake-ip-profile-ref"}]
            test_vnfd["internal-vld"][0]["ip-profile-ref"] = "wrong-ip-profile-ref"
            try:
                with self.assertRaises(EngineException, msg="Accepted non-existent IP Profile Ref") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("internal-vld[id='{}']:ip-profile-ref='{}' does not exist"
                                   .format(test_vnfd["internal-vld"][0]["id"],
                                           test_vnfd["internal-vld"][0]["ip-profile-ref"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                del test_vnfd["ip-profiles"]
                del test_vnfd["internal-vld"][0]["ip-profile-ref"]
        with self.subTest(i=15, t='Check Input Validation: vdu[monitoring-param])'):
            test_vnfd["monitoring-param"] = [{"id": "fake-mp-id", "vdu-monitoring-param": {
                "vdu-monitoring-param-ref": "fake-vdu-mp-ref", "vdu-ref": "fake-vdu-ref"}}]
            test_vnfd["vdu"][0]["monitoring-param"] = [{"id": "wrong-vdu-mp-id"}]
            try:
                with self.assertRaises(EngineException, msg="Accepted non-existent VDU Monitorimg Param") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                mp = test_vnfd["monitoring-param"][0]["vdu-monitoring-param"]
                self.assertIn(norm("monitoring-param:vdu-monitoring-param:vdu-monitoring-param-ref='{}' not defined"
                                   " at vdu[id='{}'] or vdu does not exist"
                                   .format(mp["vdu-monitoring-param-ref"], mp["vdu-ref"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                del test_vnfd["monitoring-param"]
                del test_vnfd["vdu"][0]["monitoring-param"]
        with self.subTest(i=16, t='Check Input Validation: vdu[vdu-configuration][metrics]'):
            test_vnfd["monitoring-param"] = [{"id": "fake-mp-id", "vdu-metric": {
                "vdu-metric-name-ref": "fake-vdu-mp-ref", "vdu-ref": "fake-vdu-ref"}}]
            test_vnfd["vdu"][0]["vdu-configuration"] = {"metrics": [{"name": "wrong-vdu-mp-id"}]}
            try:
                with self.assertRaises(EngineException, msg="Accepted non-existent VDU Configuration Metric") as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                mp = test_vnfd["monitoring-param"][0]["vdu-metric"]
                self.assertIn(norm("monitoring-param:vdu-metric:vdu-metric-name-ref='{}' not defined"
                                   " at vdu[id='{}'] or vdu does not exist"
                                   .format(mp["vdu-metric-name-ref"], mp["vdu-ref"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                del test_vnfd["monitoring-param"]
                del test_vnfd["vdu"][0]["vdu-configuration"]
        with self.subTest(i=17, t='Check Input Validation: scaling-group-descriptor[scaling-policy][scaling-criteria]'):
            test_vnfd["monitoring-param"] = [{"id": "fake-mp-id"}]
            test_vnfd["scaling-group-descriptor"] = [{
                "name": "fake-vnf-sg-name",
                "vdu": [{"vdu-id-ref": "wrong-vdu-id-ref"}],
                "scaling-policy": [{"name": "fake-vnf-sp-name", "scaling-criteria": [{
                    "name": "fake-vnf-sc-name", "vnf-monitoring-param-ref": "wrong-vnf-mp-id"}]}]}]
            with self.assertRaises(EngineException, msg="Accepted non-existent Scaling Group Policy Criteria") as e:
                self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            sg = test_vnfd["scaling-group-descriptor"][0]
            sc = sg["scaling-policy"][0]["scaling-criteria"][0]
            self.assertIn(norm("scaling-group-descriptor[name='{}']:scaling-criteria[name='{}']:"
                               "vnf-monitoring-param-ref='{}' not defined in any monitoring-param"
                               .format(sg["name"], sc["name"], sc["vnf-monitoring-param-ref"])),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=18, t='Check Input Validation: scaling-group-descriptor[vdu][vdu-id-ref]'):
            sc["vnf-monitoring-param-ref"] = "fake-mp-id"
            with self.assertRaises(EngineException, msg="Accepted non-existent Scaling Group VDU ID Reference") as e:
                self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn(norm("scaling-group-descriptor[name='{}']:vdu-id-ref={} does not match any vdu"
                               .format(sg["name"], sg["vdu"][0]["vdu-id-ref"])),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=19, t='Check Input Validation: scaling-group-descriptor[scaling-config-action]'):
            tmp = test_vnfd["vnf-configuration"]
            del test_vnfd["vnf-configuration"]
            sg["vdu"][0]["vdu-id-ref"] = test_vnfd["vdu"][0]["id"]
            sg["scaling-config-action"] = [{"trigger": "pre-scale-in"}]
            try:
                with self.assertRaises(EngineException, msg="Accepted non-existent Scaling Group VDU ID Reference")\
                        as e:
                    self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
                self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
                self.assertIn(norm("'vnf-configuration' not defined in the descriptor but it is referenced"
                                   " by scaling-group-descriptor[name='{}']:scaling-config-action"
                                   .format(sg["name"])),
                              norm(str(e.exception)), "Wrong exception text")
            finally:
                test_vnfd["vnf-configuration"] = tmp
        with self.subTest(i=20, t='Check Input Validation: scaling-group-descriptor[scaling-config-action]'
                                  '[vnf-config-primitive-name-ref]'):
            sg["scaling-config-action"][0]["vnf-config-primitive-name-ref"] = "wrong-sca-prim-name"
            with self.assertRaises(EngineException, msg="Accepted non-existent Scaling Group VDU ID Reference") as e:
                self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn(norm("scaling-group-descriptor[name='{}']:scaling-config-action:"
                               "vnf-config-primitive-name-ref='{}' does not match"
                               " any vnf-configuration:config-primitive:name"
                               .format(sg["name"], sg["scaling-config-action"][0]["vnf-config-primitive-name-ref"])),
                          norm(str(e.exception)), "Wrong exception text")
            # del test_vnfd["monitoring-param"]
            # del test_vnfd["scaling-group-descriptor"]
        with self.subTest(i=21, t='Check Input Validation: everything right'):
            sg["scaling-config-action"][0]["vnf-config-primitive-name-ref"] = "touch"
            test_vnfd["id"] = "fake-vnfd-id"
            self.db.get_one.side_effect = [{"_id": did, "_admin": db_vnfd_content["_admin"]}, None]
            rc = self.topic.upload_content(fake_session, did, test_vnfd, {}, {"Content-Type": []})
            self.assertTrue(rc, "Input Validation: Unexpected failure")
        return

    def test_edit_vnfd(self):
        did = db_vnfd_content["_id"]
        self.fs.file_exists.return_value = True
        self.fs.dir_ls.return_value = True
        with self.subTest(i=1, t='Normal Edition'):
            now = time()
            self.db.get_one.side_effect = [db_vnfd_content, None]
            data = {"id": "new-vnfd-id", "name": "new-vnfd-name"}
            self.topic.edit(fake_session, did, data)
            db_args = self.db.replace.call_args[0]
            msg_args = self.msg.write.call_args[0]
            data["_id"] = did
            self.assertEqual(msg_args[0], self.topic.topic_msg, "Wrong message topic")
            self.assertEqual(msg_args[1], "edited", "Wrong message action")
            self.assertEqual(msg_args[2], data, "Wrong message content")
            self.assertEqual(db_args[0], self.topic.topic, "Wrong DB topic")
            self.assertEqual(db_args[1], did, "Wrong DB ID")
            self.assertEqual(db_args[2]["_admin"]["created"], db_vnfd_content["_admin"]["created"],
                             "Wrong creation time")
            self.assertGreater(db_args[2]["_admin"]["modified"], now,
                               "Wrong modification time")
            self.assertEqual(db_args[2]["_admin"]["projects_read"], db_vnfd_content["_admin"]["projects_read"],
                             "Wrong read-only project list")
            self.assertEqual(db_args[2]["_admin"]["projects_write"], db_vnfd_content["_admin"]["projects_write"],
                             "Wrong read-write project list")
            self.assertEqual(db_args[2]["id"], data["id"], "Wrong VNFD ID")
            self.assertEqual(db_args[2]["name"], data["name"], "Wrong VNFD Name")
        with self.subTest(i=2, t='Conflict on Edit'):
            data = {"id": "fake-vnfd-id", "name": "new-vnfd-name"}
            self.db.get_one.side_effect = [db_vnfd_content, {"_id": str(uuid4()), "id": data["id"]}]
            with self.assertRaises(EngineException, msg="Accepted existing VNFD ID") as e:
                self.topic.edit(fake_session, did, data)
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn(norm("{} with id '{}' already exists for this project".format("vnfd", data["id"])),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=3, t='Check Envelope'):
            data = {"vnfd": {"id": "new-vnfd-id-1", "name": "new-vnfd-name"}}
            with self.assertRaises(EngineException, msg="Accepted VNFD with wrong envelope") as e:
                self.topic.edit(fake_session, did, data)
            self.assertEqual(e.exception.http_code, HTTPStatus.BAD_REQUEST, "Wrong HTTP status code")
            self.assertIn("'vnfd' must be a list of only one element", norm(str(e.exception)), "Wrong exception text")
        return

    def test_delete_vnfd(self):
        did = db_vnfd_content["_id"]
        self.db.get_one.return_value = db_vnfd_content
        with self.subTest(i=1, t='Normal Deletion'):
            self.db.get_list.return_value = []
            self.db.del_one.return_value = {"deleted": 1}
            self.topic.delete(fake_session, did)
            db_args = self.db.del_one.call_args[0]
            msg_args = self.msg.write.call_args[0]
            self.assertEqual(msg_args[0], self.topic.topic_msg, "Wrong message topic")
            self.assertEqual(msg_args[1], "deleted", "Wrong message action")
            self.assertEqual(msg_args[2], {"_id": did}, "Wrong message content")
            self.assertEqual(db_args[0], self.topic.topic, "Wrong DB topic")
            self.assertEqual(db_args[1]["_id"], did, "Wrong DB ID")
            self.assertEqual(db_args[1]["_admin.projects_read"], [[], ['ANY']], "Wrong DB filter")
            db_g1_args = self.db.get_one.call_args[0]
            self.assertEqual(db_g1_args[0], self.topic.topic, "Wrong DB topic")
            self.assertEqual(db_g1_args[1]["_id"], did, "Wrong DB VNFD ID")
            db_gl_calls = self.db.get_list.call_args_list
            self.assertEqual(db_gl_calls[0][0][0], "vnfrs", "Wrong DB topic")
            # self.assertEqual(db_gl_calls[0][0][1]["vnfd-id"], did, "Wrong DB VNFD ID")   # Filter changed after call
            self.assertEqual(db_gl_calls[1][0][0], "nsds", "Wrong DB topic")
            self.assertEqual(db_gl_calls[1][0][1]["constituent-vnfd.ANYINDEX.vnfd-id-ref"], db_vnfd_content["id"],
                             "Wrong DB NSD constituent-vnfd id-ref")
            db_s1_args = self.db.set_one.call_args
            self.assertEqual(db_s1_args[0][0], self.topic.topic, "Wrong DB topic")
            self.assertEqual(db_s1_args[0][1]["_id"], did, "Wrong DB ID")
            self.assertIn(test_pid, db_s1_args[0][1]["_admin.projects_write.cont"], "Wrong DB filter")
            self.assertIsNone(db_s1_args[1]["update_dict"], "Wrong DB update dictionary")
            self.assertEqual(db_s1_args[1]["pull"]["_admin.projects_read"]["$in"], fake_session["project_id"],
                             "Wrong DB pull dictionary")
            fs_del_calls = self.fs.file_delete.call_args_list
            self.assertEqual(fs_del_calls[0][0][0], did, "Wrong FS file id")
            self.assertEqual(fs_del_calls[1][0][0], did+'_', "Wrong FS folder id")
        with self.subTest(i=2, t='Conflict on Delete - VNFD in use by VNFR'):
            self.db.get_list.return_value = [{"_id": str(uuid4()), "name": "fake-vnfr"}]
            with self.assertRaises(EngineException, msg="Accepted VNFD in use by VNFR") as e:
                self.topic.delete(fake_session, did)
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("there is at least one vnf using this descriptor", norm(str(e.exception)),
                          "Wrong exception text")
        with self.subTest(i=3, t='Conflict on Delete - VNFD in use by NSD'):
            self.db.get_list.side_effect = [[], [{"_id": str(uuid4()), "name": "fake-nsd"}]]
            with self.assertRaises(EngineException, msg="Accepted VNFD in use by NSD") as e:
                self.topic.delete(fake_session, did)
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("there is at least one nsd referencing this descriptor", norm(str(e.exception)),
                          "Wrong exception text")
        with self.subTest(i=4, t='Non-existent VNFD'):
            excp_msg = "Not found any {} with filter='{}'".format("VNFD", {"_id": did})
            self.db.get_one.side_effect = DbException(excp_msg, HTTPStatus.NOT_FOUND)
            with self.assertRaises(DbException, msg="Accepted non-existent VNFD ID") as e:
                self.topic.delete(fake_session, did)
            self.assertEqual(e.exception.http_code, HTTPStatus.NOT_FOUND, "Wrong HTTP status code")
            self.assertIn(norm(excp_msg), norm(str(e.exception)), "Wrong exception text")
        return


if __name__ == '__main__':
    unittest.main()
