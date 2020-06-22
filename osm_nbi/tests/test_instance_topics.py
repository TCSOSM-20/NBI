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

import unittest
from unittest.mock import Mock, mock_open   # patch, MagicMock
from osm_common.dbbase import DbException
from osm_nbi.engine import EngineException
from osm_common.dbmemory import DbMemory
from osm_common.fsbase import FsBase
from osm_common.msgbase import MsgBase
from http import HTTPStatus
from osm_nbi.instance_topics import NsLcmOpTopic, NsrTopic
from osm_nbi.tests.test_db_descriptors import db_vim_accounts_text, db_nsds_text, db_vnfds_text, db_nsrs_text,\
    db_vnfrs_text
from copy import deepcopy
import yaml


class TestNsLcmOpTopic(unittest.TestCase):

    def setUp(self):
        self.db = DbMemory()
        self.fs = Mock(FsBase())
        self.fs.get_params.return_value = {"./fake/folder"}
        self.fs.file_open = mock_open()
        self.msg = Mock(MsgBase())
        # create class
        self.nslcmop_topic = NsLcmOpTopic(self.db, self.fs, self.msg, None)
        self.nslcmop_topic.check_quota = Mock(return_value=None)  # skip quota

        self.db.create_list("vim_accounts", yaml.load(db_vim_accounts_text, Loader=yaml.Loader))
        self.db.create_list("nsds", yaml.load(db_nsds_text, Loader=yaml.Loader))
        self.db.create_list("vnfds", yaml.load(db_vnfds_text, Loader=yaml.Loader))
        self.db.create_list("vnfrs", yaml.load(db_vnfrs_text, Loader=yaml.Loader))
        self.db.create_list("nsrs", yaml.load(db_nsrs_text, Loader=yaml.Loader))
        self.db.create = Mock(return_value="created_id")
        self.db.set_one = Mock(return_value={"updated": 1})
        self.nsd = self.db.get_list("nsds")[0]
        self.nsd_id = self.nsd["_id"]
        self.nsr = self.db.get_list("nsrs")[0]
        self.nsr_id = self.nsr["_id"]
        self.nsr_project = self.nsr["_admin"]["projects_read"][0]

        self.vim = self.db.get_list("vim_accounts")[0]
        self.vim_id = self.vim["_id"]

    def test_create_instantiate(self):
        session = {"force": False, "admin": False, "public": False, "project_id": [self.nsr_project], "method": "write"}
        indata = {
            "nsdId": self.nsd_id,
            "nsInstanceId": self.nsr_id,
            "nsName": "name",
            "vimAccountId": self.vim_id,
            "additionalParamsForVnf": [{"member-vnf-index": "1", "additionalParams": {"touch_filename": "file"}},
                                       {"member-vnf-index": "2", "additionalParams": {"touch_filename": "file"}}],
            "vnf": [{"member-vnf-index": "1",
                     "vdu": [{"id": "dataVM", "interface": [{"name": "dataVM-eth0",
                                                             "ip-address": "10.11.12.13",
                                                             "floating-ip-required": True}]
                              }],
                     "internal-vld": [{"name": "internal", "vim-network-id": "vim-net-id"}]
                     }],
            "lcmOperationType": "instantiate",

        }
        rollback = []
        headers = {}

        nslcmop_id, _ = self.nslcmop_topic.new(rollback, session, indata=deepcopy(indata), kwargs=None, headers=headers)

        # check nslcmop is created at database
        self.assertEqual(self.db.create.call_count, 1, "database create not called, or called more than once")
        _call = self.db.create.call_args_list[0]
        self.assertEqual(_call[0][0], "nslcmops", "must be create a nslcmops entry at database")

        created_nslcmop = _call[0][1]
        self.assertEqual(nslcmop_id, created_nslcmop["_id"], "mismatch between return id and database '_id'")
        self.assertEqual(self.nsr_id, created_nslcmop["nsInstanceId"], "bad reference id from nslcmop to nsr")
        self.assertTrue(created_nslcmop["_admin"].get("projects_read"),
                        "Database record must contain '_amdin.projects_read'")
        self.assertIn("created", created_nslcmop["_admin"], "Database record must contain '_admin.created'")
        self.assertTrue(created_nslcmop["lcmOperationType"] == "instantiate",
                        "Database record must contain 'lcmOperationType=instantiate'")

        self.assertEqual(len(rollback), len(self.db.set_one.call_args_list) + 1,
                         "rollback mismatch with created/set items at database")

        # test parameters with error
        bad_id = "88d90b0c-faff-4b9f-bccd-aaaaaaaaaaaa"
        test_set = (
            ("nsr not found", {"nsInstanceId": bad_id}, DbException, HTTPStatus.NOT_FOUND, ("not found", bad_id)),
            # TODO add "nsd"
            # ({"vimAccountId": bad_id}, DbException, HTTPStatus.NOT_FOUND, ("not found", bad_id)),  # TODO add "vim"
            ("bad member-vnf-index", {"vnf.0.member-vnf-index": "k"}, EngineException, HTTPStatus.BAD_REQUEST,
             ("k",)),
        )
        for message, kwargs_, expect_exc, expect_code, expect_text_list in test_set:
            with self.assertRaises(expect_exc, msg=message) as e:
                self.nslcmop_topic.new(rollback, session, indata=deepcopy(indata), kwargs=kwargs_, headers=headers)
            if expect_code:
                self.assertTrue(e.exception.http_code == expect_code)
            if expect_text_list:
                for expect_text in expect_text_list:
                    self.assertIn(expect_text, str(e.exception).lower(),
                                  "Expected '{}' at exception text".format(expect_text))

    def test_check_ns_operation_action(self):
        nsrs = self.db.get_list("nsrs")[0]
        session = {}

        indata = {
            "member_vnf_index": "1",
            "vdu_id": None,
            "primitive": "touch",
            "primitive_params": {"filename": "file"}
        }

        self.nslcmop_topic._check_ns_operation(session, nsrs, "action", indata)
        for k in indata:
            indata_copy = indata.copy()
            if k == "primitive_params":
                continue
            indata_copy[k] = "non_existing"
            with self.assertRaises(EngineException) as exc_manager:
                self.nslcmop_topic._check_ns_operation(session, nsrs, "action", indata_copy)
            exc = exc_manager.exception
            self.assertEqual(exc.http_code, HTTPStatus.BAD_REQUEST, "Engine exception bad http_code with {}".
                             format(indata_copy))


class TestNsrTopic(unittest.TestCase):

    def setUp(self):
        self.db = DbMemory()
        self.fs = Mock(FsBase())
        self.fs.get_params.return_value = {"./fake/folder"}
        self.fs.file_open = mock_open()
        self.msg = Mock(MsgBase())
        # create class
        self.nsr_topic = NsrTopic(self.db, self.fs, self.msg, None)
        self.nsr_topic.check_quota = Mock(return_value=None)  # skip quota

        self.db.create_list("vim_accounts", yaml.load(db_vim_accounts_text, Loader=yaml.Loader))
        self.db.create_list("nsds", yaml.load(db_nsds_text, Loader=yaml.Loader))
        self.db.create_list("vnfds", yaml.load(db_vnfds_text, Loader=yaml.Loader))
        self.db.create = Mock(return_value="created_id")
        self.nsd = self.db.get_list("nsds")[0]
        self.nsd_id = self.nsd["_id"]
        self.nsd_project = self.nsd["_admin"]["projects_read"][0]

        self.vim = self.db.get_list("vim_accounts")[0]
        self.vim_id = self.vim["_id"]

    def test_create(self):
        session = {"force": False, "admin": False, "public": False, "project_id": [self.nsd_project], "method": "write"}
        indata = {
            "nsdId": self.nsd_id,
            "nsName": "name",
            "vimAccountId": self.vim_id,
            "additionalParamsForVnf": [{"member-vnf-index": "1", "additionalParams": {"touch_filename": "file"}},
                                       {"member-vnf-index": "2", "additionalParams": {"touch_filename": "file"}}]
        }
        rollback = []
        headers = {}

        self.nsr_topic.new(rollback, session, indata=indata, kwargs=None, headers=headers)

        # check vnfrs and nsrs created in whatever order
        created_vnfrs = []
        created_nsrs = []
        nsr_id = None
        for _call in self.db.create.call_args_list:
            assert len(_call[0]) >= 2, "called db.create with few parameters"
            created_item = _call[0][1]
            if _call[0][0] == "vnfrs":
                created_vnfrs.append(created_item)
                self.assertIn("member-vnf-index-ref", created_item,
                              "Created item must contain member-vnf-index-ref section")
                if nsr_id:
                    self.assertEqual(nsr_id, created_item["nsr-id-ref"], "bad reference id from vnfr to nsr")
                else:
                    nsr_id = created_item["nsr-id-ref"]

            elif _call[0][0] == "nsrs":
                created_nsrs.append(created_item)
                if nsr_id:
                    self.assertEqual(nsr_id, created_item["_id"], "bad reference id from vnfr to nsr")
                else:
                    nsr_id = created_item["_id"]
            else:
                assert True, "created an unknown record {} at database".format(_call[0][0])

            self.assertTrue(created_item["_admin"].get("projects_read"),
                            "Database record must contain '_amdin.projects_read'")
            self.assertIn("created", created_item["_admin"], "Database record must contain '_admin.created'")
            self.assertTrue(created_item["_admin"]["nsState"] == "NOT_INSTANTIATED",
                            "Database record must contain '_admin.nstate=NOT INSTANTIATE'")

        self.assertEqual(len(created_vnfrs), len(self.nsd["constituent-vnfd"]),
                         "created a mismatch number of vnfr at database")
        self.assertEqual(len(created_nsrs), 1, "Only one nsrs must be created at database")
        self.assertEqual(len(rollback), len(created_vnfrs) + 1, "rollback mismatch with created items at database")

        # test parameters with error
        bad_id = "88d90b0c-faff-4b9f-bccd-aaaaaaaaaaaa"
        test_set = (
            # TODO add "nsd"
            ("nsd not found", {"nsdId": bad_id}, DbException, HTTPStatus.NOT_FOUND, ("not found", bad_id)),
            # ({"vimAccountId": bad_id}, DbException, HTTPStatus.NOT_FOUND, ("not found", bad_id)),  # TODO add "vim"
            ("additional params not supply", {"additionalParamsForVnf.0.member-vnf-index": "k"}, EngineException,
             HTTPStatus.BAD_REQUEST, None),
        )
        for message, kwargs_, expect_exc, expect_code, expect_text_list in test_set:
            with self.assertRaises(expect_exc, msg=message) as e:
                self.nsr_topic.new(rollback, session, indata=deepcopy(indata), kwargs=kwargs_, headers=headers)
            if expect_code:
                self.assertTrue(e.exception.http_code == expect_code)
            if expect_text_list:
                for expect_text in expect_text_list:
                    self.assertIn(expect_text, str(e.exception).lower(),
                                  "Expected '{}' at exception text".format(expect_text))

    def test_delete_ns(self):
        self.db.create_list("nsrs", yaml.load(db_nsrs_text, Loader=yaml.Loader))
        self.nsr = self.db.get_list("nsrs")[0]
        self.nsr_id = self.nsr["_id"]
        self.db_set_one = self.db.set_one
        p_id = self.nsd_project
        p_other = "other_p"

        session = {"force": False, "admin": False, "public": None, "project_id": [p_id], "method": "delete"}
        session2 = {"force": False, "admin": False, "public": None, "project_id": [p_other], "method": "delete"}
        session_force = {"force": True, "admin": True, "public": None, "project_id": [], "method": "delete"}
        with self.subTest(i=1, t='Normal Deletion'):
            self.db.del_one = Mock()
            self.db.set_one = Mock()
            self.nsr_topic.delete(session, self.nsr_id)

            db_args = self.db.del_one.call_args[0]
            msg_args = self.msg.write.call_args[0]
            self.assertEqual(msg_args[0], self.nsr_topic.topic_msg, "Wrong message topic")
            self.assertEqual(msg_args[1], "deleted", "Wrong message action")
            self.assertEqual(msg_args[2], {"_id": self.nsr_id}, "Wrong message content")
            self.assertEqual(db_args[0], self.nsr_topic.topic, "Wrong DB topic")
            self.assertEqual(db_args[1]["_id"], self.nsr_id, "Wrong DB ID")
            self.assertEqual(db_args[1]["_admin.projects_read.cont"], [p_id], "Wrong DB filter")
            self.db.set_one.assert_not_called()
            fs_del_calls = self.fs.file_delete.call_args_list
            self.assertEqual(fs_del_calls[0][0][0], self.nsr_id, "Wrong FS file id")
        with self.subTest(i=2, t='No delete because referenced by other project'):
            self.db_set_one("nsrs", {"_id": self.nsr_id}, update_dict=None, push={"_admin.projects_read": p_other,
                                                                                  "_admin.projects_write": p_other})
            self.db.del_one.reset_mock()
            self.db.set_one.reset_mock()
            self.msg.write.reset_mock()
            self.fs.file_delete.reset_mock()

            self.nsr_topic.delete(session2, self.nsr_id)
            self.db.del_one.assert_not_called()
            self.msg.write.assert_not_called()
            db_s1_args = self.db.set_one.call_args
            self.assertEqual(db_s1_args[0][0], self.nsr_topic.topic, "Wrong DB topic")
            self.assertEqual(db_s1_args[0][1]["_id"], self.nsr_id, "Wrong DB ID")
            self.assertIsNone(db_s1_args[1]["update_dict"], "Wrong DB update dictionary")
            self.assertEqual(db_s1_args[1]["pull_list"],
                             {"_admin.projects_read": [p_other], "_admin.projects_write": [p_other]},
                             "Wrong DB pull_list dictionary")
            self.fs.file_delete.assert_not_called()
        with self.subTest(i=4, t='Delete with force and admin'):
            self.db.del_one.reset_mock()
            self.db.set_one.reset_mock()
            self.msg.write.reset_mock()
            self.fs.file_delete.reset_mock()
            self.nsr_topic.delete(session_force, self.nsr_id)

            db_args = self.db.del_one.call_args[0]
            msg_args = self.msg.write.call_args[0]
            self.assertEqual(msg_args[0], self.nsr_topic.topic_msg, "Wrong message topic")
            self.assertEqual(msg_args[1], "deleted", "Wrong message action")
            self.assertEqual(msg_args[2], {"_id": self.nsr_id}, "Wrong message content")
            self.assertEqual(db_args[0], self.nsr_topic.topic, "Wrong DB topic")
            self.assertEqual(db_args[1]["_id"], self.nsr_id, "Wrong DB ID")
            self.db.set_one.assert_not_called()
            fs_del_calls = self.fs.file_delete.call_args_list
            self.assertEqual(fs_del_calls[0][0][0], self.nsr_id, "Wrong FS file id")
        with self.subTest(i=3, t='Conflict on Delete - NS in INSTANTIATED state'):
            self.db_set_one("nsrs", {"_id": self.nsr_id}, {"_admin.nsState": "INSTANTIATED"},
                            pull={"_admin.projects_read": p_other, "_admin.projects_write": p_other})
            self.db.del_one.reset_mock()
            self.db.set_one.reset_mock()
            self.msg.write.reset_mock()
            self.fs.file_delete.reset_mock()

            with self.assertRaises(EngineException, msg="Accepted NSR with nsState INSTANTIATED") as e:
                self.nsr_topic.delete(session, self.nsr_id)
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("INSTANTIATED", str(e.exception), "Wrong exception text")
        # TODOD with self.subTest(i=3, t='Conflict on Delete - NS in use by NSI'):

        with self.subTest(i=4, t='Non-existent NS'):
            self.db.del_one.reset_mock()
            self.db.set_one.reset_mock()
            self.msg.write.reset_mock()
            self.fs.file_delete.reset_mock()
            excp_msg = "Not found"
            with self.assertRaises(DbException, msg="Accepted non-existent NSD ID") as e:
                self.nsr_topic.delete(session2, "other_id")
            self.assertEqual(e.exception.http_code, HTTPStatus.NOT_FOUND, "Wrong HTTP status code")
            self.assertIn(excp_msg, str(e.exception), "Wrong exception text")
            self.assertIn("other_id", str(e.exception), "Wrong exception text")
        return
