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
__date__ = "$2019-10-019"

import unittest
from unittest import TestCase
from unittest.mock import Mock
from uuid import uuid4
from http import HTTPStatus
from time import time
from random import randint
from osm_common import dbbase, fsbase, msgbase
from osm_nbi import authconn, validation
from osm_nbi.admin_topics import ProjectTopicAuth, RoleTopicAuth, UserTopicAuth, CommonVimWimSdn
from osm_nbi.engine import EngineException
from osm_nbi.authconn import AuthconnNotFoundException


test_pid = str(uuid4())
test_name = "test-user"


def norm(str):
    """Normalize string for checking"""
    return ' '.join(str.strip().split()).lower()


class Test_ProjectTopicAuth(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_name = "test-project-topic"

    def setUp(self):
        self.db = Mock(dbbase.DbBase())
        self.fs = Mock(fsbase.FsBase())
        self.msg = Mock(msgbase.MsgBase())
        self.auth = Mock(authconn.Authconn(None, None, None))
        self.topic = ProjectTopicAuth(self.db, self.fs, self.msg, self.auth)
        self.fake_session = {"username": self.test_name, "project_id": (test_pid,), "method": None,
                             "admin": True, "force": False, "public": False, "allow_show_user_project_role": True}

    def test_new_project(self):
        with self.subTest(i=1):
            rollback = []
            pid1 = str(uuid4())
            self.auth.get_project_list.return_value = []
            self.auth.create_project.return_value = pid1
            pid2, oid = self.topic.new(rollback, self.fake_session, {"name": self.test_name, "quotas": {}})
            self.assertEqual(len(rollback), 1, "Wrong rollback length")
            self.assertEqual(pid2, pid1, "Wrong project identifier")
            content = self.auth.create_project.call_args[0][0]
            self.assertEqual(content["name"], self.test_name, "Wrong project name")
            self.assertEqual(content["quotas"], {}, "Wrong quotas")
            self.assertIsNotNone(content["_admin"]["created"], "Wrong creation time")
            self.assertEqual(content["_admin"]["modified"], content["_admin"]["created"], "Wrong modification time")
        with self.subTest(i=2):
            rollback = []
            with self.assertRaises(EngineException, msg="Accepted wrong quotas") as e:
                self.topic.new(rollback, self.fake_session, {"name": "other-project-name", "quotas": {"baditems": 10}})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("format error at 'quotas' 'additional properties are not allowed ('{}' was unexpected)'"
                          .format("baditems"), norm(str(e.exception)), "Wrong exception text")

    def test_edit_project(self):
        now = time()
        pid = str(uuid4())
        proj = {"_id": pid, "name": self.test_name, "_admin": {"created": now, "modified": now}}
        with self.subTest(i=1):
            self.auth.get_project_list.side_effect = [[proj], []]
            new_name = "new-project-name"
            quotas = {"vnfds": randint(0, 100), "nsds": randint(0, 100)}
            self.topic.edit(self.fake_session, pid, {"name": new_name, "quotas": quotas})
            _id, content = self.auth.update_project.call_args[0]
            self.assertEqual(_id, pid, "Wrong project identifier")
            self.assertEqual(content["_id"], pid, "Wrong project identifier")
            self.assertEqual(content["_admin"]["created"], now, "Wrong creation time")
            self.assertGreater(content["_admin"]["modified"], now, "Wrong modification time")
            self.assertEqual(content["name"], new_name, "Wrong project name")
            self.assertEqual(content["quotas"], quotas, "Wrong quotas")
        with self.subTest(i=2):
            new_name = "other-project-name"
            quotas = {"baditems": randint(0, 100)}
            self.auth.get_project_list.side_effect = [[proj], []]
            with self.assertRaises(EngineException, msg="Accepted wrong quotas") as e:
                self.topic.edit(self.fake_session, pid, {"name": new_name, "quotas": quotas})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("format error at 'quotas' 'additional properties are not allowed ('{}' was unexpected)'"
                          .format("baditems"), norm(str(e.exception)), "Wrong exception text")

    def test_conflict_on_new(self):
        with self.subTest(i=1):
            rollback = []
            pid = str(uuid4())
            with self.assertRaises(EngineException, msg="Accepted uuid as project name") as e:
                self.topic.new(rollback, self.fake_session, {"name": pid})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("project name '{}' cannot have an uuid format".format(pid),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=2):
            rollback = []
            self.auth.get_project_list.return_value = [{"_id": test_pid, "name": self.test_name}]
            with self.assertRaises(EngineException, msg="Accepted existing project name") as e:
                self.topic.new(rollback, self.fake_session, {"name": self.test_name})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("project '{}' exists".format(self.test_name),
                          norm(str(e.exception)), "Wrong exception text")

    def test_conflict_on_edit(self):
        with self.subTest(i=1):
            self.auth.get_project_list.return_value = [{"_id": test_pid, "name": self.test_name}]
            new_name = str(uuid4())
            with self.assertRaises(EngineException, msg="Accepted uuid as project name") as e:
                self.topic.edit(self.fake_session, test_pid, {"name": new_name})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("project name '{}' cannot have an uuid format".format(new_name),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=2):
            pid = str(uuid4())
            self.auth.get_project_list.return_value = [{"_id": pid, "name": "admin"}]
            with self.assertRaises(EngineException, msg="Accepted renaming of project 'admin'") as e:
                self.topic.edit(self.fake_session, pid, {"name": "new-name"})
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("you cannot rename project 'admin'",
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=3):
            new_name = "new-project-name"
            self.auth.get_project_list.side_effect = [[{"_id": test_pid, "name": self.test_name}],
                                                      [{"_id": str(uuid4()), "name": new_name}]]
            with self.assertRaises(EngineException, msg="Accepted existing project name") as e:
                self.topic.edit(self.fake_session, pid, {"name": new_name})
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("project '{}' is already used".format(new_name),
                          norm(str(e.exception)), "Wrong exception text")

    def test_delete_project(self):
        with self.subTest(i=1):
            pid = str(uuid4())
            self.auth.get_project.return_value = {"_id": pid, "name": "other-project-name"}
            self.auth.delete_project.return_value = {"deleted": 1}
            self.auth.get_user_list.return_value = []
            self.db.get_list.return_value = []
            rc = self.topic.delete(self.fake_session, pid)
            self.assertEqual(rc, {"deleted": 1}, "Wrong project deletion return info")
            self.assertEqual(self.auth.get_project.call_args[0][0], pid, "Wrong project identifier")
            self.assertEqual(self.auth.delete_project.call_args[0][0], pid, "Wrong project identifier")

    def test_conflict_on_del(self):
        with self.subTest(i=1):
            self.auth.get_project.return_value = {"_id": test_pid, "name": self.test_name}
            with self.assertRaises(EngineException, msg="Accepted deletion of own project") as e:
                self.topic.delete(self.fake_session, self.test_name)
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("you cannot delete your own project", norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=2):
            self.auth.get_project.return_value = {"_id": str(uuid4()), "name": "admin"}
            with self.assertRaises(EngineException, msg="Accepted deletion of project 'admin'") as e:
                self.topic.delete(self.fake_session, "admin")
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("you cannot delete project 'admin'", norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=3):
            pid = str(uuid4())
            name = "other-project-name"
            self.auth.get_project.return_value = {"_id": pid, "name": name}
            self.auth.get_user_list.return_value = [{"_id": str(uuid4()), "username": self.test_name,
                                                     "project_role_mappings": [{"project": pid, "role": str(uuid4())}]}]
            with self.assertRaises(EngineException, msg="Accepted deletion of used project") as e:
                self.topic.delete(self.fake_session, pid)
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("project '{}' ({}) is being used by user '{}'".format(name, pid, self.test_name),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=4):
            self.auth.get_user_list.return_value = []
            self.db.get_list.return_value = [{"_id": str(uuid4()), "id": self.test_name,
                                              "_admin": {"projects_read": [pid], "projects_write": []}}]
            with self.assertRaises(EngineException, msg="Accepted deletion of used project") as e:
                self.topic.delete(self.fake_session, pid)
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("project '{}' ({}) is being used by {} '{}'"
                          .format(name, pid, "vnf descriptor", self.test_name),
                          norm(str(e.exception)), "Wrong exception text")


class Test_RoleTopicAuth(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_name = "test-role-topic"
        cls.test_operations = ["tokens:get"]

    def setUp(self):
        self.db = Mock(dbbase.DbBase())
        self.fs = Mock(fsbase.FsBase())
        self.msg = Mock(msgbase.MsgBase())
        self.auth = Mock(authconn.Authconn(None, None, None))
        self.auth.role_permissions = self.test_operations
        self.topic = RoleTopicAuth(self.db, self.fs, self.msg, self.auth)
        self.fake_session = {"username": test_name, "project_id": (test_pid,), "method": None,
                             "admin": True, "force": False, "public": False, "allow_show_user_project_role": True}

    def test_new_role(self):
        with self.subTest(i=1):
            rollback = []
            rid1 = str(uuid4())
            perms_in = {"tokens": True}
            perms_out = {"default": False, "admin": False, "tokens": True}
            self.auth.get_role_list.return_value = []
            self.auth.create_role.return_value = rid1
            rid2, oid = self.topic.new(rollback, self.fake_session, {"name": self.test_name, "permissions": perms_in})
            self.assertEqual(len(rollback), 1, "Wrong rollback length")
            self.assertEqual(rid2, rid1, "Wrong project identifier")
            content = self.auth.create_role.call_args[0][0]
            self.assertEqual(content["name"], self.test_name, "Wrong role name")
            self.assertEqual(content["permissions"], perms_out, "Wrong permissions")
            self.assertIsNotNone(content["_admin"]["created"], "Wrong creation time")
            self.assertEqual(content["_admin"]["modified"], content["_admin"]["created"], "Wrong modification time")
        with self.subTest(i=2):
            rollback = []
            with self.assertRaises(EngineException, msg="Accepted wrong permissions") as e:
                self.topic.new(rollback, self.fake_session,
                               {"name": "other-role-name", "permissions": {"projects": True}})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("invalid permission '{}'".format("projects"),
                          norm(str(e.exception)), "Wrong exception text")

    def test_edit_role(self):
        now = time()
        rid = str(uuid4())
        role = {"_id": rid, "name": self.test_name, "permissions": {"tokens": True},
                "_admin": {"created": now, "modified": now}}
        with self.subTest(i=1):
            self.auth.get_role_list.side_effect = [[role], []]
            self.auth.get_role.return_value = role
            new_name = "new-role-name"
            perms_in = {"tokens": False, "tokens:get": True}
            perms_out = {"default": False, "admin": False, "tokens": False, "tokens:get": True}
            self.topic.edit(self.fake_session, rid, {"name": new_name, "permissions": perms_in})
            content = self.auth.update_role.call_args[0][0]
            self.assertEqual(content["_id"], rid, "Wrong role identifier")
            self.assertEqual(content["_admin"]["created"], now, "Wrong creation time")
            self.assertGreater(content["_admin"]["modified"], now, "Wrong modification time")
            self.assertEqual(content["name"], new_name, "Wrong role name")
            self.assertEqual(content["permissions"], perms_out, "Wrong permissions")
        with self.subTest(i=2):
            new_name = "other-role-name"
            perms_in = {"tokens": False, "tokens:post": True}
            self.auth.get_role_list.side_effect = [[role], []]
            with self.assertRaises(EngineException, msg="Accepted wrong permissions") as e:
                self.topic.edit(self.fake_session, rid, {"name": new_name, "permissions": perms_in})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("invalid permission '{}'".format("tokens:post"),
                          norm(str(e.exception)), "Wrong exception text")

    def test_delete_role(self):
        with self.subTest(i=1):
            rid = str(uuid4())
            role = {"_id": rid, "name": "other-role-name"}
            self.auth.get_role_list.return_value = [role]
            self.auth.get_role.return_value = role
            self.auth.delete_role.return_value = {"deleted": 1}
            self.auth.get_user_list.return_value = []
            rc = self.topic.delete(self.fake_session, rid)
            self.assertEqual(rc, {"deleted": 1}, "Wrong role deletion return info")
            self.assertEqual(self.auth.get_role_list.call_args[0][0]["_id"], rid, "Wrong role identifier")
            self.assertEqual(self.auth.get_role.call_args[0][0], rid, "Wrong role identifier")
            self.assertEqual(self.auth.delete_role.call_args[0][0], rid, "Wrong role identifier")

    def test_conflict_on_new(self):
        with self.subTest(i=1):
            rollback = []
            rid = str(uuid4())
            with self.assertRaises(EngineException, msg="Accepted uuid as role name") as e:
                self.topic.new(rollback, self.fake_session, {"name": rid})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("role name '{}' cannot have an uuid format".format(rid),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=2):
            rollback = []
            self.auth.get_role_list.return_value = [{"_id": str(uuid4()), "name": self.test_name}]
            with self.assertRaises(EngineException, msg="Accepted existing role name") as e:
                self.topic.new(rollback, self.fake_session, {"name": self.test_name})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("role name '{}' exists".format(self.test_name),
                          norm(str(e.exception)), "Wrong exception text")

    def test_conflict_on_edit(self):
        rid = str(uuid4())
        with self.subTest(i=1):
            self.auth.get_role_list.return_value = [{"_id": rid, "name": self.test_name, "permissions": {}}]
            new_name = str(uuid4())
            with self.assertRaises(EngineException, msg="Accepted uuid as role name") as e:
                self.topic.edit(self.fake_session, rid, {"name": new_name})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("role name '{}' cannot have an uuid format".format(new_name),
                          norm(str(e.exception)), "Wrong exception text")
        for i, role_name in enumerate(["system_admin", "project_admin"], start=2):
            with self.subTest(i=i):
                rid = str(uuid4())
                self.auth.get_role.return_value = {"_id": rid, "name": role_name, "permissions": {}}
                with self.assertRaises(EngineException, msg="Accepted renaming of role '{}'".format(role_name)) as e:
                    self.topic.edit(self.fake_session, rid, {"name": "new-name"})
                self.assertEqual(e.exception.http_code, HTTPStatus.FORBIDDEN, "Wrong HTTP status code")
                self.assertIn("you cannot rename role '{}'".format(role_name),
                              norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=i+1):
            new_name = "new-role-name"
            self.auth.get_role_list.side_effect = [[{"_id": rid, "name": self.test_name, "permissions": {}}],
                                                   [{"_id": str(uuid4()), "name": new_name, "permissions": {}}]]
            self.auth.get_role.return_value = {"_id": rid, "name": self.test_name, "permissions": {}}
            with self.assertRaises(EngineException, msg="Accepted existing role name") as e:
                self.topic.edit(self.fake_session, rid, {"name": new_name})
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("role name '{}' exists".format(new_name),
                          norm(str(e.exception)), "Wrong exception text")

    def test_conflict_on_del(self):
        for i, role_name in enumerate(["system_admin", "project_admin"], start=1):
            with self.subTest(i=i):
                rid = str(uuid4())
                role = {"_id": rid, "name": role_name}
                self.auth.get_role_list.return_value = [role]
                self.auth.get_role.return_value = role
                with self.assertRaises(EngineException, msg="Accepted deletion of role '{}'".format(role_name)) as e:
                    self.topic.delete(self.fake_session, rid)
                self.assertEqual(e.exception.http_code, HTTPStatus.FORBIDDEN, "Wrong HTTP status code")
                self.assertIn("you cannot delete role '{}'".format(role_name),
                              norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=i+1):
            rid = str(uuid4())
            name = "other-role-name"
            role = {"_id": rid, "name": name}
            self.auth.get_role_list.return_value = [role]
            self.auth.get_role.return_value = role
            self.auth.get_user_list.return_value = [{"_id": str(uuid4()), "username": self.test_name,
                                                     "project_role_mappings": [{"project": str(uuid4()), "role": rid}]}]
            with self.assertRaises(EngineException, msg="Accepted deletion of used role") as e:
                self.topic.delete(self.fake_session, rid)
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("role '{}' ({}) is being used by user '{}'".format(name, rid, self.test_name),
                          norm(str(e.exception)), "Wrong exception text")


class Test_UserTopicAuth(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_name = "test-user-topic"

    def setUp(self):
        self.db = Mock(dbbase.DbBase())
        self.fs = Mock(fsbase.FsBase())
        self.msg = Mock(msgbase.MsgBase())
        self.auth = Mock(authconn.Authconn(None, None, None))
        self.topic = UserTopicAuth(self.db, self.fs, self.msg, self.auth)
        self.fake_session = {"username": test_name, "project_id": (test_pid,), "method": None,
                             "admin": True, "force": False, "public": False, "allow_show_user_project_role": True}

    def test_new_user(self):
        uid1 = str(uuid4())
        pid = str(uuid4())
        self.auth.get_user_list.return_value = []
        self.auth.get_project.return_value = {"_id": pid, "name": "some_project"}
        self.auth.create_user.return_value = {"_id": uid1, "username": self.test_name}
        with self.subTest(i=1):
            rollback = []
            rid = str(uuid4())
            self.auth.get_role.return_value = {"_id": rid, "name": "some_role"}
            prms_in = [{"project": "some_project", "role": "some_role"}]
            prms_out = [{"project": pid, "role": rid}]
            uid2, oid = self.topic.new(rollback, self.fake_session, {"username": self.test_name,
                                                                     "password": self.test_name,
                                                                     "project_role_mappings": prms_in
                                                                     })
            self.assertEqual(len(rollback), 1, "Wrong rollback length")
            self.assertEqual(uid2, uid1, "Wrong project identifier")
            content = self.auth.create_user.call_args[0][0]
            self.assertEqual(content["username"], self.test_name, "Wrong project name")
            self.assertEqual(content["password"], self.test_name, "Wrong password")
            self.assertEqual(content["project_role_mappings"], prms_out, "Wrong project-role mappings")
            self.assertIsNotNone(content["_admin"]["created"], "Wrong creation time")
            self.assertEqual(content["_admin"]["modified"], content["_admin"]["created"], "Wrong modification time")
        with self.subTest(i=2):
            rollback = []
            def_rid = str(uuid4())
            def_role = {"_id": def_rid, "name": "project_admin"}
            self.auth.get_role.return_value = def_role
            self.auth.get_role_list.return_value = [def_role]
            prms_out = [{"project": pid, "role": def_rid}]
            uid2, oid = self.topic.new(rollback, self.fake_session, {"username": self.test_name,
                                                                     "password": self.test_name,
                                                                     "projects": ["some_project"]
                                                                     })
            self.assertEqual(len(rollback), 1, "Wrong rollback length")
            self.assertEqual(uid2, uid1, "Wrong project identifier")
            content = self.auth.create_user.call_args[0][0]
            self.assertEqual(content["username"], self.test_name, "Wrong project name")
            self.assertEqual(content["password"], self.test_name, "Wrong password")
            self.assertEqual(content["project_role_mappings"], prms_out, "Wrong project-role mappings")
            self.assertIsNotNone(content["_admin"]["created"], "Wrong creation time")
            self.assertEqual(content["_admin"]["modified"], content["_admin"]["created"], "Wrong modification time")
        with self.subTest(i=3):
            rollback = []
            with self.assertRaises(EngineException, msg="Accepted wrong project-role mappings") as e:
                self.topic.new(rollback, self.fake_session, {"username": "other-project-name",
                                                             "password": "other-password",
                                                             "project_role_mappings": [{}]
                                                             })
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("format error at '{}' '{}'"
                          .format("project_role_mappings:{}", "'{}' is a required property").format(0, "project"),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=4):
            rollback = []
            with self.assertRaises(EngineException, msg="Accepted wrong projects") as e:
                self.topic.new(rollback, self.fake_session, {"username": "other-project-name",
                                                             "password": "other-password",
                                                             "projects": []
                                                             })
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("format error at '{}' '{}'" .format("projects", "{} is too short").format([]),
                          norm(str(e.exception)), "Wrong exception text")

    def test_edit_user(self):
        now = time()
        uid = str(uuid4())
        pid1 = str(uuid4())
        rid1 = str(uuid4())
        prms = [{"project": pid1, "project_name": "project-1", "role": rid1, "role_name": "role-1"}]
        user = {"_id": uid, "username": self.test_name, "project_role_mappings": prms,
                "_admin": {"created": now, "modified": now}}
        with self.subTest(i=1):
            self.auth.get_user_list.side_effect = [[user], []]
            self.auth.get_user.return_value = user
            pid2 = str(uuid4())
            rid2 = str(uuid4())
            self.auth.get_project.side_effect = [{"_id": pid2, "name": "project-2"},
                                                 {"_id": pid1, "name": "project-1"}]
            self.auth.get_role.side_effect = [{"_id": rid2, "name": "role-2"},
                                              {"_id": rid1, "name": "role-1"}]
            new_name = "new-user-name"
            new_pasw = "new-password"
            add_prms = [{"project": pid2, "role": rid2}]
            rem_prms = [{"project": pid1, "role": rid1}]
            self.topic.edit(self.fake_session, uid, {"username": new_name, "password": new_pasw,
                                                     "add_project_role_mappings": add_prms,
                                                     "remove_project_role_mappings": rem_prms
                                                     })
            content = self.auth.update_user.call_args[0][0]
            self.assertEqual(content["_id"], uid, "Wrong user identifier")
            self.assertEqual(content["username"], new_name, "Wrong user name")
            self.assertEqual(content["password"], new_pasw, "Wrong user password")
            self.assertEqual(content["add_project_role_mappings"], add_prms, "Wrong project-role mappings to add")
            self.assertEqual(content["remove_project_role_mappings"], prms, "Wrong project-role mappings to remove")
        with self.subTest(i=2):
            new_name = "other-user-name"
            new_prms = [{}]
            self.auth.get_role_list.side_effect = [[user], []]
            with self.assertRaises(EngineException, msg="Accepted wrong project-role mappings") as e:
                self.topic.edit(self.fake_session, uid, {"username": new_name, "project_role_mappings": new_prms})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("format error at '{}' '{}'"
                          .format("project_role_mappings:{}", "'{}' is a required property").format(0, "project"),
                          norm(str(e.exception)), "Wrong exception text")

    def test_delete_user(self):
        with self.subTest(i=1):
            uid = str(uuid4())
            self.fake_session["username"] = self.test_name
            user = user = {"_id": uid, "username": "other-user-name", "project_role_mappings": []}
            self.auth.get_user.return_value = user
            self.auth.delete_user.return_value = {"deleted": 1}
            rc = self.topic.delete(self.fake_session, uid)
            self.assertEqual(rc, {"deleted": 1}, "Wrong user deletion return info")
            self.assertEqual(self.auth.get_user.call_args[0][0], uid, "Wrong user identifier")
            self.assertEqual(self.auth.delete_user.call_args[0][0], uid, "Wrong user identifier")

    def test_conflict_on_new(self):
        with self.subTest(i=1):
            rollback = []
            uid = str(uuid4())
            with self.assertRaises(EngineException, msg="Accepted uuid as username") as e:
                self.topic.new(rollback, self.fake_session, {"username": uid, "password": self.test_name,
                                                             "projects": [test_pid]})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("username '{}' cannot have a uuid format".format(uid),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=2):
            rollback = []
            self.auth.get_user_list.return_value = [{"_id": str(uuid4()), "username": self.test_name}]
            with self.assertRaises(EngineException, msg="Accepted existing username") as e:
                self.topic.new(rollback, self.fake_session, {"username": self.test_name, "password": self.test_name,
                                                             "projects": [test_pid]})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("username '{}' is already used".format(self.test_name),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=3):
            rollback = []
            self.auth.get_user_list.return_value = []
            self.auth.get_role_list.side_effect = [[], []]
            with self.assertRaises(AuthconnNotFoundException, msg="Accepted user without default role") as e:
                self.topic.new(rollback, self.fake_session, {"username": self.test_name, "password": self.test_name,
                                                             "projects": [str(uuid4())]})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.NOT_FOUND, "Wrong HTTP status code")
            self.assertIn("can't find default role for user '{}'".format(self.test_name),
                          norm(str(e.exception)), "Wrong exception text")

    def test_conflict_on_edit(self):
        uid = str(uuid4())
        with self.subTest(i=1):
            self.auth.get_user_list.return_value = [{"_id": uid, "username": self.test_name}]
            new_name = str(uuid4())
            with self.assertRaises(EngineException, msg="Accepted uuid as username") as e:
                self.topic.edit(self.fake_session, uid, {"username": new_name})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("username '{}' cannot have an uuid format".format(new_name),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=2):
            self.auth.get_user_list.return_value = [{"_id": uid, "username": self.test_name}]
            self.auth.get_role_list.side_effect = [[], []]
            with self.assertRaises(AuthconnNotFoundException, msg="Accepted user without default role") as e:
                self.topic.edit(self.fake_session, uid, {"projects": [str(uuid4())]})
            self.assertEqual(e.exception.http_code, HTTPStatus.NOT_FOUND, "Wrong HTTP status code")
            self.assertIn("can't find a default role for user '{}'".format(self.test_name),
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=3):
            admin_uid = str(uuid4())
            self.auth.get_user_list.return_value = [{"_id": admin_uid, "username": "admin"}]
            with self.assertRaises(EngineException, msg="Accepted removing system_admin role from admin user") as e:
                self.topic.edit(self.fake_session, admin_uid,
                                {"remove_project_role_mappings": [{"project": "admin", "role": "system_admin"}]})
            self.assertEqual(e.exception.http_code, HTTPStatus.FORBIDDEN, "Wrong HTTP status code")
            self.assertIn("you cannot remove system_admin role from admin user",
                          norm(str(e.exception)), "Wrong exception text")
        with self.subTest(i=4):
            new_name = "new-user-name"
            self.auth.get_user_list.side_effect = [[{"_id": uid, "name": self.test_name}],
                                                   [{"_id": str(uuid4()), "name": new_name}]]
            with self.assertRaises(EngineException, msg="Accepted existing username") as e:
                self.topic.edit(self.fake_session, uid, {"username": new_name})
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("username '{}' is already used".format(new_name),
                          norm(str(e.exception)), "Wrong exception text")

    def test_conflict_on_del(self):
        with self.subTest(i=1):
            uid = str(uuid4())
            self.fake_session["username"] = self.test_name
            user = user = {"_id": uid, "username": self.test_name, "project_role_mappings": []}
            self.auth.get_user.return_value = user
            with self.assertRaises(EngineException, msg="Accepted deletion of own user") as e:
                self.topic.delete(self.fake_session, uid)
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("you cannot delete your own login user", norm(str(e.exception)), "Wrong exception text")


class Test_CommonVimWimSdn(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_name = "test-cim-topic"   # CIM = Common Infrastructure Manager

    def setUp(self):
        self.db = Mock(dbbase.DbBase())
        self.fs = Mock(fsbase.FsBase())
        self.msg = Mock(msgbase.MsgBase())
        self.auth = Mock(authconn.Authconn(None, None, None))
        self.topic = CommonVimWimSdn(self.db, self.fs, self.msg, self.auth)
        # Use WIM schemas for testing because they are the simplest
        self.topic._send_msg = Mock()
        self.topic.topic = "wims"
        self.topic.schema_new = validation.wim_account_new_schema
        self.topic.schema_edit = validation.wim_account_edit_schema
        self.fake_session = {"username": test_name, "project_id": (test_pid,), "method": None,
                             "admin": True, "force": False, "public": False, "allow_show_user_project_role": True}

    def test_new_cvws(self):
        test_url = "http://0.0.0.0:0"
        with self.subTest(i=1):
            rollback = []
            test_type = "fake"
            self.db.get_one.return_value = None
            self.db.create.side_effect = lambda self, content: content["_id"]
            cid, oid = self.topic.new(rollback, self.fake_session,
                                      {"name": self.test_name, "wim_url": test_url, "wim_type": test_type})
            self.assertEqual(len(rollback), 1, "Wrong rollback length")
            args = self.db.create.call_args[0]
            content = args[1]
            self.assertEqual(args[0], self.topic.topic, "Wrong topic")
            self.assertEqual(content["_id"], cid, "Wrong CIM identifier")
            self.assertEqual(content["name"], self.test_name, "Wrong CIM name")
            self.assertEqual(content["wim_url"], test_url, "Wrong URL")
            self.assertEqual(content["wim_type"], test_type, "Wrong CIM type")
            self.assertEqual(content["schema_version"], "1.11", "Wrong schema version")
            self.assertEqual(content["op_id"], oid, "Wrong operation identifier")
            self.assertIsNotNone(content["_admin"]["created"], "Wrong creation time")
            self.assertEqual(content["_admin"]["modified"], content["_admin"]["created"], "Wrong modification time")
            self.assertEqual(content["_admin"]["operationalState"], "PROCESSING", "Wrong operational state")
            self.assertEqual(content["_admin"]["projects_read"], [test_pid], "Wrong read-only projects")
            self.assertEqual(content["_admin"]["projects_write"], [test_pid], "Wrong read/write projects")
            self.assertIsNone(content["_admin"]["current_operation"], "Wrong current operation")
            self.assertEqual(len(content["_admin"]["operations"]), 1, "Wrong number of operations")
            operation = content["_admin"]["operations"][0]
            self.assertEqual(operation["lcmOperationType"], "create", "Wrong operation type")
            self.assertEqual(operation["operationState"], "PROCESSING", "Wrong operation state")
            self.assertGreater(operation["startTime"], content["_admin"]["created"], "Wrong operation start time")
            self.assertGreater(operation["statusEnteredTime"], content["_admin"]["created"],
                               "Wrong operation status enter time")
            self.assertEqual(operation["detailed-status"], "", "Wrong operation detailed status info")
            self.assertIsNone(operation["operationParams"], "Wrong operation parameters")
        # This test is disabled. From Feature 8030 we admit all WIM/SDN types
        # with self.subTest(i=2):
        #     rollback = []
        #     test_type = "bad_type"
        #     with self.assertRaises(EngineException, msg="Accepted wrong CIM type") as e:
        #         self.topic.new(rollback, self.fake_session,
        #                        {"name": self.test_name, "wim_url": test_url, "wim_type": test_type})
        #     self.assertEqual(len(rollback), 0, "Wrong rollback length")
        #     self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
        #     self.assertIn("format error at '{}' '{}".format("wim_type", "'{}' is not one of {}").format(test_type,""),
        #                   norm(str(e.exception)), "Wrong exception text")

    def test_conflict_on_new(self):
        with self.subTest(i=1):
            rollback = []
            test_url = "http://0.0.0.0:0"
            test_type = "fake"
            self.db.get_one.return_value = {"_id": str(uuid4()), "name": self.test_name}
            with self.assertRaises(EngineException, msg="Accepted existing CIM name") as e:
                self.topic.new(rollback, self.fake_session,
                               {"name": self.test_name, "wim_url": test_url, "wim_type": test_type})
            self.assertEqual(len(rollback), 0, "Wrong rollback length")
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("name '{}' already exists for {}".format(self.test_name, self.topic.topic),
                          norm(str(e.exception)), "Wrong exception text")

    def test_edit_cvws(self):
        now = time()
        cid = str(uuid4())
        test_url = "http://0.0.0.0:0"
        test_type = "fake"
        cvws = {"_id": cid, "name": self.test_name, "wim_url": test_url, "wim_type": test_type,
                "_admin": {"created": now, "modified": now, "operations": [{"lcmOperationType": "create"}]}}
        with self.subTest(i=1):
            new_name = "new-cim-name"
            new_url = "https://1.1.1.1:1"
            new_type = "onos"
            self.db.get_one.side_effect = [cvws, None]
            self.db.replace.return_value = {"updated": 1}
            # self.db.encrypt.side_effect = [b64str(), b64str()]
            self.topic.edit(self.fake_session, cid, {"name": new_name, "wim_url": new_url, "wim_type": new_type})
            args = self.db.replace.call_args[0]
            content = args[2]
            self.assertEqual(args[0], self.topic.topic, "Wrong topic")
            self.assertEqual(args[1], cid, "Wrong CIM identifier")
            self.assertEqual(content["_id"], cid, "Wrong CIM identifier")
            self.assertEqual(content["name"], new_name, "Wrong CIM name")
            self.assertEqual(content["wim_type"], new_type, "Wrong CIM type")
            self.assertEqual(content["wim_url"], new_url, "Wrong URL")
            self.assertEqual(content["_admin"]["created"], now, "Wrong creation time")
            self.assertGreater(content["_admin"]["modified"], content["_admin"]["created"], "Wrong modification time")
            self.assertEqual(len(content["_admin"]["operations"]), 2, "Wrong number of operations")
            operation = content["_admin"]["operations"][1]
            self.assertEqual(operation["lcmOperationType"], "edit", "Wrong operation type")
            self.assertEqual(operation["operationState"], "PROCESSING", "Wrong operation state")
            self.assertGreater(operation["startTime"], content["_admin"]["modified"], "Wrong operation start time")
            self.assertGreater(operation["statusEnteredTime"], content["_admin"]["modified"],
                               "Wrong operation status enter time")
            self.assertEqual(operation["detailed-status"], "", "Wrong operation detailed status info")
            self.assertIsNone(operation["operationParams"], "Wrong operation parameters")
        with self.subTest(i=2):
            with self.assertRaises(EngineException, msg="Accepted wrong property") as e:
                self.topic.edit(self.fake_session, str(uuid4()), {"name": "new-name", "extra_prop": "anything"})
            self.assertEqual(e.exception.http_code, HTTPStatus.UNPROCESSABLE_ENTITY, "Wrong HTTP status code")
            self.assertIn("format error '{}'".format("additional properties are not allowed ('{}' was unexpected)").
                          format("extra_prop"),
                          norm(str(e.exception)), "Wrong exception text")

    def test_conflict_on_edit(self):
        with self.subTest(i=1):
            cid = str(uuid4())
            new_name = "new-cim-name"
            self.db.get_one.side_effect = [{"_id": cid, "name": self.test_name},
                                           {"_id": str(uuid4()), "name": new_name}]
            with self.assertRaises(EngineException, msg="Accepted existing CIM name") as e:
                self.topic.edit(self.fake_session, cid, {"name": new_name})
            self.assertEqual(e.exception.http_code, HTTPStatus.CONFLICT, "Wrong HTTP status code")
            self.assertIn("name '{}' already exists for {}".format(new_name, self.topic.topic),
                          norm(str(e.exception)), "Wrong exception text")

    def test_delete_cvws(self):
        cid = str(uuid4())
        ro_pid = str(uuid4())
        rw_pid = str(uuid4())
        cvws = {"_id": cid, "name": self.test_name}
        self.db.get_list.return_value = []
        with self.subTest(i=1):
            cvws["_admin"] = {"projects_read": [test_pid, ro_pid, rw_pid], "projects_write": [test_pid, rw_pid]}
            self.db.get_one.return_value = cvws
            oid = self.topic.delete(self.fake_session, cid)
            self.assertIsNone(oid, "Wrong operation identifier")
            self.assertEqual(self.db.get_one.call_args[0][0], self.topic.topic, "Wrong topic")
            self.assertEqual(self.db.get_one.call_args[0][1]["_id"], cid, "Wrong CIM identifier")
            self.assertEqual(self.db.set_one.call_args[0][0], self.topic.topic, "Wrong topic")
            self.assertEqual(self.db.set_one.call_args[0][1]["_id"], cid, "Wrong CIM identifier")
            self.assertEqual(self.db.set_one.call_args[1]["update_dict"], None,
                             "Wrong read-only projects update")
            self.assertEqual(self.db.set_one.call_args[1]["pull"], {"_admin.projects_read." + test_pid: None,
                                                                    "_admin.projects_write." + test_pid: None},
                             "Wrong read/write projects update")
            self.topic._send_msg.assert_not_called()
        with self.subTest(i=2):
            now = time()
            cvws["_admin"] = {"projects_read": [test_pid], "projects_write": [test_pid], "operations": []}
            self.db.get_one.return_value = cvws
            oid = self.topic.delete(self.fake_session, cid)
            self.assertEqual(oid, cid+":0", "Wrong operation identifier")
            self.assertEqual(self.db.get_one.call_args[0][0], self.topic.topic, "Wrong topic")
            self.assertEqual(self.db.get_one.call_args[0][1]["_id"], cid, "Wrong CIM identifier")
            self.assertEqual(self.db.set_one.call_args[0][0], self.topic.topic, "Wrong topic")
            self.assertEqual(self.db.set_one.call_args[0][1]["_id"], cid, "Wrong user identifier")
            self.assertEqual(self.db.set_one.call_args[1]["update_dict"], {"_admin.to_delete": True},
                             "Wrong _admin.to_delete update")
            operation = self.db.set_one.call_args[1]["push"]["_admin.operations"]
            self.assertEqual(operation["lcmOperationType"], "delete", "Wrong operation type")
            self.assertEqual(operation["operationState"], "PROCESSING", "Wrong operation state")
            self.assertEqual(operation["detailed-status"], "", "Wrong operation detailed status")
            self.assertIsNone(operation["operationParams"], "Wrong operation parameters")
            self.assertGreater(operation["startTime"], now, "Wrong operation start time")
            self.assertGreater(operation["statusEnteredTime"], now, "Wrong operation status enter time")
            self.topic._send_msg.assert_called_once_with("delete", {"_id": cid, "op_id": cid + ":0"}, not_send_msg=None)
        with self.subTest(i=3):
            cvws["_admin"] = {"projects_read": [], "projects_write": [], "operations": []}
            self.db.get_one.return_value = cvws
            self.topic._send_msg.reset_mock()
            self.db.get_one.reset_mock()
            self.db.del_one.reset_mock()
            self.fake_session["force"] = True   # to force deletion
            self.fake_session["admin"] = True   # to force deletion
            self.fake_session["project_id"] = []   # to force deletion
            oid = self.topic.delete(self.fake_session, cid)
            self.assertIsNone(oid, "Wrong operation identifier")
            self.assertEqual(self.db.get_one.call_args[0][0], self.topic.topic, "Wrong topic")
            self.assertEqual(self.db.get_one.call_args[0][1]["_id"], cid, "Wrong CIM identifier")
            self.assertEqual(self.db.del_one.call_args[0][0], self.topic.topic, "Wrong topic")
            self.assertEqual(self.db.del_one.call_args[0][1]["_id"], cid, "Wrong CIM identifier")
            self.topic._send_msg.assert_called_once_with("deleted", {"_id": cid, "op_id": None}, not_send_msg=None)


if __name__ == '__main__':
    unittest.main()
