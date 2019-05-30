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

# import logging
from uuid import uuid4
from hashlib import sha256
from http import HTTPStatus
from time import time
from validation import user_new_schema, user_edit_schema, project_new_schema, project_edit_schema
from validation import vim_account_new_schema, vim_account_edit_schema, sdn_new_schema, sdn_edit_schema
from validation import wim_account_new_schema, wim_account_edit_schema, roles_new_schema, roles_edit_schema
from validation import validate_input
from validation import ValidationError
from validation import is_valid_uuid    # To check that User/Project Names don't look like UUIDs
from base_topic import BaseTopic, EngineException

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class UserTopic(BaseTopic):
    topic = "users"
    topic_msg = "users"
    schema_new = user_new_schema
    schema_edit = user_edit_schema
    multiproject = False

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    @staticmethod
    def _get_project_filter(session):
        """
        Generates a filter dictionary for querying database users.
        Current policy is admin can show all, non admin, only its own user.
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :return:
        """
        if session["admin"]:  # allows all
            return {}
        else:
            return {"username": session["username"]}

    def check_conflict_on_new(self, session, indata):
        # check username not exists
        if self.db.get_one(self.topic, {"username": indata.get("username")}, fail_on_empty=False, fail_on_more=False):
            raise EngineException("username '{}' exists".format(indata["username"]), HTTPStatus.CONFLICT)
        # check projects
        if not session["force"]:
            for p in indata.get("projects"):
                # To allow project addressing by Name as well as ID
                if not self.db.get_one("projects", {BaseTopic.id_field("projects", p): p}, fail_on_empty=False,
                                       fail_on_more=False):
                    raise EngineException("project '{}' does not exist".format(p), HTTPStatus.CONFLICT)

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check if deletion can be done because of dependencies if it is not force. To override
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: internal _id
        :param db_content: The database content of this item _id
        :return: None if ok or raises EngineException with the conflict
        """
        if _id == session["username"]:
            raise EngineException("You cannot delete your own user", http_code=HTTPStatus.CONFLICT)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, make_public=False)
        # Removed so that the UUID is kept, to allow User Name modification
        # content["_id"] = content["username"]
        salt = uuid4().hex
        content["_admin"]["salt"] = salt
        if content.get("password"):
            content["password"] = sha256(content["password"].encode('utf-8') + salt.encode('utf-8')).hexdigest()
        if content.get("project_role_mappings"):
            projects = [mapping[0] for mapping in content["project_role_mappings"]]

            if content.get("projects"):
                content["projects"] += projects
            else:
                content["projects"] = projects

    @staticmethod
    def format_on_edit(final_content, edit_content):
        BaseTopic.format_on_edit(final_content, edit_content)
        if edit_content.get("password"):
            salt = uuid4().hex
            final_content["_admin"]["salt"] = salt
            final_content["password"] = sha256(edit_content["password"].encode('utf-8') +
                                               salt.encode('utf-8')).hexdigest()

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        if not session["admin"]:
            raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        # Names that look like UUIDs are not allowed
        name = (indata if indata else kwargs).get("username")
        if is_valid_uuid(name):
            raise EngineException("Usernames that look like UUIDs are not allowed",
                                  http_code=HTTPStatus.UNPROCESSABLE_ENTITY)
        return BaseTopic.edit(self, session, _id, indata=indata, kwargs=kwargs, content=content)

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        if not session["admin"]:
            raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        # Names that look like UUIDs are not allowed
        name = indata["username"] if indata else kwargs["username"]
        if is_valid_uuid(name):
            raise EngineException("Usernames that look like UUIDs are not allowed",
                                  http_code=HTTPStatus.UNPROCESSABLE_ENTITY)
        return BaseTopic.new(self, rollback, session, indata=indata, kwargs=kwargs, headers=headers)


class ProjectTopic(BaseTopic):
    topic = "projects"
    topic_msg = "projects"
    schema_new = project_new_schema
    schema_edit = project_edit_schema
    multiproject = False

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    @staticmethod
    def _get_project_filter(session):
        """
        Generates a filter dictionary for querying database users.
        Current policy is admin can show all, non admin, only its own user.
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :return:
        """
        if session["admin"]:  # allows all
            return {}
        else:
            return {"_id.cont": session["project_id"]}

    def check_conflict_on_new(self, session, indata):
        if not indata.get("name"):
            raise EngineException("missing 'name'")
        # check name not exists
        if self.db.get_one(self.topic, {"name": indata.get("name")}, fail_on_empty=False, fail_on_more=False):
            raise EngineException("name '{}' exists".format(indata["name"]), HTTPStatus.CONFLICT)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, None)
        # Removed so that the UUID is kept, to allow Project Name modification
        # content["_id"] = content["name"]

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check if deletion can be done because of dependencies if it is not force. To override
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: internal _id
        :param db_content: The database content of this item _id
        :return: None if ok or raises EngineException with the conflict
        """
        if _id in session["project_id"]:
            raise EngineException("You cannot delete your own project", http_code=HTTPStatus.CONFLICT)
        if session["force"]:
            return
        _filter = {"projects": _id}
        if self.db.get_list("users", _filter):
            raise EngineException("There is some USER that contains this project", http_code=HTTPStatus.CONFLICT)

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        if not session["admin"]:
            raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        # Names that look like UUIDs are not allowed
        name = (indata if indata else kwargs).get("name")
        if is_valid_uuid(name):
            raise EngineException("Project names that look like UUIDs are not allowed",
                                  http_code=HTTPStatus.UNPROCESSABLE_ENTITY)
        return BaseTopic.edit(self, session, _id, indata=indata, kwargs=kwargs, content=content)

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        if not session["admin"]:
            raise EngineException("needed admin privileges", http_code=HTTPStatus.UNAUTHORIZED)
        # Names that look like UUIDs are not allowed
        name = indata["name"] if indata else kwargs["name"]
        if is_valid_uuid(name):
            raise EngineException("Project names that look like UUIDs are not allowed",
                                  http_code=HTTPStatus.UNPROCESSABLE_ENTITY)
        return BaseTopic.new(self, rollback, session, indata=indata, kwargs=kwargs, headers=headers)


class VimAccountTopic(BaseTopic):
    topic = "vim_accounts"
    topic_msg = "vim_account"
    schema_new = vim_account_new_schema
    schema_edit = vim_account_edit_schema
    vim_config_encrypted = ("admin_password", "nsx_password", "vcenter_password")
    multiproject = True

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def check_conflict_on_new(self, session, indata):
        self.check_unique_name(session, indata["name"], _id=None)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        if not session["force"] and edit_content.get("name"):
            self.check_unique_name(session, edit_content["name"], _id=_id)

        # encrypt passwords
        schema_version = final_content.get("schema_version")
        if schema_version:
            if edit_content.get("vim_password"):
                final_content["vim_password"] = self.db.encrypt(edit_content["vim_password"],
                                                                schema_version=schema_version, salt=_id)
            if edit_content.get("config"):
                for p in self.vim_config_encrypted:
                    if edit_content["config"].get(p):
                        final_content["config"][p] = self.db.encrypt(edit_content["config"][p],
                                                                     schema_version=schema_version, salt=_id)

    def format_on_new(self, content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, project_id=project_id, make_public=make_public)
        content["schema_version"] = schema_version = "1.1"

        # encrypt passwords
        if content.get("vim_password"):
            content["vim_password"] = self.db.encrypt(content["vim_password"], schema_version=schema_version,
                                                      salt=content["_id"])
        if content.get("config"):
            for p in self.vim_config_encrypted:
                if content["config"].get(p):
                    content["config"][p] = self.db.encrypt(content["config"][p], schema_version=schema_version,
                                                           salt=content["_id"])

        content["_admin"]["operationalState"] = "PROCESSING"

    def delete(self, session, _id, dry_run=False):
        """
        Delete item by its internal _id
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param dry_run: make checking but do not delete
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        # TODO add admin to filter, validate rights
        if dry_run or session["force"]:    # delete completely
            return BaseTopic.delete(self, session, _id, dry_run)
        else:  # if not, sent to kafka
            v = BaseTopic.delete(self, session, _id, dry_run=True)
            self.db.set_one("vim_accounts", {"_id": _id}, {"_admin.to_delete": True})  # TODO change status
            self._send_msg("delete", {"_id": _id})
            return v  # TODO indicate an offline operation to return 202 ACCEPTED


class WimAccountTopic(BaseTopic):
    topic = "wim_accounts"
    topic_msg = "wim_account"
    schema_new = wim_account_new_schema
    schema_edit = wim_account_edit_schema
    multiproject = True
    wim_config_encrypted = ()

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def check_conflict_on_new(self, session, indata):
        self.check_unique_name(session, indata["name"], _id=None)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        if not session["force"] and edit_content.get("name"):
            self.check_unique_name(session, edit_content["name"], _id=_id)

        # encrypt passwords
        schema_version = final_content.get("schema_version")
        if schema_version:
            if edit_content.get("wim_password"):
                final_content["wim_password"] = self.db.encrypt(edit_content["wim_password"],
                                                                schema_version=schema_version, salt=_id)
            if edit_content.get("config"):
                for p in self.wim_config_encrypted:
                    if edit_content["config"].get(p):
                        final_content["config"][p] = self.db.encrypt(edit_content["config"][p],
                                                                     schema_version=schema_version, salt=_id)

    def format_on_new(self, content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, project_id=project_id, make_public=make_public)
        content["schema_version"] = schema_version = "1.1"

        # encrypt passwords
        if content.get("wim_password"):
            content["wim_password"] = self.db.encrypt(content["wim_password"], schema_version=schema_version,
                                                      salt=content["_id"])
        if content.get("config"):
            for p in self.wim_config_encrypted:
                if content["config"].get(p):
                    content["config"][p] = self.db.encrypt(content["config"][p], schema_version=schema_version,
                                                           salt=content["_id"])

        content["_admin"]["operationalState"] = "PROCESSING"

    def delete(self, session, _id, dry_run=False):
        """
        Delete item by its internal _id
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param dry_run: make checking but do not delete
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        # TODO add admin to filter, validate rights
        if dry_run or session["force"]:    # delete completely
            return BaseTopic.delete(self, session, _id, dry_run)
        else:  # if not, sent to kafka
            v = BaseTopic.delete(self, session, _id, dry_run=True)
            self.db.set_one("wim_accounts", {"_id": _id}, {"_admin.to_delete": True})  # TODO change status
            self._send_msg("delete", {"_id": _id})
            return v  # TODO indicate an offline operation to return 202 ACCEPTED


class SdnTopic(BaseTopic):
    topic = "sdns"
    topic_msg = "sdn"
    schema_new = sdn_new_schema
    schema_edit = sdn_edit_schema
    multiproject = True

    def __init__(self, db, fs, msg):
        BaseTopic.__init__(self, db, fs, msg)

    def check_conflict_on_new(self, session, indata):
        self.check_unique_name(session, indata["name"], _id=None)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        if not session["force"] and edit_content.get("name"):
            self.check_unique_name(session, edit_content["name"], _id=_id)

        # encrypt passwords
        schema_version = final_content.get("schema_version")
        if schema_version and edit_content.get("password"):
            final_content["password"] = self.db.encrypt(edit_content["password"], schema_version=schema_version,
                                                        salt=_id)

    def format_on_new(self, content, project_id=None, make_public=False):
        BaseTopic.format_on_new(content, project_id=project_id, make_public=make_public)
        content["schema_version"] = schema_version = "1.1"
        # encrypt passwords
        if content.get("password"):
            content["password"] = self.db.encrypt(content["password"], schema_version=schema_version,
                                                  salt=content["_id"])

        content["_admin"]["operationalState"] = "PROCESSING"

    def delete(self, session, _id, dry_run=False):
        """
        Delete item by its internal _id
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param dry_run: make checking but do not delete
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        if dry_run or session["force"]:  # delete completely
            return BaseTopic.delete(self, session, _id, dry_run)
        else:  # if not sent to kafka
            v = BaseTopic.delete(self, session, _id, dry_run=True)
            self.db.set_one("sdns", {"_id": _id}, {"_admin.to_delete": True})  # TODO change status
            self._send_msg("delete", {"_id": _id})
            return v   # TODO indicate an offline operation to return 202 ACCEPTED


class UserTopicAuth(UserTopic):
    # topic = "users"
    # topic_msg = "users"
    schema_new = user_new_schema
    schema_edit = user_edit_schema

    def __init__(self, db, fs, msg, auth):
        UserTopic.__init__(self, db, fs, msg)
        self.auth = auth

    def check_conflict_on_new(self, session, indata):
        """
        Check that the data to be inserted is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :return: None or raises EngineException
        """
        username = indata.get("username")
        user_list = list(map(lambda x: x["username"], self.auth.get_user_list()))

        if "projects" in indata.keys():
            raise EngineException("Format invalid: the keyword \"projects\" is not allowed for Keystone", 
                                  HTTPStatus.BAD_REQUEST)

        if username in user_list:
            raise EngineException("username '{}' exists".format(username), HTTPStatus.CONFLICT)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        """
        Check that the data to be edited/uploaded is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param final_content: data once modified
        :param edit_content: incremental data that contains the modifications to apply
        :param _id: internal _id
        :return: None or raises EngineException
        """
        users = self.auth.get_user_list()
        admin_user = [user for user in users if user["name"] == "admin"][0]

        if _id == admin_user["_id"] and edit_content["project_role_mappings"]:
            elem = {
                "project": "admin",
                "role": "system_admin"
            }
            if elem not in edit_content:
                raise EngineException("You cannot remove system_admin role from admin user", 
                                      http_code=HTTPStatus.FORBIDDEN)

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check if deletion can be done because of dependencies if it is not force. To override
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: internal _id
        :param db_content: The database content of this item _id
        :return: None if ok or raises EngineException with the conflict
        """
        if _id == session["username"]:
            raise EngineException("You cannot delete your own user", http_code=HTTPStatus.CONFLICT)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        """
        Modifies content descriptor to include _id.

        NOTE: No password salt required because the authentication backend
        should handle these security concerns.

        :param content: descriptor to be modified
        :param make_public: if included it is generated as public for reading.
        :return: None, but content is modified
        """
        BaseTopic.format_on_new(content, make_public=False)
        content["_id"] = content["username"]
        content["password"] = content["password"]

    @staticmethod
    def format_on_edit(final_content, edit_content):
        """
        Modifies final_content descriptor to include the modified date.

        NOTE: No password salt required because the authentication backend
        should handle these security concerns.

        :param final_content: final descriptor generated
        :param edit_content: alterations to be include
        :return: None, but final_content is modified
        """
        BaseTopic.format_on_edit(final_content, edit_content)
        if "password" in edit_content:
            final_content["password"] = edit_content["password"]
        else:
            final_content["project_role_mappings"] = edit_content["project_role_mappings"]

    @staticmethod
    def format_on_show(content):
        """
        Modifies the content of the role information to separate the role 
        metadata from the role definition.
        """
        project_role_mappings = []

        for project in content["projects"]:
            for role in project["roles"]:
                project_role_mappings.append({"project": project, "role": role})
        
        del content["projects"]
        content["project_role_mappings"] = project_role_mappings

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Creates a new entry into the authentication backend.

        NOTE: Overrides BaseTopic functionality because it doesn't require access to database.

        :param rollback: list to append created items at database in case a rollback may to be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id: identity of the inserted data.
        """
        try:
            content = BaseTopic._remove_envelop(indata)

            # Override descriptor with query string kwargs
            BaseTopic._update_input_with_kwargs(content, kwargs)
            content = self._validate_input_new(content, session["force"])
            self.check_conflict_on_new(session, content)
            self.format_on_new(content, session["project_id"], make_public=session["public"])
            _id = self.auth.create_user(content["username"], content["password"])
            rollback.append({"topic": self.topic, "_id": _id})
            del content["password"]
            # self._send_msg("create", content)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def show(self, session, _id):
        """
        Get complete information on an topic

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :return: dictionary, raise exception if not found.
        """
        users = [user for user in self.auth.get_user_list() if user["_id"] == _id]

        if len(users) == 1:
            return self.format_on_show(users[0])
        elif len(users) > 1:
            raise EngineException("Too many users found", HTTPStatus.CONFLICT)
        else:
            raise EngineException("User not found", HTTPStatus.NOT_FOUND)

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        """
        Updates an user entry.

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id:
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param content:
        :return: _id: identity of the inserted data.
        """
        indata = self._remove_envelop(indata)

        # Override descriptor with query string kwargs
        if kwargs:
            BaseTopic._update_input_with_kwargs(indata, kwargs)
        try:
            indata = self._validate_input_edit(indata, force=session["force"])

            if not content:
                content = self.show(session, _id)
            self.check_conflict_on_edit(session, content, indata, _id=_id)
            self.format_on_edit(content, indata)

            if "password" in content:
                self.auth.change_password(content["name"], content["password"])
            else:
                user = self.show(session, _id)
                original_mapping = user["project_role_mappings"]
                edit_mapping = content["project_role_mappings"]
                
                mappings_to_remove = [mapping for mapping in original_mapping 
                                      if mapping not in edit_mapping]
                
                mappings_to_add = [mapping for mapping in edit_mapping
                                   if mapping not in original_mapping]
                
                for mapping in mappings_to_remove:
                    self.auth.remove_role_from_user(
                        user["name"], 
                        mapping["project"],
                        mapping["role"]
                    )
                
                for mapping in mappings_to_add:
                    self.auth.assign_role_to_user(
                        user["name"], 
                        mapping["project"],
                        mapping["role"]
                    )

            return content["_id"]
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def list(self, session, filter_q=None):
        """
        Get a list of the topic that matches a filter
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param filter_q: filter of data to be applied
        :return: The list, it can be empty if no one match the filter.
        """
        if not filter_q:
            filter_q = {}

        users = [self.format_on_show(user) for user in self.auth.get_user_list(filter_q)]

        return users

    def delete(self, session, _id, dry_run=False):
        """
        Delete item by its internal _id

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param force: indicates if deletion must be forced in case of conflict
        :param dry_run: make checking but do not delete
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        self.check_conflict_on_del(session, _id, None)
        if not dry_run:
            v = self.auth.delete_user(_id)
            return v
        return None


class ProjectTopicAuth(ProjectTopic):
    # topic = "projects"
    # topic_msg = "projects"
    # schema_new = project_new_schema
    # schema_edit = project_edit_schema

    def __init__(self, db, fs, msg, auth):
        ProjectTopic.__init__(self, db, fs, msg)
        self.auth = auth

    def check_conflict_on_new(self, session, indata):
        """
        Check that the data to be inserted is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :return: None or raises EngineException
        """
        project = indata.get("name")
        project_list = list(map(lambda x: x["name"], self.auth.get_project_list()))

        if project in project_list:
            raise EngineException("project '{}' exists".format(project), HTTPStatus.CONFLICT)

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check if deletion can be done because of dependencies if it is not force. To override

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: internal _id
        :param db_content: The database content of this item _id
        :return: None if ok or raises EngineException with the conflict
        """
        projects = self.auth.get_project_list()
        current_project = [project for project in projects
                           if project["name"] == session["project_id"]][0]

        if _id == current_project["_id"]:
            raise EngineException("You cannot delete your own project", http_code=HTTPStatus.CONFLICT)

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Creates a new entry into the authentication backend.

        NOTE: Overrides BaseTopic functionality because it doesn't require access to database.

        :param rollback: list to append created items at database in case a rollback may to be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id: identity of the inserted data.
        """
        try:
            content = BaseTopic._remove_envelop(indata)

            # Override descriptor with query string kwargs
            BaseTopic._update_input_with_kwargs(content, kwargs)
            content = self._validate_input_new(content, session["force"])
            self.check_conflict_on_new(session, content)
            self.format_on_new(content, project_id=session["project_id"], make_public=session["public"])
            _id = self.auth.create_project(content["name"])
            rollback.append({"topic": self.topic, "_id": _id})
            # self._send_msg("create", content)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def show(self, session, _id):
        """
        Get complete information on an topic

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :return: dictionary, raise exception if not found.
        """
        projects = [project for project in self.auth.get_project_list() if project["_id"] == _id]

        if len(projects) == 1:
            return projects[0]
        elif len(projects) > 1:
            raise EngineException("Too many projects found", HTTPStatus.CONFLICT)
        else:
            raise EngineException("Project not found", HTTPStatus.NOT_FOUND)

    def list(self, session, filter_q=None):
        """
        Get a list of the topic that matches a filter

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param filter_q: filter of data to be applied
        :return: The list, it can be empty if no one match the filter.
        """
        if not filter_q:
            filter_q = {}

        return self.auth.get_project_list(filter_q)

    def delete(self, session, _id, dry_run=False):
        """
        Delete item by its internal _id

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param dry_run: make checking but do not delete
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        self.check_conflict_on_del(session, _id, None)
        if not dry_run:
            v = self.auth.delete_project(_id)
            return v
        return None


class RoleTopicAuth(BaseTopic):
    topic = "roles_operations"
    topic_msg = "roles"
    schema_new = roles_new_schema
    schema_edit = roles_edit_schema
    multiproject = False

    def __init__(self, db, fs, msg, auth, ops):
        BaseTopic.__init__(self, db, fs, msg)
        self.auth = auth
        self.operations = ops

    @staticmethod
    def validate_role_definition(operations, role_definitions):
        """
        Validates the role definition against the operations defined in
        the resources to operations files.

        :param operations: operations list
        :param role_definitions: role definition to test
        :return: None if ok, raises ValidationError exception on error
        """
        ignore_fields = ["_id", "_admin", "name"]
        for role_def in role_definitions.keys():
            if role_def in ignore_fields:
                continue
            if role_def == ".":
                if isinstance(role_definitions[role_def], bool):
                    continue
                else:
                    raise ValidationError("Operation authorization \".\" should be True/False.")
            if role_def[-1] == ".":
                raise ValidationError("Operation cannot end with \".\"")
            
            role_def_matches = [op for op in operations if op.startswith(role_def)]

            if len(role_def_matches) == 0:
                raise ValidationError("No matching operation found.")

            if not isinstance(role_definitions[role_def], bool):
                raise ValidationError("Operation authorization {} should be True/False.".format(role_def))

    def _validate_input_new(self, input, force=False):
        """
        Validates input user content for a new entry.

        :param input: user input content for the new topic
        :param force: may be used for being more tolerant
        :return: The same input content, or a changed version of it.
        """
        if self.schema_new:
            validate_input(input, self.schema_new)
            self.validate_role_definition(self.operations, input)
        
        return input

    def _validate_input_edit(self, input, force=False):
        """
        Validates input user content for updating an entry.

        :param input: user input content for the new topic
        :param force: may be used for being more tolerant
        :return: The same input content, or a changed version of it.
        """
        if self.schema_edit:
            validate_input(input, self.schema_edit)
            self.validate_role_definition(self.operations, input)
        
        return input

    def check_conflict_on_new(self, session, indata):
        """
        Check that the data to be inserted is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :return: None or raises EngineException
        """
        role = indata.get("name")
        role_list = list(map(lambda x: x["name"], self.auth.get_role_list()))

        if role in role_list:
            raise EngineException("role '{}' exists".format(role), HTTPStatus.CONFLICT)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        """
        Check that the data to be edited/uploaded is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param final_content: data once modified
        :param edit_content: incremental data that contains the modifications to apply
        :param _id: internal _id
        :return: None or raises EngineException
        """
        roles = self.auth.get_role_list()
        system_admin_role = [role for role in roles
                             if roles["name"] == "system_admin"][0]

        if _id == system_admin_role["_id"]:
            raise EngineException("You cannot edit system_admin role", http_code=HTTPStatus.FORBIDDEN)

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check if deletion can be done because of dependencies if it is not force. To override

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: internal _id
        :param db_content: The database content of this item _id
        :return: None if ok or raises EngineException with the conflict
        """
        roles = self.auth.get_role_list()
        system_admin_role = [role for role in roles
                             if roles["name"] == "system_admin"][0]

        if _id == system_admin_role["_id"]:
            raise EngineException("You cannot delete system_admin role", http_code=HTTPStatus.FORBIDDEN)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):
        """
        Modifies content descriptor to include _admin

        :param content: descriptor to be modified
        :param project_id: if included, it add project read/write permissions
        :param make_public: if included it is generated as public for reading.
        :return: None, but content is modified
        """
        now = time()
        if "_admin" not in content:
            content["_admin"] = {}
        if not content["_admin"].get("created"):
            content["_admin"]["created"] = now
        content["_admin"]["modified"] = now
        
        if "." in content.keys():
            content["root"] = content["."]
            del content["."]
        
        if "root" not in content.keys():
            content["root"] = False

        ignore_fields = ["_id", "_admin", "name"]
        content_keys = content.keys()
        for role_def in content_keys:
            if role_def in ignore_fields:
                continue
            content[role_def.replace(".", ":")] = content[role_def]
            del content[role_def]

    @staticmethod
    def format_on_edit(final_content, edit_content):
        """
        Modifies final_content descriptor to include the modified date.

        :param final_content: final descriptor generated
        :param edit_content: alterations to be include
        :return: None, but final_content is modified
        """
        final_content["_admin"]["modified"] = time()

        ignore_fields = ["_id", "name", "_admin"]
        delete_keys = [key for key in final_content.keys() if key not in ignore_fields]

        for key in delete_keys:
            del final_content[key]

        # Saving the role definition
        for role_def, value in edit_content.items():
            final_content[role_def.replace(".", ":")] = value
        
        if ":" in final_content.keys():
            final_content["root"] = final_content[":"]
            del final_content[":"]
        
        if "root" not in final_content.keys():
            final_content["root"] = False

    @staticmethod
    def format_on_show(content):
        """
        Modifies the content of the role information to separate the role 
        metadata from the role definition. Eases the reading process of the
        role definition.

        :param definition: role definition to be processed
        """
        content_keys = list(content.keys())

        content["_id"] = str(content["_id"])

        for key in content_keys:
            if ":" in key:
                content[key.replace(":", ".")] = content[key]
                del content[key]

    def show(self, session, _id):
        """
        Get complete information on an topic

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :return: dictionary, raise exception if not found.
        """
        filter_db = self._get_project_filter(session)
        filter_db["_id"] = _id

        role = self.db.get_one(self.topic, filter_db)
        new_role = dict(role)
        self.format_on_show(new_role)

        return new_role

    def list(self, session, filter_q=None):
        """
        Get a list of the topic that matches a filter

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param filter_q: filter of data to be applied
        :return: The list, it can be empty if no one match the filter.
        """
        if not filter_q:
            filter_q = {}

        if "root" in filter_q:
            filter_q[":"] = filter_q["root"]
            del filter_q["root"]
        
        if len(filter_q) > 0:
            keys = [key for key in filter_q.keys() if "." in key]

            for key in keys:
                filter_q[key.replace(".", ":")] = filter_q[key]
                del filter_q[key]

        roles = self.db.get_list(self.topic, filter_q)
        new_roles = []

        for role in roles:
            new_role = dict(role)
            self.format_on_show(new_role)
            new_roles.append(new_role)

        return new_roles

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Creates a new entry into database.

        :param rollback: list to append created items at database in case a rollback may to be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id: identity of the inserted data.
        """
        try:
            content = BaseTopic._remove_envelop(indata)

            # Override descriptor with query string kwargs
            BaseTopic._update_input_with_kwargs(content, kwargs)
            content = self._validate_input_new(content, session["force"])
            self.check_conflict_on_new(session, content)
            self.format_on_new(content, project_id=session["project_id"], make_public=session["public"])
            role_name = content["name"]
            role = self.auth.create_role(role_name)
            content["_id"] = role["_id"]
            _id = self.db.create(self.topic, content)
            rollback.append({"topic": self.topic, "_id": _id})
            # self._send_msg("create", content)
            return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def delete(self, session, _id, dry_run=False):
        """
        Delete item by its internal _id

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param dry_run: make checking but do not delete
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        self.check_conflict_on_del(session, _id, None)
        filter_q = self._get_project_filter(session)
        filter_q["_id"] = _id
        if not dry_run:
            self.auth.delete_role(_id)
            v = self.db.del_one(self.topic, filter_q)
            return v
        return None

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        """
        Updates a role entry.

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id:
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param content:
        :return: _id: identity of the inserted data.
        """
        indata = self._remove_envelop(indata)

        # Override descriptor with query string kwargs
        if kwargs:
            self._update_input_with_kwargs(indata, kwargs)
        try:
            indata = self._validate_input_edit(indata, force=session["force"])

            if not content:
                content = self.show(session, _id)
            self.check_conflict_on_edit(session, content, indata, _id=_id)
            self.format_on_edit(content, indata)
            self.db.replace(self.topic, _id, content)
            return id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)
