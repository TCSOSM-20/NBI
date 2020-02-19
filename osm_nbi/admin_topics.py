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
from osm_nbi.validation import user_new_schema, user_edit_schema, project_new_schema, project_edit_schema, \
    vim_account_new_schema, vim_account_edit_schema, sdn_new_schema, sdn_edit_schema, \
    wim_account_new_schema, wim_account_edit_schema, roles_new_schema, roles_edit_schema, \
    k8scluster_new_schema, k8scluster_edit_schema, k8srepo_new_schema, k8srepo_edit_schema, \
    validate_input, ValidationError, is_valid_uuid    # To check that User/Project Names don't look like UUIDs
from osm_nbi.base_topic import BaseTopic, EngineException
from osm_nbi.authconn import AuthconnNotFoundException, AuthconnConflictException
from osm_common.dbbase import deep_update_rfc7396

__author__ = "Alfonso Tierno <alfonso.tiernosepulveda@telefonica.com>"


class UserTopic(BaseTopic):
    topic = "users"
    topic_msg = "users"
    schema_new = user_new_schema
    schema_edit = user_edit_schema
    multiproject = False

    def __init__(self, db, fs, msg, auth):
        BaseTopic.__init__(self, db, fs, msg, auth)

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
            for p in indata.get("projects") or []:
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
            projects = [mapping["project"] for mapping in content["project_role_mappings"]]

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
        return None

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

    def __init__(self, db, fs, msg, auth):
        BaseTopic.__init__(self, db, fs, msg, auth)

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


class CommonVimWimSdn(BaseTopic):
    """Common class for VIM, WIM SDN just to unify methods that are equal to all of them"""
    config_to_encrypt = {}     # what keys at config must be encrypted because contains passwords
    password_to_encrypt = ""   # key that contains a password

    @staticmethod
    def _create_operation(op_type, params=None):
        """
        Creates a dictionary with the information to an operation, similar to ns-lcm-op
        :param op_type: can be create, edit, delete
        :param params: operation input parameters
        :return: new dictionary with
        """
        now = time()
        return {
            "lcmOperationType": op_type,
            "operationState": "PROCESSING",
            "startTime": now,
            "statusEnteredTime": now,
            "detailed-status": "",
            "operationParams": params,
        }

    def check_conflict_on_new(self, session, indata):
        """
        Check that the data to be inserted is valid. It is checked that name is unique
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :return: None or raises EngineException
        """
        self.check_unique_name(session, indata["name"], _id=None)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        """
        Check that the data to be edited/uploaded is valid. It is checked that name is unique
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param final_content: data once modified. This method may change it.
        :param edit_content: incremental data that contains the modifications to apply
        :param _id: internal _id
        :return: None or raises EngineException
        """
        if not session["force"] and edit_content.get("name"):
            self.check_unique_name(session, edit_content["name"], _id=_id)

    def format_on_edit(self, final_content, edit_content):
        """
        Modifies final_content inserting admin information upon edition
        :param final_content: final content to be stored at database
        :param edit_content: user requested update content
        :return: operation id
        """
        super().format_on_edit(final_content, edit_content)

        # encrypt passwords
        schema_version = final_content.get("schema_version")
        if schema_version:
            if edit_content.get(self.password_to_encrypt):
                final_content[self.password_to_encrypt] = self.db.encrypt(edit_content[self.password_to_encrypt],
                                                                          schema_version=schema_version,
                                                                          salt=final_content["_id"])
            config_to_encrypt_keys = self.config_to_encrypt.get(schema_version) or self.config_to_encrypt.get("default")
            if edit_content.get("config") and config_to_encrypt_keys:

                for p in config_to_encrypt_keys:
                    if edit_content["config"].get(p):
                        final_content["config"][p] = self.db.encrypt(edit_content["config"][p],
                                                                     schema_version=schema_version,
                                                                     salt=final_content["_id"])

        # create edit operation
        final_content["_admin"]["operations"].append(self._create_operation("edit"))
        return "{}:{}".format(final_content["_id"], len(final_content["_admin"]["operations"]) - 1)

    def format_on_new(self, content, project_id=None, make_public=False):
        """
        Modifies content descriptor to include _admin and insert create operation
        :param content: descriptor to be modified
        :param project_id: if included, it add project read/write permissions. Can be None or a list
        :param make_public: if included it is generated as public for reading.
        :return: op_id: operation id on asynchronous operation, None otherwise. In addition content is modified
        """
        super().format_on_new(content, project_id=project_id, make_public=make_public)
        content["schema_version"] = schema_version = "1.11"

        # encrypt passwords
        if content.get(self.password_to_encrypt):
            content[self.password_to_encrypt] = self.db.encrypt(content[self.password_to_encrypt],
                                                                schema_version=schema_version,
                                                                salt=content["_id"])
        config_to_encrypt_keys = self.config_to_encrypt.get(schema_version) or self.config_to_encrypt.get("default")
        if content.get("config") and config_to_encrypt_keys:
            for p in config_to_encrypt_keys:
                if content["config"].get(p):
                    content["config"][p] = self.db.encrypt(content["config"][p],
                                                           schema_version=schema_version,
                                                           salt=content["_id"])

        content["_admin"]["operationalState"] = "PROCESSING"

        # create operation
        content["_admin"]["operations"] = [self._create_operation("create")]
        content["_admin"]["current_operation"] = None

        return "{}:0".format(content["_id"])

    def delete(self, session, _id, dry_run=False, not_send_msg=None):
        """
        Delete item by its internal _id
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param dry_run: make checking but do not delete
        :param not_send_msg: To not send message (False) or store content (list) instead
        :return: operation id if it is ordered to delete. None otherwise
        """

        filter_q = self._get_project_filter(session)
        filter_q["_id"] = _id
        db_content = self.db.get_one(self.topic, filter_q)

        self.check_conflict_on_del(session, _id, db_content)
        if dry_run:
            return None

        # remove reference from project_read. If not last delete
        if session["project_id"]:
            for project_id in session["project_id"]:
                if project_id in db_content["_admin"]["projects_read"]:
                    db_content["_admin"]["projects_read"].remove(project_id)
                if project_id in db_content["_admin"]["projects_write"]:
                    db_content["_admin"]["projects_write"].remove(project_id)
        else:
            db_content["_admin"]["projects_read"].clear()
            db_content["_admin"]["projects_write"].clear()

        update_dict = {"_admin.projects_read": db_content["_admin"]["projects_read"],
                       "_admin.projects_write": db_content["_admin"]["projects_write"]
                       }

        # check if there are projects referencing it (apart from ANY that means public)....
        if db_content["_admin"]["projects_read"] and (len(db_content["_admin"]["projects_read"]) > 1 or
                                                      db_content["_admin"]["projects_read"][0] != "ANY"):
            self.db.set_one(self.topic, filter_q, update_dict=update_dict)  # remove references but not delete
            return None

        # It must be deleted
        if session["force"]:
            self.db.del_one(self.topic, {"_id": _id})
            op_id = None
            self._send_msg("deleted", {"_id": _id, "op_id": op_id}, not_send_msg=not_send_msg)
        else:
            update_dict["_admin.to_delete"] = True
            self.db.set_one(self.topic, {"_id": _id},
                            update_dict=update_dict,
                            push={"_admin.operations": self._create_operation("delete")}
                            )
            # the number of operations is the operation_id. db_content does not contains the new operation inserted,
            # so the -1 is not needed
            op_id = "{}:{}".format(db_content["_id"], len(db_content["_admin"]["operations"]))
            self._send_msg("delete", {"_id": _id, "op_id": op_id}, not_send_msg=not_send_msg)
        return op_id


class VimAccountTopic(CommonVimWimSdn):
    topic = "vim_accounts"
    topic_msg = "vim_account"
    schema_new = vim_account_new_schema
    schema_edit = vim_account_edit_schema
    multiproject = True
    password_to_encrypt = "vim_password"
    config_to_encrypt = {"1.1": ("admin_password", "nsx_password", "vcenter_password"),
                         "default": ("admin_password", "nsx_password", "vcenter_password", "vrops_password")}

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check if deletion can be done because of dependencies if it is not force. To override
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: internal _id
        :param db_content: The database content of this item _id
        :return: None if ok or raises EngineException with the conflict
        """
        if session["force"]:
            return
        # check if used by VNF
        if self.db.get_list("vnfrs", {"vim-account-id": _id}):
            raise EngineException("There is at least one VNF using this VIM account", http_code=HTTPStatus.CONFLICT)
        super().check_conflict_on_del(session, _id, db_content)


class WimAccountTopic(CommonVimWimSdn):
    topic = "wim_accounts"
    topic_msg = "wim_account"
    schema_new = wim_account_new_schema
    schema_edit = wim_account_edit_schema
    multiproject = True
    password_to_encrypt = "wim_password"
    config_to_encrypt = {}


class SdnTopic(CommonVimWimSdn):
    topic = "sdns"
    topic_msg = "sdn"
    schema_new = sdn_new_schema
    schema_edit = sdn_edit_schema
    multiproject = True
    password_to_encrypt = "password"
    config_to_encrypt = {}

    def _obtain_url(self, input, create):
        if input.get("ip") or input.get("port"):
            if not input.get("ip") or not input.get("port") or input.get('url'):
                raise ValidationError("You must provide both 'ip' and 'port' (deprecated); or just 'url' (prefered)")
            input['url'] = "http://{}:{}/".format(input["ip"], input["port"])
            del input["ip"]
            del input["port"]
        elif create and not input.get('url'):
            raise ValidationError("You must provide 'url'")
        return input

    def _validate_input_new(self, input, force=False):
        input = super()._validate_input_new(input, force)
        return self._obtain_url(input, True)

    def _validate_input_edit(self, input, force=False):
        input = super()._validate_input_edit(input, force)
        return self._obtain_url(input, False)


class K8sClusterTopic(CommonVimWimSdn):
    topic = "k8sclusters"
    topic_msg = "k8scluster"
    schema_new = k8scluster_new_schema
    schema_edit = k8scluster_edit_schema
    multiproject = True
    password_to_encrypt = None
    config_to_encrypt = {}

    def format_on_new(self, content, project_id=None, make_public=False):
        oid = super().format_on_new(content, project_id, make_public)
        self.db.encrypt_decrypt_fields(content["credentials"], 'encrypt', ['password', 'secret'],
                                       schema_version=content["schema_version"], salt=content["_id"])
        # Add Helm/Juju Repo lists
        repos = {"helm-chart": [], "juju-bundle": []}
        for proj in content["_admin"]["projects_read"]:
            if proj != 'ANY':
                for repo in self.db.get_list("k8srepos", {"_admin.projects_read": proj}):
                    if repo["_id"] not in repos[repo["type"]]:
                        repos[repo["type"]].append(repo["_id"])
        for k in repos:
            content["_admin"][k.replace('-', '_')+"_repos"] = repos[k]
        return oid

    def format_on_edit(self, final_content, edit_content):
        if final_content.get("schema_version") and edit_content.get("credentials"):
            self.db.encrypt_decrypt_fields(edit_content["credentials"], 'encrypt', ['password', 'secret'],
                                           schema_version=final_content["schema_version"], salt=final_content["_id"])
            deep_update_rfc7396(final_content["credentials"], edit_content["credentials"])
        oid = super().format_on_edit(final_content, edit_content)
        return oid

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        super(CommonVimWimSdn, self).check_conflict_on_edit(session, final_content, edit_content, _id)
        super().check_conflict_on_edit(session, final_content, edit_content, _id)
        # Update Helm/Juju Repo lists
        repos = {"helm-chart": [], "juju-bundle": []}
        for proj in session.get("set_project", []):
            if proj != 'ANY':
                for repo in self.db.get_list("k8srepos", {"_admin.projects_read": proj}):
                    if repo["_id"] not in repos[repo["type"]]:
                        repos[repo["type"]].append(repo["_id"])
        for k in repos:
            rlist = k.replace('-', '_') + "_repos"
            if rlist not in final_content["_admin"]:
                final_content["_admin"][rlist] = []
            final_content["_admin"][rlist] += repos[k]


class K8sRepoTopic(CommonVimWimSdn):
    topic = "k8srepos"
    topic_msg = "k8srepo"
    schema_new = k8srepo_new_schema
    schema_edit = k8srepo_edit_schema
    multiproject = True
    password_to_encrypt = None
    config_to_encrypt = {}

    def format_on_new(self, content, project_id=None, make_public=False):
        oid = super().format_on_new(content, project_id, make_public)
        # Update Helm/Juju Repo lists
        repo_list = content["type"].replace('-', '_')+"_repos"
        for proj in content["_admin"]["projects_read"]:
            if proj != 'ANY':
                self.db.set_list("k8sclusters",
                                 {"_admin.projects_read": proj, "_admin."+repo_list+".ne": content["_id"]}, {},
                                 push={"_admin."+repo_list: content["_id"]})
        return oid

    def delete(self, session, _id, dry_run=False, not_send_msg=None):
        type = self.db.get_one("k8srepos", {"_id": _id})["type"]
        oid = super().delete(session, _id, dry_run, not_send_msg)
        if oid:
            # Remove from Helm/Juju Repo lists
            repo_list = type.replace('-', '_') + "_repos"
            self.db.set_list("k8sclusters", {"_admin."+repo_list: _id}, {}, pull={"_admin."+repo_list: _id})
        return oid


class UserTopicAuth(UserTopic):
    # topic = "users"
    # topic_msg = "users"
    schema_new = user_new_schema
    schema_edit = user_edit_schema

    def __init__(self, db, fs, msg, auth):
        UserTopic.__init__(self, db, fs, msg, auth)
        # self.auth = auth

    def check_conflict_on_new(self, session, indata):
        """
        Check that the data to be inserted is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :return: None or raises EngineException
        """
        username = indata.get("username")
        if is_valid_uuid(username):
            raise EngineException("username '{}' cannot have a uuid format".format(username),
                                  HTTPStatus.UNPROCESSABLE_ENTITY)

        # Check that username is not used, regardless keystone already checks this
        if self.auth.get_user_list(filter_q={"name": username}):
            raise EngineException("username '{}' is already used".format(username), HTTPStatus.CONFLICT)

        if "projects" in indata.keys():
            # convert to new format project_role_mappings
            role = self.auth.get_role_list({"name": "project_admin"})
            if not role:
                role = self.auth.get_role_list()
            if not role:
                raise AuthconnNotFoundException("Can't find default role for user '{}'".format(username))
            rid = role[0]["_id"]
            if not indata.get("project_role_mappings"):
                indata["project_role_mappings"] = []
            for project in indata["projects"]:
                pid = self.auth.get_project(project)["_id"]
                prm = {"project": pid, "role": rid}
                if prm not in indata["project_role_mappings"]:
                    indata["project_role_mappings"].append(prm)
            # raise EngineException("Format invalid: the keyword 'projects' is not allowed for keystone authentication",
            #                       HTTPStatus.BAD_REQUEST)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        """
        Check that the data to be edited/uploaded is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param final_content: data once modified
        :param edit_content: incremental data that contains the modifications to apply
        :param _id: internal _id
        :return: None or raises EngineException
        """

        if "username" in edit_content:
            username = edit_content.get("username")
            if is_valid_uuid(username):
                raise EngineException("username '{}' cannot have an uuid format".format(username),
                                      HTTPStatus.UNPROCESSABLE_ENTITY)

            # Check that username is not used, regardless keystone already checks this
            if self.auth.get_user_list(filter_q={"name": username}):
                raise EngineException("username '{}' is already used".format(username), HTTPStatus.CONFLICT)

        if final_content["username"] == "admin":
            for mapping in edit_content.get("remove_project_role_mappings", ()):
                if mapping["project"] == "admin" and mapping.get("role") in (None, "system_admin"):
                    # TODO make this also available for project id and role id
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
        if db_content["username"] == session["username"]:
            raise EngineException("You cannot delete your own login user ", http_code=HTTPStatus.CONFLICT)
        # TODO: Check that user is not logged in ? How? (Would require listing current tokens)

    @staticmethod
    def format_on_show(content):
        """
        Modifies the content of the role information to separate the role
        metadata from the role definition.
        """
        project_role_mappings = []

        if "projects" in content:
            for project in content["projects"]:
                for role in project["roles"]:
                    project_role_mappings.append({"project": project["_id"],
                                                  "project_name": project["name"],
                                                  "role": role["_id"],
                                                  "role_name": role["name"]})
            del content["projects"]
        content["project_role_mappings"] = project_role_mappings

        return content

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Creates a new entry into the authentication backend.

        NOTE: Overrides BaseTopic functionality because it doesn't require access to database.

        :param rollback: list to append created items at database in case a rollback may to be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id: identity of the inserted data, operation _id (None)
        """
        try:
            content = BaseTopic._remove_envelop(indata)

            # Override descriptor with query string kwargs
            BaseTopic._update_input_with_kwargs(content, kwargs)
            content = self._validate_input_new(content, session["force"])
            self.check_conflict_on_new(session, content)
            # self.format_on_new(content, session["project_id"], make_public=session["public"])
            now = time()
            content["_admin"] = {"created": now, "modified": now}
            prms = []
            for prm in content.get("project_role_mappings", []):
                proj = self.auth.get_project(prm["project"], not session["force"])
                role = self.auth.get_role(prm["role"], not session["force"])
                pid = proj["_id"] if proj else None
                rid = role["_id"] if role else None
                prl = {"project": pid, "role": rid}
                if prl not in prms:
                    prms.append(prl)
            content["project_role_mappings"] = prms
            # _id = self.auth.create_user(content["username"], content["password"])["_id"]
            _id = self.auth.create_user(content)["_id"]

            rollback.append({"topic": self.topic, "_id": _id})
            # del content["password"]
            # self._send_msg("created", content, not_send_msg=not_send_msg)
            return _id, None
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def show(self, session, _id):
        """
        Get complete information on an topic

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :return: dictionary, raise exception if not found.
        """
        # Allow _id to be a name or uuid
        filter_q = {"username": _id}
        # users = self.auth.get_user_list(filter_q)
        users = self.list(session, filter_q)   # To allow default filtering (Bug 853)
        if len(users) == 1:
            return users[0]
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
            # self.format_on_edit(content, indata)

            if not ("password" in indata or "username" in indata or indata.get("remove_project_role_mappings") or
                    indata.get("add_project_role_mappings") or indata.get("project_role_mappings") or
                    indata.get("projects") or indata.get("add_projects")):
                return _id
            if indata.get("project_role_mappings") \
                    and (indata.get("remove_project_role_mappings") or indata.get("add_project_role_mappings")):
                raise EngineException("Option 'project_role_mappings' is incompatible with 'add_project_role_mappings"
                                      "' or 'remove_project_role_mappings'", http_code=HTTPStatus.BAD_REQUEST)

            if indata.get("projects") or indata.get("add_projects"):
                role = self.auth.get_role_list({"name": "project_admin"})
                if not role:
                    role = self.auth.get_role_list()
                if not role:
                    raise AuthconnNotFoundException("Can't find a default role for user '{}'"
                                                    .format(content["username"]))
                rid = role[0]["_id"]
                if "add_project_role_mappings" not in indata:
                    indata["add_project_role_mappings"] = []
                if "remove_project_role_mappings" not in indata:
                    indata["remove_project_role_mappings"] = []
                if isinstance(indata.get("projects"), dict):
                    # backward compatible
                    for k, v in indata["projects"].items():
                        if k.startswith("$") and v is None:
                            indata["remove_project_role_mappings"].append({"project": k[1:]})
                        elif k.startswith("$+"):
                            indata["add_project_role_mappings"].append({"project": v, "role": rid})
                    del indata["projects"]
                for proj in indata.get("projects", []) + indata.get("add_projects", []):
                    indata["add_project_role_mappings"].append({"project": proj, "role": rid})

            # user = self.show(session, _id)   # Already in 'content'
            original_mapping = content["project_role_mappings"]

            mappings_to_add = []
            mappings_to_remove = []

            # remove
            for to_remove in indata.get("remove_project_role_mappings", ()):
                for mapping in original_mapping:
                    if to_remove["project"] in (mapping["project"], mapping["project_name"]):
                        if not to_remove.get("role") or to_remove["role"] in (mapping["role"], mapping["role_name"]):
                            mappings_to_remove.append(mapping)

            # add
            for to_add in indata.get("add_project_role_mappings", ()):
                for mapping in original_mapping:
                    if to_add["project"] in (mapping["project"], mapping["project_name"]) and \
                            to_add["role"] in (mapping["role"], mapping["role_name"]):

                        if mapping in mappings_to_remove:   # do not remove
                            mappings_to_remove.remove(mapping)
                        break  # do not add, it is already at user
                else:
                    pid = self.auth.get_project(to_add["project"])["_id"]
                    rid = self.auth.get_role(to_add["role"])["_id"]
                    mappings_to_add.append({"project": pid, "role": rid})

            # set
            if indata.get("project_role_mappings"):
                for to_set in indata["project_role_mappings"]:
                    for mapping in original_mapping:
                        if to_set["project"] in (mapping["project"], mapping["project_name"]) and \
                                to_set["role"] in (mapping["role"], mapping["role_name"]):
                            if mapping in mappings_to_remove:   # do not remove
                                mappings_to_remove.remove(mapping)
                            break  # do not add, it is already at user
                    else:
                        pid = self.auth.get_project(to_set["project"])["_id"]
                        rid = self.auth.get_role(to_set["role"])["_id"]
                        mappings_to_add.append({"project": pid, "role": rid})
                for mapping in original_mapping:
                    for to_set in indata["project_role_mappings"]:
                        if to_set["project"] in (mapping["project"], mapping["project_name"]) and \
                                to_set["role"] in (mapping["role"], mapping["role_name"]):
                            break
                    else:
                        # delete
                        if mapping not in mappings_to_remove:   # do not remove
                            mappings_to_remove.append(mapping)

            self.auth.update_user({"_id": _id, "username": indata.get("username"), "password": indata.get("password"),
                                   "add_project_role_mappings": mappings_to_add,
                                   "remove_project_role_mappings": mappings_to_remove
                                   })

            # return _id
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def list(self, session, filter_q=None):
        """
        Get a list of the topic that matches a filter
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param filter_q: filter of data to be applied
        :return: The list, it can be empty if no one match the filter.
        """
        user_list = self.auth.get_user_list(filter_q)
        if not session["allow_show_user_project_role"]:
            # Bug 853 - Default filtering
            user_list = [usr for usr in user_list if usr["username"] == session["username"]]
        return user_list

    def delete(self, session, _id, dry_run=False, not_send_msg=None):
        """
        Delete item by its internal _id

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param force: indicates if deletion must be forced in case of conflict
        :param dry_run: make checking but do not delete
        :param not_send_msg: To not send message (False) or store content (list) instead
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        # Allow _id to be a name or uuid
        user = self.auth.get_user(_id)
        uid = user["_id"]
        self.check_conflict_on_del(session, uid, user)
        if not dry_run:
            v = self.auth.delete_user(uid)
            return v
        return None


class ProjectTopicAuth(ProjectTopic):
    # topic = "projects"
    # topic_msg = "projects"
    schema_new = project_new_schema
    schema_edit = project_edit_schema

    def __init__(self, db, fs, msg, auth):
        ProjectTopic.__init__(self, db, fs, msg, auth)
        # self.auth = auth

    def check_conflict_on_new(self, session, indata):
        """
        Check that the data to be inserted is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :return: None or raises EngineException
        """
        project_name = indata.get("name")
        if is_valid_uuid(project_name):
            raise EngineException("project name '{}' cannot have an uuid format".format(project_name),
                                  HTTPStatus.UNPROCESSABLE_ENTITY)

        project_list = self.auth.get_project_list(filter_q={"name": project_name})

        if project_list:
            raise EngineException("project '{}' exists".format(project_name), HTTPStatus.CONFLICT)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        """
        Check that the data to be edited/uploaded is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param final_content: data once modified
        :param edit_content: incremental data that contains the modifications to apply
        :param _id: internal _id
        :return: None or raises EngineException
        """

        project_name = edit_content.get("name")
        if project_name != final_content["name"]:  # It is a true renaming
            if is_valid_uuid(project_name):
                raise EngineException("project name '{}' cannot have an uuid format".format(project_name),
                                      HTTPStatus.UNPROCESSABLE_ENTITY)

            if final_content["name"] == "admin":
                raise EngineException("You cannot rename project 'admin'", http_code=HTTPStatus.CONFLICT)

            # Check that project name is not used, regardless keystone already checks this
            if project_name and self.auth.get_project_list(filter_q={"name": project_name}):
                raise EngineException("project '{}' is already used".format(project_name), HTTPStatus.CONFLICT)

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check if deletion can be done because of dependencies if it is not force. To override

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: internal _id
        :param db_content: The database content of this item _id
        :return: None if ok or raises EngineException with the conflict
        """

        def check_rw_projects(topic, title, id_field):
            for desc in self.db.get_list(topic):
                if _id in desc["_admin"]["projects_read"] + desc["_admin"]["projects_write"]:
                    raise EngineException("Project '{}' ({}) is being used by {} '{}'"
                                          .format(db_content["name"], _id, title, desc[id_field]), HTTPStatus.CONFLICT)

        if _id in session["project_id"]:
            raise EngineException("You cannot delete your own project", http_code=HTTPStatus.CONFLICT)

        if db_content["name"] == "admin":
            raise EngineException("You cannot delete project 'admin'", http_code=HTTPStatus.CONFLICT)

        # If any user is using this project, raise CONFLICT exception
        if not session["force"]:
            for user in self.auth.get_user_list():
                for prm in user.get("project_role_mappings"):
                    if prm["project"] == _id:
                        raise EngineException("Project '{}' ({}) is being used by user '{}'"
                                              .format(db_content["name"], _id, user["username"]), HTTPStatus.CONFLICT)

        # If any VNFD, NSD, NST, PDU, etc. is using this project, raise CONFLICT exception
        if not session["force"]:
            check_rw_projects("vnfds", "VNF Descriptor", "id")
            check_rw_projects("nsds", "NS Descriptor", "id")
            check_rw_projects("nsts", "NS Template", "id")
            check_rw_projects("pdus", "PDU Descriptor", "name")

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Creates a new entry into the authentication backend.

        NOTE: Overrides BaseTopic functionality because it doesn't require access to database.

        :param rollback: list to append created items at database in case a rollback may to be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id: identity of the inserted data, operation _id (None)
        """
        try:
            content = BaseTopic._remove_envelop(indata)

            # Override descriptor with query string kwargs
            BaseTopic._update_input_with_kwargs(content, kwargs)
            content = self._validate_input_new(content, session["force"])
            self.check_conflict_on_new(session, content)
            self.format_on_new(content, project_id=session["project_id"], make_public=session["public"])
            _id = self.auth.create_project(content)
            rollback.append({"topic": self.topic, "_id": _id})
            # self._send_msg("created", content, not_send_msg=not_send_msg)
            return _id, None
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def show(self, session, _id):
        """
        Get complete information on an topic

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :return: dictionary, raise exception if not found.
        """
        # Allow _id to be a name or uuid
        filter_q = {self.id_field(self.topic, _id): _id}
        # projects = self.auth.get_project_list(filter_q=filter_q)
        projects = self.list(session, filter_q)   # To allow default filtering (Bug 853)
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
        project_list = self.auth.get_project_list(filter_q)
        if not session["allow_show_user_project_role"]:
            # Bug 853 - Default filtering
            user = self.auth.get_user(session["username"])
            projects = [prm["project"] for prm in user["project_role_mappings"]]
            project_list = [proj for proj in project_list if proj["_id"] in projects]
        return project_list

    def delete(self, session, _id, dry_run=False, not_send_msg=None):
        """
        Delete item by its internal _id

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param dry_run: make checking but do not delete
        :param not_send_msg: To not send message (False) or store content (list) instead
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        # Allow _id to be a name or uuid
        proj = self.auth.get_project(_id)
        pid = proj["_id"]
        self.check_conflict_on_del(session, pid, proj)
        if not dry_run:
            v = self.auth.delete_project(pid)
            return v
        return None

    def edit(self, session, _id, indata=None, kwargs=None, content=None):
        """
        Updates a project entry.

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

            deep_update_rfc7396(content, indata)
            self.auth.update_project(content["_id"], content)
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)


class RoleTopicAuth(BaseTopic):
    topic = "roles"
    topic_msg = None    # "roles"
    schema_new = roles_new_schema
    schema_edit = roles_edit_schema
    multiproject = False

    def __init__(self, db, fs, msg, auth, ops):
        BaseTopic.__init__(self, db, fs, msg, auth)
        # self.auth = auth
        self.operations = ops
        # self.topic = "roles_operations" if isinstance(auth, AuthconnKeystone) else "roles"

    @staticmethod
    def validate_role_definition(operations, role_definitions):
        """
        Validates the role definition against the operations defined in
        the resources to operations files.

        :param operations: operations list
        :param role_definitions: role definition to test
        :return: None if ok, raises ValidationError exception on error
        """
        if not role_definitions.get("permissions"):
            return
        ignore_fields = ["admin", "default"]
        for role_def in role_definitions["permissions"].keys():
            if role_def in ignore_fields:
                continue
            if role_def[-1] == ":":
                raise ValidationError("Operation cannot end with ':'")

            role_def_matches = [op for op in operations if op.startswith(role_def)]

            if len(role_def_matches) == 0:
                raise ValidationError("Invalid permission '{}'".format(role_def))

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
        # check name is not uuid
        role_name = indata.get("name")
        if is_valid_uuid(role_name):
            raise EngineException("role name '{}' cannot have an uuid format".format(role_name),
                                  HTTPStatus.UNPROCESSABLE_ENTITY)
        # check name not exists
        name = indata["name"]
        # if self.db.get_one(self.topic, {"name": indata.get("name")}, fail_on_empty=False, fail_on_more=False):
        if self.auth.get_role_list({"name": name}):
            raise EngineException("role name '{}' exists".format(name), HTTPStatus.CONFLICT)

    def check_conflict_on_edit(self, session, final_content, edit_content, _id):
        """
        Check that the data to be edited/uploaded is valid

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param final_content: data once modified
        :param edit_content: incremental data that contains the modifications to apply
        :param _id: internal _id
        :return: None or raises EngineException
        """
        if "default" not in final_content["permissions"]:
            final_content["permissions"]["default"] = False
        if "admin" not in final_content["permissions"]:
            final_content["permissions"]["admin"] = False

        # check name is not uuid
        role_name = edit_content.get("name")
        if is_valid_uuid(role_name):
            raise EngineException("role name '{}' cannot have an uuid format".format(role_name),
                                  HTTPStatus.UNPROCESSABLE_ENTITY)

        # Check renaming of admin roles
        role = self.auth.get_role(_id)
        if role["name"] in ["system_admin", "project_admin"]:
            raise EngineException("You cannot rename role '{}'".format(role["name"]), http_code=HTTPStatus.FORBIDDEN)

        # check name not exists
        if "name" in edit_content:
            role_name = edit_content["name"]
            # if self.db.get_one(self.topic, {"name":role_name,"_id.ne":_id}, fail_on_empty=False, fail_on_more=False):
            roles = self.auth.get_role_list({"name": role_name})
            if roles and roles[0][BaseTopic.id_field("roles", _id)] != _id:
                raise EngineException("role name '{}' exists".format(role_name), HTTPStatus.CONFLICT)

    def check_conflict_on_del(self, session, _id, db_content):
        """
        Check if deletion can be done because of dependencies if it is not force. To override

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: internal _id
        :param db_content: The database content of this item _id
        :return: None if ok or raises EngineException with the conflict
        """
        role = self.auth.get_role(_id)
        if role["name"] in ["system_admin", "project_admin"]:
            raise EngineException("You cannot delete role '{}'".format(role["name"]), http_code=HTTPStatus.FORBIDDEN)

        # If any user is using this role, raise CONFLICT exception
        if not session["force"]:
            for user in self.auth.get_user_list():
                for prm in user.get("project_role_mappings"):
                    if prm["role"] == _id:
                        raise EngineException("Role '{}' ({}) is being used by user '{}'"
                                              .format(role["name"], _id, user["username"]), HTTPStatus.CONFLICT)

    @staticmethod
    def format_on_new(content, project_id=None, make_public=False):   # TO BE REMOVED ?
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

        if "permissions" not in content:
            content["permissions"] = {}

        if "default" not in content["permissions"]:
            content["permissions"]["default"] = False
        if "admin" not in content["permissions"]:
            content["permissions"]["admin"] = False

    @staticmethod
    def format_on_edit(final_content, edit_content):
        """
        Modifies final_content descriptor to include the modified date.

        :param final_content: final descriptor generated
        :param edit_content: alterations to be include
        :return: None, but final_content is modified
        """
        if "_admin" in final_content:
            final_content["_admin"]["modified"] = time()

        if "permissions" not in final_content:
            final_content["permissions"] = {}

        if "default" not in final_content["permissions"]:
            final_content["permissions"]["default"] = False
        if "admin" not in final_content["permissions"]:
            final_content["permissions"]["admin"] = False
        return None

    def show(self, session, _id):
        """
        Get complete information on an topic

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :return: dictionary, raise exception if not found.
        """
        filter_q = {BaseTopic.id_field(self.topic, _id): _id}
        # roles = self.auth.get_role_list(filter_q)
        roles = self.list(session, filter_q)   # To allow default filtering (Bug 853)
        if not roles:
            raise AuthconnNotFoundException("Not found any role with filter {}".format(filter_q))
        elif len(roles) > 1:
            raise AuthconnConflictException("Found more than one role with filter {}".format(filter_q))
        return roles[0]

    def list(self, session, filter_q=None):
        """
        Get a list of the topic that matches a filter

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param filter_q: filter of data to be applied
        :return: The list, it can be empty if no one match the filter.
        """
        role_list = self.auth.get_role_list(filter_q)
        if not session["allow_show_user_project_role"]:
            # Bug 853 - Default filtering
            user = self.auth.get_user(session["username"])
            roles = [prm["role"] for prm in user["project_role_mappings"]]
            role_list = [role for role in role_list if role["_id"] in roles]
        return role_list

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Creates a new entry into database.

        :param rollback: list to append created items at database in case a rollback may to be done
        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param indata: data to be inserted
        :param kwargs: used to override the indata descriptor
        :param headers: http request headers
        :return: _id: identity of the inserted data, operation _id (None)
        """
        try:
            content = self._remove_envelop(indata)

            # Override descriptor with query string kwargs
            self._update_input_with_kwargs(content, kwargs)
            content = self._validate_input_new(content, session["force"])
            self.check_conflict_on_new(session, content)
            self.format_on_new(content, project_id=session["project_id"], make_public=session["public"])
            # role_name = content["name"]
            rid = self.auth.create_role(content)
            content["_id"] = rid
            # _id = self.db.create(self.topic, content)
            rollback.append({"topic": self.topic, "_id": rid})
            # self._send_msg("created", content, not_send_msg=not_send_msg)
            return rid, None
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)

    def delete(self, session, _id, dry_run=False, not_send_msg=None):
        """
        Delete item by its internal _id

        :param session: contains "username", "admin", "force", "public", "project_id", "set_project"
        :param _id: server internal id
        :param dry_run: make checking but do not delete
        :param not_send_msg: To not send message (False) or store content (list) instead
        :return: dictionary with deleted item _id. It raises EngineException on error: not found, conflict, ...
        """
        filter_q = {BaseTopic.id_field(self.topic, _id): _id}
        roles = self.auth.get_role_list(filter_q)
        if not roles:
            raise AuthconnNotFoundException("Not found any role with filter {}".format(filter_q))
        elif len(roles) > 1:
            raise AuthconnConflictException("Found more than one role with filter {}".format(filter_q))
        rid = roles[0]["_id"]
        self.check_conflict_on_del(session, rid, None)
        # filter_q = {"_id": _id}
        # filter_q = {BaseTopic.id_field(self.topic, _id): _id}   # To allow role addressing by name
        if not dry_run:
            v = self.auth.delete_role(rid)
            # v = self.db.del_one(self.topic, filter_q)
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
        if kwargs:
            self._update_input_with_kwargs(indata, kwargs)
        try:
            indata = self._validate_input_edit(indata, force=session["force"])
            if not content:
                content = self.show(session, _id)
            deep_update_rfc7396(content, indata)
            self.check_conflict_on_edit(session, content, indata, _id=_id)
            self.format_on_edit(content, indata)
            self.auth.update_role(content)
        except ValidationError as e:
            raise EngineException(e, HTTPStatus.UNPROCESSABLE_ENTITY)
