# -*- coding: utf-8 -*-

# Copyright 2018 Telefonica S.A.
# Copyright 2018 ALTRAN Innovación S.L.
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
# contact: esousa@whitestack.com or glavado@whitestack.com
##

"""
AuthconnInternal implements implements the connector for
OSM Internal Authentication Backend and leverages the RBAC model
"""

__author__ = "Pedro de la Cruz Ramos <pdelacruzramos@altran.com>, " \
             "Alfonso Tierno <alfonso.tiernosepulveda@telefoncia.com"
__date__ = "$06-jun-2019 11:16:08$"

from osm_nbi.authconn import Authconn, AuthException   # , AuthconnOperationException
from osm_common.dbbase import DbException
from osm_nbi.base_topic import BaseTopic

import logging
import re
from time import time
from http import HTTPStatus
from uuid import uuid4
from hashlib import sha256
from copy import deepcopy
from random import choice as random_choice


class AuthconnInternal(Authconn):
    def __init__(self, config, db, token_cache):
        Authconn.__init__(self, config, db, token_cache)

        self.logger = logging.getLogger("nbi.authenticator.internal")

        self.db = db
        self.token_cache = token_cache

        # To be Confirmed
        self.auth = None
        self.sess = None

    def validate_token(self, token):
        """
        Check if the token is valid.

        :param token: token to validate
        :return: dictionary with information associated with the token:
            "_id": token id
            "project_id": project id
            "project_name": project name
            "user_id": user id
            "username": user name
            "roles": list with dict containing {name, id}
            "expires": expiration date
        If the token is not valid an exception is raised.
        """

        try:
            if not token:
                raise AuthException("Needed a token or Authorization HTTP header", http_code=HTTPStatus.UNAUTHORIZED)

            # try to get from cache first
            now = time()
            token_info = self.token_cache.get(token)
            if token_info and token_info["expires"] < now:
                # delete token. MUST be done with care, as another thread maybe already delete it. Do not use del
                self.token_cache.pop(token, None)
                token_info = None

            # get from database if not in cache
            if not token_info:
                token_info = self.db.get_one("tokens", {"_id": token})
                if token_info["expires"] < now:
                    raise AuthException("Expired Token or Authorization HTTP header", http_code=HTTPStatus.UNAUTHORIZED)

            return token_info

        except DbException as e:
            if e.http_code == HTTPStatus.NOT_FOUND:
                raise AuthException("Invalid Token or Authorization HTTP header", http_code=HTTPStatus.UNAUTHORIZED)
            else:
                raise
        except AuthException:
            raise
        except Exception:
            self.logger.exception("Error during token validation using internal backend")
            raise AuthException("Error during token validation using internal backend",
                                http_code=HTTPStatus.UNAUTHORIZED)

    def revoke_token(self, token):
        """
        Invalidate a token.

        :param token: token to be revoked
        """
        try:
            self.token_cache.pop(token, None)
            self.db.del_one("tokens", {"_id": token})
            return True
        except DbException as e:
            if e.http_code == HTTPStatus.NOT_FOUND:
                raise AuthException("Token '{}' not found".format(token), http_code=HTTPStatus.NOT_FOUND)
            else:
                # raise
                msg = "Error during token revocation using internal backend"
                self.logger.exception(msg)
                raise AuthException(msg, http_code=HTTPStatus.UNAUTHORIZED)

    def authenticate(self, user, password, project=None, token_info=None):
        """
        Authenticate a user using username/password or previous token_info plus project; its creates a new token

        :param user: user: name, id or None
        :param password: password or None
        :param project: name, id, or None. If None first found project will be used to get an scope token
        :param token_info: previous token_info to obtain authorization
        :param remote: remote host information
        :return: the scoped token info or raises an exception. The token is a dictionary with:
            _id:  token string id,
            username: username,
            project_id: scoped_token project_id,
            project_name: scoped_token project_name,
            expires: epoch time when it expires,
        """

        now = time()
        user_content = None

        # Try using username/password
        if user:
            user_rows = self.db.get_list("users", {BaseTopic.id_field("users", user): user})
            if user_rows:
                user_content = user_rows[0]
                salt = user_content["_admin"]["salt"]
                shadow_password = sha256(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
                if shadow_password != user_content["password"]:
                    user_content = None
            if not user_content:
                raise AuthException("Invalid username/password", http_code=HTTPStatus.UNAUTHORIZED)
        elif token_info:
            user_rows = self.db.get_list("users", {"username": token_info["username"]})
            if user_rows:
                user_content = user_rows[0]
            else:
                raise AuthException("Invalid token", http_code=HTTPStatus.UNAUTHORIZED)
        else:
            raise AuthException("Provide credentials: username/password or Authorization Bearer token",
                                http_code=HTTPStatus.UNAUTHORIZED)

        token_id = ''.join(random_choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                           for _ in range(0, 32))

        # projects = user_content.get("projects", [])
        prm_list = user_content.get("project_role_mappings", [])

        if not project:
            project = prm_list[0]["project"] if prm_list else None
        if not project:
            raise AuthException("can't find a default project for this user", http_code=HTTPStatus.UNAUTHORIZED)

        projects = [prm["project"] for prm in prm_list]

        proj = self.db.get_one("projects", {BaseTopic.id_field("projects", project): project})
        project_name = proj["name"]
        project_id = proj["_id"]
        if project_name not in projects and project_id not in projects:
            raise AuthException("project {} not allowed for this user".format(project),
                                http_code=HTTPStatus.UNAUTHORIZED)

        # TODO remove admin, this vill be used by roles RBAC
        if project_name == "admin":
            token_admin = True
        else:
            token_admin = proj.get("admin", False)

        # add token roles
        roles = []
        roles_list = []
        for prm in prm_list:
            if prm["project"] in [project_id, project_name]:
                role = self.db.get_one("roles", {BaseTopic.id_field("roles", prm["role"]): prm["role"]})
                rid = role["_id"]
                if rid not in roles:
                    rnm = role["name"]
                    roles.append(rid)
                    roles_list.append({"name": rnm, "id": rid})
        if not roles_list:
            rid = self.db.get_one("roles", {"name": "project_admin"})["_id"]
            roles_list = [{"name": "project_admin", "id": rid}]

        new_token = {"issued_at": now,
                     "expires": now + 3600,
                     "_id": token_id,
                     "id": token_id,
                     "project_id": proj["_id"],
                     "project_name": proj["name"],
                     "username": user_content["username"],
                     "user_id": user_content["_id"],
                     "admin": token_admin,
                     "roles": roles_list,
                     }

        self.token_cache[token_id] = new_token
        self.db.create("tokens", new_token)
        return deepcopy(new_token)

    def get_role_list(self, filter_q={}):
        """
        Get role list.

        :return: returns the list of roles.
        """
        return self.db.get_list("roles", filter_q)

    def create_role(self, role_info):
        """
        Create a role.

        :param role_info: full role info.
        :return: returns the role id.
        :raises AuthconnOperationException: if role creation failed.
        """
        # TODO: Check that role name does not exist ?
        rid = str(uuid4())
        role_info["_id"] = rid
        rid = self.db.create("roles", role_info)
        return rid

    def delete_role(self, role_id):
        """
        Delete a role.

        :param role_id: role identifier.
        :raises AuthconnOperationException: if role deletion failed.
        """
        return self.db.del_one("roles", {"_id": role_id})

    def update_role(self, role_info):
        """
        Update a role.

        :param role_info: full role info.
        :return: returns the role name and id.
        :raises AuthconnOperationException: if user creation failed.
        """
        rid = role_info["_id"]
        self.db.set_one("roles", {"_id": rid}, role_info)   # CONFIRM
        return {"_id": rid, "name": role_info["name"]}

    def create_user(self, user_info):
        """
        Create a user.

        :param user_info: full user info.
        :return: returns the username and id of the user.
        """
        BaseTopic.format_on_new(user_info, make_public=False)
        salt = uuid4().hex
        user_info["_admin"]["salt"] = salt
        if "password" in user_info:
            user_info["password"] = sha256(user_info["password"].encode('utf-8') + salt.encode('utf-8')).hexdigest()
        # "projects" are not stored any more
        if "projects" in user_info:
            del user_info["projects"]
        self.db.create("users", user_info)
        return {"username": user_info["username"], "_id": user_info["_id"]}

    def update_user(self, user_info):
        """
        Change the user name and/or password.

        :param user_info: user info modifications
        """
        uid = user_info["_id"]
        user_data = self.db.get_one("users", {BaseTopic.id_field("users", uid): uid})
        BaseTopic.format_on_edit(user_data, user_info)
        # User Name
        usnm = user_info.get("username")
        if usnm:
            user_data["username"] = usnm
        # If password is given and is not already encripted
        pswd = user_info.get("password")
        if pswd and (len(pswd) != 64 or not re.match('[a-fA-F0-9]*', pswd)):   # TODO: Improve check?
            salt = uuid4().hex
            if "_admin" not in user_data:
                user_data["_admin"] = {}
            user_data["_admin"]["salt"] = salt
            user_data["password"] = sha256(pswd.encode('utf-8') + salt.encode('utf-8')).hexdigest()
        # Project-Role Mappings
        # TODO: Check that user_info NEVER includes "project_role_mappings"
        if "project_role_mappings" not in user_data:
            user_data["project_role_mappings"] = []
        for prm in user_info.get("add_project_role_mappings", []):
            user_data["project_role_mappings"].append(prm)
        for prm in user_info.get("remove_project_role_mappings", []):
            for pidf in ["project", "project_name"]:
                for ridf in ["role", "role_name"]:
                    try:
                        user_data["project_role_mappings"].remove({"role": prm[ridf], "project": prm[pidf]})
                    except KeyError:
                        pass
                    except ValueError:
                        pass
        self.db.set_one("users", {BaseTopic.id_field("users", uid): uid}, user_data)   # CONFIRM

    def delete_user(self, user_id):
        """
        Delete user.

        :param user_id: user identifier.
        :raises AuthconnOperationException: if user deletion failed.
        """
        self.db.del_one("users", {"_id": user_id})
        return True

    def get_user_list(self, filter_q=None):
        """
        Get user list.

        :param filter_q: dictionary to filter user list by name (username is also admited) and/or _id
        :return: returns a list of users.
        """
        filt = filter_q or {}
        if "name" in filt:
            filt["username"] = filt["name"]
            del filt["name"]
        users = self.db.get_list("users", filt)
        project_id_name = {}
        role_id_name = {}
        for user in users:
            prms = user.get("project_role_mappings")
            projects = user.get("projects")
            if prms:
                projects = []
                # add project_name and role_name. Generate projects for backward compatibility
                for prm in prms:
                    project_id = prm["project"]
                    if project_id not in project_id_name:
                        pr = self.db.get_one("projects", {BaseTopic.id_field("projects", project_id): project_id},
                                             fail_on_empty=False)
                        project_id_name[project_id] = pr["name"] if pr else None
                    prm["project_name"] = project_id_name[project_id]
                    if prm["project_name"] not in projects:
                        projects.append(prm["project_name"])

                    role_id = prm["role"]
                    if role_id not in role_id_name:
                        role = self.db.get_one("roles", {BaseTopic.id_field("roles", role_id): role_id},
                                               fail_on_empty=False)
                        role_id_name[role_id] = role["name"] if role else None
                    prm["role_name"] = role_id_name[role_id]
                user["projects"] = projects  # for backward compatibility
            elif projects:
                # user created with an old version. Create a project_role mapping with role project_admin
                user["project_role_mappings"] = []
                role = self.db.get_one("roles", {BaseTopic.id_field("roles", "project_admin"): "project_admin"})
                for p_id_name in projects:
                    pr = self.db.get_one("projects", {BaseTopic.id_field("projects", p_id_name): p_id_name})
                    prm = {"project": pr["_id"],
                           "project_name": pr["name"],
                           "role_name": "project_admin",
                           "role": role["_id"]
                           }
                    user["project_role_mappings"].append(prm)
            else:
                user["projects"] = []
                user["project_role_mappings"] = []

        return users

    def get_project_list(self, filter_q={}):
        """
        Get role list.

        :return: returns the list of projects.
        """
        return self.db.get_list("projects", filter_q)

    def create_project(self, project_info):
        """
        Create a project.

        :param project: full project info.
        :return: the internal id of the created project
        :raises AuthconnOperationException: if project creation failed.
        """
        pid = self.db.create("projects", project_info)
        return pid

    def delete_project(self, project_id):
        """
        Delete a project.

        :param project_id: project identifier.
        :raises AuthconnOperationException: if project deletion failed.
        """
        filter_q = {BaseTopic.id_field("projects", project_id): project_id}
        r = self.db.del_one("projects", filter_q)
        return r

    def update_project(self, project_id, project_info):
        """
        Change the name of a project

        :param project_id: project to be changed
        :param project_info: full project info
        :return: None
        :raises AuthconnOperationException: if project update failed.
        """
        self.db.set_one("projects", {BaseTopic.id_field("projects", project_id): project_id}, project_info)
