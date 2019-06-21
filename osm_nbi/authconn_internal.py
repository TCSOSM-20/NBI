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

__author__ = "Pedro de la Cruz Ramos <pdelacruzramos@altran.com>"
__date__ = "$06-jun-2019 11:16:08$"

from authconn import Authconn, AuthException
from osm_common.dbbase import DbException
from base_topic import BaseTopic

import logging
from time import time
from http import HTTPStatus
from uuid import uuid4
from hashlib import sha256
from copy import deepcopy
from random import choice as random_choice


class AuthconnInternal(Authconn):
    def __init__(self, config, db, token_cache):
        Authconn.__init__(self, config)

        self.logger = logging.getLogger("nbi.authenticator.internal")

        # Get Configuration
        # self.xxx = config.get("xxx", "default")

        self.db = db
        self.token_cache = token_cache

        # To be Confirmed
        self.auth = None
        self.sess = None

    # def create_token (self, user, password, projects=[], project=None, remote=None):
    # Not Required

    # def authenticate_with_user_password(self, user, password, project=None, remote=None):
    # Not Required

    # def authenticate_with_token(self, token, project=None, remote=None):
    # Not Required

    # def get_user_project_list(self, token):
    # Not Required

    # def get_user_role_list(self, token):
    # Not Required

    # def create_user(self, user, password):
    # Not Required

    # def change_password(self, user, new_password):
    # Not Required

    # def delete_user(self, user_id):
    # Not Required

    # def get_user_list(self, filter_q={}):
    # Not Required

    # def get_project_list(self, filter_q={}):
    # Not required

    # def create_project(self, project):
    # Not required

    # def delete_project(self, project_id):
    # Not required

    # def assign_role_to_user(self, user, project, role):
    # Not required in Phase 1

    # def remove_role_from_user(self, user, project, role):
    # Not required in Phase 1

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
            session = self.token_cache.get(token)
            if session and session["expires"] < now:
                # delete token. MUST be done with care, as another thread maybe already delete it. Do not use del
                self.token_cache.pop(token, None)
                session = None

            # get from database if not in cache
            if not session:
                session = self.db.get_one("tokens", {"_id": token})
                if session["expires"] < now:
                    raise AuthException("Expired Token or Authorization HTTP header", http_code=HTTPStatus.UNAUTHORIZED)

            # complete token information
            pid = session["project_id"]
            prj = self.db.get_one("projects", {BaseTopic.id_field("projects", pid): pid})
            session["project_id"] = prj["_id"]
            session["project_name"] = prj["name"]
            session["user_id"] = self.db.get_one("users", {"username": session["username"]})["_id"]

            # add token roles - PROVISIONAL
            role_id = self.db.get_one("roles", {"name": "system_admin"})["_id"]
            session["roles"] = [{"name": "system_admin", "id": role_id}]

            return session

        except DbException as e:
            if e.http_code == HTTPStatus.NOT_FOUND:
                raise AuthException("Invalid Token or Authorization HTTP header", http_code=HTTPStatus.UNAUTHORIZED)
            else:
                raise
        except AuthException:
            if self.config["global"].get("test.user_not_authorized"):
                return {"id": "fake-token-id-for-test",
                        "project_id": self.config["global"].get("test.project_not_authorized", "admin"),
                        "username": self.config["global"]["test.user_not_authorized"], "admin": True}
            else:
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

    def authenticate(self, user, password, project=None, token=None):
        """
        Authenticate a user using username/password or token, plus project

        :param user: user: name, id or None
        :param password: password or None
        :param project: name, id, or None. If None first found project will be used to get an scope token
        :param token: previous token to obtain authorization
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

        try:
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
            elif token:
                user_rows = self.db.get_list("users", {"username": token["username"]})
                if user_rows:
                    user_content = user_rows[0]
                else:
                    raise AuthException("Invalid token", http_code=HTTPStatus.UNAUTHORIZED)
            else:
                raise AuthException("Provide credentials: username/password or Authorization Bearer token",
                                    http_code=HTTPStatus.UNAUTHORIZED)

            token_id = ''.join(random_choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                               for _ in range(0, 32))
            project_id = project

            if project_id:
                if project_id != "admin":
                    # To allow project names in project_id
                    proj = self.db.get_one("projects", {BaseTopic.id_field("projects", project_id): project_id})
                    if proj["_id"] not in user_content["projects"] and proj["name"] not in user_content["projects"]:
                        raise AuthException("project {} not allowed for this user"
                                            .format(project_id), http_code=HTTPStatus.UNAUTHORIZED)
            else:
                project_id = user_content["projects"][0]

            if project_id == "admin":
                token_admin = True
            else:
                # To allow project names in project_id
                proj = self.db.get_one("projects", {BaseTopic.id_field("projects", project_id): project_id})
                token_admin = proj.get("admin", False)

            new_token = {"issued_at": now, "expires": now + 3600,
                         "_id": token_id, "id": token_id,
                         "project_id": project_id,
                         "username": user_content["username"],
                         "admin": token_admin}

            self.token_cache[token_id] = new_token
            self.db.create("tokens", new_token)
            # self._internal_tokens_prune(now)   # Belongs to Authenticator - REMOVE?
            return deepcopy(new_token)

        except Exception as e:
            msg = "Error during user authentication using internal backend: {}".format(e)
            self.logger.exception(msg)
            raise AuthException(msg, http_code=HTTPStatus.UNAUTHORIZED)

    def get_role_list(self):
        """
        Get role list.

        :return: returns the list of roles.
        """
        try:
            role_list = self.db.get_list("roles")
            roles = [{"name": role["name"], "_id": role["_id"]} for role in role_list]   # if role.name != "service" ?
            return roles
        except Exception:
            raise AuthException("Error during role listing using internal backend", http_code=HTTPStatus.UNAUTHORIZED)

    def create_role(self, role):
        """
        Create a role.

        :param role: role name.
        :raises AuthconnOperationException: if role creation failed.
        """
        # try:
        # TODO: Check that role name does not exist ?
        return str(uuid4())
        # except Exception:
        #     raise AuthconnOperationException("Error during role creation using internal backend")
        # except Conflict as ex:
        #     self.logger.info("Duplicate entry: %s", str(ex))

    def delete_role(self, role_id):
        """
        Delete a role.

        :param role_id: role identifier.
        :raises AuthconnOperationException: if role deletion failed.
        """
        # try:
        # TODO: Check that role exists ?
        return True
        # except Exception:
        #     raise AuthconnOperationException("Error during role deletion using internal backend")
