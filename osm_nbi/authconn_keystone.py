# -*- coding: utf-8 -*-

# Copyright 2018 Whitestack, LLC
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
AuthconnKeystone implements implements the connector for
Openstack Keystone and leverages the RBAC model, to bring
it for OSM.
"""
import time

__author__ = "Eduardo Sousa <esousa@whitestack.com>"
__date__ = "$27-jul-2018 23:59:59$"

from authconn import Authconn, AuthException, AuthconnOperationException

import logging
import requests
from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneauth1.exceptions.base import ClientException
from keystoneauth1.exceptions.http import Conflict
from keystoneclient.v3 import client
from http import HTTPStatus


class AuthconnKeystone(Authconn):
    def __init__(self, config):
        Authconn.__init__(self, config)

        self.logger = logging.getLogger("nbi.authenticator.keystone")

        self.auth_url = "http://{0}:{1}/v3".format(config.get("auth_url", "keystone"), config.get("auth_port", "5000"))
        self.user_domain_name = config.get("user_domain_name", "default")
        self.admin_project = config.get("service_project", "service")
        self.admin_username = config.get("service_username", "nbi")
        self.admin_password = config.get("service_password", "nbi")
        self.project_domain_name = config.get("project_domain_name", "default")

        # Waiting for Keystone to be up
        available = None
        counter = 300
        while available is None:
            time.sleep(1)
            try:
                result = requests.get(self.auth_url)
                available = True if result.status_code == 200 else None
            except Exception:
                counter -= 1
                if counter == 0:
                    raise AuthException("Keystone not available after 300s timeout")

        self.auth = v3.Password(user_domain_name=self.user_domain_name,
                                username=self.admin_username,
                                password=self.admin_password,
                                project_domain_name=self.project_domain_name,
                                project_name=self.admin_project,
                                auth_url=self.auth_url)
        self.sess = session.Session(auth=self.auth)
        self.keystone = client.Client(session=self.sess)

    def authenticate_with_user_password(self, user, password):
        """
        Authenticate a user using username and password.

        :param user: username
        :param password: password
        :return: an unscoped token that grants access to project list
        """
        try:
            user_id = list(filter(lambda x: x.name == user, self.keystone.users.list()))[0].id
            project_names = [project.name for project in self.keystone.projects.list(user=user_id)]

            token = self.keystone.get_raw_token_from_identity_service(
                auth_url=self.auth_url,
                username=user,
                password=password,
                user_domain_name=self.user_domain_name,
                project_domain_name=self.project_domain_name)

            return token["auth_token"], project_names
        except ClientException:
            self.logger.exception("Error during user authentication using keystone. Method: basic")
            raise AuthException("Error during user authentication using Keystone", http_code=HTTPStatus.UNAUTHORIZED)

    def authenticate_with_token(self, token, project=None):
        """
        Authenticate a user using a token. Can be used to revalidate the token
        or to get a scoped token.

        :param token: a valid token.
        :param project: (optional) project for a scoped token.
        :return: return a revalidated token, scoped if a project was passed or
        the previous token was already scoped.
        """
        try:
            token_info = self.keystone.tokens.validate(token=token)
            projects = self.keystone.projects.list(user=token_info["user"]["id"])
            project_names = [project.name for project in projects]

            new_token = self.keystone.get_raw_token_from_identity_service(
                auth_url=self.auth_url,
                token=token,
                project_name=project,
                user_domain_name=self.user_domain_name,
                project_domain_name=self.project_domain_name)

            return new_token["auth_token"], project_names
        except ClientException:
            self.logger.exception("Error during user authentication using keystone. Method: bearer")
            raise AuthException("Error during user authentication using Keystone", http_code=HTTPStatus.UNAUTHORIZED)

    def validate_token(self, token):
        """
        Check if the token is valid.

        :param token: token to validate
        :return: dictionary with information associated with the token. If the
        token is not valid, returns None.
        """
        if not token:
            return

        try:
            token_info = self.keystone.tokens.validate(token=token)

            return token_info
        except ClientException:
            self.logger.exception("Error during token validation using keystone")
            raise AuthException("Error during token validation using Keystone", http_code=HTTPStatus.UNAUTHORIZED)

    def revoke_token(self, token):
        """
        Invalidate a token.

        :param token: token to be revoked
        """
        try:
            self.logger.info("Revoking token: " + token)
            self.keystone.tokens.revoke_token(token=token)

            return True
        except ClientException:
            self.logger.exception("Error during token revocation using keystone")
            raise AuthException("Error during token revocation using Keystone", http_code=HTTPStatus.UNAUTHORIZED)

    def get_user_project_list(self, token):
        """
        Get all the projects associated with a user.

        :param token: valid token
        :return: list of projects
        """
        try:
            token_info = self.keystone.tokens.validate(token=token)
            projects = self.keystone.projects.list(user=token_info["user"]["id"])
            project_names = [project.name for project in projects]

            return project_names
        except ClientException:
            self.logger.exception("Error during user project listing using keystone")
            raise AuthException("Error during user project listing using Keystone", http_code=HTTPStatus.UNAUTHORIZED)

    def get_user_role_list(self, token):
        """
        Get role list for a scoped project.

        :param token: scoped token.
        :return: returns the list of roles for the user in that project. If
        the token is unscoped it returns None.
        """
        try:
            token_info = self.keystone.tokens.validate(token=token)
            roles_info = self.keystone.roles.list(user=token_info["user"]["id"], project=token_info["project"]["id"])

            roles = [role.name for role in roles_info]

            return roles
        except ClientException:
            self.logger.exception("Error during user role listing using keystone")
            raise AuthException("Error during user role listing using Keystone", http_code=HTTPStatus.UNAUTHORIZED)

    def create_user(self, user, password):
        """
        Create a user.

        :param user: username.
        :param password: password.
        :raises AuthconnOperationException: if user creation failed.
        :return: returns the id of the user in keystone.
        """
        try:
            new_user = self.keystone.users.create(user, password=password, domain=self.user_domain_name)
            return {"username": new_user.name, "_id": new_user.id}
        except ClientException:
            self.logger.exception("Error during user creation using keystone")
            raise AuthconnOperationException("Error during user creation using Keystone")

    def change_password(self, user, new_password):
        """
        Change the user password.

        :param user: username.
        :param new_password: new password.
        :raises AuthconnOperationException: if user password change failed.
        """
        try:
            user_obj = list(filter(lambda x: x.name == user, self.keystone.users.list()))[0]
            self.keystone.users.update(user_obj, password=new_password)
        except ClientException:
            self.logger.exception("Error during user password update using keystone")
            raise AuthconnOperationException("Error during user password update using Keystone")

    def delete_user(self, user_id):
        """
        Delete user.

        :param user_id: user identifier.
        :raises AuthconnOperationException: if user deletion failed.
        """
        try:
            users = self.keystone.users.list()
            user_obj = [user for user in users if user.id == user_id][0]
            result, _ = self.keystone.users.delete(user_obj)

            if result.status_code != 204:
                raise ClientException("User was not deleted")

            return True
        except ClientException:
            self.logger.exception("Error during user deletion using keystone")
            raise AuthconnOperationException("Error during user deletion using Keystone")

    def get_user_list(self):
        """
        Get user list.

        :return: returns a list of users.
        """
        try:
            users = self.keystone.users.list()
            users = [{
                "username": user.name,
                "_id": user.id
            } for user in users if user.name != self.admin_username]

            for user in users:
                projects = self.keystone.projects.list(user=user["_id"])
                projects = [{
                    "name": project.name,
                    "_id": project.id
                } for project in projects]

                for project in projects:
                    roles = self.keystone.roles.list(user=user["_id"], project=project["_id"])
                    roles = [{
                        "name": role.name,
                        "_id": role.id
                    } for role in roles]
                    project["roles"] = roles

                user["projects"] = projects

            return users
        except ClientException:
            self.logger.exception("Error during user listing using keystone")
            raise AuthconnOperationException("Error during user listing using Keystone")

    def get_role_list(self):
        """
        Get role list.

        :return: returns the list of roles for the user in that project. If
        the token is unscoped it returns None.
        """
        try:
            roles_list = self.keystone.roles.list()

            roles = [{
                "name": role.name,
                "_id": role.id
            } for role in roles_list if role.name != "service"]

            return roles
        except ClientException:
            self.logger.exception("Error during user role listing using keystone")
            raise AuthException("Error during user role listing using Keystone", http_code=HTTPStatus.UNAUTHORIZED)

    def create_role(self, role):
        """
        Create a role.

        :param role: role name.
        :raises AuthconnOperationException: if role creation failed.
        """
        try:
            result = self.keystone.roles.create(role)
            return {"name": result.name, "_id": result.id}
        except Conflict as ex:
            self.logger.info("Duplicate entry: %s", str(ex))
        except ClientException:
            self.logger.exception("Error during role creation using keystone")
            raise AuthconnOperationException("Error during role creation using Keystone")

    def delete_role(self, role_id):
        """
        Delete a role.

        :param role_id: role identifier.
        :raises AuthconnOperationException: if role deletion failed.
        """
        try:
            roles = self.keystone.roles.list()
            role_obj = [role for role in roles if role.id == role_id][0]
            result, _ = self.keystone.roles.delete(role_obj)

            if result.status_code != 204:
                raise ClientException("Role was not deleted")

            return True
        except ClientException:
            self.logger.exception("Error during role deletion using keystone")
            raise AuthconnOperationException("Error during role deletion using Keystone")

    def get_project_list(self):
        """
        Get all the projects.

        :return: list of projects
        """
        try:
            projects = self.keystone.projects.list()
            projects = [{
                "name": project.name,
                "_id": project.id
            } for project in projects if project.name != self.admin_project]

            return projects
        except ClientException:
            self.logger.exception("Error during user project listing using keystone")
            raise AuthException("Error during user project listing using Keystone", http_code=HTTPStatus.UNAUTHORIZED)

    def create_project(self, project):
        """
        Create a project.

        :param project: project name.
        :raises AuthconnOperationException: if project creation failed.
        """
        try:
            result = self.keystone.projects.create(project, self.project_domain_name)
            return {"name": result.name, "_id": result.id}
        except ClientException:
            self.logger.exception("Error during project creation using keystone")
            raise AuthconnOperationException("Error during project creation using Keystone")

    def delete_project(self, project_id):
        """
        Delete a project.

        :param project_id: project identifier.
        :raises AuthconnOperationException: if project deletion failed.
        """
        try:
            projects = self.keystone.projects.list()
            project_obj = [project for project in projects if project.id == project_id][0]
            result, _ = self.keystone.projects.delete(project_obj)

            if result.status_code != 204:
                raise ClientException("Project was not deleted")

            return True
        except ClientException:
            self.logger.exception("Error during project deletion using keystone")
            raise AuthconnOperationException("Error during project deletion using Keystone")

    def assign_role_to_user(self, user, project, role):
        """
        Assigning a role to a user in a project.

        :param user: username.
        :param project: project name.
        :param role: role name.
        :raises AuthconnOperationException: if role assignment failed.
        """
        try:
            user_obj = list(filter(lambda x: x.name == user, self.keystone.users.list()))[0]
            project_obj = list(filter(lambda x: x.name == project, self.keystone.projects.list()))[0]
            role_obj = list(filter(lambda x: x.name == role, self.keystone.roles.list()))[0]

            self.keystone.roles.grant(role_obj, user=user_obj, project=project_obj)
        except ClientException:
            self.logger.exception("Error during user role assignment using keystone")
            raise AuthconnOperationException("Error during user role assignment using Keystone")

    def remove_role_from_user(self, user, project, role):
        """
        Remove a role from a user in a project.

        :param user: username.
        :param project: project name.
        :param role: role name.
        :raises AuthconnOperationException: if role assignment revocation failed.
        """
        try:
            user_obj = list(filter(lambda x: x.name == user, self.keystone.users.list()))[0]
            project_obj = list(filter(lambda x: x.name == project, self.keystone.projects.list()))[0]
            role_obj = list(filter(lambda x: x.name == role, self.keystone.roles.list()))[0]

            self.keystone.roles.revoke(role_obj, user=user_obj, project=project_obj)
        except ClientException:
            self.logger.exception("Error during user role revocation using keystone")
            raise AuthconnOperationException("Error during user role revocation using Keystone")
