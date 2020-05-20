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


__author__ = "Eduardo Sousa <esousa@whitestack.com>, " \
             "Pedro de la Cruz Ramos <pdelacruzramos@altran.com>"
__date__ = "$27-jul-2018 23:59:59$"

from osm_nbi.authconn import Authconn, AuthException, AuthconnOperationException, AuthconnNotFoundException, \
    AuthconnConflictException

import logging
import requests
import time
from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneauth1.exceptions.base import ClientException
from keystoneauth1.exceptions.http import Conflict
from keystoneclient.v3 import client
from http import HTTPStatus
from osm_nbi.validation import is_valid_uuid, validate_input, http_schema


class AuthconnKeystone(Authconn):
    def __init__(self, config, db, role_permissions):
        Authconn.__init__(self, config, db, role_permissions)

        self.logger = logging.getLogger("nbi.authenticator.keystone")
        self.domains_id2name = {}
        self.domains_name2id = {}

        self.auth_url = config.get("auth_url")
        if config.get("auth_url"):
            validate_input(self.auth_url, http_schema)
        else:
            self.auth_url = "http://{0}:{1}/v3".format(config.get("auth_host", "keystone"),
                                                       config.get("auth_port", "5000"))
        self.user_domain_name_list = config.get("user_domain_name", "default")
        self.user_domain_name_list = self.user_domain_name_list.split(",")
        # read only domain list
        self.user_domain_ro_list = [x[:-3] for x in self.user_domain_name_list if x.endswith(":ro")]
        # remove the ":ro"
        self.user_domain_name_list = [x if not x.endswith(":ro") else x[:-3] for x in self.user_domain_name_list]

        self.admin_project = config.get("service_project", "service")
        self.admin_username = config.get("service_username", "nbi")
        self.admin_password = config.get("service_password", "nbi")
        self.project_domain_name_list = config.get("project_domain_name", "default")
        self.project_domain_name_list = self.project_domain_name_list.split(",")
        if len(self.user_domain_name_list) != len(self.project_domain_name_list):
            raise ValueError("Invalid configuration parameter fo authenticate. 'project_domain_name' and "
                             "'user_domain_name' must be a comma-separated list with the same size. Revise "
                             "configuration or/and 'OSMNBI_AUTHENTICATION_PROJECT_DOMAIN_NAME', "
                             "'OSMNBI_AUTHENTICATION_USER_DOMAIN_NAME'  Variables")

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

        self.auth = v3.Password(user_domain_name=self.user_domain_name_list[0],
                                username=self.admin_username,
                                password=self.admin_password,
                                project_domain_name=self.project_domain_name_list[0],
                                project_name=self.admin_project,
                                auth_url=self.auth_url)
        self.sess = session.Session(auth=self.auth)
        self.keystone = client.Client(session=self.sess, endpoint_override=self.auth_url)

    def authenticate(self, credentials, token_info=None):
        """
        Authenticate a user using username/password or token_info, plus project
        :param credentials: dictionary that contains:
            username: name, id or None
            password: password or None
            project_id: name, id, or None. If None first found project will be used to get an scope token
            project_domain_name: (Optional) To use a concrete domain for the project
            user_domain_name: (Optional) To use a concrete domain for the project
            other items are allowed and ignored
        :param token_info: previous token_info to obtain authorization
        :return: the scoped token info or raises an exception. The token is a dictionary with:
            _id:  token string id,
            username: username,
            project_id: scoped_token project_id,
            project_name: scoped_token project_name,
            expires: epoch time when it expires,

        """
        username = None
        user_id = None
        project_id = None
        project_name = None
        if credentials.get("project_domain_name"):
            project_domain_name_list = (credentials["project_domain_name"], )
        else:
            project_domain_name_list = self.project_domain_name_list
        if credentials.get("user_domain_name"):
            user_domain_name_list = (credentials["user_domain_name"], )
        else:
            user_domain_name_list = self.user_domain_name_list

        for index, project_domain_name in enumerate(project_domain_name_list):
            user_domain_name = user_domain_name_list[index]
            try:
                if credentials.get("username"):
                    if is_valid_uuid(credentials["username"]):
                        user_id = credentials["username"]
                    else:
                        username = credentials["username"]

                    # get an unscoped token firstly
                    unscoped_token = self.keystone.get_raw_token_from_identity_service(
                        auth_url=self.auth_url,
                        user_id=user_id,
                        username=username,
                        password=credentials.get("password"),
                        user_domain_name=user_domain_name,
                        project_domain_name=project_domain_name)
                elif token_info:
                    unscoped_token = self.keystone.tokens.validate(token=token_info.get("_id"))
                else:
                    raise AuthException("Provide credentials: username/password or Authorization Bearer token",
                                        http_code=HTTPStatus.UNAUTHORIZED)

                if not credentials.get("project_id"):
                    # get first project for the user
                    project_list = self.keystone.projects.list(user=unscoped_token["user"]["id"])
                    if not project_list:
                        raise AuthException("The user {} has not any project and cannot be used for authentication".
                                            format(credentials.get("username")), http_code=HTTPStatus.UNAUTHORIZED)
                    project_id = project_list[0].id
                else:
                    if is_valid_uuid(credentials["project_id"]):
                        project_id = credentials["project_id"]
                    else:
                        project_name = credentials["project_id"]

                scoped_token = self.keystone.get_raw_token_from_identity_service(
                    auth_url=self.auth_url,
                    project_name=project_name,
                    project_id=project_id,
                    user_domain_name=user_domain_name,
                    project_domain_name=project_domain_name,
                    token=unscoped_token["auth_token"])

                auth_token = {
                    "_id": scoped_token.auth_token,
                    "id": scoped_token.auth_token,
                    "user_id": scoped_token.user_id,
                    "username": scoped_token.username,
                    "project_id": scoped_token.project_id,
                    "project_name": scoped_token.project_name,
                    "project_domain_name": scoped_token.project_domain_name,
                    "user_domain_name": scoped_token.user_domain_name,
                    "expires": scoped_token.expires.timestamp(),
                    "issued_at": scoped_token.issued.timestamp()
                }

                return auth_token
            except ClientException as e:
                if index >= len(user_domain_name_list)-1 or index >= len(project_domain_name_list)-1:
                    # if last try, launch exception
                    # self.logger.exception("Error during user authentication using keystone: {}".format(e))
                    raise AuthException("Error during user authentication using Keystone: {}".format(e),
                                        http_code=HTTPStatus.UNAUTHORIZED)

    def validate_token(self, token):
        """
        Check if the token is valid.

        :param token: token id to be validated
        :return: dictionary with information associated with the token:
             "expires":
             "_id": token_id,
             "project_id": project_id,
             "username": ,
             "roles": list with dict containing {name, id}
         If the token is not valid an exception is raised.
        """
        if not token:
            return

        try:
            token_info = self.keystone.tokens.validate(token=token)
            ses = {
                "_id": token_info["auth_token"],
                "id": token_info["auth_token"],
                "project_id": token_info["project"]["id"],
                "project_name": token_info["project"]["name"],
                "user_id": token_info["user"]["id"],
                "username": token_info["user"]["name"],
                "roles": token_info["roles"],
                "expires": token_info.expires.timestamp(),
                "issued_at": token_info.issued.timestamp()
            }

            return ses
        except ClientException as e:
            # self.logger.exception("Error during token validation using keystone: {}".format(e))
            raise AuthException("Error during token validation using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def revoke_token(self, token):
        """
        Invalidate a token.

        :param token: token to be revoked
        """
        try:
            self.logger.info("Revoking token: " + token)
            self.keystone.tokens.revoke_token(token=token)

            return True
        except ClientException as e:
            # self.logger.exception("Error during token revocation using keystone: {}".format(e))
            raise AuthException("Error during token revocation using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def _get_domain_id(self, domain_name, fail_if_not_found=True):
        """
        Get the domain id from  the domain_name
        :param domain_name: Can be the name or id
        :param fail_if_not_found: If False it returns None instead of raising an exception if not found
        :return: str or None/exception if domain is not found
        """
        domain_id = self.domains_name2id.get(domain_name)
        if not domain_id:
            self._get_domains()
            domain_id = self.domains_name2id.get(domain_name)
        if not domain_id and domain_name in self.domains_id2name:
            # domain_name is already an id
            return domain_name
        if not domain_id and fail_if_not_found:
            raise AuthconnNotFoundException("Domain {} cannot be found".format(domain_name))
        return domain_id

    def _get_domains(self):
        """
        Obtain a dictionary with domain_id to domain_name, stored at self.domains_id2name
        and from domain_name to domain_id, sored at self.domains_name2id
        :return: None. Exceptions are ignored
        """
        try:
            domains = self.keystone.domains.list()
            self.domains_id2name = {x.id: x.name for x in domains}
            self.domains_name2id = {x.name: x.id for x in domains}
        except Exception:
            pass

    def create_user(self, user_info):
        """
        Create a user.

        :param user_info: full user info.
        :raises AuthconnOperationException: if user creation failed.
        :return: returns the id of the user in keystone.
        """
        try:

            if user_info.get("domain_name") and user_info["domain_name"] in self.user_domain_ro_list:
                raise AuthconnConflictException("Cannot create a user in the read only domain {}".
                                                format(user_info["domain_name"]))

            new_user = self.keystone.users.create(
                user_info["username"], password=user_info["password"],
                domain=self._get_domain_id(user_info.get("domain_name", self.user_domain_name_list[0])),
                _admin=user_info["_admin"])
            if "project_role_mappings" in user_info.keys():
                for mapping in user_info["project_role_mappings"]:
                    self.assign_role_to_user(new_user, mapping["project"], mapping["role"])
            return {"username": new_user.name, "_id": new_user.id}
        except Conflict as e:
            # self.logger.exception("Error during user creation using keystone: {}".format(e))
            raise AuthconnOperationException(e, http_code=HTTPStatus.CONFLICT)
        except ClientException as e:
            # self.logger.exception("Error during user creation using keystone: {}".format(e))
            raise AuthconnOperationException("Error during user creation using Keystone: {}".format(e))

    def update_user(self, user_info):
        """
        Change the user name and/or password.

        :param user_info: user info modifications
        :raises AuthconnOperationException: if change failed.
        """
        try:
            user = user_info.get("_id") or user_info.get("username")
            try:
                user_obj = self.keystone.users.get(user)
            except Exception:
                user_obj = None
            if not user_obj:
                for user_domain in self.user_domain_name_list:
                    domain_id = self._get_domain_id(user_domain, fail_if_not_found=False)
                    if not domain_id:
                        continue
                    user_obj_list = self.keystone.users.list(name=user, domain=domain_id)
                    if user_obj_list:
                        user_obj = user_obj_list[0]
                        break
                else:   # user not found
                    raise AuthconnNotFoundException("User '{}' not found".format(user))

            user_id = user_obj.id
            domain_id = user_obj.domain_id
            domain_name = self.domains_id2name.get(domain_id)

            if domain_name in self.user_domain_ro_list:
                if user_info.get("password") or user_info.get("username"):
                    raise AuthconnConflictException("Cannot update the user {} belonging to a read only domain {}".
                                                    format(user, domain_name))

            elif user_info.get("password") or user_info.get("username") \
                    or user_info.get("add_project_role_mappings") or user_info.get("remove_project_role_mappings"):
                # if user_index>0, it is an external domain, that should not be updated
                ctime = user_obj._admin.get("created", 0) if hasattr(user_obj, "_admin") else 0
                self.keystone.users.update(user_id, password=user_info.get("password"), name=user_info.get("username"),
                                           _admin={"created": ctime, "modified": time.time()})

            for mapping in user_info.get("remove_project_role_mappings", []):
                self.remove_role_from_user(user_obj, mapping["project"], mapping["role"])
            for mapping in user_info.get("add_project_role_mappings", []):
                self.assign_role_to_user(user_obj, mapping["project"], mapping["role"])
        except ClientException as e:
            # self.logger.exception("Error during user password/name update using keystone: {}".format(e))
            raise AuthconnOperationException("Error during user update using Keystone: {}".format(e))

    def delete_user(self, user_id):
        """
        Delete user.

        :param user_id: user identifier.
        :raises AuthconnOperationException: if user deletion failed.
        """
        try:
            user_obj = self.keystone.users.get(user_id)
            domain_id = user_obj.domain_id
            domain_name = self.domains_id2name.get(domain_id)
            if domain_name in self.user_domain_ro_list:
                raise AuthconnConflictException("Cannot delete user {} belonging to a read only domain {}".
                                                format(user_id, domain_name))

            result, detail = self.keystone.users.delete(user_id)
            if result.status_code != 204:
                raise ClientException("error {} {}".format(result.status_code, detail))
            return True
        except ClientException as e:
            # self.logger.exception("Error during user deletion using keystone: {}".format(e))
            raise AuthconnOperationException("Error during user deletion using Keystone: {}".format(e))

    def get_user_list(self, filter_q=None):
        """
        Get user list.

        :param filter_q: dictionary to filter user list by one or several
            _id:
            name (username is also admitted).  If a user id is equal to the filter name, it is also provided
            domain_id, domain_name
        :return: returns a list of users.
        """
        try:
            self._get_domains()
            filter_name = filter_domain = None
            if filter_q:
                filter_name = filter_q.get("name") or filter_q.get("username")
                if filter_q.get("domain_name"):
                    filter_domain = self._get_domain_id(filter_q["domain_name"], fail_if_not_found=False)
                    # If domain is not found, use the same name to obtain an empty list
                    filter_domain = filter_domain or filter_q["domain_name"]
                if filter_q.get("domain_id"):
                    filter_domain = filter_q["domain_id"]

            users = self.keystone.users.list(name=filter_name, domain=filter_domain)
            # get users from user_domain_name_list[1:], because it will not be provided in case of LDAP
            if filter_domain is None and len(self.user_domain_name_list) > 1:
                for user_domain in self.user_domain_name_list[1:]:
                    domain_id = self._get_domain_id(user_domain, fail_if_not_found=False)
                    if not domain_id:
                        continue
                    # find if users of this domain are already provided. In this case ignore
                    for u in users:
                        if u.domain_id == domain_id:
                            break
                    else:
                        users += self.keystone.users.list(name=filter_name, domain=domain_id)

            # if filter name matches a user id, provide it also
            if filter_name:
                try:
                    user_obj = self.keystone.users.get(filter_name)
                    if user_obj not in users:
                        users.append(user_obj)
                except Exception:
                    pass

            users = [{
                "username": user.name,
                "_id": user.id,
                "id": user.id,
                "_admin": user.to_dict().get("_admin", {}),   # TODO: REVISE
                "domain_name": self.domains_id2name.get(user.domain_id)
            } for user in users if user.name != self.admin_username]

            if filter_q and filter_q.get("_id"):
                users = [user for user in users if filter_q["_id"] == user["_id"]]

            for user in users:
                user["project_role_mappings"] = []
                user["projects"] = []
                projects = self.keystone.projects.list(user=user["_id"])
                for project in projects:
                    user["projects"].append(project.name)

                    roles = self.keystone.roles.list(user=user["_id"], project=project.id)
                    for role in roles:
                        prm = {
                            "project": project.id,
                            "project_name": project.name,
                            "role_name": role.name,
                            "role": role.id,
                        }
                        user["project_role_mappings"].append(prm)

            return users
        except ClientException as e:
            # self.logger.exception("Error during user listing using keystone: {}".format(e))
            raise AuthconnOperationException("Error during user listing using Keystone: {}".format(e))

    def get_role_list(self, filter_q=None):
        """
        Get role list.

        :param filter_q: dictionary to filter role list by _id and/or name.
        :return: returns the list of roles.
        """
        try:
            filter_name = None
            if filter_q:
                filter_name = filter_q.get("name")
            roles_list = self.keystone.roles.list(name=filter_name)

            roles = [{
                "name": role.name,
                "_id": role.id,
                "_admin": role.to_dict().get("_admin", {}),
                "permissions": role.to_dict().get("permissions", {})
            } for role in roles_list if role.name != "service"]

            if filter_q and filter_q.get("_id"):
                roles = [role for role in roles if filter_q["_id"] == role["_id"]]

            return roles
        except ClientException as e:
            # self.logger.exception("Error during user role listing using keystone: {}".format(e))
            raise AuthException("Error during user role listing using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def create_role(self, role_info):
        """
        Create a role.

        :param role_info: full role info.
        :raises AuthconnOperationException: if role creation failed.
        """
        try:
            result = self.keystone.roles.create(role_info["name"], permissions=role_info.get("permissions"),
                                                _admin=role_info.get("_admin"))
            return result.id
        except Conflict as ex:
            raise AuthconnConflictException(str(ex))
        except ClientException as e:
            # self.logger.exception("Error during role creation using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role creation using Keystone: {}".format(e))

    def delete_role(self, role_id):
        """
        Delete a role.

        :param role_id: role identifier.
        :raises AuthconnOperationException: if role deletion failed.
        """
        try:
            result, detail = self.keystone.roles.delete(role_id)

            if result.status_code != 204:
                raise ClientException("error {} {}".format(result.status_code, detail))

            return True
        except ClientException as e:
            # self.logger.exception("Error during role deletion using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role deletion using Keystone: {}".format(e))

    def update_role(self, role_info):
        """
        Change the name of a role
        :param role_info: full role info
        :return: None
        """
        try:
            rid = role_info["_id"]
            if not is_valid_uuid(rid):   # Is this required?
                role_obj_list = self.keystone.roles.list(name=rid)
                if not role_obj_list:
                    raise AuthconnNotFoundException("Role '{}' not found".format(rid))
                rid = role_obj_list[0].id
            self.keystone.roles.update(rid, name=role_info["name"], permissions=role_info.get("permissions"),
                                       _admin=role_info.get("_admin"))
        except ClientException as e:
            # self.logger.exception("Error during role update using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role updating using Keystone: {}".format(e))

    def get_project_list(self, filter_q=None):
        """
        Get all the projects.

        :param filter_q: dictionary to filter project list.
        :return: list of projects
        """
        try:
            self._get_domains()
            filter_name = filter_domain = None
            if filter_q:
                filter_name = filter_q.get("name")
                if filter_q.get("domain_name"):
                    filter_domain = self.domains_name2id.get(filter_q["domain_name"])
                if filter_q.get("domain_id"):
                    filter_domain = filter_q["domain_id"]

            projects = self.keystone.projects.list(name=filter_name, domain=filter_domain)

            projects = [{
                "name": project.name,
                "_id": project.id,
                "_admin": project.to_dict().get("_admin", {}),  # TODO: REVISE
                "quotas": project.to_dict().get("quotas", {}),  # TODO: REVISE
                "domain_name": self.domains_id2name.get(project.domain_id)
            } for project in projects]

            if filter_q and filter_q.get("_id"):
                projects = [project for project in projects
                            if filter_q["_id"] == project["_id"]]

            return projects
        except ClientException as e:
            # self.logger.exception("Error during user project listing using keystone: {}".format(e))
            raise AuthException("Error during user project listing using Keystone: {}".format(e),
                                http_code=HTTPStatus.UNAUTHORIZED)

    def create_project(self, project_info):
        """
        Create a project.

        :param project_info: full project info.
        :return: the internal id of the created project
        :raises AuthconnOperationException: if project creation failed.
        """
        try:
            result = self.keystone.projects.create(
                project_info["name"],
                domain=self._get_domain_id(project_info.get("domain_name", self.project_domain_name_list[0])),
                _admin=project_info["_admin"],
                quotas=project_info.get("quotas", {})
            )
            return result.id
        except ClientException as e:
            # self.logger.exception("Error during project creation using keystone: {}".format(e))
            raise AuthconnOperationException("Error during project creation using Keystone: {}".format(e))

    def delete_project(self, project_id):
        """
        Delete a project.

        :param project_id: project identifier.
        :raises AuthconnOperationException: if project deletion failed.
        """
        try:
            # projects = self.keystone.projects.list()
            # project_obj = [project for project in projects if project.id == project_id][0]
            # result, _ = self.keystone.projects.delete(project_obj)

            result, detail = self.keystone.projects.delete(project_id)
            if result.status_code != 204:
                raise ClientException("error {} {}".format(result.status_code, detail))

            return True
        except ClientException as e:
            # self.logger.exception("Error during project deletion using keystone: {}".format(e))
            raise AuthconnOperationException("Error during project deletion using Keystone: {}".format(e))

    def update_project(self, project_id, project_info):
        """
        Change the name of a project
        :param project_id: project to be changed
        :param project_info: full project info
        :return: None
        """
        try:
            self.keystone.projects.update(project_id, name=project_info["name"],
                                          _admin=project_info["_admin"],
                                          quotas=project_info.get("quotas", {})
                                          )
        except ClientException as e:
            # self.logger.exception("Error during project update using keystone: {}".format(e))
            raise AuthconnOperationException("Error during project update using Keystone: {}".format(e))

    def assign_role_to_user(self, user_obj, project, role):
        """
        Assigning a role to a user in a project.

        :param user_obj: user object, obtained with keystone.users.get or list.
        :param project: project name.
        :param role: role name.
        :raises AuthconnOperationException: if role assignment failed.
        """
        try:
            try:
                project_obj = self.keystone.projects.get(project)
            except Exception:
                project_obj_list = self.keystone.projects.list(name=project)
                if not project_obj_list:
                    raise AuthconnNotFoundException("Project '{}' not found".format(project))
                project_obj = project_obj_list[0]

            try:
                role_obj = self.keystone.roles.get(role)
            except Exception:
                role_obj_list = self.keystone.roles.list(name=role)
                if not role_obj_list:
                    raise AuthconnNotFoundException("Role '{}' not found".format(role))
                role_obj = role_obj_list[0]

            self.keystone.roles.grant(role_obj, user=user_obj, project=project_obj)
        except ClientException as e:
            # self.logger.exception("Error during user role assignment using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role '{}' assignment to user '{}' and project '{}' using "
                                             "Keystone: {}".format(role, user_obj.name, project, e))

    def remove_role_from_user(self, user_obj, project, role):
        """
        Remove a role from a user in a project.

        :param user_obj: user object, obtained with keystone.users.get or list.
        :param project: project name or id.
        :param role: role name or id.

        :raises AuthconnOperationException: if role assignment revocation failed.
        """
        try:
            try:
                project_obj = self.keystone.projects.get(project)
            except Exception:
                project_obj_list = self.keystone.projects.list(name=project)
                if not project_obj_list:
                    raise AuthconnNotFoundException("Project '{}' not found".format(project))
                project_obj = project_obj_list[0]

            try:
                role_obj = self.keystone.roles.get(role)
            except Exception:
                role_obj_list = self.keystone.roles.list(name=role)
                if not role_obj_list:
                    raise AuthconnNotFoundException("Role '{}' not found".format(role))
                role_obj = role_obj_list[0]

            self.keystone.roles.revoke(role_obj, user=user_obj, project=project_obj)
        except ClientException as e:
            # self.logger.exception("Error during user role revocation using keystone: {}".format(e))
            raise AuthconnOperationException("Error during role '{}' revocation to user '{}' and project '{}' using "
                                             "Keystone: {}".format(role, user_obj.name, project, e))
