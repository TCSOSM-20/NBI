# Copyright 2020 Preethika P(Tata Elxsi)
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

import requests
from osm_nbi.base_topic import BaseTopic, EngineException
from osm_nbi.validation import subscription
from http import HTTPStatus


class CommonSubscriptions(BaseTopic):
    topic = "subscriptions"
    topic_msg = None

    def format_subscription(self, subs_data):
        """
        Brings lexicographical order for list items at any nested level. For subscriptions max level of nesting is 4.
        :param subs_data: Subscription data to be ordered.
        :return: None
        """
        if isinstance(subs_data, dict):
            for key in subs_data.keys():
                # Base case
                if isinstance(subs_data[key], list):
                    subs_data[key].sort()
                    return
                # Recursive case
                self.format_subscription(subs_data[key])
        return

    def check_conflict_on_new(self, session, content):
        """
        Two subscriptions are equal if Auth username, CallbackUri and filter are same.
        :param session: Session object.
        :param content: Subscription data.
        :return: None if no conflict otherwise, raises an exception.
        """
        # Get all subscriptions from db table subscriptions and compare.
        self.format_subscription(content)
        filter_dict = {"CallbackUri": content["CallbackUri"]}
        if content.get("authentication"):
            if content["authentication"].get("authType") == "basic":
                filter_dict["authentication.authType"] = "basic"
            # elif add other authTypes here
        else:
            filter_dict["authentication"] = None  # For Items without authentication
        existing_subscriptions = self.db.get_list("subscriptions", q_filter=filter_dict)
        new_sub_pwd = None
        if content.get("authentication") and content["authentication"].get("authType") == "basic":
            new_sub_pwd = content["authentication"]["paramsBasic"]["password"]
            content["authentication"]["paramsBasic"].pop("password", None)
        for existing_subscription in existing_subscriptions:
            sub_id = existing_subscription.pop("_id", None)
            existing_subscription.pop("_admin", None)
            existing_subscription.pop("schema_version", None)
            if existing_subscription.get("authentication") and \
                    existing_subscription["authentication"].get("authType") == "basic":
                existing_subscription["authentication"]["paramsBasic"].pop("password", None)
            # self.logger.debug(existing_subscription)
            if existing_subscription == content:
                raise EngineException("Subscription already exists with id: {}".format(sub_id),
                                      HTTPStatus.CONFLICT)
        if new_sub_pwd:
            content["authentication"]["paramsBasic"]["password"] = new_sub_pwd
        return

    def format_on_new(self, content, project_id=None, make_public=False):
        super().format_on_new(content, project_id=project_id, make_public=make_public)

        # TODO check how to release Engine.write_lock during the check
        def _check_endpoint(url, auth):
            """
            Checks if the notification endpoint is valid
            :param url: the notification end
            :param auth: contains the authentication details with type basic
            """
            try:
                if auth is None:
                    response = requests.get(url, timeout=5)
                    if response.status_code != HTTPStatus.NO_CONTENT:
                        raise EngineException("Cannot access to the notification URL '{}',received {}: {}"
                                              .format(url, response.status_code, response.content))
                elif auth["authType"] == "basic":
                    username = auth["paramsBasic"].get("userName")
                    password = auth["paramsBasic"].get("password")
                    response = requests.get(url, auth=(username, password), timeout=5)
                    if response.status_code != HTTPStatus.NO_CONTENT:
                        raise EngineException("Cannot access to the notification URL '{}',received {}: {}"
                                              .format(url, response.status_code, response.content))
            except requests.exceptions.RequestException as e:
                error_text = type(e).__name__ + ": " + str(e)
                raise EngineException("Cannot access to the notification URL '{}': {}".format(url, error_text))

        url = content["CallbackUri"]
        auth = content.get("authentication")
        _check_endpoint(url, auth)
        content["schema_version"] = schema_version = "1.1"
        if auth is not None and auth["authType"] == "basic":
            if content["authentication"]["paramsBasic"].get("password"):
                content["authentication"]["paramsBasic"]["password"] = \
                    self.db.encrypt(content["authentication"]["paramsBasic"]["password"],
                                    schema_version=schema_version, salt=content["_id"])
        return None

    def new(self, rollback, session, indata=None, kwargs=None, headers=None):
        """
        Uses BaseTopic.new to create entry into db
        Once entry is made into subscriptions,mapper function is invoked
        """
        _id, op_id = BaseTopic.new(self, rollback, session, indata=indata, kwargs=kwargs, headers=headers)
        rollback.append({"topic": "mapped_subscriptions", "operation": "del_list", "filter": {"reference": _id}})
        self._subscription_mapper(_id, indata, table="mapped_subscriptions")
        return _id, op_id

    def delete_extra(self, session, _id, db_content, not_send_msg=None):
        """
        Deletes the mapped_subscription entry for this particular subscriber
        :param _id: subscription_id deleted
        """
        super().delete_extra(session, _id, db_content, not_send_msg)
        filter_q = {"reference": _id}
        self.db.del_list("mapped_subscriptions", filter_q)


class NslcmSubscriptionsTopic(CommonSubscriptions):
    schema_new = subscription

    def _subscription_mapper(self, _id, data, table):
        """
        Performs data transformation on subscription request
        :param data: data to be trasformed
        :param table: table in which transformed data are inserted
        """
        formatted_data = []
        formed_data = {"reference": data.get("_id"),
                       "CallbackUri": data.get("CallbackUri")}
        if data.get("authentication"):
            formed_data.update({"authentication": data.get("authentication")})
        if data.get("filter"):
            if data["filter"].get("nsInstanceSubscriptionFilter"):
                key = list(data["filter"]["nsInstanceSubscriptionFilter"].keys())[0]
                identifier = data["filter"]["nsInstanceSubscriptionFilter"][key]
                formed_data.update({"identifier": identifier})
            if data["filter"].get("notificationTypes"):
                for elem in data["filter"].get("notificationTypes"):
                    update_dict = formed_data.copy()
                    update_dict["notificationType"] = elem
                    if elem == "NsIdentifierCreationNotification":
                        update_dict["operationTypes"] = "INSTANTIATE"
                        update_dict["operationStates"] = "ANY"
                        formatted_data.append(update_dict)
                    elif elem == "NsIdentifierDeletionNotification":
                        update_dict["operationTypes"] = "TERMINATE"
                        update_dict["operationStates"] = "ANY"
                        formatted_data.append(update_dict)
                    elif elem == "NsLcmOperationOccurrenceNotification":
                        if "operationTypes" in data["filter"].keys():
                            update_dict["operationTypes"] = data["filter"]["operationTypes"]
                        else:
                            update_dict["operationTypes"] = "ANY"
                        if "operationStates" in data["filter"].keys():
                            update_dict["operationStates"] = data["filter"]["operationStates"]
                        else:
                            update_dict["operationStates"] = "ANY"
                        formatted_data.append(update_dict)
                    elif elem == "NsChangeNotification":
                        if "nsComponentTypes" in data["filter"].keys():
                            update_dict["nsComponentTypes"] = data["filter"]["nsComponentTypes"]
                        else:
                            update_dict["nsComponentTypes"] = "ANY"
                        if "lcmOpNameImpactingNsComponent" in data["filter"].keys():
                            update_dict["lcmOpNameImpactingNsComponent"] = \
                                data["filter"]["lcmOpNameImpactingNsComponent"]
                        else:
                            update_dict["lcmOpNameImpactingNsComponent"] = "ANY"
                        if "lcmOpOccStatusImpactingNsComponent" in data["filter"].keys():
                            update_dict["lcmOpOccStatusImpactingNsComponent"] = \
                                data["filter"]["lcmOpOccStatusImpactingNsComponent"]
                        else:
                            update_dict["lcmOpOccStatusImpactingNsComponent"] = "ANY"
                        formatted_data.append(update_dict)
        self.db.create_list(table, formatted_data)
        return None
