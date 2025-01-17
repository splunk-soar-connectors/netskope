# File: netskope_connector.py
#
# Copyright 2018-2025 Netskope, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime
from urllib.parse import urlparse

import phantom.app as phantom
import phantom.rules as phantom_rules
import requests
from bs4 import BeautifulSoup
from phantom import vault
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from netskope_consts import *
from netskope_utilities import KennyLoggins, logging


class RetVal(tuple):
    """RetVal class"""

    def __new__(cls, val1, val2=None):
        """Return tuple"""
        return tuple.__new__(RetVal, (val1, val2))


class NetskopeConnector(BaseConnector):
    """Connector class"""

    def __init__(self):
        """Construct an instance of the connector class"""
        super(NetskopeConnector, self).__init__()
        self._state = None
        self._file_list = NETSKOPE_FILE_LIST
        self._url_list = NETSKOPE_URL_LIST
        self._server_url = None
        self._api_key = None
        self._v2_api_key = None
        self._tenant = None
        self._list_name = None
        self._scim = {"url": "", "token": ""}
        kl = KennyLoggins()
        self._log = kl.get_logger(app_name="phnetskope", file_name="connector", log_level=logging.DEBUG, version="3.0.0")
        self._log.info("initialize_client=complete")

    def _dump_error_log(self, error, message="Exception occurred."):
        self.error_print(message, dump_object=error)

    def _get_error_message_from_exception(self, e):
        """Return appropriate error message from the exception.

        :param e: Exception object
        :return: error message
        """
        error_code = NETSKOPE_ERR_CODE_MSG
        error_msg = NETSKOPE_ERR_MSG
        self._dump_error_log(e)
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as ex:
            self._dump_error_log(ex, "Error occurred while retrieving exception information")

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    @staticmethod
    def _process_empty_response(response, action_result):
        """Process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        if response.status_code >= 200 and response.status_code < 300:
            return RetVal(phantom.APP_SUCCESS, {})
        else:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    (
                        "Empty response and no information in the header. \
                           Status Code: {0}"
                    ).format(response.status_code),
                ),
                None,
            )

    @staticmethod
    def _process_html_response(response, action_result):
        """Process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        status_code = response.status_code
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = ("\n").join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)
        message = message.replace("{", "{{").replace("}", "}}")
        if len(message) > 500:
            message = NETSKOPE_ERR_CONNECTING_SERVER
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """Process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(self._get_error_message_from_exception(e))
                ),
                None,
            )

        if 200 <= response.status_code < 399 and isinstance(resp_json, dict) and resp_json.get("status", "") == "error":
            error_message = response.text.replace("{", "{{").replace("}", "}}")
            if resp_json.get("errors") and isinstance(resp_json["errors"], list):
                error_message = " ".join(resp_json["errors"])
            elif resp_json.get("errors"):
                error_message = resp_json["errors"]

            message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code, error_message)
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)
        else:
            if 200 <= response.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, resp_json)

            if response.status_code == 400 and self.get_action_identifier() == "update_url_list":
                return RetVal(phantom.APP_ERROR, resp_json)

            error_message = response.text.replace("{", "{{").replace("}", "}}")
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), None)

    def _process_response(self, response, action_result):
        """Process response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        try:
            if hasattr(action_result, "add_debug_data") and (
                self.get_action_identifier() != "get_file" or not 200 <= response.status_code < 399
            ):  # noqa: E501
                action_result.add_debug_data({"r_status_code": response.status_code})
                action_result.add_debug_data({"r_text": response.text})
                action_result.add_debug_data({"r_headers": response.headers})

            if "json" in response.headers.get("Content-Type", ""):
                self._log.info("action=process_json_response")
                return self._process_json_response(response, action_result)

            if "html" in response.headers.get("Content-Type", ""):
                self._log.info("action=process_html_response")
                return self._process_html_response(response, action_result)

            if not response.text:
                self._log.info("action=process_empty_response")
                return self._process_empty_response(response, action_result)

            error_message = response.text.replace("{", "{{").replace("}", "}}")
            message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(response.status_code, error_message)
            self._log.error(message)
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            _, _, exc_tb = sys.exc_info()
            self._log.info("exception_line={0} {1}".format(exc_tb.tb_lineno, error_msg))
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error: {0}".format(error_msg)), None)

    def _make_scim_rest_call(self, endpoint, action_result, params=None, timeout=60, method="get"):
        """Make the SCIM REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param params: request  parameters
        :param timeout: wait for REST call to complete
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        try:
            resp_json = None
            requests_response = None
            if not params:
                params = {}

            config = self.get_config()
            self._log.info("config={0} params={1} timeout={2}".format(config, params, timeout))

            if config.get(NETSKOPE_CONFIG_SCIM_URL) and config.get(NETSKOPE_CONFIG_SCIM_KEY):
                try:
                    self._scim["url"] = config.get(NETSKOPE_CONFIG_SCIM_URL).strip("/")
                    self._scim["token"] = config.get(NETSKOPE_CONFIG_SCIM_KEY)
                except Exception as e:
                    error_msg = self._get_error_message_from_exception(e)
                    self.error_print("Error while encoding server URL")
                    return RetVal(
                        action_result.set_status(
                            phantom.APP_ERROR,
                            (
                                "Error while encoding server \
                                   URL: {0}"
                            ).format(error_msg),
                        ),
                        resp_json,
                    )
            else:
                self.debug_print("Please configure both 'SCIM Server URL' and 'SCIM Token' in asset settings to execute this action")
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR,
                        "Please configure both 'SCIM Server URL' and 'SCIM Token' \
                               in asset settings to execute this action",
                    ),
                    resp_json,
                )

            try:
                request_func = getattr(requests, method)
            except AttributeError:
                self._log.error("action=failed invalid_method={0}".format(method))
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

            url = "{server_url}{endpoint}".format(server_url=self._scim["url"], endpoint=endpoint)
            headers = {"Authorization": "Bearer {0}".format(self._scim["token"])}
            if method == "post" or method == "patch":
                headers["Content-Type"] = "application/scim+json"

            self._log.info(
                "action=make_scim_rest method={0} url={1} params={2} \
                             function={3}".format(
                    method, url, json.dumps(params), request_func
                )
            )
            temp_file_path = "{dir}{asset}_temp_file".format(dir=self.get_state_dir(), asset=self.get_asset_id())

            try:
                if method == "get":
                    requests_response = request_func(url, headers=headers, params=params, timeout=timeout)
                else:
                    requests_response = request_func(url, headers=headers, data=json.dumps(params), timeout=timeout)
            except requests.exceptions.InvalidURL:
                err = "Error connecting to server. Invalid URL {0}".format(url)
                return RetVal(action_result.set_status(phantom.APP_ERROR, err), resp_json)
            except Exception as err:
                error_msg = self._get_error_message_from_exception(err)

                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)

                self._log.error("action=failed exception={0}".format(error_msg))
                message = "Error connecting to server. Details: {0}".format(error_msg)
                if "token=" in err:
                    message = "Error while connecting to the server"

                self._log.info("action=failed response={0}".format(resp_json))
                return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

            self._log.info("action=returning_success result={0} response={1}".format(action_result, requests_response))
            return self._process_response(requests_response, action_result)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            _, _, exc_tb = sys.exc_info()
            self._log.info("exception_line={0} {1}".format(exc_tb.tb_lineno, error_msg))
            return self._process_response(requests_response, action_result)

    def _make_rest_call(self, endpoint, action_result, method="get", params=None, data=None, timeout=None):
        """Make the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param method: method type to make REST call with
        :param params: request parameters
        :param data: data to send in the request body
        :param timeout: wait for REST call to complete
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        action = self.get_action_identifier()
        v2_supported_actions_list = ["run_query", "update_url_list"]
        only_v1_supported_actions_list = ["list_files", "get_file", "update_file_list"]

        if action in v2_supported_actions_list and not (self._v2_api_key or self._api_key):
            return RetVal(action_result.set_status(phantom.APP_ERROR, NETSKOPE_MISSING_BOTH_API_KEYS_ERR), None)

        if action in only_v1_supported_actions_list and not self._api_key:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Please configure 'v1 API Key' in the asset"), None)

        resp_json = None
        headers = None
        if not params:
            params = {}
        config = self.get_config()

        try:
            self._server_url = config[NETSKOPE_CONFIG_SERVER_URL].strip("/")
            self._tenant = self._server_url.split("//")[1]
            self._log.info("tenant={0}".format(self._tenant))
        except Exception as ex:
            self.error_print("Error while initializing server URL and basic connection parameters from the asset configuration")
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error while initializing server URL and basic \
                           connection parameters from the asset configuration, Error: {}".format(
                        self._get_error_message_from_exception(ex)
                    ),
                ),
                resp_json,
            )

        # v2 REST endpoints need API token in request header whereas
        # token is provided in request params in case of v1 REST endpoints
        if NETSKOPE_V2_API_PREFIX in endpoint:
            headers = {"Netskope-Api-Token": self._v2_api_key}
        else:
            params.update({"token": self._api_key})

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        url = "{server_url}{endpoint}".format(server_url=self._server_url, endpoint=endpoint)
        self._log.info("action=make_rest url={0} params={1}".format(url, json.dumps(params)))
        temp_file_path = "{dir}{asset}_temp_file".format(dir=self.get_state_dir(), asset=self.get_asset_id())

        try:
            # for the get_file action fetch the file data in stream and store the same in the Splunk SOAR
            if action == "get_file" and params.get("op", "") == "download-url":
                with request_func(url, params=params, timeout=timeout, stream=True) as (requests_response):
                    error_response_expr = (
                        "json" in requests_response.headers.get("Content-Type", "") and requests_response.json().get("error", "") == "error"
                    )

                    if 200 <= requests_response.status_code < 399 and not error_response_expr:
                        with open(temp_file_path, "wb") as (temp_file):
                            for chunk in requests_response.iter_content(chunk_size=1024):
                                if chunk:
                                    temp_file.write(chunk)
                        return RetVal(phantom.APP_SUCCESS, resp_json)
            elif method in ["patch", "post"]:
                requests_response = request_func(url, headers=headers, params=params, json=data, timeout=timeout)
            else:
                requests_response = request_func(url, headers=headers, params=params, timeout=timeout)
        except requests.exceptions.ConnectionError as e:
            error_msg = self._get_error_message_from_exception(e)
            message = "Error Details: Connection Refused from the Server. {0}".format(error_msg)
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)
        except requests.exceptions.InvalidURL:
            err = "Error connecting to server. Invalid URL {0}".format(url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, err), resp_json)
        except Exception as err:
            error_msg = self._get_error_message_from_exception(err)

            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

            message = "Error connecting to server. Details: {0}".format(error_msg)
            if "token=" in err:
                message = "Error while connecting to the server"

            return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

        return self._process_response(requests_response, action_result)

    def _handle_test_connectivity(self, param):
        """Handle the test connectivity.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        request_param = {"limit": NETSKOPE_TEST_CONNECTIVITY_LIMIT}

        # Checking connectivity for v1 API if v1 api key provided
        if self._api_key:
            self.save_progress(NETSKOPE_CONNECTION_MSG)
            ret_val, _ = self._make_rest_call(
                endpoint=NETSKOPE_CONNECTIVITY_ENDPOINT, action_result=action_result, params=request_param, timeout=30
            )

            if phantom.is_fail(ret_val):
                self.save_progress(NETSKOPE_CONNECTIVITY_FAIL_MSG)
                self.save_progress(action_result.get_message())
            else:
                self.save_progress(NETSKOPE_CONNECTIVITY_PASS_MSG)

        # Checking connectivity for v2 API if v2 api key provided
        if self._v2_api_key:
            self.save_progress(NETSKOPE_V2_KEY_FOUND_MSG)
            self.save_progress(NETSKOPE_V2_CONNECTION_MSG)
            current_time = int(time.time())
            request_param.update({"starttime": current_time - NETSKOPE_24_HOUR_GAP, "endtime": current_time})
            ret_val, _ = self._make_rest_call(
                endpoint="{0}/{1}".format(NETSKOPE_V2_EVENT_ENDPOINT, NETSKOPE_PAGE_EVENT),
                action_result=action_result,
                params=request_param,
                timeout=30,
            )

            if phantom.is_fail(ret_val):
                self.save_progress(NETSKOPE_V2_CONNECTIVITY_FAIL_MSG)
                return action_result.get_status()

            self.save_progress(NETSKOPE_V2_CONNECTIVITY_PASS_MSG)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file(self, param):
        """Get quarantine files.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        file_param = param[NETSKOPE_JSON_FILE]
        profile_param = param[NETSKOPE_JSON_PROFILE]
        details_status, file_id, file_name, profile_id = self._get_file_and_profile_details(
            action_result=action_result, file_param=file_param, profile_param=profile_param
        )

        if phantom.is_fail(details_status):
            return action_result.get_status()

        request_param = {"op": "download-url", "file_id": file_id, "quarantine_profile_id": profile_id}
        self.save_progress("Downloading file")
        ret_val, _ = self._make_rest_call(endpoint=NETSKOPE_QUARANTINE_ENDPOINT, action_result=action_result, params=request_param)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        temp_file_path = "{dir}{asset}_temp_file".format(dir=self.get_state_dir(), asset=self.get_asset_id())
        generate_file_hash_status, file_hash = self._generate_file_hash(file_path=temp_file_path)

        if phantom.is_fail(generate_file_hash_status):
            return action_result.set_status(phantom.APP_ERROR, status_message="Downloaded file does not exist")

        try:
            success, message, vault_file_list = vault.vault_info(vault_id=file_hash, container_id=self.get_container_id())
            vault_file_list = list(vault_file_list)

            if not success:
                return action_result.set_status(phantom.APP_ERROR, message)

            for vault_file_item in vault_file_list:
                if vault_file_item["vault_id"] == file_hash and vault_file_item["name"] == file_name:
                    vault_id = vault_file_item["vault_id"]
                    break
            else:
                success, message, vault_add_file_dict = vault.vault_add(
                    container=self.get_container_id(), file_location=temp_file_path, file_name=file_name
                )

                if not success:
                    return action_result.set_status(phantom.APP_ERROR, message)

                vault_id = vault_add_file_dict["vault_id"]
        except Exception as ex:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error occurred while fetching the vault details, Error: {}".format(self._get_error_message_from_exception(ex)),
            )

        action_result.add_data({"vault_id": vault_id, "file_name": file_name})
        summary = action_result.update_summary({})
        summary["vault_id"] = vault_id
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_file_and_profile_details(self, action_result, file_param, profile_param):
        """Get the file and profile details based on the input provided by user.

        :param action_result: Object of ActionResult class
        :param file_param: Input provided by the user (file id or file name)
        :param profile_param: Input provided by the user (profile param)
        :return: status (success, failure), file_id, file_name, profile_id
        """
        request_params = {"op": "get-files"}
        request_status, request_response = self._make_rest_call(
            endpoint=NETSKOPE_QUARANTINE_ENDPOINT, action_result=action_result, params=request_params
        )

        if phantom.is_fail(request_status):
            return action_result.get_status(), None, None, None
        else:
            if not request_response.get("data", {}).get("quarantined"):
                return action_result.set_status(phantom.APP_ERROR, status_message="No data found"), None, None, None

            # find and return the profile_id, file_name and file_id from the response
            for item in request_response["data"]["quarantined"]:
                # check for the file id and name only if profile matches the input data
                if (
                    item.get("quarantine_profile_id", "").lower() == profile_param.lower()
                    or item.get("quarantine_profile_name", "").lower() == profile_param.lower()
                ):  # noqa: E501
                    profile_id = item["quarantine_profile_id"]
                    for file_item in item.get("files", []):
                        if file_item["file_id"] == file_param or file_item["quarantined_file_name"].lower() == file_param.lower():
                            file_id = file_item["file_id"]
                            file_name = file_item["quarantined_file_name"]
                            return phantom.APP_SUCCESS, file_id, file_name, profile_id

            return action_result.set_status(phantom.APP_ERROR, status_message="No file or profile found"), None, None, None

    @staticmethod
    def _generate_file_hash(file_path):
        """Read file from the file_path and generate the sha1 hash for the file

        :param file_path: Location of the file
        :return: phantom.APP_SUCCESS/phantom.APP_ERROR, file_hash
        """
        if not os.path.exists(file_path):
            return phantom.APP_ERROR, None
        else:
            sha1_hash = hashlib.sha1()
            with open(file_path, "rb") as (file_obj):
                for chunk in iter(file_obj.read(1024)):
                    sha1_hash.update(chunk)

            sha1_hash = sha1_hash.hexdigest()
            return phantom.APP_SUCCESS, sha1_hash

    def _handle_list_files(self, param):
        """List quarantine files.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        params = {"op": NETSKOPE_PARAM_LIST_FILES}
        request_status, request_response = self._make_rest_call(
            endpoint=NETSKOPE_QUARANTINE_ENDPOINT, action_result=action_result, params=params
        )

        if phantom.is_fail(request_status):
            return action_result.get_status()

        if not request_response.get("data", {}).get("quarantined", []):
            return action_result.set_status(phantom.APP_ERROR, "No quarantine file data found")

        for quarantine_profile in request_response["data"]["quarantined"]:
            file_list = quarantine_profile.get("files", [])
            for file_info in file_list:
                file_info.update(
                    {
                        "quarantine_profile_id": quarantine_profile["quarantine_profile_id"],
                        "quarantine_profile_name": quarantine_profile["quarantine_profile_name"],
                    }
                )
                action_result.add_data(file_info)

        summary = action_result.update_summary({})
        summary["total_files"] = action_result.get_data_size()
        return action_result.set_status(phantom.APP_SUCCESS)

    def _verify_time(self, start_time, end_time):
        """Verify time parameters.

        :param start_time: start_time epoch
        :param end_time: end_time epoch
        :return: status success/failure with appropriate message
        """
        try:
            start_time = int(float(start_time))
        except Exception as ex:
            self._dump_error_log(ex, NETSKOPE_INVALID_START_TIME)
            return phantom.APP_ERROR, NETSKOPE_INVALID_START_TIME

        try:
            end_time = int(float(end_time))
        except Exception as ex:
            self._dump_error_log(ex, NETSKOPE_INVALID_END_TIME)
            return phantom.APP_ERROR, NETSKOPE_INVALID_END_TIME

        if start_time < 0 or end_time < 0:
            self.debug_print(NETSKOPE_INVALID_TIME)
            return phantom.APP_ERROR, NETSKOPE_INVALID_TIME

        if start_time >= end_time:
            self.debug_print(NETSKOPE_INVALID_TIME_RANGE)
            return phantom.APP_ERROR, NETSKOPE_INVALID_TIME_RANGE

        return phantom.APP_SUCCESS, NETSKOPE_VALID_TIME

    def _handle_run_query(self, param):
        """Run query against a given IP.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip = param[NETSKOPE_PARAM_IP]

        start_time = param.get(NETSKOPE_PARAM_START_TIME)
        if start_time and not isinstance(start_time, (float, int)):
            return action_result.set_status(phantom.APP_ERROR, NETSKOPE_INVALID_START_TIME)

        end_time = param.get(NETSKOPE_PARAM_END_TIME, time.time())
        if not isinstance(end_time, (float, int)):
            return action_result.set_status(phantom.APP_ERROR, NETSKOPE_INVALID_END_TIME)
        end_time = int(end_time)

        if not start_time:
            start_time = end_time - NETSKOPE_24_HOUR_GAP
        start_time = int(start_time)

        params = {"query": NETSKOPE_QUERY_PARAM.format(srcip=ip, dstip=ip)}

        if not self._v2_api_key:
            params.update({"type": "page"})
        time_status, time_response = self._verify_time(start_time, end_time)

        if phantom.is_fail(time_status):
            return action_result.set_status(phantom.APP_ERROR, time_response)

        params.update({"starttime": start_time, "endtime": end_time})
        event_details = {}
        page_event_endpoint = "{0}/{1}".format(NETSKOPE_V2_EVENT_ENDPOINT, NETSKOPE_PAGE_EVENT)
        ret_val, page_event_list = self._get_events(
            endpoint=page_event_endpoint if self._v2_api_key else NETSKOPE_EVENTS_ENDPOINT, action_result=action_result, params=params
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Failed to get 'page' events. Error: {0}".format(action_result.get_message()))

        if page_event_list:
            event_details["page"] = page_event_list

        if not self._v2_api_key:
            params.update({"type": "application"})

        application_event_endpoint = "{0}/{1}".format(NETSKOPE_V2_EVENT_ENDPOINT, NETSKOPE_APPLICATION_EVENT)
        ret_val, application_event_list = self._get_events(
            endpoint=application_event_endpoint if self._v2_api_key else NETSKOPE_EVENTS_ENDPOINT, action_result=action_result, params=params
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(
                phantom.APP_ERROR,
                (
                    "Failed to get 'application' events. \
                                                                Error: {0}"
                ).format(action_result.get_message()),
            )

        if application_event_list:
            event_details["application"] = application_event_list

        if not event_details:
            return action_result.set_status(phantom.APP_ERROR, status_message="No Data found")

        action_result.add_data(event_details)
        summary = action_result.update_summary({})
        summary["total_page_events"] = len(page_event_list)
        summary["total_application_events"] = len(application_event_list)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        """Handle on_poll.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))
        end_time = int(time.time())

        if self.is_poll_now() or self._state.get("first_run", True):
            start_time = end_time - NETSKOPE_24_HOUR_GAP
        else:
            start_time = self._state.get("last_ingestion_time", end_time - NETSKOPE_24_HOUR_GAP)

        self._log.info("action=get_poll start_time={0} end_time={1} container_count={2}".format(start_time, end_time, container_count))
        self.save_progress("Getting alerts data using {0} API key".format("v2" if self._v2_api_key else "v1"))
        request_params = {"starttime": start_time, "endtime": end_time}
        alert_event_endpoint = "{0}/{1}".format(NETSKOPE_V2_EVENT_ENDPOINT, NETSKOPE_ALERT_EVENT)
        response_status, alerts_list = self._get_events(
            endpoint=alert_event_endpoint if self._v2_api_key else NETSKOPE_ON_POLL_ENDPOINT,
            action_result=action_result,
            params=request_params,
            max_limit=container_count,
        )

        if phantom.is_fail(response_status):
            return action_result.get_status()

        if alerts_list:
            self.save_progress("Ingesting data")
        else:
            self.save_progress("No alerts found")

        for alert in alerts_list:
            container_id = self._create_container(alert)
            if not container_id:
                continue

            artifacts_creation_status, artifacts_creation_msg = self._create_artifacts(alert=alert, container_id=container_id)
            if phantom.is_fail(artifacts_creation_status):
                self.debug_print(
                    "Error while creating artifacts for container with ID {container_id}. {error_msg}".format(
                        container_id=container_id, error_msg=artifacts_creation_msg
                    )
                )

        self._state["first_run"] = False
        self._state["last_ingestion_time"] = end_time
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_events(self, endpoint, action_result, params, max_limit=None):
        """Get the list of events.

        :param endpoint: endpoint to fetch events from
        :param action_result: Object of ActionResult class
        :param params: request parameters
        :param max_limit: maximum events to fetch
        :return: status (success/failure), list of events
        """
        default_limit = NETSKOPE_DEFAULT_LIMIT
        events_list = []
        skip = NETSKOPE_INITIAL_SKIP_VALUE

        while True:
            # if max_limit is provided then only fetch that many events else fetch all the events
            if max_limit:
                if max_limit > default_limit:
                    limit = default_limit
                else:
                    limit = max_limit
            else:
                limit = default_limit

            params.update({"limit": limit, "offset" if self._v2_api_key else "skip": skip})
            request_status, request_response = self._make_rest_call(endpoint=endpoint, action_result=action_result, params=params)

            if phantom.is_fail(request_status):
                return action_result.get_status(), None

            events = request_response.get("result" if self._v2_api_key else "data", [])

            if not events:
                break

            events_list += events
            skip += limit

            # stop fetching events if max_limit is reached (if provided)
            if max_limit:
                max_limit -= limit
                if max_limit <= 0:
                    break

        return phantom.APP_SUCCESS, events_list

    def _create_container(self, alert):
        """Create the container in Phantom using alert data.

        :param alert: Data of single alert
        :return: container_id
        """
        container_dict = dict()
        self._log.info("alert={0}".format(json.dumps(alert)))
        container_dict["name"] = "{alert_name}-{id}-{type}".format(
            alert_name=alert["alert_name"], id=alert.get("_id", "unk-{0}".format(uuid.uuid4())), type=alert.get("alert_type", "unknown")
        )
        container_dict["source_data_identifier"] = container_dict["name"]
        container_dict["start_time"] = "{time}Z".format(time=datetime.utcfromtimestamp(alert["timestamp"]).isoformat())
        possible_tags = {
            "alert_type": alert.get("alert_type"),
            "category": alert.get("category"),
            "activity": alert.get("activity"),
            "type": alert.get("type"),
        }
        container_dict["tags"] = ["{0}={1}".format(x, possible_tags[x]) for x in possible_tags if possible_tags[x] is not None]
        container_creation_status, container_creation_msg, container_id = self.save_container(container=container_dict)

        if phantom.is_fail(container_creation_status):
            self.debug_print(container_creation_msg)
            self.save_progress(
                "Error while creating container for alert {alert_name}. {error_message}".format(
                    alert_name=alert["alert_name"], error_message=container_creation_msg
                )
            )
        else:
            return container_id

    def _create_artifacts(self, alert, container_id):
        """Create artifacts in given container using alert data.

        :param alert: Data of single alert
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """
        artifacts_list = []
        self._log.info("action=create_artifacts tenant={0} artifact={1}".format(self._tenant, json.dumps(alert)))
        artifacts_mapping = {
            "IP Artifact": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "Source IP": ("srcip", ["ip"]),
                "Destination IP": ("dstip", ["ip"]),
            },
            "Email Artifact": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "Email": ("user", ["email"]),
                "Source Email": ("from_user", ["email"]),
            },
            "URL Artifact": {"managementID": ("managementID", []), "nsdeviceuid": ("nsdeviceuid", []), "url": ("url", ["url"])},
            "User Artifact": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "userkey": ("userkey", ["user name"]),
                "user": ("user", ["user name"]),
                "from_user": ("from_user", ["user name"]),
            },
        }

        specific_alert_mapping = {
            "malsite": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "dstip": ("dstip", ["ip", "ipv4"]),
                "severity_level": ("severity_level", []),
                "browser_session_id": ("browser_session_id", []),
                "app": ("app", []),
                "object_type": ("object_type", []),
                "site": ("site", []),
                "malsite_id": ("malsite_id", []),
                "src_location": ("src_location", []),
                "browser_version": ("browser_version", []),
                "access_method": ("access_method", []),
                "app_session_id": ("app_session_id", []),
                "dst_location": ("dst_location", []),
                "category": ("category", ["category"]),
                "page_site": ("page_site", []),
                "severity": ("severity", []),
                "os_version": ("os_version", []),
                "ds_region": ("ds_region", []),
                "malicious": ("malicious", []),
                "userkey": ("userkey", ["user name"]),
                "managed_app": ("managed_app", []),
                "dst_country": ("dst_country", []),
                "ccl": ("ccl", []),
                "traffic_type": ("traffic_type", []),
                "type": ("type", []),
                "transaction_id": ("transaction_id", []),
                "malsite_region": ("malsite_region", []),
                "malsite_country": ("malsite_country", []),
                "timestamp": ("timestamp", []),
                "severity_level_id": ("severity_level_id", []),
                "src_region": ("src_region", []),
                "acked": ("acked", []),
                "alert": ("alert", []),
                "userip": ("userip", ["ip", "ipv4"]),
                "timer_metric_value": ("timer_metric_value", []),
                "telemetry_app": ("telemetry_app", []),
                "user": ("user", ["user name"]),
                "from_user": ("from_user", ["user name"]),
                "device": ("device", []),
                "src_country": ("src_country", []),
                "count": ("count", []),
                "_insertion_epoc_timestamp": ("_insertion_epoc_timestamp", []),
                "srcip": ("srcip", ["ip", "ipv4"]),
                "page_id": ("page_id", []),
                "malsite_ip_host": ("malsite_ip_host", ["ip", "ipv4"]),
                "malsite_category": ("malsite_category", ["category"]),
                "page": ("page", []),
                "instance_id": ("instance_id", []),
                "url": ("url", ["url"]),
                "alert_name": ("alert_name", []),
                "cci": ("cci", []),
                "thread_source_id": ("thread_source_id", []),
                "os": ("os", []),
                "thread_match_filed": ("thread_match_filed", []),
                "browser": ("browser", []),
                "appcategory": ("appcategory", ["category"]),
            },
            "malware": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "dstip": ("dstip", ["ip", "ipv4"]),
                "malware_type": ("malware_type", []),
                "app_name": ("app_name", []),
                "object": ("object", []),
                "file_type": ("file_type", []),
                "file_size": ("file_size", []),
                "app": ("app", []),
                "_insertion_epoc_timestamp": ("_insertion_epoc_timestamp", []),
                "local_sha256": ("local_sha256", ["hash", "sha256"]),
                "srcip": ("srcip", []),
                "detection_type": ("detection_type", []),
                "os_version": ("os_version", []),
                "device_classification": ("device_classification", []),
                "object_type": ("object_type", []),
                "local_md5": ("local_md5", ["hash", "md5"]),
                "user": ("user", ["user name"]),
                "action": ("action", []),
                "app_session_id": ("app_session_id", []),
                "browser_session_id": ("browser_session_id", []),
                "category": ("category", []),
                "tss_mode": ("tss_mode", []),
                "page_site": ("page_site", []),
                "severity": ("severity", ["severity"]),
                "dst_country": ("dst_country", []),
                "ns_detection_name": ("ns_detection_name", []),
                "dst_region": ("dst_region", []),
                "hostname": ("hostname", ["dvc"]),
                "managed_app": ("managed_app", []),
                "parent_id": ("parent_id", []),
                "device": ("device", []),
                "access_method": ("access_method", []),
                "traffic_type": ("traffic_type", []),
                "type": ("type", []),
                "transaction_id": ("transaction_id", []),
                "count": ("count", []),
                "detection_engine": ("detection_engine", []),
                "malware_id": ("malware_id", []),
                "timestamp": ("timestamp", []),
                "src_region": ("src_region", []),
                "severity_id": ("severity_id", []),
                "acked": ("acked", []),
                "site": ("site", []),
                "referer": ("referer", []),
                "file_id": ("file_id", []),
                "from_user": ("from_user", ["user name"]),
                "malware_profile": ("malware_profile", []),
                "user_id": ("user_id", ["user name"]),
                "src_country": ("src_country", []),
                "alert": ("alert", []),
                "malware_name": ("malware_name", []),
                "src_location": ("src_location", []),
                "dst_location": ("dst_location", []),
                "url": ("url", ["url"]),
                "page_id": ("page_id", []),
                "instance": ("instance", []),
                "instance_id": ("instance_id", []),
                "ccl": ("ccl", []),
                "cci": ("cci", []),
                "browser_version": ("browser_version", []),
                "activity": ("activity", []),
                "userip": ("userip", []),
                "userkey": ("userkey", ["user name"]),
                "browser": ("browser", []),
                "os": ("os", []),
                "appcategory": ("appcategory", ["category"]),
            },
            "dlp": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "dlp_incident_id": ("dlp_incident_id", []),
                "dstip": ("dstip", []),
                "dst_location": ("dst_location", []),
                "dlp_file": ("dlp_file", []),
                "file_type": ("file_type", ["file"]),
                "app": ("app", []),
                "_insertion_epoc_timestamp": ("_insertion_epoc_timestamp", []),
                "site": ("site", []),
                "src_location": ("src_location", []),
                "file_size": ("file_size", []),
                "owner": ("owner", ["user name"]),
                "activity": ("activity", []),
                "app_session_id": ("app_session_id", []),
                "category": ("category", ["category"]),
                "instance_id": ("instance_id", []),
                "os_version": ("os_version", []),
                "file_lang": ("file_lang", []),
                "dst_region": ("dst_region", []),
                "dst_zipcode": ("dst_zipcode", []),
                "object_id": ("object_id", []),
                "dlp_rule_count": ("dlp_rule_count", []),
                "managed_app": ("managed_app", []),
                "dst_country": ("dst_country", []),
                "access_method": ("access_method", []),
                "policy": ("policy", []),
                "shared": ("shared", []),
                "traffic_type": ("traffic_type", []),
                "type": ("type", []),
                "file_path": ("file_path", []),
                "mime_type": ("mime_type", []),
                "object_type": ("object_type", []),
                "userkey": ("userkey", ["user name"]),
                "timestamp": ("timestamp", []),
                "dlp_parent_id": ("dlp_parent_id", []),
                "acked": ("acked", []),
                "scan_type": ("scan_type", []),
                "user": ("user", ["user name"]),
                "app_activity": ("app_activity", []),
                "device": ("device", []),
                "dlp_profile": ("dlp_profile", []),
                "alert": ("alert", []),
                "md5": ("md5", []),
                "count": ("count", []),
                "dlp_rule": ("dlp_rule", []),
                "url": ("url", ["url"]),
                "modified": ("modified", []),
                "object": ("object", ["hash", "md5"]),
                "dlp_rule_severity": ("dlp_rule_severity", []),
                "ccl": ("ccl", []),
                "alert_name": ("alert_name", []),
                "cci": ("cci", []),
                "transaction_id": ("transaction_id", []),
                "action": ("action", []),
                "os": ("os", []),
                "browser": ("browser", []),
                "appcategory": ("appcategory", ["category"]),
            },
            "anomaly": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "event_type": ("event_type", []),
                "_insertion_epoc_timestamp": ("_insertion_epoc_timestamp", []),
                "site": ("site", []),
                "tenantid": ("tenantid", []),
                "category": ("category", ["category"]),
                "risk_level": ("risk_level", ["risk"]),
                "alert_name": ("alert_name", []),
                "object_id": ("object_id", []),
                "access_method": ("access_method", []),
                "traffic_type": ("traffic_type", []),
                "type": ("type", ["anomaly type"]),
                "audit_type": ("audit_type", []),
                "timestamp": ("timestamp", []),
                "acked": ("acked", []),
                "alert": ("alert", []),
                "user": ("user", ["user"]),
                "device": ("device", []),
                "object_type": ("object_type", []),
                "count": ("count", []),
                "risk_level_id": ("risk_level_id", []),
                "ccl": ("ccl", []),
                "cci": ("cci", []),
                "audit_category": ("audit_category", []),
                "os": ("os", []),
                "browser": ("browser", []),
                "appcategory": ("appcategory", []),
            },
            "compromised credential": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "breach_id": ("breach_id", ["hash", "md5"]),
                "email_source": ("email_source", []),
                "_insertion_epoc_timestamp": ("_insertion_epoc_timestamp", []),
                "breach_score": ("breach_score", ["score"]),
                "breach_date": ("breach_date", []),
                "matched_username": ("matched_username", ["user"]),
                "type": ("type", []),
                "timestamp": ("timestamp", []),
                "acked": ("acked", []),
                "alert": ("alert", []),
                "user": ("user", ["user"]),
                "count": ("count", []),
                "alert_name": ("alert_name", []),
            },
            "legal hold": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "suppression_key": ("suppression_key", []),
                "lh_version": ("lh_version", []),
                "lh_custodian_email": ("lh_custodian_email", ["user name"]),
                "file_type": ("file_type", []),
                "app": ("app", ["category"]),
                "app_activity": ("app_activity", []),
                "site": ("site", []),
                "lh_dest_app": ("lh_dest_app", []),
                "access_method": ("access_method", []),
                "lh_shared": ("lh_shared", []),
                "profile_emails": ("profile_emails", ["user name"]),
                "owner": ("owner", ["user name"]),
                "category": ("category", ["category"]),
                "user_id": ("user_id", []),
                "act_user": ("act_user", []),
                "alert_name": ("alert_name", []),
                "objec_id": ("objec_id", []),
                "instance": ("instance", []),
                "lh_fileid": ("lh_fileid", []),
                "policy": ("policy", []),
                "traffic_type": ("traffic_type", []),
                "md5": ("md5", []),
                "type": ("type", []),
                "file_path": ("file_path", []),
                "mime_type": ("mime_type", []),
                "ld_dest_instance": ("ld_dest_instance", []),
                "ns_activity": ("ns_activity", []),
                "_insertion_epoch_timestamp": ("_insertion_epoch_timestamp", []),
                "lh_custodian_name": ("lh_custodian_name", []),
                "timestamp": ("timestamp", []),
                "acked": ("acked", []),
                "lh_original_filename": ("lh_original_filename", []),
                "scan_type": ("scan_type", []),
                "action": ("action", []),
                "file_size": ("file_size", []),
                "user": ("user", ["user name"]),
                "lh_filename": ("lh_filename", ["file"]),
                "device": ("device", []),
                "dlp_profile": ("dlp_profile", []),
                "shared_with": ("shared_with", []),
                "lh_filepath": ("lh_filepath", []),
                "exposure": ("exposure", []),
                "count": ("count", []),
                "url": ("url", []),
                "legal_hold_profile_name": ("legal_hold_profile_name", []),
                "modified": ("modified", []),
                "object": ("object", []),
                "instance_id": ("instance_id", []),
                "ccl": ("ccl", []),
                "from_user": ("from_user", ["user name"]),
                "cci": ("cci", []),
                "alert": ("alert", []),
                "activity": ("activity", []),
                "object_type": ("object_type", []),
                "userkey": ("userkey", ["user name"]),
                "os": ("os", []),
                "browser": ("browser", []),
                "appcategory": ("appcategory", ["category"]),
            },
            "policy": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "dst_location": ("dst_location", []),
                "app": ("app", []),
                "src_location": ("src_location", []),
                "dstip": ("dstip", ["ip", "ipv4"]),
                "file_size": ("file_size", []),
                "object_type": ("object_type", []),
                "activty": ("activty", []),
                "app_session_id": ("app_session_id", []),
                "category": ("category", ["category"]),
                "dst_country": ("dst_country", []),
                "dst_region": ("dst_region", []),
                "object_id": ("object_id", []),
                "managed_app": ("managed_app", []),
                "os_version": ("os_version", []),
                "access_method": ("access_method", []),
                "traffic_type": ("traffic_type", []),
                "encrypt_failure": ("encrypt_failure", []),
                "type": ("type", []),
                "transaction_id": ("transaction_id", []),
                "srcip": ("srcip", ["ip", "ipv4"]),
                "timestamp": ("timestamp", []),
                "src_region": ("src_region", []),
                "acked": ("acked", []),
                "alert": ("alert", []),
                "userip": ("userip", ["ip", "ipv4"]),
                "user": ("user", ["user name"]),
                "device": ("device", []),
                "src_country": ("src_country", []),
                "md5": ("md5", []),
                "count": ("count", []),
                "url": ("url", ["url"]),
                "page_id": ("page_id", []),
                "sv": ("sv", []),
                "object": ("object", []),
                "ccl": ("ccl", []),
                "cci": ("cci", []),
                "action": ("action", []),
                "os": ("os", []),
                "browser": ("browser", []),
                "appcategory": ("appcategory", ["category"]),
            },
            "quarantine": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "dstip": ("dstip", ["ip", "ipv4"]),
                "file_type": ("file_type", []),
                "app": ("app", []),
                "src_location": ("src_location", []),
                "browser_version": ("browser_version", []),
                "device_classification": ("device_classification", []),
                "file_size": ("file_size", []),
                "object_type": ("object_type", []),
                "activity": ("activity", []),
                "app_session_id": ("app_session_id", []),
                "browser_session_id": ("browser_session_id", []),
                "category": ("category", ["category"]),
                "instance_name": ("instance_name", []),
                "page_site": ("page_site", []),
                "os_version": ("os_version", []),
                "quarantine_encrypt": ("quarantine_encrypt", []),
                "dst_region": ("dst_region", []),
                "hostname": ("hostname", []),
                "alert_name": ("alert_name", []),
                "managed_app": ("managed_app", []),
                "dst_country": ("dst_country", []),
                "parent_id": ("parent_id", []),
                "access_method": ("access_method", []),
                "policy": ("policy", []),
                "traffic_type": ("traffic_type", []),
                "type": ("type", []),
                "transaction_id": ("transaction_id", []),
                "srcip": ("srcip", ["ip", "ipv4"]),
                "instance_id": ("instance_id", []),
                "timestamp": ("timestamp", []),
                "src_region": ("src_region", []),
                "alert": ("alert", []),
                "page_id": ("page_id", []),
                "quarantine_app": ("quarantine_app", []),
                "referer": ("referer", []),
                "user": ("user", ["user name"]),
                "userkey": ("userkey", ["user name"]),
                "device": ("device", []),
                "dlp_profile": ("dlp_profile", []),
                "src_country": ("src_country", []),
                "md5": ("md5", []),
                "count": ("count", []),
                "acked": ("acked", []),
                "url": ("url", ["url"]),
                "sv": ("sv", []),
                "object": ("object", []),
                "tss_mode": ("tss_mode", []),
                "ccl": ("ccl", []),
                "from_user": ("from_user", ["user name"]),
                "cci": ("cci", []),
                "quarantine_profile_id": ("quarantine_profile_id", []),
                "userip": ("userip", ["ip", "ipv4"]),
                "quarantine_file_id": ("quarantine_file_id", []),
                "os": ("os", []),
                "page": ("page", []),
                "browser": ("browser", []),
                "appcategory": ("appcategory", ["category"]),
            },
            "security assessment": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "region_id": ("region_id", []),
                "sa_profile_name": ("sa_profile_name", []),
                "app": ("app", []),
                "site": ("site", []),
                "access_method": ("access_method", []),
                "browser": ("browser", []),
                "account_name": ("account_name", []),
                "category": ("category", ["category"]),
                "sa_profile_id": ("sa_profile_id", []),
                "sa_rule_id": ("sa_rule_id", []),
                "sa_rule_severity": ("sa_rule_severity", []),
                "policy": ("policy", []),
                "sa_rule_name": ("sa_rule_name", []),
                "traffic_type": ("traffic_type", []),
                "type": ("type", []),
                "account_id": ("account_id", []),
                "timestamp": ("timestamp", []),
                "_insertion_epoc_timestamp": ("_insertion_epoc_timestamp", []),
                "object": ("object", []),
                "acked": ("acked", []),
                "user": ("user", ["user name"]),
                "userkey": ("userkey", ["user name"]),
                "device": ("device", []),
                "count": ("count", []),
                "instance_id": ("instance_id", []),
                "ccl": ("ccl", []),
                "alert_name": ("alert_name", []),
                "cci": ("cci", []),
                "activity": ("activity", []),
                "action": ("action", []),
                "resource_category": ("resource_category", ["category"]),
                "policy_id": ("policy_id", []),
                "appcategory": ("appcategory", ["category"]),
                "sa_rule_mediation": ("sa_rule_mediation", []),
            },
            "watchlist": {
                "managementID": ("managementID", []),
                "nsdeviceuid": ("nsdeviceuid", []),
                "alert_type": ("alert_type", []),
                "app": ("app", []),
                "object_id": ("object_id", []),
                "user_category": ("user_category", ["category"]),
                "access_method": ("access_method", []),
                "traffic_type": ("traffic_type", []),
                "app_activity": ("app_activity", []),
                "type": ("type", []),
                "ns_activity": ("ns_activity", []),
                "count": ("count", []),
                "_insertion_epoc_timestamp": ("_insertion_epoc_timestamp", []),
                "timestamp": ("timestamp", []),
                "src_region": ("src_region", []),
                "user_role": ("user_role", []),
                "alert": ("alert", []),
                "user": ("user", ["user name"]),
                "device": ("device", []),
                "src_country": ("src_country", []),
                "src_location": ("src_location", []),
                "acked": ("acked", []),
                "user_name": ("user_name", ["user name"]),
                "object": ("object", []),
                "instance_id": ("instance_id", []),
                "ccl": ("ccl", []),
                "alert_name": ("alert_name", []),
                "cci": ("cci", []),
                "activity": ("activity", []),
                "userip": ("userip", ["ip", "ipv4"]),
                "userkey": ("userkey", ["user name"]),
                "os": ("os", []),
                "browser": ("browser", []),
                "appcategory": ("appcategory", []),
            },
        }

        for artifact_name, artifact_keys in artifacts_mapping.items():
            temp_dict = {}
            cef = {}
            cef_types = {}
            self._log.info("artifact_name={0}".format(artifact_name))

            if artifact_name == "URL Artifact" and not phantom.is_url(alert.get("url", "")) and "url" in alert:
                alert["domain"] = self._get_domain_from_url(alert.get("url", ""))
                alert["url"] = "http://{url}".format(url=alert.get("url", ""))

            for artifact_key, artifact_tuple in artifact_keys.items():
                if alert.get(artifact_tuple[0]):
                    cef[artifact_key] = alert[artifact_tuple[0]]
                    cef_types[artifact_key] = artifact_tuple[1]

            if cef:
                cef["tenant"] = self._tenant
                temp_dict["cef"] = cef
                temp_dict["cef_types"] = cef_types
                temp_dict["name"] = artifact_name
                temp_dict["container_id"] = container_id
                temp_dict["type"] = alert.get("alert_type", "unknown")
                temp_dict["alert_type"] = alert.get("alert_type", "unknown")
                temp_dict["source_data_identifier"] = self._create_dict_hash(temp_dict)
                temp_dict["tenant"] = self._tenant
                artifacts_list.append(temp_dict)

        al_ty = alert.get("alert_type", "unknown").lower()
        if al_ty in specific_alert_mapping:
            self._log.info("action=specific_artifact alert={0}".format(al_ty))
            temp_dict = {}
            cef = {}
            cef_types = {}
            artifact_name = "{0} Artifact".format(alert.get("alert_type"))

            for artifact_key, artifact_tuple in specific_alert_mapping.get(al_ty).items():
                if alert.get(artifact_tuple[0]):
                    cef[artifact_key] = alert[artifact_tuple[0]]
                    cef_types[artifact_key] = artifact_tuple[1]

            if cef:
                cef["tenant"] = self._tenant
                temp_dict["cef"] = cef
                temp_dict["cef_types"] = cef_types
                temp_dict["name"] = artifact_name
                temp_dict["container_id"] = container_id
                temp_dict["type"] = alert.get("alert_type", "unknown")
                temp_dict["source_data_identifier"] = self._create_dict_hash(temp_dict)
                temp_dict["tenant"] = self._tenant
                artifacts_list.append(temp_dict)

        create_artifact_status, create_artifact_msg, _ = self.save_artifacts(artifacts_list)

        if phantom.is_fail(create_artifact_status):
            return phantom.APP_ERROR, create_artifact_msg

        return phantom.APP_SUCCESS, "Artifacts created successfully"

    @staticmethod
    def _get_domain_from_url(url):
        """Domain from given URL. It uses urlparse if url is valid Phantom URL, otherwise splits with / and considers first part as a domain

        :param url: URL from which we have to extract the domain
        :return: Extracted domain
        """
        if phantom.is_url(url):
            return urlparse(url)[1]

        return url.split("/")[0]

    def _create_dict_hash(self, input_dict):
        """Generate the hash from dictionary.

        :param input_dict: Dictionary for which we have to generate the hash
        :return: hash
        """
        if not input_dict:
            return
        else:
            try:
                input_dict_str = json.dumps(input_dict, sort_keys=True)
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print("Handled exception in _create_dict_hash", error_msg)
                return

        return hashlib.md5(input_dict_str.encode("utf-8")).hexdigest()

    def _handle_update_url_list(self, param):
        """Publish & push URL list changes.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            exists, message, content = self.get_url_list()
            content = [element.strip() for element in content if element.strip()]
            content = list(set(content))
            invalid_url_list = []

            if not content:
                return action_result.set_status(phantom.APP_ERROR, "No content found to update the url list")

            if self._v2_api_key:
                # fetch the ID of the list
                ret_val, list_id = self._get_url_list_id(action_result)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                # fetch the data of the url list
                url_list_endpoint = "{0}/{1}".format(NETSKOPE_V2_URL_LIST_ENDPOINT, list_id)
                request_status, request_response = self._make_rest_call(endpoint=url_list_endpoint, action_result=action_result)

                if phantom.is_fail(request_status):
                    return action_result.get_status()

                # if type is missing in the response, will assign list_type as "exact" based on list url doc
                list_type = request_response.get("data", {}).get("type", "exact")

                if not list_type:
                    self._log.error(("Failed to get the type of url list from: {0}".format(str(request_response))))
                    return action_result.set_status(phantom.APP_ERROR, "Failed to get the type of url list")

                data = {"name": self._list_name, "data": {"urls": content, "type": list_type}}

                # push the url list data to the Netskope server
                request_status, resp_json = self._make_rest_call(
                    endpoint=("{0}/replace".format(url_list_endpoint)), action_result=action_result, data=data, method="patch"
                )

                if phantom.is_fail(request_status):
                    if resp_json.get("statusCode") == 400 and resp_json.get("message"):
                        invalid_url_list = [item[0] for item in resp_json["message"]]
                        self.save_progress("Removing invalid URLs from the url list.")

                        for item in invalid_url_list:
                            content.remove(item)

                        data["data"]["urls"] = content

                        # push the url list data to the Netskope server
                        request_status, _ = self._make_rest_call(
                            endpoint=("{0}/replace".format(url_list_endpoint)), action_result=action_result, data=data, method="patch"
                        )

                        if phantom.is_fail(request_status):
                            return action_result.get_status()
                    else:
                        self._log.error("failed to update {0} url_list on the Netskope".format(self._list_name))
                        return action_result.get_status()

                self._log.info("successfully updated {0} url_list on the Netskope".format(self._list_name))
                request_status, _ = self._make_rest_call(
                    endpoint="{0}/{1}".format(NETSKOPE_V2_URL_LIST_ENDPOINT, NETSKOPE_DEPLOY_URL_LIST),
                    action_result=action_result,
                    method="post",
                )

                if phantom.is_fail(request_status):
                    self._log.error("Failed to deploy url_list changes to the Netskope")
                    return action_result.get_status()
            else:
                params = {"list": ",".join(content), "name": self._list_name}
                self._log.info("action=get_url_list exists={0} message={1} content_length={2}".format(exists, message, len(content)))

                # deploy pushed changes
                request_status, _ = self._make_rest_call(endpoint=NETSKOPE_URL_LIST_ENDPOINT, action_result=action_result, params=params)

                if phantom.is_fail(request_status):
                    return action_result.get_status()

            # removing from the phantom url list
            remove_count = 0
            for item in invalid_url_list:
                status, remove_msg = phantom_rules.delete_from_list(list_name=self._url_list, value=item, remove_all=True, remove_row=True)
                self.debug_print(f"Removing URL {item} from the url list. status: {status} , remove_msg : {remove_msg}")
                if status:
                    remove_count += 1

            summary = action_result.update_summary({})
            summary["total_updated_urls"] = len(content)
            summary["total_removed_urls"] = remove_count
            summary["invalid_urls"] = invalid_url_list
            return action_result.set_status(
                phantom.APP_SUCCESS,
                "Successfully updated URLs: Total updated unique URLs: {}, Total removed URLs: {}".format(
                    summary['total_updated_urls'], summary['total_removed_urls']
                ),
            )
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            _, _, exc_tb = sys.exc_info()
            self._log.error("exception_line={0} Update URL List: {1}".format(exc_tb.tb_lineno, error_msg))
            return action_result.set_status(phantom.APP_ERROR, "Exception {0}: line={1}".format(error_msg, exc_tb.tb_lineno))

    def _handle_add_url_list(self, param):
        """Add URL to the URL list.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        return self._add_list(action_result, "url list", param[NETSKOPE_PARAM_URL])

    def _handle_remove_url_list(self, param):
        """Remove URL from URL list.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        self._log.info("param={0}".format(json.dumps(param)))
        self.debug_print("Fetching url list")
        status, msg, list_items = self.get_url_list()

        if not status:
            return action_result.set_status(phantom.APP_ERROR, "Failed to fetch url list. Error: {0}".format(msg))

        found_rows = [True for _, v in enumerate(list_items) if v == param[NETSKOPE_PARAM_URL]]
        self._log.info("action=checking_for_matches status={0} msg={1} matches={2}".format(status, msg, found_rows))

        if not found_rows:
            return action_result.set_status(phantom.APP_SUCCESS, "{0} does not exist in list".format((param[NETSKOPE_PARAM_URL])))

        status, remove_msg = phantom_rules.delete_from_list(
            list_name=self._url_list, value=param[NETSKOPE_PARAM_URL], remove_all=True, remove_row=True
        )

        if not status:
            return action_result.set_status(phantom.APP_ERROR, "Failed to delete url from the list. Error: {0}".format(remove_msg))

        if found_rows and len(list_items) == 1:
            status, _ = phantom_rules.set_list(list_name=self._url_list, values=[[]])
            remove_msg = "Deleted Single Row"

        self._log.info("action=delete_from_list status={0} msg={1}".format(status, remove_msg))
        status, msg, list_items = self.get_url_list()
        summary = action_result.update_summary({"remove_msg": remove_msg})
        summary["total_urls"] = len(list_items)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_url_list_id(self, action_result):
        """Get the ID of URL list.

        :param action_result: object of ActionResult class
        :return: (status success/failure, URL list ID)
        """
        request_params = {"field": ["id", "name"]}
        request_status, request_response = self._make_rest_call(
            endpoint=NETSKOPE_V2_URL_LIST_ENDPOINT, action_result=action_result, params=request_params
        )

        if phantom.is_fail(request_status):
            return action_result.get_status(), None

        for list_details in request_response:
            if list_details.get("name", "") == self._list_name:
                return action_result.set_status(phantom.APP_SUCCESS), list_details.get("id")

        return (
            action_result.set_status(
                phantom.APP_ERROR,
                "Error: A URL List object with the name provided does not \
                                            exist on the Netskope. Create one first.",
            ),
            None,
        )

    def _handle_get_scim_groups(self, param):
        """Get SCIM groups.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self._log.debug("parameters={0}".format(param))
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            if NETSKOPE_PARAM_GROUP in param:
                param["filter"] = 'displayName eq "{0}"'.format(param[NETSKOPE_PARAM_GROUP])

            self._log.debug("action=make_scim_rest_call params={0}".format(param))
            request_status, request_response = self._make_scim_rest_call(
                endpoint=NETSKOPE_SCIM_GROUPS_ENDPOINT, action_result=action_result, params=param
            )

            if phantom.is_fail(request_status):
                return action_result.get_status()

            resources = request_response.get("Resources", [])
            [action_result.add_data(x) for x in resources]
            summary = action_result.update_summary({})
            summary["total_groups"] = len(resources)
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            _, _, exc_tb = sys.exc_info()
            self._log.error("exception_line={0} Get SCIM Users: {1}".format(exc_tb.tb_lineno, error_msg))
            return action_result.set_status(phantom.APP_ERROR, "Exception {0}: line={1}".format(error_msg, exc_tb.tb_lineno))

    def _handle_get_scim_users(self, param):
        """Get SCIM users.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self._log.debug("parameters={0}".format(param))
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            if NETSKOPE_PARAM_USER in param:
                param["filter"] = ('userName eq "{0}"').format(param[NETSKOPE_PARAM_USER])

            self._log.debug("action=make_scim_rest_call params={0}".format(param))
            request_status, request_response = self._make_scim_rest_call(
                endpoint=NETSKOPE_SCIM_USERS_ENDPOINT, action_result=action_result, params=param
            )

            if phantom.is_fail(request_status):
                return action_result.get_status()

            resources = request_response.get("Resources", [])
            [action_result.add_data(x) for x in resources]
            summary = action_result.update_summary({})
            summary["total_users"] = len(resources)
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            _, _, exc_tb = sys.exc_info()
            self._log.error("exception_line={0} Get SCIM Users: {1}".format(exc_tb.tb_lineno, error_msg))
            return action_result.set_status(phantom.APP_ERROR, "Exception {0}: line={1}".format(error_msg, exc_tb.tb_lineno))

    def _handle_scim_user_to_group(self, param):
        """Add SCIM user to SCIM group.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self._log.info("parameters={0}".format(param))
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            data = {
                "Operations": [{"op": param.get("action", "add"), "path": "members", "value": [{"value": param[NETSKOPE_PARAM_USER]}]}],
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            }
            self._log.info("action=make_scim_rest_call params={0}".format(data))
            request_status, request_response = self._make_scim_rest_call(
                endpoint="{0}/{1}".format(NETSKOPE_SCIM_GROUPS_ENDPOINT, param[NETSKOPE_PARAM_GROUP]),
                action_result=action_result,
                params=data,
                method="patch",
            )

            if phantom.is_fail(request_status):
                self._log.error("action=failed status={0} response={1}".format(request_status, request_response))
                return action_result.get_status()

            resources = request_response.get("Resources", [])
            [action_result.add_data(x) for x in resources]
            summary = action_result.update_summary({})
            summary["total_users"] = len(resources)
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            _, _, exc_tb = sys.exc_info()
            self._log.error("exception_line={0} Add User to Group SCIM: {1}".format(exc_tb.tb_lineno, error_msg))
            return action_result.set_status(phantom.APP_ERROR, "Exception {0}: line={1}".format(error_msg, exc_tb.tb_lineno))

    def _handle_create_scim_group(self, param):
        """Create SCIM group.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self._log.info("parameters={0}".format(param))
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            data = {"displayName": param[NETSKOPE_PARAM_GROUP], "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]}
            self._log.info("action=make_scim_rest_call params={0}".format(data))
            request_status, request_response = self._make_scim_rest_call(
                endpoint=NETSKOPE_SCIM_GROUPS_ENDPOINT, action_result=action_result, params=data, method="post"
            )

            if phantom.is_fail(request_status):
                return action_result.get_status()

            action_result.add_data(request_response)
            summary = action_result.update_summary({})
            summary["total_groups"] = 1
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            _, _, exc_tb = sys.exc_info()
            self._log.error(("exception_line={0} Add User to Group SCIM: {1}").format(exc_tb.tb_lineno, error_msg))
            return action_result.set_status(phantom.APP_ERROR, ("Exception {0}: line={1}").format(error_msg, exc_tb.tb_lineno))

    def _handle_create_scim_user(self, param):
        """Create SCIM user.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self._log.info("parameters={0}".format(param))
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            data = {
                "userName": param[NETSKOPE_PARAM_USER],
                "name": {"familyName": param.get("familyName"), "givenName": param.get("givenName")},
                "active": True,
                "emails": [{"value": param["email"], "primary": True}],
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            }
            self._log.info("action=make_scim_rest_call params={0}".format(data))
            request_status, request_response = self._make_scim_rest_call(
                endpoint=NETSKOPE_SCIM_USERS_ENDPOINT, action_result=action_result, params=data, method="post"
            )

            if phantom.is_fail(request_status):
                return action_result.get_status()

            action_result.add_data(request_response)
            summary = action_result.update_summary({})
            summary["total_users"] = 1
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            _, _, exc_tb = sys.exc_info()
            self._log.error("exception_line={0} Add User to Group SCIM: {1}".format(exc_tb.tb_lineno, error_msg))
            return action_result.set_status(phantom.APP_ERROR, "Exception {0}: line={1}".format(error_msg, exc_tb.tb_lineno))

    def _handle_update_file_list(self, param):
        """Push file hash.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._update_file_helper(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _update_file_helper(self, action_result):
        """Update file list helper."""
        try:
            exists, message, content = self.get_file_list()
            content = [element.strip() for element in content if element.strip()]

            if not content:
                return action_result.set_status(phantom.APP_ERROR, "No content found to update the file hash list")

            params = {"list": (",").join(content), "name": self._list_name}
            self._log.info("action=get_file_list exists={0} message={1} content_length={2}".format(exists, message, len(content)))
            request_status, _ = self._make_rest_call(endpoint=NETSKOPE_FILE_LIST_ENDPOINT, action_result=action_result, params=params)

            if phantom.is_fail(request_status):
                return action_result.get_status()

            action_result.add_data({})
            summary = action_result.update_summary({})
            summary["total_hashes"] = len(content)
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            _, _, exc_tb = sys.exc_info()
            self._log.error("exception_line={0} Update File Hash List: {1}".format(exc_tb.tb_lineno, error_msg))
            return action_result.set_status(phantom.APP_ERROR, "Exception {0}: line={1}".format(error_msg, exc_tb.tb_lineno))

    def _add_list(self, action_result, list_type, new_list_name):
        base_url = self._get_phantom_base_url()
        base_url = base_url[:-1] if base_url.endswith("/") else base_url

        get_url = base_url + REST_GET_LIST_ENDPOINT
        list_name = self._url_list if list_type == "url list" else self._file_list

        self.debug_print(f"Fetching {list_type}")
        try:
            r = requests.get(get_url, verify=False)
            response_json = r.json()
            list_id = next((item["id"] for item in response_json["data"] if item.get("name") == list_name), None)
            if response_json.get("num_pages", 0) > 1 and not list_id:
                for page in range(1, response_json["num_pages"]):
                    r = requests.get(get_url, params={"page": page}, verify=False)
                    response_json = r.json()
                    list_id = next((item["id"] for item in response_json["data"] if item.get("name") == list_name), None)
                    if list_id:
                        break

            get_url = get_url + str(list_id)
            r = requests.get(get_url, verify=False)
            response_json = r.json()
            if not response_json.get("content"):
                return action_result.set_status(phantom.APP_ERROR, f'Failed to fetch {list_type}. Error: {response_json.get("message")}')

            nested_list = response_json["content"]
            old_list = [item for sublist in nested_list for item in sublist]
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print(error_msg)
            return action_result.set_status(phantom.APP_ERROR, f"Failed to fetch {list_type}. Error: {error_msg}")

        if new_list_name in old_list:
            return action_result.set_status(phantom.APP_SUCCESS, f"{new_list_name} already exists in list")

        post_url = base_url + REST_ADD_LIST_ENDPOINT.format(list_id=list_id)

        old_list.append(new_list_name)
        new_list = list(set(old_list))
        values = [[x] for x in new_list]
        data = {"content": values}
        data = json.dumps(data)

        try:
            r = requests.post(post_url, data=data, verify=False)
            data = r.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"Failed to add {list_type}. Error: {error_msg}")

        if not data.get("success"):
            return action_result.set_status(phantom.APP_ERROR, f"Failed to add {list_type}. Error: {error_msg}")

        summary = action_result.update_summary({})

        if data.get("message"):
            summary["set_list"] = data.get("message")

        if list_type == "url list":
            summary["total_urls"] = len(new_list)
        else:
            summary["total_hashes"] = len(new_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_file_list(self, param):
        """Add file to a list.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        return self._add_list(action_result, "file list", param[NETSKOPE_PARAM_HASH])

    def _handle_remove_file_list(self, param):
        """Remove files from a list.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(NETSKOPE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        self._log.info("param={0}".format(json.dumps(param)))
        self.debug_print("Fetching file list")
        status, msg, list_items = self.get_file_list()

        if not status:
            return action_result.set_status(phantom.APP_ERROR, "Failed to fetch file list. Error: {0}".format(msg))

        found_rows = [True for _, v in enumerate(list_items) if v == param[NETSKOPE_PARAM_HASH]]
        self._log.info("action=checking_for_matches status={0} msg={1} matches={2}".format(status, msg, found_rows))

        if not found_rows:
            return action_result.set_status(phantom.APP_SUCCESS, "{0} does not exist in list".format(param[NETSKOPE_PARAM_HASH]))

        status, remove_msg = phantom_rules.delete_from_list(
            list_name=self._file_list, value=param[NETSKOPE_PARAM_HASH], remove_all=True, remove_row=True
        )

        if not status:
            return action_result.set_status(phantom.APP_ERROR, "Failed to delete file hash from a list. Error: {0}".format(remove_msg))

        if found_rows and len(list_items) == 1:
            status, _ = phantom_rules.set_list(list_name=self._file_list, values=[[]])
            remove_msg = "Deleted Single Row"

        self._log.info("action=delete_from_list status={0} msg={1}".format(status, remove_msg))
        status, msg, list_items = self.get_file_list()
        self._log.info("action=after_delete_from_list status={0} msg={1} list_length={2}".format(status, msg, len(list_items)))
        summary = action_result.update_summary({"remove_msg": remove_msg})
        summary["total_files"] = len(list_items)
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Get current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """
        self.debug_print("action_id", self.get_action_identifier())
        self._log.info("action_id={0}".format(self.get_action_identifier()))

        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "get_file": self._handle_get_file,
            "list_files": self._handle_list_files,
            "run_query": self._handle_run_query,
            "on_poll": self._handle_on_poll,
            "add_url_list": self._handle_add_url_list,
            "remove_url_list": self._handle_remove_url_list,
            "update_url_list": self._handle_update_url_list,
            "add_file_list": self._handle_add_file_list,
            "remove_file_list": self._handle_remove_file_list,
            "update_file_list": self._handle_update_file_list,
            "get_scim_users": self._handle_get_scim_users,
            "get_scim_groups": self._handle_get_scim_groups,
            "create_scim_group": self._handle_create_scim_group,
            "create_scim_user": self._handle_create_scim_user,
            "scim_user_to_group": self._handle_scim_user_to_group,
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in list(action_mapping.keys()):
            action_function = action_mapping[action]
            self._log.info("execute={0} params={1}".format(action, param))
            action_execution_status = action_function(param)

        return action_execution_status

    def get_url_list(self):
        """Get URL list."""
        status, msg, pl = phantom_rules.get_list(self._url_list)
        pl2 = [x[0] for x in pl if len(x) > 0]
        self._log.info("action=get_url_list status={0} msg={1}".format(status, msg))
        return status, msg, [x for x in pl2 if x is not None]

    def create_url_list(self):
        """Create URL list."""
        return phantom_rules.add_list(self._url_list, [])

    def get_file_list(self):
        """Get file list."""
        status, msg, pl = phantom_rules.get_list(self._file_list)
        pl2 = [x[0] for x in pl if len(x) > 0]
        self._log.info("action=get_url_list status={0} msg={1}".format(status, msg))
        return status, msg, [x for x in pl2 if x is not None]

    def create_file_list(self):
        """Create file list."""
        return phantom_rules.add_list(self._file_list, [])

    def initialize(self):
        """Initialize the asset config"""
        self._log.info("action=initialize status=start")

        self._state = self.load_state()
        self._log.info("action=initialize state={0}".format(self._state))

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}
            return self.set_status(phantom.APP_ERROR, NETSKOPE_STATE_FILE_CORRUPT_ERR)

        config = self.get_config()
        self._file_list = "{0}_{1}".format(config.get(NETSKOPE_LIST_NAME, ""), NETSKOPE_FILE_LIST)
        self._url_list = "{0}_{1}".format(config.get(NETSKOPE_LIST_NAME, ""), NETSKOPE_URL_LIST)

        self._scim["url"] = config.get("scim_url", "")
        self._scim["token"] = config.get("scim_key", "")

        list_status, message, list_contents = self.get_url_list()
        self._log.info("action=get_url_list status={0} message={1} contents_length={2}".format(list_status, message, len(list_contents)))

        if not list_status:
            self._log.info("action=create_url_list return={0}".format(self.create_url_list()))

        list_status, message, list_contents = self.get_file_list()
        self._log.info("action=get_file_list status={0} message={1} contents_length={2}".format(list_status, message, len(list_contents)))

        if not list_status:
            self._log.info("action=create_file_list return={0}".format(self.create_file_list()))

        # Initialize list name
        self._list_name = config.get(NETSKOPE_LIST_NAME, "")

        # Initialize v1 API key
        self._api_key = config.get(NETSKOPE_CONFIG_API_KEY)
        if self._api_key:
            self._api_key = self._api_key.strip()

        # Initialize v2 API key
        self._v2_api_key = config.get(NETSKOPE_CONFIG_V2_API_KEY)
        if self._v2_api_key:
            self._v2_api_key = self._v2_api_key.strip()

        if self.get_action_identifier() in ["test_connectivity", "on_poll"] and not (self._v2_api_key or self._api_key):
            return self.set_status(phantom.APP_ERROR, NETSKOPE_MISSING_BOTH_API_KEYS_ERR)

        return phantom.APP_SUCCESS

    def finalize(self):
        """Save state of the app.

        :return: status (success/failure)
        """
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse

    import pudb

    pudb.set_trace()
    argparser = argparse.ArgumentParser()
    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument("-v", "--verify", action="store_true", help="verify", required=False, default=False)
    args = argparser.parse_args()
    session_id = None
    username = args.username
    password = args.password
    verify = args.verify
    if username is not None and password is None:
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            response = requests.get(login_url, verify=verify, timeout=NETSKOPE_DEFAULT_TIMEOUT)
            csrftoken = response.cookies["csrftoken"]
            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken
            headers = dict()
            headers["Cookie"] = ("csrftoken={0}").format(csrftoken)
            headers["Referer"] = login_url
            print("Logging into Platform to get the session id")
            response2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=NETSKOPE_DEFAULT_TIMEOUT)
            session_id = response2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: {0}".format(str(e)))
            sys.exit(1)

    with open(args.input_test_json) as (f):
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = NetskopeConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    sys.exit(0)
