# File: netskope_consts.py
#
# Copyright (c) 2018-2022 Splunk Inc.
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
NETSKOPE_CONFIG_SERVER_URL = 'server_url'
NETSKOPE_CONFIG_SCIM_URL = 'scim_url'
NETSKOPE_CONFIG_API_KEY = 'api_key'  # pragma: allowlist secret
NETSKOPE_CONFIG_SCIM_KEY = 'scim_key'
NETSKOPE_CONNECTIVITY_ENDPOINT = '/api/v1/clients'
NETSKOPE_QUARANTINE_ENDPOINT = '/api/v1/quarantine'
NETSKOPE_ON_POLL_ENDPOINT = '/api/v1/alerts'
NETSKOPE_EVENTS_ENDPOINT = '/api/v1/events'
NETSKOPE_URL_LIST_ENDPOINT = '/api/v1/updateUrlList'
NETSKOPE_FILE_LIST_ENDPOINT = '/api/v1/updateFileHashList'
NETSKOPE_SCIM_USERS_ENDPOINT = '/Users'
NETSKOPE_SCIM_GROUPS_ENDPOINT = '/Groups'
NETSKOPE_SCIM_GROUP_ENDPOINT = '/Group'
NETSKOPE_PARAM_LIST_FILES = 'get-files'
NETSKOPE_PARAM_IP = 'ip'
NETSKOPE_PARAM_START_TIME = 'start_time'
NETSKOPE_PARAM_END_TIME = 'end_time'
NETSKOPE_QUERY_PARAM = 'srcip eq {srcip} or dstip eq {dstip}'
NETSKOPE_INVALID_START_TIME = "Parameter 'start_time' failed validation"
NETSKOPE_INVALID_END_TIME = "Parameter 'end_time' failed validation"
NETSKOPE_INVALID_TIME_RANGE = "Invalid time range. 'end_time' should be greater than 'start_time'"
NETSKOPE_INVALID_TIME = 'Invalid time. Time cannot be negative'
NETSKOPE_VALID_TIME = 'TIme validation successful'
NETSKOPE_CONNECTIVITY_PASS_MSG = 'Test Connectivity Passed'
NETSKOPE_CONNECTIVITY_FAIL_MSG = 'Test Connectivity Failed'
NETSKOPE_CONNECTION_MSG = 'Querying endpoint to verify the credentials provided'
NETSKOPE_ERROR_CONNECTING_SERVER = 'Error while connecting to server'
NETSKOPE_JSON_FILE = 'file'
NETSKOPE_JSON_PROFILE = 'profile'
NETSKOPE_TEST_CONNECTIVITY_LIMIT = 1
NETSKOPE_24_HOUR_GAP = 86400
NETSKOPE_INITIAL_SKIP_VALUE = 0
NETSKOPE_UPDATE_SKIP_VALUE = 5000
NETSKOPE_DEFAULT_LIMIT = 50
NETSKOPE_URL_LIST = 'netskope_url_list'
NETSKOPE_FILE_LIST = 'netskope_file_list'
NETSKOPE_LIST_NAME = 'list_name'
