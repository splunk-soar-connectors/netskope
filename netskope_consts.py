# File: netskope_consts.py
#
# Copyright 2018-2022 Netskope, Inc.
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
NETSKOPE_CONFIG_V2_API_KEY = 'v2_api_key'  # pragma: allowlist secret
NETSKOPE_CONNECTIVITY_ENDPOINT = '/api/v1/clients'
NETSKOPE_QUARANTINE_ENDPOINT = '/api/v1/quarantine'
NETSKOPE_ON_POLL_ENDPOINT = '/api/v1/alerts'
NETSKOPE_EVENTS_ENDPOINT = '/api/v1/events'
NETSKOPE_URL_LIST_ENDPOINT = '/api/v1/updateUrlList'
NETSKOPE_FILE_LIST_ENDPOINT = '/api/v1/updateFileHashList'
NETSKOPE_V2_EVENT_ENDPOINT = '/api/v2/events/data'
NETSKOPE_PAGE_EVENT = 'page'
NETSKOPE_APPLICATION_EVENT = 'application'
NETSKOPE_ALERT_EVENT = 'alert'
NETSKOPE_V2_URL_LIST_ENDPOINT = '/api/v2/policy/urllist'
NETSKOPE_DEPLOY_URL_LIST = 'deploy'
NETSKOPE_SCIM_USERS_ENDPOINT = '/Users'
NETSKOPE_SCIM_GROUPS_ENDPOINT = '/Groups'
NETSKOPE_SCIM_GROUP_ENDPOINT = '/Group'
NETSKOPE_V2_API_PREFIX = '/api/v2'
NETSKOPE_PARAM_LIST_FILES = 'get-files'
NETSKOPE_PARAM_IP = 'ip'
NETSKOPE_PARAM_URL = 'url'
NETSKOPE_PARAM_USER = 'user'
NETSKOPE_PARAM_GROUP = 'group'
NETSKOPE_PARAM_HASH = 'hash'
NETSKOPE_PARAM_START_TIME = 'start_time'
NETSKOPE_PARAM_END_TIME = 'end_time'
NETSKOPE_QUERY_PARAM = 'srcip eq {srcip} or dstip eq {dstip}'
NETSKOPE_INVALID_START_TIME = "Parameter 'start_time' failed validation"
NETSKOPE_INVALID_END_TIME = "Parameter 'end_time' failed validation"
NETSKOPE_INVALID_TIME_RANGE = "Invalid time range. 'end_time' should be greater than 'start_time'"
NETSKOPE_INVALID_TIME = 'Invalid time. Time cannot be negative'
NETSKOPE_VALID_TIME = 'TIme validation successful'
NETSKOPE_CONNECTIVITY_PASS_MSG = 'Test Connectivity Passed for v1 API key'
NETSKOPE_V2_CONNECTIVITY_PASS_MSG = 'Test Connectivity Passed for v2 API key'
NETSKOPE_CONNECTIVITY_FAIL_MSG = 'Test Connectivity Failed for v1 API key'
NETSKOPE_V2_CONNECTIVITY_FAIL_MSG = 'Test Connectivity Failed for v2 API key'
NETSKOPE_CONNECTION_MSG = 'Querying endpoint to verify the credentials provided'
NETSKOPE_ERR_CONNECTING_SERVER = 'Error while connecting to server'
NETSKOPE_V2_KEY_FOUND_MSG = 'Found v2 API key in asset configuration'
NETSKOPE_V2_CONNECTION_MSG = 'Querying endpoint to verify the key provided'
NETSKOPE_ERR_CODE_MSG = 'Error code unavailable'
NETSKOPE_ERR_MSG = 'Unknown error occurred. Please check the asset configuration and|or action parameters'
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
NETSKOPE_STATE_FILE_CORRUPT_ERR = (
    "Error occurred while loading the state file due to its unexpected format. "
    "Resetting the state file with the default format. Please try again."
)
NETSKOPE_MISSING_MSG = "MISSING MESSAGE"
NETSKOPE_MISSING_BOTH_API_KEYS_ERR = "Please configure either 'v1 API Key' or 'v2 API Key'(recommended)"
NETSKOPE_ACTION_HANDLER_MSG = "In action handler for: {0}"

# Timeout
NETSKOPE_DEFAULT_TIMEOUT = 30
