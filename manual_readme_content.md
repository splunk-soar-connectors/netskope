[comment]: # " File: README.md"
[comment]: # "  Copyright 2018-2025 Netskope, Inc."
[comment]: # ""
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
## Playbook Backward Compatibility

-   The 'total_files' summary key has been replaced with the 'total_urls' key in output data paths
    for 'update url' action. This key will represent the total URLs updated on Netskope UI. Hence,
    it is requested to the end-user to please update their existing playbooks by re-inserting |
    modifying | deleting the corresponding action blocks to ensure the correct functioning of the
    playbooks created on the earlier versions of the app.
-   The 'total_files' summary key has been replaced with the 'total_hashes' key in output data paths
    for 'update hash' action. This key will represent the total hashes updated on Netskope UI.
    Hence, it is requested to the end-user to please update their existing playbooks by re-inserting
    | modifying | deleting the corresponding action blocks to ensure the correct functioning of
    the playbooks created on the earlier versions of the app.

## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Netskope server. Below are the default
ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |

<div class="document">

<div class="documentwrapper">

<div class="bodywrapper">

<div class="body" role="main">

<div id="usage-notes" class="section">

# Usage notes

<div class="toctree-wrapper compound">



<div id="action-notes" class="section">

## Action Notes

-   Below actions will use V2 REST API
    [endpoints](https://docs.netskope.com/en/rest-api-v2-overview-312207.html) if **V2 API Key** is
    configured in the asset. Actions will continue to support V1 API Key if V2 API Key is not
    provided, but it is recommended to use V2 API Key.
    -   run query
    -   update url
    -   on poll
-   Test Connectivity will behave as described below:
    -   If V1 API Key is configured, then the connectivity will be checked for V1 API Key
    -   If V2 API Key is configured, then the connectivity will be checked for V2 API Key
    -   If both are configured then the connectivity will be checked with both API Keys
    -   If none is provided then the message will be thrown to configure at least one
-   Below actions will continue to use V1 API endpoints so without configuring **V1 API Key** below
    actions will fail.
    -   update hash
    -   list files
    -   get file
-   Actions listed below just update the Splunk SOAR list and do not make any REST calls to the
    Netskope, so they'll work without any API Key.
    -   add url
    -   remove url
    -   add hash
    -   remove hash
-   V2 REST API token must have access to the below mentioned endpoints to run all the V2 supported
    actions properly.
    -   /api/v2/events/data/page (Read)
    -   /api/v2/events/data/alert (Read)
    -   /api/v2/events/data/application (Read)
    -   /api/v2/policy/urllist (Read + Write)
    -   /api/v2/policy/urllist/deploy (Read + Write)
-   In Splunk SOAR, a configured file list will be created with **{list_name}\_file_list** format
    and a url list will be created with **{list_name}\_url_list** . Where, list_name is a configured
    asset parameter.
-   In order to reflect the URL/file_hash values to the Netskope, the same profile must exist at the
    Netskope. i.e., if test_list is provided as a list_name in the asset configuration, the same
    name of the profile should exist on the Netskope server.



<div id="support" class="section">

## Support

Please contact Netskope Support for any issues relating to this app.












