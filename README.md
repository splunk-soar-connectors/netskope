[comment]: # "Auto-generated SOAR connector documentation"
# Netskope

Publisher: Netskope  
Connector Version: 3\.0\.0  
Product Vendor: Netskope  
Product Name: Netskope  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.3  

This app integrates with the Netskope to execute various investigative and polling actions

[comment]: # " File: README.md"
[comment]: # "  Copyright 2018-2022 Netskope, Inc."
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
    it is requested to the end-user to please update their existing playbooks by re-inserting \|
    modifying \| deleting the corresponding action blocks to ensure the correct functioning of the
    playbooks created on the earlier versions of the app.
-   The 'total_files' summary key has been replaced with the 'total_hashes' key in output data paths
    for 'update hash' action. This key will represent the total hashes updated on Netskope UI.
    Hence, it is requested to the end-user to please update their existing playbooks by re-inserting
    \| modifying \| deleting the corresponding action blocks to ensure the correct functioning of
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

</div>

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

</div>

<div id="support" class="section">

## Support

Please contact Netskope Support for any issues relating to this app.

</div>

</div>

</div>

</div>

</div>

</div>


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Netskope asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server\_url** |  required  | string | Server URL
**v2\_api\_key** |  optional  | password | V2 API Key \(recommended\)
**scim\_url** |  optional  | string | SCIM Server URL
**scim\_key** |  optional  | password | SCIM Token
**list\_name** |  optional  | string | Netskope List Name \(both URL and file hash\)
**api\_key** |  optional  | password | V1 API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get file](#action-get-file) - Download a quarantined file and upload it to the vault  
[get scim users](#action-get-scim-users) - Get current SCIM user\(s\)\. If no parameter is sent, it will retrieve all users  
[get scim groups](#action-get-scim-groups) - Get current SCIM group\(s\)\. If no parameter is sent, it will retrieve all users  
[create scim group](#action-create-scim-group) - Create SCIM group  
[create scim user](#action-create-scim-user) - Create SCIM user  
[scim user group](#action-scim-user-group) - Add or Remove a user from a SCIM group  
[list files](#action-list-files) - List all quarantined files  
[run query](#action-run-query) - Run query for events on a given IP  
[on poll](#action-on-poll) - Ingest data to Phantom  
[add url](#action-add-url) - Add an URL to the Netskope URL Blocklist  
[remove url](#action-remove-url) - Remove an URL from the Netskope URL Blocklist  
[update url](#action-update-url) - Send the url list to Netskope  
[add hash](#action-add-hash) - Add a file hash to the Netskope file hash list  
[remove hash](#action-remove-hash) - Remove a hash from the Netskope file hash list  
[update hash](#action-update-hash) - Send the file hash list to Netskope  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get file'
Download a quarantined file and upload it to the vault

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file** |  required  | ID or quarantined name of the file to download | string |  `netskope file id`  `file name` 
**profile** |  required  | Quarantine profile ID or quarantined profile name | string |  `netskope profile id`  `netskope profile name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file | string |  `netskope file id`  `file name` 
action\_result\.parameter\.profile | string |  `netskope profile id`  `netskope profile name` 
action\_result\.data\.\*\.file\_name | string |  `file name` 
action\_result\.data\.\*\.vault\_id | string |  `vault id` 
action\_result\.summary\.vault\_id | string |  `vault id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get scim users'
Get current SCIM user\(s\)\. If no parameter is sent, it will retrieve all users

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user** |  optional  | Username or email to find | string |  `netskope user`  `email`  `user name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.user | string |  `netskope user`  `email`  `user name` 
action\_result\.data\.\*\.active | boolean | 
action\_result\.data\.\*\.emails\.\*\.primary | boolean | 
action\_result\.data\.\*\.emails\.\*\.type | string | 
action\_result\.data\.\*\.emails\.\*\.value | string | 
action\_result\.data\.\*\.externalId | string |  `netskope external id` 
action\_result\.data\.\*\.id | string |  `netskope scim user id` 
action\_result\.data\.\*\.name\.familyName | string | 
action\_result\.data\.\*\.name\.givenName | string | 
action\_result\.data\.\*\.userName | string |  `netskope user`  `user name`  `email` 
action\_result\.summary\.total\_users | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get scim groups'
Get current SCIM group\(s\)\. If no parameter is sent, it will retrieve all users

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group** |  optional  | Group Display Name to find | string |  `netskope group name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.group | string |  `netskope group name` 
action\_result\.data\.\*\.displayName | string |  `netskope group name` 
action\_result\.data\.\*\.externalId | string |  `netskope external id` 
action\_result\.data\.\*\.id | string |  `netskope scim group id` 
action\_result\.data\.\*\.meta\.resourceType | string | 
action\_result\.summary\.total\_groups | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create scim group'
Create SCIM group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group** |  required  | Group Name | string |  `netskope group name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.group | string |  `netskope group name` 
action\_result\.data\.\*\.displayName | string | 
action\_result\.data\.\*\.id | string |  `netskope scim group id` 
action\_result\.summary\.total\_groups | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create scim user'
Create SCIM user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user** |  required  | User Name | string |  `netskope user` 
**familyName** |  optional  | Family Name | string | 
**givenName** |  optional  | Given Name | string | 
**email** |  required  | Primary Email | string |  `netskope user`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `netskope user`  `email` 
action\_result\.parameter\.familyName | string | 
action\_result\.parameter\.givenName | string | 
action\_result\.parameter\.user | string |  `netskope user` 
action\_result\.data\.\*\.active | boolean | 
action\_result\.data\.\*\.emails\.\*\.primary | boolean | 
action\_result\.data\.\*\.emails\.\*\.value | string | 
action\_result\.data\.\*\.id | string |  `netskope scim user id` 
action\_result\.data\.\*\.mail | string | 
action\_result\.data\.\*\.name\.familyName | string | 
action\_result\.data\.\*\.name\.givenName | string | 
action\_result\.data\.\*\.status | numeric | 
action\_result\.data\.\*\.userName | string | 
action\_result\.summary\.total\_users | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'scim user group'
Add or Remove a user from a SCIM group

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group** |  required  | Group ID | string |  `netskope scim group id` 
**user** |  required  | User ID | string |  `netskope scim user id` 
**action** |  required  | Action to perform | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action | string | 
action\_result\.parameter\.group | string |  `netskope scim group id` 
action\_result\.parameter\.user | string |  `netskope scim user id` 
action\_result\.data\.\*\.displayName | string |  `netskope group name` 
action\_result\.summary\.total\_users | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list files'
List all quarantined files

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.file\_id | string |  `netskope file id` 
action\_result\.data\.\*\.original\_file\_name | string |  `file name` 
action\_result\.data\.\*\.policy | string | 
action\_result\.data\.\*\.quarantine\_profile\_id | string |  `netskope profile id` 
action\_result\.data\.\*\.quarantine\_profile\_name | string |  `netskope profile name` 
action\_result\.data\.\*\.quarantined\_file\_name | string |  `file name` 
action\_result\.data\.\*\.user\_id | string |  `email` 
action\_result\.summary\.total\_files | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run query'
Run query for events on a given IP

Type: **investigate**  
Read only: **True**

<ul><li>If no &quotstart\_time&quot and &quotend\_time&quot is provided, the action will take the last 24 hours as the time period\.<li>If only &quotstart\_time&quot is provided, current time would be taken as &quotend\_time&quot\.<li>If only &quotend\_time&quot is provided, 24 hours prior to &quotend\_time&quot would be taken as &quotstart\_time&quot\.<li>The action only returns page and application events for the given IP\.</ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to be queried for | string |  `ip` 
**start\_time** |  optional  | Start time epoch | numeric | 
**end\_time** |  optional  | End time epoch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.end\_time | numeric | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.start\_time | numeric | 
action\_result\.data\.\*\.application\.\*\.\_id | string | 
action\_result\.data\.\*\.application\.\*\.access\_method | string | 
action\_result\.data\.\*\.application\.\*\.act\_user | string | 
action\_result\.data\.\*\.application\.\*\.action | string | 
action\_result\.data\.\*\.application\.\*\.activity | string | 
action\_result\.data\.\*\.application\.\*\.alert | string | 
action\_result\.data\.\*\.application\.\*\.app | string | 
action\_result\.data\.\*\.application\.\*\.app\_activity | string | 
action\_result\.data\.\*\.application\.\*\.app\_session\_id | numeric | 
action\_result\.data\.\*\.application\.\*\.appcategory | string | 
action\_result\.data\.\*\.application\.\*\.appsuite | string | 
action\_result\.data\.\*\.application\.\*\.browser | string | 
action\_result\.data\.\*\.application\.\*\.browser\_session\_id | numeric | 
action\_result\.data\.\*\.application\.\*\.browser\_version | string | 
action\_result\.data\.\*\.application\.\*\.category | string | 
action\_result\.data\.\*\.application\.\*\.cci | numeric | 
action\_result\.data\.\*\.application\.\*\.ccl | string | 
action\_result\.data\.\*\.application\.\*\.connection\_id | numeric | 
action\_result\.data\.\*\.application\.\*\.count | numeric | 
action\_result\.data\.\*\.application\.\*\.data\_type | string | 
action\_result\.data\.\*\.application\.\*\.device | string | 
action\_result\.data\.\*\.application\.\*\.device\_classification | string | 
action\_result\.data\.\*\.application\.\*\.dst\_country | string | 
action\_result\.data\.\*\.application\.\*\.dst\_geoip\_src | numeric | 
action\_result\.data\.\*\.application\.\*\.dst\_latitude | numeric | 
action\_result\.data\.\*\.application\.\*\.dst\_location | string | 
action\_result\.data\.\*\.application\.\*\.dst\_longitude | numeric | 
action\_result\.data\.\*\.application\.\*\.dst\_region | string | 
action\_result\.data\.\*\.application\.\*\.dst\_timezone | string | 
action\_result\.data\.\*\.application\.\*\.dst\_zipcode | string | 
action\_result\.data\.\*\.application\.\*\.dstip | string |  `ip` 
action\_result\.data\.\*\.application\.\*\.encrypt\_failure | string | 
action\_result\.data\.\*\.application\.\*\.file\_category | string | 
action\_result\.data\.\*\.application\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.application\.\*\.file\_type | string | 
action\_result\.data\.\*\.application\.\*\.from\_object | string | 
action\_result\.data\.\*\.application\.\*\.from\_storage | string | 
action\_result\.data\.\*\.application\.\*\.from\_user | string |  `email` 
action\_result\.data\.\*\.application\.\*\.hostname | string | 
action\_result\.data\.\*\.application\.\*\.id | numeric | 
action\_result\.data\.\*\.application\.\*\.incident\_id | numeric | 
action\_result\.data\.\*\.application\.\*\.instance\_id | string | 
action\_result\.data\.\*\.application\.\*\.managed\_app | string | 
action\_result\.data\.\*\.application\.\*\.managementID | string | 
action\_result\.data\.\*\.application\.\*\.md5 | string | 
action\_result\.data\.\*\.application\.\*\.netskope\_activity | string | 
action\_result\.data\.\*\.application\.\*\.netskope\_pop | string | 
action\_result\.data\.\*\.application\.\*\.nsdeviceuid | string | 
action\_result\.data\.\*\.application\.\*\.object | string | 
action\_result\.data\.\*\.application\.\*\.object\_id | string | 
action\_result\.data\.\*\.application\.\*\.object\_type | string | 
action\_result\.data\.\*\.application\.\*\.org | string |  `domain` 
action\_result\.data\.\*\.application\.\*\.organization\_unit | string | 
action\_result\.data\.\*\.application\.\*\.os | string | 
action\_result\.data\.\*\.application\.\*\.os\_version | string | 
action\_result\.data\.\*\.application\.\*\.page | string | 
action\_result\.data\.\*\.application\.\*\.page\_id | numeric | 
action\_result\.data\.\*\.application\.\*\.page\_site | string | 
action\_result\.data\.\*\.application\.\*\.policy | string | 
action\_result\.data\.\*\.application\.\*\.policy\_id | string | 
action\_result\.data\.\*\.application\.\*\.protocol | string | 
action\_result\.data\.\*\.application\.\*\.referer | string | 
action\_result\.data\.\*\.application\.\*\.request\_id | numeric | 
action\_result\.data\.\*\.application\.\*\.sanctioned\_instance | string | 
action\_result\.data\.\*\.application\.\*\.severity | string | 
action\_result\.data\.\*\.application\.\*\.site | string | 
action\_result\.data\.\*\.application\.\*\.src\_country | string | 
action\_result\.data\.\*\.application\.\*\.src\_geoip\_src | numeric | 
action\_result\.data\.\*\.application\.\*\.src\_latitude | numeric | 
action\_result\.data\.\*\.application\.\*\.src\_location | string | 
action\_result\.data\.\*\.application\.\*\.src\_longitude | numeric | 
action\_result\.data\.\*\.application\.\*\.src\_region | string | 
action\_result\.data\.\*\.application\.\*\.src\_time | string | 
action\_result\.data\.\*\.application\.\*\.src\_timezone | string | 
action\_result\.data\.\*\.application\.\*\.src\_zipcode | string | 
action\_result\.data\.\*\.application\.\*\.srcip | string |  `ip` 
action\_result\.data\.\*\.application\.\*\.suppression\_end\_time | numeric | 
action\_result\.data\.\*\.application\.\*\.suppression\_start\_time | numeric | 
action\_result\.data\.\*\.application\.\*\.sv | string | 
action\_result\.data\.\*\.application\.\*\.telemetry\_app | string | 
action\_result\.data\.\*\.application\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.application\.\*\.to\_user | string |  `email` 
action\_result\.data\.\*\.application\.\*\.traffic\_type | string | 
action\_result\.data\.\*\.application\.\*\.transaction\_id | numeric | 
action\_result\.data\.\*\.application\.\*\.tss\_mode | string | 
action\_result\.data\.\*\.application\.\*\.type | string | 
action\_result\.data\.\*\.application\.\*\.universal\_connector | string | 
action\_result\.data\.\*\.application\.\*\.ur\_normalized | string | 
action\_result\.data\.\*\.application\.\*\.url | string |  `url` 
action\_result\.data\.\*\.application\.\*\.user | string |  `email` 
action\_result\.data\.\*\.application\.\*\.user\_category | string | 
action\_result\.data\.\*\.application\.\*\.user\_id | string | 
action\_result\.data\.\*\.application\.\*\.user\_name | string | 
action\_result\.data\.\*\.application\.\*\.user\_role | string | 
action\_result\.data\.\*\.application\.\*\.useragent | string | 
action\_result\.data\.\*\.application\.\*\.userip | string |  `ip` 
action\_result\.data\.\*\.application\.\*\.userkey | string |  `email` 
action\_result\.data\.\*\.application\.\*\.web\_universal\_connector | string | 
action\_result\.data\.\*\.page\.\*\.\_id | string | 
action\_result\.data\.\*\.page\.\*\.access\_method | string | 
action\_result\.data\.\*\.page\.\*\.app | string | 
action\_result\.data\.\*\.page\.\*\.app\_action\_cnt | numeric | 
action\_result\.data\.\*\.page\.\*\.app\_session\_id | numeric | 
action\_result\.data\.\*\.page\.\*\.appcategory | string | 
action\_result\.data\.\*\.page\.\*\.browser | string | 
action\_result\.data\.\*\.page\.\*\.browser\_session\_id | numeric | 
action\_result\.data\.\*\.page\.\*\.browser\_version | string | 
action\_result\.data\.\*\.page\.\*\.bypass\_reason | string | 
action\_result\.data\.\*\.page\.\*\.bypass\_traffic | string | 
action\_result\.data\.\*\.page\.\*\.category | string | 
action\_result\.data\.\*\.page\.\*\.cci | numeric | 
action\_result\.data\.\*\.page\.\*\.ccl | string | 
action\_result\.data\.\*\.page\.\*\.client\_bytes | numeric | 
action\_result\.data\.\*\.page\.\*\.conn\_duration | numeric | 
action\_result\.data\.\*\.page\.\*\.conn\_endtime | numeric | 
action\_result\.data\.\*\.page\.\*\.conn\_starttime | numeric | 
action\_result\.data\.\*\.page\.\*\.connection\_id | numeric | 
action\_result\.data\.\*\.page\.\*\.count | numeric | 
action\_result\.data\.\*\.page\.\*\.device | string | 
action\_result\.data\.\*\.page\.\*\.domain | string | 
action\_result\.data\.\*\.page\.\*\.dst\_country | string | 
action\_result\.data\.\*\.page\.\*\.dst\_geoip\_src | numeric | 
action\_result\.data\.\*\.page\.\*\.dst\_latitude | numeric | 
action\_result\.data\.\*\.page\.\*\.dst\_location | string | 
action\_result\.data\.\*\.page\.\*\.dst\_longitude | numeric | 
action\_result\.data\.\*\.page\.\*\.dst\_region | string | 
action\_result\.data\.\*\.page\.\*\.dst\_timezone | string | 
action\_result\.data\.\*\.page\.\*\.dst\_zipcode | string | 
action\_result\.data\.\*\.page\.\*\.dstip | string |  `ip` 
action\_result\.data\.\*\.page\.\*\.dstport | numeric | 
action\_result\.data\.\*\.page\.\*\.hostname | string | 
action\_result\.data\.\*\.page\.\*\.http\_transaction\_count | numeric | 
action\_result\.data\.\*\.page\.\*\.id | numeric | 
action\_result\.data\.\*\.page\.\*\.incident\_id | numeric | 
action\_result\.data\.\*\.page\.\*\.latency\_max | numeric | 
action\_result\.data\.\*\.page\.\*\.latency\_min | numeric | 
action\_result\.data\.\*\.page\.\*\.latency\_total | numeric | 
action\_result\.data\.\*\.page\.\*\.netskope\_pop | string | 
action\_result\.data\.\*\.page\.\*\.numbytes | numeric | 
action\_result\.data\.\*\.page\.\*\.org | string |  `domain` 
action\_result\.data\.\*\.page\.\*\.organization\_unit | string | 
action\_result\.data\.\*\.page\.\*\.os | string | 
action\_result\.data\.\*\.page\.\*\.os\_version | string | 
action\_result\.data\.\*\.page\.\*\.page | string | 
action\_result\.data\.\*\.page\.\*\.page\_duration | numeric | 
action\_result\.data\.\*\.page\.\*\.page\_endtime | numeric | 
action\_result\.data\.\*\.page\.\*\.page\_id | numeric | 
action\_result\.data\.\*\.page\.\*\.page\_starttime | numeric | 
action\_result\.data\.\*\.page\.\*\.policy | string | 
action\_result\.data\.\*\.page\.\*\.protocol | string | 
action\_result\.data\.\*\.page\.\*\.req\_cnt | numeric | 
action\_result\.data\.\*\.page\.\*\.request\_id | numeric | 
action\_result\.data\.\*\.page\.\*\.resp\_cnt | numeric | 
action\_result\.data\.\*\.page\.\*\.resp\_content\_len | numeric | 
action\_result\.data\.\*\.page\.\*\.resp\_content\_type | string | 
action\_result\.data\.\*\.page\.\*\.server\_bytes | numeric | 
action\_result\.data\.\*\.page\.\*\.severity | string | 
action\_result\.data\.\*\.page\.\*\.site | string | 
action\_result\.data\.\*\.page\.\*\.slc\_latitude | numeric | 
action\_result\.data\.\*\.page\.\*\.slc\_longitude | numeric | 
action\_result\.data\.\*\.page\.\*\.src\_country | string | 
action\_result\.data\.\*\.page\.\*\.src\_geoip\_src | numeric | 
action\_result\.data\.\*\.page\.\*\.src\_latitude | numeric | 
action\_result\.data\.\*\.page\.\*\.src\_location | string | 
action\_result\.data\.\*\.page\.\*\.src\_longitude | numeric | 
action\_result\.data\.\*\.page\.\*\.src\_region | string | 
action\_result\.data\.\*\.page\.\*\.src\_time | string | 
action\_result\.data\.\*\.page\.\*\.src\_timezone | string | 
action\_result\.data\.\*\.page\.\*\.src\_zipcode | string | 
action\_result\.data\.\*\.page\.\*\.srcip | string |  `ip` 
action\_result\.data\.\*\.page\.\*\.ssl\_decrypt\_policy | string | 
action\_result\.data\.\*\.page\.\*\.suppression\_end\_time | numeric | 
action\_result\.data\.\*\.page\.\*\.suppression\_start\_time | numeric | 
action\_result\.data\.\*\.page\.\*\.sv | string | 
action\_result\.data\.\*\.page\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.page\.\*\.traffic\_type | string | 
action\_result\.data\.\*\.page\.\*\.transaction\_id | numeric | 
action\_result\.data\.\*\.page\.\*\.type | string | 
action\_result\.data\.\*\.page\.\*\.ur\_normalized | string | 
action\_result\.data\.\*\.page\.\*\.url | string |  `url` 
action\_result\.data\.\*\.page\.\*\.user | string |  `email` 
action\_result\.data\.\*\.page\.\*\.user\_generated | string | 
action\_result\.data\.\*\.page\.\*\.useragent | string | 
action\_result\.data\.\*\.page\.\*\.userip | string |  `ip` 
action\_result\.data\.\*\.page\.\*\.userkey | string |  `email` 
action\_result\.summary\.total\_application\_events | numeric | 
action\_result\.summary\.total\_page\_events | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Ingest data to Phantom

Type: **ingest**  
Read only: **True**

For <b>manual run</b> and <b>first poll</b>, alerts of the last 24 hours would be ingested\. Subsequent polls will ingest new alerts\.<br>Only alerts of type &quotMalware&quot will be ingested\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_count** |  optional  | Maximum number of containers to ingest | numeric | 
**container\_id** |  optional  | Parameter ignored in this app | string | 
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'add url'
Add an URL to the Netskope URL Blocklist

Type: **contain**  
Read only: **False**

This action will add URL value to the configured Splunk SOAR custom list only and that will be reflected in the Netskope after <b>update url</b> action is performed\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to block | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.data | string | 
action\_result\.summary\.set\_list | string | 
action\_result\.summary\.total\_files | numeric | 
action\_result\.summary\.total\_urls | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove url'
Remove an URL from the Netskope URL Blocklist

Type: **correct**  
Read only: **False**

This action will remove URL value from the configured Splunk SOAR custom list only and that will be reflected in the Netskope after <b>update url</b> action is performed\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to remove | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.data | string | 
action\_result\.summary\.remove\_msg | string | 
action\_result\.summary\.total\_files | numeric | 
action\_result\.summary\.total\_urls | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update url'
Send the url list to Netskope

Type: **contain**  
Read only: **False**

This action replaces the URL list of a Netskope server with the configured Splunk SOAR custom URL list\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data | string | 
action\_result\.summary\.total\_files | numeric | 
action\_result\.summary\.total\_urls | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add hash'
Add a file hash to the Netskope file hash list

Type: **contain**  
Read only: **False**

This action will add file hash value to the configured Splunk SOAR custom list only and that will be reflected in the Netskope after <b>update hash</b> action is performed\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to add | string |  `hash`  `md5`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha256` 
action\_result\.data | string | 
action\_result\.summary\.set\_list | string | 
action\_result\.summary\.total\_files | numeric | 
action\_result\.summary\.total\_hashes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove hash'
Remove a hash from the Netskope file hash list

Type: **correct**  
Read only: **False**

This action will remove file hash value from the configured Splunk SOAR custom list only and that will be reflected in the Netskope after <b>update hash</b> action is performed\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to remove | string |  `hash`  `md5`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha256` 
action\_result\.data | string | 
action\_result\.summary\.remove\_msg | string | 
action\_result\.summary\.total\_files | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update hash'
Send the file hash list to Netskope

Type: **contain**  
Read only: **False**

This action replaces the hash list of a Netskope server with the configured Splunk SOAR custom hash list\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data | string | 
action\_result\.summary\.total\_files | numeric | 
action\_result\.summary\.total\_hashes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 