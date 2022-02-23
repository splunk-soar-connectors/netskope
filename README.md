[comment]: # "Auto-generated SOAR connector documentation"
# Netskope

Publisher: Netskope  
Connector Version: 2\.1\.1  
Product Vendor: Netskope  
Product Name: Netskope  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app integrates with the Netskope to execute various investigative and polling actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2018-2022 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
<div class="document">

<div class="documentwrapper">

<div class="bodywrapper">

<div class="body" role="main">

<div id="usage-notes" class="section">

# Usage notes <a href="#usage-notes" class="headerlink" title="Permalink to this headline">¶</a>

<div class="toctree-wrapper compound">

</div>

<div id="action-notes" class="section">

## Action Notes <a href="#action-notes" class="headerlink" title="Permalink to this headline">¶</a>

Notes on Actions.

</div>

<div id="support" class="section">

## Support <a href="#support" class="headerlink" title="Permalink to this headline">¶</a>

Please contact Netskope Support for any issues relating to this app.

</div>

<div id="release-notes" class="section">

## Release Notes <a href="#release-notes" class="headerlink" title="Permalink to this headline">¶</a>

<div id="v1-0-5" class="section">

### v1.0.5 <a href="#release-notes" class="headerlink" title="Permalink to this headline">¶</a>

</div>

</div>

</div>

</div>

</div>

</div>

<div class="sphinxsidebar" aria-label="main navigation" role="navigation">

<div class="sphinxsidebarwrapper">

<div class="relations">

### Related Topics

-   [Documentation overview](index.html#document-index)

</div>

</div>

</div>

<div class="clearer">

</div>

</div>

<div class="footer">

©2019, . \| Powered by [Sphinx 1.6.2](http://sphinx-doc.org/) & [Alabaster
0.7.10](https://github.com/bitprophet/alabaster)

</div>


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Netskope asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server\_url** |  required  | string | Server URL
**api\_key** |  required  | password | API Key
**scim\_url** |  optional  | string | SCIM Server URL
**scim\_key** |  optional  | password | SCIM Token
**list\_name** |  optional  | string | Netskope List Name \(both Url and File Hash\)

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
action\_result\.summary\.\* | string | 
action\_result\.message | string | 
action\_result\.parameter\.user | string |  `netskope user`  `email`  `user name` 
action\_result\.data\.\*\.userName | string |  `netskope user`  `user name`  `email` 
action\_result\.data\.\*\.active | boolean | 
action\_result\.data\.\*\.id | string |  `netskope scim user id` 
action\_result\.data\.\*\.externalId | string |  `netskope external id` 
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
action\_result\.summary\.\* | string | 
action\_result\.message | string | 
action\_result\.parameter\.group | string |  `netskope group name` 
action\_result\.data\.\*\.displayName | string |  `netskope group name` 
action\_result\.data\.\*\.id | string |  `netskope scim group id` 
action\_result\.data\.\*\.externalId | string |  `netskope external id` 
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
action\_result\.summary\.\* | string | 
action\_result\.message | string | 
action\_result\.parameter\.group | string |  `netskope group name` 
action\_result\.data\.\*\.displayName | string | 
action\_result\.data\.\*\.id | string |  `netskope scim group id` 
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
action\_result\.summary\.\* | string | 
action\_result\.message | string | 
action\_result\.parameter\.user | string |  `netskope user` 
action\_result\.parameter\.familyName | string | 
action\_result\.parameter\.givenName | string | 
action\_result\.parameter\.email | string |  `netskope user`  `email` 
action\_result\.data\.\*\.userName | string | 
action\_result\.data\.\*\.id | string |  `netskope scim user id` 
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
action\_result\.summary\.\* | string | 
action\_result\.message | string | 
action\_result\.parameter\.group | string |  `netskope scim group id` 
action\_result\.parameter\.action | string | 
action\_result\.parameter\.user | string |  `netskope scim user id` 
action\_result\.data\.\*\.displayName | string |  `netskope group name` 
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

<ul><li>If no &quotstart\_time&quot and &quotend\_time&quot is provided, the action will take the last 24 hours as the time period\.<li>If only &quotstart\_time&quot is provided, current time would be taken as &quotend\_time&quot\.<li>If only &quotend\_time&quot is provided, 24 hours prior to &quotend\_time&quot would be taken as &quotstart\_time&quot\.</ul>

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
action\_result\.data\.\*\.application\.\*\.\_insertion\_epoch\_timestamp | numeric | 
action\_result\.data\.\*\.application\.\*\.activity | string | 
action\_result\.data\.\*\.application\.\*\.alert | string | 
action\_result\.data\.\*\.application\.\*\.app | string | 
action\_result\.data\.\*\.application\.\*\.app\_session\_id | numeric | 
action\_result\.data\.\*\.application\.\*\.appcategory | string | 
action\_result\.data\.\*\.application\.\*\.browser | string | 
action\_result\.data\.\*\.application\.\*\.category | string | 
action\_result\.data\.\*\.application\.\*\.cci | numeric | 
action\_result\.data\.\*\.application\.\*\.ccl | string | 
action\_result\.data\.\*\.application\.\*\.count | numeric | 
action\_result\.data\.\*\.application\.\*\.device | string | 
action\_result\.data\.\*\.application\.\*\.dst\_country | string | 
action\_result\.data\.\*\.application\.\*\.dst\_location | string | 
action\_result\.data\.\*\.application\.\*\.dst\_region | string | 
action\_result\.data\.\*\.application\.\*\.dst\_zipcode | string | 
action\_result\.data\.\*\.application\.\*\.dstip | string |  `ip` 
action\_result\.data\.\*\.application\.\*\.from\_object | string | 
action\_result\.data\.\*\.application\.\*\.from\_user | string |  `email` 
action\_result\.data\.\*\.application\.\*\.id | numeric | 
action\_result\.data\.\*\.application\.\*\.object | string | 
action\_result\.data\.\*\.application\.\*\.object\_type | string | 
action\_result\.data\.\*\.application\.\*\.org | string |  `domain` 
action\_result\.data\.\*\.application\.\*\.organization\_unit | string | 
action\_result\.data\.\*\.application\.\*\.os | string | 
action\_result\.data\.\*\.application\.\*\.page\_id | numeric | 
action\_result\.data\.\*\.application\.\*\.policy | string | 
action\_result\.data\.\*\.application\.\*\.site | string | 
action\_result\.data\.\*\.application\.\*\.src\_country | string | 
action\_result\.data\.\*\.application\.\*\.src\_latitude | numeric | 
action\_result\.data\.\*\.application\.\*\.src\_location | string | 
action\_result\.data\.\*\.application\.\*\.src\_longitude | numeric | 
action\_result\.data\.\*\.application\.\*\.src\_region | string | 
action\_result\.data\.\*\.application\.\*\.src\_zipcode | string | 
action\_result\.data\.\*\.application\.\*\.srcip | string |  `ip` 
action\_result\.data\.\*\.application\.\*\.sv | string | 
action\_result\.data\.\*\.application\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.application\.\*\.to\_user | string |  `email` 
action\_result\.data\.\*\.application\.\*\.traffic\_type | string | 
action\_result\.data\.\*\.application\.\*\.type | string | 
action\_result\.data\.\*\.application\.\*\.url | string |  `url` 
action\_result\.data\.\*\.application\.\*\.user | string |  `email` 
action\_result\.data\.\*\.application\.\*\.userip | string |  `ip` 
action\_result\.data\.\*\.application\.\*\.userkey | string |  `email` 
action\_result\.data\.\*\.page\.\*\.\_id | string | 
action\_result\.data\.\*\.page\.\*\.\_insertion\_epoch\_timestamp | numeric | 
action\_result\.data\.\*\.page\.\*\.app | string | 
action\_result\.data\.\*\.page\.\*\.app\_action\_cnt | numeric | 
action\_result\.data\.\*\.page\.\*\.app\_session\_id | numeric | 
action\_result\.data\.\*\.page\.\*\.appcategory | string | 
action\_result\.data\.\*\.page\.\*\.browser | string | 
action\_result\.data\.\*\.page\.\*\.category | string | 
action\_result\.data\.\*\.page\.\*\.cci | numeric | 
action\_result\.data\.\*\.page\.\*\.ccl | string | 
action\_result\.data\.\*\.page\.\*\.client\_bytes | numeric | 
action\_result\.data\.\*\.page\.\*\.count | numeric | 
action\_result\.data\.\*\.page\.\*\.device | string | 
action\_result\.data\.\*\.page\.\*\.dst\_country | string | 
action\_result\.data\.\*\.page\.\*\.dst\_location | string | 
action\_result\.data\.\*\.page\.\*\.dst\_region | string | 
action\_result\.data\.\*\.page\.\*\.dst\_zipcode | string | 
action\_result\.data\.\*\.page\.\*\.dstip | string |  `ip` 
action\_result\.data\.\*\.page\.\*\.id | numeric | 
action\_result\.data\.\*\.page\.\*\.latency\_max | numeric | 
action\_result\.data\.\*\.page\.\*\.latency\_min | numeric | 
action\_result\.data\.\*\.page\.\*\.latency\_total | numeric | 
action\_result\.data\.\*\.page\.\*\.numbytes | numeric | 
action\_result\.data\.\*\.page\.\*\.org | string |  `domain` 
action\_result\.data\.\*\.page\.\*\.organization\_unit | string | 
action\_result\.data\.\*\.page\.\*\.os | string | 
action\_result\.data\.\*\.page\.\*\.page\_duration | numeric | 
action\_result\.data\.\*\.page\.\*\.page\_endtime | numeric | 
action\_result\.data\.\*\.page\.\*\.page\_id | numeric | 
action\_result\.data\.\*\.page\.\*\.page\_starttime | numeric | 
action\_result\.data\.\*\.page\.\*\.req\_cnt | numeric | 
action\_result\.data\.\*\.page\.\*\.resp\_cnt | numeric | 
action\_result\.data\.\*\.page\.\*\.server\_bytes | numeric | 
action\_result\.data\.\*\.page\.\*\.site | string | 
action\_result\.data\.\*\.page\.\*\.src\_country | string | 
action\_result\.data\.\*\.page\.\*\.src\_latitude | numeric | 
action\_result\.data\.\*\.page\.\*\.src\_location | string | 
action\_result\.data\.\*\.page\.\*\.src\_longitude | numeric | 
action\_result\.data\.\*\.page\.\*\.src\_region | string | 
action\_result\.data\.\*\.page\.\*\.src\_zipcode | string | 
action\_result\.data\.\*\.page\.\*\.srcip | string |  `ip` 
action\_result\.data\.\*\.page\.\*\.sv | string | 
action\_result\.data\.\*\.page\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.page\.\*\.traffic\_type | string | 
action\_result\.data\.\*\.page\.\*\.type | string | 
action\_result\.data\.\*\.page\.\*\.url | string |  `url` 
action\_result\.data\.\*\.page\.\*\.user | string |  `email` 
action\_result\.data\.\*\.page\.\*\.user\_generated | string | 
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

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to block | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove url'
Remove an URL from the Netskope URL Blocklist

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to remove | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.url | string |  `url`  `domain` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update url'
Send the url list to Netskope

Type: **contain**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add hash'
Add a file hash to the Netskope file hash list

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to add | string |  `hash`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hash | string |  `hash`  `md5` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove hash'
Remove a hash from the Netskope file hash list

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to remove | string |  `hash`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hash | string |  `hash`  `md5` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update hash'
Send the file hash list to Netskope

Type: **contain**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 