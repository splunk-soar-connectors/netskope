# Netskope

Publisher: Netskope \
Connector Version: 4.0.0 \
Product Vendor: Netskope \
Product Name: Netskope \
Minimum Product Version: 6.3.0

This app integrates with the Netskope to execute various investigative and polling actions

## Playbook Backward Compatibility

- The 'total_files' summary key has been replaced with the 'total_urls' key in output data paths
  for 'update url' action. This key will represent the total URLs updated on Netskope UI. Hence,
  it is requested to the end-user to please update their existing playbooks by re-inserting |
  modifying | deleting the corresponding action blocks to ensure the correct functioning of the
  playbooks created on the earlier versions of the app.
- The 'total_files' summary key has been replaced with the 'total_hashes' key in output data paths
  for 'update hash' action. This key will represent the total hashes updated on Netskope UI.
  Hence, it is requested to the end-user to please update their existing playbooks by re-inserting
  | modifying | deleting the corresponding action blocks to ensure the correct functioning of
  the playbooks created on the earlier versions of the app.

## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Netskope server. Below are the default
ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

<div class="document">

<div class="documentwrapper">

<div class="bodywrapper">

<div class="body" role="main">

<div id="usage-notes" class="section">

# Usage notes

<div class="toctree-wrapper compound">

<div id="action-notes" class="section">

## Action Notes

- Below actions will continue to use V1 API endpoints so without configuring **V1 API Key** below actions will fail.
  - update hash
  - list files
  - get file
- Below actions will use V2 REST API endpoints. It is mandatory to configure the V2 API Key in the asset. Actions will fail without a V2 API Key.
  [endpoints](https://docs.netskope.com/en/rest-api-v2-overview-312207.html)
  - run query
  - update url
  - on poll
  - get scim users
  - get scim groups
  - create scim group
  - create scim user
  - scim user group
- Test Connectivity will behave as described below:
  - If V1 API Key is configured, then the connectivity will be checked for V1 API Key
  - If V2 API Key is configured, then the connectivity will be checked for V2 API Key
  - If both are configured then the connectivity will be checked with both API Keys
  - If none is provided then the message will be thrown to configure at least one
- Actions listed below just update the Splunk SOAR list and do not make any REST calls to the
  Netskope, so they'll work without any API Key.
  - add url
  - remove url
  - add hash
  - remove hash
- V2 REST API token must have access to the below mentioned endpoints to run all the V2 supported
  actions properly.
  - /api/v2/events/data/page (Read)
  - /api/v2/events/data/alert (Read)
  - /api/v2/events/data/application (Read)
  - /api/v2/policy/urllist (Read + Write)
  - /api/v2/policy/urllist/deploy (Read + Write)
- In Splunk SOAR, a configured file list will be created with **{list_name}\_file_list** format
  and a url list will be created with **{list_name}\_url_list** . Where, list_name is a configured
  asset parameter.
- In order to reflect the URL/file_hash values to the Netskope, the same profile must exist at the
  Netskope. i.e., if test_list is provided as a list_name in the asset configuration, the same
  name of the profile should exist on the Netskope server.

<div id="support" class="section">

## Support

Please contact Netskope Support for any issues relating to this app.

### Configuration variables

This table lists the configuration variables required to operate Netskope. These variables are specified when configuring a Netskope asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server_url** | required | string | Server URL |
**v2_api_key** | optional | password | V2 API Key (recommended) |
**list_name** | optional | string | Netskope List Name (both URL and file hash) |
**api_key** | optional | password | V1 API Key |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[get file](#action-get-file) - Download a quarantined file and upload it to the vault \
[get scim users](#action-get-scim-users) - Get current SCIM user(s). If no parameter is sent, it will retrieve all users \
[get scim groups](#action-get-scim-groups) - Get current SCIM group(s). If no parameter is sent, it will retrieve all groups \
[create scim group](#action-create-scim-group) - Create SCIM group \
[create scim user](#action-create-scim-user) - Create SCIM user \
[scim user group](#action-scim-user-group) - Add or Remove a user from a SCIM group \
[list files](#action-list-files) - List all quarantined files \
[run query](#action-run-query) - Run query for events on a given IP \
[on poll](#action-on-poll) - Ingest data to Phantom \
[add url](#action-add-url) - Add an URL to the Netskope URL Blocklist \
[remove url](#action-remove-url) - Remove an URL from the Netskope URL Blocklist \
[update url](#action-update-url) - Send the url list to Netskope \
[add hash](#action-add-hash) - Add a file hash to the Netskope file hash list \
[remove hash](#action-remove-hash) - Remove a hash from the Netskope file hash list \
[update hash](#action-update-hash) - Send the file hash list to Netskope

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'get file'

Download a quarantined file and upload it to the vault

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file** | required | ID or quarantined name of the file to download | string | `netskope file id` `file name` |
**profile** | required | Quarantine profile ID or quarantined profile name | string | `netskope profile id` `netskope profile name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.file | string | `netskope file id` `file name` | 149973352208 |
action_result.parameter.profile | string | `netskope profile id` `netskope profile name` | 1 |
action_result.data.\*.file_name | string | `file name` | inline_oid_1_548AAEF7_eicar.com |
action_result.data.\*.vault_id | string | `vault id` | d211433b0b9dba7e429618df77f1d9c6573627ed |
action_result.summary.vault_id | string | `vault id` | d211433b0b9dba7e429618df77f1d9c6573627ed |
action_result.message | string | | Vault id: d211433b0b9dba7e429618df77f1d9c6573627ed |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get scim users'

Get current SCIM user(s). If no parameter is sent, it will retrieve all users

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user** | optional | Username or email to find | string | `netskope user` `email` `user name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.user | string | `netskope user` `email` `user name` | test user |
action_result.data.\*.active | boolean | | |
action_result.data.\*.emails.\*.primary | boolean | | True False |
action_result.data.\*.emails.\*.type | string | | work |
action_result.data.\*.emails.\*.value | string | | casey.ingram@sailpoint.com |
action_result.data.\*.externalId | string | `netskope external id` | |
action_result.data.\*.id | string | `netskope scim user id` | |
action_result.data.\*.name.familyName | string | | |
action_result.data.\*.name.givenName | string | | |
action_result.data.\*.userName | string | `netskope user` `user name` `email` | |
action_result.summary.total_users | numeric | | 1 |
action_result.message | string | | Total users: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get scim groups'

Get current SCIM group(s). If no parameter is sent, it will retrieve all groups

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group** | optional | Group Display Name to find | string | `netskope group name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.group | string | `netskope group name` | |
action_result.data.\*.displayName | string | `netskope group name` | |
action_result.data.\*.externalId | string | `netskope external id` | |
action_result.data.\*.id | string | `netskope scim group id` | |
action_result.data.\*.meta.resourceType | string | | Group |
action_result.summary.total_groups | numeric | | 1 |
action_result.message | string | | Total groups: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create scim group'

Create SCIM group

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group** | required | Group Name | string | `netskope group name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.group | string | `netskope group name` | netskope user group |
action_result.data.\*.displayName | string | | |
action_result.data.\*.id | string | `netskope scim group id` | |
action_result.summary.total_groups | numeric | | 1 |
action_result.message | string | | Total groups: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create scim user'

Create SCIM user

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user** | required | User Name | string | `netskope user` |
**familyName** | optional | Family Name | string | |
**givenName** | optional | Given Name | string | |
**email** | required | Primary Email | string | `netskope user` `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.email | string | `netskope user` `email` | test@gmail.com |
action_result.parameter.familyName | string | | test family |
action_result.parameter.givenName | string | | test name |
action_result.parameter.user | string | `netskope user` | test user test@gmail.com |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.emails.\*.primary | boolean | | True False |
action_result.data.\*.emails.\*.value | string | | test.test@xyz.com |
action_result.data.\*.id | string | `netskope scim user id` | |
action_result.data.\*.mail | string | | test.test@xyz.com |
action_result.data.\*.name.familyName | string | | |
action_result.data.\*.name.givenName | string | | |
action_result.data.\*.status | numeric | | 201 |
action_result.data.\*.userName | string | | |
action_result.summary.total_users | numeric | | 1 |
action_result.message | string | | Total users: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'scim user group'

Add or Remove a user from a SCIM group

Type: **contain** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group** | required | Group ID | string | `netskope scim group id` |
**user** | required | User ID | string | `netskope scim user id` |
**action** | required | Action to perform | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action | string | | add remove |
action_result.parameter.group | string | `netskope scim group id` | 011d0b10-9176-46ac-bb01-10e15949d26c |
action_result.parameter.user | string | `netskope scim user id` | test@gmail.com 6f1209b4-a3c0-4266-a53b-0f0858480ed6 |
action_result.message | string | | Total users: 0 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list files'

List all quarantined files

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.file_id | string | `netskope file id` | 130710903942 |
action_result.data.\*.original_file_name | string | `file name` | introspection_54393699177_7_29115D1E_Sensitive New 10MB.xlsx |
action_result.data.\*.policy | string | | PCI Upload - ICAP Integration |
action_result.data.\*.quarantine_profile_id | string | `netskope profile id` | 3 |
action_result.data.\*.quarantine_profile_name | string | `netskope profile name` | DEMO QP |
action_result.data.\*.quarantined_file_name | string | `file name` | introspection_54394093013_1_B1BCEE91_introspection_54393699177_7_29115D1E_Sensitive New 10MB.xlsx |
action_result.data.\*.user_id | string | `email` | user@netskope.com |
action_result.summary.total_files | numeric | | 12 |
action_result.message | string | | Total files: 12 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run query'

Run query for events on a given IP

Type: **investigate** \
Read only: **True**

<ul><li>If no &quotstart_time&quot and &quotend_time&quot is provided, the action will take the last 24 hours as the time period.<li>If only &quotstart_time&quot is provided, current time would be taken as &quotend_time&quot.<li>If only &quotend_time&quot is provided, 24 hours prior to &quotend_time&quot would be taken as &quotstart_time&quot.<li>The action only returns page and application events for the given IP.</ul>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to be queried for | string | `ip` |
**start_time** | optional | Start time epoch | numeric | |
**end_time** | optional | End time epoch | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.end_time | numeric | | 1527842350 |
action_result.parameter.ip | string | `ip` | 23.203.216.35 |
action_result.parameter.start_time | numeric | | 1522571950 |
action_result.data.\*.application.\*.\_id | string | | 5d3dcdbc6d1b918d47df389c |
action_result.data.\*.application.\*.access_method | string | | Client |
action_result.data.\*.application.\*.act_user | string | | Introspection |
action_result.data.\*.application.\*.action | string | | alert |
action_result.data.\*.application.\*.activity | string | | Upload |
action_result.data.\*.application.\*.alert | string | | no |
action_result.data.\*.application.\*.app | string | | iCloud |
action_result.data.\*.application.\*.app_activity | string | | DOWNLOAD |
action_result.data.\*.application.\*.app_session_id | numeric | | 2740637639 |
action_result.data.\*.application.\*.appcategory | string | | Cloud Storage |
action_result.data.\*.application.\*.appsuite | string | | Amazon |
action_result.data.\*.application.\*.browser | string | | Opera |
action_result.data.\*.application.\*.browser_session_id | numeric | | 7415008769063249572 |
action_result.data.\*.application.\*.browser_version | string | | 104.0.0.0 |
action_result.data.\*.application.\*.category | string | | Cloud Storage |
action_result.data.\*.application.\*.cci | numeric | | 79 |
action_result.data.\*.application.\*.ccl | string | | high |
action_result.data.\*.application.\*.connection_id | numeric | | |
action_result.data.\*.application.\*.count | numeric | | 2 |
action_result.data.\*.application.\*.data_type | string | | application/x-protobuf |
action_result.data.\*.application.\*.device | string | | Windows PC |
action_result.data.\*.application.\*.device_classification | string | | unmanaged |
action_result.data.\*.application.\*.dst_country | string | | |
action_result.data.\*.application.\*.dst_geoip_src | numeric | | 2 |
action_result.data.\*.application.\*.dst_latitude | numeric | | 37.1835 |
action_result.data.\*.application.\*.dst_location | string | | |
action_result.data.\*.application.\*.dst_longitude | numeric | | -121.7714 |
action_result.data.\*.application.\*.dst_region | string | | |
action_result.data.\*.application.\*.dst_timezone | string | | America/Los_Angeles |
action_result.data.\*.application.\*.dst_zipcode | string | | |
action_result.data.\*.application.\*.dstip | string | `ip` | 23.203.216.35 |
action_result.data.\*.application.\*.encrypt_failure | string | | Failed getting encryption Key via KMIP |
action_result.data.\*.application.\*.file_category | string | | File Type Not Detected |
action_result.data.\*.application.\*.file_size | numeric | | 23324 |
action_result.data.\*.application.\*.file_type | string | | application/octet-stream |
action_result.data.\*.application.\*.from_object | string | | genList.pdf |
action_result.data.\*.application.\*.from_storage | string | | army-national-guard-fonts |
action_result.data.\*.application.\*.from_user | string | `email` | test@test.com |
action_result.data.\*.application.\*.hostname | string | | N26-AD |
action_result.data.\*.application.\*.id | numeric | | 2951 |
action_result.data.\*.application.\*.incident_id | numeric | | 6052068333335426188 |
action_result.data.\*.application.\*.instance_id | string | | public-link |
action_result.data.\*.application.\*.managed_app | string | | no |
action_result.data.\*.application.\*.managementID | string | | |
action_result.data.\*.application.\*.md5 | string | | f80cb839ed6c628161d8a12b5bebda9c |
action_result.data.\*.application.\*.netskope_activity | string | | True |
action_result.data.\*.application.\*.netskope_pop | string | | US-SF37 |
action_result.data.\*.application.\*.nsdeviceuid | string | | 585CE196-AF22-777B-5FDA-94F762F5836D |
action_result.data.\*.application.\*.object | string | | cutomer_list.pdf |
action_result.data.\*.application.\*.object_id | string | | 997124009987 |
action_result.data.\*.application.\*.object_type | string | | File |
action_result.data.\*.application.\*.org | string | `domain` | kkrlosktest.com |
action_result.data.\*.application.\*.organization_unit | string | | |
action_result.data.\*.application.\*.os | string | | Windows 8 |
action_result.data.\*.application.\*.os_version | string | | Windows Server 2012 R2 |
action_result.data.\*.application.\*.page | string | | cdn.flashtalking.com/94611/fonts/tu11k1r8ozm2ttu90j9uodje3rx0mvxxq4w8g1zb.woff2 |
action_result.data.\*.application.\*.page_id | numeric | | 681002638 |
action_result.data.\*.application.\*.page_site | string | | flashtalking |
action_result.data.\*.application.\*.policy | string | | Download exceed limits |
action_result.data.\*.application.\*.policy_id | string | | C40E02BACAD3F943BADH9933AEBE89BB 2022-08-16 02:48:08.232480 |
action_result.data.\*.application.\*.protocol | string | | HTTPS/1.1 |
action_result.data.\*.application.\*.referer | string | | https://cdn.flashtalking.com/153624/5787226/assets/style.css |
action_result.data.\*.application.\*.request_id | numeric | | 2390695089728323584 |
action_result.data.\*.application.\*.sanctioned_instance | string | | |
action_result.data.\*.application.\*.severity | string | | unknown |
action_result.data.\*.application.\*.site | string | | iCloud |
action_result.data.\*.application.\*.src_country | string | | US |
action_result.data.\*.application.\*.src_geoip_src | numeric | | 2 |
action_result.data.\*.application.\*.src_latitude | numeric | | 37.3541 |
action_result.data.\*.application.\*.src_location | string | | Santa Clara |
action_result.data.\*.application.\*.src_longitude | numeric | | -121.9552 |
action_result.data.\*.application.\*.src_region | string | | CA |
action_result.data.\*.application.\*.src_time | string | | Wed Aug 31 21:10:00 2022 |
action_result.data.\*.application.\*.src_timezone | string | | America/Los_Angeles |
action_result.data.\*.application.\*.src_zipcode | string | | 95050 |
action_result.data.\*.application.\*.srcip | string | `ip` | 71.135.50.1 |
action_result.data.\*.application.\*.suppression_end_time | numeric | | 1662299940 |
action_result.data.\*.application.\*.suppression_start_time | numeric | | 1662299919 |
action_result.data.\*.application.\*.sv | string | | unknown |
action_result.data.\*.application.\*.telemetry_app | string | | |
action_result.data.\*.application.\*.timestamp | numeric | | 1528218987 |
action_result.data.\*.application.\*.to_user | string | `email` | test@codsoso.com |
action_result.data.\*.application.\*.traffic_type | string | | CloudApp |
action_result.data.\*.application.\*.transaction_id | numeric | | 6052010733335426188 |
action_result.data.\*.application.\*.tss_mode | string | | inline |
action_result.data.\*.application.\*.type | string | | nspolicy |
action_result.data.\*.application.\*.universal_connector | string | | yes |
action_result.data.\*.application.\*.ur_normalized | string | | osdf@test.com |
action_result.data.\*.application.\*.url | string | `url` | http://www.iCloud.com |
action_result.data.\*.application.\*.user | string | `email` | Aaron.Etheridge@kkrlogistics.com |
action_result.data.\*.application.\*.user_category | string | | Internal |
action_result.data.\*.application.\*.user_id | string | | test+boxent@netskope.com |
action_result.data.\*.application.\*.user_name | string | | Test |
action_result.data.\*.application.\*.user_role | string | | Coadmin |
action_result.data.\*.application.\*.useragent | string | | Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36 |
action_result.data.\*.application.\*.userip | string | `ip` | 127.0.0.1 |
action_result.data.\*.application.\*.userkey | string | `email` | Test.Etderidge@kkrltestics.com |
action_result.data.\*.application.\*.web_universal_connector | string | | yes |
action_result.data.\*.page.\*.\_id | string | | 59aa3f7174d1b40691851b70 |
action_result.data.\*.page.\*.access_method | string | | Client |
action_result.data.\*.page.\*.app | string | | iCloud |
action_result.data.\*.page.\*.app_action_cnt | numeric | | 6 |
action_result.data.\*.page.\*.app_session_id | numeric | | 2740637639 |
action_result.data.\*.page.\*.appcategory | string | | Cloud Storage |
action_result.data.\*.page.\*.browser | string | | Opera |
action_result.data.\*.page.\*.browser_session_id | numeric | | 6865146192307073553 |
action_result.data.\*.page.\*.browser_version | string | | 104.0.0.0 |
action_result.data.\*.page.\*.bypass_reason | string | | SSL Bypass policy matched |
action_result.data.\*.page.\*.bypass_traffic | string | | yes |
action_result.data.\*.page.\*.category | string | | Cloud Storage |
action_result.data.\*.page.\*.cci | numeric | | 79 |
action_result.data.\*.page.\*.ccl | string | | high |
action_result.data.\*.page.\*.client_bytes | numeric | | 4296 |
action_result.data.\*.page.\*.conn_duration | numeric | | 899 |
action_result.data.\*.page.\*.conn_endtime | numeric | | 1661909943 |
action_result.data.\*.page.\*.conn_starttime | numeric | | 1661909044 |
action_result.data.\*.page.\*.connection_id | numeric | | |
action_result.data.\*.page.\*.count | numeric | | 2 |
action_result.data.\*.page.\*.device | string | | Windows PC |
action_result.data.\*.page.\*.domain | string | | login.microsoftonline.com |
action_result.data.\*.page.\*.dst_country | string | | |
action_result.data.\*.page.\*.dst_geoip_src | numeric | | 2 |
action_result.data.\*.page.\*.dst_latitude | numeric | | 37.9273 |
action_result.data.\*.page.\*.dst_location | string | | |
action_result.data.\*.page.\*.dst_longitude | numeric | | -76.8545 |
action_result.data.\*.page.\*.dst_region | string | | |
action_result.data.\*.page.\*.dst_timezone | string | | America/New_York |
action_result.data.\*.page.\*.dst_zipcode | string | | |
action_result.data.\*.page.\*.dstip | string | `ip` | 23.203.216.35 |
action_result.data.\*.page.\*.dstport | numeric | | 443 |
action_result.data.\*.page.\*.hostname | string | | N21-PC |
action_result.data.\*.page.\*.http_transaction_count | numeric | | 29 |
action_result.data.\*.page.\*.id | numeric | | 7743 |
action_result.data.\*.page.\*.incident_id | numeric | | |
action_result.data.\*.page.\*.latency_max | numeric | | 295 |
action_result.data.\*.page.\*.latency_min | numeric | | 74 |
action_result.data.\*.page.\*.latency_total | numeric | | 991 |
action_result.data.\*.page.\*.netskope_pop | string | | US-SEA1 |
action_result.data.\*.page.\*.numbytes | numeric | | 7897 |
action_result.data.\*.page.\*.org | string | `domain` | kkrlogistics.com |
action_result.data.\*.page.\*.organization_unit | string | | |
action_result.data.\*.page.\*.os | string | | Windows 8 |
action_result.data.\*.page.\*.os_version | string | | Windows Server 2012 R2 |
action_result.data.\*.page.\*.page | string | | login.microsoftonline.com |
action_result.data.\*.page.\*.page_duration | numeric | | 1748 |
action_result.data.\*.page.\*.page_endtime | numeric | | 1528219021 |
action_result.data.\*.page.\*.page_id | numeric | | 3019499457 |
action_result.data.\*.page.\*.page_starttime | numeric | | 1528217273 |
action_result.data.\*.page.\*.policy | string | | test-policy1 |
action_result.data.\*.page.\*.protocol | string | | HTTP/1.1 |
action_result.data.\*.page.\*.req_cnt | numeric | | 5 |
action_result.data.\*.page.\*.request_id | numeric | | 2389429104198680577 |
action_result.data.\*.page.\*.resp_cnt | numeric | | 8 |
action_result.data.\*.page.\*.resp_content_len | numeric | | 137663 |
action_result.data.\*.page.\*.resp_content_type | string | | text/html |
action_result.data.\*.page.\*.server_bytes | numeric | | 4382 |
action_result.data.\*.page.\*.severity | string | | unknown |
action_result.data.\*.page.\*.site | string | | iCloud |
action_result.data.\*.page.\*.slc_latitude | numeric | | 12.9762296677 |
action_result.data.\*.page.\*.slc_longitude | numeric | | 77.6032867432 |
action_result.data.\*.page.\*.src_country | string | | US |
action_result.data.\*.page.\*.src_geoip_src | numeric | | 2 |
action_result.data.\*.page.\*.src_latitude | numeric | | 37.3541 |
action_result.data.\*.page.\*.src_location | string | | Santa Clara |
action_result.data.\*.page.\*.src_longitude | numeric | | -121.9552 |
action_result.data.\*.page.\*.src_region | string | | CA |
action_result.data.\*.page.\*.src_time | string | | Tue Aug 30 03:14:00 2022 |
action_result.data.\*.page.\*.src_timezone | string | | America/Los_Angeles |
action_result.data.\*.page.\*.src_zipcode | string | | 95050 |
action_result.data.\*.page.\*.srcip | string | `ip` | 71.135.50.1 |
action_result.data.\*.page.\*.ssl_decrypt_policy | string | | yes |
action_result.data.\*.page.\*.suppression_end_time | numeric | | 1661836783 |
action_result.data.\*.page.\*.suppression_start_time | numeric | | 1661836759 |
action_result.data.\*.page.\*.sv | string | | unknown |
action_result.data.\*.page.\*.timestamp | numeric | | 1528219021 |
action_result.data.\*.page.\*.traffic_type | string | | CloudApp |
action_result.data.\*.page.\*.transaction_id | numeric | | |
action_result.data.\*.page.\*.type | string | | page |
action_result.data.\*.page.\*.ur_normalized | string | | labs_12345@protonmail.com |
action_result.data.\*.page.\*.url | string | `url` | http://www.iCloud.com |
action_result.data.\*.page.\*.user | string | `email` | Aaron.Etheridge@kkrlogistics.com |
action_result.data.\*.page.\*.user_generated | string | | yes |
action_result.data.\*.page.\*.useragent | string | | Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36 |
action_result.data.\*.page.\*.userip | string | `ip` | 127.0.0.1 |
action_result.data.\*.page.\*.userkey | string | `email` | Aaron.Etheridge@kkrlogistics.com |
action_result.summary.total_application_events | numeric | | 61 |
action_result.summary.total_page_events | numeric | | 7 |
action_result.message | string | | Total page events: 7, Total application events: 61 |
summary.total_objects | numeric | | 2 |
summary.total_objects_successful | numeric | | 2 |

## action: 'on poll'

Ingest data to Phantom

Type: **ingest** \
Read only: **True**

For <b>manual run</b> and <b>first poll</b>, alerts of the last 24 hours would be ingested. Subsequent polls will ingest new alerts.<br>Only alerts of type &quotMalware&quot will be ingested.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_count** | optional | Maximum number of containers to ingest | numeric | |
**container_id** | optional | Parameter ignored in this app | string | |
**start_time** | optional | Parameter ignored in this app | numeric | |
**end_time** | optional | Parameter ignored in this app | numeric | |
**artifact_count** | optional | Parameter ignored in this app | numeric | |

#### Action Output

No Output

## action: 'add url'

Add an URL to the Netskope URL Blocklist

Type: **contain** \
Read only: **False**

This action will add URL value to the configured Splunk SOAR custom list only and that will be reflected in the Netskope after <b>update url</b> action is performed.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to block | string | `url` `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.url | string | `url` `domain` | |
action_result.data | string | | |
action_result.summary.set_list | string | | |
action_result.summary.total_files | numeric | | 1 |
action_result.summary.total_urls | numeric | | 1 |
action_result.message | string | | Total urls: 6 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove url'

Remove an URL from the Netskope URL Blocklist

Type: **correct** \
Read only: **False**

This action will remove URL value from the configured Splunk SOAR custom list only and that will be reflected in the Netskope after <b>update url</b> action is performed.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to remove | string | `url` `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.url | string | `url` `domain` | |
action_result.data | string | | |
action_result.summary.remove_msg | string | | |
action_result.summary.total_files | numeric | | 1 |
action_result.summary.total_urls | numeric | | 1 |
action_result.message | string | | Remove msg: Removed 1 instances of "https://www.example.com:80" from "test_list_netskope_url_list", Total urls: 21 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update url'

Send the url list to Netskope

Type: **contain** \
Read only: **False**

This action replaces the URL list of a Netskope server with the configured Splunk SOAR custom URL list.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data | string | | |
action_result.summary.total_files | numeric | | 1 |
action_result.summary.total_urls | numeric | | 1 |
action_result.message | string | | Total urls: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add hash'

Add a file hash to the Netskope file hash list

Type: **contain** \
Read only: **False**

This action will add file hash value to the configured Splunk SOAR custom list only and that will be reflected in the Netskope after <b>update hash</b> action is performed.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash to add | string | `hash` `md5` `sha256` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.hash | string | `hash` `md5` `sha256` | |
action_result.data | string | | |
action_result.summary.set_list | string | | |
action_result.summary.total_files | numeric | | 1 |
action_result.summary.total_hashes | numeric | | 1 |
action_result.message | string | | Total hashes: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove hash'

Remove a hash from the Netskope file hash list

Type: **correct** \
Read only: **False**

This action will remove file hash value from the configured Splunk SOAR custom list only and that will be reflected in the Netskope after <b>update hash</b> action is performed.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash to remove | string | `hash` `md5` `sha256` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.hash | string | `hash` `md5` `sha256` | |
action_result.data | string | | |
action_result.summary.remove_msg | string | | Deleted Single Row |
action_result.summary.total_files | numeric | | 1 |
action_result.message | string | | Total files: 2, Remove msg: Removed 1 instances of "testxxxba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015adxxxtest" from "test_list_netskope_file_list" |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update hash'

Send the file hash list to Netskope

Type: **contain** \
Read only: **False**

This action replaces the hash list of a Netskope server with the configured Splunk SOAR custom hash list.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data | string | | |
action_result.summary.total_files | numeric | | 1 |
action_result.summary.total_hashes | numeric | | 1 |
action_result.message | string | | Total hashes: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
