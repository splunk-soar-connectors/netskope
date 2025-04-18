## Playbook Backward Compatibility

- The 'displayName' output data key and 'total_users' summary key have been removed from the output data path of the 'SCIM User Group' action, as these response fields are no longer available in Netskope. Hence, it is requested that the end-user update their existing playbooks to ensure the correct functioning of playbooks created in earlier versions of the app.
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
- All SCIM actions now use the v2 API Token. The SCIM URL and SCIM key from the asset configuration parameter have been removed, as they are deprecated. For more information regarding the SCIM deprecation, please refer to [this link](https://docs.netskope.com/en/netskope-scim-settings/).
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
  - /api/v2/scim/Users (Read + Write)
  - /api/v2/scim/Groups (Read + Write)
- In Splunk SOAR, a configured file list will be created with **{list_name}\_file_list** format
  and a url list will be created with **{list_name}\_url_list** . Where, list_name is a configured
  asset parameter.
- In order to reflect the URL/file_hash values to the Netskope, the same profile must exist at the
  Netskope. i.e., if test_list is provided as a list_name in the asset configuration, the same
  name of the profile should exist on the Netskope server.

<div id="support" class="section">

## Support

Please contact Netskope Support for any issues relating to this app.
