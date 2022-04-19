**Unreleased**
* Bug fixed in 'update hash' action where the file hash list stored on Phantom was never updated on Netskope server
* Updated error handling code to show the error message in case the API throws an error with 200 status code
* Added validation to check the empty content before updating URL or File Hash List on Netskope server
* Updated action result summary to show the total URLs or total Hashes updated