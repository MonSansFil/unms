## UNMS API client class

A PHP class which provides access to Ubiquiti's **UNMS API**, versions 2.1 of the UNMS Controller software is supported. It's a standalone version of the class which is used in our monsansfil.ca project which is a private project.


## Methods and functions supported

The class currently supports the following functions/methods to get/post/put/delete data through the UNMS API:

- login()
- logout()
- create_site()
- editSiteName()
- getSites()
- setSite()
- authorizeDevice()
- getAircubeWirelessConfig()
- getAircubeNetworkConfig()
- getAircubeSystemConfig()
- setCubeLedOn()
- setCubeName()
- setCubeResetEnabled()
- setCubePoeEnabled()
- setAircubeSystemConfig()
- setAircubeNetworkConfig()
- setAircubeWirelessConfig()
- getDevices()
- getRouterInterfaces()
- getAirCubeData()
- getAirCubeDevices()
- geteRouterDHCPLeases()
- getAircubeWirelessInfo()


Internal functions, getters/setters:

- set_debug()
- get_debug()
- get_last_results_raw()
- get_last_error_message()

Please refer to the source code for more details on the functions/methods and their parameters.

## Requirements

- a web server with PHP and cURL modules installed (tested on apache2 with PHP Version 7.2.2 and cURL 7.45.0 )
- network connectivity between this web server and the server and port (normally TCP port 443) where the UNMS Controller is running

## Installation ##

You can use [Git](#git) or simply [Download the Release](#download-the-release) to install the API client class.


### Git

Execute the following `git` command from the shell in your project directory:

```sh
git clone https://github.com/MonSansFil/unms.git
```

When git is done cloning, include the file containing the class like so in your code:

```php
require_once('path/to/src/Client.php');
```

### Download the Release

If you prefer not to use composer or git, you can simply [download the package](https://github.com/Art-of-WiFi/UniFi-API-client/archive/master.zip), uncompress the zip file, then include the file containing the class in your code like so:

```php
require_once('path/to/src/Unms.php');
```

## Example usage

A basic example how to use the class:

```php

/**
 * initialize the Unms API connection class, log in to the controller and request the devices from a site
 * (this example assumes you have already assigned the correct values to the variables used)
 */
$unms_connection = new Unms($user, $password, $url, true);
$login            = $unms_connection->login();
$results          = $unms_connection->getDevices($site_id); // returns a PHP array containing devices of the site
```


#### IMPORTANT NOTES:

1. The last parameter (`true`) that is passed to the constructor, enables validation of the controller's SSL certificate which is otherwise **disabled** by default. It is highly recommended to enable this feature in production environments where you have a valid SSL cert installed on the Unms Controller, and which is associated with the FQDN of the server as used in the `baseurl` parameter.

2. In the example above, `$site_id` is the id of the site which is visible in the URL when managing the site in the Unms Controller:

   `https://<controller IP address or FQDN>:443/sites/bb44fac2-3fb6-440d-bd37-f70202bcaf0f/devices`

   In this case, `bb44fac2-3fb6-440d-bd37-f70202bcaf0f` is the value required for $site_id.

## Need help or have suggestions?

There is still work to be done to add functionality and improve the usability of this class, so all suggestions/comments are welcome. Please use the github [issue](https://github.com/MonSansFil/unms/issues) list to share your ideas/questions.

## Contribute

If you would like to contribute code (improvements), please open an issue and include your code there or else create a pull request.

## Credits

This class is based on the work done by the following developers:
- Malle-pietje: https://github.com/Art-of-WiFi/UniFi-API-client

## Important Disclaimer

Many of the functions in this API client class are not officially supported by UBNT and as such, may not be supported in future versions of the Unms Controller API.