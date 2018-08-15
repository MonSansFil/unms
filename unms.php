<?php
/**
 *
 * This Unms API client is made by the DEV team @ MonSansFil
 * and is part of the monsansfil.ca project
 *
 * @author Patrice Guillemette <patriceguillemette.com>
 *
 * This Unms API client is based on the work done by the following developers:
 * Malle-pietje: https://github.com/Art-of-WiFi/UniFi-API-client
 *
 * Copyright (c) 2018, MonSansFil <info@monsansfil.ca>
 *
 * This source file is subject to the MIT license that is bundled
 * with this package in the file LICENSE.md
 */


/**
 * the Unms API client class
 */
class Unms
{
    protected $baseurl            = 'myhost.com:443';
    protected $debug              = false;
    protected $is_loggedin        = false;
    private $token                = '';
    private $request_type         = 'POST';
    private $last_error_message   = null;
    private $curl_ssl_verify_peer = false;
    private $curl_ssl_verify_host = false; //TODO use it in the init curl


    /**
     * Constructor of the API
     * @param string  $user       The username used to connect to the UNMS Api
     * @param string  $password   The account password
     * @param string  $baseurl    The url of the UNMS server, without the https:// and with the port at the end ex: unms.myhost.com:443
     * @param boolean $ssl_verify Wether or not use the ssl verify peer and host
     */
    function __construct($user, $password, $baseurl = '', $ssl_verify = false)
    {
        if (!extension_loaded('curl')){
            trigger_error('The PHP curl extension is not loaded. Please correct this before proceeding!');
        }

        $this->user     = trim($user);
        $this->password = trim($password);

        if (!empty($baseurl)) $this->baseurl = trim($baseurl);

        if ($ssl_verify === true){
            $this->curl_ssl_verify_peer = true;
            $this->curl_ssl_verify_host = 2;
        }

        $this->check_base_url();
    }

    /**
     * Destructor of the API. Will disconnect the user if not logged out manually
     */
   function __destruct()
    {
        /**
         * logout, if needed
         */
        if ($this->is_loggedin) $this->logout();
    }

    /**
     * Set debug mode
     * --------------
     * sets debug mode to true or false, returns false if a non-boolean parameter was passed
     * @param boolean $enable true will enable debug mode, false will disable it
     */
    public function set_debug($enable)
    {
        if ($enable === true || $enable === false) {
            $this->debug = $enable;
            return true;
        }

        trigger_error('Error: the parameter for set_debug() must be boolean');
        return false;
    }

    /**
     * Create a site or client in UNMS
     * @param  array $site array containing all or some of theses parameters
     *                     integer parentSiteId     The parentSiteId if you want to create a client
     *                     string name              The name of the site, as displayed in the UNMS panel
     *                     string address           The address of the site, as displayed in the UNMS panel
     *                     object location          The object location
     *                     string contactName       The contact name, as displayed in the UNMS panel
     *                     string contactPhone      The contact phone number, as displayed in the UNMS panel
     *                     string contactEmail      The contact email address, as displayed in the UNMS panel
     *                     string note              The contact note, as displayed in the UNMS panel
     *                     integer height           The site height above ground, as displayed in the UNMS panel
     *                     integer elevation        The site elevation, as displayed in the UNMS panel. Will be calculatd automatically if nothing is present
     *
     * @return object       The return value from the API
     */
    public function create_site($site)
    {
        if (!$this->is_loggedin) return false;

        $defaultSite = [
            'parentSiteId' => null,
            'name' => 'Undefined',
            'address' => 'Undefined',
            'location'=> null,
            'contactName' => null,
            'contactPhone' => null,
            'contactEmail' => null,
            'note' => null,
            'height' => 8,
            'elevation' => 8,
        ];

        $site = array_merge($defaultSite,array_intersect_key($site, $defaultSite));


        $json     = json_encode([
            'parentSiteId' => $site['parentSiteId'],
            'name' => $site['name'],
            'address' => $site['address'],
            'location' => $site['location'],
            'contactName' => $site['contactName'],
            'contactPhone' => $site['contactPhone'],
            'contactEmail' => $site['contactEmail'],
            'note' => $site['note'],
            'height' => $site['height'],
            'elevation' => $site['elevation'],
            'location' => $site['location'],
        ]);

        $response = $this->exec_curl('/v2.1/sites', $json);
        return $this->process_response($response);
    }

    /**
     * Will edit the site name, without changing any other things
     * @param  string $siteId The site ID to edit
     * @param  string $name   THe new name to be setted
     *
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function editSiteName($siteId, $name)
    {
        $site = $this->getSites($siteId);
        if(!$site) return false;

        $site = $site[0];

        $site->identification->name = $name;

        return $this->setSite($siteId, $site);
    }

    /**
     * Return the site's object
     * @param  string $siteId The site id to get
     * @return object               The entire site's object
     */
    public function getSites($siteId)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/sites?id='.$siteId);
        return $this->process_response($response);
    }

    /**
     * The set site function is only to be used by subfunctions in this class. It is expecting to receive a valid site object as parameter
     * @param string $siteId the site id to set
     * @param object $data   the valid data of the site to set
     *
     * @return object       The return value from the API or FALSE if an error occured
     */
    protected function setSite($siteId, $data)
    {
        if (!$this->is_loggedin) return false;
        $json     = json_encode($data);

        $this->request_type = 'PUT';

        $response = $this->exec_curl('/v2.1/sites/'.$siteId, $json);
        return $this->process_response($response);
    }

    /**
     * Move a device from one site to the other
     * @param  string $deviceId The device to move
     * @param  string $siteId   The site id in which to move the device
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function authorizeDevice($deviceId, $siteId)
    {
        if (!$this->is_loggedin) return false;
        $json     = json_encode(['siteId' => $siteId]);

        $response = $this->exec_curl('/v2.1/devices/'.$deviceId.'/authorize', $json);
        return $this->process_response($response);
    }

    /**
     * Get the Wireless configuration from an aircube
     * @param  string $aircubeId The aircube ID to get the data from
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function getAircubeWirelessConfig($aircubeId)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/devices/aircubes/'.$aircubeId.'/config/wireless');
        return $this->process_response($response);
    }

    /**
     * Get the Network configuration from an aircube
     * @param  string $aircubeId The aircube ID to get the data from
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function getAircubeNetworkConfig($aircubeId)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/devices/aircubes/'.$aircubeId.'/config/network');
        return $this->process_response($response);
    }

    /**
     * Get the System configuration from an aircube
     * @param  string $aircubeId The aircube ID to get the data from
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function getAircubeSystemConfig($aircubeId)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/devices/aircubes/'.$aircubeId.'/config/system');
        return $this->process_response($response);
    }

    /**
     * Set the aircube led On or Off
     * @param string $aircubeId The aircube ID to set the led
     * @param boolean $is_on     Wether to turn On or Off the aircube led
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function setCubeLedOn($aircubeId, $is_on)
    {
        $originVal = $this->getAircubeSystemConfig($aircubeId);
        if(!$originVal) return false;

        $origin = (array) $originVal;

        $origin['ledNightMode'] = (array) $origin['ledNightMode'];

        $origin['ledNightMode']['enable'] = ($is_on ? false : true);;
        $origin['ledNightMode']['start'] = "0";
        $origin['ledNightMode']['end'] = "0";

        return $this->setAircubeSystemConfig($aircubeId, $origin);
    }

    /**
     * Set the aircube name
     * @param string $aircubeId The aircube ID to set the name
     * @param string $name     The new name to be setted to the cube
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function setCubeName($aircubeId, $name)
    {
        $originVal = $this->getAircubeSystemConfig($aircubeId);
        if(!$originVal) return false;

        $origin = (array) $originVal;

        $origin['ledNightMode'] = (array) $origin['ledNightMode'];

        $origin['deviceName'] = $name;

        return $this->setAircubeSystemConfig($aircubeId, $origin);
    }

    /**
     * Set the aircube reset swith available or not
     * @param string $aircubeId The aircube ID to set the name
     * @param string $is_enabled Wether or not the reset switch is available
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function setCubeResetEnabled($aircubeId, $is_enabled)
    {
        $originVal = $this->getAircubeSystemConfig($aircubeId);
        if(!$originVal) return false;

        $origin = (array) $originVal;
        $origin['ledNightMode'] = (array) $origin['ledNightMode'];

        $origin['resetButtonEnabled'] = ($is_enabled ? true : false);

        return $this->setAircubeSystemConfig($aircubeId, $origin);
    }

    /**
     * Set the aircube POE On or Off
     * @param string $aircubeId The aircube ID to set the name
     * @param string $is_enabled Wether or not the POE is turned On
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function setCubePoeEnabled($aircubeId, $is_enabled)
    {
        $originVal = $this->getAircubeSystemConfig($aircubeId);
        if(!$originVal) return false;

        $origin = (array) $originVal;
        $origin['ledNightMode'] = (array) $origin['ledNightMode'];

        $origin['poePassthrough'] = ($is_enabled ? true : false);

        return $this->setAircubeSystemConfig($aircubeId, $origin);
    }

    /**
     * Set the aircube system configuration
     * @param string $aircubeId The aircube ID to set the config
     * @param array $config    array containing all or some of theses parameters
     *                         deviceName           The name of the aircube, as displayed in the UNMS panel
     *                         timezone             The timezone of the aircube, as displayed in the UNMS panel
     *                         zonename             Not used, for future use
     *                         ledNightMode
     *                             enable           Wether or not the nightMode is enables
     *                             start            The time to start the nightmode every day
     *                             end              The time to end the nightmode every day
     *                         resetButtonEnabled   Wether or not the reset Button is enabled on the cube
     *                         poePassthrough       Wether or not the POE is enabled on the cube
     *                         username             The Administrator username
     *                         newPassword          The administrator password
     *
     * @return object       The return value from the API
     */
    public function setAircubeSystemConfig($aircubeId, $config)
    {
        if (!$this->is_loggedin) return false;
        $defaultConfig = [
            "deviceName" => "AirCube",
            "timezone" => "UTC",
            "zonename" => null,
            "ledNightMode" => [
                "enable" => false,
                "start" => "0",
                "end" => "0",
            ],
            "resetButtonEnabled" => false,
            "poePassthrough" => false,
            "username" => $this->user,
            "newPassword" => $this->password,
        ];

        $config = array_merge($defaultConfig,array_intersect_key($config, $defaultConfig));
        $config['ledNightMode'] = array_merge($defaultConfig['ledNightMode'],array_intersect_key($config['ledNightMode'], $defaultConfig['ledNightMode']));

        $json     = json_encode($config);

        $this->request_type = 'PUT';

        $response = $this->exec_curl('/v2.1/devices/aircubes/'.$aircubeId.'/config/system', $json);

        return $this->process_response($response);
    }


    /**
     * Set the aircube network configuration
     * @param string $aircubeId the aircube ID to set the config
     * @param array $config    the configuration array (see UNMS doc for details. Upcoming here in future version)
     *
     * @return object       The return value from the API
     */
    public function setAircubeNetworkConfig($aircubeId, $config)
    {
        if (!$this->is_loggedin) return false;
        $defaultConfig = [
            "mode" => (isset($config['mode']) ? $config['mode'] : "bridge"),
            "blockManagementAccess" => (isset($config['blockManagementAccess']) ? $config['blockManagementAccess'] : true),
            "lan" => [
                "type" => (isset($config['lan']['type']) ? $config['lan']['type'] : "bridge"),
                "interfaceNames" => (isset($config['lan']['interfaceNames']) ? $config['lan']['interfaceNames'] : ['lan0','wan0']),
                "gateway" => (isset($config['lan']['gateway']) ? $config['lan']['gateway'] : null),
                "cidr" => (isset($config['lan']['cidr']) ? $config['lan']['cidr'] : "192.168.1.1/24"),
                "proto" => (isset($config['lan']['proto']) ? $config['lan']['proto'] : 'dhcp'),
                "dns" => (isset($config['lan']['dns']) ? $config['lan']['dns'] : [null,null]),
                "dhcp" => [
                    "ignore" => (isset($config['lan']['dhcp']['ignore']) ? $config['lan']['dhcp']['ignore'] : true),
                    "interface" => (isset($config['lan']['dhcp']['interface']) ? $config['lan']['dhcp']['interface'] : "lan"), 
                    "rangeStart" => (isset($config['lan']['dhcp']['rangeStart']) ? $config['lan']['dhcp']['rangeStart'] : "192.168.1.100"),
                    "rangeEnd" => (isset($config['lan']['dhcp']['rangeEnd']) ? $config['lan']['dhcp']['rangeEnd'] : '192.168.1.250'),
                    "leaseTime" => (isset($config['lan']['dhcp']['leaseTime']) ? $config['lan']['dhcp']['leaseTime'] : '12h'),
                ],
            ],
            "wan" => [
                "enabled" => (isset($config['wan']['enabled']) ? $config['wan']['enabled'] : false),
                "interfaceNames" => [null],
                "cidr" => null,

                "gateway" => null,
                "proto" => 'dhcp',
                "dns" => [null, null],
                "service" => null,
                "username" => null,
                "password" => null,
            ],
            "mgt" => [
                "enabled" => true,
                "vlanId" => 103,
                "proto" => "dhcp",
                "cidr" => null,
                "service" => null,
                "username" => null,
                "password" => null
            ],
        ];

        $config = $defaultConfig;

        $json     = json_encode($config);

        $this->request_type = 'PUT';

        $response = $this->exec_curl('/v2.1/devices/aircubes/'.$aircubeId.'/config/network', $json);
        return $this->process_response($response);

    }

    /**
     * Set the aircube wireless configuration
     * @param string $aircubeId the aircube ID to set the config
     * @param array $config    the configuration array (see UNMS doc for details. Upcoming here in future version)
     *
     * @return object       The return value from the API
     */
    public function setAircubeWirelessConfig($aircubeId, $config)
    {
        if (!$this->is_loggedin) return false;
        $defaultConfig = [
            "wifi2Ghz" => [
                "enabled" => true,
                "available" => true,
                "mode" => "ap",
                "ssid" => "#MonSansFil",
                "country" => "CA",
                "channel" => "auto",
                "channelWidth" => 20,
                "encryption" => "wpa2",
                "authentication" => "psk2",
                "txPower" => 12,
                "key" => "monsansfilaircube",
                'isWPA2PSKEnabled' => true,
            ],
            "wifi5Ghz" => [
                "enabled" => false,
                "available" => true,
                "mode" => "ap",
                "ssid" => "#MonSansFil",
                "country" => "CA",
                "channel" => "auto",
                "channelWidth" => 80,
                "encryption" => "wpa2",
                "authentication" => "psk2",
                "txPower" => 22,
                "key" => "monsansfilaircube",
                'isWPA2PSKEnabled' => true,
            ],
        ];

        $config = array_merge($defaultConfig,array_intersect_key($config, $defaultConfig));
        $config['wifi2Ghz'] = array_merge($defaultConfig['wifi2Ghz'],array_intersect_key($config['wifi2Ghz'], $defaultConfig['wifi2Ghz']));
        $config['wifi5Ghz'] = array_merge($defaultConfig['wifi5Ghz'],array_intersect_key($config['wifi5Ghz'], $defaultConfig['wifi5Ghz']));

        $json     = json_encode($config);

        $this->request_type = 'PUT';

        $response = $this->exec_curl('/v2.1/devices/aircubes/'.$aircubeId.'/config/wireless', $json);
        return $this->process_response($response);

    }



    /**
     * Get the devices at the root of a site. This will not return child sites devices
     * @param  string $siteId the site Id to get the devices from
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function getDevices($siteId)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/devices?siteId='.$siteId);
        return $this->process_response($response);
    }

    /**
     * Get the interfaces from the router specified
     * @param  string $deviceId The router's device ID
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function getRouterInterfaces($deviceId)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/devices/'.$deviceId.'/interfaces');
        return $this->process_response($response);
    }

    /**
     * Get the specified aircube's data
     * @param  string $aircubeId the aircube Id to get the data from
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function getAirCubeData($aircubeId)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/devices/aircubes/'.$aircubeId);
        return $this->process_response($response);
    }

    /**
     * Get the clients connected to the specified aircube
     * @param  string $aircubeId the aircube Id to get the clients from
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function getAirCubeDevices($aircubeId)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/devices/aircubes/'.$aircubeId.'/stations');
        return $this->process_response($response);
    }

    /**
     * Get the DHCP Lease from the specified router
     * @param  string $id the router device Id to get the DHCP Lease from
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function geteRouterDHCPLeases($id)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/devices/erouters/'.$id.'/dhcp/leases');
        return $this->process_response($response);
    }

    /**
     * Get the Wireless network informations from an aircube
     * @param  string $aircubeId the aircube device Id to get the wireless info from
     * @return object       The return value from the API or FALSE if an error occured
     */
    public function getAircubeWirelessInfo($aircubeId)
    {
        if (!$this->is_loggedin) return false;
        $response    = $this->exec_curl('/v2.1/devices/aircubes/'.$aircubeId.'/config/wireless');
        return $this->process_response($response);
    }












    /**
     * Process regular responses where output is the content of the data array
     */
    protected function process_response($response_json)
    {
        $response = json_decode($response_json);
        $this->catch_json_last_error();
        $this->last_results_raw = $response;

        if(is_object($response))
        {
            if(isset($response->statusCode) && $response->statusCode == '400')
            {
                if (isset($response->message)) $this->last_error_message = $response->message;
                if ($this->debug) trigger_error('Debug: Last error message: '.$this->last_error_message);
                return false;
            }
        }

        if (is_array($response)) return $response;
        if (is_object($response)) return $response;
        return true;

    }


    /**
     * Capture the latest JSON error when $this->debug is true
     */
    private function catch_json_last_error()
    {
        if ($this->debug) {
            switch (json_last_error()) {
                case JSON_ERROR_NONE:
                    // JSON is valid, no error has occurred
                    $error = '';
                    break;
                case JSON_ERROR_DEPTH:
                    $error = 'The maximum stack depth has been exceeded';
                    break;
                case JSON_ERROR_STATE_MISMATCH:
                    $error = 'Invalid or malformed JSON.';
                    break;
                case JSON_ERROR_CTRL_CHAR:
                    $error = 'Control character error, possibly incorrectly encoded';
                    break;
                case JSON_ERROR_SYNTAX:
                    $error = 'Syntax error, malformed JSON.';
                    break;
                case JSON_ERROR_UTF8:
                    // PHP >= 5.3.3
                    $error = 'Malformed UTF-8 characters, possibly incorrectly encoded';
                    break;
                case JSON_ERROR_RECURSION:
                    // PHP >= 5.5.0
                    $error = 'One or more recursive references in the value to be encoded';
                    break;
                case JSON_ERROR_INF_OR_NAN:
                    // PHP >= 5.5.0
                    $error = 'One or more NAN or INF values in the value to be encoded';
                    break;
                case JSON_ERROR_UNSUPPORTED_TYPE:
                    $error = 'A value of a type that cannot be encoded was given';
                    break;
                case JSON_ERROR_INVALID_PROPERTY_NAME:
                    // PHP >= 7.0.0
                    $error = 'A property name that cannot be encoded was given';
                    break;
                case JSON_ERROR_UTF16:
                    // PHP >= 7.0.0
                    $error = 'Malformed UTF-16 characters, possibly incorrectly encoded';
                    break;
                default:
                    // we have an unknown error
                    $error = 'Unknown JSON error occured.';
                    break;
            }

            if ($error !== '') {
                trigger_error('JSON decode error: ' . $error);
                return false;
            }
        }

        return true;
    }

   /**
     * Check the submitted base URL
     */
    private function check_base_url()
    {
        $url_valid = filter_var('http://'.$this->baseurl, FILTER_VALIDATE_URL);
        if (!$url_valid)
        {
            trigger_error('The URL provided is incomplete or invalid!');
            return false;
        }

        $base_url_components = parse_url('http://'.$this->baseurl);
        if (empty($base_url_components['port']))
        {
            trigger_error('The URL provided does not have a port suffix, normally this is :8444');
            return false;
        }

        return true;
    }

    /**
     * Logout from UNMS Controller
     * ----------------------------
     * returns true upon success
     */
    public function logout()
    {
        if (!$this->is_loggedin) return false;
        $this->exec_curl('/logout');
        $this->is_loggedin = false;
        return true;
    }

    /**
     * Login to Unms
     * -------------------------
     * returns true upon success
     */
    public function login()
    {
        /**
         * if user has token set, skip the login
         */
        if (isset($this->token) && $this->token != '') return $this->is_loggedin = true;


            $logindata = array('password' => $this->password, 'username' => $this->user, 'sessionTimeout' => '3600000');
            $login_json = json_encode($logindata);

            $url = "https://".$this->baseurl."/v2.1/user/login";

            $headers = array();
            $headers[] = 'Content-Type: application/json';

            #
            #Login to get x-auth-token
            #

            $curl_login = curl_init();
            curl_setopt($curl_login, CURLOPT_URL,$url);
            curl_setopt($curl_login, CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($curl_login, CURLOPT_POSTFIELDS, $login_json);
            curl_setopt($curl_login, CURLOPT_HEADER, 1);
            curl_setopt($curl_login, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl_login, CURLOPT_RETURNTRANSFER, true);

            $content = curl_exec($curl_login);

            if (curl_errno($curl_login)) trigger_error('cURL error: '.curl_error($curl_login));

            if ($this->debug) {
                curl_setopt($curl_login, CURLOPT_VERBOSE, true);

                print '<pre>';
                print PHP_EOL.'-----------LOGIN-------------'.PHP_EOL;
                print_r (curl_getinfo($curl_login));
                print PHP_EOL.'----------RESPONSE-----------'.PHP_EOL;
                print $content;
                print PHP_EOL.'-----------------------------'.PHP_EOL;
                print '</pre>';
            }


            if($content === false)
            {
                    output('Curl error: ' . curl_error($curl_login));
            }

            $header = \Ubnt::get_headers_from_curl_response($content);

            $header_size = curl_getinfo($curl_login, CURLINFO_HEADER_SIZE);
            $body        = trim(substr($content, $header_size));
            $code        = curl_getinfo($curl_login, CURLINFO_HTTP_CODE);

            curl_close ($curl_login);

            $token= false;

            if($header && isset($header['x-auth-token']))
            {
                $token = $header['x-auth-token'];
            }

            $this->token = $token;

        $this->is_loggedin = true;
        return true;
    }

    /**
     * Execute the cURL request
     */
    protected function exec_curl($path, $data = '')
    {
        $url = 'https://'.$this->baseurl.$path;

        $ch  = $this->get_curl_obj();
        curl_setopt($ch, CURLOPT_URL, $url);

        if (trim($data) != ''){
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            if ($this->request_type === 'PUT'){
                $headers = array();
                $headers[] = "Accept: application/json";
                $headers[] = "Content-Type: application/json";
                $headers[] = "X-Auth-Token: ".$this->token;
                $headers[] = "Content-Length: ".strlen($data);
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
            }else{
                $headers = array();
                $headers[] = "Accept: application/json";
                $headers[] = "Content-Type: application/json";
                $headers[] = "X-Auth-Token: ".$this->token;
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            }
        }else{
            curl_setopt($ch, CURLOPT_POST, false);
            if ($this->request_type === 'DELETE') curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }

        /**
         * execute the cURL request
         */
        $content = curl_exec($ch);
        if (curl_errno($ch)) {
            trigger_error('cURL error: '.curl_error($ch));
        }

        /**
         * has the session timed out?
         */
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $json_decoded_content = json_decode($content, true);

        if ($http_code == 401 && isset($json_decoded_content['meta']['msg']) && $json_decoded_content['meta']['msg'] === 'api.err.LoginRequired') {
            if ($this->debug) error_log('cURL debug: Needed to reconnect to UniFi Controller');

            /**
             * explicitly unset the old token now
             */
            if (isset($this->token)) {
                $this->token = '';
            }

            $this->login();

            /**
             * when login was okay, exec the same command again
             */
            if ($this->is_loggedin) {
                curl_close($ch);

                return $this->exec_curl($path, $data);
            }
        }

        if ($this->debug) {
            print '<pre>';
            print PHP_EOL.'---------cURL INFO-----------'.PHP_EOL;
            print_r (curl_getinfo($ch));
            print PHP_EOL.'-------URL & PAYLOAD---------'.PHP_EOL;
            print $url.PHP_EOL;
            print $data;
            print PHP_EOL.'----------RESPONSE-----------'.PHP_EOL;
            print $content;
            print PHP_EOL.'-----------------------------'.PHP_EOL;
            print '</pre>';
        }

        curl_close($ch);

        /**
         * set request_type value back to default, just in case
         */
        $this->request_type = 'POST';

        return $content;
    }

    /**
     * Get the cURL object
     */
    private function get_curl_obj()
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        $headers = array();
        $headers[] = "Accept: application/json";
        $headers[] = "X-Auth-Token: ".$this->token;
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        if($this->curl_ssl_verify_peer) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        }

        if($this->curl_ssl_verify_host) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, true);
        }

        if ($this->debug) curl_setopt($ch, CURLOPT_VERBOSE, true);

        return $ch;
    }
}
