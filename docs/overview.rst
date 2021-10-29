.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. SPDX-License-Identifier: CC-BY-4.0
.. Copyright (C) 2019 highstreet technologies GmbH and others


sim/o1-interface Overview
**************************

Network Topology Simulator (NTS) | next generation
--------------------------------------------------

The Network Topology Simulator is a framework that allows simulating Network Functions (NF) that expose a management interface via NETCONF/YANG.

Overview
--------

The NETCONF/YANG management interface is simulated, and any YANG models can be loaded by the framework to be exposed. Random data is generated based on the specific models, such that each simulated NF presents different data on its management interface.

The NTS framework is based on several open-source projects

- `cJSON <https://github.com/DaveGamble/cJSON>`_
- `libcurl <https://curl.haxx.se>`_
- `libyang <https://github.com/CESNET/libyang>`_
- `sysrepo <https://github.com/sysrepo/sysrepo>`_
- `libnetconf2 <https://github.com/CESNET/libnetconf2>`_
- `Netopeer2 <https://github.com/CESNET/Netopeer2>`_

The NTS Manager can be used to specify the simulation details and to manage the simulation environment at runtime.

Each simulated NF is represented as a docker container, where the NETCONF Server is running. The creation and deletion of docker containers associated with simulated NFs is handled by the NTS Manager. The NTS Manager is also running as a docker container and exposes a proprietary NETCONF/YANG interface to control the simulation.

NTS Manager
-----------

The purpose of the NTS Manager is to ease the utilization of the NTS framework. It enables the user to interact with the simulation framework through a NETCONF/YANG interface. The user has the ability to modify the simulation parameters at runtime and to see the status of the current state of the NTS. The NETCONF/YANG interface will be detailed below.

::

    module: nts-manager
    +--rw simulation!
        +--ro available-images
        |  +--ro network-function-image* []
        |     +--ro function-type?        identityref
        |     +--ro docker-image-name     string
        |     +--ro docker-version-tag    string
        |     +--ro docker-repository     string
        +--rw network-functions!
        |  +--rw network-function* [function-type]
        |     +--rw function-type                    identityref
        |     +--rw started-instances                uint16
        |     +--rw mounted-instances                uint16
        |     +--rw mount-point-addressing-method?   enumeration
        |     +--rw docker-instance-name             string
        |     +--rw docker-version-tag               string
        |     +--rw docker-repository                string
        |     +--rw fault-generation!
        |     |  +--rw fault-delay-list* [index]
        |     |  |  +--rw index           uint16
        |     |  |  +--rw delay-period?   uint16
        |     |  +--ro fault-count {faults-status}?
        |     |     +--ro normal?     uint32
        |     |     +--ro warning?    uint32
        |     |     +--ro minor?      uint32
        |     |     +--ro major?      uint32
        |     |     +--ro critical?   uint32
        |     +--rw netconf!
        |     |  +--rw faults-enabled?   boolean
        |     |  +--rw call-home?        boolean
        |     +--rw ves!
        |     |  +--rw faults-enabled?     boolean
        |     |  +--rw pnf-registration?   boolean
        |     |  +--rw heartbeat-period?   uint16
        |     +--ro instances
        |        +--ro instance* [name]
        |           +--ro mount-point-addressing-method?   enumeration
        |           +--ro name                             string
        |           +--ro is-mounted?                      boolean
        |           +--ro networking
        |              +--ro docker-ip?      inet:ip-address
        |              +--ro docker-ports* [port]
        |              |  +--ro port        inet:port-number
        |              |  +--ro protocol?   identityref
        |              +--ro host-ip?        inet:ip-address
        |              +--ro host-ports* [port]
        |                 +--ro port        inet:port-number
        |                 +--ro protocol?   identityref
        +--rw sdn-controller!
        |  +--rw controller-protocol?                 enumeration
        |  +--rw controller-ip?                       inet:ip-address
        |  +--rw controller-port?                     inet:port-number
        |  +--rw controller-netconf-call-home-ip?     inet:ip-address
        |  +--rw controller-netconf-call-home-port?   inet:port-number
        |  +--rw controller-username?                 string
        |  +--rw controller-password?                 string
        +--rw ves-endpoint!
        |  +--rw ves-endpoint-protocol?      enumeration
        |  +--rw ves-endpoint-ip?            inet:ip-address
        |  +--rw ves-endpoint-port?          inet:port-number
        |  +--rw ves-endpoint-auth-method?   authentication-method-type
        |  +--rw ves-endpoint-username?      string
        |  +--rw ves-endpoint-password?      string
        |  +--rw ves-endpoint-certificate?   string
        +--ro ports
        |  +--ro netconf-ssh-port?      inet:port-number
        |  +--ro netconf-tls-port?      inet:port-number
        |  +--ro transport-ftp-port?    inet:port-number
        |  +--ro transport-sftp-port?   inet:port-number
        +--ro ssh-connections?         uint8
        +--ro tls-connections?         uint8
        +--ro cpu-usage?               percent
        +--ro mem-usage?               uint32
        +--ro last-operation-status?   string

    notifications:
        +---n instance-changed
        |  +--ro change-status    string
        |  +--ro function-type    identityref
        |  +--ro name             string
        |  +--ro is-mounted?      boolean
        |  +--ro networking
        |     +--ro docker-ip?      inet:ip-address
        |     +--ro docker-ports* [port]
        |     |  +--ro port        inet:port-number
        |     |  +--ro protocol?   identityref
        |     +--ro host-ip?        inet:ip-address
        |     +--ro host-ports* [port]
        |        +--ro port        inet:port-number
        |        +--ro protocol?   identityref
        +---n operation-status-changed
        +--ro operation-status    string
        +--ro error-message?      string

Detailed information about the YANG attributes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Under **simulation** there are 3 configuration containers and a couple of statistics leafs:

- **network-functions** - represents the simulation data, which will be best described below
- **sdn-controller** - this container groups the configuration related to the ODL based SDN controller that the simulated devices can connect to:
  
    - **controller-protocol** - SDN controller protocol (http/https)
    - **controller-ip** - the IP address of the ODL based SDN controller where the simulated devices can be mounted. Both IPv4 and IPv6 are supported
    - **controller-port** - the port of the ODL based SDN controller
    - **controller-netconf-call-home-ip** - the IP address of the ODL based SDN controller where the simulated devices can Call Home via the NETCONF Call Home feature.
    - **controller-netconf-call-home-port** - the NETCONF Call Home port of the ODL based SDN controller
    - **controller-username** - the username to be used when connecting to the ODL based SDN controller
    - **controller-password** - the password to be used when connecting to the ODL based SDN controller

- **ves-endpoint** - this container groups the configuration related to the VES endpoint where the VES messages are targeted:

    - **ves-endpoint-protocol** - the protocol of the VES endpoint where VES messages are targeted (http/https)
    - **ves-endpoint-ip** - the IP address of the VES endpoint where VES messages are targeted
    - **ves-endpoint-port** - the port address of the VES endpoint where VES messages are targeted
    - **ves-endpoint-auth-method** - the authentication method to be used when sending the VES message to the VES endpoint. Possible values are:

        + *no-auth* - no authentication
        + *cert-only* - certificate only authentication in this case the certificate to be used for the communication must be configured
        + *basic-auth* - classic username/password authentication in this case both the username and password need to be configured
        + *cert-basic-auth* - authentication that uses both username/password and a certificate all three values need to be configured in this case
        + 
    - **ves-endpoint-username** - the username to be used when authenticating to the VES endpoint
    - **ves-endpoint-password** - the password to be used when authenticating to the VES endpoint
    - **ves-endpoint-certificate** - the certificate to be used when authenticating to the VES endpoint
- **ports**: if any ports share the same number, the order is: netconf-ssh (all ports), netconf-tls (all ports), ftp (1 port), sftp (1 port):

    - **netconf-ssh-port** - base port for NETCONF SSH
    - **netconf-tls-port** - base port for NETCONF TLS
    - **transport-ftp-port** - base port for FTP
    - **transport-sftp-port** - base port for SFTP

- **ssh-connections** - status node indicating the number of SSH Endpoints each network function instance exposes
- **tls-connections** - status node indicating the number of TLS Endpoints each network function instance exposes
- **cpu-usage** - status node indicating the **total** CPU usage of the simulation
- **mem-usage** - status node indicating the **total** memory usage of the simulation
- **last-operation-status** - indicates the status of last manager ran operation

Under the **network-functions** there is the **network-function** list. This list is automatically populated by the NTS Manager at start time with the available network functions. No changes at the actual list are allowed (adding or removing elements), only the changes of the properties of the elements have effect. The structure of an element of this list is described below:

- **function-type** - the function type
- **started-devices** - represents the number of simulated devices. The default value is 0, meaning that when the NTS is started, there are no simulated devices. When this value is increased to **n**, the NTS Manager starts docker containers in order to reach **n** simulated devices. If the value is decreased to **k**, the NTS Manager will remove docker containers in a LIFO manner, until the number of simulated devices reaches **k**
- **mounted-devices** - represents the number of devices to be mounted to an ODL based SDN Controller. The same phylosophy as in the case of the previous leaf applies. If this number is increased, the number of ODL mountpoints increases. Else, the simulated devices are being unmounted from ODL. The number of mounted devices cannot exceed the number of started devices. The details about the ODL controller where to mount/unmount are given by the **sdn-controller** container
- **mount-point-addressing-method** - addressing method of the mount point. Possible values are:
  
    + *docker-mapping* - [default value] future started simulated devices will be mapped on the Docker container
    + *host-mapping* - future started simulated devices will me mapped on the host's IP address and port based on *base-port*
- **docker-instance-name** - the prefix for future simulated devices (to this name a dash and an increasing number is added)
- **docker-version-tag** - a specific version tag for the Docker container to be ran. if empty, the latest version is ran
- **docker-repository** - the prefix for containing the Docker repository information. if local repository is used, value can be either blank or *local*
- **fault-generation** - container which groups the fault generation features, explained later
- **netconf** - container with settings for enabling or disabling netconf features:

    - **faults-enabled** - enable or disable faults over netconf
    - **call-home** - enable the NETCONF Call Home feature. If set to 'true', each simulated device, when booting up, will try to Call Home to the SDN Controller.
- **ves** - container with settings for enabling or disabling VES features:

    - **faults-enabled** - enable or disable faults over VES
    - **pnf-registration** - enable PNF registration on start
    - **heartbeat-period** - the number of seconds between VES heartbeat messages

The **available-images** container has a list containing available (installed) simulations. The list corresponds (has the same name, and specific leafs) to the **network-function** list inside **simulation**, and the description is the same. This list is populated by the Manager at runtime after it checks which Docker images are pulled, including having multiple versions (both in tag and repository). To be more clear, each entry of this list is a possible simulation, and the list contains all the possible simulations. This allows the user to know the simulation capabilities of the Manager.

There are 2 defined **notifications**:

- **instance-changed** notification: is called by the manager whenever a change is done to any of the network functions. This contains data about the change:
  
    - **change-status**: is a string which has the following structure: operation STATUS - info. operation can be *start*, *stop*, *mount*, *unmount*, *config* and *reconfig*; STATUS can be SUCCESS or FAILED; info can be present or not, depending on what further information is available about the change
    - **function-type**: the function-type for the instance
    - **name**: name of the instance that is changed
    - **networking**: when starting and configuring an instance, this container has all the necessary networking data, such as IP and ports
  
- **operation-status-changed** notification is called by the manager at the end of an operation:

    - **status** returns the status of the operation: SUCCESS/FAILED. This status can also be statically read from the operational datastore under *nts-manager:simulation/last-operation-status*
    - **error-mesage** an error message with details of the error (if any).

Manager datastore changes mode of operation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Changing any value from **sdn-controller** or **ves-endpoint** containers will be propagated to all running simulated network functions, and all new ones will use the values here. In the same manner, triggering any changes to the **fault-generation**, **netconf** and **ves** settings in a network function element from the *network-function* list will automatically propagate to all running network functions of the same *function-type*. However, changing the *docker-\** leafs of the *network-function* won't propagate, as they're only used as settings for starting new network functions.

NTS network function
---------------------

The NTS network function represents the actual simulated device.

::

    module: nts-network-function
    +--ro info
    |  +--ro build-time?         yang:date-and-time
    |  +--ro version?            string
    |  +--ro started-features?   ntsc:feature-type
    +--rw simulation
        +--rw network-function
        |  +--rw function-type?                   string
        |  +--rw mount-point-addressing-method?   enumeration
        |  +--rw fault-generation!
        |  |  +--rw fault-delay-list* [index]
        |  |  |  +--rw index           uint16
        |  |  |  +--rw delay-period?   uint16
        |  |  +--ro fault-count {faults-status}?
        |  |     +--ro normal?     uint32
        |  |     +--ro warning?    uint32
        |  |     +--ro minor?      uint32
        |  |     +--ro major?      uint32
        |  |     +--ro critical?   uint32
        |  +--rw netconf!
        |  |  +--rw faults-enabled?   boolean
        |  |  +--rw call-home?        boolean
        |  +--rw ves!
        |     +--rw faults-enabled?     boolean
        |     +--rw pnf-registration?   boolean
        |     +--rw heartbeat-period?   uint16
        +--rw sdn-controller
        |  +--rw controller-ip?                       inet:ip-address
        |  +--rw controller-port?                     inet:port-number
        |  +--rw controller-netconf-call-home-ip?     inet:ip-address
        |  +--rw controller-netconf-call-home-port?   inet:port-number
        |  +--rw controller-username?                 string
        |  +--rw controller-password?                 string
        +--rw ves-endpoint
            +--rw ves-endpoint-protocol?      enumeration
            +--rw ves-endpoint-ip?            inet:ip-address
            +--rw ves-endpoint-port?          inet:port-number
            +--rw ves-endpoint-auth-method?   authentication-method-type
            +--rw ves-endpoint-username?      string
            +--rw ves-endpoint-password?      string
            +--rw ves-endpoint-certificate?   string

    rpcs:
        +---x datastore-populate
        |  +--ro output
        |     +--ro status    enumeration
        +---x feature-control
        |  +---w input
        |  |  +---w start-features?   ntsc:feature-type
        |  |  +---w stop-features?    ntsc:feature-type
        |  +--ro output
        |     +--ro status    enumeration
        +---x invoke-notification
        |  +---w input
        |  |  +---w notification-format    enumeration
        |  |  +---w notification-object    string
        |  +--ro output
        |     +--ro status    enumeration
        +---x invoke-ves-pm-file-ready
        |  +---w input
        |  |  +---w file-location    string
        |  +--ro output
        |     +--ro status    enumeration
        +---x clear-fault-counters
        +--ro output
            +--ro status    enumeration


Detailed information about the YANG attributes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All de details and mechanisms of the **network-function** container are explained in the **NTS Manager** section. Besides this container, there are also a couple of RPCs defined:

- **datastore-populate** - calling this will trigger the network function to populate all its datastores with data based on the *config.json* defined rules
- **feature-control** - calling this will start or stop selected features. currently available features are (features marked with * can not be stopped once started):

    - **ves-file-ready** - enables VES file ready, and stats a FTP and a SFTP server on the network function
    - **ves-heartbeat** - enabled VES heartbeat feature
    - **ves-pnf-registration*** - enables VES PNF registration
    - **manual-notification-generation** - enables the manual notification generation feature
    - **netconf-call-home*** - enables NETCONF's Call Home feature
    - **web-cut-through** - enables web cut through, adding the info to the ietf-system module

- **invoke-notification** - this RPC is used for forcing a simulated device to send a NETCONF notification, as defined by the user:

    - The **input** needed by the RPC:
  
        - **notification-format** - can be either *json* or *xml*
        - **notification-object** - this is a string containing the notification object that we are trying to send from the simulated device, in JSON format. **Please note that the user has the responsibility to ensure that the JSON object is valid, according to the definition of the notification in the YANG module.** There is no possibility to see what was wrong when trying to send an incorrect notification. The RPC will only respond with an "ERROR" status in that case, without further information. E.g. of a JSON containing a notification object of type ***otdr-scan-result*** defined in the ***org-openroadm-device*** YANG module: ***{"org-openroadm-device:otdr-scan-result":{"status":"Successful","status-message":"Scan result was successful","result-file":"/home/result-file.txt"}}***. **Please note that the notification object contains also the name of the YANG model defning it, as a namespace, as seen in the example.**
    - The **output** returned by the RPC:
  
        - **status** - if the notification was send successfully by the simulated device, the RPC will return a **SUCCESS** value. Else, the RPC will return a **ERROR** value.

- **invoke-ves-pm-file-ready** - as name impiles, it invokes a file ready VES request, with a specified *file-location*
- **clear-fault-counters** - clears all counters for the fault generation system. see **Fault generation** below.

It is worth mentioning that the *NTS Manager* also populates the `function-type` leaf of its own *nts-network-function* module with the value `NTS_FUNCTION_TYPE_MANAGER`. This is done to help users which are connected to a NETCONF server get the data from *nts-network-function* and immediatly see what they are connected to.

Network function operation
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Under usual operation, the network functions are managed by the manager which will perform the operations listed below. However, if a user chooses to, it can manually start up a network function, and manage it via NETCONF (datastore and RPCs) or enviroment (see below).
1. Create and start Docker container
2. Set the VES and SDN controller data via NETCONF
3. Invoke **datastore-populate** RPC to populate the datastore
4. Invoke **feature-control**, enabling **ALL** the features.


Network function standalone operation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The network function can run in standalone mode when the **NTS_NF_STANDALONE_START_FEATURES** environment variable is not blank. The value found here determines the standalone operation, and it can be combined of two values:

- datastore-populate, which populates the datastore by the rules
- any bits of the feature-type YANG typedef (defined in nts-common.yang), which will enable the respective features.

Other than this, the network-function will operate just as it would when started by the manager and it can be controller through the **nts-network-function.yang** interface.

The default mount point addressing method is "docker-mapping". However this behaviour can be changed by setting the  **NTS_NF_MOUNT_POINT_ADDRESSING_METHOD** enviroment variable to "host-mapping". When "host-mapping" is chosen, all the host ports must be fowareded from Docker by the user when running the network function, and **NTS_HOST_IP** and **NTS_HOST_xxxx_PORT** enviroment variables should be set for the network function to know how to perform its tasks.

Datastore random population
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The datastore will be populated with random values on each of its leafs. However, certain there is some control on the population itself, which can be found in *config.json*, which is commented. Please note that the nodes below should be main nodes in *config.json*:

::

    "datastore-random-generation-rules" : {
        "excluded-modules": [           //modules to be excluded from populating
            "sysrepo",
            "sysrepo-monitoring",
            "ietf-yang-library",
            "ietf-netconf-acm",
            "ietf-netconf-monitoring",
            "nc-notifications",
            "ietf-keystore",
            "ietf-truststore",
            "ietf-system",
            "ietf-netconf-server"
        ],

        "debug-max-string-size" : 50,       //max size of string. if not set, default is 255
        
        "default-list-instances": 1,    //default number of instances a list or a leaflist should be populated with
        "custom-list-instances" : [     //custom number of list instances. instance is schema name, and should reflect a list or a leaflist
            {"/ietf-interfaces:interfaces/interface": 2}, //2 instances of this. if 0, list will be excluded from populating
        ],
        "restrict-schema" : [           //restrictions to certain schema nodes to a set of values (so no random here)
            {"/ietf-interfaces:interfaces/interface/type" : ["iana-if-type:ethernetCsmacd", "other-value"]},
            {"/ietf-interfaces:interfaces/interface/name" : ["name1", "name2"]}
        ]
    },

    "datastore-populate-rules": {
        "random-generation-enabled": true,  //true or false, whether to generate random data or not (use false only if you want to load pre-generated data only and nothing more)

        "pre-generated-operational-data": [ //path with files containing NETCONF data, either JSON or XML
            "path/to/data.json",
            "path/to/data.xml"
        ],
        
        "pre-generated-running-data": [ //path with files containing NETCONF data, either JSON or XML
            "path/to/data.json",
            "path/to/data.xml"
        ]
    }

NOTE: pre-generated data must be in either JSON or XML format; be careful on how the file name is saved, because the simulator can only discover format based on filename (case-sensitve ".json" or ".xml")

NOTE: when generating random data, the pre-generated data is loaded first, and any module affected by the pre-generated data is automatically excluded from random populating. The order in which data is added to the datastore is:

1. pre-generated data
2. random data

NOTE: the order in which datastores are being populated:

1. the RUNNING datastore
2. the OPERATIONAL datastore

Fault generation
^^^^^^^^^^^^^^^^

Fault generation is controlled using a combination of JSON and YANG settings. From the JSON perspective, the settings are as below:

::

    "fault-rules" : {
        "yang-notif-template" : "<xml ... %%severity%%  $$time$$  %%custom1%%>",
        "choosing-method" : "random | linear",
        "faults" : [
            {
                //ves mandatory fields
                "condition" : "",
                "object"    : "",
                "severity"  : "",
                "date-time" : "$$time$$",
                "specific-problem" : "",

                //template custom fileds
                "custom1" : "",
                "custom2" : ""
            }
            ...
            {
                ...
            }
        ]
    }

- **fault-rules** node should be a main node in *config.json* for the respective network function in order for the fault generation to be enabled
- **yang-notif-template** - template of the yang notification model in current network function. can be "" to disable notifications. must always be present
- **choosing-method** - method to choose the fault. can be either *linear* or *random*, and must always be present
- **faults** list of faults to choose from by "choosing-method". it can contain any number of fields, custom ones, along with the mandatory VES fields presented below:

    - **condition**
    - **object**
    - **severity** - should correspond to VES defined: NORMAL, WARNING, MINOR, MAJOR, CRITICAL (case sensitive)
    - **date-time**
    - **specific-problem**

On the **yang-notif-template** and on any of the fields, there are two options for creating "dynamic" content (also see example above):
- **variables** - any field put in between %% will be replaced with the field's value
- **functions** - function names are put in between $$. Available functions are:

    - **time** - returns current timestamp in a YANG date-time format
    - **uint8_counter** - a unique 8-bit counter, starting from 0, each time this function is found, the counter is automatically increased; when going above the max value, it will reset from 0
    - **uint16_counter** - a unique 16-bit counter, starting from 0, each time this function is found, the counter is automatically increased; when going above the max value, it will reset from 0
    - **uint32_counter** - a unique 32-bit counter, starting from 0, each time this function is found, the counter is automatically increased; when going above the max value, it will reset from 0

It is worth to mention that the replacement is done within any field, of any field. This means that it is possible to have nested fields and functions. See example for better understanding.

From the YANG perspective, one can control whether faults are enabled or disabled independently via NETCONF and/or VES, through their respective containers described in the sections above. The YANG **fault-generation** container contains:

- **fault-delay-list** - a list with elements which consists of *index* (unimportant, but needs to be unique) and *delay-period* which represents the number of seconds in between the current fault and the next fault. Please note that the fault is chosen from and based on the settings esablished in *config.json*
- **fault-count** - the status of the faults encountered by the network function; it is not present in the manager's schema

In order to clear the **fault-count** counters, on the **network-function** module there is a **clear-fault-counters** RPC which can be called via NETCONF.

NTS Application
---------------

Either of the two main functionalities (*manager* and *network-function*) are implemented by the same binary application. This another functionality added in v1.0.8 which implements supervisor capabilities for governing the Docker container. Besides these functionalities, the application can also do some utility functions, which can be used if the application is ran from the CLI (command line interface), along with some parameters.

CLI paramters
^^^^^^^^^^^^^^

The paramers are described below:
- --help - shows the help (also described here)
- --version - describes ntsng version and build time
- **main modes**:
  
    - --container-init - is automatically used by Docker when building the images to install modules and enable features. Described in the next chapter. **Do not run manually**
    - --supervisor - runs in supervisor mode (configuration is done via config.json)
    - --manager - runs in manager mode
    - --network-function - runs in network function mode
    - --generate - generates data based on current settings and datastores, without commiting the data (saves to file)
    - --test-mode - test mode for automated tests. **Do not use**

- global settings changer:

    - --fixed-rand - used in testing. specify a fixed value seed for the randomness
    - --verbose - set the verbose level. can range from 0 (errors-only) to 2 (verbose), default is 1 (info)
    - --workspace - set the current working workspace. the workspace **MUST** be writeable and should contain *config/config.json* file, otherwise a blank json file will be created
- tools:
  
    - --ls - list all modules in the datastore with their attributes
    - --schema - list the schema of an xpath given as parameter

Environment variables
^^^^^^^^^^^^^^^^^^^^^

Below all the available enviroment variables are listed. Please note that if a variable is not defined, it will have a default behaviour:

- **NTS_MANUAL** - when defined, SUPERVISOR will not start any tasks marked as "nomanual"
- **NTS_BUILD_VERSION** - defines build version, set by Dockerfile
- **NTS_BUILD_DATE** - defines build date, set by Dockerfile
- **NTS_NF_STANDALONE_START_FEATURES** - when value is not blank, it allows the network function to run in standalone mode; see "Network function standalone mode" sub-chapter for this
- **NTS_NF_MOUNT_POINT_ADDRESSING_METHOD** - either "docker-mapping" or "host-mapping"; available only when running in network function STANDALONE MODE

- **DOCKER_ENGINE_VERSION** - Docker engine version, defaults to 1.40 if not set
- **HOSTNAME** - Container hostname
- **IPv6_ENABLED** - true/false whether IP v6 is enabled (default false)
- **SSH_CONNECTIONS** - number of NETCONF SSH connections that should be enabled (default 1)
- **TLS_CONNECTIONS** - number of NETCONF TLS connections that should be enabled (default 0)

- **NTS_HOST_IP** - Docker host IP address
- **NTS_HOST_BASE_PORT** - see "Starting the NTS Manager" sub-chapter
- **NTS_HOST_NETCONF_SSH_BASE_PORT** - see "Starting the NTS Manager" sub-chapter
- **NTS_HOST_NETCONF_TLS_BASE_PORT** - see "Starting the NTS Manager" sub-chapter
- **NTS_HOST_TRANSFER_FTP_BASE_PORT** - see "Starting the NTS Manager" sub-chapter
- **NTS_HOST_TRANSFER_SFTP_BASE_PORT** - see "Starting the NTS Manager" sub-chapter

- **SDN_CONTROLLER_PROTOCOL** - protocol used for communication with the SDN controller (http or https, defaults to https)
- **SDN_CONTROLLER_IP** - SDN controller IP address
- **SDN_CONTROLLER_PORT** - SDN controller port
- **SDN_CONTROLLER_CALLHOME_IP** - SDN controller IP address for NETCONF call-home
- **SDN_CONTROLLER_CALLHOME_PORT** - SDN controller port for NETCONF call-home
- **SDN_CONTROLLER_USERNAME** - SDN controller username
- **SDN_CONTROLLER_PASSWORD** - SDN controller password

- **VES_COMMON_HEADER_VERSION** - VES protocol version to report (defaults to 7.2)
- **VES_ENDPOINT_PROTOCOL** - protocol used for communication with the VES endpoint (http or https, defaults to https)
- **VES_ENDPOINT_IP** - VES endpoint IP address
- **VES_ENDPOINT_PORT** - VES endpoint port
- **VES_ENDPOINT_AUTH_METHOD** - VES endpoint auth method; see YANG definition for possible values
- **VES_ENDPOINT_USERNAME** - VES endpoint username
- **VES_ENDPOINT_PASSWORD** - VES endpoint password
- **VES_ENDPOINT_CERTIFICATE** - VES endpoint certificate; not implemented at the moment of writing

Supervisor functionality and configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The NTS app tries to be very little dependent on other tools. Until v1.0.8 one of these tools was supervisord, and now its functionality is embedded inside the NTS app. Now the Docker image runs the NTS app with --supervisor parameter to start the supervisor. When supervisor is ran, other main modes and their options are unavailable for that instance (the supervisor will spawn another instance for the main functionalities). Configuration of the supervisor functionality is done via config.json:

::

    "supervisor-rules": {
        "netopeer": {
            "path": "/usr/local/bin/netopeer2-server",
            "args": ["-d", "-v2"],
            "autorestart": true,
            "stdout": "log/netopeer-stdout.log",
            "stderr": "log/netopeer-stderr.log"
        },

        "sshd": {
            "path": "/usr/sbin/sshd",
            "args": ["-D"],
            "autorestart": true,
            "stdout": "log/sshd-stdout.log",
            "stderr": "log/sshd-stderr.log"
        },

        "ntsim-network-function": {
            "path": "/opt/dev/ntsim-ng/ntsim-ng",
            "args": ["-w/opt/dev/ntsim-ng", "-f"],
            "nomanual": true,
            "stdout": "",
            "stderr": ""
        }
    }

The example above is the default example for a network function. The *supervisor-rules* object contains a list of tasks to run, each with their own settings. Below is a description of all parameters:

- path: *mandatory field* - full path to the the binary
- args: a list of arguments to be passed to the binary, default is no arguments
- autorestart: this is true or false, whether to autorestart the application on exit/kill, default is false
- nomanual: when this is true, the task **won't** be automatically ran when the **NTS_MANUAL** environment variable is present. Default is false, and using this is usually good for debugging.
- stdout and stderr: path to redirect stdout or stderr to; if **blank**, it will be replaced by **/dev/null** for discarding. If any of the fields are not present in configuration, default value will be used (actual stdout/stderr).

Docker container initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The NTS app is responsible for initializing the Docker container upon build. What it actually does is described below:

1. Install modules located in the *deploy/yang/* folder recusively
    - note that if a module requires startup data (mandatory data), this can be acheived by having an **XML** or a **JSON** file with this data along the YANG file. For example, if, let's say *ietf-interfaces.yang* would require startup date, there must be a *ietf-interfaces.xml* or *ietf-interfaces.json* located in the same folder.
2. Enable all YANG features of the modules, unless specifically excluded

If the initialization failes, the result is returned to the Docker builder, so the build will fail, and user can see the output. Docker initialization can be customized from the *config.json* file, as described below. The example is self-expainatory, and the *container-rules* node needs to be a main node of *config.json*:

::

    "container-rules": {
        "excluded-modules": [          //excluded modules from installing
            "module1",
            "module2"
        ],
        "excluded-features": [         //excluded features from installing
            "feature1",
            "feature2"
        ]
    }

Building the images locally
---------------------------

The `nts_build.sh` script should be used for building the docker images needed by the NTS to the local machine. This will create docker images for the Manager and for each type of simulated network function.

The user can also directly use the already built docker images, that are pushed to the nexus3 docker repository by the LF Jenkins Job. E.g.: *nexus3.o-ran-sc.org:10004/o-ran-sc/nts-ng-o-ran-du:1.2.0*

Starting the NTS Manager
------------------------

The **nts-manager-ng** can be started using the docker-compose file in this repo. The file assumes that the docker images were built locally previously.

::

    docker-compose up -d ntsim-ng


Before starting, the user should set the environment variables defined in the docker-compose file according to his needs:

- **NTS_HOST_IP**: an IP address from the host, which should be used by systems outside the local machine to address the simulators;
- **NTS_HOST_BASE_PORT**: the port from where the allocation for the simulated network functions should start, if not specified otherwise sepparately (see below); any port not defined will automatically be assigned to *BASE_PORT*; **NOTE** that in order for a port to be eligible, it must be greater than or equal to **1000**:
  
    - **NTS_HOST_NETCONF_SSH_BASE_PORT**
    - **NTS_HOST_NETCONF_TLS_BASE_PORT**
    - **NTS_HOST_TRANSFER_FTP_BASE_PORT**
    - **NTS_HOST_TRANSFER_SFTP_BASE_PORT**

- **IPv6_ENABLED**: should be set to `true` if IPv6 is enabled in the docker daemon and the user wants to use IPv6 to address the simulated network functions.

In each simulated network-function the **docker-repository** leaf must be set accordingly  (to the value: *o-ran-sc/*), because all the docker images that are being built locally have this prefix.

Starting standalone NFs
-----------------------

One could start 1 instance of a simulated O-RU-FH and 1 instance of a simulated O-DU by running the `nts-start.sh` script. Pre-configured values can be set in the `.env` file.
