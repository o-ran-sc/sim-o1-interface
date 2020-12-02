.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. SPDX-License-Identifier: CC-BY-4.0
.. Copyright (C) 2019 highstreet technologies GmbH and others


sim/o1-interface Overview
==========================

# Network Topology Simulator (NTS) | next generation

The Network Topology Simulator is a framework that allows simulating devices that expose a management interface through a NETCONF/YANG interface.

## Description

### Overview

The NETCONF/YANG management interface is simulated, and any YANG models can be loaded by the framework to be exposed. Random data is generated based on the specific models, such that each simulated device presents different data on its management interface.

The NTS framework is based on several open-source projects:
* [cJSON](https://github.com/DaveGamble/cJSON)
* [libcurl](https://curl.haxx.se)
* [libyang](https://github.com/CESNET/libyang)
* [sysrepo](https://github.com/sysrepo/sysrepo)
* [libnetconf2](https://github.com/CESNET/libnetconf2)
* [Netopeer2](https://github.com/CESNET/Netopeer2) 

The NTS Manager can be used to specify the simulation details and to manage the simulation environment at runtime.

Each simulated device is represented as a docker container, where the NETCONF Server is running. The creation and deletion of docker containers associated with simulated devices is handled by the NTS Manager. The NTS Manager is also running as a docker container and exposes a NETCONF/YANG interface to control the simulation.

### NTS Manager

The purpose of the NTS Manager is to ease the utilization of the NTS framework. It enables the user to interact with the simulation framework through a NETCONF/YANG interface. The user has the ability to modify the simulation parameters at runtime and to see the status of the current state of the NTS. The NETCONF/YANG interface will be detailed below.

```
module: nts-manager
  +--rw simulation
     +--rw network-functions
     |  +--rw network-function* [function-type]
     |     +--rw function-type                    identityref
     |     +--rw started-instances                uint16
     |     +--rw mounted-instances                uint16
     |     +--rw mount-point-addressing-method?   enumeration
     |     +--rw docker-instance-name             string
     |     +--rw docker-version-tag               string
     |     +--rw docker-repository                string
     |     +--rw fault-generation
     |     |  +--rw fault-delay-list* [index]
     |     |  |  +--rw index           uint16
     |     |  |  +--rw delay-period?   uint16
     |     |  +--ro fault-count {faults-status}?
     |     |     +--ro normal?     uint32
     |     |     +--ro warning?    uint32
     |     |     +--ro minor?      uint32
     |     |     +--ro major?      uint32
     |     |     +--ro critical?   uint32
     |     +--rw netconf
     |     |  +--rw faults-enabled?   boolean
     |     |  +--rw call-home?        boolean
     |     +--rw ves
     |     |  +--rw faults-enabled?     boolean
     |     |  +--rw pnf-registration?   boolean
     |     |  +--rw heartbeat-period?   uint16
     |     +--ro instances
     |        +--ro instance* [name]
     |           +--ro mount-point-addressing-method?   enumeration
     |           +--ro name                             string
     |           +--ro networking
     |              +--ro docker-ip?     inet:ip-address
     |              +--ro docker-port*   inet:port-number
     |              +--ro host-ip?       inet:ip-address
     |              +--ro host-port*     inet:port-number
     +--rw sdn-controller
     |  +--rw controller-ip?                       inet:ip-address
     |  +--rw controller-port?                     inet:port-number
     |  +--rw controller-netconf-call-home-port?   inet:port-number
     |  +--rw controller-username?                 string
     |  +--rw controller-password?                 string
     +--rw ves-endpoint
     |  +--rw ves-endpoint-protocol?      enumeration
     |  +--rw ves-endpoint-ip?            inet:ip-address
     |  +--rw ves-endpoint-port?          inet:port-number
     |  +--rw ves-endpoint-auth-method?   authentication-method-type
     |  +--rw ves-endpoint-username?      string
     |  +--rw ves-endpoint-password?      string
     |  +--rw ves-endpoint-certificate?   string
     +--ro base-port?           inet:port-number
     +--ro ssh-connections?     uint8
     +--ro tls-connections?     uint8
     +--ro cpu-usage?           percent
     +--ro mem-usage?           uint32
```

#### Detailed information about the YANG attributes

Under **simulation** there are 3 configuration containers and a couple of statistics leafs:
* **network-functions** - represents the simulation data, which will be best described below
* **sdn-controller** - this container groups the configuration related to the ODL based SDN controller that the simulated devices can connect to
    * **controller-ip** - the IP address of the ODL based SDN controller where the simulated devices can be mounted. Both IPv4 and IPv6 are supported
    * **controller-port** - the port of the ODL based SDN controller
    * **controller-netconf-call-home-port** - the NETCONF Call Home port of the ODL based SDN controller
    * **controller-username** - the username to be used when connecting to the ODL based SDN controller
    * **controller-password** - the password to be used when connecting to the ODL based SDN controller
* **ves-endpoint** - this container groups the configuration related to the VES endpoint where the VES messages are targeted
    * **ves-endpoint-protocol** - the protocol of the VES endpoint where VES messages are targeted
    * **ves-endpoint-ip** - the IP address of the VES endpoint where VES messages are targeted
    * **ves-endpoint-port** - the port address of the VES endpoint where VES messages are targeted
    * **ves-endpoint-auth-method** - the authentication method to be used when sending the VES message to the VES endpoint. Possible values are:
        + *no-auth* - no authentication
        + *cert-only* - certificate only authentication in this case the certificate to be used for the communication must be configured
        + *basic-auth* - classic username/password authentication in this case both the username and password need to be configured
        + *cert-basic-auth* - authentication that uses both username/password and a certificate all three values need to be configured in this case
    * **ves-endpoint-username** - the username to be used when authenticating to the VES endpoint
    * **ves-endpoint-password** - the password to be used when authenticating to the VES endpoint
    * **ves-endpoint-certificate** - the certificate to be used when authenticating to the VES endpoint
* base-port - status node indicating the start port for mapping the simulated network functions; ports are assigned in an increasing order starting from this base port
* ssh-connections - status node indicating the number of SSH Endpoints each network function instance exposes
* tls-connections - status node indicating the number of TLS Endpoints each network function instance exposes
* cpu-usage - status node indicating the **total** CPU usage of the simulation
* mem-usage - status node indicating the **total** memory usage of the simulation

Under the **network-functions** there is the **network-function** list. This list is automatically populated by the NTS Manager at start time with the available network functions. No changes at the actual list are allowed (adding or removing elements), only the changes of the properties of the elements have effect. The structure of an element of this list is described below:
* **function-type** - the function type
* **started-devices** - represents the number of simulated devices. The default value is 0, meaning that when the NTS is started, there are no simulated devices. When this value is increased to **n**, the NTS Manager starts docker containers in order to reach **n** simulated devices. If the value is decreased to **k**, the NTS Manager will remove docker containers in a LIFO manner, until the number of simulated devices reaches **k**
* **mounted-devices** - represents the number of devices to be mounted to an ODL based SDN Controller. The same phylosophy as in the case of the previous leaf applies. If this number is increased, the number of ODL mountpoints increases. Else, the simulated devices are being unmounted from ODL. The number of mounted devices cannot exceed the number of started devices. The details about the ODL controller where to mount/unmount are given by the **sdn-controller** container
* **mount-point-addressing-method** - addressing method of the mount point. Possible values are:
    + *docker-mapping* - [default value] future started simulated devices will be mapped on the Docker container
    + *host-mapping* - future started simulated devices will me mapped on the host's IP address and port based on *base-port*
* **docker-instance-name** - the prefix for future simulated devices (to this name a dash and an increasing number is added)
* **docker-version-tag** - a specific version tag for the Docker container to be ran. if empty, the latest version is ran
* **docker-repository** - the prefix for containing the Docker repository information. if local repository is used, value can be either blank or *local*
* **fault-generation** - container which groups the fault generation features, explained later
* **netconf** - container with settings for enabling or disabling netconf features
    * **faults-enabled** - enable or disable faults over netconf
    * **call-home** - enable the NETCONF Call Home feature. If set to 'true', each simulated device, when booting up, will try to Call Home to the SDN Controller.
* **ves** - container with settings for enabling or disabling VES features
    * **faults-enabled** - enable or disable faults over VES
    * **pnf-registration** - enable PNF registration on start
    * **heartbeat-period** - the number of seconds between VES heartbeat messages
    
#### Manager datastore changes mode of operation

Changing any value from **sdn-controller** or **ves-endpoint** containers will be propagated to all running simulated network functions, and all new ones will use the values here. In the same manner, triggering any changes to the **fault-generation**, **netconf** and **ves** settings in a network function element from the *network-function* list will automatically propagate to all running network functions of the same *function-type*. However, changing the *docker-\** leafs of the *network-function* won't propagate, as they're only used as settings for starting new network functions.

### NTS network function 

The NTS network function represents the actual simulated device.

```
module: nts-network-function
  +--rw simulation
     +--rw network-function
     |  +--rw mount-point-addressing-method?   enumeration
     |  +--rw fault-generation
     |  |  +--rw fault-delay-list* [index]
     |  |  |  +--rw index           uint16
     |  |  |  +--rw delay-period?   uint16
     |  |  +--ro fault-count {faults-status}?
     |  |     +--ro normal?     uint32
     |  |     +--ro warning?    uint32
     |  |     +--ro minor?      uint32
     |  |     +--ro major?      uint32
     |  |     +--ro critical?   uint32
     |  +--rw netconf
     |  |  +--rw faults-enabled?   boolean
     |  |  +--rw call-home?        boolean
     |  +--rw ves
     |     +--rw faults-enabled?     boolean
     |     +--rw pnf-registration?   boolean
     |     +--rw heartbeat-period?   uint16
     +--rw sdn-controller
     |  +--rw controller-ip?                       inet:ip-address
     |  +--rw controller-port?                     inet:port-number
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
    +---x datastore-random-populate
    |  +--ro output
    |     +--ro status    enumeration
    +---x feature-control
    |  +---w input
    |  |  +---w features    ntsc:feature-type
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
```

#### Detailed information about the YANG attributes

All de details and mechanisms of the **network-function** container are explained in the **NTS Manager** section. Besides this container, there are also a couple of RPCs defined:
* **datastore-random-populate** - calling this will trigger the network function to populate all its datastore with random data, and based on the *config.json* defined rules
* **feature-control** - calling this will enable selected features. currently available features are:
    * **ves-file-ready** - enables VES file ready, and stats a FTP and a SFTP server on the network function
    * **ves-heartbeat** - enabled VES heartbeat feature
    * **ves-pnf-registration** - enables VES PNF registration
    * **manual-notification-generation** - enables the manual notification generation feature
    * **netconf-call-home** - enables NETCONF's Call Home feature
    * **web-cut-through** - enables web cut through, adding the info to the ietf-system module
* **invoke-notification** - this RPC is used for forcing a simulated device to send a NETCONF notification, as defined by the user. 
    - The **input** needed by the RPC:
        - **notification-format** - can be either *json* or *xml*
        - **notification-object** - this is a string containing the notification object that we are trying to send from the simulated device, in JSON format. **Please note that the user has the responsibility to ensure that the JSON object is valid, according to the definition of the notification in the YANG module.** There is no possibility to see what was wrong when trying to send an incorrect notification. The RPC will only respond with an "ERROR" status in that case, without further information. E.g. of a JSON containing a notification object of type ***otdr-scan-result*** defined in the ***org-openroadm-device*** YANG module: ***{"org-openroadm-device:otdr-scan-result":{"status":"Successful","status-message":"Scan result was successful","result-file":"/home/result-file.txt"}}***. **Please note that the notification object contains also the name of the YANG model defning it, as a namespace, as seen in the example.**
    - The **output** returned by the RPC:
        - **status** - if the notification was send successfully by the simulated device, the RPC will return a **SUCCESS** value. Else, the RPC will return a **ERROR** value.
* **invoke-ves-pm-file-ready** - as name impiles, it invokes a file ready VES request, with a specified *file-location*
* **clear-fault-counters** - clears all counters for the fault generation system. see **Fault generation** below.

#### Network function operation

Under usual operation, the network functions are managed by the manager which will perform the operations listed below. However, if a user chooses to, it can manually start up a network function, and manage it via NETCONF (datastore and RPCs).
1. Create and start Docker container
2. Set the VES and SDN controller data via NETCONF
3. Invoke **datastore-random-populate** RPC to populate the datastore
4. Invoke **feature-control**, enabling **ALL** the features.

#### Datastore random population

The datastore will be populated with random values on each of its leafs. However, certain there is some control on the population itself, which can be found in *config.json*, which is commented. Please note that the nodes below should be main nodes in *config.json*:
```
"debug-max-string-size" : 50,       //max size of string. if not set, default is 255
    
"populate-rules" : {
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
    
    "default-list-instances": 1,    //default number of instances a list or a leaflist should be populated with
    "custom-list-instances" : [     //custom number of list instances. instance is schema name, and should reflect a list or a leaflist
        {"/ietf-interfaces:interfaces/interface": 2}, //2 instances of this. if 0, list will be excluded from populating
    ],
    "restrict-schema" : [           //restrictions to certain schema nodes to a set of values (so no random here)
        {"/ietf-interfaces:interfaces/interface/type" : ["iana-if-type:ethernetCsmacd", "other-value"]},
        {"/ietf-interfaces:interfaces/interface/name" : ["name1", "name2"]}
    ]
}
```

#### Fault generation

Fault generation is controlled using a combination of JSON and YANG settings.
From the JSON perspective, the settings are as below:
```
"alarm-rules" : {
    "yang-notif-template" : "<xml ... %%severity%%  $$time$$  %%custom1%%>",
    "choosing-method" : "random | linear",
    "alarms" : [
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
```
* **alarm-rules** node should be a main node in *config.json* for the respective network function in order for the fault generation to be enabled
    * **yang-notif-template** - template of the yang notification model in current network function. can be "" to disable notifications. must always be present
    * **choosing-method** - method to choose the alarm. can be either *linear* or *random*, and must always be present
    * **alarms** list of alarms to choose from by "choosing-method". it can contain any number of fields, custom ones, along with the mandatory VES fields presented below:
        * **condition**
        * **object**
        * **severity** - should correspond to VES defined: NORMAL, WARNING, MINOR, MAJOR, CRITICAL (case sensitive)
        * **date-time**
        * **specific-problem**

On the **yang-notif-template** and on any of the fields, there are two options for creating "dynamic" content (also see example above):
* **variables** - any field put in between %% will be replaced with the field's value
* **functions** - function names are put in between $$. Available functions are:
    * **time** - returns current timestamp in a YANG date-time format
    * **uint8_counter** - a unique 8-bit counter, starting from 0, each time this function is found, the counter is automatically increased; when going above the max value, it will reset from 0
    * **uint16_counter** - a unique 16-bit counter, starting from 0, each time this function is found, the counter is automatically increased; when going above the max value, it will reset from 0
    * **uint32_counter** - a unique 32-bit counter, starting from 0, each time this function is found, the counter is automatically increased; when going above the max value, it will reset from 0

It is worth to mention that the replacement is done within any field, of any field. This means that it is possible to have nested fields and functions. See example for better understanding.

From the YANG perspective, one can control whether faults are enabled or disabled independently via NETCONF and/or VES, through their respective containers described in the sections above. The YANG **fault-generation** container contains:
* **fault-delay-list** - a list with elements which consists of *index* (unimportant, but needs to be unique) and *delay-period* which represents the number of seconds in between the current fault and the next fault. Please note that the fault is chosen from and based on the settings esablished in *config.json*
* **fault-count** - the status of the faults encountered by the network function; it is not present in the manager's schema

In order to clear the **fault-count** counters, on the **network-function** module there is a **clear-fault-counters** RPC which can be called via NETCONF.

### NTS Application

Either of the two main functionalities (*manager* and *network-function*) are implemented by the same binary application. Besides this functionality, the application can also do some utility functions, which can be used if the application is ran from the CLI (command line interface), along with some parameters.

#### CLI paramters
The paramers are described below:
- --help - shows the help (also described here)
- --docker-init - is automatically used by Docker when building the images to install modules and enable features. Described in the next chapter. **Do not run manually**
- the two main modes:
    - --manager - runs in manager mode
    - --network-function - runs in network function mode
- global settings, which can be used with **ANY** of the other operating modes:
    - --operational-only - used in testing. do not use the RUNNING datastore, only do the population on OPERATIONAL datastore
    - --fixed-rand - used in testing. specify a fixed value seed for the randomness
    - --verbose - set the verbose level. can range from 0 to 2, default is 1
    - --workspace - set the current working workspace. the workspace must contain the *config* and *log* folders    
- test modes - do not use
- utilitary functions:
    - --ls - list all modules in the datastore with their attributes
    - --schema - list the schema of an xpath given as parameter
    - --populate - populate the datastore upon starting
    - --enable-features - enable all features upon starting, after (if requested) the populating was done
    - --nc-server-init - initialize netconf server
    - --loop - after everything is done, run an endless loop

#### Docker container initialization

The NTS app is responsible for initializing the Docker container upon build. What it actually does is described below:
1. Install modules located in the *deploy/yang/* folder recusively
    - note that if a module requires startup data (mandatory data), this can be acheived by having an **XML** file with this data along the YANG file. For example, if, let's say *ietf-interfaces.yang* would require startup date, there must be a *ietf-interfaces.xml* located in the same folder.
2. Enable all YANG features of the modules, unless specifically excluded

If the initialization failes, the result is returned to the Docker builder, so the build will fail, and user can see the output. Docker initialization can be customized from the *config.json* file, as described below. The example is self-expainatory, and the *docker-rules* node needs to be a main node of *config.json*:

```
"docker-rules": {
    "excluded-modules": [          //excluded modules from installing
        "module1",
        "module2"
    ],
    "excluded-features": [         //excluded features from installing
        "feature1",
        "feature2"
    ]
}
```

## Usage

The NTS Manager can be used to start any type of simulated network function.

### Building the images

The `nts_build.sh` script should be used for building the docker images needed by the NTS to the local machine. This will create docker images for the Manager and for each type of simulated network function.

The user can also directly use the already built docker images, that are pushed to the highstreet docker repository. This can be done by using the `nts_pull_highstreet_repo.sh` script, which will pull all the images locally.

### Starting the NTS Manager

The **nts-manager-ng** can be started using the docker-compose file in this repo. The file assumes that the docker images were pulled from the highstreet docker repository.

```
docker-compose up
```

Before starting, the user should set the environment variables defined in the docker-compose file according to his needs:
* **NETCONF_NTS_HOST_IP**: an IP address from the host, which should be used by systems outside the local machine to address the simulators;
* **NETCONF_NTS_HOST_BASE_PORT**: the port from where the allocation for the simulated network functions should start;
* **IPv6Enabled**: should be set to `true` if IPv6 is enabled in the docker daemon and the user wants to use IPv6 to address the simulated  network functions.

When using the highstreet docker repository for the images, in each simulated network-function the **docker-repository** leaf must be set accordingly  (to the value: *10.20.6.10:30000/hightec*), because all the docker images that are being pulled from the docker repo have this prefix.

## Release notes
### version 1.0.2
- [fixed] bug that occured when trying to start a wrong instance (bad docker-repository or docker-tag)
- [fixed] when populating the fault-delay-list, if the sum of all the faults was 0, the network funciton kept on generating faults and crashed

### version 1.0.1
- [feature-add] added web-cut-through feature
- [fixed] mount-point-addressing-method was mistakenly changing after starting

### version 1.0.0
Initial release.
