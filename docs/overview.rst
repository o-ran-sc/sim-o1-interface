.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. SPDX-License-Identifier: CC-BY-4.0
.. Copyright (C) 2019 highstreet technologies GmbH


sim/o1-interface Overview
==========================

The o1-interface simulator is based on the Network Topology Simulator (NTS). NTS is a framework that allows simulating devices that expose a management interface through a NETCONF/YANG interface. The NTS is loaded with the YANG files associated with the O-RAN O1 interface specifications.

The NETCONF/YANG management interface is simulated, and the O1 YANG models are loaded by the framework to be exposed. Random data is generated based on the specific models, such that each simulated device presents different data on its management interface.

The NTS Manager can be used to specify the simulation details and to manage the simulation environment at runtime.

The NTS framework is based on several open-source projects:
* [Netopeer2](https://github.com/CESNET/Netopeer2) 
* [libnetconf2](https://github.com/CESNET/libnetconf2) 
* [libyang](https://github.com/CESNET/libyang)
* [sysrepo](https://github.com/sysrepo/sysrepo) - all of these are used for the implementation of the NETCONF Server, both in the NTS Manager and in each simulated device
* [cJSON](https://github.com/DaveGamble/cJSON) - used to create the JSON payloads for talking with the simulation framework
* [pyang](https://github.com/mbj4668/pyang) - used to create random data from the YANG models that are exposed

Each simulated device is represented as a docker container, where the NETCONF Server is running. The creation and deletion of docker containers associated with simulated devices is handled by the NTS Manager. The NTS Manager is also running as a docker container and exposes a NETCONF/YANG interface to control the simulation.