.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. SPDX-License-Identifier: CC-BY-4.0
.. Copyright (C) 2019 highstreet technologies GmbH and others


Release Notes
=============


This document provides the release notes for the sim/o1-interface project.

.. contents::
   :depth: 3
   :local:


Version history
---------------

+--------------------+--------------------+--------------------+--------------------+
| **Date**           | **Ver.**           | **Author**         | **Comment**        |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
| 2020-12-02         | 1.0.3              |  Alex Stancu       | Cherry release     |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
| 2020-11-11         | 1.0.0              |  Alex Stancu       | Cherry release     |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
| 2020-06-08         | 0.6.1              |  Alex Stancu       | Bronze release     |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
| 2019-11-13         | 0.0.1              |  Alex Stancu       | First draft - Amber|
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+


Summary
-------

The O1 interface simulator is a framework that provides simulated devices with a management plane exposed through a NETCONF/YANG interface, using the O-RAN O1 interface YANG modules.


Release Data
------------
version 1.0.3

[fixed] fixed issues where ODL could not parse the correct versions for yang files


version 1.0.2

[fixed] bug that occured when trying to start a wrong instance (bad docker-repository or docker-tag)
[fixed] when populating the fault-delay-list, if the sum of all the faults was 0, the network funciton kept on generating faults and crashed


version 1.0.1

[feature-add] added web-cut-through feature
[fixed] mount-point-addressing-method was mistakenly changing after starting


version 1.0.0
Initial release.

Feature Additions
^^^^^^^^^^^^^^^^^
* IPv6 for the simulated devices
* NETCONF CallHome for the simulated devices
* Manual notification generation
* Custom naming of the simulated devices

Bug Corrections
^^^^^^^^^^^^^^^
* `ssh-connections` and `tls-connections` leafs are now removed from the simulator-config
* `fault-notification-delay-period` has now the attribute `ordered-by user`

Deliverables
^^^^^^^^^^^^

Software Deliverables
+++++++++++++++++++++

The following docker containers are the resulting artefacts of the sim-o1-project:

* **o-ran-sc/ntsim-manager** - this image contains the NTS Manager, which handles the simulation environment;

* **o-ran-sc/ntsim-o-ran-ru-fh** - this image contains a simulated device which exposes a management interface via NETCONF/YANG, implementing the O1 FH interface specifications;

* **o-ran-sc/ntsim-x-ran** - this image contains a simulated device which exposes a management interface via NETCONF/YANG, implementing the X-RAN Management interface.


Documentation Deliverables
++++++++++++++++++++++++++


Known Limitations, Issues and Workarounds
-----------------------------------------
N/A

System Limitations
^^^^^^^^^^^^^^^^^^
N/A

Known Issues
^^^^^^^^^^^^
N/A

Workarounds
^^^^^^^^^^^
N/A


References
----------
`NTS Project <https://github.com/Melacon/ntsim>`_



