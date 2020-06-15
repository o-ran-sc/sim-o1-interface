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
N/A

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

* **o-ran-sc/ntsim-o-ran-sc-o-ran-ru** - this image contains a simulated device which exposes a management interface via NETCONF/YANG, implementing the O-RAN-SC O-RU Management interface defined by the OAM project;

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



