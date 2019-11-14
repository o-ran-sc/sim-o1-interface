.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. SPDX-License-Identifier: CC-BY-4.0
.. Copyright (C) 2019 highstreet technologies GmbH and others


Release Notes
=============


This document provides the release notes for Amber of sim/o1-interface.

.. contents::
   :depth: 3
   :local:


Version history
---------------

+--------------------+--------------------+--------------------+--------------------+
| **Date**           | **Ver.**           | **Author**         | **Comment**        |
|                    |                    |                    |                    |
+--------------------+--------------------+--------------------+--------------------+
| 2019-11-13         | 0.0.1              |  Alex Stancu       | First draft        |
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
N/A

Bug Corrections
^^^^^^^^^^^^^^^

N/A

Deliverables
^^^^^^^^^^^^

Software Deliverables
+++++++++++++++++++++

Two docker containers are the resulting artefacts of the sim-o1-project:

* **sim-o1-interface-manager** - this image contains the NTS Manager, which handles the simulation environment;

* **sim-o1-interface-device** - this image contains a simulated device which exposes a management interface via NETCONF/YANG, implementing the O1 interface specifications.


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



