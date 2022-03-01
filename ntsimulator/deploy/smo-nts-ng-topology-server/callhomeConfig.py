#!/usr/bin/python3

################################################################################
# Copyright 2022 highstreet technologies GmbH
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################
# Script for adding this running NTS Topology Server to the allowed-devices list of the
# local OpenDaylight instance, for enabling NETCONF CallHome

import http.client
import time
import base64
import os

TIMEOUT=1000
INTERVAL=30

# default ODL credentials
username = os.getenv("SDN_CONTROLLER_USERNAME")
password = os.getenv("SDN_CONTROLLER_PASSWORD")
cred_string = username + ":" + password

certreadyCmd="GET"
certreadyUrl="/rests/data/odl-netconf-callhome-server:netconf-callhome-server"
timePassed=0

headers = {'Authorization':'Basic %s' % base64.b64encode(cred_string.encode()).decode(),
           'Accept':"application/json",
           'Content-type':"application/yang-data+json"}

# ODL NETCONF CallHome allowed devices URL
callhomeConfigUrl = "/rests/data/odl-netconf-callhome-server:netconf-callhome-server/allowed-devices/device=o-ran-sc-topology-service"
# ODL NETCONF CallHome allowed devices payload; private key will be replaced with the one generated on the device at runtime
callhomeConfigPayload = "{\"odl-netconf-callhome-server:device\":[{\"odl-netconf-callhome-server:unique-id\":\"o-ran-sc-topology-service\", \"odl-netconf-callhome-server:ssh-client-params\": {\"odl-netconf-callhome-server:host-key\":\"@priv_key@\",\"odl-netconf-callhome-server:credentials\":{\"odl-netconf-callhome-server:username\":\"netconf\",\"odl-netconf-callhome-server:passwords\":[\"netconf!\"]}}}]}"


# checking if RESTCONF and NETCONF CallHome feature are functional in ODL
def makeHealthcheckCall(headers, timePassed):
    connected = False
    # WAIT 10 minutes maximum and test every 30 seconds if HealthCheck API is returning 200
    while timePassed < TIMEOUT:
        try:
            conn = http.client.HTTPConnection("127.0.0.1",8181)
            req = conn.request(certreadyCmd, certreadyUrl,headers=headers)
            res = conn.getresponse()
            res.read()
            httpStatus = res.status
            if httpStatus == 200:
                print("Healthcheck Passed in %d seconds." %timePassed)
                connected = True
                break
            else:
                print("Sleep: %d seconds before testing if Healthcheck worked. Total wait time up now is: %d seconds. Timeout is: %d seconds. Problem code was: %d" %(INTERVAL, timePassed, TIMEOUT, httpStatus))
        except:
            print("Cannot execute REST call. Sleep: %d seconds before testing if Healthcheck worked. Total wait time up now is: %d seconds. Timeout is: %d seconds." %(INTERVAL, timePassed, TIMEOUT))
        timePassed = timeIncrement(timePassed)

    if timePassed > TIMEOUT:
        print("TIME OUT: Healthcheck not passed in  %d seconds... Could cause problems for testing activities..." %TIMEOUT)

    return connected


def timeIncrement(timePassed):
    time.sleep(INTERVAL)
    timePassed = timePassed + INTERVAL
    return timePassed

# add current NTS in allowed devices list for NETCONF CallHome
def configureNetconfCallhome():
    connected = makeHealthcheckCall(headers, timePassed)
    if connected:
        with open('/home/netconf/.ssh/melacon.server.key.pub', 'r') as file:
            data = file.read().rstrip()
            words = data.split()
            publicKey = words[1]
            payload = callhomeConfigPayload.replace("@priv_key@", publicKey)
            conn = http.client.HTTPConnection("localhost",8181)
            req = conn.request("PUT", callhomeConfigUrl,headers=headers, body=payload)
            res = conn.getresponse()
            res.read()
            httpStatus = res.status
            if httpStatus >= 200 and httpStatus < 300:
                print("Successfully enabled CallHome for device with key=%s" % publicKey)
            else:
                print("Could not allow device...")

print("Starting NETCONF Callhome configuration...")
configureNetconfCallhome()
