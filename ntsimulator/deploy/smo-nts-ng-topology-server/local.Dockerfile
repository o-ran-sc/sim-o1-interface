#
# Copyright 2020 highstreet technologies GmbH and others
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

################
#### DEVICE ####
################

FROM o-ran-sc/nts-ng-base:latest
LABEL maintainer="alexandru.stancu@highstreet-technologies.com / adrian.lita@highstreet-technologies.com"

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Opendaylight download
    wget \
    # Java 11
    default-jdk \
    python3 \
    && rm -rf /var/lib/apt/lists/* && \
    mkdir /opt/opendaylight

WORKDIR /opt

ARG ODL_VERSION=15.1.0

RUN wget --no-check-certificate https://nexus.opendaylight.org/content/repositories/opendaylight.release/org/opendaylight/integration/opendaylight/$ODL_VERSION/opendaylight-$ODL_VERSION.tar.gz

RUN tar -xvzf opendaylight-${ODL_VERSION}.tar.gz -C opendaylight --strip-components 1 && \
    rm -rf opendaylight-${ODL_VERSION}.tar.gz

# ntsim-ng configuration and deployment
COPY ./yang /opt/dev/deploy/yang
COPY ./data /opt/dev/deploy/data
COPY ./config.json /opt/dev/ntsim-ng/config/config.json
COPY ./org.apache.karaf.features.cfg /opt/opendaylight/etc/org.apache.karaf.features.cfg

# ntsim-ng init docker
RUN /opt/dev/ntsim-ng/ntsim-ng --container-init -w /opt/dev/ntsim-ng

COPY ./callhomeConfig.py /opt/dev/workspace/callhomeConfig.py

# add exposed ports
EXPOSE 8181

ENV NTS_FUNCTION_TYPE=NTS_FUNCTION_TYPE_TOPOLOGY_SERVER
ENV NTS_NF_STANDALONE_START_FEATURES="datastore-populate netconf-call-home"
ENV SDN_CONTROLLER_IP="127.0.0.1"
ENV SDN_CONTROLLER_PROTOCOL="http"
ENV SDN_CONTROLLER_PORT="8181"
ENV SDN_CONTROLLER_CALLHOME_IP="127.0.0.1"
ENV SDN_CONTROLLER_CALLHOME_PORT="6666"
ENV SDN_CONTROLLER_USERNAME="admin"
ENV SDN_CONTROLLER_PASSWORD="admin"
ENV ODL_HOME=/opt/opendaylight

# run
WORKDIR /opt/dev/workspace
CMD ["/opt/dev/ntsim-ng/ntsim-ng", "-w/opt/dev/ntsim-ng", "--supervisor"]
