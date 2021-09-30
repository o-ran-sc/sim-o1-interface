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

#################
#### BUILDER ####
#################

FROM ubuntu:20.04 as builder
LABEL maintainer="alexandru.stancu@highstreet-technologies.com / adrian.lita@highstreet-technologies.com"

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y \
    # basic tools
    tzdata build-essential git cmake pkg-config \
    # libyang dependencies
    libpcre3-dev \
    # libssh dependencies
    zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# add netconf user and configure access
RUN \
    adduser --system netconf && \
    echo "netconf:netconf!" | chpasswd

# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev

# get required build libs from git
RUN \
    git config --global advice.detachedHead false && \
    git clone --single-branch --branch v1.7.14 https://github.com/DaveGamble/cJSON.git && \
    git clone --single-branch --branch v1.0.240 https://github.com/CESNET/libyang.git && \
    git clone --single-branch --branch v1.4.140 https://github.com/sysrepo/sysrepo.git && \
    git clone --single-branch --branch libssh-0.9.2 https://git.libssh.org/projects/libssh.git && \
    git clone --single-branch --branch v1.1.46 https://github.com/CESNET/libnetconf2.git && \
    git clone --single-branch --branch v1.1.76 https://github.com/CESNET/netopeer2.git && \
    git clone --single-branch --branch curl-7_72_0 https://github.com/curl/curl.git

# build and install cJSON
RUN \
    cd cJSON && \
    mkdir build && cd build && \
    cmake .. -DENABLE_CJSON_UTILS=On -DENABLE_CJSON_TEST=Off && \
    make -j4 && \
    make install && \
    ldconfig

# build and install libyang
RUN \
    cd libyang && \
    mkdir build && cd build  && \
    cmake -DCMAKE_BUILD_TYPE:String="Release" -DGEN_LANGUAGE_BINDINGS=ON -DGEN_CPP_BINDINGS=ON -DGEN_PYTHON_BINDINGS=OFF -DENABLE_BUILD_TESTS=OFF .. && \
    make -j4  && \
    make install && \
    ldconfig

# build and install sysrepo
COPY ./deploy/base/common.h.in /opt/dev/sysrepo/src/common.h.in
RUN \
    cd sysrepo && \
    mkdir build && cd build  && \
    cmake -DCMAKE_BUILD_TYPE:String="Release" -DGEN_LANGUAGE_BINDINGS=ON -DGEN_CPP_BINDINGS=ON -DGEN_PYTHON_BINDINGS=OFF -DENABLE_TESTS=OFF -DREPOSITORY_LOC:PATH=/etc/sysrepo -DREQUEST_TIMEOUT=60 -DOPER_DATA_PROVIDE_TIMEOUT=60 .. && \
    make -j4 && \
    make install && \
    ldconfig

# build and install libssh-dev
RUN \
    cd libssh && \
    mkdir build && cd build  && \
    cmake -DWITH_EXAMPLES=OFF ..  && \
    make -j4 && \
    make install && \
    ldconfig

# build and install libnetconf2
RUN \
    cd libnetconf2 && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
    make -j4 && \
    make install && \
    ldconfig

# build and install netopeer2
RUN \
    cd netopeer2 && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE:String="Release" -DGENERATE_HOSTKEY=OFF -DMERGE_LISTEN_CONFIG=OFF .. && \
    make -j4 && \
    make install

# build and install cURL
RUN \
    cd curl && \
    mkdir build && cd build && \
    cmake -DBUILD_TESTING=OFF .. && \
    make -j4 && \
    make install && \
    ldconfig

# regxstring copy, build and install
RUN mkdir /opt/dev/regxstring
COPY ./regxstring /opt/dev/regxstring
COPY ./deploy/base/build_regxstring.sh /opt/dev/regxstring/build_regxstring.sh
RUN \
    cd /opt/dev/regxstring && \
    ./build_regxstring.sh && \
    cp regxstring /usr/bin && \
    cd ..

# ntsim-ng copy and build
ARG BUILD_WITH_DEBUG
ENV BUILD_WITH_DEBUG=${BUILD_WITH_DEBUG}

RUN \
    mkdir /opt/dev/ntsim-ng && \
    mkdir /opt/dev/ntsim-ng/config && \
    mkdir /opt/dev/ntsim-ng/source
COPY ./ntsim-ng /opt/dev/ntsim-ng/source
COPY ./deploy/base/build_ntsim-ng.sh /opt/dev/ntsim-ng/build_ntsim-ng.sh
RUN \
    cd /opt/dev/ntsim-ng && \
    sed -i '/argp/d' build_ntsim-ng.sh && \
    ./build_ntsim-ng.sh && \
    rm -rf source && \
    rm -f build_ntsim-ng.sh

# copy SSH related scripts and keys
COPY ./deploy/base/ca.key /home/netconf/.ssh/ca.key
COPY ./deploy/base/ca.pem /home/netconf/.ssh/ca.pem
COPY ./deploy/base/client.crt /home/netconf/.ssh/client.crt
COPY ./deploy/base/client.key /home/netconf/.ssh/client.key
COPY ./deploy/base/generate-ssh-keys.sh /home/netconf/.ssh/generate-ssh-keys.sh

#############################
#### Lightweight Base ####
#############################


FROM ubuntu:20.04
LABEL maintainer="alexandru.stancu@highstreet-technologies.com / adrian.lita@highstreet-technologies.com"

RUN apt-get update && apt-get install -y --no-install-recommends \
    psmisc \
    unzip \
    openssl \
    openssh-client \
    vsftpd \
    openssh-server \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*
    
ARG BUILD_WITH_DEBUG
ENV BUILD_WITH_DEBUG=${BUILD_WITH_DEBUG}
RUN if [ -n "${BUILD_WITH_DEBUG}" ]; then DEBIAN_FRONTEND="noninteractive" apt-get install -y gdb valgrind nano mc && unset BUILD_WITH_DEBUG; fi

# add netconf user and configure access
RUN \
    adduser netconf && \
    echo "netconf:netconf!" | chpasswd && \
    mkdir -p /home/netconf/.ssh

COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/share /usr/local/share

COPY --from=builder /etc/sysrepo /etc/sysrepo
RUN ldconfig

# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev

# copy common NTS yang models
RUN mkdir /opt/dev/deploy
COPY ./deploy/base/yang /opt/dev/deploy/yang

# copy ntsim-ng and dependencies
COPY --from=builder /usr/bin/regxstring /usr/bin/regxstring
COPY --from=builder /opt/dev/ntsim-ng /opt/dev/ntsim-ng

# copy SSH related scripts and keys
COPY --from=builder /home/netconf/.ssh /home/netconf/.ssh

### FTP and SFTP configuration
RUN \
    mkdir /ftp && \
    chown -R netconf:netconf /ftp && \
    mkdir /var/run/vsftpd && \
    mkdir /var/run/vsftpd/empty  && \
    mkdir /run/sshd && \
    echo "Match User netconf\n    ChrootDirectory /\n    X11Forwarding no\n    AllowTcpForwarding no\n    ForceCommand internal-sftp -d /ftp" >> /etc/ssh/sshd_config

COPY ./deploy/base/vsftpd.conf /etc/vsftpd.conf
COPY ./deploy/base/vsftpd.userlist /etc/vsftpd.userlist
COPY ./deploy/base/pm_files /ftp

WORKDIR /opt/dev/workspace

ENV SSH_CONNECTIONS=1
ENV TLS_CONNECTIONS=0
ENV IPv6_ENABLED=false

ARG NTS_BUILD_VERSION
ENV NTS_BUILD_VERSION=${NTS_BUILD_VERSION}

ARG NTS_BUILD_DATE
ENV NTS_BUILD_DATE=${NTS_BUILD_DATE}
