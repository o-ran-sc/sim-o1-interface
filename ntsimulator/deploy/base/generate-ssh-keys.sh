#!/bin/bash

# Copyright 2021 highstreet technologies GmbH and others
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
#

cd /home/netconf/.ssh

# generate a new private key
openssl genrsa -out melacon.server.key 2048 2>/dev/null

# create a new Certificate Signing Request
openssl req -new -sha256 -key melacon.server.key -subj "/C=US/ST=CA/O=MeLaCon, Inc./CN=melacon.com" -out melacon.server.csr 2>/dev/null

# sign the certificate with our own CA
openssl x509 -req -in melacon.server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out melacon.server.crt -days 500 -sha256 2>/dev/null
rm melacon.server.csr

# public key in SSH format
ssh-keygen -y -f melacon.server.key > melacon.server.key.pub 2>/dev/null

# public key in PEM format
openssl rsa -in melacon.server.key -pubout > melacon.server.key.pub.pem 2>/dev/null

exit 0