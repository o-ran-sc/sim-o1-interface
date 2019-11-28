#!/bin/bash
################################################################################
#
# Copyright 2019 highstreet technologies GmbH and others
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
################################################################################

sleep 20

echo "Loading data into sysrepo..."

#SSH_PUB_KEY="$(cat /home/netconf/.ssh/id_dsa.pub| awk '{print $2}')"

#echo '<system xmlns="urn:ietf:params:xml:ns:yang:ietf-system"><authentication><user><name>netconf</name><authorized-key><name>ssh_key</name><algorithm>ssh-dss</algorithm>' >> load_auth_pubkey.xml
#echo '<key-data>'"$SSH_PUB_KEY"'</key-data></authorized-key></user></authentication></system>' >> load_auth_pubkey.xml

#sysrepocfg --merge=load_auth_pubkey.xml --format=xml ietf-system
#rm load_auth_pubkey.xml
#
#ssh-keyscan -p 830 localhost >> ~/.ssh/known_hosts

pyang -f sample-xml-skeleton --sample-xml-list-entries 3 *.yang

result=$(netopeer2-cli <<-END
	connect --host 127.0.0.1 --login netconf
	user-rpc --content=/opt/dev/yang/edit_config_operation.xml
	disconnect
END
)

while [[ "$result" != "OK" ]]
do
  pyang -f sample-xml-skeleton --sample-xml-list-entries 2 *.yang
  
  result=$(netopeer2-cli <<-END
	connect --host 127.0.0.1 --login netconf
	user-rpc --content=edit_config_operation.xml
	disconnect
END
)
done
echo "Finished loading data into sysrepo..."

exit 0