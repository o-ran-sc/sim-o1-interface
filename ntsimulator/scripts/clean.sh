#/bin/bash
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

echo "Cleaning up..."

mapfile -t NTS_containers < <( docker ps -a --filter "label=NTS" --format "{{.ID}}" )

CONTAINERS=""

if [ ${#NTS_containers[@]} -gt 0 ]
then

	for container in "${NTS_containers[@]}"
	do
		CONTAINERS="$CONTAINERS $container"
	done
	echo "Cleaning up ontainers: $CONTAINERS"
	docker kill $CONTAINERS > /dev/null 2>&1
	docker rm $CONTAINERS > /dev/null 2>&1
fi

echo "Cleaning NTS Manager container"
docker kill NTS_Manager > /dev/null 2>&1
docker rm NTS_Manager > /dev/null 2>&1

echo "All cleaned up!"
