#!/bin/bash

# /*************************************************************************
# *
# * Copyright 2020 highstreet technologies GmbH and others
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *     http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# ***************************************************************************/

files=(
    "core/container.c"
    "core/context.c"
    "core/docker.c"
    "core/framework.c"
    "core/test.c"
    "core/session.c"
    "core/nc_config.c"
    "core/app/supervisor.c"
    "core/app/app_common.c"
    "core/app/manager.c"
    "core/app/manager_context.c"
    "core/app/manager_operations.c"
    "core/app/manager_actions.c"
    "core/app/manager_sysrepo.c"
    "core/app/network_function.c"
    "core/app/nf_oran_du.c"
    "core/app/blank.c"
    "core/datastore/schema.c"
    "core/datastore/operations.c"
    "core/datastore/populate.c"
    "core/datastore/populate_aux.c"
    "core/datastore/populate_late_resolve.c"
    "core/datastore/populate_recursive.c"
    "core/datastore/populate_validation.c"
    "core/faults/faults.c"
    "core/faults/faults_counters.c"
    "core/faults/faults_processing.c"
    "core/faults/faults_logic.c"
    "core/faults/faults_ves.c"
    "utils/debug_utils.c"
    "utils/log_utils.c"
    "utils/rand_utils.c"
    "utils/type_utils.c"
    "utils/sys_utils.c"
    "utils/http_client.c"
    "utils/nts_utils.c"
    "utils/nc_client.c"
    "utils/network_emulation.c"
    "features/ves_pnf_registration/ves_pnf_registration.c"
    "features/ves_heartbeat/ves_heartbeat.c"
    "features/ves_file_ready/ves_file_ready.c"
    "features/manual_notification/manual_notification.c"
    "features/netconf_call_home/netconf_call_home.c"
    "features/web_cut_through/web_cut_through.c"
    "main.c"
)

libs=(
    "argp"
    "m"
    "yang"
    "sysrepo"
    "netconf2"
    "cjson"
    "curl"
    "pthread"
)

sources=""
for i in ${files[@]}
do
    sources="$sources source/$i"
done

libraries=""
for i in ${libs[@]}
do
    libraries="$libraries -l$i"
done

output="ntsim-ng"

build="gcc -Wall -pedantic -Isource $sources $libraries -o$output"
if [[ -n "${BUILD_WITH_DEBUG}" ]]; then
    build="gcc -g -Wall -pedantic -Isource $sources $libraries -o$output"
fi

echo "Building with command: $build"
$build
if [ "$?" -ne "0" ]; then
  echo "Build failed"
  exit 1
fi
