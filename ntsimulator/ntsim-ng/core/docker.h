/*************************************************************************
*
* Copyright 2020 highstreet technologies GmbH and others
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
***************************************************************************/

#pragma once

#include <stdbool.h>
#include "core/app/manager.h"

typedef struct {
    float cpu;
    float mem;
} docker_usage_t;

//init current container. used *only* with --docker-init
bool docker_container_init(void);

//docker container functions for manager
int docker_device_init(void);
int docker_device_start(const manager_network_function_type *function_type, manager_network_function_instance_t *instance);
int docker_device_stop(manager_network_function_instance_t *instance);

docker_usage_t docker_usage_get(const manager_network_function_type *function_type, int function_type_count);
