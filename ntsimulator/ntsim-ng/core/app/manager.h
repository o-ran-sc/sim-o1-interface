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
#include <stdint.h>
#include <libyang/libyang.h>

typedef struct {
    //meta-data
    char *docker_id;
    bool is_configured;
    bool is_mounted;

    //yang data
    char *name;
    char *mount_point_addressing_method;
    char *docker_ip;
    uint16_t docker_port;
    char *host_ip;
    uint16_t host_port;
} manager_network_function_instance_t;

typedef struct {
    //manager_docker data
    manager_network_function_instance_t *instance;
    bool data_changed;

    //meta-data, constant
    struct lys_ident *function_type;
    char *function_type_string;
    const char *docker_image_name;

    //yang data
    int started_instances;
    int mounted_instances;
    
    char *docker_instance_name;
    char *docker_version_tag;
    char *docker_repository;

    char *mount_point_addressing_method;
} manager_network_function_type;

//manager.c
int manager_run(void);

//manager_operations.c
void manager_operations_init(void);

int manager_start_instance(manager_network_function_type *function_type);
int manager_config_instance(manager_network_function_type *function_type, manager_network_function_instance_t *instance);
int manager_stop_instance(manager_network_function_type *function_type);
int manager_mount_instance(manager_network_function_type *function_type);
int manager_unmount_instance(manager_network_function_type *function_type);
