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
#include <semaphore.h>
#include <sysrepo.h>
#include <sysrepo/values.h>
#include "core/docker.h"


typedef struct {
    //meta-data
    const struct lys_ident *ft;
    const char *function_type;
    bool is_init;
    bool is_configured;
    bool is_mounted;

    docker_container_t container;
    char *mount_point_addressing_method;
} manager_network_function_instance_t;

typedef struct {
    //manager_docker data
    const struct lys_ident *ft;
    char *function_type;
    manager_network_function_instance_t *instance;
    docker_context_t *docker;

    //yang data
    int started_instances;
    int mounted_instances;

    char *mount_point_addressing_method;
    
    char *docker_instance_name;
    char *docker_version_tag;
    char *docker_repository;
} manager_context_t;

typedef enum {
    MANAGER_OPERATION_EDIT = 0,
    MANAGER_OPERATION_RPC = 1,
} manager_operation_type_t;

typedef struct manager_operation {
    manager_operation_type_t type;

    int ft_index;
    char *function_type;

    int started_instances;
    int mounted_instances;

    char *docker_instance_name;
    char *docker_repository;
    char *docker_version_tag;

    char *mount_point_addressing_method;

    //not used by EDIT, as datastore will be automatically updated
    struct {
        int *delay_period;
        int delay_period_count;
    } fault_generation;

    struct {
        int faults_enabled;
        int call_home;
    } netconf;

    struct {
        int faults_enabled;
        int pnf_registration;
        int heartbeat_period;
    } ves;

    char *errmsg;
    struct manager_operation *next;
} manager_operation_t;

extern manager_context_t *manager_context;
extern docker_context_t *docker_context;
extern int docker_context_count;

typedef enum {
    MANAGER_PROTOCOL_UNUSED = 0,
    MANAGER_PROTOCOL_UNAVAILABLE,

    MANAGER_PROTOCOL_NETCONF_SSH,
    MANAGER_PROTOCOL_NETCONF_TLS,
    MANAGER_PROTOCOL_FTP,
    MANAGER_PROTOCOL_SFTP,
    MANAGER_PROTOCOL_HTTP,
    MANAGER_PROTOCOL_HTTPS,
} manager_protocol_type_t;

extern manager_protocol_type_t manager_port[65536];

//manager.c
int manager_run(void);

//manager_context.c
int manager_context_init(void);
void manager_context_free(void);

//manager_operations.c
int manager_operations_init(void);
void manager_operations_loop(void);
void manager_operations_free(void);

manager_operation_t *manager_operations_new_oper(manager_operation_type_t type);
int manager_operations_free_oper(manager_operation_t *oper);

int manager_operations_begin(void);
int manager_operations_add(manager_operation_t *oper);
void manager_operations_finish_and_execute(void);
void manager_operations_finish_with_error(void);

int manager_operations_validate(manager_operation_t *oper);

//manager_actions.c
int manager_actions_start(manager_context_t *ctx);
int manager_actions_config_instance(manager_context_t *ctx, manager_network_function_instance_t *instance);
int manager_actions_stop(manager_context_t *ctx);
int manager_actions_mount(manager_context_t *ctx);
int manager_actions_unmount(manager_context_t *ctx);

//manager_sysrepo.c
int manager_sr_get_context_sync(void);
int manager_sr_update_context(manager_context_t *ctx);
int manager_sr_on_last_operation_status(const char *status, const char *errmsg);
int manager_sr_notif_send_instance_changed(const char *status, const char *function_type, const char *name, const manager_network_function_instance_t* instance);
int manager_sr_update_static_stats(void);
int manager_sr_stats_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);
int manager_sr_populate_networking(struct lyd_node *parent, const manager_network_function_instance_t* instance);
