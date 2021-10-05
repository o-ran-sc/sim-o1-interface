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

#define _GNU_SOURCE

#include "manager.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include <stdio.h>
#include <assert.h>

#include "core/framework.h"
#include "core/session.h"
#include "core/xpath.h"

static int manager_context_sync = 0;

int manager_sr_get_context_sync(void) {
    return manager_context_sync;
}

int manager_sr_update_context(manager_context_t *ctx) {
    assert(ctx);
    assert_session();

    char xpath[512];
    char int_to_str[30];

    //setup sdn-controller defaults
    sprintf(xpath, NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH"[function-type='%s']/started-instances", ctx->function_type);
    sprintf(int_to_str, "%d", ctx->started_instances);
    int rc = sr_set_item_str(session_running, xpath, (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    sprintf(xpath, NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH"[function-type='%s']/mounted-instances", ctx->function_type);
    sprintf(int_to_str, "%d", ctx->mounted_instances);
    rc = sr_set_item_str(session_running, xpath, (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    manager_context_sync = 1;

    //apply all changes
    rc = sr_apply_changes(session_running, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed\n");
        return NTS_ERR_FAILED;
    }

    manager_context_sync = 0;

    return NTS_ERR_OK;
}

int manager_sr_on_last_operation_status(const char *status, const char *errmsg) {
    assert(status);

    int rc = sr_set_item_str(session_operational, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"/last-operation-status", status, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    //apply all changes
    rc = sr_apply_changes(session_operational, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed\n");
        return NTS_ERR_FAILED;
    }

    //push notification
    const struct lys_module *manager_module = ly_ctx_get_module(session_context, NTS_MANAGER_MODULE, 0, 0);
    if(manager_module == 0) {
        log_error("ly_ctx_get_module failed\n");
        return NTS_ERR_FAILED;
    }

    struct lyd_node *notif = lyd_new(0, manager_module, "operation-status-changed");
    if(notif == 0) {
        log_error("lyd_new failed\n");
        return NTS_ERR_FAILED;
    }

    lyd_new_leaf(notif, manager_module, "operation-status", status);
    if(errmsg && errmsg[0]) {
        lyd_new_leaf(notif, manager_module, "error-message", errmsg);
    }

    rc = sr_event_notif_send_tree(session_running, notif);
    if(rc != SR_ERR_OK) {
        log_error("sr_event_notif_send_tree failed\n");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

int manager_sr_notif_send_instance_changed(const char *status, const char *function_type, const char *name, const manager_network_function_instance_t* instance) {
    assert(status);
    assert(function_type);
    assert(name);

    //push notification
    const struct lys_module *manager_module = ly_ctx_get_module(session_context, NTS_MANAGER_MODULE, 0, 0);
    if(manager_module == 0) {
        log_error("ly_ctx_get_module failed\n");
        return NTS_ERR_FAILED;
    }

    struct lyd_node *notif = lyd_new(0, manager_module, "instance-changed");
    if(notif == 0) {
        log_error("lyd_new failed\n");
        return NTS_ERR_FAILED;
    }

    if(lyd_new_leaf(notif, manager_module, "change-status", status) == 0) {
        log_error("lyd_new_leaf error\n");
        return NTS_ERR_FAILED;
    }

    if(lyd_new_leaf(notif, manager_module, "function-type", function_type) == 0) {
        log_error("lyd_new_leaf error\n");
        return NTS_ERR_FAILED;
    }

    if(lyd_new_leaf(notif, manager_module, "name", name) == 0) {
        log_error("lyd_new_leaf error\n");
        return NTS_ERR_FAILED;
    }

    if(instance) {
        if(manager_sr_populate_networking(notif, instance) != NTS_ERR_OK) {
            log_error("manager_sr_populate_networking error\n");
            return NTS_ERR_FAILED;
        }
    }

    int rc = sr_event_notif_send_tree(session_running, notif);
    if(rc != SR_ERR_OK) {
        log_error("sr_event_notif_send_tree failed\n");
        return NTS_ERR_FAILED;
    }
    
    return NTS_ERR_OK;
}


int manager_sr_update_static_stats(void) {
    assert_session();
    char int_to_str[30];
    int rc;

    sprintf(int_to_str, "%d", framework_environment.host.ssh_base_port);
    rc = sr_set_item_str(session_operational, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"/ports/netconf-ssh-port", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    sprintf(int_to_str, "%d", framework_environment.host.tls_base_port);
    rc = sr_set_item_str(session_operational, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"/ports/netconf-tls-port", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    sprintf(int_to_str, "%d", framework_environment.host.ftp_base_port);
    rc = sr_set_item_str(session_operational, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"/ports/transport-ftp-port", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    sprintf(int_to_str, "%d", framework_environment.host.sftp_base_port);
    rc = sr_set_item_str(session_operational, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"/ports/transport-sftp-port", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    sprintf(int_to_str, "%d", framework_environment.settings.ssh_connections);
    rc = sr_set_item_str(session_operational, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"/ssh-connections", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    sprintf(int_to_str, "%d", framework_environment.settings.tls_connections);
    rc = sr_set_item_str(session_operational, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"/tls-connections", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    //apply all changes
    rc = sr_apply_changes(session_operational, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

int manager_sr_stats_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data) {
    char value[128];

    *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), NTS_MANAGER_SIMULATION_SCHEMA_XPATH, 0, 0, 0);
    if(*parent == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    int docker_instances_count = 0;
    for(int i = 0; i < docker_context_count; i++) {
        docker_instances_count += manager_context[i].started_instances;
    }

    const char **instances_id = malloc(sizeof(char *) * docker_instances_count);
    if(instances_id == 0) {
        log_error("malloc failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    int k = 0;
    for(int i = 0; i < docker_context_count; i++) {
        for(int j = 0; j < manager_context[i].started_instances; j++) {
            instances_id[k] = manager_context[i].instance[j].container.id;
            k++;
        }
    }

    docker_usage_t usage;
    int rc = docker_usage_get(instances_id, docker_instances_count, &usage);
    free(instances_id);
    if(rc != NTS_ERR_OK) {
        log_error("docker_usage_get failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%.2f", usage.cpu);
    if(lyd_new_path(*parent, NULL, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"/cpu-usage", value, 0, 0) == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%.0f", usage.mem);
    if(lyd_new_path(*parent, NULL, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"/mem-usage", value, 0, 0) == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    return SR_ERR_OK;
}

int manager_sr_populate_networking(struct lyd_node *parent, const manager_network_function_instance_t* instance) {
    assert(instance);
    assert(parent);


    struct lyd_node *networking = lyd_new(parent, parent->schema->module, "networking");
    if(networking == 0) {
        log_error("lyd_new failed\n");
        return NTS_ERR_FAILED;
    }

    if(lyd_new_leaf(networking, parent->schema->module, "docker-ip", instance->container.docker_ip) == 0) {
        log_error("lyd_new_leaf failed\n");
        return NTS_ERR_FAILED;
    }

    if(lyd_new_leaf(networking, parent->schema->module, "host-ip", instance->container.host_ip) == 0) {
        log_error("lyd_new_leaf failed\n");
        return NTS_ERR_FAILED;
    }

    //netconf ssh ports
    for(int k = 0; k < framework_environment.settings.ssh_connections; k++) {
        char value[128];
        
        struct lyd_node *ports = lyd_new(networking, parent->schema->module, "docker-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", instance->container.docker_netconf_ssh_port + k);
        if(lyd_new_leaf(ports, ports->schema->module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, ports->schema->module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_NETCONF_SSH") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }


        ports = lyd_new(networking, parent->schema->module, "host-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", instance->container.host_netconf_ssh_port + k);
        if(lyd_new_leaf(ports, ports->schema->module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, ports->schema->module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_NETCONF_SSH") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }
    }

    //netconf tls ports
    for(int k = 0; k < framework_environment.settings.tls_connections; k++) {
        char value[128];
        
        struct lyd_node *ports = lyd_new(networking, parent->schema->module, "docker-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", instance->container.docker_netconf_tls_port + k);
        if(lyd_new_leaf(ports, ports->schema->module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, ports->schema->module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_NETCONF_TLS") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }


        ports = lyd_new(networking, parent->schema->module, "host-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", instance->container.host_netconf_tls_port + k);
        if(lyd_new_leaf(ports, ports->schema->module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, ports->schema->module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_NETCONF_TLS") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }
    }

    //ftp ports
    for(int k = 0; k < framework_environment.settings.ftp_connections; k++) {
        char value[128];
        
        struct lyd_node *ports = lyd_new(networking, parent->schema->module, "docker-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", instance->container.docker_ftp_port + k);
        if(lyd_new_leaf(ports, ports->schema->module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, ports->schema->module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_FTP") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }


        ports = lyd_new(networking, parent->schema->module, "host-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", instance->container.host_ftp_port + k);
        if(lyd_new_leaf(ports, ports->schema->module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, ports->schema->module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_FTP") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }
    }

    //sftp ports
    for(int k = 0; k < framework_environment.settings.sftp_connections; k++) {
        char value[128];
        
        struct lyd_node *ports = lyd_new(networking, parent->schema->module, "docker-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", instance->container.docker_sftp_port + k);
        if(lyd_new_leaf(ports, ports->schema->module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, ports->schema->module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_SFTP") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }


        ports = lyd_new(networking, parent->schema->module, "host-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", instance->container.host_sftp_port + k);
        if(lyd_new_leaf(ports, ports->schema->module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, ports->schema->module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_SFTP") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }
    }

    return NTS_ERR_OK;
}
