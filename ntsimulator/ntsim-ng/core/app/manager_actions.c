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
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "core/framework.h"
#include "core/docker.h"
#include "core/session.h"
#include "core/xpath.h"
#include "core/nc_config.h"
#include "utils/nc_client.h"
#include "utils/http_client.h"
#include "utils/nts_utils.h"

int manager_actions_start(manager_context_t *ctx) {
    assert(ctx);

    int started_instances = ctx->started_instances;
    char instance_name[512];
    sprintf(instance_name, "%s-%d", ctx->docker_instance_name, started_instances);

    uint16_t netconf_ssh_port = framework_environment.host.ssh_base_port;
    uint16_t netconf_tls_port = framework_environment.host.tls_base_port;
    uint16_t ftp_port = framework_environment.host.ftp_base_port;
    uint16_t sftp_port = framework_environment.host.sftp_base_port;

    if(framework_environment.settings.ssh_connections) {
        while((netconf_ssh_port) && (manager_port[netconf_ssh_port] != MANAGER_PROTOCOL_UNUSED)) {
            netconf_ssh_port++;
        }

        for(int i = 0; i < framework_environment.settings.ssh_connections; i++) {
            if(manager_port[i + netconf_ssh_port] != MANAGER_PROTOCOL_UNUSED) {
                log_error("no ports available for operation for ssh\n");
                manager_sr_notif_send_instance_changed("start FAILED - no ports available for ssh", ctx->function_type, instance_name, 0);
                return NTS_ERR_FAILED;
            }
        }

        for(int i = 0; i < framework_environment.settings.ssh_connections; i++) {
            manager_port[i + netconf_ssh_port] = MANAGER_PROTOCOL_NETCONF_SSH;
        }
    }

    if(framework_environment.settings.tls_connections) {
        while((netconf_tls_port) && (manager_port[netconf_tls_port] != MANAGER_PROTOCOL_UNUSED)) {
            netconf_tls_port++;
        }

        for(int i = 0; i < framework_environment.settings.tls_connections; i++) {
            if(manager_port[i + netconf_tls_port] != MANAGER_PROTOCOL_UNUSED) {
                log_error("no ports available for operation for tls\n");
                manager_sr_notif_send_instance_changed("start FAILED - no ports available for tls", ctx->function_type, instance_name, 0);

                for(int i = 0; i < framework_environment.settings.ssh_connections; i++) {
                    manager_port[i + netconf_ssh_port] = MANAGER_PROTOCOL_UNUSED;
                }
                return NTS_ERR_FAILED;
            }
        }

        for(int i = 0; i < framework_environment.settings.tls_connections; i++) {
            manager_port[i + netconf_tls_port] = MANAGER_PROTOCOL_NETCONF_TLS;
        }
    }

    if(framework_environment.settings.ftp_connections) {
        while((ftp_port) && (manager_port[ftp_port] != MANAGER_PROTOCOL_UNUSED)) {
            ftp_port++;
        }

        for(int i = 0; i < framework_environment.settings.ftp_connections; i++) {
            if(manager_port[i + ftp_port] != MANAGER_PROTOCOL_UNUSED) {
                log_error("no ports available for operation for ftp\n");
                manager_sr_notif_send_instance_changed("start FAILED - no ports available for ftp", ctx->function_type, instance_name, 0);

                for(int i = 0; i < framework_environment.settings.ssh_connections; i++) {
                    manager_port[i + netconf_ssh_port] = MANAGER_PROTOCOL_UNUSED;
                }

                for(int i = 0; i < framework_environment.settings.tls_connections; i++) {
                    manager_port[i + netconf_tls_port] = MANAGER_PROTOCOL_UNUSED;
                }
                return NTS_ERR_FAILED;
            }
        }

        for(int i = 0; i < framework_environment.settings.ftp_connections; i++) {
            manager_port[i + ftp_port] = MANAGER_PROTOCOL_FTP;
        }
    }

    if(framework_environment.settings.sftp_connections) {
        while((sftp_port) && (manager_port[sftp_port] != MANAGER_PROTOCOL_UNUSED)) {
            sftp_port++;
        }

        for(int i = 0; i < framework_environment.settings.sftp_connections; i++) {
            if(manager_port[i + sftp_port] != MANAGER_PROTOCOL_UNUSED) {
                log_error("no ports available for operation for sftp\n");
                manager_sr_notif_send_instance_changed("start FAILED - no ports available for sftp", ctx->function_type, instance_name, 0);

                for(int i = 0; i < framework_environment.settings.ssh_connections; i++) {
                    manager_port[i + netconf_ssh_port] = MANAGER_PROTOCOL_UNUSED;
                }

                for(int i = 0; i < framework_environment.settings.tls_connections; i++) {
                    manager_port[i + netconf_tls_port] = MANAGER_PROTOCOL_UNUSED;
                }

                for(int i = 0; i < framework_environment.settings.ftp_connections; i++) {
                    manager_port[i + ftp_port] = MANAGER_PROTOCOL_UNUSED;
                }
                return NTS_ERR_FAILED;
            }
        }

        for(int i = 0; i < framework_environment.settings.sftp_connections; i++) {
            manager_port[i + sftp_port] = MANAGER_PROTOCOL_SFTP;
        }
    }

    ctx->instance = (manager_network_function_instance_t *)realloc(ctx->instance, sizeof(manager_network_function_instance_t) * (started_instances + 1));
    if(ctx->instance == 0) {
        log_error("realloc failed\n");
        manager_sr_notif_send_instance_changed("start FAILED - realloc error", ctx->function_type, instance_name, 0);
        for(int i = 0; i < framework_environment.settings.ssh_connections; i++) {
            manager_port[i + netconf_ssh_port] = MANAGER_PROTOCOL_UNUSED;
        }

        for(int i = 0; i < framework_environment.settings.tls_connections; i++) {
            manager_port[i + netconf_tls_port] = MANAGER_PROTOCOL_UNUSED;
        }

        for(int i = 0; i < framework_environment.settings.ftp_connections; i++) {
            manager_port[i + ftp_port] = MANAGER_PROTOCOL_UNUSED;
        }

        for(int i = 0; i < framework_environment.settings.sftp_connections; i++) {
            manager_port[i + sftp_port] = MANAGER_PROTOCOL_UNUSED;
        }
        return NTS_ERR_FAILED;
    }

    manager_network_function_instance_t *instance = &ctx->instance[started_instances];
    instance->is_init = false;
    instance->is_configured = false;
    instance->is_mounted = false;
    instance->mount_point_addressing_method = strdup(ctx->mount_point_addressing_method);

    int rc = docker_start(instance_name, ctx->docker_version_tag, ctx->docker->image, ctx->docker_repository, netconf_ssh_port, netconf_tls_port, ftp_port, sftp_port, &instance->container);
    if(rc != NTS_ERR_OK) {
        log_error("docker_start failed\n");
        manager_sr_notif_send_instance_changed("start FAILED - Docker start error", ctx->function_type, instance_name, 0);
        for(int i = 0; i < framework_environment.settings.ssh_connections; i++) {
            manager_port[i + netconf_ssh_port] = MANAGER_PROTOCOL_UNUSED;
        }

        for(int i = 0; i < framework_environment.settings.tls_connections; i++) {
            manager_port[i + netconf_tls_port] = MANAGER_PROTOCOL_UNUSED;
        }

        for(int i = 0; i < framework_environment.settings.ftp_connections; i++) {
            manager_port[i + ftp_port] = MANAGER_PROTOCOL_UNUSED;
        }

        for(int i = 0; i < framework_environment.settings.sftp_connections; i++) {
            manager_port[i + sftp_port] = MANAGER_PROTOCOL_UNUSED;
        }
        return NTS_ERR_FAILED;
    }

    ctx->started_instances++;
    manager_sr_notif_send_instance_changed("start SUCCESS", ctx->function_type, instance_name, instance);
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" started (%s); ports host(docker): ", instance_name, instance->mount_point_addressing_method);
    if(framework_environment.settings.ssh_connections > 1) {
        log_add(1, "NETCONF SSH: %d-%d(%d-%d)", instance->container.host_netconf_ssh_port, (instance->container.host_netconf_ssh_port + framework_environment.settings.ssh_connections - 1), instance->container.docker_netconf_ssh_port, (instance->container.docker_netconf_ssh_port + framework_environment.settings.ssh_connections  - 1));
    }
    else if(framework_environment.settings.ssh_connections == 1) {
        log_add(1, "NETCONF SSH: %d(%d)", instance->container.host_netconf_ssh_port, instance->container.docker_netconf_ssh_port);
    }
    else {
        log_add(1, "NETCONF SSH: disabled");
    }

    if(framework_environment.settings.tls_connections > 1) {
        log_add(1, " | NETCONF TLS: %d-%d(%d-%d)", instance->container.host_netconf_tls_port, (instance->container.host_netconf_tls_port + framework_environment.settings.tls_connections - 1), instance->container.docker_netconf_tls_port, (instance->container.docker_netconf_tls_port + framework_environment.settings.tls_connections - 1));
    }
    else if(framework_environment.settings.tls_connections == 1) {
        log_add(1, " | NETCONF TLS: %d(%d)", instance->container.host_netconf_tls_port, instance->container.docker_netconf_tls_port);
    }
    else {
        log_add(1, " | NETCONF TLS: disabled");
    }

    if(framework_environment.settings.ftp_connections > 1) {
        log_add(1, " | FTP: %d-%d(%d-%d)", instance->container.host_ftp_port, (instance->container.host_ftp_port + framework_environment.settings.ftp_connections - 1), instance->container.docker_ftp_port, (instance->container.docker_ftp_port + framework_environment.settings.ftp_connections - 1));
    }
    else if(framework_environment.settings.ftp_connections == 1) {
        log_add(1, " | FTP: %d(%d)", instance->container.host_ftp_port, instance->container.docker_ftp_port);
    }
    else {
        log_add(1, " | FTP: disabled");
    }

    if(framework_environment.settings.sftp_connections > 1) {
        log_add(1, " | SFTP: %d-%d(%d-%d)", instance->container.host_sftp_port, (instance->container.host_sftp_port + framework_environment.settings.sftp_connections - 1), instance->container.docker_sftp_port, (instance->container.docker_sftp_port + framework_environment.settings.sftp_connections - 1));
    }
    else if(framework_environment.settings.sftp_connections == 1) {
        log_add(1, " | SFTP: %d(%d)", instance->container.host_sftp_port, instance->container.docker_sftp_port);
    }
    else {
        log_add(1, " | SFTP: disabled");
    }

    log_add(1, "\n");


    return NTS_ERR_OK;
}

int manager_actions_config_instance(manager_context_t *ctx, manager_network_function_instance_t *instance) {
    assert(ctx);
    assert(instance);

    //first wait for the nc server to be up and running
    int retries = 0;
    while(check_port_open(instance->container.docker_ip, CLIENT_CONFIG_TLS_PORT) == false) {
        usleep(50000);
        retries++;
        if(retries >= 200) {
            log_error("manager_actions_config_instance() could not connect to %s, as port is not open\n", instance->container.name);
            return NTS_ERR_FAILED;
        }
    }

    //populate sdn-controller and ves-endpoint
    struct lyd_node *local_tree = 0;
    int rc = lyd_utils_dup(session_running, NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH, NTS_NF_SDN_CONTROLLER_CONFIG_XPATH, &local_tree);
    if(rc != NTS_ERR_OK) {
        log_error("lyd_utils_dup failed\n");
        manager_sr_notif_send_instance_changed("config FAILED - libyang", ctx->function_type, instance->container.name, instance);
        return NTS_ERR_FAILED;
    }

    rc = lyd_utils_dup(session_running, NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH, NTS_NF_VES_ENDPOINT_CONFIG_XPATH, &local_tree);
    if(rc != NTS_ERR_OK) {
        log_error("lyd_utils_dup failed\n");
        manager_sr_notif_send_instance_changed("config FAILED - libyang", ctx->function_type, instance->container.name, instance);
        lyd_free_withsiblings(local_tree);
        return NTS_ERR_FAILED;
    }

    char xpath_s[512];
    sprintf(xpath_s, NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH"[function-type='%s']", ctx->function_type);
    rc = lyd_utils_dup(session_running, xpath_s, NTS_NF_NETWORK_FUNCTION_SCHEMA_XPATH, &local_tree);
    if(rc != NTS_ERR_OK) {
        log_error("lyd_utils_dup failed\n");
        manager_sr_notif_send_instance_changed("config FAILED - libyang", ctx->function_type, instance->container.name, instance);
        lyd_free_withsiblings(local_tree);
        return NTS_ERR_FAILED;
    }    

    nc_client_t *nc_client = nc_client_tls_connect(instance->container.docker_ip, CLIENT_CONFIG_TLS_PORT);
    // nc_client_t *nc_client = nc_client_ssh_connect(instance->container.docker_ip, instance->container.docker_port, "netconf", "netconf!");
    if(nc_client == 0) {
        log_error("nc_client_tls_connect\n");
        manager_sr_notif_send_instance_changed("config FAILED - netconf client connect", ctx->function_type, instance->container.name, instance);
        lyd_free_withsiblings(local_tree);
        return NTS_ERR_FAILED;
    }

    rc += nc_client_edit_batch(nc_client, local_tree, 5000);
    lyd_free_withsiblings(local_tree);
    if(rc != NTS_ERR_OK) {
        log_error("nc_client_edit_batch failed %d\n", rc);
        manager_sr_notif_send_instance_changed("config FAILED - netconf edit batch", ctx->function_type, instance->container.name, instance);
        nc_client_disconnect(nc_client);
        return NTS_ERR_FAILED;
    }
    
    if(instance->is_init == false) {
        //run datastore-populate rpc
        struct lyd_node *rpc_node = 0;
        struct lyd_node *rpcout = 0;
        rpc_node = lyd_new_path(0, session_context, NTS_NF_RPC_POPULATE_SCHEMA_XPATH, 0, 0, 0);
        if(rpc_node == 0) {
            log_error("failed to create rpc node\n");
            manager_sr_notif_send_instance_changed("config FAILED - populate RPC", ctx->function_type, instance->container.name, instance);
            nc_client_disconnect(nc_client);
            return NTS_ERR_FAILED;
        }

        rpcout = nc_client_send_rpc(nc_client, rpc_node, 10000);
        if(rpcout == 0) {
            log_error("datastore-populate rpc failed\n");
            manager_sr_notif_send_instance_changed("config FAILED - datastore populate RPC", ctx->function_type, instance->container.name, instance);
            nc_client_disconnect(nc_client);
            lyd_free_withsiblings(rpc_node);
            return NTS_ERR_FAILED;
        }
        else {
            lyd_free_withsiblings(rpcout);
        }
        lyd_free_withsiblings(rpc_node);

        //run feature-control rpc
        rpc_node = lyd_new_path(0, session_context, NTS_NF_RPC_FEATURE_CONTROL_SCHEMA_XPATH"/start-features", "ves-file-ready ves-heartbeat ves-pnf-registration manual-notification-generation netconf-call-home web-cut-through", 0, 0);
        if(rpc_node == 0) {
            log_error("failed to create rpc node\n");
            manager_sr_notif_send_instance_changed("config FAILED - feature-control RPC", ctx->function_type, instance->container.name, instance);
            nc_client_disconnect(nc_client);
            return NTS_ERR_FAILED;
        }

        rpcout = nc_client_send_rpc(nc_client, rpc_node, 10000);
        if(rpcout == 0) {
            log_error("feature-control rpc failed\n");
            manager_sr_notif_send_instance_changed("config FAILED - feature-control RPC", ctx->function_type, instance->container.name, instance);
            nc_client_disconnect(nc_client);
            lyd_free_withsiblings(rpc_node);
            return NTS_ERR_FAILED;
        }
        else {
            lyd_free_withsiblings(rpcout);
        }
        lyd_free_withsiblings(rpc_node);
    }

    instance->is_init = true;
    instance->is_configured = true;
    nc_client_disconnect(nc_client);
    manager_sr_notif_send_instance_changed("config SUCCESS", ctx->function_type, instance->container.name, instance);
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" configured via netconf\n", instance->container.name);

    return NTS_ERR_OK;
}

int manager_actions_stop(manager_context_t *ctx) {
    assert(ctx);

    manager_network_function_instance_t *instance = &ctx->instance[ctx->started_instances - 1];
    char instance_name[512];
    strcpy(instance_name, instance->container.name);

    if(instance->is_mounted) {
        if(manager_actions_unmount(ctx) != NTS_ERR_OK) {
            log_error("failed to unmount instance\n");
        }
    }

    int rc = docker_stop(&instance->container);
    if(rc != NTS_ERR_OK) {
        log_error("docker_device_stop failed\n");
        manager_sr_notif_send_instance_changed("stop FAILED - Docker error", ctx->function_type, instance_name, 0);
        return NTS_ERR_FAILED;
    }

    //free ports
    for(int i = 0; i < framework_environment.settings.ssh_connections; i++) {
        manager_port[i + ctx->instance[ctx->started_instances - 1].container.host_netconf_ssh_port] = MANAGER_PROTOCOL_UNUSED;
    }

    for(int i = 0; i < framework_environment.settings.tls_connections; i++) {
        manager_port[i + ctx->instance[ctx->started_instances - 1].container.host_netconf_tls_port] = MANAGER_PROTOCOL_UNUSED;
    }

    for(int i = 0; i < framework_environment.settings.ftp_connections; i++) {
        manager_port[i + ctx->instance[ctx->started_instances - 1].container.host_ftp_port] = MANAGER_PROTOCOL_UNUSED;
    }

    for(int i = 0; i < framework_environment.settings.sftp_connections; i++) {
        manager_port[i + ctx->instance[ctx->started_instances - 1].container.host_sftp_port] = MANAGER_PROTOCOL_UNUSED;
    }

    free(instance->mount_point_addressing_method);

    if(ctx->started_instances > 1) {
        ctx->instance = (manager_network_function_instance_t *)realloc(ctx->instance, sizeof(manager_network_function_instance_t) * ctx->started_instances);
        if(ctx->instance == 0) {
            log_error("realloc failed\n");
            manager_sr_notif_send_instance_changed("stop FAILED - realloc", ctx->function_type, instance_name, 0);
            return NTS_ERR_FAILED;
        }
    }
    else {
        free(ctx->instance);
        ctx->instance = 0;
    }
    ctx->started_instances--;
    manager_sr_notif_send_instance_changed("stop SUCCESS", ctx->function_type, instance_name, 0);
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" stopped\n", instance_name);
    

    return NTS_ERR_OK;
}

int manager_actions_mount(manager_context_t *ctx) {
    assert(ctx);

    manager_network_function_instance_t *instance = &ctx->instance[ctx->mounted_instances];

    if(instance->is_mounted == true) {
        manager_sr_notif_send_instance_changed("mount SUCCESS - already mounted", ctx->function_type, instance->container.name, instance);
        return NTS_ERR_OK;
    }

    controller_details_t *controller;
    controller = controller_details_get(0);
    if(controller == 0) {
        log_error("could not get controller details\n");
        manager_sr_notif_send_instance_changed("mount FAILED - no controller details", ctx->function_type, instance->container.name, instance);
        return NTS_ERR_FAILED;
    }

    for(int i = 0; i < (framework_environment.settings.ssh_connections + framework_environment.settings.tls_connections); i++) {
        char *protocol;
        char *protocol_data;

        char *ip = 0;
        uint16_t port = 0;
        if(instance->mount_point_addressing_method[0] == 'd') {
            ip = instance->container.docker_ip;
        }
        else {
            ip = instance->container.host_ip;
        }


        if(i < framework_environment.settings.ssh_connections) {
            protocol = "SSH";
            protocol_data = "\
            \"network-topology:netconf-node-topology:username\": \"netconf\",\
            \"network-topology:netconf-node-topology:password\": \"netconf!\"";

            if(instance->mount_point_addressing_method[0] == 'd') {
                port = instance->container.docker_netconf_ssh_port + i;
            }
            else {
                port = instance->container.host_netconf_ssh_port + i;
            }
        }
        else {
            protocol = "TLS";
            protocol_data = "\
            \"netconf-node-topology:key-based\" : {\
                \"netconf-node-topology:username\" : \"netconf\",\
                \"netconf-node-topology:key-id\" : \""KS_KEY_NAME"\"\
            }";

            if(instance->mount_point_addressing_method[0] == 'd') {
                port = instance->container.docker_netconf_tls_port + i - framework_environment.settings.ssh_connections;
            }
            else {
                port = instance->container.host_netconf_tls_port + i - framework_environment.settings.ssh_connections;
            }
        }

        char *json_template = "\
        {\
            \"network-topology:node\": [{\
                    \"network-topology:node-id\": \"%s\",\
                    \"network-topology:netconf-node-topology:host\": \"%s\",\
                    \"network-topology:netconf-node-topology:port\": \"%d\",\
                    \"network-topology:netconf-node-topology:tcp-only\": \"false\",\
                    \"network-topology:netconf-node-topology:protocol\": {\
                        \"network-topology:netconf-node-topology:name\": \"%s\"\
                    },\
                    %s,\
                    \"network-topology:netconf-node-topology:connection-timeout-millis\": \"20000\",\
                    \"network-topology:netconf-node-topology:default-request-timeout-millis\": \"60000\",\
                    \"network-topology:netconf-node-topology:max-connection-attempts\": \"3\"\
            }]\
        }";

        char node_id[128];
        char json[4096];
        if(framework_environment.settings.ssh_connections + framework_environment.settings.tls_connections > 1) {
            sprintf(node_id, "%s-%d", instance->container.name, port);
        }
        else {
            sprintf(node_id, "%s", instance->container.name);
        }
        sprintf(json, json_template, node_id, ip, port, protocol, protocol_data);

        char url[512];
        sprintf(url, "%s/rests/data/network-topology:network-topology/topology=topology-netconf/node=%s", controller->base_url, node_id);
        int rc = http_request(url, controller->username, controller->password, "PUT", json, 0, 0);
        if(rc != NTS_ERR_OK) {
            log_error("http_request failed\n");
            controller_details_free(controller);
            manager_sr_notif_send_instance_changed("mount FAILED - REST request", ctx->function_type, instance->container.name, instance);
            return NTS_ERR_FAILED;
        }
    }

    controller_details_free(controller);

    instance->is_mounted = true;
    ctx->mounted_instances++;
    manager_sr_notif_send_instance_changed("mount SUCCESS", ctx->function_type, instance->container.name, instance);
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" mounted\n", instance->container.name);

    return NTS_ERR_OK;
}

int manager_actions_unmount(manager_context_t *ctx) {
    assert(ctx);

    int ret = NTS_ERR_OK;

    manager_network_function_instance_t *instance = &ctx->instance[ctx->mounted_instances - 1];

    if(instance->is_mounted == false) {
        log_error("tried to unmount an unmounted instance\n");
        manager_sr_notif_send_instance_changed("unmount FAILED - already unmounted", ctx->function_type, instance->container.name, instance);
        return NTS_ERR_OK;
    }

    controller_details_t *controller;
    controller = controller_details_get(0);
    if(controller == 0) {
        log_error("could not get controller details\n");
        manager_sr_notif_send_instance_changed("unmount FAILED - no controller details", ctx->function_type, instance->container.name, instance);
        return NTS_ERR_FAILED;
    }

    for(int i = 0; i < (framework_environment.settings.ssh_connections + framework_environment.settings.tls_connections); i++) {
        uint16_t port = 0;
        if(i < framework_environment.settings.ssh_connections) {
            if(instance->mount_point_addressing_method[0] == 'd') {
                port = instance->container.docker_netconf_ssh_port + i;
            }
            else {
                port = instance->container.host_netconf_ssh_port + i;
            }
        }
        else {
            if(instance->mount_point_addressing_method[0] == 'd') {
                port = instance->container.docker_netconf_tls_port + i - framework_environment.settings.ssh_connections;
            }
            else {
                port = instance->container.host_netconf_tls_port + i - framework_environment.settings.ssh_connections;
            }
        }
        char node_id[128];
        if(framework_environment.settings.ssh_connections + framework_environment.settings.tls_connections > 1) {
            sprintf(node_id, "%s-%d", instance->container.name, port);
        }
        else {
            sprintf(node_id, "%s", instance->container.name);
        }

        char url[512];
        sprintf(url, "%s/rests/data/network-topology:network-topology/topology=topology-netconf/node=%s", controller->base_url, node_id);
        int rc = http_request(url, controller->username, controller->password, "DELETE", "", 0, 0);
        if(rc != NTS_ERR_OK) {
            log_error("http_request failed\n");
            manager_sr_notif_send_instance_changed("unmount FAILED - REST request", ctx->function_type, instance->container.name, instance);
            ret = NTS_ERR_FAILED;
        }
    }

    controller_details_free(controller);

    ctx->mounted_instances--;
    ctx->instance[ctx->mounted_instances].is_mounted = false;
    manager_sr_notif_send_instance_changed("unmount SUCCESS", ctx->function_type, instance->container.name, instance);
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" unmounted\n", instance->container.name);

    return ret;
}
