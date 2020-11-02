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

#include "core/framework.h"
#include "core/docker.h"
#include "core/session.h"
#include "utils/nc_client.h"
#include "utils/http_client.h"
#include "utils/nts_utils.h"

static uint16_t manager_start_port = 0;
static uint8_t manager_port[65536];

void manager_operations_init(void) {
    manager_start_port = framework_environment.host_base_port;
    for(int i = 0; i < 65536; i++) {
        manager_port[i] = 0;
    }
}

int manager_start_instance(manager_network_function_type *function_type) {
    assert(function_type);
    assert_session();

    function_type->started_instances++;
    function_type->instance = (manager_network_function_instance_t *)realloc(function_type->instance, sizeof(manager_network_function_instance_t) * function_type->started_instances);
    if(function_type->instance == 0) {
        log_error("realloc failed");
        return NTS_ERR_FAILED;
    }

    manager_network_function_instance_t *instance = &function_type->instance[function_type->started_instances - 1];
    instance->is_configured = false;
    instance->is_mounted = false;
    
    asprintf(&instance->name, "%s-%d", function_type->docker_instance_name, function_type->started_instances - 1);

    instance->mount_point_addressing_method = strdup(function_type->mount_point_addressing_method);

    instance->docker_port = STANDARD_NETCONF_PORT;
    instance->host_ip = strdup(framework_environment.host_ip);
    instance->host_port = 0;

    //find start host port
    for(int i = manager_start_port; i < 65536 - (framework_environment.ssh_connections + framework_environment.tls_connections + framework_environment.ftp_connections + framework_environment.sftp_connections); i += (framework_environment.ssh_connections + framework_environment.tls_connections + framework_environment.ftp_connections + framework_environment.sftp_connections)) {
        if(manager_port[i] == 0) {
            manager_port[i] = 1;
            instance->host_port = i;
            break;
        }
    }

    if(instance->host_port == 0) {
        log_error("no ports available for operation");
        return NTS_ERR_FAILED;
    }

    int rc = docker_device_start(function_type, instance);
    if(rc != NTS_ERR_OK) {
        log_error("docker_device_start failed");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

int manager_config_instance(manager_network_function_type *function_type, manager_network_function_instance_t *instance) {
    assert(function_type);
    assert(instance);

    //first wait for the nc server to be up and running
    while(check_port_open(instance->docker_ip, instance->docker_port) == false) {
        usleep(10000);
    }

    //populate sdn-controller and ves-endpoint
    struct lyd_node *local_tree = 0;
    int rc = lyd_utils_dup(session_running, "/nts-manager:simulation/sdn-controller", "/nts-network-function:simulation/sdn-controller", &local_tree);
    if(rc != NTS_ERR_OK) {
        log_error("lyd_utils_dup failed");
        return NTS_ERR_FAILED;
    }

    rc = lyd_utils_dup(session_running, "/nts-manager:simulation/ves-endpoint", "/nts-network-function:simulation/ves-endpoint", &local_tree);
    if(rc != NTS_ERR_OK) {
        log_error("lyd_utils_dup failed");
        return NTS_ERR_FAILED;
    }

    char *xpath_s = 0;
    asprintf(&xpath_s, "/nts-manager:simulation/network-functions/network-function[function-type='%s']", function_type->function_type_string);
    rc = lyd_utils_dup(session_running, xpath_s, "/nts-network-function:simulation/network-function", &local_tree);
    if(rc != NTS_ERR_OK) {
        log_error("lyd_utils_dup failed");
        return NTS_ERR_FAILED;
    }
    free(xpath_s);

    nc_client_t *nc_client = nc_client_ssh_connect(instance->docker_ip, instance->docker_port, "netconf", "netconf");
    if(nc_client == 0) {
        log_error("nc_client_ssh_connect");
        return NTS_ERR_FAILED;
    }

    rc += nc_client_edit_batch(nc_client, local_tree, 1000);
    if(rc != NTS_ERR_OK) {
        log_error("nc_client_edit_batch failed %d\n", rc);
        return NTS_ERR_FAILED;
    }
    lyd_free_withsiblings(local_tree);

    
    if(instance->is_configured == false) {
        //run datastore-random-populate rpc
        struct lyd_node *rpc_node = 0;
        struct lyd_node *rpcout = 0;
        rpc_node = lyd_new_path(0, session_context, "/nts-network-function:datastore-random-populate", 0, 0, 0);
        if(rpc_node == 0) {
            log_error("failed to create rpc node");
            return NTS_ERR_FAILED;
        }

        rpcout = nc_client_send_rpc(nc_client, rpc_node, 5000);
        if(rpcout == 0) {
            log_error("datastore-random-populate rpc failed");
            return NTS_ERR_FAILED;
        }
        else {
            lyd_free_withsiblings(rpcout);
        }
        lyd_free_withsiblings(rpc_node);

        //run feature-control rpc
        rpc_node = lyd_new_path(0, session_context, "/nts-network-function:feature-control/features", "ves-file-ready ves-heartbeat ves-pnf-registration manual-notification-generation netconf-call-home", 0, 0);
        if(rpc_node == 0) {
            log_error("failed to create rpc node");
            return NTS_ERR_FAILED;
        }

        rpcout = nc_client_send_rpc(nc_client, rpc_node, 1000);
        if(rpcout == 0) {
            log_error("feature-control rpc failed");
            return NTS_ERR_FAILED;
        }
        else {
            lyd_free_withsiblings(rpcout);
        }
        lyd_free_withsiblings(rpc_node);
    }

    instance->is_configured = true;

    nc_client_disconnect(nc_client);

    return NTS_ERR_OK;
}

int manager_stop_instance(manager_network_function_type *function_type) {
    assert(function_type);

    manager_network_function_instance_t *instance = &function_type->instance[function_type->started_instances - 1];

    if(instance->is_mounted) {
        if(manager_unmount_instance(function_type) != NTS_ERR_OK) {
            return NTS_ERR_FAILED;
        }
    }

    int rc = docker_device_stop(instance);
    if(rc != NTS_ERR_OK) {
        log_error("docker_device_stop failed");
        return NTS_ERR_FAILED;
    }

    //clear unused ports
    manager_port[instance->host_port] = 0;

    free(instance->mount_point_addressing_method);
    free(instance->docker_id);
    free(instance->name);
    free(instance->docker_ip);
    free(instance->host_ip);

    function_type->started_instances--;
    if(function_type->started_instances) {
        function_type->instance = (manager_network_function_instance_t *)realloc(function_type->instance, sizeof(manager_network_function_instance_t) * function_type->started_instances);
        if(function_type->instance == 0) {
            log_error("realloc failed");
            return NTS_ERR_FAILED;
        }
    }
    else {
        free(function_type->instance);
        function_type->instance = 0;
    }
    return NTS_ERR_OK;
}

int manager_mount_instance(manager_network_function_type *function_type) {
    assert(function_type);

    manager_network_function_instance_t *instance = &function_type->instance[function_type->mounted_instances];

    if(instance->is_mounted == true) {
        return NTS_ERR_FAILED;
    }

    controller_details_t *controller;
    controller = controller_details_get(0);
    if(controller == 0) {
        log_error("could not get controller detailes");
        return NTS_ERR_FAILED;
    }

    for(int i = 0; i < (framework_environment.ssh_connections + framework_environment.tls_connections); i++) {
        char *protocol;
        char *protocol_data;
        if(i < framework_environment.ssh_connections) {
            protocol = "SSH";
            protocol_data = "\
            \"network-topology:netconf-node-topology:username\": \"netconf\",\
            \"network-topology:netconf-node-topology:password\": \"netconf\"";

        }
        else {
            protocol = "TLS";
            protocol_data = "\
            \"netconf-node-topology:key-based\" : {\
                \"netconf-node-topology:username\" : \"netconf\",\
                \"netconf-node-topology:key-id\" : \""KS_KEY_NAME"\"\
            }";
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

        char *json = 0;
        uint16_t port = 0;
        char *ip = 0;
        if(instance->mount_point_addressing_method[0] == 'd') {
            ip = instance->docker_ip;
            port = instance->docker_port + i;
        }
        else {
            ip = instance->host_ip;
            port = instance->host_port + i;
        }
        char *node_id = 0;
        asprintf(&node_id, "%s-%d", instance->name, port);
        asprintf(&json, json_template, node_id, ip, port, protocol, protocol_data);

        char *url = 0;
        asprintf(&url, "%s/rests/data/network-topology:network-topology/topology=topology-netconf/node=%s", controller->base_url, node_id);
        int rc = http_request(url, controller->username, controller->password, "PUT", json, 0, 0);
        if(rc != NTS_ERR_OK) {
            log_error("http_request failed");
            return NTS_ERR_FAILED;
        }

        free(url);
        free(node_id);
        free(json);
    }

    controller_details_free(controller);

    instance->is_mounted = true;
    function_type->mounted_instances++;

    return NTS_ERR_OK;
}

int manager_unmount_instance(manager_network_function_type *function_type) {
    assert(function_type);

    manager_network_function_instance_t *instance = &function_type->instance[function_type->mounted_instances - 1];

    if(instance->is_mounted == false) {
        log_error("tried to unmount an unmounted instance");
        return NTS_ERR_FAILED;
    }

    controller_details_t *controller;
    controller = controller_details_get(0);
    if(controller == 0) {
        log_error("could not get controller detailes");
        return NTS_ERR_FAILED;
    }

    for(int i = 0; i < (framework_environment.ssh_connections + framework_environment.tls_connections); i++) {
        uint16_t port = 0;
        if(function_type->mount_point_addressing_method[0] == 'd') {
            port = instance->docker_port + i;
        }
        else {
            port = instance->host_port + i;
        }
        char *node_id = 0;
        asprintf(&node_id, "%s-%d", instance->name, port);

        char *url = 0;
        asprintf(&url, "%s/rests/data/network-topology:network-topology/topology=topology-netconf/node=%s", controller->base_url, node_id);
        int rc = http_request(url, controller->username, controller->password, "DELETE", "", 0, 0);
        if(rc != NTS_ERR_OK) {
            log_error("http_request failed");
            return NTS_ERR_FAILED;
        }

        free(url);
        free(node_id);
    }

    controller_details_free(controller);

    function_type->mounted_instances--;
    function_type->instance[function_type->mounted_instances].is_mounted = false;

    return NTS_ERR_OK;
}
