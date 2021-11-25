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

#include "nts_utils.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "core/framework.h"
#include "core/session.h"
#include "core/xpath.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>


cJSON* ves_create_common_event_header(const char *domain, const char *event_type, const char *hostname, int port, const char *priority, int seq_id) {
    assert(domain);
    assert(event_type);
    assert(hostname);
    assert(priority);

    char *eventId = 0;
    long useconds = get_microseconds_since_epoch();

    asprintf(&eventId, "%s-%d", event_type, seq_id);
    if(eventId == 0) {
        log_error("asprintf failed\n");
        return 0;
    }

    cJSON *common_event_header = cJSON_CreateObject();
    if(common_event_header == 0) {
        log_error("could not create JSON object\n");
        free(eventId);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "domain", domain) == 0) {
        log_error("cJSON AddStringToObject error\n");
        free(eventId);
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "eventId", eventId) == 0) {
        log_error("cJSON AddStringToObject error\n");
        free(eventId);
        cJSON_Delete(common_event_header);
        return 0;
    }

    free(eventId);

    if(cJSON_AddStringToObject(common_event_header, "eventName", event_type) == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddNumberToObject(common_event_header, "sequence", (double)(seq_id)) == 0) {
        log_error("cJSON AddNumberToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "priority", priority) == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "reportingEntityId", "") == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    char source_name[512];
    if(port) {
        sprintf(source_name, "%s-%d", hostname, port);
    }
    else {
        sprintf(source_name, "%s", hostname);
    }

    if(cJSON_AddStringToObject(common_event_header, "reportingEntityName", source_name) == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "sourceId", "") == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "sourceName", source_name) == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddNumberToObject(common_event_header, "startEpochMicrosec", (double)(useconds)) == 0) {
        log_error("cJSON AddNumberToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddNumberToObject(common_event_header, "lastEpochMicrosec", (double)(useconds)) == 0) {
        log_error("cJSON AddNumberToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "nfNamingCode", "sdn controller") == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "nfVendorName", "sdn") == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "timeZoneOffset", "+00:00") == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "version", "4.1") == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "vesEventListenerVersion", framework_environment.ves_endpoint.common_header_version) == 0) {
        log_error("cJSON AddStringToObject error\n");
        cJSON_Delete(common_event_header);
        return 0;
    }

    return common_event_header;
}

nts_mount_point_addressing_method_t nts_mount_point_addressing_method_get(sr_session_ctx_t *current_session) {
    assert_session();

    nts_mount_point_addressing_method_t ret = UNKNOWN_MAPPING;

    int rc;
    bool session_started = false;
    if(current_session == 0) {
        rc = sr_session_start(session_connection, SR_DS_RUNNING, &current_session);
        if(rc != SR_ERR_OK) {
            log_error("could not start sysrepo session\n");
            return ret;
        }
        session_started = true;
    }

    sr_val_t *value = 0;
    rc = sr_get_item(current_session, NTS_NF_NETWORK_FUNCTION_MPAM_SCHEMA_XPATH, 0, &value);
    if(rc == SR_ERR_OK) {
        if(strcmp(value->data.enum_val, "host-mapping") == 0) {
            ret = HOST_MAPPING;
        }
        else {
            ret = DOCKER_MAPPING;
        }
        sr_free_val(value);
    }

    if(session_started) {
        rc = sr_session_stop(current_session);
        if(rc != SR_ERR_OK) {
            log_error("could not stop sysrepo session\n");
            return ret;
        }
    }

    return ret;
}

// checkAS authentication via certificate not supported yet
ves_details_t *ves_endpoint_details_get(sr_session_ctx_t *current_session, const char *custom_path) {
    assert_session();

    int rc;
    bool session_started = false;
    if(current_session == 0) {
        rc = sr_session_start(session_connection, SR_DS_RUNNING, &current_session);
        if(rc != SR_ERR_OK) {
            log_error("could not start sysrepo session\n");
            return 0;
        }
        session_started = true;
    }

    struct lyd_node *data = 0;
    char *xpath_to_get;

    if(custom_path == 0) {
        if(framework_arguments.nts_mode == NTS_MODE_MANAGER) {
            xpath_to_get = NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH;
        }
        else {
            xpath_to_get = NTS_NF_VES_ENDPOINT_CONFIG_XPATH;
        }
    }
    else {
        xpath_to_get = (char *)custom_path;
    }

    rc = sr_get_subtree(current_session, xpath_to_get, 0, &data);
    if(rc != SR_ERR_OK) {
        log_error("could not get value for xPath=%s from the running datastore\n", xpath_to_get);
        if(session_started) {
            sr_session_stop(current_session);
        }
        return 0;
    }

    if(session_started) {
        rc = sr_session_stop(current_session);
        if(rc != SR_ERR_OK) {
            log_error("could not stop sysrepo session\n");
            lyd_free(data);
            return 0;
        }
    }

    if(data->child == 0) {
        log_error("ves-endpoint probably not set yet\n", xpath_to_get);
        lyd_free(data);
        return 0;
    }

    ves_details_t *ret = (ves_details_t *)malloc(sizeof(ves_details_t));
    if(!ret) {
        log_error("malloc failed\n");
        lyd_free(data);
        return 0;
    }

    ret->protocol = 0;
    ret->ip = 0;
    ret->port = 0;
    ret->auth_method = 0;
    ret->username = 0;
    ret->password = 0;

    struct lyd_node *chd = 0;
    LY_TREE_FOR(data->child, chd) {
        const char *val = ((const struct lyd_node_leaf_list *)chd)->value_str;

        if(strcmp(chd->schema->name, "ves-endpoint-protocol") == 0) {
            ret->protocol = strdup(val);
        }
        else if(strcmp(chd->schema->name, "ves-endpoint-ip") == 0) {
            ret->ip = strdup(val);
        }
        else if(strcmp(chd->schema->name, "ves-endpoint-port") == 0) {
            ret->port = ((const struct lyd_node_leaf_list *)chd)->value.uint16;
        }
        else if(strcmp(chd->schema->name, "ves-endpoint-auth-method") == 0) {
            ret->auth_method = strdup(val);
        }
        else if(strcmp(chd->schema->name, "ves-endpoint-username") == 0) {
            ret->username = strdup(val);
        }
        else if(strcmp(chd->schema->name, "ves-endpoint-password") == 0) {
            ret->password = strdup(val);
        }
    }
    lyd_free(data);

    if (strstr(ret->ip, ":")) {
        // IPv6 address
        asprintf(&ret->url, "%s://[%s]:%d/eventListener/v7", ret->protocol, ret->ip, ret->port);
    }
    else {
        if (framework_environment.ves_endpoint.port_absent == true) {
            // hostname addressing with port missing
            asprintf(&ret->url, "%s://%s/eventListener/v7", ret->protocol, ret->ip);
        }
        else {
            // normal addressing with IP and Port
            asprintf(&ret->url, "%s://%s:%d/eventListener/v7", ret->protocol, ret->ip, ret->port);
        }
        
    }
    
    if((ret->protocol == 0) || (ret->ip == 0) || (ret->auth_method == 0) || (ret->username == 0) || (ret->password == 0) || (ret->url == 0)) {
        free(ret->protocol);
        free(ret->ip);
        free(ret->auth_method);
        free(ret->username);
        free(ret->password);
        free(ret->url);
        free(ret);
        ret = 0;
    }

    return ret;
}

void ves_details_free(ves_details_t *instance) {
    assert(instance);

    free(instance->protocol);
    free(instance->ip);
    free(instance->url);
    free(instance->auth_method);
    free(instance->username);
    free(instance->password);
    free(instance);
}


// checkAS authentication via certificate not supported yet
controller_details_t *controller_details_get(sr_session_ctx_t *current_session) {
    assert_session();

    int rc;
    bool session_started = false;
    if(current_session == 0) {
        rc = sr_session_start(session_connection, SR_DS_RUNNING, &current_session);
        if(rc != SR_ERR_OK) {
            log_error("could not start sysrepo session\n");
            return 0;
        }
        session_started = true;
    }

    struct lyd_node *data = 0;
    char *xpath_to_get;

    if(framework_arguments.nts_mode == NTS_MODE_MANAGER) {
        xpath_to_get = NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH;
    }
    else {
        xpath_to_get = NTS_NF_SDN_CONTROLLER_CONFIG_XPATH;
    }

    rc = sr_get_subtree(current_session, xpath_to_get, 0, &data);
    if(rc != SR_ERR_OK) {
        log_error("could not get value for xPath=%s from the running datastore\n", xpath_to_get);
        if(session_started) {
            sr_session_stop(current_session);
        }
        return 0;
    }

    if(session_started) {
        rc = sr_session_stop(current_session);
        if(rc != SR_ERR_OK) {
            log_error("could not stop sysrepo session\n");
            lyd_free(data);
            return 0;
        }
    }

    if(data->child == 0) {
        log_error("sdn-controller probably not set yet\n");
        lyd_free(data);
        return 0;
    }

    controller_details_t *ret = (controller_details_t *)malloc(sizeof(controller_details_t));
    if(!ret) {
        log_error("malloc failed\n");
        lyd_free(data);
        return 0;
    }

    ret->protocol = 0;
    ret->ip = 0;
    ret->port = 0;
    ret->nc_callhome_ip = 0;
    ret->nc_callhome_port = 0;
    ret->auth_method = 0;
    ret->username = 0;
    ret->password = 0;

    ret->auth_method = strdup("basic");

    struct lyd_node *chd = 0;
    LY_TREE_FOR(data->child, chd) {
        const char *val = ((const struct lyd_node_leaf_list *)chd)->value_str;

        if(strcmp(chd->schema->name, "controller-protocol") == 0) {
            ret->protocol = strdup(val);
        }
        else if(strcmp(chd->schema->name, "controller-ip") == 0) {
            ret->ip = strdup(val);
        }
        else if(strcmp(chd->schema->name, "controller-port") == 0) {
            ret->port = ((const struct lyd_node_leaf_list *)chd)->value.uint16;
        }
        else if(strcmp(chd->schema->name, "controller-netconf-call-home-ip") == 0) {
            ret->nc_callhome_ip = strdup(val);
        }
        else if(strcmp(chd->schema->name, "controller-netconf-call-home-port") == 0) {
            ret->nc_callhome_port = ((const struct lyd_node_leaf_list *)chd)->value.uint16;
        }
        else if(strcmp(chd->schema->name, "controller-username") == 0) {
            ret->username = strdup(val);
        }
        else if(strcmp(chd->schema->name, "controller-password") == 0) {
            ret->password = strdup(val);
        }
    }
    lyd_free(data);

    if (strstr(ret->ip, ":")) {
        // IPv6 address
        asprintf(&ret->base_url, "%s://[%s]:%d", ret->protocol, ret->ip, ret->port);
    }
    else {
        if (framework_environment.sdn_controller.port_absent == true) {
            // hostname without port addressing
            asprintf(&ret->base_url, "%s://%s", ret->protocol, ret->ip);
        }
        else {
            // normal IP and Port addressing
            asprintf(&ret->base_url, "%s://%s:%d", ret->protocol, ret->ip, ret->port);
        }
    }

    if((ret->protocol == 0) || (ret->ip == 0) || (ret->nc_callhome_ip == 0) || (ret->auth_method == 0) || (ret->username == 0) || (ret->password == 0) || (ret->base_url == 0)) {
        free(ret->protocol);
        free(ret->ip);
        free(ret->nc_callhome_ip);
        free(ret->auth_method);
        free(ret->username);
        free(ret->password);
        free(ret->base_url);
        free(ret);
        ret = 0;
    }

    return ret;
}

void controller_details_free(controller_details_t *instance) {
    assert(instance);

    free(instance->protocol);
    free(instance->ip);
    free(instance->nc_callhome_ip);
    free(instance->base_url);
    free(instance->auth_method);
    free(instance->username);
    free(instance->password);
    free(instance);
}

int nts_vercmp(const char *ver1, const char *ver2) {
    assert(ver1);
    assert(ver2);

    int i = 0;
    int v1 = 0, v2 = 0, v3 = 0;
    while(ver1[i] && (ver1[i] != '.')) {
        v1 *= 10;
        v1 += ver1[i] - '0';
        i++;
    }

    if(ver1[i]) {
        i++;
        while(ver1[i] && (ver1[i] != '.')) {
            v2 *= 10;
            v2 += ver1[i] - '0';
            i++;
        }

        if(ver1[i]) {
            i++;
            while(ver1[i] && (ver1[i] != '.')) {
                v3 *= 10;
                v3 += ver1[i] - '0';
                i++;
            }
        }
    }


    int V1 = 0, V2 = 0, V3 = 0;
    i = 0;
    while(ver2[i] && (ver2[i] != '.')) {
        V1 *= 10;
        V1 += ver2[i] - '0';
        i++;
    }

    if(ver2[i]) {
        i++;
        while(ver2[i] && (ver2[i] != '.')) {
            V2 *= 10;
            V2 += ver2[i] - '0';
            i++;
        }

        if(ver2[i]) {
            i++;
            while(ver2[i] && (ver2[i] != '.')) {
                V3 *= 10;
                V3 += ver2[i] - '0';
                i++;
            }
        }
    }

    if(v1 < V1) {
        return -1;
    }
    else if(v1 > V1) {
        return 1;
    }

    if(v2 < V2) {
        return -1;
    }
    else if(v2 > V2) {
        return 1;
    }

    if(v3 < V3) {
        return -1;
    }
    else if(v3 > V3) {
        return 1;
    }

    return 0;
}

int nts_utils_populate_info(sr_session_ctx_t *current_session, const char *function_type) {
    assert(current_session);
    assert(function_type);

    bool manager = (strcmp(function_type, "NTS_FUNCTION_TYPE_MANAGER") == 0);

    int rc;
    char int_to_str[30];
    //setup sdn-controller defaults
    if(strlen(framework_environment.sdn_controller.protocol)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH"/controller-protocol", (const char*)framework_environment.sdn_controller.protocol, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_SDN_CONTROLLER_CONFIG_XPATH"/controller-protocol", (const char*)framework_environment.sdn_controller.protocol, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.sdn_controller.ip)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH"/controller-ip", (const char*)framework_environment.sdn_controller.ip, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_SDN_CONTROLLER_CONFIG_XPATH"/controller-ip", (const char*)framework_environment.sdn_controller.ip, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    sprintf(int_to_str, "%d", framework_environment.sdn_controller.port);
    if(manager) {
        rc = sr_set_item_str(current_session, NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH"/controller-port", (const char*)int_to_str, 0, 0);
    }
    else {
        rc = sr_set_item_str(current_session, NTS_NF_SDN_CONTROLLER_CONFIG_XPATH"/controller-port", (const char*)int_to_str, 0, 0);
    }
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    if(strlen(framework_environment.sdn_controller.callhome_ip)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH"/controller-netconf-call-home-ip", (const char*)framework_environment.sdn_controller.callhome_ip, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_SDN_CONTROLLER_CONFIG_XPATH"/controller-netconf-call-home-ip", (const char*)framework_environment.sdn_controller.callhome_ip, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    sprintf(int_to_str, "%d", framework_environment.sdn_controller.callhome_port);
    if(manager) {
        rc = sr_set_item_str(current_session, NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH"/controller-netconf-call-home-port", (const char*)int_to_str, 0, 0);
    }
    else {
        rc = sr_set_item_str(current_session, NTS_NF_SDN_CONTROLLER_CONFIG_XPATH"/controller-netconf-call-home-port", (const char*)int_to_str, 0, 0);
    }
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    if(strlen(framework_environment.sdn_controller.username)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH"/controller-username", (const char*)framework_environment.sdn_controller.username, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_SDN_CONTROLLER_CONFIG_XPATH"/controller-username", (const char*)framework_environment.sdn_controller.username, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.sdn_controller.password)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_SDN_CONTROLLER_CONFIG_XPATH"/controller-password", (const char*)framework_environment.sdn_controller.password, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_SDN_CONTROLLER_CONFIG_XPATH"/controller-password", (const char*)framework_environment.sdn_controller.password, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    //setup ves-endpoint details
    if(strlen(framework_environment.ves_endpoint.protocol)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-protocol", (const char*)framework_environment.ves_endpoint.protocol, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-protocol", (const char*)framework_environment.ves_endpoint.protocol, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.ves_endpoint.ip)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-ip", (const char*)framework_environment.ves_endpoint.ip, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-ip", (const char*)framework_environment.ves_endpoint.ip, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    sprintf(int_to_str, "%d", framework_environment.ves_endpoint.port);
    if(manager) {
        rc = sr_set_item_str(current_session, NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-port", (const char*)int_to_str, 0, 0);
    }
    else {
        rc = sr_set_item_str(current_session, NTS_NF_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-port", (const char*)int_to_str, 0, 0);
    }
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    if(strlen(framework_environment.ves_endpoint.auth_method)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-auth-method", (const char*)framework_environment.ves_endpoint.auth_method, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-auth-method", (const char*)framework_environment.ves_endpoint.auth_method, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.ves_endpoint.username)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-username", (const char*)framework_environment.ves_endpoint.username, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-username", (const char*)framework_environment.ves_endpoint.username, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.ves_endpoint.password)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-password", (const char*)framework_environment.ves_endpoint.password, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-password", (const char*)framework_environment.ves_endpoint.password, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.ves_endpoint.certificate)) {
        if(manager) {
            rc = sr_set_item_str(current_session, NTS_MANAGER_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-certificate", (const char*)framework_environment.ves_endpoint.certificate, 0, 0);
        }
        else {
            rc = sr_set_item_str(current_session, NTS_NF_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-certificate", (const char*)framework_environment.ves_endpoint.certificate, 0, 0);
        }
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    if(manager == false) {
        //presence containers
        rc = sr_set_item_str(current_session, NTS_NF_FAULT_GENERATION_SCHEMA_XPATH, 0, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_set_item_str(current_session, NTS_NF_NETCONF_SCHEMA_XPATH, 0, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_set_item_str(current_session, NTS_NF_VES_SCHEMA_XPATH, 0, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    //also set the network-function module for easy identifying the function type
    rc = sr_set_item_str(current_session, NTS_NF_NETWORK_FUNCTION_FTYPE_SCHEMA_XPATH, function_type, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    //mount-point-addressing-method
    rc = sr_set_item_str(current_session, NTS_NF_NETWORK_FUNCTION_MPAM_SCHEMA_XPATH, framework_environment.nts.nf_mount_point_addressing_method, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    //apply all changes
    rc = sr_apply_changes(current_session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}
