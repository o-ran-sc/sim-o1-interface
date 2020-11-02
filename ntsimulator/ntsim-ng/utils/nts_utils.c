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
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define MOUNT_POINT_ADDRESSING_METHOD_SCHEMA_XPATH  "/nts-network-function:simulation/network-function/mount-point-addressing-method"

cJSON* ves_create_common_event_header(const char *domain, const char *event_type, const char *source_name, const char *priority, int seq_id) {
    assert(domain);
    assert(event_type);
    assert(source_name);
    assert(priority);

    char *eventId = 0;
    long useconds = get_microseconds_since_epoch();

    asprintf(&eventId, "%s-%d", event_type, seq_id);
    if(eventId == 0) {
        log_error("asprintf failed");
        return 0;
    }

    cJSON *common_event_header = cJSON_CreateObject();
    if(common_event_header == 0) {
        log_error("could not create JSON object");
        free(eventId);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "domain", domain) == 0) {
        log_error("cJSON AddStringToObject error");
        free(eventId);
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "eventId", eventId) == 0) {
        log_error("cJSON AddStringToObject error");
        free(eventId);
        cJSON_Delete(common_event_header);
        return 0;
    }

    free(eventId);

    if(cJSON_AddStringToObject(common_event_header, "eventName", event_type) == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddNumberToObject(common_event_header, "sequence", (double)(seq_id)) == 0) {
        log_error("cJSON AddNumberToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "priority", priority) == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "reportingEntityId", "") == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "reportingEntityName", source_name) == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "sourceId", "") == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "sourceName", source_name) == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddNumberToObject(common_event_header, "startEpochMicrosec", (double)(useconds)) == 0) {
        log_error("cJSON AddNumberToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddNumberToObject(common_event_header, "lastEpochMicrosec", (double)(useconds)) == 0) {
        log_error("cJSON AddNumberToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "nfNamingCode", "sdn controller") == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "nfVendorName", "sdn") == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "timeZoneOffset", "+00:00") == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "version", "4.1") == 0) {
        log_error("cJSON AddStringToObject error");
        cJSON_Delete(common_event_header);
        return 0;
    }

    if(cJSON_AddStringToObject(common_event_header, "vesEventListenerVersion", "7.2") == 0) {
        log_error("cJSON AddStringToObject error");
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
            log_error("could not start sysrepo session");
            return ret;
        }
        session_started = true;
    }

    sr_val_t *value = 0;
    rc = sr_get_item(session_running, MOUNT_POINT_ADDRESSING_METHOD_SCHEMA_XPATH, 0, &value);
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
            log_error("could not stop sysrepo session");
            return ret;
        }
    }

    return ret;
}

// checkAS authentication via certificate not supported yet
ves_details_t *ves_endpoint_details_get(sr_session_ctx_t *current_session) {
    assert_session();

    int rc;
    bool session_started = false;
    if(current_session == 0) {
        rc = sr_session_start(session_connection, SR_DS_RUNNING, &current_session);
        if(rc != SR_ERR_OK) {
            log_error("could not start sysrepo session");
            return 0;
        }
        session_started = true;
    }

    struct lyd_node *data = 0;
    char *xpath_to_get;

    if(framework_arguments.manager) {
        xpath_to_get = "/nts-manager:simulation/ves-endpoint";
    }
    else {
        xpath_to_get = "/nts-network-function:simulation/ves-endpoint";
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
            log_error("could not stop sysrepo session");
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
        log_error("malloc failed");
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

    asprintf(&ret->url, "%s://%s:%d/eventListener/v7", ret->protocol, ret->ip, ret->port);
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
            log_error("could not start sysrepo session");
            return 0;
        }
        session_started = true;
    }

    struct lyd_node *data = 0;
    char *xpath_to_get;

    if(framework_arguments.manager) {
        xpath_to_get = "/nts-manager:simulation/sdn-controller";
    }
    else {
        xpath_to_get = "/nts-network-function:simulation/sdn-controller";
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
            log_error("could not stop sysrepo session");
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
        log_error("malloc failed");
        lyd_free(data);
        return 0;
    }

    ret->protocol = 0;
    ret->ip = 0;
    ret->port = 0;
    ret->nc_callhome_port = 0;
    ret->auth_method = 0;
    ret->username = 0;
    ret->password = 0;

    ret->protocol = strdup("http");
    ret->auth_method = strdup("basic");

    struct lyd_node *chd = 0;
    LY_TREE_FOR(data->child, chd) {
        const char *val = ((const struct lyd_node_leaf_list *)chd)->value_str;

        if(strcmp(chd->schema->name, "controller-ip") == 0) {
            ret->ip = strdup(val);
        }
        else if(strcmp(chd->schema->name, "controller-port") == 0) {
            ret->port = ((const struct lyd_node_leaf_list *)chd)->value.uint16;
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

    asprintf(&ret->base_url, "%s://%s:%d", ret->protocol, ret->ip, ret->port);
    if((ret->protocol == 0) || (ret->ip == 0) || (ret->auth_method == 0) || (ret->username == 0) || (ret->password == 0) || (ret->base_url == 0)) {
        free(ret->protocol);
        free(ret->ip);
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
    free(instance->base_url);
    free(instance->auth_method);
    free(instance->username);
    free(instance->password);
    free(instance);
}
