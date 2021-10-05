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

#include "supervisor.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/network_emulation.h"
#include <stdio.h>
#include <assert.h>

#include "core/session.h"
#include "core/xpath.h"
#include "core/framework.h"

#include <sysrepo.h>
#include <sysrepo/values.h>

static int app_common_populate_info(void);

static int app_common_populate_network_emulation_info(void);
static int app_common_network_emulation_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

static int app_common_hardware_emulation_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
static int app_common_hardware_emulation_netconf_delay_oper_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

static int app_common_emulate_total_loss_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);

static uint32_t netconf_delay = 0;

int app_common_init(void) {
    assert_session();

    int rc = app_common_populate_info();
    if(rc != NTS_ERR_OK) {
        log_error("app_common_populate_info() failed\n");
        return NTS_ERR_FAILED;
    }

    network_emulation_init();

    rc = app_common_populate_network_emulation_info();
    if(rc != NTS_ERR_OK) {
        log_error("app_common_populate_network_emulation() failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_module_change_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH, app_common_network_emulation_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_UPDATE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to network emulation\n");
        return NTS_ERR_FAILED;
    }


    rc = sr_module_change_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, NTS_NF_HARDWARE_EMULATION_SCHEMA_XPATH, app_common_hardware_emulation_change_cb, NULL, 2, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_UPDATE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to hardware emulation changes\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_oper_get_items_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, NTS_NF_HE_NETCONF_DELAY_SCHEMA_XPATH, app_common_hardware_emulation_netconf_delay_oper_cb, 0, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_OPER_MERGE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_oper_get_items_subscribe: %s\n", sr_strerror(rc));
        return 0;
    }

    rc = sr_rpc_subscribe(session_running, NTS_NF_RPC_EMULATE_TOTAL_LOSS_SCHEMA_XPATH, app_common_emulate_total_loss_cb, 0, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_rpc_subscribe: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int app_common_populate_info(void) {
    int rc;
    char aux[9];

    struct lys_module *module = (struct lys_module *)ly_ctx_get_module(session_context, NTS_NETWORK_FUNCTION_MODULE, 0, 0);
    if(module == 0) {
        log_error("could not get module %s from context\n", NTS_NETWORK_FUNCTION_MODULE);
        return NTS_ERR_FAILED;
    }

    struct lyd_node *info = lyd_new(0, module, "info");
    if(info == 0) {
        log_error("lyd_new failed\n");
        return NTS_ERR_FAILED;
    }

    struct lyd_node *node;
    if (framework_environment.nts.build_time && strlen(framework_environment.nts.build_time) > 0) {
        node  = lyd_new_leaf(info, module, "build-time", framework_environment.nts.build_time);
        if(node == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }
    }

    node  = lyd_new_leaf(info, module, "version", framework_environment.nts.version);
    if(node == 0) {
        log_error("lyd_new_leaf failed\n");
        return NTS_ERR_FAILED;
    }

    sprintf(aux, "%d", framework_environment.settings.ssh_connections);
    node  = lyd_new_leaf(info, module, "ssh-connections", aux);
    if(node == 0) {
        log_error("lyd_new_leaf failed\n");
        return NTS_ERR_FAILED;
    }

    sprintf(aux, "%d", framework_environment.settings.tls_connections);
    node  = lyd_new_leaf(info, module, "tls-connections", aux);
    if(node == 0) {
        log_error("lyd_new_leaf failed\n");
        return NTS_ERR_FAILED;
    }

    node  = lyd_new_leaf(info, module, "hostname", framework_environment.settings.hostname);
    if(node == 0) {
        log_error("lyd_new_leaf failed\n");
        return NTS_ERR_FAILED;
    }

    //netconf ssh ports
    for(int k = 0; k < framework_environment.settings.ssh_connections; k++) {
        char value[128];
        
        struct lyd_node *ports = lyd_new(info, module, "docker-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", STANDARD_NETCONF_PORT + k);
        if(lyd_new_leaf(ports, module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_NETCONF_SSH") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }
    }

    //netconf tls ports
    for(int k = 0; k < framework_environment.settings.tls_connections; k++) {
        char value[128];
        
        struct lyd_node *ports = lyd_new(info, module, "docker-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", STANDARD_NETCONF_PORT + framework_environment.settings.ssh_connections + k);
        if(lyd_new_leaf(ports, module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_NETCONF_TLS") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }
    }

    //ftp ports
    for(int k = 0; k < framework_environment.settings.ftp_connections; k++) {
        char value[128];
        
        struct lyd_node *ports = lyd_new(info, module, "docker-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", STANDARD_FTP_PORT + k);
        if(lyd_new_leaf(ports, module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_FTP") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }
    }

    //sftp ports
    for(int k = 0; k < framework_environment.settings.sftp_connections; k++) {
        char value[128];
        
        struct lyd_node *ports = lyd_new(info, module, "docker-ports");
        if(ports == 0) {
            log_error("lyd_new failed\n");
            return NTS_ERR_FAILED;
        }

        sprintf(value, "%d", STANDARD_SFTP_PORT + k);
        if(lyd_new_leaf(ports, module, "port", value) == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }

        if(lyd_new_leaf(ports, module, "protocol", "nts-common:NTS_PROTOCOL_TYPE_SFTP") == 0) {
            log_error("lyd_new_leaf failed\n");
            return NTS_ERR_FAILED;
        }
    }

    rc = sr_edit_batch(session_operational, info, "merge");
    if(rc != SR_ERR_OK) {
        log_error("sr_edit_batch failed: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(session_operational, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int app_common_populate_network_emulation_info(void) {
    int rc;

    rc  = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/limit", NETWORK_EMULATION_DEFAULT_LIMIT, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/delay/time", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/delay/jitter", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/delay/correlation", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/delay/distribution", "normal", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/loss", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/corruption/percentage", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/corruption/correlation", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/duplication/percentage", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/duplication/correlation", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/reordering/percentage", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/reordering/correlation", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(session_running, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/rate", "0", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(session_running, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int app_common_network_emulation_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    
    if(event == SR_EV_UPDATE) {
        sr_change_iter_t *it = 0;
        int rc = SR_ERR_OK;
        sr_change_oper_t oper;
        sr_val_t *old_value = 0;
        sr_val_t *new_value = 0;

        rc = sr_get_changes_iter(session, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"//.", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed\n");
            return SR_ERR_VALIDATION_FAILED;
        }

        uint16_t delay_time = 0;
        uint16_t delay_jitter = 0;

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            if(new_value->xpath && (strstr(new_value->xpath, "/delay/time"))) {
                delay_time = new_value->data.uint16_val;
            }

            if(new_value->xpath && (strstr(new_value->xpath, "/delay/jitter"))) {
                delay_jitter = new_value->data.uint16_val;
            }
            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);

        if((delay_time == 0) || (delay_jitter == 0)) {
            rc = sr_set_item_str(session, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/delay/distribution", "normal", 0, 0);
            if(rc != SR_ERR_OK) {
                log_error("sr_set_item failed\n");
                return SR_ERR_VALIDATION_FAILED;
            }
        }

        if(delay_time == 0) {
            rc = sr_set_item_str(session, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/delay/jitter", "0", 0, 0);
            if(rc != SR_ERR_OK) {
                log_error("sr_set_item failed\n");
                return SR_ERR_VALIDATION_FAILED;
            }

            rc = sr_set_item_str(session, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"/delay/correlation", "0", 0, 0);
            if(rc != SR_ERR_OK) {
                log_error("sr_set_item failed\n");
                return SR_ERR_VALIDATION_FAILED;
            }
        }
    }
    else if(event == SR_EV_DONE) {
        sr_val_t *values = NULL;
        size_t count = 0;
        
        int rc = sr_get_items(session, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"//.", 0, 0, &values, &count);
        if (rc != SR_ERR_OK) {
            log_error("sr_get_items failed\n");
            return rc;
        }

        network_emultation_settings_t s;

        for(size_t i = 0; i < count; i++) {
            if(strstr(values[i].xpath, "/limit")) {
                s.limit = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/delay/time")) {
                s.delay.time = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/delay/jitter")) {
                s.delay.jitter = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/delay/correlation")) {
                s.delay.correlation = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/delay/distribution")) {
                s.delay.distribution = strdup(values[i].data.string_val);
            }
            else if(strstr(values[i].xpath, "/loss")) {
                s.loss = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/corruption/percentage")) {
                s.corruption.percentage = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/corruption/correlation")) {
                s.corruption.correlation = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/duplication/percentage")) {
                s.duplication.percentage = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/duplication/correlation")) {
                s.duplication.correlation = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/reordering/percentage")) {
                s.reordering.percentage = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/reordering/correlation")) {
                s.reordering.correlation = values[i].data.uint16_val;
            }
            else if(strstr(values[i].xpath, "/rate")) {
                s.rate = values[i].data.uint16_val;
            }
        }

        sr_free_values(values, count);
        if(network_emulation_update(&s) != NTS_ERR_OK) {
            log_error("network_emulation_update() failed\n");
            free(s.delay.distribution);
            return SR_ERR_OPERATION_FAILED;
        }
        free(s.delay.distribution);
    }

    return SR_ERR_OK;
}

static int app_common_hardware_emulation_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    bool delay = false;

    if(event == SR_EV_UPDATE) {
        sr_change_iter_t *it = 0;
        int rc = SR_ERR_OK;
        sr_change_oper_t oper;
        sr_val_t *old_value = 0;
        sr_val_t *new_value = 0;

        rc = sr_get_changes_iter(session, NTS_NF_HARDWARE_EMULATION_SCHEMA_XPATH"//.", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed\n");
            return SR_ERR_VALIDATION_FAILED;
        }

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            if(new_value->xpath && (strstr(new_value->xpath, "/netconf-delay/edit-test-list"))) {
                delay = true;
            }
            else if(new_value->xpath && (strstr(new_value->xpath, "/netconf-delay/edit-test"))) {
                rc = sr_set_item_str(session, NTS_NF_HARDWARE_EMULATION_SCHEMA_XPATH"/netconf-delay/edit-test", "0", 0, 0);
                if(rc != SR_ERR_OK) {
                    log_error("sr_set_item failed\n");
                    return SR_ERR_VALIDATION_FAILED;
                }
                
                delay = true;
            }

            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        if(delay) {
            delay = false;

            int32_t sec = netconf_delay / 1000;
            uint32_t usec = (netconf_delay % 1000) * 1000;

            usleep(usec);
            if(sec > 0) {
                sleep(sec);
            }
        }

        sr_free_change_iter(it);
    }

    if(event == SR_EV_DONE) {
        sr_val_t *values = NULL;
        size_t count = 0;
        
        int rc = sr_get_items(session, NTS_NF_HARDWARE_EMULATION_SCHEMA_XPATH"//.", 0, 0, &values, &count);
        if (rc != SR_ERR_OK) {
            log_error("sr_get_items failed\n");
            return rc;
        }

        for(size_t i = 0; i < count; i++) {
            if(strstr(values[i].xpath, "/netconf-delay/delay")) {
                netconf_delay = values[i].data.uint32_val;
            }
        }

        sr_free_values(values, count);
    }

    return SR_ERR_OK;
}

static int app_common_hardware_emulation_netconf_delay_oper_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data) {

    char aux[9];
    sprintf(aux, "%d", netconf_delay);
    struct lyd_node *container = lyd_new_path(0, session_context, NTS_NF_HE_NETCONF_DELAY_SCHEMA_XPATH, 0, 0, LYD_PATH_OPT_NOPARENTRET);
    if(container == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    //get test leaf
    lyd_new_leaf(container, container->schema->module, "get-test", aux);

    //get test list
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = sr_get_items(session_running, NTS_NF_HE_NETCONF_DELAY_SCHEMA_XPATH"/edit-test-list/*", 0, 0, &values, &count);
    if (rc != SR_ERR_OK) {
        log_error("sr_get_items failed\n");
        return rc;
    }
    for(size_t i = 0; i < count; i++) {
        struct lyd_node *listitem = lyd_new(container, container->schema->module, "get-test-list");
        if(listitem) {
            lyd_new_leaf(listitem, container->schema->module, "value", values[i].data.string_val);
        }
    }

    sr_free_values(values, count);



    uint32_t sec = netconf_delay / 1000;
    uint32_t usec = (netconf_delay % 1000) * 1000;

    usleep(usec);
    if(sec > 0) {
        sleep(sec);
    }

    *parent = container;
    return SR_ERR_OK;
}

static int app_common_emulate_total_loss_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {
    int rc;

    *output_cnt = 1;
    rc = sr_new_values(*output_cnt, output);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(output[0], NTS_NF_RPC_EMULATE_TOTAL_LOSS_SCHEMA_XPATH"/status");
    if(SR_ERR_OK != rc) {
        return rc;
    }

    sr_val_t *values = NULL;
    size_t count = 0;
    
    rc = sr_get_items(session, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH"//.", 0, 0, &values, &count);
    if (rc != SR_ERR_OK) {
        log_error("sr_get_items failed\n");
        return rc;
    }

    network_emultation_settings_t s;
    for(size_t i = 0; i < count; i++) {
        if(strstr(values[i].xpath, "/limit")) {
            s.limit = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/delay/time")) {
            s.delay.time = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/delay/jitter")) {
            s.delay.jitter = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/delay/correlation")) {
            s.delay.correlation = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/delay/distribution")) {
            s.delay.distribution = strdup(values[i].data.string_val);
        }
        else if(strstr(values[i].xpath, "/loss")) {
            s.loss = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/corruption/percentage")) {
            s.corruption.percentage = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/corruption/correlation")) {
            s.corruption.correlation = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/duplication/percentage")) {
            s.duplication.percentage = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/duplication/correlation")) {
            s.duplication.correlation = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/reordering/percentage")) {
            s.reordering.percentage = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/reordering/correlation")) {
            s.reordering.correlation = values[i].data.uint16_val;
        }
        else if(strstr(values[i].xpath, "/rate")) {
            s.rate = values[i].data.uint16_val;
        }
    }

    uint16_t old_loss = s.loss;
    s.loss = 100;   //100 percent loss

    sr_free_values(values, count);
    if(network_emulation_update(&s) != NTS_ERR_OK) {
        log_error("network_emulation_update() failed\n");
        free(s.delay.distribution);
        return SR_ERR_OPERATION_FAILED;
    }

    int delay = input->data.uint32_val;
    int32_t sec = delay / 1000;
    uint32_t usec = (delay % 1000) * 1000;

    usleep(usec);
    if(sec > 0) {
        sleep(sec);
    }

    s.loss = old_loss;
    if(network_emulation_update(&s) != NTS_ERR_OK) {
        log_error("network_emulation_update() failed\n");
        free(s.delay.distribution);
        return SR_ERR_OPERATION_FAILED;
    }
    free(s.delay.distribution);

    rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "SUCCESS");
    return rc;
}
