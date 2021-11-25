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

#include "network_function.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/nts_utils.h"
#include <stdio.h>
#include <pthread.h>
#include <assert.h>

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <libnetconf2/netconf.h>

#include "core/framework.h"
#include "core/context.h"
#include "core/session.h"
#include "core/xpath.h"
#include "core/datastore/schema.h"
#include "core/datastore/populate.h"

#include "core/faults/faults.h"

#include "features/ves_pnf_registration/ves_pnf_registration.h"
#include "features/ves_heartbeat/ves_heartbeat.h"
#include "features/ves_file_ready/ves_file_ready.h"
#include "features/manual_notification/manual_notification.h"
#include "features/netconf_call_home/netconf_call_home.h"
#include "features/web_cut_through/web_cut_through.h"

#include "app_common.h"
#include "nf_oran_du.h"

#define NF_FUNCTION_CONTROL_BUFFER_LENGTH                       32

static int netconf_monitoring_state_schemas_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);
static int notifications_streams_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

static int network_function_populate_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);
static int network_function_feature_control_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);
static int network_function_faults_clear_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);
static int network_function_faults_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
static int network_function_faults_count_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);
static int network_function_info_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

static int network_function_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

static int faults_update_config(sr_session_ctx_t *session);                 //not protected by lock
static void *faults_thread_routine(void *arg);

static pthread_mutex_t nf_function_control_lock;
static char *nf_function_control_buffer[NF_FUNCTION_CONTROL_BUFFER_LENGTH];
static int nf_function_control_buffer_in;
static int nf_function_control_buffer_out;

static pthread_t faults_thread;
static pthread_mutex_t faults_lock;

int network_function_run(void) {
    assert_session();

    nf_function_control_buffer_in = 0;
    nf_function_control_buffer_out = 0;

    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"running as NETWORK FUNCTION daemon...\n"LOG_COLOR_RESET);

    int rc = app_common_init();
    if(rc != NTS_ERR_OK) {
        log_error("app_common_init failed\n");
        return NTS_ERR_FAILED;
    }

    if(strlen(framework_environment.nts.nf_standalone_start_features)) {
        rc = nts_utils_populate_info(session_running, framework_environment.nts.function_type);
        if(rc != NTS_ERR_OK) {
            log_error("nts_utils_populate_info failed\n");
            return NTS_ERR_FAILED;
        }
    }

    if(pthread_mutex_init(&nf_function_control_lock, NULL) != 0) { 
        log_error("mutex init has failed\n"); 
        return NTS_ERR_FAILED; 
    }

    //ietf-netconf-monitoring schemas populate with modules and submodules (overwrite default Netopeer2 behaviour)
    rc = sr_oper_get_items_subscribe(session_running, IETF_NETCONF_MONITORING_MODULE, IETF_NETCONF_MONITORING_STATE_SCHEMAS_SCHEMA_XPATH, netconf_monitoring_state_schemas_cb, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_oper_get_items_subscribe: %s\n", sr_strerror(rc));
        return 0;
    }

    //nc-notifications overwrite
    rc = sr_oper_get_items_subscribe(session_running, NC_NOTIFICATIONS_MODULE, NC_NOTIFICATIONS_STREAMS_SCHEMA_XPATH, notifications_streams_cb, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_oper_get_items_subscribe: %s\n", sr_strerror(rc));
        return 0;
    }

    //populate
    rc = sr_rpc_subscribe(session_running, NTS_NF_RPC_POPULATE_SCHEMA_XPATH, network_function_populate_cb, 0, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_rpc_subscribe: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    //feature control
    rc = sr_rpc_subscribe(session_running, NTS_NF_RPC_FEATURE_CONTROL_SCHEMA_XPATH, network_function_feature_control_cb, 0, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_rpc_subscribe: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    //faults
    rc = sr_module_change_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, NTS_NF_FAULT_GENERATION_SCHEMA_XPATH, network_function_faults_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to faults");
        return NTS_ERR_FAILED;
    }

    rc = sr_oper_get_items_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, NTS_NF_FAULT_COUNT_LIST_SCHEMA_XPATH, network_function_faults_count_get_items_cb, NULL, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to oper faults: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    rc = sr_rpc_subscribe(session_running, NTS_NF_RPC_FAULTS_CLEAR_SCHEMA_XPATH, network_function_faults_clear_cb, 0, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_rpc_subscribe: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    rc = sr_oper_get_items_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, NTS_NF_INFO_SCHEMA_XPATH, network_function_info_get_items_cb, NULL, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_OPER_MERGE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to oper started-features: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    //subscribe to any changes on the main
    rc = sr_module_change_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, NTS_NF_NETWORK_FUNCTION_SCHEMA_XPATH, network_function_change_cb, NULL, 1, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_UPDATE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to simulation changes: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    rc = faults_init();
    if(rc != NTS_ERR_OK) {
        log_error("faults_init error\n");
        return NTS_ERR_FAILED;
    }

    if(pthread_mutex_init(&faults_lock, NULL) != 0) { 
        log_error("mutex init has failed\n"); 
        return NTS_ERR_FAILED; 
    }

    if(pthread_create(&faults_thread, 0, faults_thread_routine, 0)) {
        log_error("could not create thread for heartbeat\n");
        return NTS_ERR_FAILED;
    }

    //check standalone mode
    if(strlen(framework_environment.nts.nf_standalone_start_features)) {
        char *start_features = 0;

        asprintf(&start_features, "1 %s", framework_environment.nts.nf_standalone_start_features);
        nf_function_control_buffer[nf_function_control_buffer_in] = start_features;
        nf_function_control_buffer_in++;
        if(nf_function_control_buffer_in >= NF_FUNCTION_CONTROL_BUFFER_LENGTH) {
            nf_function_control_buffer_in = 0;
        }

        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"running in NETWORK FUNCTION STANDALONE mode!\n"LOG_COLOR_RESET);
        log_add_verbose(1, "Currently enabled features are: %s\n", framework_environment.nts.nf_standalone_start_features);
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"Docker IP:"LOG_COLOR_RESET" %s\n", framework_environment.settings.ip_v6_enabled ? framework_environment.settings.ip_v6 : framework_environment.settings.ip_v4);
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"Docker ports"LOG_COLOR_RESET": ");
        if(framework_environment.settings.ssh_connections) {
            log_add(1, "NETCONF SSH: %d (%d)", STANDARD_NETCONF_PORT, framework_environment.settings.ssh_connections);
        }
        else {
            log_add(1, "NETCONF SSH: disabled");
        }
        if(framework_environment.settings.tls_connections) {
            log_add(1, " | NETCONF TLS: %d (%d)", STANDARD_NETCONF_PORT + framework_environment.settings.ssh_connections, framework_environment.settings.tls_connections);
        }
        else {
            log_add(1, " | NETCONF TLS: disabled");
        }
        if(framework_environment.settings.ftp_connections) {
            log_add(1, " | FTP: %d (%d)", STANDARD_FTP_PORT, framework_environment.settings.ftp_connections);
        }
        else {
            log_add(1, " | FTP: disabled");
        }
        if(framework_environment.settings.sftp_connections) {
            log_add(1, " | SFTP: %d (%d)", STANDARD_SFTP_PORT, framework_environment.settings.sftp_connections);
        }
        else {
            log_add(1, " | SFTP: disabled");
        }
        log_add(1,"\n");
    }

    if(strcmp(framework_environment.nts.function_type, "NTS_FUNCTION_TYPE_O_RAN_O_DU") == 0) {
        rc = nf_oran_du_init();
        if(rc != NTS_ERR_OK) {
            log_error("nf_oran_du_init failed\n"); 
            return NTS_ERR_FAILED; 
        }
    }

    while(!framework_sigint) {
        pthread_mutex_lock(&nf_function_control_lock);
        while(nf_function_control_buffer_in != nf_function_control_buffer_out) {
            //get current function control string
            char *nf_function_control_string = nf_function_control_buffer[nf_function_control_buffer_out];
            nf_function_control_buffer_out++;
            if(nf_function_control_buffer_out >= NF_FUNCTION_CONTROL_BUFFER_LENGTH) {
                nf_function_control_buffer_out = 0;
            }

            if(strstr(nf_function_control_string, "datastore-populate") != 0) {
                rc = datastore_populate_all();
                if(rc != NTS_ERR_OK) {
                    log_error("datastore_populate_all() failed\n");
                }

                //subscribe to any changes so the operational is dynamic
                char **xpaths = 0;
                char **modules = 0;
                int xpaths_count = datastore_schema_get_running_xpaths(&xpaths, &modules);
                if(xpaths_count < 0) {
                    log_error("datastore_schema_get_running_xpaths failed\n");
                    return NTS_ERR_FAILED;
                }

                for(int i = 0; i < xpaths_count; i++) {
                    //subscribe
                    log_add_verbose(1, "subscribing to %s on module %s... ", xpaths[i], modules[i]);
                    rc = sr_module_change_subscribe(session_running, modules[i], xpaths[i], datastore_dynamic_operational_auto_callback, 0, 0, SR_SUBSCR_DONE_ONLY | SR_SUBSCR_CTX_REUSE, &session_subscription);
                    if(rc != SR_ERR_OK) {
                        log_error("sr_module_change_subscribe error\n");
                    }
                    else {
                        log_add(1, "done\n");
                    }

                    free(xpaths[i]);
                    free(modules[i]);
                }
                free(modules);
                free(xpaths);
            }

            if(strstr(nf_function_control_string, "ves-file-ready") != 0) {
                if(nf_function_control_string[0] == '1') {
                    // start feature for handling the fileReady VES message
                    rc = ves_file_ready_feature_start(session_running);
                    if(rc != 0) {
                        log_error("ves_file_ready_feature_start() failed\n");
                    }
                }
                else if(nf_function_control_string[0] == '0') {
                    // stop feature for handling the fileReady VES message
                    rc = ves_file_ready_feature_stop();
                    if(rc != 0) {
                        log_error("ves_file_ready_feature_stop() failed\n");
                    }
                }
            }

            if(strstr(nf_function_control_string, "ves-pnf-registration") != 0) {
                if(nf_function_control_string[0] == '1') {
                    // check if PNF registration is enabled and send PNF registration message if so
                    rc = ves_pnf_registration_feature_start(session_running);
                    if(rc != 0) {
                        log_error("ves_pnf_registration_feature_start() failed\n");
                    }
                }
            }

            if(strstr(nf_function_control_string, "ves-heartbeat") != 0) {
                if(nf_function_control_string[0] == '1') {
                    // start feature for handling the heartbeat VES message
                    rc = ves_heartbeat_feature_start(session_running);
                    if(rc != 0) {
                        log_error("ves_heartbeat_feature_start() failed\n");
                    }
                }
                else if(nf_function_control_string[0] == '0') {
                    // stop feature for handling the heartbeat VES message
                    rc = ves_heartbeat_feature_stop();
                    if(rc != 0) {
                        log_error("ves_heartbeat_feature_stop() failed\n");
                    }
                }
            }

            if(strstr(nf_function_control_string, "manual-notification-generation") != 0) {
                if(nf_function_control_string[0] == '1') {
                    // start feature for manual notification
                    rc = manual_notification_feature_start(session_running);
                    if(rc != 0) {
                        log_error("manual_notification_feature_start() failed\n");
                    }
                }
                else if(nf_function_control_string[0] == '0') {
                    // stop feature for manual notification
                    rc = manual_notification_feature_stop();
                    if(rc != 0) {
                        log_error("manual_notification_feature_stop() failed\n");
                    }
                }
            }

            if(strstr(nf_function_control_string, "netconf-call-home") != 0) {
                if(nf_function_control_string[0] == '1') {
                    // start feature for NETCONF Call Home
                    rc = netconf_call_home_feature_start(session_running);
                    if(rc != 0) {
                        log_error("netconf_call_home_feature_start() failed\n");
                    }
                }
            }

            if(strstr(nf_function_control_string, "web-cut-through") != 0) {
                if(nf_function_control_string[0] == '1') {
                    // start feature for web cut-through
                    rc = web_cut_through_feature_start(session_running);
                    if(rc != 0) {
                        log_error("web_cut_through_feature_start() failed\n");
                    }
                }
                else if(nf_function_control_string[0] == '0') {
                    // stop feature for web cut-through
                    rc = web_cut_through_feature_stop(session_running);
                    if(rc != 0) {
                        log_error("web_cut_through_feature_stop() failed\n");
                    }
                }
            }

            free(nf_function_control_string);
            nf_function_control_string = 0;
        }
        pthread_mutex_unlock(&nf_function_control_lock);

        sleep(1);
    }

    faults_free();
    nf_oran_du_free();

    return NTS_ERR_OK;
}

static int netconf_monitoring_state_schemas_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data) {
    struct lyd_node *root = 0;
    root = lyd_new_path(*parent, session_context, IETF_NETCONF_MONITORING_STATE_SCHEMAS_SCHEMA_XPATH, 0, 0, 0);

    struct lyd_node *list = 0;
    const struct lys_module *mod = 0;
    const struct lys_submodule *submod = 0;
    uint32_t i = 0;

    // get all modules from context
    while ((mod = ly_ctx_get_module_iter(session_context, &i))) {
        // we skip the internal sysrepo modules
        if (!strcmp("sysrepo", mod->name) || !strcmp("sysrepo-monitoring", mod->name) || !strcmp("sysrepo-plugind", mod->name)) {
            continue;
        }
        
        list = lyd_new(root, NULL, "schema");
        lyd_new_leaf(list, NULL, "identifier", mod->name);
        lyd_new_leaf(list, NULL, "version", (mod->rev ? mod->rev[0].date : NULL));
        lyd_new_leaf(list, NULL, "format", "yang");
        lyd_new_leaf(list, NULL, "namespace", lys_main_module(mod)->ns);
        lyd_new_leaf(list, NULL, "location", "NETCONF");

        // iterate all the submodules included by a module
        for (int j = 0; j < mod->inc_size; j++) {
            submod = mod->inc[j].submodule;

            list = lyd_new(root, NULL, "schema");
            lyd_new_leaf(list, NULL, "identifier", submod->name);
            lyd_new_leaf(list, NULL, "version", (submod->rev ? submod->rev[0].date : NULL));
            lyd_new_leaf(list, NULL, "format", "yang");
            lyd_new_leaf(list, NULL, "namespace", lys_main_module(mod)->ns);
            lyd_new_leaf(list, NULL, "location", "NETCONF");
        }
    }

    return SR_ERR_OK;
}

static int notifications_streams_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data) {
    struct lyd_node *root = lyd_new_path(0, session_context, NC_NOTIFICATIONS_STREAMS_SCHEMA_XPATH, 0, 0, 0);

    /* generic stream */
    struct lyd_node *stream = lyd_new_path(root, 0, NC_NOTIFICATIONS_STREAMS_SCHEMA_XPATH"/stream[name='NETCONF']", NULL, 0, 0);
    lyd_new_leaf(stream, stream->schema->module, "description", "Default NETCONF stream containing notifications from all the modules. Replays only notifications for modules that support replay.");
    lyd_new_leaf(stream, stream->schema->module, "replaySupport", "true");
    
    /* all other streams */
    struct lyd_node *sr_data;
    struct lyd_node *sr_mod;
     /* go through all the sysrepo modules */
    int rc = sr_get_module_info(session_connection, &sr_data);
    if(rc != SR_ERR_OK) {
        log_error("sr_get_module_info failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    LY_TREE_FOR(sr_data->child, sr_mod) {
        const char *mod_name = ((struct lyd_node_leaf_list *)sr_mod->child)->value_str;
        const struct lys_module *mod = ly_ctx_get_module(session_context, mod_name, 0, 1);
        int has_notifications = 0;
        struct lys_node *data = mod->data;
        while(data) {
            if(data->nodetype == LYS_NOTIF) {
                has_notifications = 1;
            }
            data = data->next;
        }

        if(has_notifications) {
            /* generate information about the stream/module */
            stream = lyd_new(root->child, NULL, "stream");
            lyd_new_leaf(stream, NULL, "name", mod_name);
            lyd_new_leaf(stream, NULL, "description", "Stream with all notifications of a module.");

            struct lyd_node *rep_sup = 0;
            struct ly_set *set = lyd_find_path(sr_mod, "replay-support");
            if(set && (set->number == 1)) {
                rep_sup = set->set.d[0];
            }
            ly_set_free(set);
            
            lyd_new_leaf(stream, NULL, "replaySupport", rep_sup ? "true" : "false");
            if(rep_sup) {
                char buf[26];
                nc_time2datetime(((struct lyd_node_leaf_list *)rep_sup)->value.uint64, NULL, buf);
                lyd_new_leaf(stream, NULL, "replayLogCreationTime", buf);
            }
        }
    }

    lyd_free_withsiblings(sr_data);
    *parent = root;

    return SR_ERR_OK;
}

static int network_function_populate_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {
    int rc;

    *output_cnt = 1;
    rc = sr_new_values(*output_cnt, output);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(output[0], NTS_NF_RPC_POPULATE_SCHEMA_XPATH"/status");
    if(SR_ERR_OK != rc) {
        return rc;
    }

    pthread_mutex_lock(&nf_function_control_lock);
    nf_function_control_buffer[nf_function_control_buffer_in] = strdup("datastore-populate");
    nf_function_control_buffer_in++;
    if(nf_function_control_buffer_in >= NF_FUNCTION_CONTROL_BUFFER_LENGTH) {
        nf_function_control_buffer_in = 0;
    }
    pthread_mutex_unlock(&nf_function_control_lock);

    rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "SUCCESS");
    return rc;
}

static int network_function_feature_control_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {
    int rc;
    int total_errors = 0;

    char start_features[16][64];
    int start_features_cnt = 0;

    char stop_features[16][64];
    int stop_features_cnt = 0;

    char *start_input = 0;
    char *stop_input = 0;

    for(int i = 0; i < input_cnt; i++) {
        if(input[i].data.bits_val == 0) {
            continue;
        }

        char *val = strdup(input[i].data.bits_val);

        if(strstr(input[i].xpath, "start")) {
            start_input = input[i].data.bits_val;

            const char *tok = " ";
            char *token = strtok(val, tok);
            while(token) {
                strcpy(start_features[start_features_cnt++], token);
                token = strtok(0, tok);
            }
        }

        if(strstr(input[i].xpath, "stop")) {
            stop_input = input[i].data.bits_val;

            const char *tok = " ";
            char *token = strtok(val, tok);
            while(token) {
                strcpy(stop_features[stop_features_cnt++], token);
                token = strtok(0, tok);
            }
        }

        free(val);
    }

    for(int i = 0; i < start_features_cnt; i++) {
        for(int j = 0; j < stop_features_cnt; j++) {
            if(strcmp(start_features[i], stop_features[j]) == 0) {
                total_errors++;
            }
        }
    }

    *output_cnt = 1;
    rc = sr_new_values(*output_cnt, output);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(output[0], NTS_NF_RPC_FEATURE_CONTROL_SCHEMA_XPATH"/status");
    if(SR_ERR_OK != rc) {
        return rc;
    }

    if(total_errors != 0) {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "ERROR");
    }
    else {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "SUCCESS");

        pthread_mutex_lock(&nf_function_control_lock);
        if(start_features_cnt) {
            asprintf(&nf_function_control_buffer[nf_function_control_buffer_in], "1 %s", start_input);
            nf_function_control_buffer_in++;
            if(nf_function_control_buffer_in >= NF_FUNCTION_CONTROL_BUFFER_LENGTH) {
                nf_function_control_buffer_in = 0;
            }
        }

        if(stop_features_cnt) {
            asprintf(&nf_function_control_buffer[nf_function_control_buffer_in], "0 %s", stop_input);
            nf_function_control_buffer_in++;
            if(nf_function_control_buffer_in >= NF_FUNCTION_CONTROL_BUFFER_LENGTH) {
                nf_function_control_buffer_in = 0;
            }
        }
        pthread_mutex_unlock(&nf_function_control_lock);
    }

    

    return rc;
}

static int network_function_faults_clear_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {
    int rc;

    *output_cnt = 1;
    rc = sr_new_values(*output_cnt, output);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(output[0], NTS_NF_RPC_FAULTS_CLEAR_SCHEMA_XPATH"/status");
    if(SR_ERR_OK != rc) {
        return rc;
    }

    pthread_mutex_lock(&faults_lock);
    faults_counters_clear();
    pthread_mutex_unlock(&faults_lock);

    rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "SUCCESS");
    return rc;
}

static int network_function_faults_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    int rc = SR_ERR_OK;

    if(event == SR_EV_DONE) {
        pthread_mutex_lock(&faults_lock);
        rc = faults_update_config(session);
        pthread_mutex_unlock(&faults_lock);
        if(rc != NTS_ERR_OK) {
            log_error("faults_update_config failed\n");
            return SR_ERR_VALIDATION_FAILED;
        }
    }

    return SR_ERR_OK;
}

static int network_function_faults_count_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data) {
    pthread_mutex_lock(&faults_lock);
    fault_counters_t counters = faults_counters_get();
    pthread_mutex_unlock(&faults_lock);
    char value[20];

    *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), NTS_NF_FAULT_COUNT_LIST_SCHEMA_XPATH, 0, 0, 0);
    if(*parent == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.normal);
    if(lyd_new_path(*parent, NULL, NTS_NF_FAULT_COUNT_LIST_SCHEMA_XPATH"/normal", value, 0, 0) == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.warning);
    if(lyd_new_path(*parent, NULL, NTS_NF_FAULT_COUNT_LIST_SCHEMA_XPATH"/warning", value, 0, 0) == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.minor);
    if(lyd_new_path(*parent, NULL, NTS_NF_FAULT_COUNT_LIST_SCHEMA_XPATH"/minor", value, 0, 0) == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.major);
    if(lyd_new_path(*parent, NULL, NTS_NF_FAULT_COUNT_LIST_SCHEMA_XPATH"/major", value, 0, 0) == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.critical);
    if(lyd_new_path(*parent, NULL, NTS_NF_FAULT_COUNT_LIST_SCHEMA_XPATH"/critical", value, 0, 0) == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    return SR_ERR_OK;
}

static int network_function_info_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data) {
    char started_features[1024];
    started_features[0] = 0;

    if(ves_file_ready_feature_get_status()) {
        strcat(started_features, "ves-file-ready ");
    }
    
    if(ves_pnf_registration_feature_get_status()) {
        strcat(started_features, "ves-pnf-registration ");
    }

    if(ves_heartbeat_feature_get_status()) {
        strcat(started_features, "ves-heartbeat ");
    }
    
    if(manual_notification_feature_get_status()) {
        strcat(started_features, "manual-notification-generation ");
    }

    if(netconf_call_home_feature_get_status()) {
        strcat(started_features, "netconf-call-home ");
    }
    
    if(web_cut_through_feature_get_status()) {
        strcat(started_features, "web-cut-through ");
    }
    
    if(strlen(started_features)) {
        started_features[strlen(started_features) - 1] = 0;
    }

    *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), NTS_NF_INFO_SCHEMA_XPATH, 0, 0, 0);
    if(*parent == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    struct lyd_node *n = lyd_new_leaf(*parent, (*parent)->schema->module, "started-features", started_features);
    if(n == 0) {
        log_error("lyd_new_leaf failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    return SR_ERR_OK;
}

static int faults_update_config(sr_session_ctx_t *session) {
    assert(session);
    assert_session();

    int ret = NTS_ERR_OK;
    
    int rc;
    struct lyd_node *data;
    rc = sr_get_subtree(session, NTS_NF_FAULT_GENERATION_SCHEMA_XPATH, 0, &data);
    if(rc != SR_ERR_OK) {
        log_error("sr_get_subtree failed\n");
        return NTS_ERR_FAILED;
    }

    faults_fault_list_clear();
    if(data == 0) {
        return NTS_ERR_OK;
    }

    if(data->child == 0) {
        goto faults_update_config_free;
    }

    struct lyd_node *chd = 0;
    LY_TREE_FOR(data->child, chd) {
        if(strcmp(chd->schema->name, "fault-delay-list") == 0) {
            struct lyd_node *delay_list_entry = 0;
            LY_TREE_FOR(chd->child, delay_list_entry) {
                if(strcmp(delay_list_entry->schema->name, "delay-period") == 0) {
                    rc = faults_fault_list_add(((const struct lyd_node_leaf_list *)delay_list_entry)->value.uint16);
                    if(rc != NTS_ERR_OK) {
                        log_error("faults_fault_list_add failed\n");
                        ret = NTS_ERR_FAILED;
                        goto faults_update_config_free;
                    }
                }
            }
        }
        
    }
    
    faults_update_config_free:
    lyd_free(data);

    return ret;
}

static void *faults_thread_routine(void *arg) {
    int rc = 0;

    sr_session_ctx_t *current_session_running = 0;
    rc = sr_session_start(session_connection, SR_DS_RUNNING, &current_session_running);
    if (rc != SR_ERR_OK) {
        log_error("sr_session_start failed\n");
        return 0;
    }

    sr_session_ctx_t *current_session_operational = 0;
    rc = sr_session_start(session_connection, SR_DS_OPERATIONAL, &current_session_operational);
    if (rc != SR_ERR_OK) {
        log_error("sr_session_start failed\n");
        return 0;
    }

    pthread_mutex_lock(&faults_lock);
    rc = faults_update_config(current_session_running);
    if(rc != NTS_ERR_OK) {
        log_error("faults_update_config failed\n");
        return 0;
    }
    pthread_mutex_unlock(&faults_lock);

    while(!framework_sigint) {
        pthread_mutex_lock(&faults_lock);
        if(faults_fault_list_not_empty()) {
            uint16_t new_delay = faults_fault_list_get_next();

            fault_details_t *fault = faults_generate_fault();
            if(fault == 0) {
                log_error("faults_generate_fault failed\n");
                pthread_mutex_unlock(&faults_lock);
                sleep(1);
                continue;
            }

            rc = faults_counters_increase(fault->severity);
            if(rc != NTS_ERR_OK) {
                log_error("faults_counters_increase failed\n");
            }
            pthread_mutex_unlock(&faults_lock);

            sr_val_t *val = 0;
            bool nc_fault_enabled = false;
            bool ves_fault_enabled = false;

            rc = sr_get_item(current_session_running, NTS_NF_NETCONF_FAULTS_ENABLED_SCHEMA_PATH, 0, &val);
            if(rc == SR_ERR_OK) {
                nc_fault_enabled = val->data.bool_val;
                sr_free_val(val);
            }

            rc = sr_get_item(current_session_running, NTS_NF_VES_FAULTS_ENABLED_SCHEMA_XPATH, 0, &val);
            if(rc == SR_ERR_OK) {
                ves_fault_enabled = val->data.bool_val;
                sr_free_val(val);
            }

            if(nc_fault_enabled) {
                struct lyd_node *notif = 0;
                log_add_verbose(1, "[faults] notification is '%s'\n", fault->yang_notif_processed);
                notif = lyd_parse_mem(session_context, fault->yang_notif_processed, LYD_XML, LYD_OPT_NOTIF, 0);
                if(notif == 0) {
                    log_error("lyd_parse_mem failed\n");
                    goto fault_send_ves;
                }
                
                rc = sr_event_notif_send_tree(current_session_running, notif);
                lyd_free(notif);
                if(rc != SR_ERR_OK) {
                    log_error("sr_event_notif_send_tree failed\n");
                }
            }

            fault_send_ves:
            if(ves_fault_enabled) {
                rc = faults_ves_message_send(current_session_running, fault->condition, fault->object, fault->severity, fault->date_time, fault->specific_problem);
                if(rc != NTS_ERR_OK) {
                    log_error("faults_ves_message_send failed\n");
                }
            }

            log_add_verbose(1, "[faults] delaying %d sec\n", new_delay);
            sleep(new_delay);
        }
        else {
            pthread_mutex_unlock(&faults_lock);
            sleep(1);
        }
    }

    sr_session_stop(current_session_running);
    sr_session_stop(current_session_operational);

    return 0;
}

static int network_function_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    sr_change_iter_t *it = 0;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = 0;
    sr_val_t *new_value = 0;

    if(event == SR_EV_UPDATE) {
        rc = sr_get_changes_iter(session, NTS_NF_NETWORK_FUNCTION_SCHEMA_XPATH"//.", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed\n");
            return SR_ERR_VALIDATION_FAILED;
        }

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            
            if(new_value->xpath && (strcmp(new_value->xpath, NTS_NF_NETWORK_FUNCTION_FTYPE_SCHEMA_XPATH) == 0)) {
                if(old_value && !old_value->dflt) {
                    rc = sr_set_item(session, old_value->xpath, old_value, 0);
                    if(rc != SR_ERR_OK) {
                        log_error("sr_set_item failed\n");
                        return SR_ERR_VALIDATION_FAILED;
                    }
                }
            }

            if(new_value->xpath && (strcmp(new_value->xpath, NTS_NF_NETWORK_FUNCTION_MPAM_SCHEMA_XPATH) == 0)) {
                if(old_value && !old_value->dflt) {
                    rc = sr_set_item(session, old_value->xpath, old_value, 0);
                    if(rc != SR_ERR_OK) {
                        log_error("sr_set_item failed\n");
                        return SR_ERR_VALIDATION_FAILED;
                    }
                }
            }

            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);
    }

    return SR_ERR_OK;
}
