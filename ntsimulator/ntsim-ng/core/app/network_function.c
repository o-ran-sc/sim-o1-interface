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
#include <stdio.h>
#include <pthread.h>
#include <assert.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#include "core/framework.h"
#include "core/context.h"
#include "core/session.h"
#include "core/datastore/populate.h"

#include "core/faults/faults.h"

#include "features/ves_pnf_registration/ves_pnf_registration.h"
#include "features/ves_heartbeat/ves_heartbeat.h"
#include "features/ves_file_ready/ves_file_ready.h"
#include "features/manual_notification/manual_notification.h"
#include "features/netconf_call_home/netconf_call_home.h"
#include "features/web_cut_through/web_cut_through.h"

#define NTS_NETWORK_FUNCTION_MODULE         "nts-network-function"
#define NTS_NETWORK_FUNCTION_SCHEMA_XPATH   "/nts-network-function:simulation/network-function"

#define POPULATE_RPC_SCHEMA_XPATH           "/nts-network-function:datastore-random-populate"
#define FEATURE_CONTROL_SCHEMA_XPATH        "/nts-network-function:feature-control"
#define FAULTS_CLEAR_SCHEMA_XPATH           "/nts-network-function:clear-fault-counters"
#define FAULTS_LIST_SCHEMA_XPATH            "/nts-network-function:simulation/network-function/fault-generation"
#define FAULTS_COUNT_LIST_SCHEMA_XPATH      "/nts-network-function:simulation/network-function/fault-generation/fault-count"
#define FAULTS_NC_ENABLED_SCHEMA_XPATH      "/nts-network-function:simulation/network-function/netconf/faults-enabled"
#define FAULTS_VES_ENABLED_SCHEMA_XPATH     "/nts-network-function:simulation/network-function/ves/faults-enabled"

static int network_function_populate_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);
static int network_function_feature_control_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);
static int network_function_faults_clear_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);
static int network_function_faults_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
static int network_function_faults_count_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

static int network_function_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

static int faults_update_config(sr_session_ctx_t *session);                 //not protected by lock
static void *faults_thread_routine(void *arg);

static pthread_mutex_t nf_function_control_lock;
static char *nf_function_control_string = 0;

static pthread_t faults_thread;
static pthread_mutex_t faults_lock;

static pthread_mutex_t mount_point_addressing_method_lock;
static char *mount_point_addressing_method_default = 0;
static char *mount_point_addressing_method_val = 0;

int network_function_run(void) {
    assert_session();

    log_message(1, LOG_COLOR_BOLD_YELLOW"\nrunning as NETWORK FUNCTION daemon...\n"LOG_COLOR_RESET);

    if(pthread_mutex_init(&nf_function_control_lock, NULL) != 0) { 
        log_error("mutex init has failed"); 
        return NTS_ERR_FAILED; 
    }

    //populate
    int rc = sr_rpc_subscribe(session_running, POPULATE_RPC_SCHEMA_XPATH, network_function_populate_cb, 0, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_rpc_subscribe: %s", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    //feature control
    rc = sr_rpc_subscribe(session_running, FEATURE_CONTROL_SCHEMA_XPATH, network_function_feature_control_cb, 0, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_rpc_subscribe: %s", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    //faults
    rc = sr_module_change_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, FAULTS_LIST_SCHEMA_XPATH, network_function_faults_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to faults");
        return 0;
    }

    rc = sr_oper_get_items_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, FAULTS_COUNT_LIST_SCHEMA_XPATH, network_function_faults_count_get_items_cb, NULL, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to oper faults: %s", sr_strerror(rc));
        return 0;
    }

    rc = sr_rpc_subscribe(session_running, FAULTS_CLEAR_SCHEMA_XPATH, network_function_faults_clear_cb, 0, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_rpc_subscribe: %s", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    //subscribe to any changes on the main
    rc = sr_module_change_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, NTS_NETWORK_FUNCTION_SCHEMA_XPATH, network_function_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to simulation changes");
        return NTS_ERR_FAILED;
    }

    rc = faults_init();
    if(rc != NTS_ERR_OK) {
        log_error("faults_init error", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    if(pthread_mutex_init(&faults_lock, NULL) != 0) { 
        log_error("mutex init has failed"); 
        return NTS_ERR_FAILED; 
    }

    if(pthread_create(&faults_thread, 0, faults_thread_routine, 0)) {
        log_error("could not create thread for heartbeat");
        return NTS_ERR_FAILED;
    }

    if(pthread_mutex_init(&mount_point_addressing_method_lock, NULL) != 0) { 
        log_error("mutex init has failed"); 
        return NTS_ERR_FAILED; 
    }

    while(!framework_sigint) {
        pthread_mutex_lock(&mount_point_addressing_method_lock);
        if(mount_point_addressing_method_val) {
            rc = sr_set_item_str(session_running, NTS_NETWORK_FUNCTION_SCHEMA_XPATH"/mount-point-addressing-method", mount_point_addressing_method_val, 0, 0);
            if(rc != SR_ERR_OK) {
                log_error("sr_set_item_str failed");
            }

            rc = sr_apply_changes(session_running, 0, 0);
            if(rc != SR_ERR_OK) {
                log_error("sr_apply_changes failed");
            }

            mount_point_addressing_method_val = 0;
        }
        pthread_mutex_unlock(&mount_point_addressing_method_lock);

        pthread_mutex_lock(&nf_function_control_lock);
        if(nf_function_control_string) {
            if(strstr(nf_function_control_string, "ves-file-ready") != 0) {
                // start feature for handling the fileReady VES message
                rc = ves_file_ready_feature_start(session_running);
                if(rc != 0) {
                    log_error("ves_file_ready_feature_start() failed");
                }
            }

            if(strstr(nf_function_control_string, "ves-pnf-registration") != 0) {
                // check if PNF registration is enabled and send PNF registration message if so
                rc = ves_pnf_registration_feature_start(session_running);
                if(rc != 0) {
                    log_error("ves_pnf_registration_feature_start() failed");
                }
            }

            if(strstr(nf_function_control_string, "ves-heartbeat") != 0) {
                // start feature for handling the heartbeat VES message
                rc = ves_heartbeat_feature_start(session_running);
                if(rc != 0) {
                    log_error("ves_heartbeat_feature_start() failed");
                }
            }

            if(strstr(nf_function_control_string, "manual-notification-generation") != 0) {
                // start feature for manual notification
                rc = manual_notification_feature_start(session_running);
                if(rc != 0) {
                    log_error("manual_notification_feature_start() failed");
                }
            }

            if(strstr(nf_function_control_string, "netconf-call-home") != 0) {
                // start feature for NETCONF Call Home
                rc = netconf_call_home_feature_start(session_running);
                if(rc != 0) {
                    log_error("netconf_call_home_feature_start() failed");
                }
            }

            if(strstr(nf_function_control_string, "web-cut-through") != 0) {
                // start feature for NETCONF Call Home
                rc = web_cut_through_feature_start(session_running);
                if(rc != 0) {
                    log_error("web_cut_through_feature_start() failed");
                }
            }

            free(nf_function_control_string);
            nf_function_control_string = 0;
        }
        pthread_mutex_unlock(&nf_function_control_lock);

        sleep(1);
    }

    faults_free();

    return NTS_ERR_OK;
}

static int network_function_populate_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {
    int rc;

    *output_cnt = 1;
    rc = sr_new_values(*output_cnt, output);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(output[0], POPULATE_RPC_SCHEMA_XPATH"/status");
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = schema_populate();
    if(rc != NTS_ERR_OK) {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "ERROR");
    }
    else {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "SUCCESS");
    }

    return rc;
}

static int network_function_feature_control_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {
    int rc;
    int total_errors = 0;

    *output_cnt = 1;
    rc = sr_new_values(*output_cnt, output);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(output[0], FEATURE_CONTROL_SCHEMA_XPATH"/status");
    if(SR_ERR_OK != rc) {
        return rc;
    }

    if(total_errors != 0) {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "ERROR");
    }
    else {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "SUCCESS");
    }

    pthread_mutex_lock(&nf_function_control_lock);
    nf_function_control_string = strdup(input[0].data.bits_val);
    pthread_mutex_unlock(&nf_function_control_lock);

    return rc;
}

static int network_function_faults_clear_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {
    int rc;

    *output_cnt = 1;
    rc = sr_new_values(*output_cnt, output);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(output[0], FAULTS_CLEAR_SCHEMA_XPATH"/status");
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
            log_error("faults_update_config failed");
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

    *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), FAULTS_COUNT_LIST_SCHEMA_XPATH, 0, 0, 0);
    if(*parent == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.normal);
    if(lyd_new_path(*parent, NULL, FAULTS_COUNT_LIST_SCHEMA_XPATH"/normal", value, 0, 0) == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.warning);
    if(lyd_new_path(*parent, NULL, FAULTS_COUNT_LIST_SCHEMA_XPATH"/warning", value, 0, 0) == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.minor);
    if(lyd_new_path(*parent, NULL, FAULTS_COUNT_LIST_SCHEMA_XPATH"/minor", value, 0, 0) == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.major);
    if(lyd_new_path(*parent, NULL, FAULTS_COUNT_LIST_SCHEMA_XPATH"/major", value, 0, 0) == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", counters.critical);
    if(lyd_new_path(*parent, NULL, FAULTS_COUNT_LIST_SCHEMA_XPATH"/critical", value, 0, 0) == 0) {
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
    rc = sr_get_subtree(session, FAULTS_LIST_SCHEMA_XPATH, 0, &data);
    if(rc != SR_ERR_OK) {
        log_error("sr_get_subtree failed");
        ret = NTS_ERR_FAILED;
    }

    faults_fault_list_clear();
    faults_counters_clear();
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
                        log_error("faults_fault_list_add failed");
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
        log_error("sr_session_start failed");
        return 0;
    }

    sr_session_ctx_t *current_session_operational = 0;
    rc = sr_session_start(session_connection, SR_DS_OPERATIONAL, &current_session_operational);
    if (rc != SR_ERR_OK) {
        log_error("sr_session_start failed");
        return 0;
    }

    pthread_mutex_lock(&faults_lock);
    rc = faults_update_config(current_session_running);
    if(rc != NTS_ERR_OK) {
        log_error("faults_update_config failed");
        return 0;
    }
    pthread_mutex_unlock(&faults_lock);

    while(!framework_sigint) {
        pthread_mutex_lock(&faults_lock);
        if(faults_fault_list_not_empty()) {
            uint16_t new_delay = faults_fault_list_get_next();

            fault_details_t *fault = faults_generate_fault();
            if(fault == 0) {
                log_error("faults_generate_fault failed");
                pthread_mutex_unlock(&faults_lock);
                sleep(1);
                continue;
            }

            rc = faults_counters_increase(fault->severity);
            if(rc != NTS_ERR_OK) {
                log_error("faults_counters_increase failed");
            }
            pthread_mutex_unlock(&faults_lock);

            sr_val_t *val = 0;
            bool nc_fault_enabled = false;
            bool ves_fault_enabled = false;

            rc = sr_get_item(current_session_running, FAULTS_NC_ENABLED_SCHEMA_XPATH, 0, &val);
            if(rc == SR_ERR_OK) {
                nc_fault_enabled = val->data.bool_val;
                sr_free_val(val);
            }

            rc = sr_get_item(current_session_running, FAULTS_VES_ENABLED_SCHEMA_XPATH, 0, &val);
            if(rc == SR_ERR_OK) {
                ves_fault_enabled = val->data.bool_val;
                sr_free_val(val);
            }

            if(nc_fault_enabled) {
                struct lyd_node *notif = 0;
                notif = lyd_parse_mem(session_context, fault->yang_notif_processed, LYD_XML, LYD_OPT_NOTIF, 0);
                if(notif == 0) {
                    log_error("lyd_parse_mem failed");
                    goto fault_send_ves;
                }
                
                rc = sr_event_notif_send_tree(current_session_running, notif);
                lyd_free(notif);
                if(rc != SR_ERR_OK) {
                    log_error("sr_event_notif_send_tree failed");
                }
            }

            fault_send_ves:
            if(ves_fault_enabled) {
                rc = faults_ves_message_send(current_session_running, fault->condition, fault->object, fault->severity, fault->date_time, fault->specific_problem);
                if(rc != NTS_ERR_OK) {
                    log_error("faults_ves_message_send failed");
                }
            }

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

    static bool mount_point_addressing_method_set = false;

    if(event == SR_EV_DONE) {
        rc = sr_get_changes_iter(session, NTS_NETWORK_FUNCTION_SCHEMA_XPATH"//.", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed");
            return SR_ERR_VALIDATION_FAILED;
        }

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            if(new_value->xpath && (strcmp(new_value->xpath, NTS_NETWORK_FUNCTION_SCHEMA_XPATH"/mount-point-addressing-method") == 0)) {
                if(mount_point_addressing_method_set == false) {
                    mount_point_addressing_method_set = true;
                    mount_point_addressing_method_default = strdup(new_value->data.string_val);
                }
                else {
                    //prevent changing mount_point_addressing_method
                    if(strcmp(new_value->data.string_val, mount_point_addressing_method_default) != 0) {
                        pthread_mutex_lock(&mount_point_addressing_method_lock);
                        mount_point_addressing_method_val = mount_point_addressing_method_default;
                        pthread_mutex_unlock(&mount_point_addressing_method_lock);
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
