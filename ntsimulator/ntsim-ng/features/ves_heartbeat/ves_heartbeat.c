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

#include "ves_heartbeat.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/http_client.h"
#include "utils/nts_utils.h"
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>

#include "core/session.h"
#include "core/framework.h"

#define HEARTBEAT_SCHEMA_XPATH      "/nts-network-function:simulation/network-function/ves/heartbeat-period" 

static volatile int ves_heartbeat_period;
static int ves_sequence_number;

static pthread_t ves_heartbeat_thread;
static pthread_mutex_t ves_heartbeat_lock;


//mutex-guarded access
static int ves_heartbeat_period_get(void);
static void ves_heartbeat_period_set(int new_period);

static int ves_heartbeat_send_ves_message(void);
static void *ves_heartbeat_thread_routine(void *arg);
static cJSON* ves_create_heartbeat_fields(int heartbeat_period);
static int heartbeat_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

int ves_heartbeat_feature_start(sr_session_ctx_t *current_session) {
    assert_session();

    sr_val_t *value = 0;
    if(pthread_mutex_init(&ves_heartbeat_lock, NULL) != 0) { 
        log_error("mutex init has failed"); 
        return NTS_ERR_FAILED; 
    }

    ves_heartbeat_period = 0;
    ves_sequence_number = 0;

    int rc = sr_get_item(current_session, HEARTBEAT_SCHEMA_XPATH, 0, &value);
    if(rc == SR_ERR_OK) {
        ves_heartbeat_period_set(value->data.uint16_val);
        sr_free_val(value);
    }
    else if(rc != SR_ERR_NOT_FOUND) {
        log_error("sr_get_item failed");
    }

    rc = sr_module_change_subscribe(current_session, "nts-network-function", HEARTBEAT_SCHEMA_XPATH, heartbeat_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to heartbeat");
        return NTS_ERR_FAILED;
    }

    if(pthread_create(&ves_heartbeat_thread, 0, ves_heartbeat_thread_routine, 0)) {
        log_error("could not create thread for heartbeat");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int ves_heartbeat_period_get(void) {
    pthread_mutex_lock(&ves_heartbeat_lock);
    int ret = ves_heartbeat_period;
    pthread_mutex_unlock(&ves_heartbeat_lock);
    return ret;
}

static void ves_heartbeat_period_set(int new_period) {
    pthread_mutex_lock(&ves_heartbeat_lock);
    ves_heartbeat_period = new_period;
    pthread_mutex_unlock(&ves_heartbeat_lock);
}

static int ves_heartbeat_send_ves_message(void) {
    char *hostname_string = framework_environment.hostname;
    cJSON *post_data_json = cJSON_CreateObject();
    if(post_data_json == 0) {
        log_error("cJSON_CreateObject failed");
        return NTS_ERR_FAILED;
    }

    cJSON *event = cJSON_CreateObject();
    if(event == 0) {
        log_error("cJSON_CreateObject failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    
    if(cJSON_AddItemToObject(post_data_json, "event", event) == 0) {
        log_error("cJOSN_AddItemToObject failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }

    cJSON *common_event_header = ves_create_common_event_header("heartbeat", "Controller", hostname_string, "Low", ves_sequence_number++);
    if(common_event_header == 0) {
        log_error("ves_create_common_event_header failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    
    if(cJSON_AddItemToObject(event, "commonEventHeader", common_event_header) == 0) {
        log_error("cJOSN_AddItemToObject failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }

    cJSON *heartbeat_fields = ves_create_heartbeat_fields(ves_heartbeat_period_get());
    if(heartbeat_fields == 0) {
        log_error("ves_create_heartbeat_fields failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    
    if(cJSON_AddItemToObject(event, "heartbeatFields", heartbeat_fields) == 0) {
        log_error("cJOSN_AddItemToObject failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }

    char *post_data = cJSON_PrintUnformatted(post_data_json);
    cJSON_Delete(post_data_json);
    if(post_data == 0) {
        log_error("cJSON_PrintUnformatted failed");
        return NTS_ERR_FAILED;
    }

    ves_details_t *ves_details = ves_endpoint_details_get(0);
    if(!ves_details) {
        log_error("ves_endpoint_details_get failed");
        free(post_data);
        return NTS_ERR_FAILED;
    }
    
    int rc = http_request(ves_details->url, ves_details->username, ves_details->password, "POST", post_data, 0, 0);
    ves_details_free(ves_details);
    free(post_data);
    
    if(rc != NTS_ERR_OK) {
        log_error("http_request failed");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static void *ves_heartbeat_thread_routine(void *arg) {
    int current_heartbeat_period = 0;
    unsigned int timer_counter = 0;

    while(!framework_sigint) {
        current_heartbeat_period = ves_heartbeat_period_get();
        timer_counter++;

        if((timer_counter >= current_heartbeat_period) && (current_heartbeat_period > 0)) {
            timer_counter = 0;

            int rc = ves_heartbeat_send_ves_message();
            if(rc != NTS_ERR_FAILED) {
                log_error("could not send VES heartbeat");
            }
        }

        sleep(1);
    }

    return 0;
}

static cJSON* ves_create_heartbeat_fields(int heartbeat_period) {
    cJSON *heartbeat_fields = cJSON_CreateObject();
    if(heartbeat_fields == 0) {
        log_error("could not create JSON object");
        return 0;
    }

    if(cJSON_AddStringToObject(heartbeat_fields, "heartbeatFieldsVersion", "3.0") == 0) {
        log_error("cJSON_Add*ToObject failed");
        cJSON_Delete(heartbeat_fields);
        return 0;
    }

    if(cJSON_AddNumberToObject(heartbeat_fields, "heartbeatInterval", (double)(heartbeat_period)) == 0) {
        log_error("cJSON_Add*ToObject failed");
        cJSON_Delete(heartbeat_fields);
        return 0;
    }

    cJSON *additional_fields = cJSON_CreateObject();
    if(additional_fields == 0) {
        log_error("could not create JSON object");
        log_error("cJSON_Add*ToObject failed");
        cJSON_Delete(heartbeat_fields);
        return 0;
    }
    
    if(cJSON_AddItemToObject(heartbeat_fields, "additionalFields", additional_fields) == 0) {
        log_error("cJSON_Add*ToObject failed");
        cJSON_Delete(heartbeat_fields);
        return 0;
    }

    char *current_date_and_time = get_current_date_and_time();
    if(current_date_and_time == 0) {
        log_error("get_current_date_and_time failed");
        cJSON_Delete(heartbeat_fields);
        return 0;
    }

    if(cJSON_AddStringToObject(additional_fields, "eventTime", current_date_and_time) == 0) {
        log_error("cJSON_Add*ToObject failed");
        cJSON_Delete(heartbeat_fields);
        free(current_date_and_time);
        return 0;
    }
    free(current_date_and_time);

    return heartbeat_fields;
}

static int heartbeat_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    sr_change_iter_t *it = 0;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = 0;
    sr_val_t *new_value = 0;

    if(event == SR_EV_DONE) {
        rc = sr_get_changes_iter(session, HEARTBEAT_SCHEMA_XPATH, &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed");
            return SR_ERR_VALIDATION_FAILED;
        }

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            ves_heartbeat_period_set(new_value->data.uint16_val);
            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);
    }

    return SR_ERR_OK;
}
