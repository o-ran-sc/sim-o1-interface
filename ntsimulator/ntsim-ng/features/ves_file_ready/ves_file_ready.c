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

#include "ves_file_ready.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/http_client.h"
#include "utils/nts_utils.h"
#include <stdio.h>
#include <assert.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#include "core/framework.h"
#include "core/session.h"

#define FILE_READY_RPC_SCHEMA_XPATH         "/nts-network-function:invoke-ves-pm-file-ready"

static int ves_file_ready_invoke_pm_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);
static int ves_file_ready_send_message(sr_session_ctx_t *session, const char *file_location);
static cJSON* ves_create_file_ready_fields(const char* file_location);
static void ves_file_ready_vsftp_daemon_init(void);

int ves_file_ready_feature_start(sr_session_ctx_t *current_session) {
    assert(current_session);
    assert_session();

    int rc = sr_rpc_subscribe(current_session, FILE_READY_RPC_SCHEMA_XPATH, ves_file_ready_invoke_pm_cb, 0, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("error from sr_rpc_subscribe: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    ves_file_ready_vsftp_daemon_init();

    return NTS_ERR_OK;
}

static void ves_file_ready_vsftp_daemon_init(void) {
    system("/usr/sbin/vsftpd &");
}

static int ves_file_ready_invoke_pm_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {
    int rc;

    *output_cnt = 1;
    rc = sr_new_values(*output_cnt, output);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(output[0], FILE_READY_RPC_SCHEMA_XPATH"/status");
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = ves_file_ready_send_message(session, input[0].data.string_val);
    if(rc != NTS_ERR_OK) {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "ERROR");
    }
    else {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "SUCCESS");
    }

    return rc;
}

static int ves_file_ready_send_message(sr_session_ctx_t *session, const char *file_location) {
    assert(session);
    assert(file_location);

    int rc;
    static int sequence_number = 0;

    cJSON *post_data_json = cJSON_CreateObject();
    if(post_data_json == 0) {
        log_error("could not create cJSON object");
        return NTS_ERR_FAILED;
    }

    cJSON *event = cJSON_CreateObject();
    if(event == 0) {
        log_error("could not create cJSON object");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    
    if(cJSON_AddItemToObject(post_data_json, "event", event) == 0) {
        log_error("cJSON_AddItemToObject failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }

    char *hostname_string = framework_environment.hostname;
    cJSON *common_event_header = ves_create_common_event_header("notification", "Notification-gnb_Nokia-FileReady", hostname_string, "Normal", sequence_number++);
    if(common_event_header == 0) {
        log_error("could not create cJSON object");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    
    if(cJSON_AddItemToObject(event, "commonEventHeader", common_event_header) == 0) {
        log_error("cJSON_AddItemToObject failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }

    cJSON *file_ready_fields = ves_create_file_ready_fields(file_location);
    if(file_ready_fields == 0) {
        log_error("could not create cJSON object");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    
    if(cJSON_AddItemToObject(event, "notificationFields", file_ready_fields) == 0) {
        log_error("cJSON_AddItemToObject failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }

    char *post_data = cJSON_PrintUnformatted(post_data_json);
    cJSON_Delete(post_data_json);
    if(post_data == 0) {
        log_error("cJSON_PrintUnformatted failed");
        return NTS_ERR_FAILED;
    }


    ves_details_t *ves_details = ves_endpoint_details_get(session);
    if(!ves_details) {
        log_error("ves_endpoint_details_get failed");
        free(post_data);
        return NTS_ERR_FAILED;
    }
    
    rc = http_request(ves_details->url, ves_details->username, ves_details->password, "POST", post_data, 0, 0);
    ves_details_free(ves_details);
    free(post_data);
    
    if(rc != NTS_ERR_OK) {
        log_error("http_request failed");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static cJSON* ves_create_file_ready_fields(const char* file_location) {
    assert(file_location);

    cJSON *file_ready_fields = cJSON_CreateObject();
    if(file_ready_fields == 0) {
        log_error("could not create JSON object");
        return 0;
    }

    if(cJSON_AddStringToObject(file_ready_fields, "changeIdentifier", "PM_MEAS_FILES") == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    if(cJSON_AddStringToObject(file_ready_fields, "changeType", "FileReady") == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    if(cJSON_AddStringToObject(file_ready_fields, "notificationFieldsVersion", "2.0") == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    cJSON *array_of_named_hash_map = cJSON_CreateArray();
    if(array_of_named_hash_map == 0) {
        log_error("could not create JSON object");
        cJSON_Delete(file_ready_fields);
        return 0;
    }
    
    if(cJSON_AddItemToObject(file_ready_fields, "arrayOfNamedHashMap", array_of_named_hash_map) == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    cJSON *additional_fields_entry = cJSON_CreateObject();
    if(additional_fields_entry == 0) {
        log_error("could not create JSON object");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    char *filename = strrchr(file_location, '/');

    if(filename == 0) {
        if(cJSON_AddStringToObject(additional_fields_entry, "name", "dummy_file.tar.gz") == 0) {
            log_error("cJSON_AddStringToObject failed");
            cJSON_Delete(file_ready_fields);
            return 0;
        }
    }
    else {
        if(cJSON_AddStringToObject(additional_fields_entry, "name", filename + 1) == 0) {
            log_error("cJSON_AddStringToObject failed");
            cJSON_Delete(file_ready_fields);
            return 0;
        }
    }

    cJSON *hash_map = cJSON_CreateObject();
    if(hash_map == 0) {
        log_error("could not create JSON object");
        cJSON_Delete(file_ready_fields);
        return 0;
    }
    
    if(cJSON_AddItemToObject(additional_fields_entry, "hashMap", hash_map) == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    if(cJSON_AddStringToObject(hash_map, "location", file_location) == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    if(cJSON_AddStringToObject(hash_map, "compression", "gzip") == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    if(cJSON_AddStringToObject(hash_map, "fileFormatType", "org.3GPP.32.435#measCollec") == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    if(cJSON_AddStringToObject(hash_map, "fileFormatVersion", "V5") == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    if(cJSON_AddItemToArray(array_of_named_hash_map, additional_fields_entry) == 0) {
        log_error("cJSON_AddStringToObject failed");
        cJSON_Delete(file_ready_fields);
        return 0;
    }

    return file_ready_fields;
}
