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

#include "faults.h"
#include "utils/log_utils.h"
#include "utils/rand_utils.h"
#include "utils/nts_utils.h"
#include "utils/sys_utils.h"
#include "utils/http_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "core/framework.h"
#include <cjson/cJSON.h>

static uint32_t *fault_ves_sequence_number = 0;

static cJSON *ves_create_fault_fields(const char *alarm_condition, const char *alarm_object, const char *severity, const char *date_time, const char *specific_problem);
static int ves_message_send_internal(sr_session_ctx_t *session, const char *condition, const char *object, const char *severity, const char *date_time, const char *specific_problem, int port, uint32_t *seq_id);

int faults_ves_init(void) {
    fault_ves_sequence_number = (uint32_t *)malloc(sizeof(uint32_t) * (framework_environment.ssh_connections + framework_environment.tls_connections));
    if(fault_ves_sequence_number == 0) {
        log_error("malloc failed"); 
        return NTS_ERR_FAILED; 
    }

    for(int i = 0; i < (framework_environment.ssh_connections + framework_environment.tls_connections); i++) {
        fault_ves_sequence_number[i] = 0;
    }

    return NTS_ERR_OK;
}

void faults_ves_free(void) {
    free(fault_ves_sequence_number);
    fault_ves_sequence_number = 0;
}

int faults_ves_message_send(sr_session_ctx_t *session, const char *condition, const char *object, const char *severity, const char *date_time, const char *specific_problem) {
    assert(condition);
    assert(object);
    assert(severity);
    assert(date_time);
    assert(specific_problem);

    nts_mount_point_addressing_method_t mp = nts_mount_point_addressing_method_get(session);
    if(mp == UNKNOWN_MAPPING) {
        log_error("mount-point-addressing-method failed");
        return NTS_ERR_FAILED;
    }

    int base_port = STANDARD_NETCONF_PORT;
    if(mp == HOST_MAPPING) {
        base_port = framework_environment.host_base_port;
    }

    for(int port = base_port; port < base_port + (framework_environment.ssh_connections + framework_environment.tls_connections); port++) {
        uint32_t *seq_id = &fault_ves_sequence_number[port - base_port];
        int rc = ves_message_send_internal(session, condition, object, severity, date_time, specific_problem, port, seq_id);
        if(rc != NTS_ERR_OK) {
            log_error("ves_message_send_internal failed");
        }
    }

    return NTS_ERR_OK;
}

static cJSON *ves_create_fault_fields(const char *alarm_condition, const char *alarm_object, const char *severity, const char *date_time, const char *specific_problem) {
    assert(alarm_condition);
    assert(alarm_object);
    assert(severity);
    assert(date_time);
    assert(specific_problem);
    
    cJSON *faultFields = cJSON_CreateObject();
    if(faultFields == 0) {
        log_error("could not create JSON object: faultFields");
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "faultFieldsVersion", "4.0") == 0) {
        log_error("could not create JSON object: faultFieldsVersion");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "alarmCondition", alarm_condition) == 0) {
        log_error("could not create JSON object: alarmCondition");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "alarmInterfaceA", alarm_object) == 0) {
        log_error("could not create JSON object: alarmInterfaceA");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "eventSourceType", "O_RAN_COMPONENT") == 0) {
        log_error("could not create JSON object: eventSourceType");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "specificProblem", specific_problem) == 0) {
        log_error("could not create JSON object: specificProblem");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "eventSeverity", severity) == 0) {
        log_error("could not create JSON object: eventSeverity");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "vfStatus", "Active") == 0) {
        log_error("could not create JSON object: vfStatus");
        cJSON_Delete(faultFields);
        return 0;
    }

    cJSON *alarmAdditionalInformation = cJSON_CreateObject();
    if(alarmAdditionalInformation == 0) {
        log_error("could not create JSON object: alarmAdditionalInformation");
        cJSON_Delete(faultFields);
        return 0;
    }
    cJSON_AddItemToObject(faultFields, "alarmAdditionalInformation", alarmAdditionalInformation);

    if(cJSON_AddStringToObject(alarmAdditionalInformation, "eventTime", date_time) == 0) {
        log_error("could not create JSON object: eventTime");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(alarmAdditionalInformation, "equipType", "O-RAN-sim") == 0) {
        log_error("could not create JSON object: equipType");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(alarmAdditionalInformation, "vendor", "Melacon") == 0) {
        log_error("could not create JSON object: vendor");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(alarmAdditionalInformation, "model", "Simulated Device") == 0) {
        log_error("could not create JSON object: model");
        cJSON_Delete(faultFields);
        return 0;
    }

    return faultFields;
}

static int ves_message_send_internal(sr_session_ctx_t *session, const char *condition, const char *object, const char *severity, const char *date_time, const char *specific_problem, int port, uint32_t *seq_id) {
    assert(condition);
    assert(object);
    assert(severity);
    assert(date_time);
    assert(specific_problem);

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
    cJSON_AddItemToObject(post_data_json, "event", event);

    char *source_name = 0;
    asprintf(&source_name, "%s-%d", hostname_string, port);
    cJSON *common_event_header = ves_create_common_event_header("fault", "O_RAN_COMPONENT_Alarms", source_name, "Low", (*seq_id)++);
    free(source_name);

    if(common_event_header == 0) {
        log_error("ves_create_common_event_header failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    cJSON_AddItemToObject(event, "commonEventHeader", common_event_header);

    cJSON *fault_fields = ves_create_fault_fields(condition, object, severity, date_time, specific_problem);
    if(fault_fields == 0) {
        log_error("ves_create_fault_fields failed");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    cJSON_AddItemToObject(event, "faultFields", fault_fields);

    char *post_data = cJSON_PrintUnformatted(post_data_json);
    ves_details_t *ves_details = ves_endpoint_details_get(session);
    if(!ves_details) {
        log_error("ves_endpoint_details_get failed");
        return NTS_ERR_FAILED;
    }
    
    int rc = http_request(ves_details->url, ves_details->username, ves_details->password, "POST", post_data, 0, 0);
    ves_details_free(ves_details);
    cJSON_Delete(post_data_json);
    free(post_data);
    
    if(rc != NTS_ERR_OK) {
        log_error("http_request failed");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}
