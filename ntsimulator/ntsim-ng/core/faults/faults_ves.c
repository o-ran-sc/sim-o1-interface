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
    fault_ves_sequence_number = (uint32_t *)malloc(sizeof(uint32_t) * (framework_environment.settings.ssh_connections + framework_environment.settings.tls_connections));
    if(fault_ves_sequence_number == 0) {
        log_error("malloc failed\n");
        return NTS_ERR_FAILED; 
    }

    for(int i = 0; i < (framework_environment.settings.ssh_connections + framework_environment.settings.tls_connections); i++) {
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

    int sequence_index = 0;
    int ssh_base_port = 0;
    int tls_base_port = 0;
    nts_mount_point_addressing_method_t mp = nts_mount_point_addressing_method_get(session);
    if(mp == UNKNOWN_MAPPING) {
        log_error("mount-point-addressing-method failed\n");
        return NTS_ERR_FAILED;
    }
    else if(mp == DOCKER_MAPPING) {
        ssh_base_port = STANDARD_NETCONF_PORT;
        tls_base_port = ssh_base_port + framework_environment.settings.ssh_connections;
    }
    else {
        ssh_base_port = framework_environment.host.ssh_base_port;
        tls_base_port = framework_environment.host.tls_base_port;       
    }

    if((framework_environment.settings.ssh_connections + framework_environment.settings.tls_connections) > 1) {
        for(int port = ssh_base_port; port < ssh_base_port + framework_environment.settings.ssh_connections; port++) {
            uint32_t *seq_id = &fault_ves_sequence_number[sequence_index++];
            int rc = ves_message_send_internal(session, condition, object, severity, date_time, specific_problem, port, seq_id);
            if(rc != NTS_ERR_OK) {
                log_error("ves_message_send_internal failed\n");
            }
        }

        for(int port = tls_base_port; port < tls_base_port + framework_environment.settings.tls_connections; port++) {
            uint32_t *seq_id = &fault_ves_sequence_number[sequence_index++];
            int rc = ves_message_send_internal(session, condition, object, severity, date_time, specific_problem, port, seq_id);
            if(rc != NTS_ERR_OK) {
                log_error("ves_message_send_internal failed\n");
            }
        }
    }
    else {
        uint32_t *seq_id = &fault_ves_sequence_number[sequence_index++];
        int rc = ves_message_send_internal(session, condition, object, severity, date_time, specific_problem, 0, seq_id);
        if(rc != NTS_ERR_OK) {
            log_error("ves_message_send_internal failed\n");
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
        log_error("could not create JSON object: faultFields\n");
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "faultFieldsVersion", "4.0") == 0) {
        log_error("could not create JSON object: faultFieldsVersion\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "alarmCondition", alarm_condition) == 0) {
        log_error("could not create JSON object: alarmCondition\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "alarmInterfaceA", alarm_object) == 0) {
        log_error("could not create JSON object: alarmInterfaceA\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "eventSourceType", "O_RAN_COMPONENT") == 0) {
        log_error("could not create JSON object: eventSourceType\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "specificProblem", specific_problem) == 0) {
        log_error("could not create JSON object: specificProblem\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "eventSeverity", severity) == 0) {
        log_error("could not create JSON object: eventSeverity\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(faultFields, "vfStatus", "Active") == 0) {
        log_error("could not create JSON object: vfStatus\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    cJSON *alarmAdditionalInformation = cJSON_CreateObject();
    if(alarmAdditionalInformation == 0) {
        log_error("could not create JSON object: alarmAdditionalInformation\n");
        cJSON_Delete(faultFields);
        return 0;
    }
    cJSON_AddItemToObject(faultFields, "alarmAdditionalInformation", alarmAdditionalInformation);

    if(cJSON_AddStringToObject(alarmAdditionalInformation, "eventTime", date_time) == 0) {
        log_error("could not create JSON object: eventTime\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(alarmAdditionalInformation, "equipType", "O-RAN-sim") == 0) {
        log_error("could not create JSON object: equipType\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(alarmAdditionalInformation, "vendor", "Melacon") == 0) {
        log_error("could not create JSON object: vendor\n");
        cJSON_Delete(faultFields);
        return 0;
    }

    if(cJSON_AddStringToObject(alarmAdditionalInformation, "model", "Simulated Device") == 0) {
        log_error("could not create JSON object: model\n");
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

    char *hostname_string = framework_environment.settings.hostname;
    cJSON *post_data_json = cJSON_CreateObject();
    if(post_data_json == 0) {
        log_error("cJSON_CreateObject failed\n");
        return NTS_ERR_FAILED;
    }

    cJSON *event = cJSON_CreateObject();
    if(event == 0) {
        log_error("cJSON_CreateObject failed\n");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    cJSON_AddItemToObject(post_data_json, "event", event);

    cJSON *common_event_header = ves_create_common_event_header("fault", "O_RAN_COMPONENT_Alarms", hostname_string, port, "Low", (*seq_id)++);
    if(common_event_header == 0) {
        log_error("ves_create_common_event_header failed\n");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    cJSON_AddItemToObject(event, "commonEventHeader", common_event_header);

    cJSON *fault_fields = ves_create_fault_fields(condition, object, severity, date_time, specific_problem);
    if(fault_fields == 0) {
        log_error("ves_create_fault_fields failed\n");
        cJSON_Delete(post_data_json);
        return NTS_ERR_FAILED;
    }
    cJSON_AddItemToObject(event, "faultFields", fault_fields);

    char *post_data = cJSON_PrintUnformatted(post_data_json);
    ves_details_t *ves_details = ves_endpoint_details_get(session, 0);
    if(!ves_details) {
        log_error("ves_endpoint_details_get failed\n");
        return NTS_ERR_FAILED;
    }
    
    int rc = http_request(ves_details->url, ves_details->username, ves_details->password, "POST", post_data, 0, 0);
    ves_details_free(ves_details);
    cJSON_Delete(post_data_json);
    free(post_data);
    
    if(rc != NTS_ERR_OK) {
        log_error("http_request failed\n");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}
