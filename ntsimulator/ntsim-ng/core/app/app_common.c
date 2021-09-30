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

static int app_common_populate_info(void);
static int app_common_populate_network_emulation_info(void);
static int app_common_populate_network_emulation_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

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

    rc = sr_module_change_subscribe(session_running, NTS_NETWORK_FUNCTION_MODULE, NTS_NF_NETWORK_EMULATION_SCHEMA_XPATH, app_common_populate_network_emulation_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_UPDATE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to faults");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int app_common_populate_info(void) {
    int rc;

    if (framework_environment.nts.build_time && strlen(framework_environment.nts.build_time) > 0) {
        rc  = sr_set_item_str(session_operational, NTS_NF_INFO_SCHEMA_XPATH"/build-time", framework_environment.nts.build_time, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    rc = sr_set_item_str(session_operational, NTS_NF_INFO_SCHEMA_XPATH"/version", framework_environment.nts.version, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed\n");
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

static int app_common_populate_network_emulation_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    
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
