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

#include "manual_notification.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/rand_utils.h"
#include "utils/http_client.h"
#include "utils/nts_utils.h"
#include <stdio.h>
#include <assert.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#include "core/session.h"
#include "core/xpath.h"
#include "core/framework.h"

static int manual_notification_pm_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);
static sr_subscription_ctx_t *manual_notification_subscription = 0;

int manual_notification_feature_get_status(void) {
    return (manual_notification_subscription != 0);
}

int manual_notification_feature_start(sr_session_ctx_t *current_session) {
    assert_session();
    assert(current_session);

    if(manual_notification_subscription == 0) {
        int rc = sr_rpc_subscribe(current_session, NTS_NF_RPC_MANUAL_NOTIF_SCHEMA_XPATH, manual_notification_pm_cb, 0, 0, SR_SUBSCR_CTX_REUSE, &manual_notification_subscription);
        if(rc != SR_ERR_OK) {
            log_error("error from sr_rpc_subscribe: %s\n", sr_strerror(rc));
            return NTS_ERR_FAILED;
        }
    }

    return NTS_ERR_OK;
}

int manual_notification_feature_stop(void) {
    assert_session();

    if(manual_notification_subscription) {
        int rc = sr_unsubscribe(manual_notification_subscription);
        if(rc != SR_ERR_OK) {
            log_error("error from sr_rpc_subscribe: %s\n", sr_strerror(rc));
            return NTS_ERR_FAILED;
        }

        manual_notification_subscription = 0;
    }

    return NTS_ERR_OK;
}


static int manual_notification_pm_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {
    int rc;

    *output_cnt = 1;
    rc = sr_new_values(*output_cnt, output);
    if(SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(output[0], NTS_NF_RPC_MANUAL_NOTIF_SCHEMA_XPATH"/status");
    if(SR_ERR_OK != rc) {
        return rc;
    }

    LYD_FORMAT notif_format = LYD_UNKNOWN;
    char *notif_object = 0;
    for(int i = 0; i < input_cnt; i++) {
        if(strstr(input[i].xpath, "notification-format") != 0) {
            if(input[i].data.enum_val[0] == 'x') {
                notif_format = LYD_XML;
            }
            else if(input[i].data.enum_val[0] == 'j') {
                notif_format = LYD_JSON;
            }
        }
        else if(strstr(input[i].xpath, "notification-object") != 0) {
            notif_object = input[i].data.string_val;
        }
    }

    struct lyd_node *notif = 0;
    notif = lyd_parse_mem(session_context, notif_object, notif_format, LYD_OPT_NOTIF, 0);
    if(notif) {
        rc = sr_event_notif_send_tree(session, notif);
    }
    else {
        rc = SR_ERR_VALIDATION_FAILED;
    }

    lyd_free_withsiblings(notif);

    if(rc != SR_ERR_OK) {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "ERROR");
    }
    else {
        rc = sr_val_build_str_data(output[0], SR_ENUM_T, "%s", "SUCCESS");
    }

    return rc;
}
