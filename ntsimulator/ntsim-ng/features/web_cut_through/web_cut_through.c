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

#include "web_cut_through.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/rand_utils.h"
#include "utils/http_client.h"
#include "utils/nts_utils.h"
#include <stdio.h>
#include <assert.h>

#include "core/session.h"
#include "core/framework.h"
#include "core/xpath.h"

static int web_cut_through_status = 0;

int web_cut_through_feature_get_status(void) {
    return web_cut_through_status;
}

int web_cut_through_feature_start(sr_session_ctx_t *current_session) {
    assert(current_session);
    assert_session();

    if(web_cut_through_status == 0) {
        //update ietf-system details
        int rc = sr_set_item_str(current_session, IETF_SYSTEM_NAME_SCHEMA_XPATH, framework_environment.settings.hostname, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }

        controller_details_t *controller_details = controller_details_get(current_session);
        if(controller_details == 0) {
            log_error("controller_details_get failed\n");
            return NTS_ERR_FAILED;
        }

        char *web_ui = 0;
    	asprintf(&web_ui, "%s/odlux/index.html#/configuration/%s", controller_details->base_url, framework_environment.settings.hostname);
        controller_details_free(controller_details);

        if(web_ui == 0) {
            log_error("asprintf failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_set_item_str(current_session, IETF_SYSTEM_WEB_UI_SCHEMA_XPATH, web_ui, 0, 0);
        free(web_ui);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_set_item_str(current_session, IETF_SYSTEM_CONTACT_SCHEMA_XPATH, "O-RAN-SC SIM project", 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_set_item_str(current_session, IETF_SYSTEM_HOSTNAME_SCHEMA_XPATH, framework_environment.settings.hostname, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_set_item_str(current_session, IETF_SYSTEM_LOCATION_SCHEMA_XPATH, "Open Wireless Lab", 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_set_item_str(current_session, IETF_SYSTEM_TIMEZONE_NAME_SCHEMA_XPATH, "UTC", 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_set_item_str(current_session, IETF_SYSTEM_NTP_ENABLED_SCHEMA_XPATH, "false", 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_apply_changes(current_session, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("could not apply changes on datastore\n");
            return NTS_ERR_FAILED;
        }

        web_cut_through_status = 1;
    }

    return NTS_ERR_OK;
}

int web_cut_through_feature_stop(sr_session_ctx_t *current_session) {
    assert(current_session);
    assert_session();

    if(web_cut_through_status) {
        //update ietf-system details
        int rc = sr_delete_item(current_session, IETF_SYSTEM_NAME_SCHEMA_XPATH, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_delete_item failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_delete_item(current_session, IETF_SYSTEM_WEB_UI_SCHEMA_XPATH, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_delete_item failed\n");
            return NTS_ERR_FAILED;
        }

        rc = sr_apply_changes(current_session, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("could not apply changes on datastore\n");
            return NTS_ERR_FAILED;
        }

        web_cut_through_status = 0;
    }

    return NTS_ERR_OK;
}
