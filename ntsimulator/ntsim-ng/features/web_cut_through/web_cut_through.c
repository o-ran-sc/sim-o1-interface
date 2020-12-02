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

#define SYSTEM_NAME_SCHEMA_XPATH                "/ietf-system:system/onap-system:name"
#define SYSTEM_WEB_UI_SCHEMA_XPATH              "/ietf-system:system/onap-system:web-ui"


int web_cut_through_feature_start(sr_session_ctx_t *current_session) {
    assert(current_session);
    assert_session();

    int rc = 0;

    //update ietf-system details
    rc = sr_set_item_str(current_session, SYSTEM_NAME_SCHEMA_XPATH, framework_environment.hostname, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed");
        return NTS_ERR_FAILED;
    }

    controller_details_t *controller_details = controller_details_get(current_session);
    if(controller_details == 0) {
        log_error("controller_details_get failed");
        return NTS_ERR_FAILED;
    }

    char *web_ui = 0;
    asprintf(&web_ui, "%s/odlux/index.html#/about", controller_details->base_url);
    controller_details_free(controller_details);

    if(web_ui == 0) {
        log_error("asprintf failed");
        return NTS_ERR_FAILED;
    }

    rc = sr_set_item_str(current_session, SYSTEM_WEB_UI_SCHEMA_XPATH, web_ui, 0, 0);
    free(web_ui);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed");
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(current_session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}
