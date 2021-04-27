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
#include <stdio.h>
#include <assert.h>

#include "core/session.h"
#include "core/xpath.h"
#include "core/framework.h"

static int app_common_populate_info(void);

int app_common_init(void) {
    assert_session();

    int rc = app_common_populate_info();
    if(rc != NTS_ERR_OK) {
        log_error("app_common_populate_info() failed\n");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int app_common_populate_info(void) {
    int rc;
    if (framework_environment.nts.build_time && strlen(framework_environment.nts.build_time) > 0) {
        rc  = sr_set_item_str(session_operational, NTS_NF_INFO_BUILD_TIME_XPATH, framework_environment.nts.build_time, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
    }

    rc = sr_set_item_str(session_operational, NTS_NF_INFO_VERSION_XPATH, framework_environment.nts.version, 0, 0);
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
