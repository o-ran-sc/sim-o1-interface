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

#include "session.h"
#include "core/framework.h"
#include "utils/log_utils.h"
#include <stdio.h>
#include <assert.h>

sr_conn_ctx_t *session_connection = 0;
sr_session_ctx_t *session_running = 0;
sr_session_ctx_t *session_operational = 0;
struct ly_ctx *session_context = 0;
sr_subscription_ctx_t *session_subscription = 0;

int session_init(void) {
    int rc = SR_ERR_OK;
    
    /* connect to sysrepo */
    rc = sr_connect(0, &session_connection);
    if(SR_ERR_OK != rc) {
        log_error("sr_connect failed\n");
        goto session_init_cleanup;
    }

    /* start session */
    rc = sr_session_start(session_connection, SR_DS_OPERATIONAL, &session_operational);
    if (rc != SR_ERR_OK) {
        log_error("sr_session_start operational failed\n");
        goto session_init_cleanup;
    }

    rc = sr_session_start(session_connection, SR_DS_RUNNING, &session_running);
    if (rc != SR_ERR_OK) {
        log_error("sr_session_start running failed\n");
        goto session_init_cleanup;
    }

    /* get context */
    session_context = (struct ly_ctx *)sr_get_context(session_connection);
    if(session_context == 0) {
        log_error("sr_get_context failed\n");
        goto session_init_cleanup;
    }

    return NTS_ERR_OK;

session_init_cleanup:
    return NTS_ERR_FAILED;
}

void session_free(void) {
    log_add_verbose(2, "session_free()... ");
    if(session_subscription) {
        sr_unsubscribe(session_subscription);
    }

    sr_session_stop(session_operational);
    sr_session_stop(session_running);

    sr_disconnect(session_connection);

    session_connection = 0;
    session_running = 0;
    session_operational = 0;
    session_context = 0;
    log_add(2, "done\n");
}
