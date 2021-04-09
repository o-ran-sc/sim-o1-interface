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

#include "populate.h"
#include "utils/log_utils.h"
#include "utils/rand_utils.h"
#include "utils/type_utils.h"
#include <stdio.h>
#include <assert.h>

#include "generate.h"
#include "core/session.h"
#include "core/framework.h"

static int datastore_populate_from_store(const char *running_filename, const char *operational_filename);
static int datastore_populate_commit(void);

int datastore_populate(int retries) {
    int rc;

    while(retries) {
        int failed = 0;

        rc = datastore_generate_external();
        if(rc != NTS_ERR_OK) {
            log_error("datastore_generate_external() failed\n");
            return NTS_ERR_FAILED;
        }

        rc = datastore_populate_from_store(DATASTORE_RUNNING_PATH, DATASTORE_OPERATIONAL_PATH);
        if(rc != NTS_ERR_OK) {
            failed = 1;
            log_error("datastore_populate_from_store() failed\n");
        }

        if(failed) {
            sr_discard_changes(session_running);
            sr_discard_changes(session_operational);
            log_error("datastore_populate() failed, discarding changes\n");
        }
        else {
            rc = datastore_populate_commit();
            if(rc != NTS_ERR_OK) {
                log_error("datastore_populate_commit() failed\n");
                failed = 1;
            }
        }

        if(!failed) {
            break;
        }
        retries--;
    }

    if(retries == 0) {
        log_error("datastore_populate() failed to populate\n");
        return NTS_ERR_FAILED;
    }

    log_add_verbose(1, LOG_COLOR_BOLD_GREEN"datastore_populate() success\n"LOG_COLOR_RESET);
    return NTS_ERR_OK;
}


static int datastore_populate_from_store(const char *running_filename, const char *operational_filename) {
    assert_session();
    
    int rc = 0;
    struct lyd_node *data;

    data = datastore_load_external(running_filename, false);
    if(data) {
        log_add_verbose(1, "editing batch for RUNNING... ");
        rc = sr_edit_batch(session_running, data, "replace");
        lyd_free_withsiblings(data);
        if (rc != SR_ERR_OK) {
            log_add(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            return NTS_ERR_FAILED;
        }
        else {
            log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }
    }
    else {
        if(running_filename) {
            log_add_verbose(2, "datastore_populate_from_store(): %s could not be loaded, skipping\n", running_filename);
        }
    }

    data = datastore_load_external(operational_filename, true);
    if(data) {
        log_add_verbose(1, "editing batch for OPERATIONAL... ");
        rc = sr_edit_batch(session_operational, data, "replace");
        lyd_free_withsiblings(data);
        if (rc != SR_ERR_OK) {
            log_add(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            return NTS_ERR_FAILED;
        }
        else {
            log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }
    }
    else {
        if(running_filename) {
            log_add_verbose(2, "datastore_populate_from_store(): %s could not be loaded, skipping\n", operational_filename);
        }
    }

    return NTS_ERR_OK;
}

static int datastore_populate_commit(void) {
    assert_session();

    log_add_verbose(1, "appling changes to RUNNING... ");
    int rc = sr_apply_changes(session_running, 0, 0);
    if (rc != SR_ERR_OK) {
        sr_discard_changes(session_running);
        log_add(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
        return NTS_ERR_FAILED;
    }
    else {
        log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
    }

    log_add_verbose(1, "appling changes to OPERATIONAL... ");
    rc = sr_apply_changes(session_operational, 0, 0);
    if (rc != SR_ERR_OK) {
        log_add(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
        return NTS_ERR_FAILED;
    }
    else {
        log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
    }

    return NTS_ERR_OK;
}
