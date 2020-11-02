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

#include "test.h"
#include "utils/log_utils.h"
#include "utils/rand_utils.h"
#include "utils/type_utils.h"
#include "utils/sys_utils.h"
#include <stdio.h>
#include <assert.h>

#include <libyang/libyang.h>
#include "core/session.h"
#include "core/framework.h"
#include "core/docker.h"

#include "core/datastore/schema.h"
#include "core/datastore/populate.h"


int exhaustive_test_run(void) {
    //first get all xpaths
    char **xpaths = 0;
    int xpaths_count = schema_get_xpaths(&xpaths);
    if(xpaths_count < 0) {
        log_error("schema_get_xpaths failed");
        return NTS_ERR_FAILED;
    }
    else {
        log_message(0, "schema_get_xpaths executed with "LOG_COLOR_BOLD_GREEN"success"LOG_COLOR_RESET" (%d)\n", xpaths_count);
    }

    //switching verbosity level to 0 so we don't see logs
    int old_verbosity_level = framework_arguments.verbosity_level;
    framework_arguments.verbosity_level = 0;

    //testing schema_print_xpath()
    for(int i = 0 ; i < xpaths_count; i++) {
        int rc = schema_print_xpath(xpaths[i]);
        if(rc != NTS_ERR_OK) {
            log_error("error in schema_print_xpath");
            return rc;
        }
    }

    log_message(0, "schema_print_xpath executed with "LOG_COLOR_BOLD_GREEN"success"LOG_COLOR_RESET" for all paths\n");

    //freeing paths
    for(int i = 0; i < xpaths_count; i++) {
        free(xpaths[i]);
    }
    free(xpaths);

    //testing schema_populate
    int rc = schema_populate();
    if(rc != NTS_ERR_OK) {
        log_error("error in schema_populate");
        return rc;
    }
    
    log_message(0, "schema_populate executed with "LOG_COLOR_BOLD_GREEN"success"LOG_COLOR_RESET"\n");

    log_message(0, LOG_COLOR_BOLD_GREEN"ALL TESTS WENT GOOD!"LOG_COLOR_RESET"\n\n\n");

    //switching back verbosity level
    framework_arguments.verbosity_level = old_verbosity_level;

    return NTS_ERR_OK;
}

int test_mode_run(void) {
    assert_session();

   
    return NTS_ERR_OK;
}
