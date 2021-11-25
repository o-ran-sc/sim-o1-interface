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

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

#include "utils/log_utils.h"
#include "utils/nc_client.h"

#include "core/framework.h"
#include "core/container.h"
#include "core/session.h"
#include "core/context.h"
#include "core/test.h"
#include "core/nc_config.h"

#include "core/app/supervisor.h"
#include "core/app/manager.h"
#include "core/app/network_function.h"
#include "core/app/blank.h"
#include "core/datastore/schema.h"
#include "core/datastore/populate.h"

int main(int argc, char **argv) {
    int return_code = EXIT_SUCCESS;

    if(framework_init(argc, argv) != NTS_ERR_OK) {
        log_error(LOG_COLOR_BOLD_RED"framework_init() error\n");
        framework_free();
        return EXIT_FAILURE;
    }

    //common init
    switch(framework_arguments.nts_mode) {
        case NTS_MODE_MANAGER:
        case NTS_MODE_NETWORK_FUNCTION:
        case NTS_MODE_TEST:
        case NTS_MODE_DEFAULT:
            sr_log_stderr(SR_LL_INF);   //checkAL WRN
        
            if(session_init() != NTS_ERR_OK) {
                log_error("session_init() failed\n");
                return_code = EXIT_FAILURE;
                goto main_clean_session;
            }

            if(context_init(session_context) != 0) {
                log_error("context_init() failed\n");
                return_code = EXIT_FAILURE;
                goto main_clean_context;
            }

            nc_client_init();
            break;

        default:
            break;
    }

    //netconf server configure
    switch(framework_arguments.nts_mode) {
        case NTS_MODE_MANAGER:
        case NTS_MODE_NETWORK_FUNCTION:
        case NTS_MODE_TEST: //checkAL remove this
            //configure local netconf server
            if(netconf_configure() != NTS_ERR_OK) {
                log_error("netconf_configure() failed\n")
                return_code = EXIT_FAILURE;
                goto main_clean;
            }
            break;

        default:
            break;
    }

    switch(framework_arguments.nts_mode) {
        case NTS_MODE_CONTAINER_INIT:
            if(!container_self_init()) {
                log_error("container_self_init() failed\n");
                return_code = EXIT_FAILURE;
            }

            goto main_clean_framework;
            break;

        case NTS_MODE_SUPERVISOR:
            //run in supervisor mode
            if(supervisor_run(argc, argv) != NTS_ERR_OK) {
                log_error("supervisor_run() failed\n");
                return_code = EXIT_FAILURE;
            }

            goto main_clean_framework;
            break;

        case NTS_MODE_MANAGER:
            if(manager_run() != NTS_ERR_OK) {
                log_error("manager_run() failed\n");
                return_code = EXIT_FAILURE;
            }

            goto main_clean;
            break;

        case NTS_MODE_NETWORK_FUNCTION:
            if(network_function_run() != NTS_ERR_OK) {
                log_error("network_function_run() failed\n");
                return_code = EXIT_FAILURE;
            }

            goto main_clean;
            break;

        case NTS_MODE_BLANK:
            if(blank_run() != NTS_ERR_OK) {
                log_error("blank_run() failed\n");
                return_code = EXIT_FAILURE;
            }

            goto main_clean_framework;
            break;

        case NTS_MODE_TEST:
            if(exhaustive_test_run() != NTS_ERR_OK) {
                log_error("exhaustive_test_run() failed\n");
                return_code = EXIT_FAILURE;
            }
        
            goto main_clean;
            break;

        case NTS_MODE_DEFAULT:
            if(framework_arguments.print_root_paths) {
                if(datastore_schema_print_root_paths() != NTS_ERR_OK) {
                    log_error("datastore_schema_print_root_paths() failed\n");
                    return_code = EXIT_FAILURE;
                    goto main_clean;
                }
            }
            
            if(framework_arguments.print_structure_xpath != 0) {
                //print the associated structure
                if(datastore_schema_print_xpath(framework_arguments.print_structure_xpath) != NTS_ERR_OK) {
                    log_error("datastore_schema_print_xpath() failed\n");
                    return_code = EXIT_FAILURE;
                    goto main_clean;
                }
            }

            goto main_clean;
            break;

        default:
            assert(0);
            break;
    }

main_clean:
    log_add_verbose(1, LOG_COLOR_BOLD_RED"stopping now...\n"LOG_COLOR_RESET);
    nc_client_destroy();
main_clean_context:
    context_free();
main_clean_session:
    session_free();
main_clean_framework:
    framework_free();
    return return_code;
}
