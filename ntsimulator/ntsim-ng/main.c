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
#include "core/docker.h"
#include "core/session.h"
#include "core/context.h"
#include "core/test.h"
#include "core/nc_config.h"

#include "core/app/manager.h"
#include "core/app/network_function.h"
#include "core/datastore/schema.h"
#include "core/datastore/populate.h"
#include "core/faults/faults.h"

#include "features/ves_pnf_registration/ves_pnf_registration.h"
#include "features/ves_heartbeat/ves_heartbeat.h"
#include "features/ves_file_ready/ves_file_ready.h"
#include "features/manual_notification/manual_notification.h"
#include "features/netconf_call_home/netconf_call_home.h"

int main(int argc, char **argv) {
    int return_code = EXIT_SUCCESS;

    framework_init(argc, argv);

    if(framework_arguments.container_init) {
        if(!docker_container_init()) {
            log_error("docker_container_init() failed");
            return_code = EXIT_FAILURE;   
        }

        framework_free();
        return return_code;
    }
    else { //not in container-init mode
        sr_log_stderr(SR_LL_NONE);

        int rc;
        rc = session_init();
        if(rc != 0) {
            log_error("session_init() failed");
            return_code = EXIT_FAILURE;
            goto non_container_init_cleanup;
        }

        rc = context_init(session_context);
        if(rc != 0) {
            log_error("context_init() failed");
            return_code = EXIT_FAILURE;
            goto non_container_init_cleanup;
        }

        nc_client_init();

        if(framework_arguments.nc_server_init) {
            //configure local netconf server
            rc = netconf_configure();
            if(rc != 0) {
                log_error("netconf_configure() failed");
                return_code = EXIT_FAILURE;
                goto non_container_init_cleanup;
            }
        }

        if(framework_arguments.manager) {
            //run in manager mode
            if(manager_run() != NTS_ERR_OK) {
                return_code = EXIT_FAILURE;
                goto non_container_init_cleanup;
            }
        }
        else if(framework_arguments.network_function) {
            //run in network function mode
            if(network_function_run() != NTS_ERR_OK) {
                return_code = EXIT_FAILURE;
                goto non_container_init_cleanup;
            }
        }
        else {
            if(framework_arguments.test_mode) {
                if(test_mode_run() != NTS_ERR_OK) {
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }
            }
            else if(framework_arguments.exhaustive_test) {
                //exhaustive test
                if(exhaustive_test_run() != NTS_ERR_OK) {
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }
            }

            if(framework_arguments.print_root_paths) {
                //print all root paths with their attributes
                if(schema_print_root_paths() != NTS_ERR_OK) {
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }
            }
            
            if(framework_arguments.print_structure_xpath != 0) {
                //print the associated structure
                if(schema_print_xpath(framework_arguments.print_structure_xpath) != NTS_ERR_OK) {
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }
            }
            
            if(framework_arguments.populate_all) {
                // populate all
                if(schema_populate() != NTS_ERR_OK) {
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }
            }

            if(framework_arguments.enable_features) {
                // check if PNF registration is enabled and send PNF registration message if so
                rc = ves_pnf_registration_feature_start(session_running);
                if(rc != 0) {
                    log_error("ves_pnf_registration_feature_start() failed");
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }

                // start feature for handling the heartbeat VES message
                rc = ves_heartbeat_feature_start(session_running);
                if(rc != 0) {
                    log_error("ves_heartbeat_feature_start() failed");
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }

                // start feature for handling the fileReady VES message
                rc = ves_file_ready_feature_start(session_running);
                if(rc != 0) {
                    log_error("ves_file_ready_feature_start() failed");
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }

                // start feature for manual notification
                rc = manual_notification_feature_start(session_running);
                if(rc != 0) {
                    log_error("manual_notification_feature_start() failed");
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }

                // start feature for NETCONF Call Home
                rc = netconf_call_home_feature_start(session_running);
                if(rc != 0) {
                    log_error("netconf_call_home_feature_start() failed");
                    return_code = EXIT_FAILURE;
                    goto non_container_init_cleanup;
                }
            }

            if(framework_arguments.loop) {
                while(!framework_sigint) {
                    sleep(1);
                }
            }
        }

        non_container_init_cleanup:
        log_message(1, LOG_COLOR_BOLD_RED"\nstopping now...\n"LOG_COLOR_RESET);

        nc_client_destroy();
        context_free();
        session_free();
        framework_free();

        return return_code;
    }

    return EXIT_FAILURE;
}
