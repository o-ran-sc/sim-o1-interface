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

#include "manager.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include <stdio.h>
#include <assert.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#include "core/framework.h"
#include "core/session.h"
#include "core/xpath.h"
#include "core/context.h"

#include "app_common.h"

static int manager_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
static int manager_instances_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int manager_run(void) {
    assert_session();

    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"starting MANAGER...\n"LOG_COLOR_RESET);

    int rc = app_common_init();
    if(rc != NTS_ERR_OK) {
        log_error("app_common_init failed\n");
        return NTS_ERR_FAILED;
    }
    
    //init manager context
    rc = manager_context_init();
    if(rc != NTS_ERR_OK) {
        log_error("manager_context_init failed\n");
        return NTS_ERR_FAILED;
    }

    //init operations
    rc = manager_operations_init();
    if(rc != NTS_ERR_OK) {
        log_error("manager_operations_init failed\n");
        return NTS_ERR_FAILED;
    }

    //print everything on the manager's screen
    log_add_verbose(1, LOG_COLOR_BOLD_CYAN"Available images: \n"LOG_COLOR_RESET);
    for(int i = 0; i < docker_context_count; i++) {
        log_add_verbose(1, LOG_COLOR_BOLD_CYAN"- %s\n"LOG_COLOR_RESET, docker_context[i].image);
        for(int j = 0; j < docker_context[i].available_images_count; j++) {
            log_add_verbose(1, "   - "LOG_COLOR_RED"%s/"LOG_COLOR_CYAN"%s"LOG_COLOR_RESET":"LOG_COLOR_YELLOW"%s\n"LOG_COLOR_RESET, docker_context[i].available_images[j].repo, docker_context[i].image, docker_context[i].available_images[j].tag);
        }
    }
    
    // subscribe to any changes on the list
    rc = sr_module_change_subscribe(session_running, NTS_MANAGER_MODULE, NTS_MANAGER_SIMULATION_SCHEMA_XPATH, manager_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_UPDATE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to simulation changes\n");
        return NTS_ERR_FAILED;
    }

    //subscribe to stats
    rc = sr_oper_get_items_subscribe(session_running, NTS_MANAGER_MODULE, NTS_MANAGER_SIMULATION_SCHEMA_XPATH, manager_sr_stats_get_items_cb, NULL, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_OPER_MERGE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to oper faults\n");
        return NTS_ERR_FAILED;
    }

    //subscribe to instances oper change
    rc = sr_oper_get_items_subscribe(session_running, NTS_MANAGER_MODULE, NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_instances_get_items_cb, NULL, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to oper faults\n");
        return 0;
    }

    rc = manager_sr_update_static_stats();
    if(rc != NTS_ERR_OK) {
        log_error("manager_sr_update_static_stats failed\n");
        return NTS_ERR_FAILED;
    }

    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"nts-ng manager"LOG_COLOR_RESET" v%s build %s\n", framework_environment.nts.version, framework_environment.nts.build_time);
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"Host IP:"LOG_COLOR_RESET" %s\n", framework_environment.host.ip);
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"Host ports"LOG_COLOR_RESET": ");
    if(framework_environment.settings.ssh_connections) {
        log_add(1, "NETCONF SSH: %d (%d)", framework_environment.host.ssh_base_port, framework_environment.settings.ssh_connections);
    }
    else {
        log_add(1, "NETCONF SSH: disabled");
    }
    if(framework_environment.settings.tls_connections) {
        log_add(1, " | NETCONF TLS: %d (%d)", framework_environment.host.tls_base_port, framework_environment.settings.tls_connections);
    }
    else {
        log_add(1, " | NETCONF TLS: disabled");
    }
    if(framework_environment.settings.ftp_connections) {
        log_add(1, " | FTP: %d (%d)", framework_environment.host.ftp_base_port, framework_environment.settings.ftp_connections);
    }
    else {
        log_add(1, " | FTP: disabled");
    }
    if(framework_environment.settings.sftp_connections) {
        log_add(1, " | SFTP: %d (%d)", framework_environment.host.sftp_base_port, framework_environment.settings.sftp_connections);
    }
    else {
        log_add(1, " | SFTP: disabled");
    }
    log_add(1,"\n");
    log_add_verbose(1, LOG_COLOR_BOLD_GREEN"started!\n"LOG_COLOR_RESET);

    //daemonize
    while(!framework_sigint) {
        manager_operations_loop();  //caution - this function time-waits (1sec) on manager_operation_sem
    }

    manager_operations_free();
    manager_context_free();

    return NTS_ERR_OK;
}

static int manager_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    sr_change_iter_t *it = 0;
    sr_change_oper_t oper;
    sr_val_t *old_value = 0;
    sr_val_t *new_value = 0;
    int rc = SR_ERR_OK;

    if(manager_sr_get_context_sync()) {
        return SR_ERR_OK;
    }

    if(event == SR_EV_UPDATE) {
        rc = sr_get_changes_iter(session, NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH"//.", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed\n");
            return SR_ERR_VALIDATION_FAILED;
        }

        manager_operation_t *new_oper = 0;
        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            if(new_value) {
                //get function type and index
                char *nv = sr_val_to_str(new_value);

                char function_type[512];
                strncpy(function_type, strstr(new_value->xpath, "function-type='") + 15, 510);
                *strchr(function_type, '\'') = 0;
                
                //if context is new
                if((new_oper == 0) || (strcmp(new_oper->function_type, function_type) != 0)) {

                    if(new_oper == 0) {
                        manager_operations_begin();
                    }
                    else {
                        //validate and add the operation
                        if(manager_operations_validate(new_oper) != NTS_ERR_OK) {
                            manager_operations_free_oper(new_oper);
                            manager_operations_finish_with_error();
                            return SR_ERR_VALIDATION_FAILED;
                        }
                        
                        manager_operations_add(new_oper);
                    }

                    new_oper = manager_operations_new_oper(MANAGER_OPERATION_EDIT);
                    new_oper->function_type = strdup(function_type);

                    //get ft_idnex
                    for(int i = 0; i < docker_context_count; i++) {
                        if(strcmp(new_oper->function_type, manager_context[i].function_type) == 0) {
                            new_oper->ft_index = i;
                            break;
                        }
                    }

                    if(new_oper->ft_index == -1) {
                        log_error("function-type not found: %s\n", new_oper->function_type);
                        return SR_ERR_VALIDATION_FAILED;
                    }
                }

                char *leaf_path  = strdup(strstr(new_value->xpath, "']/") + 3);
                if(strcmp(leaf_path, "started-instances") == 0) {
                    new_oper->started_instances = new_value->data.uint16_val;
                    // checkAL sysrepo v1.4.140 workaround
                    // rc = sr_set_item(session, old_value->xpath, old_value, 0);
                    // if(rc != SR_ERR_OK) {
                    //     log_error("sr_set_item failed\n");
                    //     return SR_ERR_VALIDATION_FAILED;
                    // }
                }
                else if(strcmp(leaf_path, "mounted-instances") == 0) {
                    new_oper->mounted_instances = new_value->data.uint16_val;
                    // checkAL sysrepo v1.4.140 workaround
                    // rc = sr_set_item(session, old_value->xpath, old_value, 0);
                    // if(rc != SR_ERR_OK) {
                    //     log_error("sr_set_item failed\n");
                    //     return SR_ERR_VALIDATION_FAILED;
                    // }
                }
                else if(strcmp(leaf_path, "docker-instance-name") == 0) {
                    new_oper->docker_instance_name = strdup(nv);
                    free(manager_context[new_oper->ft_index].docker_instance_name);
                    manager_context[new_oper->ft_index].docker_instance_name = strdup(nv);
                }
                else if(strcmp(leaf_path, "docker-version-tag") == 0) {
                    new_oper->docker_version_tag = strdup(nv);
                    free(manager_context[new_oper->ft_index].docker_version_tag);
                    manager_context[new_oper->ft_index].docker_version_tag = strdup(nv);
                }
                else if(strcmp(leaf_path, "docker-repository") == 0) {
                    new_oper->docker_repository = strdup(nv);
                    free(manager_context[new_oper->ft_index].docker_repository);
                    manager_context[new_oper->ft_index].docker_repository = strdup(nv);
                }
                else if(strcmp(leaf_path, "mount-point-addressing-method") == 0) {
                    //update conetxt
                    free(manager_context[new_oper->ft_index].mount_point_addressing_method);
                    manager_context[new_oper->ft_index].mount_point_addressing_method = strdup(nv);
                }
                else {
                    //mark each instance for reconfiguration
                    for(int i = 0; i < manager_context[new_oper->ft_index].started_instances; i++) {
                        manager_context[new_oper->ft_index].instance[i].is_configured = false;
                    }
                }

                free(leaf_path);
                free(nv);
            }

            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);

        //validate and add the operation, if any; can be 0 if no modifications to NF list
        if(new_oper) {
            if(manager_operations_validate(new_oper) != NTS_ERR_OK) {
                manager_operations_free_oper(new_oper);
                manager_operations_finish_with_error();
                return SR_ERR_VALIDATION_FAILED;
            }

            manager_operations_add(new_oper);
        }
    }
    else if(event == SR_EV_CHANGE) {
    }
    else if(event == SR_EV_DONE) {
        bool global_change = false;

        // go throughout all the changes, not just NF list
        rc = sr_get_changes_iter(session, NTS_MANAGER_SIMULATION_SCHEMA_XPATH"//.", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed\n");
            return SR_ERR_VALIDATION_FAILED;
        }

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            if(new_value) {
                if(strstr(new_value->xpath, NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH) != new_value->xpath) {
                    global_change = true;
                    sr_free_val(old_value);
                    sr_free_val(new_value);
                    break;
                }
            }

            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);

        if(global_change) {
            //mark each instance for reconfiguration
            for(int i = 0; i < docker_context_count; i++) {
                for(int j = 0; j < manager_context[i].started_instances; j++) {
                    manager_context[i].instance[j].is_configured = false;
                }
            }
        }

        manager_operations_finish_and_execute();   //from this point on, manager_operations_loop will take over
    }

    return SR_ERR_OK;
}

static int manager_instances_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data) {

    *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, 0, 0, 0);
    if(*parent == 0) {
        log_error("lyd_new_path failed\n");
        return SR_ERR_OPERATION_FAILED;
    }

    for(int i = 0; i < docker_context_count; i++) {
        char ftype_path[512];
        sprintf(ftype_path, "%s[function-type='%s']/instances/instance", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        for(int j = 0; j < manager_context[i].started_instances; j++) {
            char instance_path[1024];
            sprintf(instance_path, "%s[name='%s']", ftype_path, manager_context[i].instance[j].container.name);

            char full_path[2048];

            sprintf(full_path, "%s/mount-point-addressing-method", instance_path);
            if(lyd_new_path(*parent, NULL, full_path, manager_context[i].instance[j].mount_point_addressing_method, 0, 0) == 0) {
                log_error("lyd_new_path failed\n");
                return SR_ERR_OPERATION_FAILED;
            }

            sprintf(full_path, "%s/is-mounted", instance_path);
            struct lyd_node *is_mounted = lyd_new_path(*parent, NULL, full_path, manager_context[i].instance[j].is_mounted ? "true" : "false", 0, LYD_PATH_OPT_NOPARENTRET);
            if(is_mounted == 0) {
                log_error("lyd_new_path failed\n");
                return SR_ERR_OPERATION_FAILED;
            }

            if(manager_sr_populate_networking(is_mounted->parent, &manager_context[i].instance[j]) != NTS_ERR_OK) {
                log_error("manager_sr_populate_networking failed\n");
                return SR_ERR_OPERATION_FAILED;
            }
        }
    }

    return SR_ERR_OK;
}
