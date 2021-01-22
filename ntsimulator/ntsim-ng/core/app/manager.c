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
#include "core/context.h"
#include "core/docker.h"

#define NTS_MANAGER_MODULE                          "nts-manager"
#define NTS_SIMULATION_SCHEMA_XPATH                 "/nts-manager:simulation"
#define NTS_FUNCTION_LIST_SCHEMA_XPATH              "/nts-manager:simulation/network-functions/network-function"
#define NTS_SDN_CONTROLLER_CONFIG_XPATH             "/nts-manager:simulation/sdn-controller"
#define NTS_VES_ENDPOINT_CONFIG_XPATH               "/nts-manager:simulation/ves-endpoint"

#define NTS_NETWORK_FUNCTION_FTYPE_SCHEMA_XPATH     "/nts-network-function:simulation/network-function/function-type"

static manager_network_function_type *manager_context = 0;
static int manager_installed_function_types_count = 0;

static int manager_populate_sysrepo_network_function_list(void);
static int manager_populate_static_status(void);

static void manager_context_free(manager_network_function_type *context);

static int manager_process_change(int context_index, manager_network_function_type *new_context);
static int manager_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
static int manager_instances_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);
static int manager_stats_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int manager_run(void) {
    assert_session();

    log_message(1, LOG_COLOR_BOLD_YELLOW"\nrunning as MANAGER daemon...\n"LOG_COLOR_RESET);

    manager_operations_init();
    docker_device_init();

    //get installed function types
    struct lys_node_leaf *elem = (struct lys_node_leaf *)ly_ctx_get_node(session_context, 0, NTS_FUNCTION_LIST_SCHEMA_XPATH"/function-type", 0);
    if(elem == 0) {
        log_error("ly_ctx_get_node failed for xpath: %s", NTS_FUNCTION_LIST_SCHEMA_XPATH"/function-type");
        return NTS_ERR_FAILED;
    }

    struct lys_ident **found = 0;
    manager_installed_function_types_count = context_get_identity_leafs_of_type(elem->type.info.ident.ref[0], &found);
    if(!manager_installed_function_types_count) {
        log_error("error network functions");
        return NTS_ERR_FAILED;
    }

    //initial list population
    manager_context = (manager_network_function_type *)malloc(sizeof(manager_network_function_type) * manager_installed_function_types_count);
    for(int i = 0; i < manager_installed_function_types_count; i++) {
        manager_context[i].instance = 0;

        manager_context[i].function_type = found[i];
        asprintf(&manager_context[i].function_type_string, "%s:%s", found[i]->module->name, found[i]->name);
        manager_context[i].docker_image_name = manager_context[i].function_type->ref;
        manager_context[i].started_instances = 0;
        manager_context[i].mounted_instances = 0;
        manager_context[i].mount_point_addressing_method = strdup("docker-mapping");
        manager_context[i].docker_instance_name = strdup(manager_context[i].function_type->name);
        manager_context[i].docker_version_tag = strdup("latest");
        manager_context[i].docker_repository = strdup("local");
    }
    free(found);

    //do initial sysrepo list population
    int rc = manager_populate_sysrepo_network_function_list();
    if(rc != NTS_ERR_OK) {
        log_error("manager_populate_sysrepo_network_function_list failed");
        return NTS_ERR_FAILED;
    }

    rc = manager_populate_static_status();
    if(rc != NTS_ERR_OK) {
        log_error("manager_populate_static_status failed");
        return NTS_ERR_FAILED;
    }
    
    //subscribe to any changes on the list
    rc = sr_module_change_subscribe(session_running, NTS_MANAGER_MODULE, NTS_SIMULATION_SCHEMA_XPATH, manager_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to simulation changes");
        return NTS_ERR_FAILED;
    }

    rc = sr_oper_get_items_subscribe(session_running, NTS_MANAGER_MODULE, NTS_FUNCTION_LIST_SCHEMA_XPATH, manager_instances_get_items_cb, NULL, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to oper faults");
        return 0;
    }

    rc = sr_oper_get_items_subscribe(session_running, NTS_MANAGER_MODULE, NTS_SIMULATION_SCHEMA_XPATH, manager_stats_get_items_cb, NULL, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to oper faults");
        return 0;
    }

    //daemonize
    while(!framework_sigint) {
        sleep(1);
    }

    for(int i = 0; i < manager_installed_function_types_count; i++) {
        while(manager_context[i].started_instances) {
            manager_stop_instance(&manager_context[i]);
        }
        manager_context_free(&manager_context[i]);
    }

    free(manager_context);

    return NTS_ERR_OK;
}

static int manager_populate_sysrepo_network_function_list(void) {
    //check whether everything is already populated, read and update (if previously ran)
    sr_val_t *values = 0;
    size_t value_count = 0;
    int rc = sr_get_items(session_running, NTS_FUNCTION_LIST_SCHEMA_XPATH, 0, 0, &values, &value_count);
    if(rc != SR_ERR_OK) {
        log_error("get items failed");
        return NTS_ERR_FAILED;
    }

    //either get values, or if data inconclusive, delete everything
    if(value_count) {
        log_message(2, "nts-manager instances found (%d). cleaning up for fresh start...\n", value_count);

        for(int i = 0; i < value_count; i++) {           
            rc = sr_delete_item(session_running, values[i].xpath, 0);
            if(rc != SR_ERR_OK) {
                log_error("sr_delete_item failed");
                return NTS_ERR_FAILED;
            }
        }
        rc = sr_apply_changes(session_running, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_apply_changes failed");
            return NTS_ERR_FAILED;
        }
    }

    //populate everything if needed
    for(int i = 0; i < manager_installed_function_types_count; i++) {
        char *xpath = 0;

        asprintf(&xpath, "%s[function-type='%s']/function-type", NTS_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type_string);
        rc = sr_set_item_str(session_running, xpath, (const char *)manager_context[i].function_type_string, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/started-instances", NTS_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type_string);
        rc = sr_set_item_str(session_running, xpath, "0", 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/mounted-instances", NTS_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type_string);
        rc = sr_set_item_str(session_running, xpath, "0", 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/mount-point-addressing-method", NTS_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type_string);
        rc = sr_set_item_str(session_running, xpath, (const char*)manager_context[i].mount_point_addressing_method, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/docker-instance-name", NTS_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type_string);
        rc = sr_set_item_str(session_running, xpath, (const char*)manager_context[i].docker_instance_name, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/docker-version-tag", NTS_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type_string);
        rc = sr_set_item_str(session_running, xpath, (const char*)manager_context[i].docker_version_tag, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/docker-repository", NTS_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type_string);
        rc = sr_set_item_str(session_running, xpath, (const char*)manager_context[i].docker_repository, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
        free(xpath);
    }

    char int_to_str[30];

    //setup sdn-controller defaults
    if(strlen(framework_environment.sdn_controller_ip)) {
        rc = sr_set_item_str(session_running, NTS_SDN_CONTROLLER_CONFIG_XPATH"/controller-ip", (const char*)framework_environment.sdn_controller_ip, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
    }

    sprintf(int_to_str, "%d", framework_environment.sdn_controller_port);
    rc = sr_set_item_str(session_running, NTS_SDN_CONTROLLER_CONFIG_XPATH"/controller-port", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed");
        return NTS_ERR_FAILED;
    }

    sprintf(int_to_str, "%d", framework_environment.sdn_controller_callhome_port);
    rc = sr_set_item_str(session_running, NTS_SDN_CONTROLLER_CONFIG_XPATH"/controller-netconf-call-home-port", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed");
        return NTS_ERR_FAILED;
    }

    if(strlen(framework_environment.sdn_controller_username)) {
        rc = sr_set_item_str(session_running, NTS_SDN_CONTROLLER_CONFIG_XPATH"/controller-username", (const char*)framework_environment.sdn_controller_username, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.sdn_controller_password)) {
        rc = sr_set_item_str(session_running, NTS_SDN_CONTROLLER_CONFIG_XPATH"/controller-password", (const char*)framework_environment.sdn_controller_password, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
    }

    //setup ves-endpoint details
    if(strlen(framework_environment.ves_endpoint_protocol)) {
        rc = sr_set_item_str(session_running, NTS_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-protocol", (const char*)framework_environment.ves_endpoint_protocol, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.ves_endpoint_ip)) {
        rc = sr_set_item_str(session_running, NTS_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-ip", (const char*)framework_environment.ves_endpoint_ip, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
    }

    sprintf(int_to_str, "%d", framework_environment.ves_endpoint_port);
    rc = sr_set_item_str(session_running, NTS_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-port", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed");
        return NTS_ERR_FAILED;
    }

    if(strlen(framework_environment.ves_endpoint_auth_method)) {
        rc = sr_set_item_str(session_running, NTS_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-auth-method", (const char*)framework_environment.ves_endpoint_auth_method, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.ves_endpoint_username)) {
        rc = sr_set_item_str(session_running, NTS_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-username", (const char*)framework_environment.ves_endpoint_username, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.ves_endpoint_password)) {
        rc = sr_set_item_str(session_running, NTS_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-password", (const char*)framework_environment.ves_endpoint_password, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
    }

    if(strlen(framework_environment.ves_endpoint_certificate)) {
        rc = sr_set_item_str(session_running, NTS_VES_ENDPOINT_CONFIG_XPATH"/ves-endpoint-certificate", (const char*)framework_environment.ves_endpoint_certificate, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed");
            return NTS_ERR_FAILED;
        }
    }

    rc = sr_set_item_str(session_running, NTS_NETWORK_FUNCTION_FTYPE_SCHEMA_XPATH, "NTS_FUNCTION_TYPE_MANAGER", 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed");
        return NTS_ERR_FAILED;
    }


    //apply all changes
    rc = sr_apply_changes(session_running, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed: %s", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int manager_populate_static_status(void) {
    assert_session();

    char int_to_str[30];

    //setup sdn-controller defaults
    sprintf(int_to_str, "%d", framework_environment.host_base_port);
    int rc = sr_set_item_str(session_operational, NTS_SIMULATION_SCHEMA_XPATH"/base-port", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed");
        return NTS_ERR_FAILED;
    }

    sprintf(int_to_str, "%d", framework_environment.ssh_connections);
    rc = sr_set_item_str(session_operational, NTS_SIMULATION_SCHEMA_XPATH"/ssh-connections", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed");
        return NTS_ERR_FAILED;
    }

    sprintf(int_to_str, "%d", framework_environment.tls_connections);
    rc = sr_set_item_str(session_operational, NTS_SIMULATION_SCHEMA_XPATH"/tls-connections", (const char*)int_to_str, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_set_item_str failed");
        return NTS_ERR_FAILED;
    }

    //apply all changes
    rc = sr_apply_changes(session_operational, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static void manager_context_free(manager_network_function_type *context) {
    assert(context);

    free(context->function_type_string);
    free(context->mount_point_addressing_method);
    free(context->docker_instance_name);
    free(context->docker_version_tag);
    free(context->docker_repository);
}

//take note that this happens in the sysrepo thread
static int manager_process_change(int context_index, manager_network_function_type *new_context) {
    assert(context_index < manager_installed_function_types_count);
    assert(new_context);

    manager_network_function_type *current_context = &manager_context[context_index];
    int rc = 0;

    current_context->data_changed |= new_context->data_changed;

    //process changes, and update data in current_context to resemble new_context
    if(new_context->docker_instance_name != 0) {
        free(current_context->docker_instance_name);
        current_context->docker_instance_name = strdup(new_context->docker_instance_name);
    }

    if(new_context->docker_version_tag != 0) {
        free(current_context->docker_version_tag);
        current_context->docker_version_tag = strdup(new_context->docker_version_tag);
    }

    if(new_context->docker_repository != 0) {
        free(current_context->docker_repository);
        current_context->docker_repository = strdup(new_context->docker_repository);
    }

    if(new_context->mount_point_addressing_method != 0) {
        free(current_context->mount_point_addressing_method);
        current_context->mount_point_addressing_method = strdup(new_context->mount_point_addressing_method);
    }

    if(new_context->started_instances != -1) {
        if(new_context->started_instances < current_context->started_instances) {
            //remove started instances
            while(current_context->started_instances > new_context->started_instances) {
                log_message(2, "stopping instance of type %s\n", current_context->function_type_string);
                rc = manager_stop_instance(current_context);
                if(rc != NTS_ERR_OK) {
                    log_error("manager_stop_instance failed");
                    return NTS_ERR_FAILED;
                    break;
                }
            }
        }
        else if(new_context->started_instances > current_context->started_instances) {
            //add started instances
            while(current_context->started_instances < new_context->started_instances) {
                log_message(2, "staring instance of type %s\n", current_context->function_type_string);
                rc = manager_start_instance(current_context);
                if(rc != NTS_ERR_OK) {
                    log_error("manager_start_instance failed");
                    return NTS_ERR_FAILED;
                    break;
                }
            }
        }
    }

    if(new_context->mounted_instances != -1) {
        if(new_context->mounted_instances < current_context->mounted_instances) {
            //remove mounted instances
            while(current_context->mounted_instances > new_context->mounted_instances) {
                log_message(2, "unmounting instance of type %s\n", current_context->function_type_string);
                rc = manager_unmount_instance(current_context);
                if(rc != NTS_ERR_OK) {
                    log_error("manager_unmount_instance failed");
                    break;
                }
            }
        }
        else if(new_context->mounted_instances > current_context->mounted_instances) {
            //add mounted instances
            while(current_context->mounted_instances < new_context->mounted_instances) {
                log_message(2, "mouting instance of type %s\n", current_context->function_type_string);
                rc = manager_mount_instance(current_context);
                if(rc != NTS_ERR_OK) {
                    log_error("manager_mount_instance failed");
                    break;
                }
            }
        }
    }

    return NTS_ERR_OK;
}

static int manager_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    sr_change_iter_t *it = 0;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = 0;
    sr_val_t *new_value = 0;

    if(event == SR_EV_CHANGE) {
        manager_network_function_type new_context;
        new_context.function_type = 0;          //not to be used. use only from current_context
        new_context.function_type_string = 0;   //not to be used. use only from current_context
        int index = -1;

        rc = sr_get_changes_iter(session, NTS_FUNCTION_LIST_SCHEMA_XPATH"//.", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed");
            return SR_ERR_VALIDATION_FAILED;
        }

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            char *ov = sr_val_to_str(old_value);
            char *nv = sr_val_to_str(new_value);

            //get function type and index
            char *function_type_string = strdup(strstr(new_value->xpath, "function-type='") + 15);
            *strchr(function_type_string, '\'') = 0;
            
            //if context is new
            if((new_context.function_type_string == 0) || (strcmp(new_context.function_type_string, function_type_string) != 0)) {

                if(new_context.function_type_string != 0) {
                    if(manager_process_change(index, &new_context) != NTS_ERR_OK) {
                        manager_context_free(&new_context);
                        return SR_ERR_VALIDATION_FAILED;
                    }

                    manager_context_free(&new_context);
                }

                //-1 means no change
                new_context.function_type_string = function_type_string;
                new_context.started_instances = -1;
                new_context.mounted_instances = -1;
                new_context.mount_point_addressing_method = 0;
                new_context.docker_instance_name = 0;
                new_context.docker_version_tag = 0;
                new_context.docker_repository = 0;

                new_context.data_changed = false;

                //find intex in manager_context[]
                for(int i = 0; i < manager_installed_function_types_count; i++) {
                    if(strcmp(function_type_string, manager_context[i].function_type_string) == 0) {
                        index = i;
                        break;
                    }
                }
            }

            char *leaf_path  = strdup(strstr(new_value->xpath, "']/") + 3);
            if(strcmp(leaf_path, "started-instances") == 0) {
                new_context.started_instances = new_value->data.uint16_val;
            }
            else if(strcmp(leaf_path, "mounted-instances") == 0) {
                new_context.mounted_instances = new_value->data.uint16_val;
            }
            else if(strcmp(leaf_path, "mount-point-addressing-method") == 0) {
                new_context.mount_point_addressing_method = strdup(nv);
            }
            else if(strcmp(leaf_path, "docker-instance-name") == 0) {
                new_context.docker_instance_name = strdup(nv);
            }
            else if(strcmp(leaf_path, "docker-version-tag") == 0) {
                new_context.docker_version_tag = strdup(nv);
            }
            else if(strcmp(leaf_path, "docker-repository") == 0) {
                new_context.docker_repository = strdup(nv);
            }
            else {
                new_context.data_changed = true;
            }

            free(leaf_path);
            free(ov);
            free(nv);
            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);
        
        if(index != -1) {
            if(manager_process_change(index, &new_context) != NTS_ERR_OK) {
                manager_context_free(&new_context);
                return SR_ERR_VALIDATION_FAILED;
            }

            manager_context_free(&new_context);
        }
    }
    else if(event == SR_EV_DONE) {
        bool global_change = true;

        rc = sr_get_changes_iter(session, NTS_SIMULATION_SCHEMA_XPATH"//.", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed");
            return SR_ERR_VALIDATION_FAILED;
        }

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            if(strstr(new_value->xpath, NTS_FUNCTION_LIST_SCHEMA_XPATH) == new_value->xpath) {
                global_change = false;
                sr_free_val(old_value);
                sr_free_val(new_value);
                break;
            }

            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);

        // commit all updates
        for(int i = 0; i < manager_installed_function_types_count; i++) {
            for(int j = 0; j < manager_context[i].started_instances; j++) {
                if(global_change || manager_context[i].data_changed || (manager_context[i].instance[j].is_configured == false)) {
                    log_message(2, "configuring instance %d of type %s\n", j, manager_context[i].function_type_string);
                    rc = manager_config_instance(&manager_context[i], &manager_context[i].instance[j]);
                    if(rc != NTS_ERR_OK) {
                        log_error("manager_config_instance failed");
                    }
                }
            }

            manager_context[i].data_changed = false;
        }
        global_change = false;
    }

    return SR_ERR_OK;
}

static int manager_instances_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data) {
    
    char value[100];

    *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), NTS_FUNCTION_LIST_SCHEMA_XPATH, 0, 0, 0);
    if(*parent == 0) {
        log_error("lyd_new_path failed");
        return SR_ERR_OPERATION_FAILED;
    }

    for(int i = 0; i < manager_installed_function_types_count; i++) {
        char *ftype_path = 0;
        asprintf(&ftype_path, "%s[function-type='%s']/instances/instance", NTS_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type_string);
        for(int j = 0; j < manager_context[i].started_instances; j++) {
            char *instance_path = 0;
            asprintf(&instance_path, "%s[name='%s']", ftype_path, manager_context[i].instance[j].name);

            char *full_path = 0;

            asprintf(&full_path, "%s/mount-point-addressing-method", instance_path);
            if(lyd_new_path(*parent, NULL, full_path, manager_context[i].instance[j].mount_point_addressing_method, 0, 0) == 0) {
                log_error("lyd_new_path failed");
                return SR_ERR_OPERATION_FAILED;
            }
            free(full_path);

            asprintf(&full_path, "%s/networking/docker-ip", instance_path);
            if(lyd_new_path(*parent, NULL, full_path, manager_context[i].instance[j].docker_ip, 0, 0) == 0) {
                log_error("lyd_new_path failed");
                return SR_ERR_OPERATION_FAILED;
            }
            free(full_path);

            asprintf(&full_path, "%s/networking/docker-port", instance_path);
            sprintf(value, "%d", manager_context[i].instance[j].docker_port);
            if(lyd_new_path(*parent, NULL, full_path, value, 0, 0) == 0) {
                log_error("lyd_new_path failed");
                return SR_ERR_OPERATION_FAILED;
            }
            free(full_path);

            asprintf(&full_path, "%s/networking/host-ip", instance_path);
            if(lyd_new_path(*parent, NULL, full_path, manager_context[i].instance[j].host_ip, 0, 0) == 0) {
                log_error("lyd_new_path failed");
                return SR_ERR_OPERATION_FAILED;
            }
            free(full_path);

            asprintf(&full_path, "%s/networking/host-port", instance_path);
            sprintf(value, "%d", manager_context[i].instance[j].host_port);
            if(lyd_new_path(*parent, NULL, full_path, value, 0, 0) == 0) {
                log_error("lyd_new_path failed");
                return SR_ERR_OPERATION_FAILED;
            }
            free(full_path);

            free(instance_path);
        }
        free(ftype_path);
    }

    return SR_ERR_OK;
}

static int manager_stats_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data) {
    char value[128];

    *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), NTS_SIMULATION_SCHEMA_XPATH, 0, 0, 0);
    if(*parent == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    docker_usage_t usage = docker_usage_get(manager_context, manager_installed_function_types_count);

    sprintf(value, "%.2f", usage.cpu);
    if(lyd_new_path(*parent, NULL, NTS_SIMULATION_SCHEMA_XPATH"/cpu-usage", value, 0, 0) == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%.0f", usage.mem);
    if(lyd_new_path(*parent, NULL, NTS_SIMULATION_SCHEMA_XPATH"/mem-usage", value, 0, 0) == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    //setup sdn-controller defaults
    sprintf(value, "%d", framework_environment.host_base_port);
    if(lyd_new_path(*parent, NULL, NTS_SIMULATION_SCHEMA_XPATH"/base-port", value, 0, 0) == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", framework_environment.ssh_connections);
    if(lyd_new_path(*parent, NULL, NTS_SIMULATION_SCHEMA_XPATH"/ssh-connections", value, 0, 0) == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    sprintf(value, "%d", framework_environment.tls_connections);
    if(lyd_new_path(*parent, NULL, NTS_SIMULATION_SCHEMA_XPATH"/tls-connections", value, 0, 0) == 0) {
        return SR_ERR_OPERATION_FAILED;
    }

    return SR_ERR_OK;
}
