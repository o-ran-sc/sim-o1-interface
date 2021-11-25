/*************************************************************************
*
* Copyright 2021 highstreet technologies GmbH and others
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

#include "populate.h"
#include "populate_internal.h"
#include "utils/log_utils.h"
#include "utils/debug_utils.h"
#include "utils/rand_utils.h"
#include "utils/type_utils.h"

#include "core/datastore/schema.h"
#include "core/datastore/operations.h"
#include "core/framework.h"
#include "core/session.h"

#include <sysrepo.h>
#include <libyang/libyang.h>

#include <stdlib.h>
#include <assert.h>

populate_job_t populate_job = {0};

int datastore_populate_all() {
    log_add_verbose(1, "populate starting...\n");

    //load pre-populated data
    for(int i = 0; i < framework_config.datastore_populate.preg_running_count; i++) {
        char *filename = framework_config.datastore_populate.preg_running[i];
        struct lyd_node *data = datastore_load_external(filename, false);
        if(data == 0) {
            log_add_verbose(2, "datastore_load_external() could not load %s\n", filename);
        }
        else {
            log_add_verbose(1, "loaded into running %s (%s)\n", filename, data->schema->module->name);
            if(populate_job.running) {
                int rc = lyd_merge(populate_job.running, data, 0);
                if(rc != 0) {
                    log_error("lyd_merge failed\n");
                }

                lyd_free_withsiblings(data);
            }
            else {
                populate_job.running = data;
            }
        }

        //also load as dev
        data = datastore_load_external(filename, false);
        if(data == 0) {
            log_add_verbose(2, "datastore_load_external() could not load %s\n", filename);
        }
        else {
            log_add_verbose(1, "loaded into dev %s (%s)\n", filename, data->schema->module->name);
            if(populate_job.dev) {
                int rc = lyd_merge(populate_job.dev, data, 0);
                if(rc != 0) {
                    log_error("lyd_merge failed\n");
                }

                lyd_free_withsiblings(data);
            }
            else {
                populate_job.dev = data;
            }
        }
    }

    for(int i = 0; i < framework_config.datastore_populate.preg_operational_count; i++) {
        char *filename = framework_config.datastore_populate.preg_operational[i];
        struct lyd_node *data = datastore_load_external(filename, true);
        if(data == 0) {
            log_add_verbose(2, "datastore_load_external() could not load %s\n", filename);
        }
        else {
            log_add_verbose(1, "loaded into operational %s (%s)\n", filename, data->schema->module->name);
            if(populate_job.operational) {
                int rc = lyd_merge(populate_job.operational, data, 0);
                if(rc != 0) {
                    log_error("lyd_merge failed\n");
                }

                lyd_free_withsiblings(data);
            }
            else {
                populate_job.operational = data;
            }
        }

        //also load as dev
        data = datastore_load_external(filename, true);
        if(data == 0) {
            log_add_verbose(2, "datastore_load_external() could not load %s\n", filename);
        }
        else {
            log_add_verbose(1, "loaded into dev %s (%s)\n", filename, data->schema->module->name);
            if(populate_job.dev) {
                int rc = lyd_merge(populate_job.dev, data, 0);
                if(rc != 0) {
                    log_error("lyd_merge failed\n");
                }

                lyd_free_withsiblings(data);
            }
            else {
                populate_job.dev = data;
            }
        }
    }

    if(framework_config.datastore_populate.random_generation_enabled) {
        //get all xpaths
        char **xpaths = 0;
        int xpaths_count = datastore_schema_get_xpaths(&xpaths);
        if(xpaths_count < 0) {
            log_error("datastore_schema_get_xpaths failed\n");
            return NTS_ERR_FAILED;
        }

        //exclude pre-populated modules; also modules excluded by config are not outputted by datastore_schema_get_xpaths
        struct lyd_node *elem;
        LY_TREE_FOR(populate_job.dev, elem) {
            for(int i = 0; i < xpaths_count; i++) {
                if(strstr(xpaths[i], elem->schema->module->name) == (xpaths[i] + 1)) {  //xpaths[i] is "/module:container"
                    log_add_verbose(1, "excluding "LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" as being pre-populated...\n", xpaths[i]);
                    free(xpaths[i]);

                    xpaths_count--;
                    for(int j = i; j < xpaths_count; j++) {
                        xpaths[j] = xpaths[j + 1];
                    }

                    break;
                }
            }
        }

        populate_instance_t *instance = (populate_instance_t *)malloc(sizeof(populate_instance_t) * xpaths_count);
        if(!instance) {
            log_error("bad malloc\n");
            for(int i = 0; i < xpaths_count; i++) {
                free(xpaths[i]);
            }
            free(xpaths);
            return NTS_ERR_FAILED;
        }

        //RANDOM generate everything
        for(int i = 0; i < xpaths_count; i++) {
            log_add_verbose(1, "generating "LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" data...\n", xpaths[i]);

            struct lys_node *schema_node = (struct lys_node *)ly_ctx_get_node(session_context, 0, xpaths[i], 0);
            if(schema_node == 0) {
                log_error("ly_ctx_get_node failed for %s\n", xpaths[i]);
                return NTS_ERR_FAILED;
            }

            if(!schema_node->module->implemented) {
                log_add_verbose(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
                log_error("module is not implemented for %s\n", xpaths[i]);
                return NTS_ERR_FAILED;
            }

            if((schema_node->flags & LYS_STATUS_DEPRC) != 0) {
                log_add_verbose(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
                log_error("module is deprecated for %s\n", xpaths[i]);
                return NTS_ERR_FAILED;
            }

            //populate current instance vals
            instance[i].init = 0;
            instance[i].xpath = strdup(xpaths[i]);
            instance[i].modules = 0;
            instance[i].mod_count = 0;
            instance[i].operational = 0;
            instance[i].running = 0;
            instance[i].dev = 0;
            
            //do the actual population
            int rc = populate_recursive(&populate_job, &instance[i], schema_node, 0, 0, 0, 0);
            if(rc != NTS_ERR_OK) {
                log_error("populate_recursive failed instance %d with xpath %s\n", i, instance[i].xpath);
                return rc;
            }
        }

        //link everything so we would be able to find everything in late-resolve
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_populate_data() done generating, now linking... (%d root nodes)\n"LOG_COLOR_RESET, xpaths_count);
        for(int i = 0; i < xpaths_count; i++) {
            if(instance[i].dev) {
                if(populate_job.dev) {
                    int rc = lyd_insert_sibling(&populate_job.dev, instance[i].dev);
                    if(rc != 0) {
                        log_error("lyd_insert_sibling\n");
                        return NTS_ERR_FAILED;
                    }
                }
                else {
                    populate_job.dev = instance[i].dev;
                }
            }

            if(instance[i].operational) {
                if(populate_job.operational) {
                    int rc = lyd_insert_sibling(&populate_job.operational, instance[i].operational);
                    if(rc != 0) {
                        log_error("lyd_insert_sibling\n");
                        return NTS_ERR_FAILED;
                    }
                }
                else {
                    populate_job.operational = instance[i].operational;
                }
            }

            if(instance[i].running) {
                if(populate_job.running) {
                    int rc = lyd_insert_sibling(&populate_job.running, instance[i].running);
                    if(rc != 0) {
                        log_error("lyd_insert_sibling\n");
                        return NTS_ERR_FAILED;
                    }
                }
                else {
                    populate_job.running = instance[i].running;
                }
            }
        }

        //late-resolve
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_populate_data() starting late-resolve process...\n"LOG_COLOR_RESET);
        if(populate_job.late_resolve_count) {
            int rc = populate_late_resolve(&populate_job);
            if(rc != NTS_ERR_OK) {
                log_error("populate_late_resolve failed\n");
                return rc;
            }
        }
        
        //validate data and remove invalid nodes
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_populate_data() validating\n"LOG_COLOR_RESET);
        int rc = populate_validate(instance, xpaths_count);
        if(rc != NTS_ERR_OK) {
            log_error("populate_validate failed\n");
            return rc;
        }

        //cleanup
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_populate_data() cleanup\n"LOG_COLOR_RESET);
        for(int i = 0; i < xpaths_count; i++) {
            log_add(1, "%d ", i);

            free(instance[i].modules);
            free(instance[i].xpath);

            free(xpaths[i]);
        }
        log_add(1, "\n");

        free(xpaths);
        free(populate_job.late_resolve_instance);
        free(populate_job.late_resolve_schema);
        free(populate_job.late_resolve_parent_d);
        free(populate_job.late_resolve_parent_o);
        free(populate_job.late_resolve_parent_r);

        populate_job.late_resolving = false;
        populate_job.late_resolve_instance = 0;
        populate_job.late_resolve_schema = 0;
        populate_job.late_resolve_parent_d = 0;
        populate_job.late_resolve_parent_o = 0;
        populate_job.late_resolve_parent_r = 0;
        populate_job.late_resolve_count = 0;
    }

    if(populate_job.running) {
        log_add_verbose(1, "editing batch for RUNNING... ");
        int rc = sr_edit_batch(session_running, populate_job.running, "replace");
        // lyd_free_withsiblings(populate_job.running); //checkAL
        if (rc != SR_ERR_OK) {
            log_add(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            return NTS_ERR_FAILED;
        }
        else {
            log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }
    }
    
    if(populate_job.operational) {
        log_add_verbose(1, "editing batch for OPERATIONAL... ");
        int rc = sr_edit_batch(session_operational, populate_job.operational, "replace");
        // lyd_free_withsiblings(populate_job.operational); //checkAL
        if (rc != SR_ERR_OK) {
            log_add(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            return NTS_ERR_FAILED;
        }
        else {
            log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }
    }


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
    
    log_add_verbose(1, "populate finished...\n");
    return NTS_ERR_OK;
}

int datastore_populate_update_operational(const char **xpath, int xpath_len) {

    if(xpath_len == 0) {
        return NTS_ERR_OK;
    }

    populate_instance_t *instance = 0;
    int instance_count = 0;

    for(int i = 0; i < xpath_len; i++) {
        log_add_verbose(1, "generating "LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" operational data...\n", xpath[i]);

        struct lyd_node *node_dev = datastore_operations_get_lyd_node(populate_job.dev, xpath[i]);
        if(node_dev == 0) {
            log_error("datastore_operations_get_lyd_node failed on dev\n");
            return NTS_ERR_FAILED;
        }

        struct lyd_node *node_running = datastore_operations_get_lyd_node(populate_job.running, xpath[i]);
        if(node_running == 0) {
            log_error("datastore_operations_get_lyd_node failed on running\n");
            return NTS_ERR_FAILED;
        }

        //operational node (container/list) does not exist yet
        struct lyd_node *node_operational = lyd_new_path(populate_job.operational, 0, xpath[i], 0, 0, LYD_PATH_OPT_NOPARENTRET | LYD_PATH_OPT_UPDATE);
        if(node_operational == 0) {
            log_error("lyd_new_path failed on operational\n");
            return NTS_ERR_FAILED;
        }

        struct lys_node *schema_node = node_dev->schema;

        int cinst = instance_count;
        instance_count++;
        instance = (populate_instance_t *)realloc(instance, sizeof(populate_instance_t) * instance_count);
        instance[cinst].init = true;
        instance[cinst].xpath = strdup(xpath[i]);
        instance[cinst].modules = 0;
        instance[cinst].mod_count = 0;
        instance[cinst].dev = node_dev;
        instance[cinst].operational = node_operational;
        instance[cinst].running = node_running;

        int rc = populate_instance_add_module(&instance[cinst], schema_node->module);
        if(rc != NTS_ERR_OK) {
            log_error("instance_add_module failed\n");
            return rc;
        }

        //populate-recursive pe toti childrenii, cu param only_operational == 1
        struct lys_node *elem;
        LY_TREE_FOR(schema_node->child, elem) {
            int rc = populate_recursive(&populate_job, &instance[cinst], elem, node_dev, node_operational, node_running, 1);
            if(rc != NTS_ERR_OK) {
                log_error("populate_recursive failed with xpath %s\n", instance[cinst].xpath);
                return rc;
            }
        }
    }

    //late resolve
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_populate_update_operational() starting late-resolve process...\n"LOG_COLOR_RESET);
    if(populate_job.late_resolve_count) {
        int rc = populate_late_resolve(&populate_job);
        if(rc != NTS_ERR_OK) {
            log_error("populate_late_resolve failed\n");
            return rc;
        }
    }

    // //validate
    // log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_populate_update_operational() validating\n"LOG_COLOR_RESET);

    // //build validate_instance' populate_validate must have root-path instances
    // populate_instance_t *validate_instance = 0;
    // int validate_instance_count = 0;

    // for(int i = 0; i < instance_count; i++) {
    //     //get root path from instance[i].xpath
    //     char *root_path = strdup(instance[i].xpath);
    //     *strstr(root_path + 1, "/") = 0;
        
    //     int found = validate_instance_count;
    //     for(int j = 0; j < validate_instance_count; j++) {
    //         if(strcmp(root_path, validate_instance[j].xpath) == 0) {
    //             found = j;
    //             break;
    //         }
    //     }

    //     //if not found
    //     if(found == validate_instance_count) {
    //         //add root path UNIQUE to validate_instance
    //         validate_instance_count++;
    //         validate_instance = (populate_instance_t *)realloc(validate_instance, sizeof(populate_instance_t) * validate_instance_count);

    //         validate_instance[found].init = true;
    //         validate_instance[found].xpath = strdup(root_path);
    //         validate_instance[found].modules = 0;
    //         validate_instance[found].mod_count = 0;
    //         validate_instance[found].dev = datastore_operations_get_lyd_node(populate_job.dev, root_path);
    //         validate_instance[found].operational = datastore_operations_get_lyd_node(populate_job.operational, root_path);
    //         validate_instance[found].running = datastore_operations_get_lyd_node(populate_job.running, root_path);
    //     }
    //     free(root_path);

    //     //add each instance[i].modules to validate_instance[].modules
    //     for(int j = 0; j < instance[i].mod_count; j++) {
    //         int rc = populate_instance_add_module(&validate_instance[found], instance[i].modules[j]);
    //         if(rc != NTS_ERR_OK) {
    //             log_error("instance_add_module failed\n");
    //             return rc;
    //         }
    //     }
    // }

    // int rc = populate_validate(validate_instance, validate_instance_count);
    // if(rc != NTS_ERR_OK) {
    //     log_error("populate_validate failed\n");
    //     return rc;
    // }

    //cleanup
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_populate_update_operational() cleanup\n"LOG_COLOR_RESET);
    // for(int i = 0; i < validate_instance_count; i++) {
    //     free(validate_instance[i].modules);
    //     free(validate_instance[i].xpath);
    // }
    // free(validate_instance);

    for(int i = 0; i < instance_count; i++) {
        free(instance[i].modules);
        free(instance[i].xpath);
    }
    free(instance);

    free(populate_job.late_resolve_instance);
    free(populate_job.late_resolve_schema);
    free(populate_job.late_resolve_parent_d);
    free(populate_job.late_resolve_parent_o);
    free(populate_job.late_resolve_parent_r);

    populate_job.late_resolving = false;
    populate_job.late_resolve_instance = 0;
    populate_job.late_resolve_schema = 0;
    populate_job.late_resolve_parent_d = 0;
    populate_job.late_resolve_parent_o = 0;
    populate_job.late_resolve_parent_r = 0;
    populate_job.late_resolve_count = 0;

    //edit batch and apply pe operational
    if(populate_job.operational) {
        log_add_verbose(1, "editing batch for OPERATIONAL... ");
        int rc = sr_edit_batch(session_operational, populate_job.operational, "replace");
        // lyd_free_withsiblings(populate_job.running); //checkAL
        if (rc != SR_ERR_OK) {
            log_add(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            return NTS_ERR_FAILED;
        }
        else {
            log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }
    

        //apply pe operational
        log_add_verbose(1, "appling changes to OPERATIONAL... ");
        rc = sr_apply_changes(session_operational, 0, 0);
        if (rc != SR_ERR_OK) {
            log_add(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            return NTS_ERR_FAILED;
        }
        else {
            log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }
    }
    
    log_add_verbose(1, "datastore_populate_update_operational() finished...\n");

    return NTS_ERR_OK;
}

int datastore_dynamic_operational_auto_callback(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    sr_change_iter_t *it = 0;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = 0;
    sr_val_t *new_value = 0;

    rc = sr_get_changes_iter(session, "//.", &it);
    if(rc != SR_ERR_OK) {
        log_error("sr_get_changes_iter failed\n");
        return SR_ERR_VALIDATION_FAILED;
    }

    //event-ul este mereu DONE

    char **add_item = 0;
    int add_item_len = 0;

    char *prev_xpath = strdup("x"); //a non empty value
    while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
        if(oper == SR_OP_CREATED) {
            if((new_value->type == SR_CONTAINER_T) || (new_value->type == SR_CONTAINER_PRESENCE_T) || (new_value->type == SR_LIST_T)) {
                add_item = (char**)realloc(add_item, sizeof(char *) * (add_item_len + 1));
                add_item[add_item_len] = strdup(new_value->xpath);
                add_item_len++;
            }
            
            datastore_operations_add_sr_val(populate_job.running, new_value);
            datastore_operations_add_sr_val(populate_job.dev, new_value);
        }
        else if(oper == SR_OP_DELETED) {
            if(strncmp(prev_xpath, old_value->xpath, strlen(prev_xpath)) != 0) {
                if((old_value->type == SR_CONTAINER_T) || (old_value->type == SR_CONTAINER_PRESENCE_T) || (old_value->type == SR_LIST_T)) {
                    datastore_operations_free_path(populate_job.running, old_value->xpath);
                    datastore_operations_free_path(populate_job.dev, old_value->xpath);
                    datastore_operations_free_path(populate_job.operational, old_value->xpath);
                    free(prev_xpath);
                    prev_xpath = strdup(old_value->xpath);
                }
                else {
                    datastore_operations_free_path(populate_job.running, old_value->xpath);
                    datastore_operations_free_path(populate_job.dev, old_value->xpath);
                }
            }
        }
        else if(oper == SR_OP_MODIFIED) {
            datastore_operations_change_sr_val(populate_job.running, new_value);
            datastore_operations_change_sr_val(populate_job.dev, new_value);
        }


        debug_print_sr_change(oper, old_value, new_value);
        
        sr_free_val(old_value);
        sr_free_val(new_value);
    }

    free(prev_xpath);
    sr_free_change_iter(it);

    //add operational (and dev)
    rc = datastore_populate_update_operational((const char **)add_item, add_item_len);
    if(rc != NTS_ERR_OK) {
        log_error("datastore_populate_update_operational error\n");
    }
    for(int i = 0; i < add_item_len; i++) {
        free(add_item[i]);
    }
    free(add_item);

    return SR_ERR_OK;
}
