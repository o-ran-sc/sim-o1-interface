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
#include <inttypes.h>
#include <assert.h>

#include "core/session.h"
#include "core/framework.h"

#define SCHEMA_LEAFREF_TOTAL_ENTRIES      11

static int schema_instance_add_module(populate_instance_t *instance, const struct lys_module *module);
static int schema_populate_late_resolve_add_leaf(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r);
static const char* schema_leafref_temp_val(int index);

int schema_populate_recursive(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r) {
    assert_session();
    assert(job);
    assert(schema);
    assert(instance);
    
    char *resolved_schema_path = lys_path(schema, LYS_PATH_FIRST_PREFIX);
    bool schema_operational = ((schema->flags & LYS_CONFIG_W) == 0);

    schema_populate_rerun_switch:
    switch(schema->nodetype) {
        //for container, just add it to the xpath, and iterate it's childeren to further traverse the tree
        case LYS_CONTAINER: {
            //add container

            struct lyd_node *new_parent_o = parent_o;
            struct lyd_node *new_parent_r = parent_r;

            new_parent_o = lyd_new(parent_o, schema->module, schema->name);
            if(!new_parent_o) {
                log_error("error creating container operational -> %s", schema->name);
                log_error("ly_error: %s\n", ly_errmsg(session_context));
                return NTS_ERR_FAILED;
            }

            if(!schema_operational && !framework_arguments.operational_only) {
                new_parent_r = lyd_new(parent_r, schema->module, schema->name);
                if(!new_parent_r) {
                    log_error("error creating container running -> %s", schema->name);
                    log_error("ly_error: %s\n", ly_errmsg(session_context));
                    return NTS_ERR_FAILED;
                }
            }

            if(!instance->init) {
                instance->init = true;
                instance->operational = new_parent_o;
                instance->running = new_parent_r;
            }

            char mandatory = ' ';
            if((schema->flags & LYS_MAND_TRUE) != 0) {
                mandatory = 'M';
            }
            if((schema->parent) && (schema->parent->nodetype == LYS_CASE)) {
                if((schema->parent->flags & LYS_MAND_TRUE) != 0) {
                    mandatory = 'M';
                }
            }
            bool node_operational = ((schema->flags & LYS_CONFIG_W) == 0);
            char *xpath = lyd_path(new_parent_o);
            log_message(1, LOG_COLOR_BOLD_MAGENTA"[%15s] "LOG_COLOR_BOLD_YELLOW"[%c%c]"LOG_COLOR_RESET" %s\n", "CONTAINER", node_operational ? 'O' : 'R', mandatory, xpath);
            free(xpath);

            int rc = schema_instance_add_module(instance, schema->module);
            if(rc != NTS_ERR_OK) {
                log_error("schema_instance_add_module failed");
                return rc;
            }

            struct lys_node *child = 0;
            LY_TREE_FOR(schema->child, child) {
                int rc = schema_populate_recursive(job, instance, child, new_parent_o, new_parent_r);
                if(rc != NTS_ERR_OK) {
                    log_error("schema_populate_recursive failed");
                    return rc;
                }
            }
        } break;

        //choice does not appear into the data path. get all the avalable choices, and choose a random one
        case LYS_CHOICE: {
            int choice_no = 0;
            struct lys_node_case *choice = (struct lys_node_case *)schema->child;
            while(choice) {
                choice_no++;
                choice = (struct lys_node_case *)choice->next;
            }

            //select a random choice
            choice_no = rand_uint16() % choice_no;

            int i = 0;
            choice = (struct lys_node_case *)schema->child;
            while(i < choice_no) {
                i++;
                choice = (struct lys_node_case *)choice->next;
            }

            //after the choice was made, rerun the adding without other tree-searching (will run into a CASE)
            schema = (struct lys_node *)choice;
            goto schema_populate_rerun_switch;
        } break;

        //the actual "case" is this node's child, so we skip directly to that
        case LYS_CASE:
            //case contains mandatory
            if(schema->child) {
                schema = schema->child;
                goto schema_populate_rerun_switch;
            }
            else {
                //blank case
                return NTS_ERR_OK;
            }
            break;

        //populate a list
        case LYS_LIST: {
            //get min-max for current list
            struct lys_node_list *list = (struct lys_node_list *)schema;
            int min_added = list->min ? list->min : 1;
            int max_added = list->max ? list->max : 65536;
            
            int populating_times = framework_populate_get_instance_count(resolved_schema_path);
            if(populating_times != 0) {
                if(min_added < populating_times) {
                    min_added = populating_times;
                }
                if(min_added > max_added) {
                    min_added = max_added;
                    log_error("min-elements exceeds max-elements for path %s. truncated to %d", resolved_schema_path, max_added);
                }
                log_message(2, "populating %d times list '%s'\n", min_added, resolved_schema_path);

                //populate node with the intended number of values
                while(min_added) {
                    //add list

                    struct lyd_node *new_parent_o = parent_o;
                    struct lyd_node *new_parent_r = parent_r;

                    new_parent_o = lyd_new(parent_o, schema->module, schema->name);
                    if(!new_parent_o) {
                        log_error("error creating list operational -> %s", schema->name);
                        log_error("ly_error: %s\n", ly_errmsg(session_context));
                        return NTS_ERR_FAILED;
                    }

                    if(!schema_operational && !framework_arguments.operational_only) {
                        new_parent_r = lyd_new(parent_r, schema->module, schema->name);
                        if(!new_parent_r) {
                            log_error("error creating container running -> %s", schema->name);
                            log_error("ly_error: %s\n", ly_errmsg(session_context));
                            return NTS_ERR_FAILED;
                        }
                    }

                    if(!instance->init) {
                        instance->init = true;
                        instance->operational = new_parent_o;
                        instance->running = new_parent_r;
                    }

                    char mandatory = ' ';
                    if((schema->flags & LYS_MAND_TRUE) != 0) {
                        mandatory = 'M';
                    }
                    if((schema->parent) && (schema->parent->nodetype == LYS_CASE)) {
                        if((schema->parent->flags & LYS_MAND_TRUE) != 0) {
                            mandatory = 'M';
                        }
                    }
                    bool node_operational = ((schema->flags & LYS_CONFIG_W) == 0);
                    char *xpath = lyd_path(new_parent_o);
                    log_message(1, LOG_COLOR_BOLD_MAGENTA"[%15s] "LOG_COLOR_BOLD_YELLOW"[%c%c]"LOG_COLOR_RESET" %s\n", "LIST", node_operational ? 'O' : 'R', mandatory, xpath);
                    free(xpath);

                    int rc = schema_instance_add_module(instance, schema->module);
                    if(rc != NTS_ERR_OK) {
                        log_error("schema_instance_add_module failed");
                        return rc;
                    }

                    //populate all list elements below in the tree
                    struct lys_node *child = 0;
                    LY_TREE_FOR(schema->child, child) {
                        int rc = schema_populate_recursive(job, instance, child, new_parent_o, new_parent_r);
                        if(rc != NTS_ERR_OK) {
                            log_error("schema_populate_recursive failed");
                            return rc;
                        }
                    }

                    min_added--;
                }
            }
            else {
                log_message(2, "not populating list '%s'\n", resolved_schema_path);
            }
        } break;

        //populate the leaf
        case LYS_LEAF: {
            if(schema_populate_add_leaf(job, instance, schema, parent_o, parent_r) != NTS_ERR_OK) {
                return NTS_ERR_FAILED;
            }            
        } break;

        //leaflist is treated the same as a LEAF, but with min/max characteristics of a LIST
        case LYS_LEAFLIST: {
            //get min-max for the current leaflist
            struct lys_node_leaflist *list = (struct lys_node_leaflist *)schema;
            int min_added = list->min ? list->min : 1;
            int max_added = list->max ? list->max : 65536;
            
            int populating_times = framework_populate_get_instance_count(resolved_schema_path);
            if(populating_times != 0) {
                if(min_added < populating_times) {
                    min_added = populating_times;
                }
                if(min_added > max_added) {
                    min_added = max_added;
                    log_error("min-elements exceeds max-elements for path %s truncated to %d", resolved_schema_path, max_added);
                }
                log_message(2, "populating %d times leaflist '%s'\n", min_added, resolved_schema_path);

                //add the leafs
                while(min_added) {
                    if(schema_populate_add_leaf(job, instance, schema, parent_o, parent_r) != NTS_ERR_OK) {
                        return NTS_ERR_FAILED;
                    }   
                    min_added--;
                }
            }
            else {
                log_message(2, "not populating leaflist '%s'\n", resolved_schema_path);
            }
        } break;

        case LYS_ACTION:
        case LYS_INPUT:
        case LYS_OUTPUT:
        case LYS_NOTIF:
            //don't do anything, since we don't want to add this or go further down the tree when we meet them
            break;

        //other node types (grouping, uses, augment, etc just traverse)
        default:
            log_message(1, "[%15s]      %s\n", typeutils_yang_nodetype_to_str(schema->nodetype), resolved_schema_path);

            //traverse the tree down for any other node types, without adding anything to the path
            struct lys_node *child = 0;
            LY_TREE_FOR(schema->child, child) {
                int rc = schema_populate_recursive(job, instance, child, parent_o, parent_r);
                if(rc != NTS_ERR_OK) {
                    return rc;
                }
            }
            break;
    }

    free(resolved_schema_path);

    return NTS_ERR_OK;
}

int schema_populate_add_leaf(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r) {
    assert_session();
    assert(job);
    assert(schema);
    assert(parent_o);

    int rc = schema_instance_add_module(instance, schema->module);
    if(rc != NTS_ERR_OK) {
        log_error("bad schema_instance_add module");
        return rc;
    }

    struct lys_type *type = &((struct lys_node_leaf *)schema)->type;
    
    char *data_xpath = lyd_path(parent_o);
    data_xpath = (char *)realloc(data_xpath, sizeof(char) * (strlen(data_xpath) + 1 + strlen(schema->name) + 1));
    if(!data_xpath) {
        log_error("lyd_path failed");
        return NTS_ERR_FAILED;
    }
    strcat(data_xpath, "/");
    strcat(data_xpath, schema->name);

    //check whether the value is MANDATORY or not (for logging purposes)
    char mandatory = ' ';
    if((schema->flags & LYS_MAND_TRUE) != 0) {
        mandatory = 'M';
    }

    if((schema->parent) && (schema->parent->nodetype == LYS_CASE)) {
        if((schema->parent->flags & LYS_MAND_TRUE) != 0) {
            mandatory = 'M';
        }
    }

    bool node_operational = ((schema->flags & LYS_CONFIG_W) == 0);
    log_message(1, LOG_COLOR_BOLD_MAGENTA"[%15s] "LOG_COLOR_BOLD_YELLOW"[%c%c]"LOG_COLOR_RESET" %s <-- ", typeutils_yang_type_to_str(type->base), node_operational ? 'O' : 'R', mandatory, data_xpath);
    free(data_xpath);


    char *resolved_schema_path = lys_path(schema, LYS_PATH_FIRST_PREFIX);
    char *value = framework_populate_get_restrict_schema(resolved_schema_path);
    free(resolved_schema_path);

    schema_populate_add_leaf_rerun_switch:
    switch(type->base) {
        case LY_TYPE_UNION:
            if((type->info.uni.count == 0) && (type->der != 0)) {
                type = &type->der->type;
            }

            type = &type->info.uni.types[0];
            goto schema_populate_add_leaf_rerun_switch;
            break;

        case LY_TYPE_INST: {
            struct lyd_node *parent = parent_o;
            while(parent->parent) {
                parent = parent->parent;
            }

            if(value == 0) {
                value = lyd_path(parent);
            }

            goto schema_populate_add_leaf_actual_add;
        } break;

        case LY_TYPE_EMPTY:
            if(rand_bool()) {   //if present, add it
                log_message(1, LOG_COLOR_CYAN"present"LOG_COLOR_RESET"\n");
                goto schema_populate_add_leaf_actual_add;
            }
            else {
                log_message(1, LOG_COLOR_CYAN"empty"LOG_COLOR_RESET"\n");
                return NTS_ERR_OK;
            }
            break;

        case LY_TYPE_LEAFREF: {
            if(value == 0) {
                int index = 0;
                struct lyd_node *new_node = 0;
                while((new_node == 0) && (index < SCHEMA_LEAFREF_TOTAL_ENTRIES)) {
                    new_node = lyd_new_leaf(parent_o, schema->module, schema->name, schema_leafref_temp_val(index));
                    index++;
                }

                if(new_node == 0) {
                    log_error("error on lyd_new_leaf schema %s. didn't work with any temp val", schema->name);
                    return NTS_ERR_FAILED;
                }

                //based on the new_node's path, try to find elements of relative path for the leafref
                struct ly_set *set = lyd_find_path(new_node, type->info.lref.path);
                lyd_free(new_node);

                if(set && set->number) {
                    //choose a random schema and get its value
                    static int set_number = 0;  //checkAL aici trebuia oare random ?
                    set_number++;
                    if(set_number >= set->number) {
                        set_number = 0;
                    }
                    asprintf(&value, "%s", ((struct lyd_node_leaf_list *)set->set.d[set_number])->value_str);
                    if(!value) {
                        log_error("bad asprintf");
                        return NTS_ERR_FAILED;
                    }

                    int rc = schema_instance_add_module(instance, set->set.d[set_number]->schema->module);
                    if(rc != NTS_ERR_OK) {
                        log_error("bad schema_instance_add module");
                        return rc;
                    }

                    ly_set_free(set);

                    goto schema_populate_add_leaf_actual_add;
                }
                else {
                    //adding to late-resolve list, as we don't have any nodes in the leafref path
                    int rc = schema_populate_late_resolve_add_leaf(job, instance, schema, parent_o, parent_r);
                    if(rc != NTS_ERR_OK) {
                        return rc;
                    }

                    if(!job->late_resolving) {
                        log_message(1, LOG_COLOR_BOLD_YELLOW"added to late-resolve list...\n"LOG_COLOR_RESET);
                    }
                    else {
                        log_message(1, LOG_COLOR_BOLD_YELLOW"REadded to late-resolve list...\n"LOG_COLOR_RESET);
                    }

                    return NTS_ERR_OK;
                }
            }
        } break;
      
        default:
            if(value == 0) {
                value = rand_get_populate_value(type);
            }
            goto schema_populate_add_leaf_actual_add;
            break;
    }

    schema_populate_add_leaf_actual_add: {
        //add schema to operational
        struct lyd_node *new_node = lyd_new_leaf(parent_o, schema->module, schema->name, value);
        if(new_node == 0) {
            log_error("error on lyd_new_leaf operational: %s", ly_errmsg(session_context));
            return NTS_ERR_FAILED;
        }
        
        //print out the value
        if(value) {
            log_message(1, LOG_COLOR_CYAN"'%s'"LOG_COLOR_RESET"\n",  value);
        }
        else {
            log_message(1, "\n");
        }

        //if it fits the case, add it also to running
        if(!node_operational && !framework_arguments.operational_only) {
            struct lyd_node *new_node = lyd_new_leaf(parent_r, schema->module, schema->name, value);
            if(new_node == 0) {
                log_error("error on lyd_new_leaf running: %s", ly_errmsg(session_context));
                return NTS_ERR_FAILED;
            }
        }
        
        free(value);
    }

    return NTS_ERR_OK;
}

static int schema_instance_add_module(populate_instance_t *instance, const struct lys_module *module) {
    assert(module);
    assert(instance);

    for(int i = 0; i < instance->mod_count; i++) {
        if(instance->modules[i] == module) {
            return NTS_ERR_OK;
        }
    }

    instance->modules = (const struct lys_module **)realloc(instance->modules, sizeof(const struct lys_module *) * (instance->mod_count + 1));
    if(!instance->modules) {
        log_error("bad realloc");
        return NTS_ERR_FAILED;
    }
    instance->modules[instance->mod_count] = module;
    instance->mod_count++;

    return NTS_ERR_OK;
}

static int schema_populate_late_resolve_add_leaf(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r) {
    assert(job);
    assert(instance);

    job->late_resolve_schema = (struct lys_node **)realloc(job->late_resolve_schema, (job->late_resolve_count + 1) * sizeof(struct lys_node *));
    if(!job->late_resolve_schema) {
        log_error("bad realloc");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_schema[job->late_resolve_count] = schema;

    job->late_resolve_parent_o = (struct lyd_node **)realloc(job->late_resolve_parent_o, (job->late_resolve_count + 1) * sizeof(struct lyd_node *));
    if(!job->late_resolve_parent_o) {
        log_error("bad realloc");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_parent_o[job->late_resolve_count] = parent_o;

    job->late_resolve_parent_r = (struct lyd_node **)realloc(job->late_resolve_parent_r, (job->late_resolve_count + 1) * sizeof(struct lyd_node *));
    if(!job->late_resolve_parent_r) {
        log_error("bad realloc");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_parent_r[job->late_resolve_count] = parent_r;

    job->late_resolve_instance = (populate_instance_t **)realloc(job->late_resolve_instance, (job->late_resolve_count + 1) * sizeof(populate_instance_t *));
    if(!job->late_resolve_instance) {
        log_error("bad realloc");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_instance[job->late_resolve_count] = instance;

    job->late_resolve_count++;

    return NTS_ERR_OK;
}

static const char* schema_leafref_temp_val(int index) {
    switch(index) {
        case 0:
            return "1";
            break;

        case 1:
            return "1.1.1.1";
            break;

        case 2:
            return "Fd:4D:63:A5:21:C5";
            break;

        case 3:
            return "";
            break;

        case 4:
            return "::1";
            break;

        case 5:
            return "false";
            break;

        case 6:
            return "TDD";
            break;

        case 7:
            return "NR";
            break;

        case 8:
            return "best-effort";
            break;

        case 9:
            return "yes-fault:o-ran-sc-alarm-type";
            break;

        case 10:
            return "";
            break;

        


        default:
            log_error("index out of bounds");
            return 0;
            break;
    }
}
