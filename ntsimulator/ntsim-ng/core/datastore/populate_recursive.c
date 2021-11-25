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
#define _GNU_SOURCE

#include "populate.h"
#include "populate_internal.h"
#include "utils/log_utils.h"
#include "utils/rand_utils.h"
#include "utils/type_utils.h"

#include "core/datastore/schema.h"
#include "core/framework.h"
#include "core/session.h"

#include <sysrepo.h>
#include <libyang/libyang.h>

#include <stdlib.h>
#include <assert.h>


int populate_recursive(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_d, struct lyd_node *parent_o, struct lyd_node *parent_r, int operational_only) {
    assert(schema);
    
    char *resolved_schema_path = lys_path(schema, LYS_PATH_FIRST_PREFIX);
    bool element_operational = ((schema->flags & LYS_CONFIG_W) == 0);

    populate_recursive_rerun_switch:
    switch(schema->nodetype) {
        //for container, just add it to the xpath, and iterate it's childeren to further traverse the tree
        case LYS_CONTAINER: {
            //don't add if populating only operational
            if(operational_only && !element_operational) {
                return NTS_ERR_OK;
            }

            //add container

            struct lyd_node *new_parent_d = parent_d;
            struct lyd_node *new_parent_o = parent_o;
            struct lyd_node *new_parent_r = parent_r;

            new_parent_d = lyd_new(parent_d, schema->module, schema->name);
            if(!new_parent_d) {
                log_error("error creating container dev -> %s\n", schema->name);
                log_error("ly_error: %s\n", ly_errmsg(session_context));
                return NTS_ERR_FAILED;
            }

            new_parent_o = lyd_new(parent_o, schema->module, schema->name);
            if(!new_parent_o) {
                log_error("error creating container operational -> %s\n", schema->name);
                log_error("ly_error: %s\n", ly_errmsg(session_context));
                return NTS_ERR_FAILED;
            }

            if(!element_operational) {
                new_parent_r = lyd_new(parent_r, schema->module, schema->name);
                if(!new_parent_r) {
                    log_error("error creating container running -> %s\n", schema->name);
                    log_error("ly_error: %s\n", ly_errmsg(session_context));
                    return NTS_ERR_FAILED;
                }
            }

            if(!instance->init) {
                instance->init = true;
                instance->dev = new_parent_d;
                instance->operational = new_parent_o;
                instance->running = new_parent_r;
            }

            char *xpath = lyd_path(new_parent_d);
            log_add_verbose(1, LOG_COLOR_BOLD_MAGENTA"[%15s] "LOG_COLOR_BOLD_YELLOW"[%c%c]"LOG_COLOR_RESET" %s\n", "CONTAINER", element_operational ? 'O' : 'R', populate_info_get_mandatory(schema), xpath);
            free(xpath);

            int rc = populate_instance_add_module(instance, schema->module);
            if(rc != NTS_ERR_OK) {
                log_error("instance_add_module failed\n");
                return rc;
            }

            struct lys_node *child = 0;
            LY_TREE_FOR(schema->child, child) {
                int rc = populate_recursive(job, instance, child, new_parent_d, new_parent_o, new_parent_r, operational_only);
                if(rc != NTS_ERR_OK) {
                    log_error("populate_recursive failed\n");
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
            goto populate_recursive_rerun_switch;
        } break;

        //the actual "case" is this node's child, so we skip directly to that
        case LYS_CASE:
            //case contains mandatory
            if(schema->child) {
                schema = schema->child;
                goto populate_recursive_rerun_switch;
            }
            else {
                //blank case
                return NTS_ERR_OK;
            }
            break;

        //populate a list
        case LYS_LIST: {
            //don't add if populating only operational
            if(operational_only && !element_operational) {
                return NTS_ERR_OK;
            }

            //get min-max for current list
            struct lys_node_list *list = (struct lys_node_list *)schema;
            int min_added = list->min ? list->min : 1;
            int max_added = list->max ? list->max : 65536;
            
            int populating_times = populate_instance_get_count(resolved_schema_path);
            if(populating_times != 0) {
                if(min_added < populating_times) {
                    min_added = populating_times;
                }
                if(min_added > max_added) {
                    min_added = max_added;
                    log_error("min-elements exceeds max-elements for path %s. truncated to %d\n", resolved_schema_path, max_added);
                }
                log_add_verbose(2, "populating %d times list '%s'\n", min_added, resolved_schema_path);

                //populate node with the intended number of values
                while(min_added) {
                    //add list

                    struct lyd_node *new_parent_d = parent_d;
                    struct lyd_node *new_parent_o = parent_o;
                    struct lyd_node *new_parent_r = parent_r;

                    new_parent_d = lyd_new(parent_d, schema->module, schema->name);
                    if(!new_parent_d) {
                        log_error("error creating list dev -> %s\n", schema->name);
                        log_error("ly_error: %s\n", ly_errmsg(session_context));
                        return NTS_ERR_FAILED;
                    }


                    new_parent_o = lyd_new(parent_o, schema->module, schema->name);
                    if(!new_parent_o) {
                        log_error("error creating list operational -> %s\n", schema->name);
                        log_error("ly_error: %s\n", ly_errmsg(session_context));
                        return NTS_ERR_FAILED;
                    }

                    if(!element_operational) {
                        new_parent_r = lyd_new(parent_r, schema->module, schema->name);
                        if(!new_parent_r) {
                            log_error("error creating container running -> %s\n", schema->name);
                            log_error("ly_error: %s\n", ly_errmsg(session_context));
                            return NTS_ERR_FAILED;
                        }
                    }

                    if(!instance->init) {
                        instance->init = true;
                        instance->dev = new_parent_d;
                        instance->operational = new_parent_o;
                        instance->running = new_parent_r;
                    }

                    char *xpath = lyd_path(new_parent_d);
                    log_add_verbose(1, LOG_COLOR_BOLD_MAGENTA"[%15s] "LOG_COLOR_BOLD_YELLOW"[%c%c]"LOG_COLOR_RESET" %s\n", "LIST", element_operational ? 'O' : 'R', populate_info_get_mandatory(schema), xpath);
                    free(xpath);

                    int rc = populate_instance_add_module(instance, schema->module);
                    if(rc != NTS_ERR_OK) {
                        log_error("instance_add_module failed\n");
                        return rc;
                    }

                    //populate all list elements below in the tree
                    struct lys_node *child = 0;
                    LY_TREE_FOR(schema->child, child) {
                        int rc = populate_recursive(job, instance, child, new_parent_d, new_parent_o, new_parent_r, operational_only);
                        if(rc != NTS_ERR_OK) {
                            log_error("populate_recursive failed\n");
                            return rc;
                        }
                    }

                    min_added--;
                }
            }
            else {
                log_add_verbose(2, "not populating list '%s'\n", resolved_schema_path);
            }
        } break;

        //populate the leaf
        case LYS_LEAF: {
            //don't add if populating only operational
            if(operational_only && !element_operational) {
                return NTS_ERR_OK;
            }

            if(populate_add_leaf(job, instance, schema, parent_d, parent_o, parent_r) != NTS_ERR_OK) {
                return NTS_ERR_FAILED;
            }            
        } break;

        //leaflist is treated the same as a LEAF, but with min/max characteristics of a LIST
        case LYS_LEAFLIST: {
            //don't add if populating only operational
            if(operational_only && !element_operational) {
                return NTS_ERR_OK;
            }

            //get min-max for the current leaflist
            struct lys_node_leaflist *list = (struct lys_node_leaflist *)schema;
            int min_added = list->min ? list->min : 1;
            int max_added = list->max ? list->max : 65536;
            
            int populating_times = populate_instance_get_count(resolved_schema_path);
            if(populating_times != 0) {
                if(min_added < populating_times) {
                    min_added = populating_times;
                }
                if(min_added > max_added) {
                    min_added = max_added;
                    log_error("min-elements exceeds max-elements for path %s truncated to %d\n", resolved_schema_path, max_added);
                }
                log_add_verbose(2, "populating %d times leaflist '%s'\n", min_added, resolved_schema_path);

                //add the leafs
                while(min_added) {
                    if(populate_add_leaf(job, instance, schema, parent_d, parent_o, parent_r) != NTS_ERR_OK) {
                        return NTS_ERR_FAILED;
                    }   
                    min_added--;
                }
            }
            else {
                log_add_verbose(2, "not populating leaflist '%s'\n", resolved_schema_path);
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
            log_add_verbose(1, "[%15s]      %s\n", typeutils_yang_nodetype_to_str(schema->nodetype), resolved_schema_path);

            //traverse the tree down for any other node types, without adding anything to the path
            struct lys_node *child = 0;
            LY_TREE_FOR(schema->child, child) {
                int rc = populate_recursive(job, instance, child, parent_d, parent_o, parent_r, operational_only);
                if(rc != NTS_ERR_OK) {
                    return rc;
                }
            }
            break;
    }

    free(resolved_schema_path);

    return NTS_ERR_OK;
}

int populate_add_leaf(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_d, struct lyd_node *parent_o, struct lyd_node *parent_r) {
    assert_session();
    assert(job);
    assert(schema);
    assert(parent_d);

    int rc = populate_instance_add_module(instance, schema->module);
    if(rc != NTS_ERR_OK) {
        log_error("bad schema_instance_add module\n");
        return rc;
    }

    struct lys_type *type = &((struct lys_node_leaf *)schema)->type;
    
    char *data_xpath = lyd_path(parent_d);
    data_xpath = (char *)realloc(data_xpath, sizeof(char) * (strlen(data_xpath) + 1 + strlen(schema->name) + 1));
    if(!data_xpath) {
        log_error("lyd_path failed\n");
        return NTS_ERR_FAILED;
    }
    strcat(data_xpath, "/");
    strcat(data_xpath, schema->name);

    bool leaf_operational = ((schema->flags & LYS_CONFIG_W) == 0);
    log_add_verbose(1, LOG_COLOR_BOLD_MAGENTA"[%15s] "LOG_COLOR_BOLD_YELLOW"[%c%c]"LOG_COLOR_RESET" %s <-- ", typeutils_yang_type_to_str(type->base), leaf_operational ? 'O' : 'R', populate_info_get_mandatory(schema), data_xpath);
    free(data_xpath);


    char *resolved_schema_path = lys_path(schema, LYS_PATH_FIRST_PREFIX);
    char *value = populate_get_restrict_schema(resolved_schema_path);
    free(resolved_schema_path);

    populate_add_leaf_rerun_switch:
    switch(type->base) {
        case LY_TYPE_UNION:
            if((type->info.uni.count == 0) && (type->der != 0)) {
                type = &type->der->type;
            }

            type = &type->info.uni.types[0];
            goto populate_add_leaf_rerun_switch;
            break;

        case LY_TYPE_INST: {
            struct lyd_node *parent = parent_o;
            while(parent->parent) {
                parent = parent->parent;
            }

            if(value == 0) {
                value = lyd_path(parent);
            }

            goto populate_add_leaf_actual_add;
        } break;

        case LY_TYPE_EMPTY:
            if(rand_bool()) {   //if present, add it
                log_add(1, LOG_COLOR_CYAN"present"LOG_COLOR_RESET"\n");
                goto populate_add_leaf_actual_add;
            }
            else {
                log_add(1, LOG_COLOR_CYAN"empty"LOG_COLOR_RESET"\n");
                return NTS_ERR_OK;
            }
            break;

        case LY_TYPE_LEAFREF: {
            if(value == 0) {
                int index = 0;
                struct lyd_node *new_node = 0;
                while((new_node == 0) && (index < POPULATE_LEAFREF_TEST_ENTRIES_TOTAL)) {
                    new_node = lyd_new_leaf(parent_d, schema->module, schema->name, populate_leafref_test_val(index));
                    index++;
                }

                if(new_node == 0) {
                    log_error("error on lyd_new_leaf schema %s. didn't work with any temp val\n", schema->name);
                    return NTS_ERR_FAILED;
                }

                //based on the new_node's path, try to find elements of relative path for the leafref
                struct ly_set *set = lyd_find_path(new_node, type->info.lref.path);
                lyd_free(new_node);

                if(set && set->number) {
                    //choose a random schema and get its value
                    static int set_number = 0;
                    set_number++;
                    if(set_number >= set->number) {
                        set_number = 0;
                    }
                    asprintf(&value, "%s", ((struct lyd_node_leaf_list *)set->set.d[set_number])->value_str);
                    if(!value) {
                        log_error("bad asprintf\n");
                        return NTS_ERR_FAILED;
                    }

                    int rc = populate_instance_add_module(instance, set->set.d[set_number]->schema->module);
                    if(rc != NTS_ERR_OK) {
                        log_error("bad schema_instance_add module\n");
                        return rc;
                    }

                    ly_set_free(set);

                    goto populate_add_leaf_actual_add;
                }
                else {
                    //adding to late-resolve list, as we don't have any nodes in the leafref path
                    int rc = populate_late_resolve_add_leaf(job, instance, schema, parent_d, parent_o, parent_r);
                    if(rc != NTS_ERR_OK) {
                        return rc;
                    }

                    if(!job->late_resolving) {
                        log_add(1, LOG_COLOR_BOLD_YELLOW"added to late-resolve list...\n"LOG_COLOR_RESET);
                    }
                    else {
                        log_add(1, LOG_COLOR_BOLD_YELLOW"REadded to late-resolve list...\n"LOG_COLOR_RESET);
                    }

                    return NTS_ERR_OK;
                }
            }
        } break;
      
        default:
            if(value == 0) {
                value = rand_get_populate_value(type);
            }
            goto populate_add_leaf_actual_add;
            break;
    }

    populate_add_leaf_actual_add: {
        //add schema to dev
        struct lyd_node *new_node = lyd_new_leaf(parent_d, schema->module, schema->name, value);
        if(new_node == 0) {
            log_error("error on lyd_new_leaf dev: %s\n", ly_errmsg(session_context));
            return NTS_ERR_FAILED;
        }

        //print out the value
        if(value) {
            log_add(1, LOG_COLOR_CYAN"'%s'"LOG_COLOR_RESET"\n",  value);
        }
        else {
            log_add(1, "\n");
        }

        //if it fits the case, add it also to running
        if(leaf_operational || (lys_is_key((const struct lys_node_leaf *)schema, 0) != 0)) {
            //add schema to operational
            struct lyd_node *new_node = lyd_new_leaf(parent_o, schema->module, schema->name, value);
            if(new_node == 0) {
                log_error("error on lyd_new_leaf operational: %s\n", ly_errmsg(session_context));
                return NTS_ERR_FAILED;
            }
        }
        
        if(!leaf_operational) {
            struct lyd_node *new_node = lyd_new_leaf(parent_r, schema->module, schema->name, value);
            if(new_node == 0) {
                log_error("error on lyd_new_leaf running: %s\n", ly_errmsg(session_context));
                return NTS_ERR_FAILED;
            }
        }
        
        free(value);
    }

    return NTS_ERR_OK;
}
