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

#include "generate.h"
#include "utils/log_utils.h"
#include "utils/rand_utils.h"
#include "utils/type_utils.h"
#include "utils/sys_utils.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "core/session.h"
#include "core/framework.h"

#include "schema.h"

#define LEAFREF_TOTAL_TEST_ENTRIES      11

typedef struct {
    int init;

    char *xpath;

    const struct lys_module **modules;
    int mod_count;

    struct lyd_node *operational;
    struct lyd_node *running;
} generate_instance_t;

typedef struct {
    struct lyd_node *operational;
    struct lyd_node *running;
    bool late_resolving;

    int late_resolve_count;
    struct lys_node **late_resolve_schema;
    struct lyd_node **late_resolve_parent_o;
    struct lyd_node **late_resolve_parent_r;
    generate_instance_t **late_resolve_instance;
} generate_job_t;

static int generate_recursive(generate_job_t *job, generate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r);
static int generate_add_leaf(generate_job_t *job, generate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r);

static int generate_late_resolve(generate_job_t *job);
static int generate_validate(generate_instance_t *instance, int count);
static int generate_export_data(generate_job_t *job, const char *running_filename, const char *operational_filename);

static int instance_add_module(generate_instance_t *instance, const struct lys_module *module);
static int generate_late_resolve_add_leaf(generate_job_t *job, generate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r);
static const char* leafref_test_val(int index);

static int generate_get_instance_count(const char *path);
static char *generate_get_restrict_schema(const char *path);

struct lyd_node *datastore_load_external(const char *filename, bool operational) {

    struct lyd_node *data_tree = 0;

    if(filename) {
        if(file_exists(filename)) {
            LYD_FORMAT format = LYD_JSON;
            if(strstr(filename, ".xml") != 0) {
                format = LYD_XML;
            }

            int flags = LYD_OPT_TRUSTED | LYD_OPT_NOSIBLINGS;
            if(operational) {
                flags |= LYD_OPT_DATA;
            }
            else {
                flags |= LYD_OPT_CONFIG;
            }

            data_tree = lyd_parse_path(session_context, filename, format, flags);
            if(data_tree == 0) {
                log_error("lyd_parse_path failed\n");
            }
        }
    }

    return data_tree;
}

int datastore_generate_data(const char *running_filename, const char *operational_filename) {
    assert_session();

    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_generate_data() begin\n"LOG_COLOR_RESET);

    generate_job_t job;
    job.operational = 0;
    job.running = 0;
    job.late_resolve_count = 0;
    job.late_resolve_instance = 0;
    job.late_resolve_schema = 0;
    job.late_resolve_parent_o = 0;
    job.late_resolve_parent_r = 0;
    job.late_resolving = false;


    //load pre-populated data
    for(int i = 0; i < framework_config.datastore_populate.preg_running_count; i++) {
        char *filename = framework_config.datastore_populate.preg_running[i];
        struct lyd_node *data = datastore_load_external(filename, false);
        if(data == 0) {
            log_add_verbose(2, "datastore_load_external() could not load %s\n", filename);
        }
        else {
            log_add_verbose(1, "loaded into running %s (%s)\n", filename, data->schema->module->name);
            if(job.running) {
                int rc = lyd_merge(job.running, data, 0);
                if(rc != 0) {
                    log_error("lyd_merge failed\n");
                }

                lyd_free_withsiblings(data);
            }
            else {
                job.running = data;
            }
        }

        //also load as operational
        data = datastore_load_external(filename, true);
        if(data == 0) {
            log_add_verbose(2, "datastore_load_external() could not load %s\n", filename);
        }
        else {
            log_add_verbose(1, "loaded into operational %s (%s)\n", filename, data->schema->module->name);
            if(job.operational) {
                int rc = lyd_merge(job.operational, data, 0);
                if(rc != 0) {
                    log_error("lyd_merge failed\n");
                }

                lyd_free_withsiblings(data);
            }
            else {
                job.operational = data;
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
            if(job.operational) {
                int rc = lyd_merge(job.operational, data, 0);
                if(rc != 0) {
                    log_error("lyd_merge failed\n");
                }

                lyd_free_withsiblings(data);
            }
            else {
                job.operational = data;
            }
        }
    }

    if(framework_config.datastore_populate.random_generation_enabled) {
        char **xpaths = 0;
        int instance_count = datastore_schema_get_xpaths(&xpaths);
        if(instance_count < 0) {
            log_error("datastore_schema_get_xpaths failed\n");
            return NTS_ERR_FAILED;
        }

        //exclude pre-populated modules
        struct lyd_node *elem;
        LY_TREE_FOR(job.operational, elem) {
            for(int i = 0; i < instance_count; i++) {
                if(strstr(xpaths[i], elem->schema->module->name) == (xpaths[i] + 1)) {  //xpaths[i] is "/module:container"
                    free(xpaths[i]);

                    instance_count--;
                    for(int j = i; j < instance_count; j++) {
                        xpaths[j] = xpaths[j + 1];
                    }

                    break;
                }
            }
        }

        generate_instance_t *instance = (generate_instance_t *)malloc(sizeof(generate_instance_t) * instance_count);
        if(!instance) {
            log_error("bad malloc\n");
            for(int i = 0; i < instance_count; i++) {
                free(xpaths[i]);
            }
            free(xpaths);
            return NTS_ERR_FAILED;
        }
    

        //RANDOM generate everything
        for(int i = 0; i < instance_count; i++) {
            log_add_verbose(1, "generating "LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" data...\n", xpaths[i]);

            struct lys_node *schema_node = (struct lys_node *)ly_ctx_get_node(session_context, 0, xpaths[i], 0);
            if(schema_node == 0) {
                log_error("ly_ctx_get_node failed for %s\n", xpaths[i]);
                return NTS_ERR_FAILED;
            }

            if(schema_node == 0) {
                log_add_verbose(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
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
            
            //do the actual population
            int rc = generate_recursive(&job, &instance[i], schema_node, 0, 0);
            if(rc != NTS_ERR_OK) {
                log_error("generate_recursive failed instance %d with xpath %s\n", i, instance[i].xpath);
                return rc;
            }
        }

        //link everything so we would be able to find everything in late-resolve
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_generate_data() done generating, now linking... (%d root nodes)\n"LOG_COLOR_RESET, instance_count);
        for(int i = 0; i < instance_count; i++) {

            if(instance[i].operational) {
                if(job.operational) {
                    int rc = lyd_insert_sibling(&job.operational, instance[i].operational);
                    if(rc != 0) {
                        log_error("lyd_insert_sibling\n");
                        return NTS_ERR_FAILED;
                    }
                }
                else {
                    job.operational = instance[i].operational;
                }
            }

            if(instance[i].running) {
                if(job.running) {
                    int rc = lyd_insert_sibling(&job.running, instance[i].running);
                    if(rc != 0) {
                        log_error("lyd_insert_sibling\n");
                        return NTS_ERR_FAILED;
                    }
                }
                else {
                    job.running = instance[i].running;
                }
            }
        }

        //late-resolve
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_generate_data() starting late-resolve process...\n"LOG_COLOR_RESET);
        if(job.late_resolve_count) {
            int rc = generate_late_resolve(&job);
            if(rc != NTS_ERR_OK) {
                log_error("generate_late_resolve failed\n");
                return rc;
            }
        }
        
        //validate data and remove invalid nodes
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_generate_data() validating\n"LOG_COLOR_RESET);
        int rc = generate_validate(instance, instance_count);
        if(rc != NTS_ERR_OK) {
            log_error("generate_validate failed\n");
            return rc;
        }

        for(int i = 0; i < instance_count; i++) {
            log_add(1, "%d ", i);

            free(instance[i].modules);
            free(instance[i].xpath);

            free(xpaths[i]);
        }
        free(xpaths);
        free(job.late_resolve_instance);
        free(job.late_resolve_schema);
        free(job.late_resolve_parent_o);
        free(job.late_resolve_parent_r);
    }

    //export generated data
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_generate_data() exporting data\n"LOG_COLOR_RESET);
    int rc = generate_export_data(&job, running_filename, operational_filename);
    if(rc != NTS_ERR_OK) {
        log_error("generate_export_data failed\n");
        return rc;
    }

    //cleanup
    log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"datastore_generate_data() cleaning up... "LOG_COLOR_RESET);
    

    lyd_free_withsiblings(job.operational);
    lyd_free_withsiblings(job.running);
        
    log_add(1, "\n");
    log_add_verbose(1, LOG_COLOR_BOLD_GREEN"datastore_generate_data() finished\n"LOG_COLOR_RESET);
    
    return NTS_ERR_OK;
}

int datastore_generate_external(void) {
    char cmd[512];
    sprintf(cmd, "%s --generate", framework_arguments.argv[0]);
    if(system(cmd) == 0) {
        return NTS_ERR_OK;
    }
    else {
        return NTS_ERR_FAILED;
    }
}


static int generate_recursive(generate_job_t *job, generate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r) {
    assert(job);
    assert(schema);
    assert(instance);
    
    char *resolved_schema_path = lys_path(schema, LYS_PATH_FIRST_PREFIX);
    bool schema_operational = ((schema->flags & LYS_CONFIG_W) == 0);

    generate_recursive_rerun_switch:
    switch(schema->nodetype) {
        //for container, just add it to the xpath, and iterate it's childeren to further traverse the tree
        case LYS_CONTAINER: {
            //add container

            struct lyd_node *new_parent_o = parent_o;
            struct lyd_node *new_parent_r = parent_r;

            new_parent_o = lyd_new(parent_o, schema->module, schema->name);
            if(!new_parent_o) {
                log_error("error creating container operational -> %s\n", schema->name);
                log_error("ly_error: %s\n", ly_errmsg(session_context));
                return NTS_ERR_FAILED;
            }

            if(!schema_operational) {
                new_parent_r = lyd_new(parent_r, schema->module, schema->name);
                if(!new_parent_r) {
                    log_error("error creating container running -> %s\n", schema->name);
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
            log_add_verbose(1, LOG_COLOR_BOLD_MAGENTA"[%15s] "LOG_COLOR_BOLD_YELLOW"[%c%c]"LOG_COLOR_RESET" %s\n", "CONTAINER", node_operational ? 'O' : 'R', mandatory, xpath);
            free(xpath);

            int rc = instance_add_module(instance, schema->module);
            if(rc != NTS_ERR_OK) {
                log_error("instance_add_module failed\n");
                return rc;
            }

            struct lys_node *child = 0;
            LY_TREE_FOR(schema->child, child) {
                int rc = generate_recursive(job, instance, child, new_parent_o, new_parent_r);
                if(rc != NTS_ERR_OK) {
                    log_error("generate_recursive failed\n");
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
            goto generate_recursive_rerun_switch;
        } break;

        //the actual "case" is this node's child, so we skip directly to that
        case LYS_CASE:
            //case contains mandatory
            if(schema->child) {
                schema = schema->child;
                goto generate_recursive_rerun_switch;
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
            
            int populating_times = generate_get_instance_count(resolved_schema_path);
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

                    struct lyd_node *new_parent_o = parent_o;
                    struct lyd_node *new_parent_r = parent_r;

                    new_parent_o = lyd_new(parent_o, schema->module, schema->name);
                    if(!new_parent_o) {
                        log_error("error creating list operational -> %s\n", schema->name);
                        log_error("ly_error: %s\n", ly_errmsg(session_context));
                        return NTS_ERR_FAILED;
                    }

                    if(!schema_operational) {
                        new_parent_r = lyd_new(parent_r, schema->module, schema->name);
                        if(!new_parent_r) {
                            log_error("error creating container running -> %s\n", schema->name);
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
                    log_add_verbose(1, LOG_COLOR_BOLD_MAGENTA"[%15s] "LOG_COLOR_BOLD_YELLOW"[%c%c]"LOG_COLOR_RESET" %s\n", "LIST", node_operational ? 'O' : 'R', mandatory, xpath);
                    free(xpath);

                    int rc = instance_add_module(instance, schema->module);
                    if(rc != NTS_ERR_OK) {
                        log_error("instance_add_module failed\n");
                        return rc;
                    }

                    //populate all list elements below in the tree
                    struct lys_node *child = 0;
                    LY_TREE_FOR(schema->child, child) {
                        int rc = generate_recursive(job, instance, child, new_parent_o, new_parent_r);
                        if(rc != NTS_ERR_OK) {
                            log_error("generate_recursive failed\n");
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
            if(generate_add_leaf(job, instance, schema, parent_o, parent_r) != NTS_ERR_OK) {
                return NTS_ERR_FAILED;
            }            
        } break;

        //leaflist is treated the same as a LEAF, but with min/max characteristics of a LIST
        case LYS_LEAFLIST: {
            //get min-max for the current leaflist
            struct lys_node_leaflist *list = (struct lys_node_leaflist *)schema;
            int min_added = list->min ? list->min : 1;
            int max_added = list->max ? list->max : 65536;
            
            int populating_times = generate_get_instance_count(resolved_schema_path);
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
                    if(generate_add_leaf(job, instance, schema, parent_o, parent_r) != NTS_ERR_OK) {
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
                int rc = generate_recursive(job, instance, child, parent_o, parent_r);
                if(rc != NTS_ERR_OK) {
                    return rc;
                }
            }
            break;
    }

    free(resolved_schema_path);

    return NTS_ERR_OK;
}

static int generate_add_leaf(generate_job_t *job, generate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r) {
    assert_session();
    assert(job);
    assert(schema);
    assert(parent_o);

    int rc = instance_add_module(instance, schema->module);
    if(rc != NTS_ERR_OK) {
        log_error("bad schema_instance_add module\n");
        return rc;
    }

    struct lys_type *type = &((struct lys_node_leaf *)schema)->type;
    
    char *data_xpath = lyd_path(parent_o);
    data_xpath = (char *)realloc(data_xpath, sizeof(char) * (strlen(data_xpath) + 1 + strlen(schema->name) + 1));
    if(!data_xpath) {
        log_error("lyd_path failed\n");
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
    log_add_verbose(1, LOG_COLOR_BOLD_MAGENTA"[%15s] "LOG_COLOR_BOLD_YELLOW"[%c%c]"LOG_COLOR_RESET" %s <-- ", typeutils_yang_type_to_str(type->base), node_operational ? 'O' : 'R', mandatory, data_xpath);
    free(data_xpath);


    char *resolved_schema_path = lys_path(schema, LYS_PATH_FIRST_PREFIX);
    char *value = generate_get_restrict_schema(resolved_schema_path);
    free(resolved_schema_path);

    generate_add_leaf_rerun_switch:
    switch(type->base) {
        case LY_TYPE_UNION:
            if((type->info.uni.count == 0) && (type->der != 0)) {
                type = &type->der->type;
            }

            type = &type->info.uni.types[0];
            goto generate_add_leaf_rerun_switch;
            break;

        case LY_TYPE_INST: {
            struct lyd_node *parent = parent_o;
            while(parent->parent) {
                parent = parent->parent;
            }

            if(value == 0) {
                value = lyd_path(parent);
            }

            goto generate_add_leaf_actual_add;
        } break;

        case LY_TYPE_EMPTY:
            if(rand_bool()) {   //if present, add it
                log_add(1, LOG_COLOR_CYAN"present"LOG_COLOR_RESET"\n");
                goto generate_add_leaf_actual_add;
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
                while((new_node == 0) && (index < LEAFREF_TOTAL_TEST_ENTRIES)) {
                    new_node = lyd_new_leaf(parent_o, schema->module, schema->name, leafref_test_val(index));
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
                    static int set_number = 0;  //checkAL aici trebuia oare random ?
                    set_number++;
                    if(set_number >= set->number) {
                        set_number = 0;
                    }
                    asprintf(&value, "%s", ((struct lyd_node_leaf_list *)set->set.d[set_number])->value_str);
                    if(!value) {
                        log_error("bad asprintf\n");
                        return NTS_ERR_FAILED;
                    }

                    int rc = instance_add_module(instance, set->set.d[set_number]->schema->module);
                    if(rc != NTS_ERR_OK) {
                        log_error("bad schema_instance_add module\n");
                        return rc;
                    }

                    ly_set_free(set);

                    goto generate_add_leaf_actual_add;
                }
                else {
                    //adding to late-resolve list, as we don't have any nodes in the leafref path
                    int rc = generate_late_resolve_add_leaf(job, instance, schema, parent_o, parent_r);
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
            goto generate_add_leaf_actual_add;
            break;
    }

    generate_add_leaf_actual_add: {
        //add schema to operational
        struct lyd_node *new_node = lyd_new_leaf(parent_o, schema->module, schema->name, value);
        if(new_node == 0) {
            log_error("error on lyd_new_leaf operational: %s\n", ly_errmsg(session_context));
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
        if(!node_operational) {
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



static int generate_late_resolve(generate_job_t *job) {
    assert(job);

    job->late_resolving = true;

    int prev_count = job->late_resolve_count + 1;

    while(prev_count > job->late_resolve_count) {
        int late_resolve_count = job->late_resolve_count;
        struct lys_node **late_resolve_schema = job->late_resolve_schema;
        struct lyd_node **late_resolve_parent_o = job->late_resolve_parent_o;
        struct lyd_node **late_resolve_parent_r = job->late_resolve_parent_r;
        generate_instance_t **late_resolve_instance = job->late_resolve_instance;

        job->late_resolve_count = 0;
        job->late_resolve_schema = 0;
        job->late_resolve_parent_o = 0;
        job->late_resolve_parent_r = 0;
        job->late_resolve_instance = 0;

        prev_count = late_resolve_count;

        for(int i = 0; i < late_resolve_count; i++) {
            log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"late-populating "LOG_COLOR_RESET": ");
            int rc = generate_add_leaf(job, late_resolve_instance[i], late_resolve_schema[i], late_resolve_parent_o[i], late_resolve_parent_r[i]);
            if(rc != NTS_ERR_OK) {
                log_error("generate_add_leaf failed on late-resolve\n");
                return rc;
            }
        }

        free(late_resolve_schema);
        free(late_resolve_parent_o);
        free(late_resolve_parent_r);
        free(late_resolve_instance);
    }
    job->late_resolving = false;

    if(prev_count != 0) {
        log_error("generate_late_resolve detected circular loop!\n");
    }

    return NTS_ERR_OK;
}

static int generate_validate(generate_instance_t *instance, int count) {
    assert(instance);

    int rc = 0;
    int commit_ok = NTS_ERR_OK;

    for(int i = 0; i < count; i++) {
        if(instance[i].operational) {
            log_add_verbose(2, "available modules:");
            for(int j = 0; j < instance[i].mod_count; j++) {
                log_add(2, " %s", instance[i].modules[j]->name);
            }
            log_add(2, "\n");
            log_add_verbose(1, "validating OPERATIONAL for [%d] : %s... ", i, instance[i].xpath);

            int solved_instance_errors = 1;
            int solved_errors = 0;
            bool success = false;
            while(instance[i].operational && solved_instance_errors) {
                solved_instance_errors = 0;
                rc = lyd_validate_modules(&instance[i].operational, instance[i].modules, instance[i].mod_count, LYD_OPT_DATA, 0);
                if(rc == 0) {
                    log_add(1, LOG_COLOR_BOLD_GREEN"success (%d)\n"LOG_COLOR_RESET, solved_errors);
                    success = true;
                    break;
                }
                else {
                    log_add(2, "\n");

                    struct ly_err_item *err = ly_err_first(session_context);
                    while(err) {
                        if((err->vecode == LYVE_NOWHEN) || (err->vecode == LYVE_NOMUST) || (err->vecode == LYVE_NOCONSTR) || (err->vecode == LYVE_NOLEAFREF) || (err->vecode == LYVE_NOMIN) || (err->vecode == LYVE_INVAL)) {
                            struct ly_set *set = lyd_find_path(instance[i].operational, err->path);
                            if(set && set->number) {
                                log_add_verbose(2, "operational error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                                log_add_verbose(2, LOG_COLOR_BOLD_RED"  [WHEN-DELETE O]"LOG_COLOR_RESET" %s ... ", err->path);

                                bool mandatory = false;
                                if((set->set.d[0]->schema->flags & LYS_MAND_TRUE) != 0) {
                                    mandatory = true;
                                }

                                if((set->set.d[0]->schema->parent) && (set->set.d[0]->schema->parent->nodetype == LYS_CASE)) {
                                    if((set->set.d[0]->schema->parent->flags & LYS_MAND_TRUE) != 0) {
                                        mandatory = true;
                                    }
                                }

                                if((set->set.d[0]->dflt != 0) || (lys_is_key((const struct lys_node_leaf *)set->set.d[0]->schema, 0)) || (mandatory) || (err->vecode == LYVE_NOMIN)) {
                                    //delete whole parent
                                    log_add(2, "deleted parent : %s\n", lyd_path(set->set.d[0]->parent));
                                    struct lyd_node *p = set->set.d[0]->parent;
                                    lyd_free_withsiblings(set->set.d[0]);
                                    lyd_free(p);
                                    if(p == instance[i].operational) {
                                        log_add_verbose(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].operational = 0;
                                        break;
                                    }
                                }
                                else {
                                    //delete THIS node only
                                    lyd_free(set->set.d[0]);
                                    log_add(2, "deleted\n");
                                    if(set->set.d[0] == instance[i].operational) {
                                        log_add_verbose(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].operational = 0;
                                        break;
                                    }
                                }
                                solved_instance_errors++;

                                ly_set_free(set);
                            }
                        }
                        else if((err->vecode != 0) && (err->vecode != 29)) {
                            log_add_verbose(2, "operational error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                        }

                        err = err->next;
                    }
                    ly_err_clean(session_context, 0);
                }

                solved_errors += solved_instance_errors;
            }

            if(!success) {
                if(!solved_errors) {
                    log_add(1, LOG_COLOR_BOLD_YELLOW"failed"LOG_COLOR_RESET"\n%s\n", ly_errmsg(session_context));
                }
                else {
                    log_add(1, LOG_COLOR_BOLD_YELLOW"partially solved (%d)"LOG_COLOR_RESET"\n", solved_errors);
                }
            }
        }

        if(instance[i].running) {
            log_add_verbose(1, "validating RUNNING... for [%d] : %s... ", i, instance[i].xpath);

            int solved_instance_errors = 1;
            int solved_errors = 0;
            bool success = false;
            while(instance[i].running && solved_instance_errors) {
                solved_instance_errors = 0;
                rc = lyd_validate_modules(&instance[i].running, instance[i].modules, instance[i].mod_count, LYD_OPT_CONFIG, 0);
                if(rc == 0) {
                    log_add(1, LOG_COLOR_BOLD_GREEN"success (%d)\n"LOG_COLOR_RESET, solved_errors);
                    success = true;
                    break;
                }
                else {
                    log_add(2, "\n");

                    struct ly_err_item *err = ly_err_first(session_context);
                    while(err) {
                        if((err->vecode == LYVE_NOWHEN) || (err->vecode == LYVE_NOMUST) || (err->vecode == LYVE_NOCONSTR) || (err->vecode == LYVE_NOLEAFREF) || (err->vecode == LYVE_NOMIN) || (err->vecode == LYVE_INVAL)) {
                            struct ly_set *set = lyd_find_path(instance[i].running, err->path);
                            if(set && set->number) {
                                log_add_verbose(2, "running error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                                log_add_verbose(2, LOG_COLOR_BOLD_RED"  [WHEN-DELETE R]"LOG_COLOR_RESET" %s ... ", err->path);

                                bool mandatory = false;
                                if((set->set.d[0]->schema->flags & LYS_MAND_TRUE) != 0) {
                                    mandatory = true;
                                }

                                if((set->set.d[0]->schema->parent) && (set->set.d[0]->schema->parent->nodetype == LYS_CASE)) {
                                    if((set->set.d[0]->schema->parent->flags & LYS_MAND_TRUE) != 0) {
                                        mandatory = true;
                                    }
                                }

                                if((set->set.d[0]->dflt != 0) || (lys_is_key((const struct lys_node_leaf *)set->set.d[0]->schema, 0)) || (mandatory) || (err->vecode == LYVE_NOMIN))  {
                                    //delete whole parent
                                    log_add(2, "deleted parent : %s\n", lyd_path(set->set.d[0]->parent));
                                    struct lyd_node *p = set->set.d[0]->parent;
                                    lyd_free_withsiblings(set->set.d[0]);
                                    lyd_free(p);

                                    if(p == instance[i].running) {
                                        log_add_verbose(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].running = 0;
                                        break;
                                    }
                                }
                                else {
                                    //delete THIS node only
                                    lyd_free(set->set.d[0]);
                                    log_add(2, "deleted\n");
                                    if(set->set.d[0] == instance[i].running) {
                                        log_add_verbose(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].running = 0;
                                        break;
                                    }
                                }
                                solved_instance_errors++;

                                ly_set_free(set);
                            }
                        }
                        else if((err->vecode != 0) && (err->vecode != 29)) {
                            log_add_verbose(2, "running error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                        }

                        err = err->next;
                    }
                    ly_err_clean(session_context, 0);
                }

                solved_errors += solved_instance_errors;
            }

            if(!success) {
                if(!solved_errors) {
                    log_add(1, LOG_COLOR_BOLD_YELLOW"failed"LOG_COLOR_RESET"\n%s\n", ly_errmsg(session_context));
                }
                else {
                    log_add(1, LOG_COLOR_BOLD_YELLOW"partially solved (%d)"LOG_COLOR_RESET"\n", solved_errors);
                }
            }
        }
    }

    return commit_ok;
}

static int generate_export_data(generate_job_t *job, const char *running_filename, const char *operational_filename) {
    assert(job);

    if(job->operational) {
        if(lyd_print_path(operational_filename, job->operational, LYD_JSON, LYP_FORMAT | LYP_WITHSIBLINGS) != 0) {
            log_error("lyd_print_path failed for operational\n");
            return NTS_ERR_FAILED;
        }
    }

    if(job->running) {
        if(lyd_print_path(running_filename, job->running, LYD_JSON, LYP_FORMAT | LYP_WITHSIBLINGS) != 0) {
            log_error("lyd_print_path failed for running\n");
            return NTS_ERR_FAILED;
        }
    }

    return NTS_ERR_OK;
}

static int instance_add_module(generate_instance_t *instance, const struct lys_module *module) {
    assert(module);
    assert(instance);

    for(int i = 0; i < instance->mod_count; i++) {
        if(instance->modules[i] == module) {
            return NTS_ERR_OK;
        }
    }

    instance->modules = (const struct lys_module **)realloc(instance->modules, sizeof(const struct lys_module *) * (instance->mod_count + 1));
    if(!instance->modules) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    instance->modules[instance->mod_count] = module;
    instance->mod_count++;

    return NTS_ERR_OK;
}

static int generate_late_resolve_add_leaf(generate_job_t *job, generate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r) {
    assert(job);
    assert(instance);

    job->late_resolve_schema = (struct lys_node **)realloc(job->late_resolve_schema, (job->late_resolve_count + 1) * sizeof(struct lys_node *));
    if(!job->late_resolve_schema) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_schema[job->late_resolve_count] = schema;

    job->late_resolve_parent_o = (struct lyd_node **)realloc(job->late_resolve_parent_o, (job->late_resolve_count + 1) * sizeof(struct lyd_node *));
    if(!job->late_resolve_parent_o) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_parent_o[job->late_resolve_count] = parent_o;

    job->late_resolve_parent_r = (struct lyd_node **)realloc(job->late_resolve_parent_r, (job->late_resolve_count + 1) * sizeof(struct lyd_node *));
    if(!job->late_resolve_parent_r) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_parent_r[job->late_resolve_count] = parent_r;

    job->late_resolve_instance = (generate_instance_t **)realloc(job->late_resolve_instance, (job->late_resolve_count + 1) * sizeof(generate_instance_t *));
    if(!job->late_resolve_instance) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_instance[job->late_resolve_count] = instance;

    job->late_resolve_count++;

    return NTS_ERR_OK;
}

static const char* leafref_test_val(int index) {
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
            log_error("index out of bounds\n");
            return 0;
            break;
    }
}

static int generate_get_instance_count(const char *path) {
    assert(path);

    for(int i = 0; i < framework_config.datastore_generate.custom_list_instances_count; i++) {
        if(strcmp(path, framework_config.datastore_generate.custom_list_instances[i].path) == 0) {
            return framework_config.datastore_generate.custom_list_instances[i].count;
        }
    }
    return framework_config.datastore_generate.default_list_instances;
}

static char *generate_get_restrict_schema(const char *path) {
    assert(path);
    char *ret = 0;

    for(int i = 0; i < framework_config.datastore_generate.restrict_schema_count; i++) {
        if(strcmp(path, framework_config.datastore_generate.restrict_schema[i].path) == 0) {
            ret = strdup(framework_config.datastore_generate.restrict_schema[i].values[framework_config.datastore_generate.restrict_schema[i].index]);
            framework_config.datastore_generate.restrict_schema[i].index++;
            if(framework_config.datastore_generate.restrict_schema[i].index >= framework_config.datastore_generate.restrict_schema[i].values_count) {
                framework_config.datastore_generate.restrict_schema[i].index = 0;
            }
            break;
        }
    }

    return ret;
}
