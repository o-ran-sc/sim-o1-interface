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
#include "utils/nts_utils.h"
#include <stdio.h>
#include <assert.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#include "core/framework.h"
#include "core/session.h"
#include "core/xpath.h"
#include "core/context.h"

manager_context_t *manager_context = 0;
docker_context_t *docker_context = 0;
int docker_context_count = 0;

static int manager_populate_sysrepo_network_function_list(void);
static int manager_populate_available_simulations(void);

int manager_context_init(void) {

    //get installed function types
    struct lys_node_leaf *elem = (struct lys_node_leaf *)ly_ctx_get_node(session_context, 0, NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH"/function-type", 0);
    if(elem == 0) {
        log_error("ly_ctx_get_node failed for xpath: %s\n", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH"/function-type");
        return NTS_ERR_FAILED;
    }

    struct lys_ident **function_types = 0;
    docker_context_count = context_get_identity_leafs_of_type(elem->type.info.ident.ref[0], &function_types);
    if(!docker_context_count) {
        log_error("context_get_identity_leafs_of_type() error\n");
        return NTS_ERR_FAILED;
    }

    docker_context_count = docker_context_count;

    const char **docker_filter = malloc(sizeof(char *) * docker_context_count);
    if(docker_filter == 0) {
        log_error("bad malloc\n");
        free(function_types);
        return NTS_ERR_FAILED;
    }

    for(int i = 0; i < docker_context_count; i++) {
        docker_filter[i] = function_types[i]->ref;
    }

    int rc = docker_init(docker_filter, docker_context_count, NTS_VERSION_FALLBACK, &docker_context);
    if(rc != NTS_ERR_OK) {
        log_error("docker_init() failed\n");
        free(docker_filter);
        free(function_types);
        return NTS_ERR_FAILED;
    }

    //check if an image needs to be pulled
    log_add_verbose(1, "Docker auto-pull is ");
    if(strlen(framework_environment.settings.docker_repository)) {
        log_add(1, LOG_COLOR_BOLD_GREEN"enabled"LOG_COLOR_RESET"\n");
        int pull_count = 0;
        for(int i = 0; i < docker_context_count; i++) {
            bool pull = true;
            for(int j = 0; j < docker_context[i].available_images_count; j++) {
                if(strcmp(framework_environment.nts.version, docker_context[i].available_images[j].tag) == 0) {
                    pull = false;
                }
            }
            
            if(pull) {
                log_add_verbose(1, "pulling "LOG_COLOR_RED"%s/"LOG_COLOR_CYAN"%s"LOG_COLOR_RESET":"LOG_COLOR_YELLOW"%s"LOG_COLOR_RESET"... ", framework_environment.settings.docker_repository, docker_context[i].image, framework_environment.nts.version);
                rc = docker_pull(framework_environment.settings.docker_repository, docker_context[i].image, framework_environment.nts.version);
                if(rc != NTS_ERR_OK) {
                    log_add(1, LOG_COLOR_BOLD_RED"failed"LOG_COLOR_RESET"\n");
                }
                else {
                    log_add(1, LOG_COLOR_BOLD_GREEN"OK"LOG_COLOR_RESET"\n");
                    pull_count++;
                }
            }
        }

        if(pull_count) {
            //reinit docker
            docker_free(docker_context, docker_context_count);
            rc = docker_init(docker_filter, docker_context_count, NTS_VERSION_FALLBACK, &docker_context);
            if(rc != NTS_ERR_OK) {
                log_error("docker_init() failed\n");
                free(docker_filter);
                free(function_types);
                return NTS_ERR_FAILED;
            }
        }
    }
    else {
        log_add(1, LOG_COLOR_YELLOW"disabled"LOG_COLOR_RESET"\n");
    }
    free(docker_filter);


    //remove non-present network functions
    int new_context_count = 0;
    docker_context_t *new_context = malloc(sizeof(docker_context_t) * docker_context_count);
    struct lys_ident **new_function_types = (struct lys_ident **)malloc(sizeof(struct lys_ident *) * docker_context_count);
    for(int i = 0; i < docker_context_count; i++) {
        if(docker_context[i].available_images_count) {
            new_context[new_context_count].image = docker_context[i].image;
            new_context[new_context_count].available_images = docker_context[i].available_images;
            new_context[new_context_count].available_images_count = docker_context[i].available_images_count;
            new_function_types[new_context_count] = function_types[i];
            
            new_context_count++;

        }
        else {
            free(docker_context[i].image);
        }
    }

    free(function_types);
    function_types = new_function_types;

    free(docker_context);
    docker_context = new_context;
    docker_context_count = new_context_count;

    //initial list population
    manager_context = (manager_context_t *)malloc(sizeof(manager_context_t) * docker_context_count);
    if(manager_context == 0) {
        log_error("malloc failed\n");
        free(function_types);
        return NTS_ERR_FAILED;
    }

    for(int i = 0; i < docker_context_count; i++) {
        manager_context[i].ft = function_types[i];

        asprintf(&manager_context[i].function_type, "%s:%s", manager_context[i].ft->module->name, manager_context[i].ft->name);
        manager_context[i].instance = 0;
        manager_context[i].docker = &docker_context[i];

        manager_context[i].started_instances = 0;
        manager_context[i].mounted_instances = 0;
        manager_context[i].mount_point_addressing_method = strdup("docker-mapping");
        
        if(docker_context[i].available_images_count) {
            manager_context[i].docker_instance_name = strdup(strstr(manager_context[i].function_type, ":") + 1);
            manager_context[i].docker_version_tag = strdup(docker_context[i].available_images[0].tag);
            manager_context[i].docker_repository = strdup(docker_context[i].available_images[0].repo);
        }
        else {
            manager_context[i].docker_instance_name = strdup("no-image-installed");
            manager_context[i].docker_version_tag = strdup("no-image-installed");
            manager_context[i].docker_repository = strdup("no-image-installed");
        }
    }
    free(function_types);

    //do initial sysrepo list population
    rc = manager_populate_sysrepo_network_function_list();
    if(rc != NTS_ERR_OK) {
        log_error("manager_populate_sysrepo_network_function_list failed\n");
        return NTS_ERR_FAILED;
    }

    rc = manager_populate_available_simulations();
    if(rc != NTS_ERR_OK) {
        log_error("manager_populate_available_simulations failed\n");
        return NTS_ERR_FAILED;
    }

    rc = nts_utils_populate_info(session_running, framework_environment.nts.function_type);
    if(rc != NTS_ERR_OK) {
        log_error("nts_utils_populate_info failed\n");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

void manager_context_free(void) {
    for(int i = 0; i < docker_context_count; i++) {
        free(manager_context[i].docker_instance_name);
        free(manager_context[i].docker_version_tag);
        free(manager_context[i].docker_repository);
        free(manager_context[i].function_type);
    }

    free(manager_context);
}

static int manager_populate_sysrepo_network_function_list(void) {
    //check whether everything is already populated, read and update (if previously ran)
    sr_val_t *values = 0;
    size_t value_count = 0;
    int rc = sr_get_items(session_running, NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, 0, 0, &values, &value_count);
    if(rc != SR_ERR_OK) {
        log_error("get items failed\n");
        return NTS_ERR_FAILED;
    }

    //either get values, or if data inconclusive, delete everything
    if(value_count) {
        log_add_verbose(2, "nts-manager instances found (%d). cleaning up for fresh start...\n", value_count);

        for(int i = 0; i < value_count; i++) {           
            rc = sr_delete_item(session_running, values[i].xpath, 0);
            if(rc != SR_ERR_OK) {
                log_error("sr_delete_item failed\n");
                return NTS_ERR_FAILED;
            }
        }
        rc = sr_apply_changes(session_running, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_apply_changes failed\n");
            return NTS_ERR_FAILED;
        }

        sr_free_values(values, value_count);
    }

    //populate everything if needed
    for(int i = 0; i < docker_context_count; i++) {
        char *xpath = 0;

        asprintf(&xpath, "%s[function-type='%s']/function-type", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, (const char *)manager_context[i].function_type, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/started-instances", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, "0", 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/mounted-instances", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, "0", 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/docker-instance-name", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, (const char*)manager_context[i].docker_instance_name, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/docker-version-tag", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, (const char*)manager_context[i].docker_version_tag, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/docker-repository", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, (const char*)manager_context[i].docker_repository, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/mount-point-addressing-method", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, (const char *)manager_context[i].mount_point_addressing_method, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        //presence containers
        asprintf(&xpath, "%s[function-type='%s']/fault-generation", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, 0, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/netconf", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, 0, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);

        asprintf(&xpath, "%s[function-type='%s']/ves", NTS_MANAGER_FUNCTION_LIST_SCHEMA_XPATH, manager_context[i].function_type);
        rc = sr_set_item_str(session_running, xpath, 0, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_set_item_str failed\n");
            return NTS_ERR_FAILED;
        }
        free(xpath);
    }

    //apply all changes
    rc = sr_apply_changes(session_running, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int manager_populate_available_simulations(void) {
    assert_session();

    struct lyd_node *container = lyd_new_path(0, session_context, NTS_MANAGER_AVAILABLE_IMAGES_SCHEMA_XPATH, 0, LYD_ANYDATA_CONSTSTRING, LYD_PATH_OPT_NOPARENTRET);
    if(container == 0) {
        log_error("lyd_new_path failed\n");
        return NTS_ERR_FAILED;
    }

    for(int i = 0; i < docker_context_count; i++) {
        for(int j = 0; j < docker_context[i].available_images_count; j++) {
            struct lyd_node *list = lyd_new(container, container->schema->module, "network-function-image");
            if(!list) {
                log_error("lyd_new failed\n");
                return NTS_ERR_FAILED;
            }

            struct lyd_node *rc = lyd_new_leaf(list, list->schema->module, "function-type", (const char *)manager_context[i].function_type);
            if(rc == 0) {
                log_error("lyd_new_leaf failed\n");
                return NTS_ERR_FAILED;
            }

            rc = lyd_new_leaf(list, list->schema->module, "docker-image-name", docker_context[i].image);
            if(rc == 0) {
                log_error("lyd_new_leaf failed\n");
                return NTS_ERR_FAILED;
            }

            rc = lyd_new_leaf(list, list->schema->module, "docker-version-tag", docker_context[i].available_images[j].tag);
            if(rc == 0) {
                log_error("lyd_new_leaf failed\n");
                return NTS_ERR_FAILED;
            }

            rc = lyd_new_leaf(list, list->schema->module, "docker-repository", docker_context[i].available_images[j].repo);
            if(rc == 0) {
                log_error("lyd_new_leaf failed\n");
                return NTS_ERR_FAILED;
            }

        }
    }

    //find top level container
    struct lyd_node *root = container;
    while(root->parent) {
        root = root->parent;
    }

    int rc = sr_edit_batch(session_operational, root, "replace");
    if(rc != SR_ERR_OK) {
        log_error("sr_edit_batch failed\n");
        return NTS_ERR_FAILED;
    }

    //apply all changes
    rc = sr_apply_changes(session_operational, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_apply_changes failed: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}
