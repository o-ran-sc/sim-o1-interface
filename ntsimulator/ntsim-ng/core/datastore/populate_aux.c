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

#include "populate_internal.h"

#include "core/session.h"
#include "core/framework.h"
#include "utils/sys_utils.h"
#include "utils/log_utils.h"
#include "utils/type_utils.h"
#include "utils/rand_utils.h"

#include <assert.h>
#include <stdlib.h>

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

char populate_info_get_mandatory(const struct lys_node *schema) {
    assert(schema);

    char mandatory = ' ';
    if((schema->flags & LYS_MAND_TRUE) != 0) {
        mandatory = 'M';
    }
    if((schema->parent) && (schema->parent->nodetype == LYS_CASE)) {
        if((schema->parent->flags & LYS_MAND_TRUE) != 0) {
            mandatory = 'M';
        }
    }

    return mandatory;
}

const char* populate_leafref_test_val(int index) {
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

int populate_instance_add_module(populate_instance_t *instance, const struct lys_module *module) {
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

int populate_instance_get_count(const char *path) {
    assert(path);

    for(int i = 0; i < framework_config.datastore_generate.custom_list_instances_count; i++) {
        if(strcmp(path, framework_config.datastore_generate.custom_list_instances[i].path) == 0) {
            return framework_config.datastore_generate.custom_list_instances[i].count;
        }
    }
    return framework_config.datastore_generate.default_list_instances;
}

char *populate_get_restrict_schema(const char *path) {
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
