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

#include "utils/log_utils.h"
#include "utils/type_utils.h"
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <assert.h>

#include <libyang/libyang.h>
#include "core/session.h"
#include "core/framework.h"

static int schema_print_recursive(struct lys_node *root);
static bool generate_is_excluded_module(const char *module);

int datastore_schema_get_xpaths(char ***root_xpath) {
    assert_session();
    assert(root_xpath);

    const struct lys_module *module;
    const struct lys_node *root;
    uint32_t idx = 0;
    char **list = 0;
    int total = 0;

    while((module = ly_ctx_get_module_iter(session_context, &idx)) != 0) {
        if(!generate_is_excluded_module(module->name) && (module->implemented)) {
            LY_TREE_FOR(module->data, root) {
                if(((root->nodetype == LYS_CONTAINER) || (root->nodetype == LYS_LIST)) && ((root->flags & LYS_STATUS_DEPRC) == 0)) {
                    list = (char **)realloc(list, sizeof(char *) * (total + 1));
                    if(!list) {
                        log_error("bad realloc\n");
                        return NTS_ERR_FAILED;
                    }
                    asprintf(&list[total], "/%s:%s", module->name, root->name);
                    if(!list[total]) {
                        log_error("bad asprintf\n");
                        return NTS_ERR_FAILED;
                    }
                    total++; 
                }
                else if(root->nodetype == LYS_USES) {
                    struct lys_node *chd;
                    LY_TREE_FOR(root->child, chd) {
                        if(((chd->nodetype == LYS_CONTAINER) || (chd->nodetype == LYS_LIST)) && ((chd->flags & LYS_STATUS_DEPRC) == 0)) {
                            list = (char **)realloc(list, sizeof(char *) * (total + 1));
                            if(!list) {
                                log_error("bad realloc\n");
                                return NTS_ERR_FAILED;
                            }
                            asprintf(&list[total], "/%s:%s", module->name, chd->name);                            
                            if(!list[total]) {
                                log_error("bad asprintf\n");
                                return NTS_ERR_FAILED;
                            }
                            total++;
                        }
                    }
                }
            }
        }
    }

    *root_xpath = list;
    return total;
}

int datastore_schema_get_running_xpaths(char ***root_xpath, char ***modules) {
    assert_session();
    assert(root_xpath);
    assert(modules);

    const struct lys_module *module;
    const struct lys_node *root;
    uint32_t idx = 0;
    char **xpath_list = 0;
    char **mod_list = 0;
    int total = 0;

    while((module = ly_ctx_get_module_iter(session_context, &idx)) != 0) {
        if(!generate_is_excluded_module(module->name) && (module->implemented)) {
            LY_TREE_FOR(module->data, root) {
                if(((root->nodetype == LYS_CONTAINER) || (root->nodetype == LYS_LIST)) && ((root->flags & LYS_STATUS_DEPRC) == 0) && ((root->flags & LYS_CONFIG_W) == 1)) {
                    xpath_list = (char **)realloc(xpath_list, sizeof(char *) * (total + 1));
                    if(!xpath_list) {
                        log_error("bad realloc\n");
                        return NTS_ERR_FAILED;
                    }
                    asprintf(&xpath_list[total], "/%s:%s", module->name, root->name);
                    if(!xpath_list[total]) {
                        log_error("bad asprintf\n");
                        return NTS_ERR_FAILED;
                    }

                    mod_list = (char **)realloc(mod_list, sizeof(char *) * (total + 1));
                    if(!mod_list) {
                        log_error("bad realloc\n");
                        return NTS_ERR_FAILED;
                    }
                    asprintf(&mod_list[total], "%s", module->name);
                    if(!mod_list[total]) {
                        log_error("bad asprintf\n");
                        return NTS_ERR_FAILED;
                    }
                    total++; 
                }
                else if(root->nodetype == LYS_USES) {
                    struct lys_node *chd;
                    LY_TREE_FOR(root->child, chd) {
                        if(((chd->nodetype == LYS_CONTAINER) || (chd->nodetype == LYS_LIST)) && ((chd->flags & LYS_STATUS_DEPRC) == 0) && ((root->flags & LYS_CONFIG_W) == 1)) {
                            xpath_list = (char **)realloc(xpath_list, sizeof(char *) * (total + 1));
                            if(!xpath_list) {
                                log_error("bad realloc\n");
                                return NTS_ERR_FAILED;
                            }
                            asprintf(&xpath_list[total], "/%s:%s", module->name, chd->name);                            
                            if(!xpath_list[total]) {
                                log_error("bad asprintf\n");
                                return NTS_ERR_FAILED;
                            }

                            mod_list = (char **)realloc(mod_list, sizeof(char *) * (total + 1));
                            if(!mod_list) {
                                log_error("bad realloc\n");
                                return NTS_ERR_FAILED;
                            }
                            asprintf(&mod_list[total], "%s", module->name);
                            if(!mod_list[total]) {
                                log_error("bad asprintf\n");
                                return NTS_ERR_FAILED;
                            }
                            total++;
                        }
                    }
                }
            }
        }
    }

    *root_xpath = xpath_list;
    *modules = mod_list;
    return total;
}

int datastore_schema_print_root_paths(void) {
    assert_session();

    struct lys_module *module;
    struct lys_node *root;
    uint32_t idx = 0;

    while((module = (struct lys_module *)ly_ctx_get_module_iter(session_context, &idx)) != 0) {
        log_add_verbose(2, "looking into module "LOG_COLOR_BOLD_MAGENTA"%s"LOG_COLOR_RESET"\n", module->name);

        char flags[10];
        strcpy(flags, "[     ]");
        flags[1] = (module->implemented == 0) ? 'i' : ' ';
        flags[3] = generate_is_excluded_module(module->name) ? 'E' : ' ';

        LY_TREE_FOR(module->data, root) {
            log_add_verbose(2, "   found "LOG_COLOR_CYAN"%s"LOG_COLOR_RESET" with name "LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET"\n", typeutils_yang_nodetype_to_str(root->nodetype), root->name);
            if((root->nodetype == LYS_CONTAINER) || (root->nodetype == LYS_LIST)) {
                flags[2] = ((root->flags & LYS_STATUS_DEPRC) != 0) ? 'D' : ' ';
                flags[4] = ((root->flags & LYS_CONFIG_W) == 0) ? 'O' : 'R';
                flags[5] = (root->nodetype == LYS_CONTAINER) ? 'C' : 'L';
                log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_CYAN" /%s:%s\n"LOG_COLOR_RESET, flags, module->name, root->name);
            }
            else if(root->nodetype == LYS_USES) {
                struct lys_node *chd;
                LY_TREE_FOR(root->child, chd) {
                    log_add_verbose(2, "   - found "LOG_COLOR_CYAN"%s"LOG_COLOR_RESET" with name "LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET"\n", typeutils_yang_nodetype_to_str(chd->nodetype), chd->name);
                    if((chd->nodetype == LYS_CONTAINER) || (chd->nodetype == LYS_LIST)) {
                        flags[2] = ((chd->flags & LYS_STATUS_DEPRC) != 0) ? 'D' : ' ';
                        flags[4] = ((chd->flags & LYS_CONFIG_W) == 0) ? 'O' : 'R';
                        flags[5] = (chd->nodetype == LYS_CONTAINER) ? 'C' : 'L';
                        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_CYAN" /%s:%s\n"LOG_COLOR_RESET, flags, module->name, chd->name);
                    }
                }
            }
        }
    }

    log_add_verbose(1, "\n   "LOG_COLOR_BOLD_YELLOW"i"LOG_COLOR_RESET" - not implemented | "LOG_COLOR_BOLD_YELLOW"D"LOG_COLOR_RESET" - deprecated | "LOG_COLOR_BOLD_YELLOW"E"LOG_COLOR_RESET" - excluded by config | "LOG_COLOR_BOLD_YELLOW"O"LOG_COLOR_RESET" - operational datastore | "LOG_COLOR_BOLD_YELLOW"R"LOG_COLOR_RESET" - running datastore | "LOG_COLOR_BOLD_YELLOW"C"LOG_COLOR_RESET" - container | "LOG_COLOR_BOLD_YELLOW"L"LOG_COLOR_RESET" - list\n\n");
    return NTS_ERR_OK;
}

int datastore_schema_print_xpath(const char *xpath) {
    assert_session();
    assert(xpath);

    if(xpath == 0) {
        log_error("xpath is null\n");
        return NTS_ERR_FAILED;
    }
    log_add_verbose(1, "printing out data structure for xpath: "LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET"\n", xpath);
    
    struct lys_node *elem = (struct lys_node *)ly_ctx_get_node(session_context, 0, xpath, 0);
    if(elem == 0) {
        log_error("ly_ctx_get_node failed for xpath: %s\n", xpath);
        return NTS_ERR_FAILED;
    }

    struct lys_module *module = lys_node_module(elem);
    if(module == 0) {
        log_error("lys_node_module failed for xpath: %s\n", xpath);
        return NTS_ERR_FAILED;
    }


    log_add_verbose(2, "module is %s @ revision %s\n", module->name, module->rev[0].date);

    int rc = schema_print_recursive(elem);
    if(rc != NTS_ERR_OK) {
        log_error("schema_print_recursive failed for xpath: %s\n", xpath);
        return NTS_ERR_FAILED;
    }

    log_add_verbose(1, "\n   "LOG_COLOR_BOLD_YELLOW"O"LOG_COLOR_RESET" - operational datastore | "LOG_COLOR_BOLD_YELLOW"R"LOG_COLOR_RESET" - running datastore | "LOG_COLOR_BOLD_YELLOW"*"LOG_COLOR_RESET" - key | "LOG_COLOR_BOLD_YELLOW"M"LOG_COLOR_RESET" - mandatory | "LOG_COLOR_BOLD_YELLOW"D"LOG_COLOR_RESET" - deprecated | "LOG_COLOR_BOLD_YELLOW"S"LOG_COLOR_RESET" - obsolete\n\n");
    log_add_verbose(2, "schema_print() finished\n");

    return NTS_ERR_OK;

}

static int schema_print_recursive(struct lys_node *root) {
    assert(root);

    char my_status[] = "[    ]";
    my_status[1] = ((root->flags & LYS_CONFIG_W) == 0) ? 'O' : 'R';
    my_status[2] = ((root->flags & LYS_MAND_TRUE) != 0) ? 'M' : ' ';
    my_status[3] = ((root->flags & LYS_STATUS_DEPRC) != 0) ? 'D' : ' ';
    my_status[4] = ((root->flags & LYS_STATUS_OBSLT) != 0) ? 'S' : ' ';

    if(((root->parent) && (root->parent->nodetype == LYS_CASE)) && ((root->parent->flags & LYS_MAND_TRUE) != 0)) {
        my_status[2] = 'M';
    }

    char *path = lys_data_path(root);
    if((root->nodetype != LYS_CHOICE) && (root->nodetype != LYS_CASE)) {
        log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" %-100s ", my_status, path);

        if(root->nodetype == LYS_LIST) {
            struct lys_node_list *list = (struct lys_node_list *)root;
            log_add(1, LOG_COLOR_CYAN"%s "LOG_COLOR_MAGENTA"(m: %d M: %d)"LOG_COLOR_RESET, 4 + typeutils_yang_nodetype_to_str(root->nodetype), list->min, list->max); //+4 to skip "LYS_"
        }
        else if(root->nodetype == LYS_LEAFLIST) {
            struct lys_node_leaflist *list = (struct lys_node_leaflist *)root;
            log_add(1, LOG_COLOR_CYAN"%s "LOG_COLOR_MAGENTA"(m: %d M: %d)"LOG_COLOR_RESET, 4 + typeutils_yang_nodetype_to_str(root->nodetype), list->min, list->max); //+4 to skip "LYS_"
        }
        else {
            log_add(1, LOG_COLOR_CYAN"%-20s"LOG_COLOR_RESET, 4 + typeutils_yang_nodetype_to_str(root->nodetype)); //+4 to skip "LYS_"
        }
    }
    free(path);

    switch(root->nodetype) {
        case LYS_LEAF:
        case LYS_LEAFLIST: {            
            struct lys_type *type = &((struct lys_node_leaf *)root)->type;
            if(lys_is_key((const struct lys_node_leaf *)root, 0) != 0) {
                log_add(1, LOG_COLOR_BOLD_YELLOW"[*]"LOG_COLOR_RESET);
            }
            else {
                log_add(1, "   ");
            }

            char *typestr = typeutils_type_to_str(type);
            log_add(1, "[%s]", typestr);
            free(typestr);
            
            if(root->parent) {
                if(root->parent->nodetype == LYS_CASE) {
                    log_add(1, " is a "LOG_COLOR_BLUE"CASE"LOG_COLOR_RESET" of "LOG_COLOR_CYAN"%s"LOG_COLOR_RESET, root->parent->parent->name);
                }
            }
            
            if(type->base == LY_TYPE_LEAFREF) {
                log_add(1, " path: "LOG_COLOR_GREEN"%s"LOG_COLOR_RESET" ", type->info.lref.path);
            }
            else if(type->base == LY_TYPE_UNION) {
                if((type->info.uni.count == 0) && (type->der != 0)) {
                    type = &type->der->type;
                }

                log_add(1, " available union types (%d):"LOG_COLOR_GREEN, type->info.uni.count);
                for(int i = 0; i < type->info.uni.count; i++) {
                    char *typestr = typeutils_type_to_str(&type->info.uni.types[i]);
                    log_add(1, " %s", typestr);
                    free(typestr);
                }
                log_add(1, LOG_COLOR_RESET);
            }
        } break;

        default:
            break;
    }
  
    if((root->nodetype != LYS_CHOICE) && (root->nodetype != LYS_CASE)) {
        log_add(1, "\n");
    }

    struct lys_node *child = 0;
    LY_TREE_FOR(root->child, child) {
        int rc = schema_print_recursive(child);
        if(rc != NTS_ERR_OK) {
            return rc;
        }
    }

    return NTS_ERR_OK;
}

static bool generate_is_excluded_module(const char *module) {
    assert(module);

    for(int i = 0; i < framework_config.datastore_generate.excluded_modules_count; i++) {
        if(strstr(module, framework_config.datastore_generate.excluded_modules[i]) != 0) {
            return true;
        }
    }
    
    return false;
}
