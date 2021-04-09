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

#include "container.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/http_client.h"
#include "core/framework.h"
#include "core/session.h"
#include "core/context.h"
#include <sysrepo.h>
#include <dirent.h>
#include <assert.h>

struct installable_module {
    char *name;
    char *fullpath;
    bool installed;
    bool submodule;
};


static int get_installable_modules(struct installable_module **modules);    //list available modules for install
static void list_yangs(const char *path, struct installable_module **modules, int *total);
static bool container_rules_is_excluded_module(const char *module);
static bool container_rules_is_excluded_feature(const char *feature);

bool container_self_init(void) {
    int rc;

    sr_log_stderr(SR_LL_NONE);
    log_add_verbose(1, "Entering container-init mode...\n");

    // connect to sysrepo
    rc = sr_connect(0, &session_connection);
    if(SR_ERR_OK != rc) {
        log_error("sr_connect failed\n");
        return false;
    }

    /* get context */
    session_context = (struct ly_ctx *)sr_get_context(session_connection);
    if(session_context == 0) {
        log_error("sr_get_context failed\n");
        return false;
    }

    /* install yang files */
    log_add_verbose(1, "Installing yang files...\n");
    struct installable_module *modules;
    int total_modules = get_installable_modules(&modules);
    log_add_verbose(1, "Found total modules: %d\n", total_modules);

    int old_failed_installations = 1;
    int failed_installations = 0;
    int install_round = 0;
    while(failed_installations != old_failed_installations) {
        old_failed_installations = failed_installations;
        failed_installations = 0;
        install_round++;
        for(int i = 0; i < total_modules; i++) {
            if(!modules[i].installed) {
                modules[i].submodule = context_yang_is_module(modules[i].fullpath);
                if(!modules[i].submodule) {
                    if(!container_rules_is_excluded_module(modules[i].name)) {
                        log_add_verbose(1, "[round %d] trying to install module %s from %s... ", install_round, modules[i].name, modules[i].fullpath);
                        if(!context_module_install(modules[i].name, modules[i].fullpath)) {
                            failed_installations++;
                            log_add(1, LOG_COLOR_BOLD_YELLOW"failed"LOG_COLOR_RESET"\n");
                        }
                        else {
                            log_add(1, LOG_COLOR_BOLD_GREEN"done"LOG_COLOR_RESET"\n");
                            modules[i].installed = true;
                        }
                    }
                    else {
                        log_add_verbose(1, "[round %d] not installing module %s as it's excluded in config.\n", install_round, modules[i].name);
                        modules[i].installed = true;
                    }
                }
                else {
                    log_add_verbose(1, "[round %d] %s is a submodule... "LOG_COLOR_BOLD_YELLOW"skipping"LOG_COLOR_RESET"\n", install_round, modules[i].name);
                    modules[i].installed = true;
                }
            }
        }
    }

    if(failed_installations != 0) {
        log_error("failed to install all modules in %d rounds...\n", install_round);
        return false;
    }
    else {
        log_add_verbose(1, LOG_COLOR_BOLD_GREEN"successfully"LOG_COLOR_RESET" installed "LOG_COLOR_BOLD_GREEN"ALL"LOG_COLOR_RESET" modules in "LOG_COLOR_BOLD_YELLOW"%d"LOG_COLOR_RESET" rounds\n", (install_round - 1));
    }

    //set access for all installed modules
    log_add_verbose(1, "Setting access configuration for installed modules... ");
    for(int i = 0; i < total_modules; i++) {
        if((!container_rules_is_excluded_module(modules[i].name)) && (!modules[i].submodule)) {
            if(!context_module_set_access(modules[i].name)) {
                log_error("failed to set access to module %s...\n", modules[i].name);
                return false;
            }
        }
    }
    log_add(1, LOG_COLOR_BOLD_GREEN"done"LOG_COLOR_RESET"\n");

    //cleanup module-install used memory
    for(int i = 0; i < total_modules; i++) {
        free(modules[i].name);
        free(modules[i].fullpath);
    }
    free(modules);

    //get context
    session_context = (struct ly_ctx *)sr_get_context(session_connection);
    if(session_context == 0) {
        log_error("sr_get_context failed\n");
        return false;
    }

    //init context so we can see all the available modules, features, etc
    rc = context_init(session_context);
    if(rc != 0) {
        log_error("context_init() failed\n");
        return false;
    }

    /* enable features */
    log_add_verbose(1, "Enabling yang features...\n");
    char **available_features;
    int total_available_features;
    total_available_features = context_get_features(&available_features);
    log_add_verbose(1, "Found total features: %d\n", total_available_features);
    for(int i = 0; i < total_available_features; i++) {
        log_add_verbose(1, "feature %s: ", available_features[i]);

        if(!context_get_feature_enabled(available_features[i])) {
            if(!container_rules_is_excluded_feature(available_features[i])) {
                if(context_feature_enable(available_features[i])) {
                    log_add(1, "enabling... "LOG_COLOR_BOLD_GREEN"done"LOG_COLOR_RESET"\n");
                }
                else {
                    log_error("enabling... failed\n");
                }
            }
            else {
                log_add(1, "excluded in config, skipping\n");
            }
        }
        else {
            log_add(1, "already "LOG_COLOR_BOLD_GREEN"enabled"LOG_COLOR_RESET", skipping.\n");
        }
    }
    for(int i = 0; i < total_available_features; i++) {
        free(available_features[i]);
    }
    free(available_features);

    sr_disconnect(session_connection);
    context_free();

    log_add_verbose(1, LOG_COLOR_BOLD_GREEN"ntsim successfully initialized Docker container"LOG_COLOR_RESET"\n");
    return true;
}

static int get_installable_modules(struct installable_module **modules) {
    int total = 0;
    *modules = 0;
    list_yangs("/opt/dev/deploy/yang", modules, &total);
    return total;
}

static void list_yangs(const char *path, struct installable_module **modules, int *total) {
    DIR *d;
    struct dirent *dir;
    d = opendir(path);
    if(d) {
        while((dir = readdir(d)) != NULL) {
            if(dir->d_type == DT_DIR) {
                if(strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
                {
                    char new_path[1024];
                    snprintf(new_path, sizeof(new_path), "%s/%s", path, dir->d_name);
                    list_yangs(new_path, modules, total);
                }
            } else {
                if(strstr(dir->d_name, ".yang") != 0) {
                    *modules = (struct installable_module *)realloc(*modules, sizeof(struct installable_module) * (*total + 1));
                    if(!*modules) {
                        log_error("allocation failed\n");
                        return;
                    }

                    (*modules)[*total].name = (char*)malloc(sizeof(char) * (strlen(dir->d_name) + 1));
                    if(!(*modules)[*total].name) {
                        log_error("allocation failed\n");
                        return;
                    }
                    strcpy((*modules)[*total].name, dir->d_name);
                    (*modules)[*total].name[strlen(dir->d_name) - 5] = 0;   //extract ".yang"
                    char *rev = strstr((*modules)[*total].name, "@");
                    if(rev) { //extract revision, if exists
                        *rev = 0;
                    }

                    (*modules)[*total].fullpath = (char*)malloc(sizeof(char) * (strlen(path) + 1 + strlen(dir->d_name) + 1));
                    if(!(*modules)[*total].fullpath) {
                        log_error("allocation failed\n");
                        return;
                    }
                    sprintf((*modules)[*total].fullpath, "%s/%s", path, dir->d_name);

                    (*modules)[*total].installed = false;
                    (*modules)[*total].submodule = false;

                    (*total)++;
                }
            }
        }
        closedir(d);
    }
}

static bool container_rules_is_excluded_module(const char *module) {
    assert(module);

    for(int i = 0; i < framework_config.docker.excluded_modules_count; i++) {
        if(strstr(module, framework_config.docker.excluded_modules[i]) != 0) {
            return true;
        }
    }
    
    return false;
}

static bool container_rules_is_excluded_feature(const char *feature) {
    assert(feature);

    for(int i = 0; i < framework_config.docker.excluded_features_count; i++) {
        if(strstr(feature, framework_config.docker.excluded_features[i]) != 0) {
            return true;
        }
    }
    
    return false;
}