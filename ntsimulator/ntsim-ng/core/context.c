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

#include "context.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include <sysrepo.h>
#include "core/session.h"
#include <dirent.h>
#include <libgen.h>
#include <assert.h>

//private variables for context state
struct lys_ident_with_childcount {
    struct lys_ident *ident;
    int children;
};
static struct lys_ident_with_childcount *identities;
static int identities_size;                 //number of found identities

struct features_with_info {
    char *name;
    bool enabled;
};
static struct features_with_info *features;
static int features_size;


//private functions
static bool check_identity_of_type(const struct lys_ident *ident, const struct lys_ident *type);
static int identity_get_id(const struct lys_ident *ident);

int context_init(const struct ly_ctx *ly_ctx) {
    log_add_verbose(2, "context_init() begin\n");

    identities = 0;
    identities_size = 0;

    features = 0;
    features_size = 0;

    log_add_verbose(2, "loading modules\n");
    uint32_t idx = 0;
    struct lys_module *module;
    while((module = (struct lys_module *)ly_ctx_get_module_iter(ly_ctx, &idx)) != 0) {
        log_add_verbose(2, "MODULE %s\n", module->name);
        log_add_verbose(2, "  prefix: %s\n", module->prefix);
        log_add_verbose(2, "  namespace: %s\n", module->ns);
        log_add_verbose(2, "  imports [%d]", module->imp_size);
        if(module->imp_size) {
            log_add(2, ": ");
            for(int i = 0; i < module->imp_size; i++) {
                log_add(2, "%s(%s), ", module->imp[i].module->name, module->imp[i].module->prefix);
            }
        }
        log_add(2, "\n");
        log_add_verbose(2, "  implemented: %d\n", module->implemented);
        
        if(module->implemented) {
            log_add_verbose(2, "  IDENT count: %d\n", module->ident_size);
            if(module->ident_size) {
                //add to list of identities
                identities = (struct lys_ident_with_childcount *)realloc(identities, sizeof(struct lys_ident_with_childcount) * (identities_size + module->ident_size));
                if(!identities) {
                    log_error("bad realloc\n");
                    return 1;
                }

                for(int i = 0; i < module->ident_size; i++) {
                    identities[identities_size].ident = &module->ident[i];
                    identities[identities_size].children = 0;
                    identities_size++;

                    if(module->ident[i].base_size) {
                        log_add_verbose(2, "  IDENT[%d]  %s with base %s:%s\n", i, module->ident[i].name, module->ident[i].base[0]->module->name, module->ident[i].base[0]->name);
                        int id = identity_get_id(module->ident[i].base[0]);
                        if(id != -1) {
                            identities[id].children++;
                        }
                    }
                    else {
                        log_add_verbose(2, "  IDENT[%d]  %s as base\n", i, module->ident[i].name);
                    }
                }
            }


            log_add_verbose(2, "  FEATURES count: %d\n", module->features_size);
            if(module->features_size) {
                //add to list of features
                features = (struct features_with_info *)realloc(features, sizeof(struct features_with_info) * (features_size + module->features_size));
                if(!features) {
                    log_error("bad realloc\n");
                    return 1;
                }

                for(int i = 0; i < module->features_size; i++) {
                    asprintf(&features[features_size].name, "%s:%s", module->name, module->features[i].name);
                    features[features_size].enabled = (lys_features_state(module, module->features[i].name) == 1);
                    log_add_verbose(2, "  FEATURE[%d]  %s iffeature_size=%d enabled=%d\n", i, module->features[i].name, module->features[i].iffeature_size, features[features_size].enabled);
                    features_size++;
                }
            }
        }
        else {
            log_add_verbose(2, "-> module not implemented, skipping...\n");
        }

        log_add_verbose(2, " ----\n");
    }

    log_add_verbose(2, "context_init() finished\n");

    return 0;
}

void context_free(void) {
    log_add_verbose(2, "context_free()... ");
    free(identities);
    identities_size = 0;

    for(int i = 0; i < features_size; i++) {
        free(features[i].name);
    }
    free(features);   
    log_add(2, "done\n");
}

int context_get_identity_leafs_of_type(const struct lys_ident *ident, struct lys_ident ***found) {

    *found = (struct lys_ident **)malloc(sizeof(struct lys_ident *) * identities_size);
    if(!*found) {
        log_error("bad malloc\n");
    }

    int count = 0;
    for(int i = 0; i < identities_size; i++) {
        if(check_identity_of_type(identities[i].ident, ident)) {
            if(identities[i].children == 0) {
                (*found)[count] = identities[i].ident;
                count++;
            }
        }
    }

    if(count == 0) {
        log_error("no identities found\n");
    }
    else {
        *found = (struct lys_ident **)realloc(*found, sizeof(struct lys_ident *) * count);
    }

    return count;
}

int context_get_features(char ***found_features) {
    char **ftrs = (char **)malloc(sizeof(char *) * features_size);
    if(!ftrs) {
        log_error("could not alloc\n");
        return 0;
    }

    for(int i = 0; i < features_size; i++) {
        ftrs[i] = (char *)malloc(sizeof(char) * (strlen(features[i].name) + 1));
        if(!ftrs) {
            log_error("could not alloc\n");
            return 0;
        }

        strcpy(ftrs[i], features[i].name);
    }

    *found_features = ftrs;
    return features_size;
}

bool context_get_feature_enabled(const char *feature) {
    for(int i = 0; i < features_size; i++) {
        if(strcmp(feature, features[i].name) == 0) {
            return features[i].enabled;
        }
    }
    return false;
}

bool context_feature_enable(const char *feature) {
    assert(feature);

    char mod[96];
    char feat[96];

    mod[0] = 0;
    feat[0] = 0;

    int i = 0;
    int j = 0;
    while((i < strlen(feature)) && (feature[i] != ':')) {
        mod[j] = feature[i];
        j++;
        i++;
    }
    mod[j] = 0;
    
    i++;
    j = 0;
    while(i < strlen(feature)) {
        feat[j] = feature[i];
        j++;
        i++;
    }
    feat[j] = 0;

    int rc;
    if((rc = sr_enable_module_feature(session_connection, mod, feat)) != SR_ERR_OK) {
        return false;
    }
    
    return true;
}

bool context_module_install(const char *name, const char *path) {
    assert(name);
    assert(path);

    char *searchpath = strdup(path);
    int rc = sr_install_module(session_connection, path, dirname(searchpath), 0, 0);
    free(searchpath);
    if(rc != SR_ERR_OK) {
        /* succeed if the module is already installed */
        if(rc != SR_ERR_EXISTS) {
            return false;
        }
    }

    char *data_path = str_replace(path, ".yang", ".xml");
    if(file_exists(data_path)) {
        rc = sr_install_module_data(session_connection, name, 0, data_path, LYD_XML);
        if(rc != SR_ERR_OK) {
            log_add(1, " xml error    ");
            sr_remove_module(session_connection, name);
            context_apply_changes();
            return false;
        }
    }
    free(data_path);

    data_path = str_replace(path, ".yang", ".json");
    if(file_exists(data_path)) {
        rc = sr_install_module_data(session_connection, name, 0, data_path, LYD_JSON);
        if(rc != SR_ERR_OK) {
            log_add(1, " json error    ");
            sr_remove_module(session_connection, name);
            context_apply_changes();
            return false;
        }
    }
    free(data_path);

    //apply changes
    if(!context_apply_changes()) {
        sr_remove_module(session_connection, name);
        context_apply_changes();
        return false;
    }

    return true;
}

bool context_module_set_access(const char *module_name) {
    assert(module_name);

    if(sr_set_module_access(session_connection, module_name, "root", "root", 0666) != SR_ERR_OK) {
        return false;
    }

    return true;
}

bool context_apply_changes(void) {
    int rc;
    uint32_t connection_count = 0;

    session_context = 0;
    sr_disconnect(session_connection);
    session_connection = 0;

    /* get connection count */
    if((rc = sr_connection_count(&connection_count)) != SR_ERR_OK) {
        log_error("sr_connection_count() failed to get connection count\n");
        return false;
    }

    if(connection_count) {
        log_error("cannot apply changes because of existing connections\n");
        return false;
    }

    if((rc = sr_connect(SR_CONN_ERR_ON_SCHED_FAIL, &session_connection)) != SR_ERR_OK) {
        if((rc = sr_connect(0, &session_connection)) != SR_ERR_OK) {
            log_error("failed to reconnect to sysrepo\n");
        }
        return false;
    }

    /* get context */
    session_context = (struct ly_ctx *)sr_get_context(session_connection);
    if(session_context == 0) {
        log_error("sr_get_context failed\n");
        return false;
    }

    return true;
}

bool context_yang_is_module(const char *path) {
    assert(path);

    bool ret = false;
    struct ly_ctx *ctx = ly_ctx_new(0, 0);
    if(!ctx) {
        log_error("ly_ctx_new failed\n");
    }

    char *searchpath = strdup(path);
    ly_ctx_set_searchdir(ctx, dirname(searchpath));
    const struct lys_module *mod = lys_parse_path(ctx, path, LYS_YANG);
    if((!mod) && (ly_vecode(ctx) == LYVE_SUBMODULE)) {
        ret = true;
    }

    free(searchpath);
    ly_ctx_destroy(ctx, 0);
    return ret;
}


static bool check_identity_of_type(const struct lys_ident *ident, const struct lys_ident *type) {
    assert(type);

    if((ident->name == type->name) && (ident->module->name == type->module->name)) {
        return true;
    }
    else if(ident->base_size != 0) {
        bool result = false;
        for(int i = 0; i < ident->base_size; i++) {
            result |= check_identity_of_type(ident->base[i], type);
        }
        return result;
    }
    else {
        return false;
    }

}

static int identity_get_id(const struct lys_ident *ident) {
    assert(ident);

    for(int i = 0; i < identities_size; i++) {
        if((ident->name == identities[i].ident->name) && (ident->module->name == identities[i].ident->module->name)) {
            return i;
        }
    }

    return -1;
}
