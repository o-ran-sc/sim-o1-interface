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

#pragma once

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <libyang/libyang.h>

int context_init(const struct ly_ctx *ly_ctx);
void context_free(void);

int context_get_identity_leafs_of_type(const struct lys_ident *ident, struct lys_ident ***found);

//context_features (feature expressed as in module:feature)
int context_get_features(char ***found_features);
bool context_get_feature_enabled(const char *feature);
bool context_feature_enable(const char *feature);                       //enable feature 

bool context_module_install(const char *name, const char *path);        //install module. module needs to be present in yang/ folder as module_name.yang
bool context_yang_is_module(const char *path);                          //check whether the file only has submodules, and no modules. function assumes that installing has failed every round
bool context_module_set_access(const char *module_name);                //set root permissions for module
bool context_apply_changes(void);                                       //used after installing modules mainly
