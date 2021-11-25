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

#pragma once

#include <string.h>
#include <stdint.h>

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <sysrepo/values.h>

int datastore_operations_add_sr_val(struct lyd_node *datastore, const sr_val_t *val);
int datastore_operations_change_sr_val(struct lyd_node *datastore, const sr_val_t *val);
int datastore_operations_free_path(struct lyd_node *datastore, const char *xpath);

struct lyd_node *datastore_operations_get_lyd_node(struct lyd_node *datastore, const char *xpath);
