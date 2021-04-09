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

#include <stdbool.h>
#include <string.h>
#include <libyang/libyang.h>

struct lyd_node *datastore_load_external(const char *filename, bool operational);

//generate all available root nodes (taking into consideration excluded, deprecated and unimplemented modules and containers)
int datastore_generate_data(const char *running_filename, const char *operational_filename);
int datastore_generate_external(void);
