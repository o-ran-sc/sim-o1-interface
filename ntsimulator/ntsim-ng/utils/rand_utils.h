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
#include <stdbool.h>
#include <libyang/libyang.h>

void rand_init(void);
void rand_init_fixed(unsigned int seed);
char *rand_get_populate_value(const struct lys_type *type);

// independent functions used by rand_get_populate_value
uint8_t rand_uint8(void);
int8_t rand_int8(void);
uint16_t rand_uint16(void);
int16_t rand_int16(void);
uint32_t rand_uint32(void);
int32_t rand_int32(void);
uint64_t rand_uint64(void);
int64_t rand_int64(void);
bool rand_bool(void);

//results should be freed by user
char *rand_regex(const char *regexp);
char *rand_mac_address(void);

