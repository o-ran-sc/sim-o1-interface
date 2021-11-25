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

#include <stdint.h>
#include <libyang/libyang.h>
#include <stdbool.h>

#define POPULATE_LEAFREF_TEST_ENTRIES_TOTAL      11

typedef struct {
    int init;

    char *xpath;

    const struct lys_module **modules;
    int mod_count;

    struct lyd_node *dev;
    struct lyd_node *operational;
    struct lyd_node *running;
} populate_instance_t;

typedef struct {
    struct lyd_node *dev;
    struct lyd_node *operational;
    struct lyd_node *running;

    bool late_resolving;

    int late_resolve_count;
    struct lys_node **late_resolve_schema;
    struct lyd_node **late_resolve_parent_d;
    struct lyd_node **late_resolve_parent_o;
    struct lyd_node **late_resolve_parent_r;
    populate_instance_t **late_resolve_instance;
} populate_job_t;

//populate_aux.c
struct lyd_node *datastore_load_external(const char *filename, bool operational);

char populate_info_get_mandatory(const struct lys_node *schema);
const char* populate_leafref_test_val(int index);

int populate_instance_add_module(populate_instance_t *instance, const struct lys_module *module);
int populate_instance_get_count(const char *path);
char *populate_get_restrict_schema(const char *path);

//populate_late_resolve.c
int populate_late_resolve_add_leaf(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_d, struct lyd_node *parent_o, struct lyd_node *parent_r);
int populate_late_resolve(populate_job_t *job);

//populate_recursive.c
int populate_recursive(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_d, struct lyd_node *parent_o, struct lyd_node *parent_r, int operational_only);
int populate_add_leaf(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_d, struct lyd_node *parent_o, struct lyd_node *parent_r);

//populate_validation.c
int populate_validate(populate_instance_t *instance, int count);
