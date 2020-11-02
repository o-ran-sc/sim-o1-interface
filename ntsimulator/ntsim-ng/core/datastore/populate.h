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

typedef struct {
    int init;

    char *xpath;

    const struct lys_module **modules;
    int mod_count;

    struct lyd_node *operational;
    struct lyd_node *running;
} populate_instance_t;

typedef struct {
    struct lyd_node *operational;
    struct lyd_node *running;
    bool late_resolving;

    int late_resolve_count;
    struct lys_node **late_resolve_schema;
    struct lyd_node **late_resolve_parent_o;
    struct lyd_node **late_resolve_parent_r;
    populate_instance_t **late_resolve_instance;
} populate_job_t;

//populate.c
int schema_populate(void);                     //populate all available root nodes (taking into consideration excluded, deprecated and unimplemented)

//populate_rec.c
int schema_populate_recursive(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r);
int schema_populate_add_leaf(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_o, struct lyd_node *parent_r);
