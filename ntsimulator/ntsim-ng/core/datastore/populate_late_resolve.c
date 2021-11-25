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

#include "populate_internal.h"
#include "utils/log_utils.h"
#include "utils/rand_utils.h"
#include "utils/type_utils.h"

#include "core/datastore/schema.h"
#include "core/framework.h"
#include "core/session.h"

#include <sysrepo.h>
#include <libyang/libyang.h>

#include <stdlib.h>
#include <assert.h>

int populate_late_resolve_add_leaf(populate_job_t *job, populate_instance_t *instance, struct lys_node *schema, struct lyd_node *parent_d, struct lyd_node *parent_o, struct lyd_node *parent_r) {
    assert(job);
    assert(instance);

    job->late_resolve_schema = (struct lys_node **)realloc(job->late_resolve_schema, (job->late_resolve_count + 1) * sizeof(struct lys_node *));
    if(!job->late_resolve_schema) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_schema[job->late_resolve_count] = schema;

    job->late_resolve_parent_d = (struct lyd_node **)realloc(job->late_resolve_parent_d, (job->late_resolve_count + 1) * sizeof(struct lyd_node *));
    if(!job->late_resolve_parent_d) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_parent_d[job->late_resolve_count] = parent_d;

    job->late_resolve_parent_o = (struct lyd_node **)realloc(job->late_resolve_parent_o, (job->late_resolve_count + 1) * sizeof(struct lyd_node *));
    if(!job->late_resolve_parent_o) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_parent_o[job->late_resolve_count] = parent_o;

    job->late_resolve_parent_r = (struct lyd_node **)realloc(job->late_resolve_parent_r, (job->late_resolve_count + 1) * sizeof(struct lyd_node *));
    if(!job->late_resolve_parent_r) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_parent_r[job->late_resolve_count] = parent_r;

    job->late_resolve_instance = (populate_instance_t **)realloc(job->late_resolve_instance, (job->late_resolve_count + 1) * sizeof(populate_instance_t *));
    if(!job->late_resolve_instance) {
        log_error("bad realloc\n");
        return NTS_ERR_FAILED;
    }
    job->late_resolve_instance[job->late_resolve_count] = instance;

    job->late_resolve_count++;

    return NTS_ERR_OK;
}


int populate_late_resolve(populate_job_t *job) {
    assert(job);

    job->late_resolving = true;

    int prev_count = job->late_resolve_count + 1;

    while(prev_count > job->late_resolve_count) {
        int late_resolve_count = job->late_resolve_count;
        struct lys_node **late_resolve_schema = job->late_resolve_schema;
        struct lyd_node **late_resolve_parent_d = job->late_resolve_parent_d;
        struct lyd_node **late_resolve_parent_o = job->late_resolve_parent_o;
        struct lyd_node **late_resolve_parent_r = job->late_resolve_parent_r;
        populate_instance_t **late_resolve_instance = job->late_resolve_instance;
        
        job->late_resolve_count = 0;
        job->late_resolve_schema = 0;
        job->late_resolve_parent_d = 0;
        job->late_resolve_parent_o = 0;
        job->late_resolve_parent_r = 0;
        job->late_resolve_instance = 0;

        prev_count = late_resolve_count;

        for(int i = 0; i < late_resolve_count; i++) {
            log_add_verbose(1, LOG_COLOR_BOLD_YELLOW"late-populating "LOG_COLOR_RESET": ");
            int rc = populate_add_leaf(job, late_resolve_instance[i], late_resolve_schema[i], late_resolve_parent_d[i], late_resolve_parent_o[i], late_resolve_parent_r[i]);
            if(rc != NTS_ERR_OK) {
                log_error("populate_add_leaf failed on late-resolve\n");
                return rc;
            }
        }

        free(late_resolve_schema);
        free(late_resolve_parent_d);
        free(late_resolve_parent_o);
        free(late_resolve_parent_r);
        free(late_resolve_instance);
    }
    job->late_resolving = false;

    if(prev_count != 0) {
        log_error("populate_late_resolve detected circular loop!\n");
    }

    return NTS_ERR_OK;
}
