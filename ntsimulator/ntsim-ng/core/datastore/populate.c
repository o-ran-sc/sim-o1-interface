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

#include "populate.h"
#include "utils/log_utils.h"
#include "utils/rand_utils.h"
#include "utils/type_utils.h"
#include <stdio.h>
#include <assert.h>

#include "core/session.h"
#include "core/framework.h"

#include "core/datastore/schema.h"

static int schema_populate_late_resolve(populate_job_t *job);
static int schema_populate_validate(populate_instance_t *instance, int count);
static int schema_populate_commit_to_datastore(populate_job_t *job);

int schema_populate(void) {
    assert_session();

    log_message(1, LOG_COLOR_BOLD_YELLOW"schema_populate() begin\n"LOG_COLOR_RESET);

    char **xpaths = 0;
    int instance_count = schema_get_xpaths(&xpaths);
    if(instance_count < 0) {
        log_error("schema_get_xpaths failed");
        return NTS_ERR_FAILED;
    }

    populate_job_t job;
    job.operational = 0;
    job.running = 0;
    job.late_resolve_count = 0;
    job.late_resolve_instance = 0;
    job.late_resolve_schema = 0;
    job.late_resolve_parent_o = 0;
    job.late_resolve_parent_r = 0;
    job.late_resolving = false;

    populate_instance_t *instance = (populate_instance_t *)malloc(sizeof(populate_instance_t) * instance_count);
    if(!instance) {
        log_error("bad malloc");
        return NTS_ERR_FAILED;
    }
    
    //populate everything
    for(int i = 0; i < instance_count; i++) {
        log_message(1, "populating "LOG_COLOR_BOLD_YELLOW"%s"LOG_COLOR_RESET" with data...\n", xpaths[i]);

        struct lys_node *schema_node = (struct lys_node *)ly_ctx_get_node(session_context, 0, xpaths[i], 0);
        if(schema_node == 0) {
            log_error("ly_ctx_get_node failed for %s", xpaths[i]);
            return NTS_ERR_FAILED;
        }

        if(schema_node == 0) {
            log_message(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            log_error("ly_ctx_get_node failed for %s", xpaths[i]);
            return NTS_ERR_FAILED;
        }

        if(!schema_node->module->implemented) {
            log_message(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            log_error("module is not implemented for %s", xpaths[i]);
            return NTS_ERR_FAILED;
        }

        if((schema_node->flags & LYS_STATUS_DEPRC) != 0) {
            log_message(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            log_error("module is deprecated for %s", xpaths[i]);
            return NTS_ERR_FAILED;
        }

        //populate current instance vals
        instance[i].init = 0;
        instance[i].xpath = strdup(xpaths[i]);
        instance[i].modules = 0;
        instance[i].mod_count = 0;
        instance[i].operational = 0;
        instance[i].running = 0;
        
        //do the actual population
        int rc = schema_populate_recursive(&job, &instance[i], schema_node, 0, 0);
        if(rc != NTS_ERR_OK) {
            log_error("schema_populate_recursive failed instance %d with xpath %s", i, instance[i].xpath);
            return rc;
        }
    }

    //link everything so we would be able to find everything in late-resolve
    log_message(1, LOG_COLOR_BOLD_YELLOW"schema_populate() done populating, now linking... (%d root nodes)\n"LOG_COLOR_RESET, instance_count);
    for(int i = 0; i < instance_count; i++) {

        if(instance[i].operational) {
            if(job.operational) {
                int rc = lyd_insert_sibling(&job.operational, instance[i].operational);
                if(rc != 0) {
                    log_error("lyd_insert_sibling");
                    return NTS_ERR_FAILED;
                }
            }
            else {
                job.operational = instance[i].operational;
            }
        }

        if(instance[i].running) {
            if(job.running) {
                int rc = lyd_insert_sibling(&job.running, instance[i].running);
                if(rc != 0) {
                    log_error("lyd_insert_sibling");
                    return NTS_ERR_FAILED;
                }
            }
            else {
                job.running = instance[i].running;
            }
        }
    }

    //late-resolve
    log_message(1, LOG_COLOR_BOLD_YELLOW"schema_populate() starting late-resolve process...\n"LOG_COLOR_RESET);
    if(job.late_resolve_count) {
        int rc = schema_populate_late_resolve(&job);
        if(rc != NTS_ERR_OK) {
            log_error("schema_populate_late_resolve failed");
            return rc;
        }
    }
    
    //validate data and remove invalid nodes
    log_message(1, LOG_COLOR_BOLD_YELLOW"schema_populate() validating\n"LOG_COLOR_RESET);
    int rc = schema_populate_validate(instance, instance_count);
    if(rc != NTS_ERR_OK) {
        log_error("schema_populate_commit_to_datastore failed");
        return rc;
    }

    //commit to datastore
    log_message(1, LOG_COLOR_BOLD_YELLOW"schema_populate() commiting to datastore\n"LOG_COLOR_RESET);
    rc = schema_populate_commit_to_datastore(&job);
    if(rc != NTS_ERR_OK) {
        log_error("schema_populate_commit_to_datastore failed");
        return rc;
    }

    //cleanup
    log_message(1, LOG_COLOR_BOLD_YELLOW"schema_populate() cleaning up... "LOG_COLOR_RESET);
    for(int i = 0; i < instance_count; i++) {
        log_message(1, "%d ", i);

        free(instance[i].modules);
        free(instance[i].xpath);

        free(xpaths[i]);
    }
    free(xpaths);
    free(job.late_resolve_instance);
    free(job.late_resolve_schema);
    free(job.late_resolve_parent_o);
    free(job.late_resolve_parent_r);

    lyd_free_withsiblings(job.operational);
    lyd_free_withsiblings(job.running);
        
    log_message(1, "\n");
    log_message(1, LOG_COLOR_BOLD_GREEN"schema_populate() finished\n"LOG_COLOR_RESET);
    
    return NTS_ERR_OK;
}

static int schema_populate_late_resolve(populate_job_t *job) {
    assert(job);

    job->late_resolving = true;
    for(int i = 0; i < job->late_resolve_count; i++) {
        log_message(1, LOG_COLOR_BOLD_YELLOW"late-populating "LOG_COLOR_RESET": ");
        int rc = schema_populate_add_leaf(job, job->late_resolve_instance[i], job->late_resolve_schema[i], job->late_resolve_parent_o[i], job->late_resolve_parent_r[i]);
        if(rc != NTS_ERR_OK) {
            log_error("schema_populate_add_leaf failed on late-resolve");
            return rc;
        }
    }
    job->late_resolving = false;

    return NTS_ERR_OK;
}

static int schema_populate_validate(populate_instance_t *instance, int count) {
    assert_session();
    assert(instance);

    int rc = 0;
    int commit_ok = NTS_ERR_OK;

    for(int i = 0; i < count; i++) {
        if(instance[i].operational) {
            log_message(2, "available modules:");
            for(int j = 0; j < instance[i].mod_count; j++) {
                log_message(2, " %s", instance[i].modules[j]->name);
            }
            log_message(2, "\n");
            log_message(1, "validating OPERATIONAL for [%d] : %s... ", i, instance[i].xpath);

            int solved_instance_errors = 1;
            int solved_errors = 0;
            bool success = false;
            while(instance[i].operational && solved_instance_errors) {
                solved_instance_errors = 0;
                rc = lyd_validate_modules(&instance[i].operational, instance[i].modules, instance[i].mod_count, LYD_OPT_DATA, 0);
                if(rc == 0) {
                    log_message(1, LOG_COLOR_BOLD_GREEN"success (%d)\n"LOG_COLOR_RESET, solved_errors);
                    success = true;
                    break;
                }
                else {
                    log_message(2, "\n");

                    struct ly_err_item *err = ly_err_first(session_context);
                    while(err) {
                        if((err->vecode == LYVE_NOWHEN) || (err->vecode == LYVE_NOMUST) || (err->vecode == LYVE_NOCONSTR) || (err->vecode == LYVE_NOLEAFREF) || (err->vecode == LYVE_NOMIN) || (err->vecode == LYVE_INVAL)) {
                            struct ly_set *set = lyd_find_path(instance[i].operational, err->path);
                            if(set && set->number) {
                                log_message(2, "operational error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                                log_message(2, LOG_COLOR_BOLD_RED"  [WHEN-DELETE O]"LOG_COLOR_RESET" %s ... ", err->path);

                                bool mandatory = false;
                                if((set->set.d[0]->schema->flags & LYS_MAND_TRUE) != 0) {
                                    mandatory = true;
                                }

                                if((set->set.d[0]->schema->parent) && (set->set.d[0]->schema->parent->nodetype == LYS_CASE)) {
                                    if((set->set.d[0]->schema->parent->flags & LYS_MAND_TRUE) != 0) {
                                        mandatory = true;
                                    }
                                }

                                if((set->set.d[0]->dflt != 0) || (lys_is_key((const struct lys_node_leaf *)set->set.d[0]->schema, 0)) || (mandatory) || (err->vecode == LYVE_NOMIN)) {
                                    //delete whole parent
                                    log_message(2, "deleted parent : %s\n", lyd_path(set->set.d[0]->parent));
                                    struct lyd_node *p = set->set.d[0]->parent;
                                    lyd_free_withsiblings(set->set.d[0]);
                                    lyd_free(p);
                                    if(p == instance[i].operational) {
                                        log_message(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].operational = 0;
                                        break;
                                    }
                                }
                                else {
                                    //delete THIS node only
                                    lyd_free(set->set.d[0]);
                                    log_message(2, "deleted\n");
                                    if(set->set.d[0] == instance[i].operational) {
                                        log_message(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].operational = 0;
                                        break;
                                    }
                                }
                                solved_instance_errors++;

                                ly_set_free(set);
                            }
                        }
                        else if((err->vecode != 0) && (err->vecode != 29)) {
                            log_message(2, "operational error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                        }

                        err = err->next;
                    }
                    ly_err_clean(session_context, 0);
                }

                solved_errors += solved_instance_errors;
            }

            if(!success) {
                if(!solved_errors) {
                    log_message(1, LOG_COLOR_BOLD_YELLOW"failed"LOG_COLOR_RESET"\n%s\n", ly_errmsg(session_context));
                }
                else {
                    log_message(1, LOG_COLOR_BOLD_YELLOW"partially solved (%d)"LOG_COLOR_RESET"\n", solved_errors);
                }
            }
        }

        if(instance[i].running) {
            log_message(1, "validating RUNNING... for [%d] : %s... ", i, instance[i].xpath);

            int solved_instance_errors = 1;
            int solved_errors = 0;
            bool success = false;
            while(instance[i].running && solved_instance_errors) {
                solved_instance_errors = 0;
                rc = lyd_validate_modules(&instance[i].running, instance[i].modules, instance[i].mod_count, LYD_OPT_CONFIG, 0);
                if(rc == 0) {
                    log_message(1, LOG_COLOR_BOLD_GREEN"success (%d)\n"LOG_COLOR_RESET, solved_errors);
                    success = true;
                    break;
                }
                else {
                    log_message(2, "\n");

                    struct ly_err_item *err = ly_err_first(session_context);
                    while(err) {
                        if((err->vecode == LYVE_NOWHEN) || (err->vecode == LYVE_NOMUST) || (err->vecode == LYVE_NOCONSTR) || (err->vecode == LYVE_NOLEAFREF) || (err->vecode == LYVE_NOMIN) || (err->vecode == LYVE_INVAL)) {
                            struct ly_set *set = lyd_find_path(instance[i].running, err->path);
                            if(set && set->number) {
                                log_message(2, "running error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                                log_message(2, LOG_COLOR_BOLD_RED"  [WHEN-DELETE R]"LOG_COLOR_RESET" %s ... ", err->path);

                                bool mandatory = false;
                                if((set->set.d[0]->schema->flags & LYS_MAND_TRUE) != 0) {
                                    mandatory = true;
                                }

                                if((set->set.d[0]->schema->parent) && (set->set.d[0]->schema->parent->nodetype == LYS_CASE)) {
                                    if((set->set.d[0]->schema->parent->flags & LYS_MAND_TRUE) != 0) {
                                        mandatory = true;
                                    }
                                }

                                if((set->set.d[0]->dflt != 0) || (lys_is_key((const struct lys_node_leaf *)set->set.d[0]->schema, 0)) || (mandatory) || (err->vecode == LYVE_NOMIN))  {
                                    //delete whole parent
                                    log_message(2, "deleted parent : %s\n", lyd_path(set->set.d[0]->parent));
                                    struct lyd_node *p = set->set.d[0]->parent;
                                    lyd_free_withsiblings(set->set.d[0]);
                                    lyd_free(p);

                                    if(p == instance[i].running) {
                                        log_message(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].running = 0;
                                        break;
                                    }
                                }
                                else {
                                    //delete THIS node only
                                    lyd_free(set->set.d[0]);
                                    log_message(2, "deleted\n");
                                    if(set->set.d[0] == instance[i].running) {
                                        log_message(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].running = 0;
                                        break;
                                    }
                                }
                                solved_instance_errors++;

                                ly_set_free(set);
                            }
                        }
                        else if((err->vecode != 0) && (err->vecode != 29)) {
                            log_message(2, "running error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                        }

                        err = err->next;
                    }
                    ly_err_clean(session_context, 0);
                }

                solved_errors += solved_instance_errors;
            }

            if(!success) {
                if(!solved_errors) {
                    log_message(1, LOG_COLOR_BOLD_YELLOW"failed"LOG_COLOR_RESET"\n%s\n", ly_errmsg(session_context));
                }
                else {
                    log_message(1, LOG_COLOR_BOLD_YELLOW"partially solved (%d)"LOG_COLOR_RESET"\n", solved_errors);
                }
            }
        }
    }

    return commit_ok;
}

static int schema_populate_commit_to_datastore(populate_job_t *job) {
    assert_session();
    assert(job);

    int rc = 0;
    int commit_ok = 0;

    if(job->operational) {
        rc = SR_ERR_OK;
        log_message(1, "editing batch for OPERATIONAL... ");
        rc = sr_edit_batch(session_operational, job->operational, "merge");
        if (rc != SR_ERR_OK) {
            log_message(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            commit_ok = NTS_ERR_FAILED;
        }
        else {
            log_message(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }

        rc = SR_ERR_OK;
        log_message(1, "appling changes to OPERATIONAL... ");
        rc = sr_apply_changes(session_operational, 0, 0);
        if (rc != SR_ERR_OK) {
            sr_discard_changes(session_operational);
            commit_ok = NTS_ERR_FAILED;
            log_message(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
        }
        else {
            log_message(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }
    }

    if(job->running) {
        // or you can do it like this, but will replace the WHOLE datastore
        // rc = SR_ERR_OK;
        // log_message(1, "editing batch for RUNNING...");
        // rc = sr_replace_config(session_running, 0, job->running, 0, 0);
        // if (rc != SR_ERR_OK) {
        //     log_message(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
        //     commit_ok = NTS_ERR_FAILED;
        // }
        // else {
        //     log_message(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        // }

        rc = SR_ERR_OK;
        log_message(1, "editing batch for RUNNING...");
        rc = sr_edit_batch(session_running, job->running, "merge");
        if (rc != SR_ERR_OK) {
            log_message(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
            commit_ok = NTS_ERR_FAILED;
        }
        else {
            log_message(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }

        rc = SR_ERR_OK;
        log_message(1, "appling changes to RUNNING... ");
        rc = sr_apply_changes(session_running, 0, 0);
        if (rc != SR_ERR_OK) {
            sr_discard_changes(session_running);
            commit_ok = NTS_ERR_FAILED;
            log_message(1, LOG_COLOR_BOLD_RED"failed\n"LOG_COLOR_RESET);
        }
        else {
            log_message(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);
        }
    }

    return commit_ok;
}
