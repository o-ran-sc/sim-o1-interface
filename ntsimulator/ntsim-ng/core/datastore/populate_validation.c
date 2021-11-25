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
#define _GNU_SOURCE

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


int populate_validate(populate_instance_t *instance, int count) {
    assert(instance);

    int rc = 0;
    int commit_ok = NTS_ERR_OK;

    for(int i = 0; i < count; i++) {
        if(instance[i].operational) {
            log_add_verbose(2, "available modules:");
            for(int j = 0; j < instance[i].mod_count; j++) {
                log_add(2, " %s", instance[i].modules[j]->name);
            }
            log_add(2, "\n");
            log_add_verbose(1, "validating OPERATIONAL for [%d] : %s... ", i, instance[i].xpath);

            int solved_instance_errors = 1;
            int solved_errors = 0;
            bool success = false;
            while(instance[i].operational && solved_instance_errors) {
                solved_instance_errors = 0;
                rc = lyd_validate_modules(&instance[i].operational, instance[i].modules, instance[i].mod_count, LYD_OPT_DATA, 0);
                if(rc == 0) {
                    log_add(1, LOG_COLOR_BOLD_GREEN"success (%d)\n"LOG_COLOR_RESET, solved_errors);
                    success = true;
                    break;
                }
                else {
                    log_add(2, "\n");

                    struct ly_err_item *err = ly_err_first(session_context);
                    while(err) {
                        if((err->vecode == LYVE_NOWHEN) || (err->vecode == LYVE_NOMUST) || (err->vecode == LYVE_NOCONSTR) || (err->vecode == LYVE_NOLEAFREF) || (err->vecode == LYVE_NOMIN) || (err->vecode == LYVE_INVAL)) {
                            struct ly_set *set = lyd_find_path(instance[i].operational, err->path);
                            if(set && set->number) {
                                log_add_verbose(2, "operational error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                                log_add_verbose(2, LOG_COLOR_BOLD_RED"  [WHEN-DELETE O]"LOG_COLOR_RESET" %s ... ", err->path);

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
                                    log_add(2, "deleted parent : %s\n", lyd_path(set->set.d[0]->parent));
                                    struct lyd_node *p = set->set.d[0]->parent;
                                    lyd_free_withsiblings(set->set.d[0]);
                                    lyd_free(p);
                                    if(p == instance[i].operational) {
                                        log_add_verbose(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].operational = 0;
                                        break;
                                    }
                                }
                                else {
                                    //delete THIS node only
                                    lyd_free(set->set.d[0]);
                                    log_add(2, "deleted\n");
                                    if(set->set.d[0] == instance[i].operational) {
                                        log_add_verbose(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
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
                            log_add_verbose(2, "operational error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                        }

                        err = err->next;
                    }
                    ly_err_clean(session_context, 0);
                }

                solved_errors += solved_instance_errors;
            }

            if(!success) {
                if(!solved_errors) {
                    log_add(1, LOG_COLOR_BOLD_YELLOW"failed"LOG_COLOR_RESET"\n%s\n", ly_errmsg(session_context));
                }
                else {
                    log_add(1, LOG_COLOR_BOLD_YELLOW"partially solved (%d)"LOG_COLOR_RESET"\n", solved_errors);
                }
            }
        }

        if(instance[i].running) {
            log_add_verbose(1, "validating RUNNING... for [%d] : %s... ", i, instance[i].xpath);

            int solved_instance_errors = 1;
            int solved_errors = 0;
            bool success = false;
            while(instance[i].running && solved_instance_errors) {
                solved_instance_errors = 0;
                rc = lyd_validate_modules(&instance[i].running, instance[i].modules, instance[i].mod_count, LYD_OPT_CONFIG, 0);
                if(rc == 0) {
                    log_add(1, LOG_COLOR_BOLD_GREEN"success (%d)\n"LOG_COLOR_RESET, solved_errors);
                    success = true;
                    break;
                }
                else {
                    log_add(2, "\n");

                    struct ly_err_item *err = ly_err_first(session_context);
                    while(err) {
                        if((err->vecode == LYVE_NOWHEN) || (err->vecode == LYVE_NOMUST) || (err->vecode == LYVE_NOCONSTR) || (err->vecode == LYVE_NOLEAFREF) || (err->vecode == LYVE_NOMIN) || (err->vecode == LYVE_INVAL)) {
                            struct ly_set *set = lyd_find_path(instance[i].running, err->path);
                            if(set && set->number) {
                                log_add_verbose(2, "running error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                                log_add_verbose(2, LOG_COLOR_BOLD_RED"  [WHEN-DELETE R]"LOG_COLOR_RESET" %s ... ", err->path);

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
                                    log_add(2, "deleted parent : %s\n", lyd_path(set->set.d[0]->parent));
                                    struct lyd_node *p = set->set.d[0]->parent;
                                    lyd_free_withsiblings(set->set.d[0]);
                                    lyd_free(p);

                                    if(p == instance[i].running) {
                                        log_add_verbose(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
                                        success = true;
                                        instance[i].running = 0;
                                        break;
                                    }
                                }
                                else {
                                    //delete THIS node only
                                    lyd_free(set->set.d[0]);
                                    log_add(2, "deleted\n");
                                    if(set->set.d[0] == instance[i].running) {
                                        log_add_verbose(1, "instance became empty "LOG_COLOR_BOLD_GREEN"success\n"LOG_COLOR_RESET);
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
                            log_add_verbose(2, "running error code %d on path %s with msg %s\n", err->vecode, err->path, err->msg);
                        }

                        err = err->next;
                    }
                    ly_err_clean(session_context, 0);
                }

                solved_errors += solved_instance_errors;
            }

            if(!success) {
                if(!solved_errors) {
                    log_add(1, LOG_COLOR_BOLD_YELLOW"failed"LOG_COLOR_RESET"\n%s\n", ly_errmsg(session_context));
                }
                else {
                    log_add(1, LOG_COLOR_BOLD_YELLOW"partially solved (%d)"LOG_COLOR_RESET"\n", solved_errors);
                }
            }
        }
    }

    return commit_ok;
}
