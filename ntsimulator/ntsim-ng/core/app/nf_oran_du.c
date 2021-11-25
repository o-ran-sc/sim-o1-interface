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

#include "nf_oran_du.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/nts_utils.h"
#include "utils/rand_utils.h"
#include "utils/http_client.h"
#include <stdio.h>
#include <pthread.h>
#include <assert.h>

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <libnetconf2/netconf.h>

#include "core/framework.h"
#include "core/context.h"
#include "core/session.h"
#include "core/xpath.h"

typedef struct {
    char *id;
    uint32_t counter;
} subscription_stream_t;

static subscription_stream_t **subscription_streams;
static int subscription_streams_count;

static int subscription_streams_add(const char *id);
static int subscription_streams_free(const char *id);
static subscription_stream_t *subscription_streams_get(const char *id);
static int subscription_streams_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

typedef struct {
    pthread_t thread;
    sig_atomic_t wait;
    sig_atomic_t terminate;

    char *id;
    char *administrative_state;
    char *user_label;
    char *job_tag;
    uint32_t granularity_period;
    char **performance_metrics;
    int performance_metrics_count;
    char *stream_target;

    subscription_stream_t *stream;
} pm_job_t;

static pm_job_t **pm_jobs;
static int pm_jobs_count;


static int pm_jobs_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
static void *pm_job_thread_routine(void *arg);

typedef struct {
    //list of all fields, including ves mandatory
    char **field_name;
    char **field_value;
    int field_count;

    pm_job_t *job;
} nf_du_template_details_t;

static void nf_du_template_free(nf_du_template_details_t *details);
static char *nf_du_template_process_vars(const char *template, const nf_du_template_details_t *details);
static char *nf_du_template_process_function(const char *function, const nf_du_template_details_t *details);

static char *ves_template = 0;

int nf_oran_du_init(void) {
    log_add_verbose(1, LOG_COLOR_BOLD_MAGENTA"NTS_FUNCTION_TYPE_O_RAN_O_DU"LOG_COLOR_RESET " mode initializing...\n");

    pm_jobs = 0;
    pm_jobs_count = 0;

    subscription_streams = 0;
    subscription_streams_count = 0;

    ves_template = file_read_content("config/ves_template.json");
    if(ves_template == 0) {
        log_error("could not read config/ves_template.json");
        return NTS_ERR_FAILED;
    }

    //check whether everything is already populated, read and update (if previously ran)
    sr_val_t *values = 0;
    size_t value_count = 0;
    int rc = sr_get_items(session_running, NTS_NF_ORAN_DU_PM_JOBS_SCHEMA_XPATH, 0, 0, &values, &value_count);
    if(rc != SR_ERR_OK) {
        log_error("get items failed\n");
        return NTS_ERR_FAILED;
    }

    //delete everything
    if(value_count) {
        log_add_verbose(2, "pm jobs already found (%d). cleaning up for fresh start...\n", value_count);

        for(int i = 0; i < value_count; i++) {           
            rc = sr_delete_item(session_running, values[i].xpath, 0);
            if(rc != SR_ERR_OK) {
                log_error("sr_delete_item failed\n");
                return NTS_ERR_FAILED;
            }
        }
        rc = sr_apply_changes(session_running, 0, 0);
        if(rc != SR_ERR_OK) {
            log_error("sr_apply_changes failed\n");
            return NTS_ERR_FAILED;
        }

        sr_free_values(values, value_count);
    }

    //check subscription-streams
    rc = sr_get_items(session_running, NTS_NF_ORAN_DU_SUBSCRIPTION_STREAMS_SCHEMA_XPATH, 0, 0, &values, &value_count);
    if(rc != SR_ERR_OK) {
        log_error("get items failed\n");
        return NTS_ERR_FAILED;
    }

    if(value_count) {
        for(int i = 0; i < value_count; i++) {
            char *id = strdup(strstr(values[i].xpath, "[id='") + 5);
            *strstr(id, "'") = 0;

            rc = subscription_streams_add(id);
             if(rc != NTS_ERR_OK) {
                log_error("subscription_streams_add failed\n");
                return NTS_ERR_FAILED;
            }
            free(id);
        }

        sr_free_values(values, value_count);
    }

    log_add_verbose(1, "subscribing to changes on %s...\n", NTS_NF_ORAN_DU_SUBSCRIPTION_STREAMS_SCHEMA_XPATH);
    rc = sr_module_change_subscribe(session_running, NTS_NF_ORAN_DU_MODULE, NTS_NF_ORAN_DU_SUBSCRIPTION_STREAMS_SCHEMA_XPATH, subscription_streams_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to module changes: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    log_add_verbose(1, "subscribing to changes on %s...\n", NTS_NF_ORAN_DU_PM_JOBS_SCHEMA_XPATH);
    rc = sr_module_change_subscribe(session_running, NTS_NF_ORAN_DU_MODULE, NTS_NF_ORAN_DU_PM_JOBS_SCHEMA_XPATH, pm_jobs_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &session_subscription);
    if(rc != SR_ERR_OK) {
        log_error("could not subscribe to module changes: %s\n", sr_strerror(rc));
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

void nf_oran_du_free(void) {
    free(ves_template);
}

static int subscription_streams_add(const char *id) {
    assert(id);

    subscription_streams_count++;
    subscription_streams = (subscription_stream_t **)realloc(subscription_streams, sizeof(subscription_stream_t *) * (subscription_streams_count));
    if(subscription_streams == 0) {
        log_error("realloc failed\n");
        return NTS_ERR_FAILED;
    }

    subscription_streams[subscription_streams_count - 1] = (subscription_stream_t *)malloc(sizeof(subscription_stream_t));
    if(subscription_streams[subscription_streams_count - 1] == 0) {
        log_error("malloc failed\n");
        return NTS_ERR_FAILED;
    }
    subscription_streams[subscription_streams_count - 1]->id = strdup(id);
    if(subscription_streams[subscription_streams_count - 1]->id == 0) {
        log_error("strdup failed\n");
        return NTS_ERR_FAILED;
    }
    subscription_streams[subscription_streams_count - 1]->counter = 0;

    log_add_verbose(1, "added stream target %s\n", id); //checkAL

    return NTS_ERR_OK;
}

static int subscription_streams_free(const char *id) {
    assert(id);

    subscription_stream_t *found = 0;
    for(int i = 0; i < subscription_streams_count; i++) {
        if(strcmp(id, subscription_streams[i]->id) == 0) {
            found = subscription_streams[i];

            for(int j = i; j < subscription_streams_count - 1; j++) {
                subscription_streams[j] = subscription_streams[j + 1];
            }

            subscription_streams_count--;
            subscription_streams = (subscription_stream_t **)realloc(subscription_streams, sizeof(subscription_stream_t *) * (subscription_streams_count));
            if(subscription_streams_count && (subscription_streams == 0)) {
                log_error("realloc failed\n");
                return NTS_ERR_FAILED;
            }
            break;
        }
    }

    if(found == 0) {
        log_error("could not find subscription stream %s\n", id);
        return NTS_ERR_FAILED;
    }

    log_add_verbose(1, "removed stream target %s\n", id);    //checkAL

    free(found->id);
    free(found);

    return NTS_ERR_OK;
}

static subscription_stream_t *subscription_streams_get(const char *id) {
    assert(id);

    subscription_stream_t *found = 0;
    for(int i = 0; i < subscription_streams_count; i++) {
        if(strcmp(id, subscription_streams[i]->id) == 0) {
            found = subscription_streams[i];
            break;
        }
    }

    if(found == 0) {
        log_error("could not find subscription stream %s\n", id);
    }
    return found;
}

static int subscription_streams_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    sr_change_iter_t *it = 0;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = 0;
    sr_val_t *new_value = 0;

    if(event == SR_EV_CHANGE) {
        rc = sr_get_changes_iter(session, NTS_NF_ORAN_DU_SUBSCRIPTION_STREAMS_SCHEMA_XPATH"/id", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed\n");
            return SR_ERR_VALIDATION_FAILED;
        }

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            if(oper == SR_OP_CREATED) {
                if(subscription_streams_add(new_value->data.string_val) != NTS_ERR_OK) {
                    log_error("could not create subscription stream\n");
                    return SR_ERR_OPERATION_FAILED;
                }
            }
            else if(oper == SR_OP_DELETED) {
                if(subscription_streams_free(old_value->data.string_val) != NTS_ERR_OK) {
                    log_error("could not delete subscription stream\n");
                    return SR_ERR_OPERATION_FAILED;
                }
            }

            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);
    }

    return SR_ERR_OK;
}



static int pm_jobs_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data) {
    sr_change_iter_t *it = 0;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = 0;
    sr_val_t *new_value = 0;

    if(event == SR_EV_CHANGE) {
        rc = sr_get_changes_iter(session, NTS_NF_ORAN_DU_PM_JOBS_SCHEMA_XPATH"/id", &it);
        if(rc != SR_ERR_OK) {
            log_error("sr_get_changes_iter failed\n");
            return SR_ERR_VALIDATION_FAILED;
        }

        while((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            if(oper == SR_OP_CREATED) {
                pm_job_t *job = (pm_job_t *)malloc(sizeof(pm_job_t));
                if(job == 0) {
                    log_error("bad realloc\n");
                    return SR_ERR_OPERATION_FAILED;
                }

                pm_jobs_count++;
                pm_jobs = (pm_job_t **)realloc(pm_jobs, sizeof(pm_job_t *) * pm_jobs_count);
                if(pm_jobs == 0) {
                    log_error("bad realloc\n");
                    return SR_ERR_OPERATION_FAILED;
                }

                pm_jobs[pm_jobs_count - 1] = job;

                job->id = strdup(new_value->data.string_val);
                job->wait = 1; //thread will wait on this flag until 0 in the begining to make sure it has data
                job->terminate = 0;

                if(pthread_create(&job->thread, 0, pm_job_thread_routine, job)) {
                    log_error("could not create thread for pm job\n");
                    return SR_ERR_OPERATION_FAILED;
                }
            }
            else if(oper == SR_OP_DELETED) {
                int job_id = -1; 
                for(int i = 0; i < pm_jobs_count; i++) {
                    if(strcmp(pm_jobs[i]->id, old_value->data.string_val) == 0) {
                        job_id = i;
                        break;
                    }
                }
                if(job_id == -1) {
                    log_error("could not find corresponding job\n");
                    return SR_ERR_OPERATION_FAILED;
                }

                pm_job_t *job = pm_jobs[job_id];
                job->terminate = 1;
                
                //remove from list
                for(int i = job_id; i < pm_jobs_count - 1; i++) {
                    pm_jobs[i] = pm_jobs[i + 1];
                }

                pm_jobs_count--;
                pm_jobs = (pm_job_t **)realloc(pm_jobs, sizeof(pm_job_t *) * pm_jobs_count);
                if(pm_jobs_count && (pm_jobs == 0)) {
                    log_error("bad realloc\n");
                    return SR_ERR_OPERATION_FAILED;
                }
            }

            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);
    }
    else if(event == SR_EV_DONE) {
        for(int i = 0; i < pm_jobs_count; i++) {
            pm_jobs[i]->wait = 0;
        }
    }

    return SR_ERR_OK;
}

static void *pm_job_thread_routine(void *arg) {
    pm_job_t *job = (pm_job_t *)arg;

    job->administrative_state = strdup("");
    job->user_label = strdup("");
    job->job_tag = strdup("");
    job->granularity_period = 1;
    job->performance_metrics = 0;
    job->performance_metrics_count = 0;
    job->stream_target = strdup("");

    log_add_verbose(1, "pm_job_thread_routine started for job id %s\n", job->id);
    while(job->wait) {
        sleep(1);
    }
    log_add_verbose(1, "pm_job_thread_routine[%s] finished waiting...\n", job->id);
    
    char *xpath_to_get = 0;
    asprintf(&xpath_to_get, "%s[id='%s']", NTS_NF_ORAN_DU_PM_JOBS_SCHEMA_XPATH, job->id);
    if(xpath_to_get == 0) {
        log_error("pm_job_thread_routine[%s] asprintf failed\n", job->id);
        return (void*)NTS_ERR_FAILED;
    }

    int rc;
    sr_session_ctx_t *current_session;
    rc = sr_session_start(session_connection, SR_DS_RUNNING, &current_session);
    if(rc != SR_ERR_OK) {
        log_error("pm_job_thread_routine[%s] could not start sysrepo session\n", job->id);
        return (void*)NTS_ERR_FAILED;
    }

    struct lyd_node *data = 0;
    rc = sr_get_subtree(current_session, xpath_to_get, 0, &data);
    free(xpath_to_get);
    if(rc != SR_ERR_OK) {
        log_error("pm_job_thread_routine[%s] could not get value for xPath=%s from the running datastore\n", job->id, xpath_to_get);
        sr_session_stop(current_session);
        return (void*)NTS_ERR_FAILED;
    }

    struct lyd_node *chd = 0;
    LY_TREE_FOR(data->child, chd) {
        if(strcmp(chd->schema->name, "administrative-state") == 0) {
            const char *val = ((const struct lyd_node_leaf_list *)chd)->value_str;
            free(job->administrative_state);
            job->administrative_state = strdup(val);
            if(job->administrative_state == 0) {
                log_error("pm_job_thread_routine[%s] strdup failed\n", job->id);
                sr_session_stop(current_session);
                return (void*)NTS_ERR_FAILED;
            }
        }

        if(strcmp(chd->schema->name, "user-label") == 0) {
            const char *val = ((const struct lyd_node_leaf_list *)chd)->value_str;
            free(job->user_label);
            job->user_label = strdup(val);
            if(job->user_label == 0) {
                log_error("pm_job_thread_routine[%s] strdup failed\n", job->id);
                sr_session_stop(current_session);
                return (void*)NTS_ERR_FAILED;
            }
        }

        if(strcmp(chd->schema->name, "job-tag") == 0) {
            const char *val = ((const struct lyd_node_leaf_list *)chd)->value_str;
            free(job->job_tag);
            job->job_tag = strdup(val);
            if(job->job_tag == 0) {
                log_error("pm_job_thread_routine[%s] strdup failed\n", job->id);
                sr_session_stop(current_session);
                return (void*)NTS_ERR_FAILED;
            }
        }

        if(strcmp(chd->schema->name, "granularity-period") == 0) {
            job->granularity_period = ((const struct lyd_node_leaf_list *)chd)->value.uint32;
        }

        if(strcmp(chd->schema->name, "performance-metrics") == 0) {
            const char *val = ((const struct lyd_node_leaf_list *)chd)->value_str;
            
            job->performance_metrics_count++;
            job->performance_metrics = (char **)realloc(job->performance_metrics, sizeof(char **) * job->performance_metrics_count);
            if(job->performance_metrics == 0) {
                log_error("pm_job_thread_routine[%s] realloc failed\n", job->id);
                sr_session_stop(current_session);
                return (void*)NTS_ERR_FAILED;
            }
            job->performance_metrics[job->performance_metrics_count - 1] = strdup(val);
            if(job->performance_metrics[job->performance_metrics_count - 1] == 0) {
                log_error("pm_job_thread_routine[%s] strdup failed\n", job->id);
                sr_session_stop(current_session);
                return (void*)NTS_ERR_FAILED;
            }
        }

        if(strcmp(chd->schema->name, "stream-target") == 0) {
            const char *val = ((const struct lyd_node_leaf_list *)chd)->value_str;
            free(job->stream_target);
            job->stream_target = strdup(val);
            if(job->stream_target == 0) {
                log_error("pm_job_thread_routine[%s] strdup failed\n", job->id);
                sr_session_stop(current_session);
                return (void*)NTS_ERR_FAILED;
            }

            job->stream = subscription_streams_get(job->stream_target);
            if(job->stream == 0) {
                log_error("subscription_streams_get error")
                return 0;
            }
        }
    }

    if(job->granularity_period == 0) {
        job->granularity_period = 1;
    }

    //get ves details
    char *ves_details_xpath;
    asprintf(&ves_details_xpath, "%s[id='%s']", NTS_NF_ORAN_DU_SUBSCRIPTION_STREAMS_SCHEMA_XPATH, job->stream_target);
    if(ves_details_xpath == 0) {
        log_error("pm_job_thread_routine[%s] asprintf failed\n", job->id);
        sr_session_stop(current_session);
        return (void*)NTS_ERR_FAILED;
    }

    ves_details_t *ves_details = ves_endpoint_details_get(current_session, ves_details_xpath);
    free(ves_details_xpath);
    if(ves_details == 0) {
        log_error("pm_job_thread_routine[%s] ves_endpoint_details_get failed\n", job->id);
        sr_session_stop(current_session);
        return (void*)NTS_ERR_FAILED;
    }

    sr_session_stop(current_session);

    nf_du_template_details_t details;
    details.job = job;
    details.field_count = 8;
    details.field_name = (char **)malloc(sizeof(char *) * details.field_count);
    details.field_value = (char **)malloc(sizeof(char *) * details.field_count);

    details.field_name[0] = strdup("%%administrative-state%%");
    details.field_value[0] = strdup(job->administrative_state);
    details.field_name[1] = strdup("%%user-label%%");
    details.field_value[1] = strdup(job->user_label);
    details.field_name[2] = strdup("%%job-tag%%");
    details.field_value[2] = strdup(job->job_tag);
    details.field_name[3] = strdup("%%granularity-period%%");
    asprintf(&details.field_value[3], "%d", job->granularity_period);
    details.field_name[4] = strdup("%%job-id%%");
    details.field_value[4] = strdup(job->id);
    
    long int now = get_microseconds_since_epoch() / 1000000;
    long int start_time = now - (now % job->granularity_period);
    long int end_time = start_time + job->granularity_period;
    int granularity_period = end_time - now;

    details.field_name[5] = strdup("%%starttime%%");
    asprintf(&details.field_value[5], "%lu", now);  //first intervall is probably less than granularity-period
    details.field_name[6] = strdup("%%endtime%%");
    asprintf(&details.field_value[6], "%lu", end_time);

    details.field_name[7] = strdup("%%starttime-literal%%");
    
    struct tm tm = *localtime(&now);
    asprintf(&details.field_value[7], "%04d-%02d-%02dT%02d:%02d:%02d.%01dZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, 0);

    while(job->terminate == 0) {
        sleep(granularity_period);

        char *content = nf_du_template_process_vars(ves_template, &details);
        if(content == 0) {
            log_error("nf_du_template_process_vars failed\n");
            return (void*)NTS_ERR_FAILED;
        }

        rc = http_request(ves_details->url, ves_details->username, ves_details->password, "POST", content, 0, 0);
        if(rc != NTS_ERR_OK) {
            log_error("pm_job_thread_routine[%s] http_request failed\n", job->id);
        }

        free(content);


        start_time = end_time;
        end_time = start_time + job->granularity_period;
        granularity_period = job->granularity_period;

        free(details.field_value[5]);
        free(details.field_value[6]);
        free(details.field_value[7]);
        asprintf(&details.field_value[5], "%lu", start_time);
        asprintf(&details.field_value[6], "%lu", end_time);
        struct tm tm = *localtime(&start_time);
        asprintf(&details.field_value[7], "%04d-%02d-%02dT%02d:%02d:%02d.%01dZ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, 0);
    }

    log_add_verbose(1, "pm_job_thread_routine[%s] ending...\n", job->id);

    nf_du_template_free(&details);
    free(ves_details);
    free(job->id);
    free(job->administrative_state);
    free(job->user_label);
    free(job->job_tag);
    for(int i = 0; i < job->performance_metrics_count; i++) {
        free(job->performance_metrics[i]);
    }
    free(job->performance_metrics);
    free(job->stream_target);
    free(job);

    return (void*)NTS_ERR_OK;
}

static void nf_du_template_free(nf_du_template_details_t *details) {
    assert(details);
    
    for(int j = 0; j < details->field_count; j++) {
        free(details->field_name[j]);
        free(details->field_value[j]);
    }

    free(details->field_name);
    free(details->field_value);
}

static char *nf_du_template_process_vars(const char *template, const nf_du_template_details_t *details) {
    assert(template);
    assert(details);

    char *ret = strdup(template);
    if(ret == 0) {
        log_error("strdup error\n");
        return 0;
    }

    //if template is blank, do not process anything, means nc notif disabled
    if(ret[0] == 0) {
        return ret;
    }

    char **vars = 0;
    int vars_count = 0;
    
    char **funcs = 0;
    int funcs_count = 0;

    char *var = 0;
    char *func = 0;

    //do replacements until no replacement is done
    int replaced = 1;
    while(replaced) {
        replaced = 0;

        var = 0;
        vars = 0;
        vars_count = 0;
        func = 0;
        funcs = 0;
        funcs_count = 0;

        char *pos_start;

        //look for vars
        pos_start = strstr(ret, "%%");
        while(pos_start) {
            char *pos_end = strstr(pos_start + 2, "%%");
            int var_size = pos_end - pos_start + 2;
            var = (char *)malloc(sizeof(char) * (var_size + 1));
            if(var == 0) {
                log_error("bad malloc\n");
                goto nf_du_template_process_vars_failed;
            }

            for(int i = 0; i < var_size; i++) {
                var[i] = pos_start[i];
            }
            var[var_size] = 0;

            // found var
            vars_count++;
            vars = (char **)realloc(vars, sizeof(char *) * vars_count);
            if(!vars) {
                vars_count = 0;
                log_error("bad malloc\n");
                goto nf_du_template_process_vars_failed;
            }

            vars[vars_count - 1] = strdup(var);
            if(!vars[vars_count - 1]) {
                vars_count--;
                log_error("bad malloc\n");
                goto nf_du_template_process_vars_failed;
            }
            free(var);
            var = 0;

            pos_start = strstr(pos_end + 2, "%%");
        }

        //look for functions
        pos_start = strstr(ret, "$$");
        while(pos_start) {
            char *pos_end = strstr(pos_start + 2, "$$");
            int func_size = pos_end - pos_start + 2;
            func = (char *)malloc(sizeof(char) * (func_size + 1));
            if(func == 0) {
                log_error("bad malloc\n");
                goto nf_du_template_process_vars_failed;
            }

            for(int i = 0; i < func_size; i++) {
                func[i] = pos_start[i];
            }
            func[func_size] = 0;

            // found func
            funcs_count++;
            funcs = (char **)realloc(funcs, sizeof(char *) * funcs_count);
            if(!funcs) {
                funcs_count = 0;
                log_error("bad malloc\n");
                goto nf_du_template_process_vars_failed;
            }

            funcs[funcs_count - 1] = strdup(func);
            if(!funcs[funcs_count - 1]) {
                funcs_count--;
                log_error("bad malloc\n");
                goto nf_du_template_process_vars_failed;
            }
            free(func);
            func = 0;

            pos_start = strstr(pos_end + 2, "$$");
        }

        //replace vars
        for(int i = 0; i < vars_count; i++) {
            char *var_value = 0;
            for(int j = 0; j < details->field_count; j++) {
                if(strcmp(details->field_name[j], vars[i]) == 0) {
                    var_value = strdup(details->field_value[j]);
                }
            }

            if(var_value == 0) {
                log_error("value %s not found\n", vars[i]);
                goto nf_du_template_process_vars_failed;
            }

            ret = str_replace(ret, vars[i], var_value);
            if(ret == 0) {
                free(var_value);
                var_value = 0;
                goto nf_du_template_process_vars_failed;
            }

            free(var_value);
            var_value = 0;
            replaced++;
        }

        //replace functions
        for(int i = 0; i < funcs_count; i++) {
            char *func_value = nf_du_template_process_function(funcs[i], details);
            if(func_value == 0) {
                log_error("function %s not found\n", vars[i]);
                goto nf_du_template_process_vars_failed;
            }

            ret = str_replace(ret, funcs[i], func_value);
            if(ret == 0) {
                free(func_value);
                goto nf_du_template_process_vars_failed;
            }

            free(func_value);
            func_value = 0;
            replaced++;
        }

        for(int i = 0; i < vars_count; i++) {
            free(vars[i]);
        }
        free(vars);
        vars = 0;
        vars_count = 0;

        for(int i = 0; i < funcs_count; i++) {
            free(funcs[i]);
        }
        free(funcs);
        funcs = 0;
        funcs_count = 0;
    }


    free(var);
    free(func);
    for(int i = 0; i < vars_count; i++) {
        free(vars[i]);
    }
    free(vars);

    for(int i = 0; i < funcs_count; i++) {
        free(funcs[i]);
    }
    free(funcs);
    return ret;

nf_du_template_process_vars_failed:
    free(var);
    free(func);

    for(int i = 0; i < vars_count; i++) {
        free(vars[i]);
    }
    free(vars);

    for(int i = 0; i < funcs_count; i++) {
        free(funcs[i]);
    }
    free(funcs);
    return 0;
}

static char *nf_du_template_process_function(const char *function, const nf_du_template_details_t *details) {
    assert(function);
    assert(details);

    const char *measurement_template = "{\"measurement-type-instance-reference\": \"%%instance_ref%%\",\"value\": $$uint16_rand$$,\"unit\": \"kbit/s\"}\n";

    if(strcmp(function, "$$du_ves_measurements$$") == 0) {
        char *ret = strdup("");

        for(int i = 0; i < details->job->performance_metrics_count; i++) {
            char *ci = str_replace(measurement_template, "%%instance_ref%%", details->job->performance_metrics[i]);
            if(ci == 0) {
                log_error("str_replace failed\n");
                return 0;
            }
            
            int nl = strlen(ci) + 2;   //\0 and perhaps comma
            char *ret2 = (char *)malloc(sizeof(char) * (strlen(ret) + nl));
            if(ret2 == 0) {
                log_error("malloc failed\n");
                return 0;
            }
            strcpy(ret2, ret);
            free(ret);

            strcat(ret2, ci);
            free(ci);

            if(i < (details->job->performance_metrics_count - 1)) {
                strcat(ret2, ",");
            }

            ret = ret2;
        }

        return ret;
    }
    else if(strcmp(function, "$$uint16_rand$$") == 0) {
        char *ret = 0;
        asprintf(&ret, "%d", rand_uint16());
        return ret;
    }
    else if(strcmp(function, "$$uint32_counter$$") == 0) {
        char *ret = 0;
        
        asprintf(&ret, "%d", details->job->stream->counter);
        details->job->stream->counter++;
        return ret;
    }
    else if(strcmp(function, "$$hostname$$") == 0) {
        char *ret = 0;
        asprintf(&ret, "%s", framework_environment.settings.hostname);
        return ret;
    }

    return 0;
}
