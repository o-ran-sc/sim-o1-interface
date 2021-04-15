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

#include "faults.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "core/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <cjson/cJSON.h>

static char *fault_process_vars(const char *template, const fault_details_t *details);
static char *fault_process_function(const char *function);

fault_settings_t *faults_settings_read(const char *json_plain) {
    if(json_plain == 0) {
        return 0;
    }

    fault_settings_t *ret = (fault_settings_t *)malloc(sizeof(fault_settings_t));
    if(ret == 0) {
        log_error("malloc failed\n");
        goto faults_settings_read_failed_cleanup;
    }

    ret->yang_notif_template = 0;
    ret->choosing_method = 0;
    ret->fault = 0;
    ret->fault_count = 0;

    cJSON *json = cJSON_Parse(json_plain);
    if(!json) {
        log_error("json parsing error: %s\n", cJSON_GetErrorPtr());
        goto faults_settings_read_failed_cleanup;
    }

    cJSON *main_node = cJSON_GetObjectItem(json, "fault-rules");
    if(main_node == 0) {
        goto faults_settings_read_failed_cleanup;
    }

    cJSON *node = cJSON_GetObjectItem(main_node, "yang-notif-template");
    if(node && cJSON_IsString(node)) {
        ret->yang_notif_template = strdup(node->valuestring);
    }
    else {
        log_error("could not find yang-notif-template\n");
        goto faults_settings_read_failed_cleanup;
    }

    node = cJSON_GetObjectItem(main_node, "choosing-method");
    if(node && cJSON_IsString(node)) {
        ret->choosing_method = strdup(node->valuestring);
    }
    else {
        log_error("could not find choosing-method\n");
        goto faults_settings_read_failed_cleanup;
    }

    node = cJSON_GetObjectItem(main_node, "faults");
    if(node && cJSON_IsArray(node)) {
        cJSON *fault_detail;
        cJSON_ArrayForEach(fault_detail, node) {
            cJSON *object;
            ret->fault_count++;
            ret->fault = (fault_details_t *)realloc(ret->fault, sizeof(fault_details_t)*ret->fault_count);
            if(ret->fault == 0) {
                ret->fault_count--;
                log_error("realloc failed\n");
                goto faults_settings_read_failed_cleanup;
            }

            ret->fault[ret->fault_count - 1].condition = 0;
            ret->fault[ret->fault_count - 1].object = 0;
            ret->fault[ret->fault_count - 1].severity = 0;
            ret->fault[ret->fault_count - 1].date_time = 0;
            ret->fault[ret->fault_count - 1].specific_problem = 0;
            ret->fault[ret->fault_count - 1].field_name = 0;
            ret->fault[ret->fault_count - 1].field_value = 0;
            ret->fault[ret->fault_count - 1].field_count = 0;
            ret->fault[ret->fault_count - 1].yang_notif_processed = 0;

            cJSON_ArrayForEach(object, fault_detail) {
                ret->fault[ret->fault_count - 1].field_count++;
                ret->fault[ret->fault_count - 1].field_name = (char **)realloc(ret->fault[ret->fault_count - 1].field_name, sizeof(char*) * ret->fault[ret->fault_count - 1].field_count);
                if(ret->fault[ret->fault_count - 1].field_name == 0) {
                    ret->fault[ret->fault_count - 1].field_count--;
                    log_error("realloc failed\n");
                    goto faults_settings_read_failed_cleanup;
                }

                ret->fault[ret->fault_count - 1].field_value = (char **)realloc(ret->fault[ret->fault_count - 1].field_value, sizeof(char*) * ret->fault[ret->fault_count - 1].field_count);
                if(ret->fault[ret->fault_count - 1].field_value == 0) {
                    ret->fault[ret->fault_count - 1].field_count--;
                    log_error("realloc failed\n");
                    goto faults_settings_read_failed_cleanup;
                }

                asprintf(&ret->fault[ret->fault_count - 1].field_name[ret->fault[ret->fault_count - 1].field_count - 1], "%%%%%s%%%%", object->string);
                ret->fault[ret->fault_count - 1].field_value[ret->fault[ret->fault_count - 1].field_count - 1] = strdup(object->valuestring);
            }
        }
    }
    else {
        log_error("could not find faults list\n");
        goto faults_settings_read_failed_cleanup;
    }

    cJSON_Delete(json);
    return ret;

    faults_settings_read_failed_cleanup:
    faults_settings_free(ret);
    cJSON_Delete(json);
    return 0;
}

void faults_settings_free(fault_settings_t *faults) {
    if(faults) {
        free(faults->yang_notif_template);
        free(faults->choosing_method);

        for(int i = 0; i < faults->fault_count; i++) {
            free(faults->fault[i].condition);
            free(faults->fault[i].object);
            free(faults->fault[i].severity);
            free(faults->fault[i].date_time);
            free(faults->fault[i].specific_problem);

            for(int j = 0; j < faults->fault[i].field_count; j++) {
                free(faults->fault[i].field_name[j]);
                free(faults->fault[i].field_value[j]);
            }
            free(faults->fault[i].field_name);
            free(faults->fault[i].field_value);

            free(faults->fault[i].yang_notif_processed);
        }
    }
}

int faults_settings_process(fault_settings_t *faults, int fault_no) {
    assert(faults);
    assert(fault_no < faults->fault_count);

    free(faults->fault[fault_no].condition);
    free(faults->fault[fault_no].object);
    free(faults->fault[fault_no].severity);
    free(faults->fault[fault_no].date_time);
    free(faults->fault[fault_no].specific_problem);
    free(faults->fault[fault_no].yang_notif_processed);

    faults->fault[fault_no].condition = 0;
    faults->fault[fault_no].object = 0;
    faults->fault[fault_no].severity = 0;
    faults->fault[fault_no].date_time = 0;
    faults->fault[fault_no].specific_problem = 0;
    faults->fault[fault_no].yang_notif_processed = 0;
    
    for(int j = 0; j < faults->fault[fault_no].field_count; j++) {
        if(strcmp(faults->fault[fault_no].field_name[j], "%%condition%%") == 0) {
            faults->fault[fault_no].condition = fault_process_vars(faults->fault[fault_no].field_value[j], &faults->fault[fault_no]);
        }
        else if(strcmp(faults->fault[fault_no].field_name[j], "%%object%%") == 0) {
            faults->fault[fault_no].object = fault_process_vars(faults->fault[fault_no].field_value[j], &faults->fault[fault_no]);
        }
        else if(strcmp(faults->fault[fault_no].field_name[j], "%%severity%%") == 0) {
            faults->fault[fault_no].severity = fault_process_vars(faults->fault[fault_no].field_value[j], &faults->fault[fault_no]);
        }
        else if(strcmp(faults->fault[fault_no].field_name[j], "%%date-time%%") == 0) {
            faults->fault[fault_no].date_time = fault_process_vars(faults->fault[fault_no].field_value[j], &faults->fault[fault_no]);
        }
        else if(strcmp(faults->fault[fault_no].field_name[j], "%%specific-problem%%") == 0) {
            faults->fault[fault_no].specific_problem = fault_process_vars(faults->fault[fault_no].field_value[j], &faults->fault[fault_no]);
        }
    }

    faults->fault[fault_no].yang_notif_processed = fault_process_vars(faults->yang_notif_template, &faults->fault[fault_no]);

    if(faults->fault[fault_no].condition == 0) {
        log_error("could not find condition in fault\n");
        return NTS_ERR_FAILED;
    }

    if(faults->fault[fault_no].object == 0) {
        log_error("could not find object in fault\n");
        return NTS_ERR_FAILED;
    }

    if(faults->fault[fault_no].severity == 0) {
        log_error("could not find severity in fault\n");
        return NTS_ERR_FAILED;
    }

    if(faults->fault[fault_no].date_time == 0) {
        log_error("could not find date_time in fault\n");
        return NTS_ERR_FAILED;
    }

    if(faults->fault[fault_no].specific_problem == 0) {
        log_error("could not find specific_problem in fault\n");
        return NTS_ERR_FAILED;
    }

    if(faults->fault[fault_no].yang_notif_processed == 0) {
        log_error("could not find yang_notif_processed in fault\n");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static char *fault_process_vars(const char *template, const fault_details_t *details) {
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
                goto fault_process_vars_failed;
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
                goto fault_process_vars_failed;
            }

            vars[vars_count - 1] = strdup(var);
            if(!vars[vars_count - 1]) {
                vars_count--;
                log_error("bad malloc\n");
                goto fault_process_vars_failed;
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
                goto fault_process_vars_failed;
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
                goto fault_process_vars_failed;
            }

            funcs[funcs_count - 1] = strdup(func);
            if(!funcs[funcs_count - 1]) {
                funcs_count--;
                log_error("bad malloc\n");
                goto fault_process_vars_failed;
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
                goto fault_process_vars_failed;
            }

            ret = str_replace(ret, vars[i], var_value);
            if(ret == 0) {
                free(var_value);
                var_value = 0;
                goto fault_process_vars_failed;
            }

            free(var_value);
            var_value = 0;
            replaced++;
        }

        //replace functions
        for(int i = 0; i < funcs_count; i++) {
            char *func_value = fault_process_function(funcs[i]);
            if(func_value == 0) {
                log_error("function %s not found\n", vars[i]);
                goto fault_process_vars_failed;
            }

            ret = str_replace(ret, funcs[i], func_value);
            if(ret == 0) {
                free(func_value);
                goto fault_process_vars_failed;
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

    fault_process_vars_failed:
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

static char *fault_process_function(const char *function) {
    assert(function);

    static uint8_t uint8_counter = 0;
    static uint16_t uint16_counter = 0;
    static uint32_t uint32_counter = 0;

    if(strcmp(function, "$$time$$") == 0) {
        return get_current_date_and_time();
    }
    else if(strcmp(function, "$$uint8_counter$$") == 0) {
        char *ret = 0;
        asprintf(&ret, "%d", uint8_counter);
        uint8_counter++;
        return ret;
    }
    else if(strcmp(function, "$$uint16_counter$$") == 0) {
        char *ret = 0;
        asprintf(&ret, "%d", uint16_counter);
        uint16_counter++;
        return ret;
    }
    else if(strcmp(function, "$$uint32_counter$$") == 0) {
        char *ret = 0;
        asprintf(&ret, "%d", uint32_counter);
        uint32_counter++;
        return ret;
    }
    else if(strcmp(function, "$$hostname$$") == 0) {
        char *ret = 0;
        asprintf(&ret, "%s", framework_environment.settings.hostname);
        return ret;
    }

    return 0;
}
