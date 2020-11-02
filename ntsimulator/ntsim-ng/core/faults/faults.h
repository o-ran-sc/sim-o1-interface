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
#include <stdint.h>
#include <sysrepo.h>

typedef struct {
    //list of all fields, including ves mandatory
    char **field_name;
    char **field_value;
    int field_count;

    //mandatory ves fields
    char *condition;
    char *object;
    char *severity;
    char *date_time;
    char *specific_problem;

    //output data
    char *yang_notif_processed;
} fault_details_t;

typedef struct {
    char *yang_notif_template;
    char *choosing_method;

    fault_details_t *fault;
    int fault_count;
} fault_settings_t;

typedef struct {
    uint32_t normal;
    uint32_t warning;
    uint32_t minor;
    uint32_t major;
    uint32_t critical;
} fault_counters_t;

int faults_init(void);
void faults_free(void);

int faults_change_settings(const char *json);
bool faults_get_present(void);                      //returns wheter faults are present or not in current config

fault_details_t *faults_generate_fault(void);       //does not require freeing, does not update counters

//faults_processing.c
fault_settings_t *faults_settings_read(const char *json_plain);
void faults_settings_free(fault_settings_t *faults);
int faults_settings_process(fault_settings_t *faults, int fault_no);

//faults_counters.c
fault_counters_t faults_counters_get(void);             //assumes faults_lock is acquired
void faults_counters_clear(void);                       //assumes faults_lock is acquired
int faults_counters_increase(const char *severity);     //assumes faults_lock is acquired

//faults_logic.c
void faults_fault_list_clear(void);         //assumes faults_lock is acquired
int faults_fault_list_add(uint16_t delay);  //assumes faults_lock is acquired
bool faults_fault_list_not_empty(void);     //assumes faults_lock is acquired
uint16_t faults_fault_list_get_next(void);  //assumes faults_lock is acquired

//faults_ves.c
int faults_ves_init(void);
void faults_ves_free(void);

int faults_ves_message_send(sr_session_ctx_t *session, const char *condition, const char *object, const char *severity, const char *date_time, const char *specific_problem);
