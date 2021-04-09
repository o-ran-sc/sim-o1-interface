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
#include "utils/rand_utils.h"
#include "utils/sys_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

static uint16_t *faults_fault_list = 0;
static uint16_t faults_fault_list_len = 0;
static uint16_t faults_fault_list_iterator = 0;

void faults_fault_list_clear(void) {
    faults_fault_list_len = 0;
    free(faults_fault_list);
    faults_fault_list = 0;
    faults_fault_list_iterator = 0;
    log_add_verbose(2, "[faults] fault list cleared\n");
}

int faults_fault_list_add(uint16_t delay) {
    faults_fault_list_len++;
    faults_fault_list = (uint16_t *)realloc(faults_fault_list, sizeof(uint16_t) * (faults_fault_list_len));
    if(faults_fault_list == 0) {
        log_error("realloc failed\n");
        return NTS_ERR_FAILED;
    }
    faults_fault_list[faults_fault_list_len - 1] = delay;
    log_add_verbose(2, "[faults] added %d\n", delay);

    return NTS_ERR_OK;
}

bool faults_fault_list_not_empty(void) {
    bool not_empty = (faults_fault_list_len != 0);
    if(not_empty == true) {
        int delay_sum = 0;
        for(int i = 0; i < faults_fault_list_len; i++) {
            delay_sum += faults_fault_list[i];
        }

        not_empty = (delay_sum != 0);
    }
    return not_empty;
}

uint16_t faults_fault_list_get_next(void) {
    assert(faults_fault_list_iterator < faults_fault_list_len);

    uint16_t ret = faults_fault_list[faults_fault_list_iterator];
    faults_fault_list_iterator++;
    if(faults_fault_list_iterator >= faults_fault_list_len) {
        faults_fault_list_iterator = 0;
    }

    return ret;
}
