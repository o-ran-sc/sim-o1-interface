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
#include "utils/nts_utils.h"
#include "utils/sys_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

static fault_settings_t *faults = 0;
static int fault_iterator = -1;

int faults_init(void) {
    int rc = 0;

    rc = faults_ves_init();
    if(rc != NTS_ERR_OK) {
        log_error("faults_ves_init failed\n");
        return NTS_ERR_FAILED; 
    }

    faults_counters_clear();

    char *config_contents = file_read_content("config/config.json");
    rc = faults_change_settings(config_contents);
    free(config_contents);

    return rc;
}

void faults_free(void) {
    faults_ves_free();
    faults_settings_free(faults);
}

int faults_change_settings(const char *json) {
    assert(json);

    fault_settings_t *local_faults = faults_settings_read(json);
    if(faults) {
        faults_settings_free(faults);
    }
    faults = local_faults;

    return NTS_ERR_OK;
}

bool faults_get_present(void) {
    return (faults != 0);
}

fault_details_t *faults_generate_fault(void) {
    if(faults == 0) {
        return 0;
    }

    switch(faults->choosing_method[0]) {
        case 'l':
            fault_iterator++;
            if(fault_iterator >= faults->fault_count) {
                fault_iterator = 0;
            }

            break;

        case 'r':
            fault_iterator = rand_uint32() % faults->fault_count;
            break;

        default:
            log_error("invalid fault choosing method\n");
            return 0;
            break;
    }

    int rc = faults_settings_process(faults, fault_iterator);
    if(rc != NTS_ERR_OK) {
        log_error("faults_settings_process failed\n");
        faults_settings_free(faults);
        return 0;
    }

    return &faults->fault[fault_iterator];
}
