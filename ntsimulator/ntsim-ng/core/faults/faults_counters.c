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

static fault_counters_t fault_counters;

fault_counters_t faults_counters_get(void) {
    return fault_counters;
}

void faults_counters_clear(void) {
    fault_counters.normal = 0;
    fault_counters.warning = 0;
    fault_counters.minor = 0;
    fault_counters.major = 0;
    fault_counters.critical = 0;
}

int faults_counters_increase(const char *severity) {
    assert(severity);

    int ret = NTS_ERR_OK;
    if(strcmp(severity, "NORMAL") == 0) {
        fault_counters.normal++;
    }
    else if(strcmp(severity, "WARNING") == 0) {
        fault_counters.warning++;
    }
    else if(strcmp(severity, "MINOR") == 0) {
        fault_counters.minor++;
    }
    else if(strcmp(severity, "MAJOR") == 0) {
        fault_counters.major++;
    }
    else if(strcmp(severity, "CRITICAL") == 0) {
        fault_counters.critical++;
    }
    else {
        log_error("severity not found: %s\n", severity);
        ret = NTS_ERR_FAILED;
    }

    return ret;
}
