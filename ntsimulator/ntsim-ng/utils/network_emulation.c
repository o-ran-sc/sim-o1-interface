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

#include "network_emulation.h"
#include "log_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int network_emulation_init(void) {
    system("tc qdisc add dev eth0 root netem limit "NETWORK_EMULATION_DEFAULT_LIMIT" delay 0ms > /dev/null");
    return NTS_ERR_OK;
}

int network_emulation_update(const network_emultation_settings_t *s) {
    assert(s);

    char command[512];
    if(s->delay.time && s->delay.jitter) {
        sprintf(command, "tc qdisc change dev eth0 root netem limit %d delay %dms %dms %d%% distribution %s loss random %d%% corrupt %d%% %d%% duplicate %d%% %d%% reorder %d%% %d%% rate %dkbit > /dev/null", s->limit, s->delay.time, s->delay.jitter, s->delay.correlation, s->delay.distribution, s->loss, s->corruption.percentage, s->corruption.correlation, s->duplication.percentage, s->duplication.correlation, s->reordering.percentage, s->reordering.correlation, s->rate);
    }
    else {
        sprintf(command, "tc qdisc change dev eth0 root netem limit %d delay %dms %dms %d%% loss random %d%% corrupt %d%% %d%% duplicate %d%% %d%% reorder %d%% %d%% rate %dkbit > /dev/null", s->limit, s->delay.time, s->delay.jitter, s->delay.correlation, s->loss, s->corruption.percentage, s->corruption.correlation, s->duplication.percentage, s->duplication.correlation, s->reordering.percentage, s->reordering.correlation, s->rate);
    }
    log_add_verbose(2, "chaning netem: %s\n", command);
    int rc = system(command);
    return rc;
}
