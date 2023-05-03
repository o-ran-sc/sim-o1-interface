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

#include "nf_oran_ru_supervision.h"
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
#include <libyang/libyang.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "core/framework.h"
#include "core/context.h"
#include "core/session.h"
#include "core/xpath.h"

int notification_timer_seconds=60;
int supervision_timer_seconds=10;

static pthread_t o_ran_supervision_thread = NULL;
static void *o_ran_supervision_thread_routine(void *arg);

static int
supervision_watchdog_reset_rpc_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    size_t i;

    (void)session;
    (void)event;
    (void)request_id;
    (void)private_data;

    bool notification_default = true;
    bool supervision_default = true;

    for (i = 0; i < input_cnt; ++i) {
        if (!strcmp(input[i].xpath, "/o-ran-supervision:supervision-watchdog-reset/supervision-notification-interval")) {
            notification_timer_seconds = input[i].data.uint16_val;
            notification_default = false;
        }
        else if (!strcmp(input[i].xpath, "/o-ran-supervision:supervision-watchdog-reset/guard-timer-overhead")) {
            supervision_timer_seconds = input[i].data.uint16_val;
            supervision_default = false;
        }
    }

    if (notification_default) {
        notification_timer_seconds = 60;
    }
    if (supervision_default) {
        supervision_timer_seconds = 10;
    }

    if (!strcmp(path, "/o-ran-supervision:supervision-watchdog-reset")) {
        *output = malloc(sizeof **output);
        *output_cnt = 1;

        (*output)[0].xpath = strdup("/o-ran-supervision:supervision-watchdog-reset/next-update-at");
        (*output)[0].type = SR_STRING_T;
        (*output)[0].dflt = 0;
        (*output)[0].data.string_val = get_current_date_and_time_delay_seconds(notification_timer_seconds);
    }

    if (o_ran_supervision_thread != NULL) {
        pthread_cancel(o_ran_supervision_thread);
        o_ran_supervision_thread = NULL;
    }

    if(pthread_create(&o_ran_supervision_thread, 0, o_ran_supervision_thread_routine, 0)) {
        log_error("could not create thread for o-ran-supervision\n");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

int nf_oran_ru_supervision_init(void) {
    int rc;

    rc = sr_rpc_subscribe(session_running, O_RAN_SUPERVISION_WATCHDOG_RESET_RPC_SCHEMA_XPATH, supervision_watchdog_reset_rpc_cb, NULL, 0, 0, &session_subscription);
    if (rc != SR_ERR_OK) {
        log_add_verbose(1, "Subscribing for RPC \"%s\" failed.\n", O_RAN_SUPERVISION_WATCHDOG_RESET_RPC_SCHEMA_XPATH);
        return NTS_ERR_FAILED;
    }

    if(pthread_create(&o_ran_supervision_thread, 0, o_ran_supervision_thread_routine, 0)) {
        log_error("could not create thread for o-ran-supervision\n");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static void *o_ran_supervision_thread_routine(void *arg) {
    int notification_counter = notification_timer_seconds;
    int supervision_counter = notification_timer_seconds + supervision_timer_seconds;
    int rc;

    log_add_verbose(1, "Starting thread for o-ran-supervision...\n");

    struct lyd_node *notif = NULL;
    notif = lyd_new_path(NULL, session_context, O_RAN_SUPERVISION_NOTIFICATION_SCHEMA_XPATH, NULL, 0, 0);
    if (!notif) {
        log_error("Creating notification \"%s\" failed.\n", O_RAN_SUPERVISION_NOTIFICATION_SCHEMA_XPATH);
        return NTS_ERR_FAILED;
    }

    while (supervision_counter > 0) {
        sleep(1);
        supervision_counter--;
        notification_counter--;

        if (notification_counter == 0) {
            log_add_verbose(1, "Sending o-ran-supervision supervision-notification..\n");
            rc = sr_event_notif_send_tree(session_running, notif);
            if (rc != SR_ERR_OK) {
                lyd_free(notif);
                return NTS_ERR_FAILED;
            }
        }
    }

    log_add_verbose(1, "Failed to receive watchdog reset, terminating supervision timer for o-ran-supervision...\n");
    pthread_exit((void *)1);
}

void nf_oran_ru_supervision_free(void) {

}

