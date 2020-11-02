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

#include <string.h>
#include <stdint.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

extern sr_conn_ctx_t *session_connection;
extern sr_session_ctx_t *session_running;
extern sr_session_ctx_t *session_operational;
extern struct ly_ctx *session_context;
extern sr_subscription_ctx_t *session_subscription;

#define assert_session()    assert(session_connection && session_running && session_operational && session_context) 

int session_init(void);
void session_free(void);
