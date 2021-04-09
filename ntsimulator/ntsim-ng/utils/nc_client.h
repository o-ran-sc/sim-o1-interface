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

#define NC_ENABLED_SSH
#define NC_ENABLED_TLS
#include <libyang/libyang.h>
#include <libnetconf2/session.h>
#include <libnetconf2/session_client.h>
#include <sysrepo.h>

// void nc_client_init(void);   --imported from libnetconf2, must be called on app init
// void nc_client_destroy(void);   --imported from libnetconf2, must be called on app deinit

typedef struct {
    struct nc_session *session;
    struct lyd_node *edit_batch_root;

    char *password;
} nc_client_t;

nc_client_t *nc_client_ssh_connect(const char *host, uint16_t port, const char *username, const char *password);
nc_client_t *nc_client_tls_connect(const char *host, uint16_t port);
int nc_client_disconnect(nc_client_t *client);

struct lyd_node *nc_client_send_rpc(nc_client_t *client, struct lyd_node *data, int timeout);

struct lyd_node *nc_client_get_batch(nc_client_t *client, const char *xpath, int timeout);
int nc_client_edit_batch(nc_client_t *client, struct lyd_node *data, int timeout);

int nc_client_set_item_str(nc_client_t *client, const char *xpath, const char *value);
int nc_client_edit_apply_changes(nc_client_t *client, int timeout);

int lyd_utils_dup(sr_session_ctx_t *session, const char *xpath_s, const char *xpath_d, struct lyd_node **tree);
