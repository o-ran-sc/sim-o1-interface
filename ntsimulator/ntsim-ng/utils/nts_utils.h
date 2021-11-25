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

#include <stdint.h>
#include <cjson/cJSON.h>
#include <sysrepo.h>

typedef enum {
    UNKNOWN_MAPPING = 0,
    DOCKER_MAPPING = 1,
    HOST_MAPPING = 2,
} nts_mount_point_addressing_method_t;

typedef struct {
    char *protocol;
    char *ip;
    uint16_t port;
    char *auth_method;
    char *username;
    char *password;

    char *url;
} ves_details_t;

typedef struct {   
    char *ip;
    uint16_t port;
    char *nc_callhome_ip;
    uint16_t nc_callhome_port;
    char *username;
    char *password;

    char *protocol;
    char *base_url;
    char *auth_method;
} controller_details_t;

cJSON* ves_create_common_event_header(const char *domain, const char *event_type, const char *hostname, int port, const char *priority, int seq_id);

nts_mount_point_addressing_method_t nts_mount_point_addressing_method_get(sr_session_ctx_t *current_session);

ves_details_t *ves_endpoint_details_get(sr_session_ctx_t *current_session, const char *custom_path);
void ves_details_free(ves_details_t *instance);

controller_details_t *controller_details_get(sr_session_ctx_t *current_session);
void controller_details_free(controller_details_t *instance);

int nts_utils_populate_info(sr_session_ctx_t *current_session, const char *function_type);

int nts_vercmp(const char *ver1, const char *ver2);
