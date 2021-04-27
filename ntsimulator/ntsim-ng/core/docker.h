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

typedef struct {
    char *repo;
    char *tag;
} docker_available_images_t;

typedef struct {
    char *image;
    docker_available_images_t *available_images;
    int available_images_count;
} docker_context_t;

typedef struct {
    char *name;
    char *id;

    char *docker_ip;
    uint16_t docker_netconf_ssh_port;
    uint16_t docker_netconf_tls_port;
    uint16_t docker_ftp_port;
    uint16_t docker_sftp_port;

    char *host_ip;
    uint16_t host_netconf_ssh_port;
    uint16_t host_netconf_tls_port;
    uint16_t host_ftp_port;
    uint16_t host_sftp_port;
} docker_container_t;

typedef struct {
    float cpu;
    float mem;
} docker_usage_t;

//docker container functions for manager
int docker_init(const char **filter, int filter_count, const char *min_version, docker_context_t **context);
void docker_free(docker_context_t *context, int count);

int docker_start(const char *container_name, const char *tag, const char *image, const char *repo, uint16_t host_netconf_ssh_port, uint16_t host_netconf_tls_port, uint16_t host_ftp_port, uint16_t host_sftp_port, docker_container_t *container);
int docker_stop(docker_container_t *container);

int docker_usage_get(const char **instances_id, int count, docker_usage_t *usage);
int docker_pull(const char *repo, const char *image, const char *tag);
