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

#include <argp.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#define ENV_VAR_HOSTNAME                        "HOSTNAME"
#define ENV_VAR_DOCKER_ENGINE_VERSION           "DOCKER_ENGINE_VERSION"
#define ENV_VAR_IPV6ENABLED                     "IPv6_ENABLED"
#define ENV_VAR_HOST_IP                         "NETCONF_NTS_HOST_IP"
#define ENV_VAR_HOST_BASE_PORT                  "NETCONF_NTS_HOST_BASE_PORT"
#define ENV_VAR_SSH_CONNECTIONS                 "SSH_CONNECTIONS"
#define ENV_VAR_TLS_CONNECTIONS                 "TLS_CONNECTIONS"

#define ENV_VAR_SDN_CONTROLLER_IP               "SDN_CONTROLLER_IP"
#define ENV_VAR_SDN_CONTROLLER_PORT             "SDN_CONTROLLER_PORT"
#define ENV_VAR_SDN_CONTROLLER_CALLHOME_PORT    "SDN_CONTROLLER_CALLHOME_PORT"
#define ENV_VAR_SDN_CONTROLLER_USERNAME         "SDN_CONTROLLER_USERNAME"
#define ENV_VAR_SDN_CONTROLLER_PASSWORD         "SDN_CONTROLLER_PASSWORD"

#define ENV_VAR_VES_ENDPOINT_PROTOCOL           "VES_ENDPOINT_PROTOCOL"
#define ENV_VAR_VES_ENDPOINT_IP                 "VES_ENDPOINT_IP"
#define ENV_VAR_VES_ENDPOINT_PORT               "VES_ENDPOINT_PORT"
#define ENV_VAR_VES_ENDPOINT_AUTH_METHOD        "VES_ENDPOINT_AUTH_METHOD"
#define ENV_VAR_VES_ENDPOINT_USERNAME           "VES_ENDPOINT_USERNAME"
#define ENV_VAR_VES_ENDPOINT_PASSWORD           "VES_ENDPOINT_PASSWORD"
#define ENV_VAR_VES_ENDPOINT_CERTIFICATE        "VES_ENDPOINT_CERTIFICATE"

typedef struct {
    char *path;
    int count;
} custom_list_instances_t;

typedef struct {
    char *path;
    int values_count;
    char **values;
    int index;
} restrict_schema_t;

typedef struct {
    bool container_init;
    bool nc_server_init;

    bool no_rand;
    unsigned int fixed_seed;
    bool operational_only;
    int verbosity_level;
    bool loop;
    bool test_mode;

    bool manager;
    bool network_function;

    bool exhaustive_test;
    bool print_root_paths;
    char *print_structure_xpath;
    bool populate_all;
    bool enable_features;
} framework_arguments_t;

typedef struct {
    int docker_excluded_modules_count;
    char **docker_excluded_modules;

    int docker_excluded_features_count;
    char **docker_excluded_features;

    int debug_max_string_size;

    int populate_excluded_modules_count;
    char **populate_excluded_modules;

    int default_list_instances;

    int custom_list_instances_count;
    custom_list_instances_t *custom_list_instances;

    int restrict_schema_count;
    restrict_schema_t *restrict_schema;
} framework_config_t;

typedef struct {
    char *docker_engine_version;

    char *ip_v4;
    char *ip_v6;
    bool ip_v6_enabled;

    char *hostname;
    char *host_ip;
    uint16_t host_base_port;
    uint16_t ssh_connections;
    uint16_t tls_connections;
    uint16_t ftp_connections;
    uint16_t sftp_connections;

    char *sdn_controller_ip;
    uint16_t sdn_controller_port;
    uint16_t sdn_controller_callhome_port;
    char *sdn_controller_username;
    char *sdn_controller_password;

    char *ves_endpoint_protocol;
    char *ves_endpoint_ip;
    uint16_t ves_endpoint_port;
    char *ves_endpoint_auth_method;
    char *ves_endpoint_username;
    char *ves_endpoint_password;
    char *ves_endpoint_certificate;
} framework_environment_t;

extern framework_arguments_t framework_arguments;
extern framework_config_t framework_config;
extern framework_environment_t framework_environment;

volatile sig_atomic_t framework_sigint;

void framework_init(int argc, char **argv);
void framework_free(void);

//docker-related functions
bool framework_is_docker_excluded_module(const char *module);
bool framework_is_docker_excluded_feature(const char *feature);

//populate-related functions
bool framework_is_populate_excluded_module(const char *module);

int framework_populate_get_instance_count(const char *path);
char *framework_populate_get_restrict_schema(const char *path);     //returns null if there is no restricted entry, value otherwise. value must be freed
