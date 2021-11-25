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

#define NTS_VERSION_FALLBACK                            "1.2.0"

#define ENV_VAR_NTS_MANUAL                              "NTS_MANUAL"
#define ENV_VAR_NTS_BUILD_VERSION                       "NTS_BUILD_VERSION"
#define ENV_VAR_NTS_BUILD_TIME                          "NTS_BUILD_DATE"
#define ENV_VAR_NTS_FUNCTION_TYPE                       "NTS_FUNCTION_TYPE"
#define ENV_VAR_NTS_NF_STANDALONE_START_FEATURES        "NTS_NF_STANDALONE_START_FEATURES"
#define ENV_VAR_NTS_NF_MOUNT_POINT_ADDRESSING_METHOD    "NTS_NF_MOUNT_POINT_ADDRESSING_METHOD"

#define ENV_VAR_DOCKER_REPOSITORY                       "DOCKER_REPOSITORY"
#define ENV_VAR_DOCKER_ENGINE_VERSION                   "DOCKER_ENGINE_VERSION"
#define ENV_VAR_HOSTNAME                                "HOSTNAME"
#define ENV_VAR_IPV6ENABLED                             "IPv6_ENABLED"
#define ENV_VAR_SSH_CONNECTIONS                         "SSH_CONNECTIONS"
#define ENV_VAR_TLS_CONNECTIONS                         "TLS_CONNECTIONS"

#define ENV_VAR_HOST_IP                                 "NTS_HOST_IP"
#define ENV_VAR_HOST_BASE_PORT                          "NTS_HOST_BASE_PORT"
#define ENV_VAR_HOST_NETCONF_SSH_BASE_PORT              "NTS_HOST_NETCONF_SSH_BASE_PORT"
#define ENV_VAR_HOST_NETCONF_TLS_BASE_PORT              "NTS_HOST_NETCONF_TLS_BASE_PORT"
#define ENV_VAR_HOST_TRANSFER_FTP_BASE_PORT             "NTS_HOST_TRANSFER_FTP_BASE_PORT"
#define ENV_VAR_HOST_TRANSFER_SFTP_BASE_PORT            "NTS_HOST_TRANSFER_SFTP_BASE_PORT"

#define ENV_VAR_SDN_CONTROLLER_PROTOCOL                 "SDN_CONTROLLER_PROTOCOL"
#define ENV_VAR_SDN_CONTROLLER_IP                       "SDN_CONTROLLER_IP"
#define ENV_VAR_SDN_CONTROLLER_PORT                     "SDN_CONTROLLER_PORT"
#define ENV_VAR_SDN_CONTROLLER_CALLHOME_IP              "SDN_CONTROLLER_CALLHOME_IP"
#define ENV_VAR_SDN_CONTROLLER_CALLHOME_PORT            "SDN_CONTROLLER_CALLHOME_PORT"
#define ENV_VAR_SDN_CONTROLLER_USERNAME                 "SDN_CONTROLLER_USERNAME"
#define ENV_VAR_SDN_CONTROLLER_PASSWORD                 "SDN_CONTROLLER_PASSWORD"

#define ENV_VAR_VES_COMMON_HEADER_VERSION               "VES_COMMON_HEADER_VERSION"
#define ENV_VAR_VES_ENDPOINT_PROTOCOL                   "VES_ENDPOINT_PROTOCOL"
#define ENV_VAR_VES_ENDPOINT_IP                         "VES_ENDPOINT_IP"
#define ENV_VAR_VES_ENDPOINT_PORT                       "VES_ENDPOINT_PORT"
#define ENV_VAR_VES_ENDPOINT_AUTH_METHOD                "VES_ENDPOINT_AUTH_METHOD"
#define ENV_VAR_VES_ENDPOINT_USERNAME                   "VES_ENDPOINT_USERNAME"
#define ENV_VAR_VES_ENDPOINT_PASSWORD                   "VES_ENDPOINT_PASSWORD"
#define ENV_VAR_VES_ENDPOINT_CERTIFICATE                "VES_ENDPOINT_CERTIFICATE"

typedef enum {
    NTS_MODE_DEFAULT = 0,
    NTS_MODE_CONTAINER_INIT,
    NTS_MODE_SUPERVISOR,
    NTS_MODE_MANAGER,
    NTS_MODE_NETWORK_FUNCTION,
    NTS_MODE_BLANK,
    NTS_MODE_TEST,
} nts_mode_t;

typedef struct {
    nts_mode_t nts_mode;

    int argc;
    char **argv;    //no-copy

    bool no_rand;
    unsigned int fixed_seed;
    int verbosity_level;
    
    bool print_root_paths;
    char *print_structure_xpath;
} framework_arguments_t;

typedef struct {
    struct  {
        bool manual;
        char *version;
        char *build_time;
        char *function_type;
        char *nf_standalone_start_features;
        char *nf_mount_point_addressing_method;
    } nts;

    struct {
        char *docker_repository;
        char *docker_engine_version;

        char *hostname;
        char *ip_v4;
        char *ip_v6;
        bool ip_v6_enabled;
        uint16_t ssh_connections;
        uint16_t tls_connections;
        uint16_t ftp_connections;
        uint16_t sftp_connections;
    } settings;

    struct {
        char *ip;
        uint16_t base_port;
        uint16_t ssh_base_port;
        uint16_t tls_base_port;
        uint16_t ftp_base_port;
        uint16_t sftp_base_port;
    } host;

    struct {
        char *protocol;
        char *ip;
        uint16_t port;
        char *callhome_ip;
        uint16_t callhome_port;
        char *username;
        char *password;
        bool port_absent;
    } sdn_controller;

    struct {
        char *common_header_version;

        char *protocol;
        char *ip;
        uint16_t port;
        char *auth_method;
        char *username;
        char *password;
        char *certificate;
        bool port_absent;
    } ves_endpoint;
} framework_environment_t;

typedef struct {
    char *name;
    char *path;
    char **args;
    int args_count;
    bool nomanual;
    bool autorestart;
    char *stdout_path;
    char *stderr_path;
} supervisor_rules_t;

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
    struct {
        int excluded_modules_count;
        char **excluded_modules;

        int excluded_features_count;
        char **excluded_features;
    } docker;

    struct {
        int rules_count;
        supervisor_rules_t *rules;
    } supervisor;

    struct {
        int debug_max_string_size;

        int excluded_modules_count;
        char **excluded_modules;

        int default_list_instances;

        int custom_list_instances_count;
        custom_list_instances_t *custom_list_instances;

        int restrict_schema_count;
        restrict_schema_t *restrict_schema;
    } datastore_generate;

    struct {
        bool random_generation_enabled;

        int preg_operational_count;
        char **preg_operational;

        int preg_running_count;
        char **preg_running;
    } datastore_populate;   
} framework_config_t;

extern framework_arguments_t framework_arguments;
extern framework_environment_t framework_environment;
extern framework_config_t framework_config;

volatile sig_atomic_t framework_sigint;

int framework_init(int argc, char **argv);
void framework_free(void);
