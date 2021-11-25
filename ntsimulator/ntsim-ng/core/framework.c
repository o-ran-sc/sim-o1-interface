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

#include "framework.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cjson/cJSON.h>

#include "utils/sys_utils.h"
#include "utils/log_utils.h"
#include "utils/rand_utils.h"

framework_arguments_t framework_arguments;
framework_environment_t framework_environment;
framework_config_t framework_config;

const char *argp_program_version = 0;    //is set later
const char *argp_program_bug_address = "<alexandru.stancu@highstreet-technologies.com> / <adrian.lita@highstreet-technologies.com>";
static char doc[] = "ntsim - new generation";

static struct argp_option options[] = {
    { "container-init", 'i', 0, 0, "Runs initialization tasks for the Docker container that's being built. Do not run manually." },
    { "supervisor", 's', 0, 0, "Run as supervisor; manager/network-function is chosen via config.json"},
    { "manager", 'm', 0, 0, "Run the daemon as manager." },
    { "network-function", 'f', 0, 0, "Run the daemon as network function." },
    { "blank", 'b', 0, 0, "Run the deamon as a blank network function." },
    { "test-mode", 't', 0, 0, "Test mode." },
    
    // tools
    { "ls", '1', 0, 0, "Print all available root paths." },
    { "schema", '2', "XPATH", 0, "Print schema for XPATH." },
    
    { "fixed-rand", 'r', "SEED", 0, "Initialize RAND seed to a fixed value (for debugging purposes)." },
    { "verbose", 'v', "LEVEL", 0, "Verbosity level for printing to stdout (logs will still save everything). LEVEL is: 0=errors only, 1=requested info(default), 2=info" },
    { "workspace", 'w', "PATH", 0, "Initialize workspace to a different one than the current working directory." },
    { 0 } 
};

volatile sig_atomic_t framework_sigint;

static int framework_env_init(void);
static int framework_config_init(void);

static void framework_signal_handler(int signo);
static error_t parse_opt(int key, char *arg, struct argp_state *state);

int framework_init(int argc, char **argv) {
    //environment vars
    framework_environment.nts.version = (getenv(ENV_VAR_NTS_BUILD_VERSION) && strlen(getenv(ENV_VAR_NTS_BUILD_VERSION))) ? strdup(getenv(ENV_VAR_NTS_BUILD_VERSION)) : strdup(NTS_VERSION_FALLBACK"!");
    if(getenv(ENV_VAR_NTS_BUILD_TIME) && strlen(getenv(ENV_VAR_NTS_BUILD_TIME))) {
        framework_environment.nts.build_time = strdup(getenv(ENV_VAR_NTS_BUILD_TIME));
    }
    else {
        if(__DATE__[0] == '?') {
            framework_environment.nts.build_time = strdup("1970-01-01T00:00:00Z");
        }
        else {
            //01234567890
            //May  4 2021
            int year = 0;
            int month = 1;
            int day = 0;
            
            year = (__DATE__[10] - '0') + (__DATE__[9] - '0')*10 + (__DATE__[8] - '0')*100 + (__DATE__[7] - '0')*1000;
            day = (__DATE__[5] - '0');
            if(__DATE__[4] != ' ') {
                day += (__DATE__[4] - '0')*10;
            }
            
            switch(__DATE__[0]) {
                case 'J':
                    switch(__DATE__[1]) {
                        case 'a':
                            month = 1;
                            break;
                        
                        case 'u':
                            if(__DATE__[2] == 'n') {
                                month = 6;
                            }
                            else {
                                month = 7;
                            }
                            break;
                    }
                    break;
                    
                case 'F':
                    month = 2;
                    break;
                    
                case 'M':
                    switch(__DATE__[2]) {
                        case 'r':
                            month = 3;
                            break;
                            
                        case 'y':
                            month = 5;
                            break;
                    }
                    break;
                
                case 'A':
                    switch(__DATE__[1]) {
                        case 'p':
                            month = 4;
                            break;
                            
                        case 'u':
                            month = 8;
                            break;
                    }
                    break;
                    
                case 'S':
                    month = 9;
                    break;
                    
                case 'O':
                    month = 10;
                    break;
                    
                case 'N':
                    month = 11;
                    break;
                    
                case 'D':
                    month = 12;
                    break;
            }
            
            asprintf(&framework_environment.nts.build_time, "%04d-%02d-%02dT%sZ", year, month, day, __TIME__);
        }
    }

    //set argp_version
    char *version = 0;
    asprintf(&version, "ntsim-ng v%s build %s", framework_environment.nts.version, framework_environment.nts.build_time);
    argp_program_version = version;

    //initialize app arguments
    framework_arguments.nts_mode = NTS_MODE_DEFAULT;

    framework_arguments.argc = argc;
    framework_arguments.argv = argv;

    framework_arguments.no_rand = false;
    framework_arguments.fixed_seed = 0;
    framework_arguments.verbosity_level = 1;

    framework_arguments.print_root_paths = false;
    framework_arguments.print_structure_xpath = 0;

    //parse provided command line arguments
    struct argp argp = { options, parse_opt, 0, doc, 0, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, &framework_arguments);

    //manage signals
    framework_sigint = 0;
    signal(SIGINT, framework_signal_handler);
    signal(SIGTERM, framework_signal_handler);
    signal(SIGQUIT, framework_signal_handler);

    //disable buffering for stdout
    setbuf(stdout, NULL);

    //init logging subsystem
    char *log_file = 0;
    char *stderr_file = 0;

    if(!dir_exists("log")) {
        mkdir("log", 0777);
    }

    switch(framework_arguments.nts_mode) {
        case NTS_MODE_CONTAINER_INIT:
            log_file = "log/log-install.txt";
            stderr_file = "log/stderr-install.txt";
            break;

        case NTS_MODE_BLANK:
            log_file = "log/log-blank.txt";
            stderr_file = "log/stderr-blank.txt";
            break;

        case NTS_MODE_SUPERVISOR:
            log_file = "log/log-supervisor.txt";
            stderr_file = "log/stderr-supervisor.txt";
            break;

        default:
            log_file = "log/log.txt";
            stderr_file = "log/stderr.txt";
            break;
    }

    log_init(log_file);
    log_redirect_stderr(stderr_file);

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    log_add_verbose(2, "[framework] current working dir is: %s\n", cwd);

    //init rand generator if needed
    if(framework_arguments.no_rand == false) {
        rand_init();
    }
    else {
        rand_init_fixed(framework_arguments.fixed_seed);
    }

    log_add_verbose(2, "[framework] app was called: ");
    for(int i = 0; i < argc; i++) {
        log_add(2, "%s ", argv[i]);
    }
    log_add(2, "\n");

    if(framework_env_init() != NTS_ERR_OK) {
        log_error("[framework] framework_env_init() failed\n");
        return NTS_ERR_FAILED;
    }

    if(framework_config_init() != NTS_ERR_OK) {
        log_error("[framework] framework_config_init() failed\n");
        return NTS_ERR_FAILED;
    }

    log_add_verbose(2, "[framework] init complete\n");
    return NTS_ERR_OK;
}

static int framework_env_init(void) {
    log_add_verbose(2, "[framework-env] started\n");

    /*
    The following env vars are taken care of by framework_init()
        framework_environment.nts.version
        framework_environment.nts.build_time
    */

    framework_environment.nts.manual = getenv(ENV_VAR_NTS_MANUAL) ? true : false;
    framework_environment.nts.function_type = getenv(ENV_VAR_NTS_FUNCTION_TYPE) ? strdup(getenv(ENV_VAR_NTS_FUNCTION_TYPE)) : strdup("");
    framework_environment.nts.nf_standalone_start_features = getenv(ENV_VAR_NTS_NF_STANDALONE_START_FEATURES) ? strdup(getenv(ENV_VAR_NTS_NF_STANDALONE_START_FEATURES)) : strdup("");
    framework_environment.nts.nf_mount_point_addressing_method = getenv(ENV_VAR_NTS_NF_MOUNT_POINT_ADDRESSING_METHOD) ? strdup(getenv(ENV_VAR_NTS_NF_MOUNT_POINT_ADDRESSING_METHOD)) : strdup("docker-mapping");

    framework_environment.settings.docker_repository = getenv(ENV_VAR_DOCKER_REPOSITORY) ? strdup(getenv(ENV_VAR_DOCKER_REPOSITORY)) : strdup("");
    if(strlen(framework_environment.settings.docker_repository)) {
        if(framework_environment.settings.docker_repository[strlen(framework_environment.settings.docker_repository) - 1] == '/') {
            framework_environment.settings.docker_repository[strlen(framework_environment.settings.docker_repository) - 1] = 0;
        }
    }
    framework_environment.settings.docker_engine_version = getenv(ENV_VAR_DOCKER_ENGINE_VERSION) ? strdup(getenv(ENV_VAR_DOCKER_ENGINE_VERSION)) : strdup("1.40");
    framework_environment.settings.hostname = getenv(ENV_VAR_HOSTNAME) ? strdup(getenv(ENV_VAR_HOSTNAME)) : strdup("localhost");

    bool ip_ok = get_local_ips("eth0", &framework_environment.settings.ip_v4, &framework_environment.settings.ip_v6);
    if(!ip_ok) {
        log_error("[framework-env] could not get local IP addresses\n");
    }

    char *ipv6_env_var = getenv(ENV_VAR_IPV6ENABLED);
    if(ipv6_env_var == 0) {
        log_error("[framework-env] could not get the IPv6 Enabled env variable\n");
    }
    framework_environment.settings.ip_v6_enabled = (strcmp(ipv6_env_var, "true") == 0) ? true : false;
    framework_environment.settings.ssh_connections = get_int_from_string_with_default(getenv(ENV_VAR_SSH_CONNECTIONS), 1);
    framework_environment.settings.tls_connections = get_int_from_string_with_default(getenv(ENV_VAR_TLS_CONNECTIONS), 0);
    framework_environment.settings.ftp_connections = 1;
    framework_environment.settings.sftp_connections = 1;

    //build version and build time are set in the begining of the function
    framework_environment.host.ip = getenv(ENV_VAR_HOST_IP) ? strdup(getenv(ENV_VAR_HOST_IP)) : strdup("127.0.0.1");
    framework_environment.host.base_port = get_int_from_string_with_default(getenv(ENV_VAR_HOST_BASE_PORT), 1000);
    framework_environment.host.ssh_base_port = get_int_from_string_with_default(getenv(ENV_VAR_HOST_NETCONF_SSH_BASE_PORT), 0);
    framework_environment.host.tls_base_port = get_int_from_string_with_default(getenv(ENV_VAR_HOST_NETCONF_TLS_BASE_PORT), 0);
    framework_environment.host.ftp_base_port = get_int_from_string_with_default(getenv(ENV_VAR_HOST_TRANSFER_FTP_BASE_PORT), 0);
    framework_environment.host.sftp_base_port = get_int_from_string_with_default(getenv(ENV_VAR_HOST_TRANSFER_SFTP_BASE_PORT), 0);
    
    framework_environment.sdn_controller.protocol = getenv(ENV_VAR_SDN_CONTROLLER_IP) ? strdup(getenv(ENV_VAR_SDN_CONTROLLER_PROTOCOL)) : strdup("https");
    framework_environment.sdn_controller.ip = getenv(ENV_VAR_SDN_CONTROLLER_IP) ? strdup(getenv(ENV_VAR_SDN_CONTROLLER_IP)) : strdup("127.0.0.1");
    framework_environment.sdn_controller.port = get_int_from_string_with_default(getenv(ENV_VAR_SDN_CONTROLLER_PORT), 8181);
    framework_environment.sdn_controller.callhome_ip = getenv(ENV_VAR_SDN_CONTROLLER_CALLHOME_IP) ? strdup(getenv(ENV_VAR_SDN_CONTROLLER_CALLHOME_IP)) : strdup("127.0.0.1");
    framework_environment.sdn_controller.callhome_port = get_int_from_string_with_default(getenv(ENV_VAR_SDN_CONTROLLER_CALLHOME_PORT), 6666);
    framework_environment.sdn_controller.username = getenv(ENV_VAR_SDN_CONTROLLER_USERNAME) ? strdup(getenv(ENV_VAR_SDN_CONTROLLER_USERNAME)) : strdup("admin");
    framework_environment.sdn_controller.password = getenv(ENV_VAR_SDN_CONTROLLER_PASSWORD) ? strdup(getenv(ENV_VAR_SDN_CONTROLLER_PASSWORD)) : strdup("admin");
    framework_environment.sdn_controller.port_absent = (getenv(ENV_VAR_SDN_CONTROLLER_PORT) == 0) ? true : false;

    framework_environment.ves_endpoint.common_header_version = getenv(ENV_VAR_VES_COMMON_HEADER_VERSION) ? strdup(getenv(ENV_VAR_VES_COMMON_HEADER_VERSION)) : strdup("7.2");
    framework_environment.ves_endpoint.protocol = getenv(ENV_VAR_VES_ENDPOINT_PROTOCOL) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_PROTOCOL)) : strdup("https");
    framework_environment.ves_endpoint.ip = getenv(ENV_VAR_VES_ENDPOINT_IP) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_IP)) : strdup("127.0.0.1");
    framework_environment.ves_endpoint.port = get_int_from_string_with_default(getenv(ENV_VAR_VES_ENDPOINT_PORT), 1234);
    framework_environment.ves_endpoint.auth_method = getenv(ENV_VAR_VES_ENDPOINT_AUTH_METHOD) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_AUTH_METHOD)) : strdup("no-auth");
    framework_environment.ves_endpoint.username = getenv(ENV_VAR_VES_ENDPOINT_USERNAME) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_USERNAME)) : strdup("admin");
    framework_environment.ves_endpoint.password = getenv(ENV_VAR_VES_ENDPOINT_PASSWORD) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_PASSWORD)) : strdup("admin");
    framework_environment.ves_endpoint.certificate = getenv(ENV_VAR_VES_ENDPOINT_CERTIFICATE) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_CERTIFICATE)) : strdup("");
    framework_environment.ves_endpoint.port_absent = (getenv(ENV_VAR_VES_ENDPOINT_PORT) == 0) ? true : false;

    log_add_verbose(2, "[framework-env] nts.manual = %d\n", framework_environment.nts.manual);
    log_add_verbose(2, "[framework-env] nts.version = %s\n", framework_environment.nts.version);
    log_add_verbose(2, "[framework-env] nts.build_time = %s\n", framework_environment.nts.build_time);
    log_add_verbose(2, "[framework-env] nts.function_type = %s\n", framework_environment.nts.function_type);
    log_add_verbose(2, "[framework-env] nts.nf_standalone_start_features = %s\n", framework_environment.nts.nf_standalone_start_features);
    log_add_verbose(2, "[framework-env] nts.nf_mount_point_addressing_method = %s\n", framework_environment.nts.nf_mount_point_addressing_method);

    log_add_verbose(2, "[framework-env] settings.docker_engine_version = %s\n", framework_environment.settings.docker_engine_version);
    log_add_verbose(2, "[framework-env] settings.docker_repository = %s\n", framework_environment.settings.docker_repository);
    log_add_verbose(2, "[framework-env] settings.hostname = %s\n", framework_environment.settings.hostname);
    log_add_verbose(2, "[framework-env] settings.ip_v4 = %s\n", framework_environment.settings.ip_v4);
    log_add_verbose(2, "[framework-env] settings.ip_v6 = %s\n", framework_environment.settings.ip_v6);
    log_add_verbose(2, "[framework-env] settings.ip_v6_enabled = %s\n", framework_environment.settings.ip_v6_enabled ? "true" : "false");
    log_add_verbose(2, "[framework-env] settings.ssh_connections = %d\n", framework_environment.settings.ssh_connections);
    log_add_verbose(2, "[framework-env] settings.tls_connections = %d\n", framework_environment.settings.tls_connections);
    log_add_verbose(2, "[framework-env] settings.ftp_connections = %d\n", framework_environment.settings.ftp_connections);
    log_add_verbose(2, "[framework-env] settings.sftp_connections = %d\n", framework_environment.settings.sftp_connections);

    //check ports
    if(framework_environment.host.base_port < 1000) {
        log_add_verbose(2, "[framework-env] host.base_port < 1000 -> disabling\n");
        framework_environment.host.base_port = 0;
    }

    if(framework_environment.host.ssh_base_port < 1000) {
        log_add_verbose(2, "[framework-env] host.ssh_base_port < 1000 -> using base_port\n");
        framework_environment.host.ssh_base_port = framework_environment.host.base_port;
    }

    if(framework_environment.host.tls_base_port < 1000) {
        log_add_verbose(2, "[framework-env] host.tls_base_port < 1000 -> using base_port\n");
        framework_environment.host.tls_base_port = framework_environment.host.base_port;
    }

    if(framework_environment.host.ftp_base_port < 1000) {
        log_add_verbose(2, "[framework-env] host.ftp_base_port < 1000 -> using base_port\n");
        framework_environment.host.ftp_base_port = framework_environment.host.base_port;
    }

    if(framework_environment.host.sftp_base_port < 1000) {
        log_add_verbose(2, "[framework-env] host.sftp_base_port < 1000 -> using base_port\n");
        framework_environment.host.sftp_base_port = framework_environment.host.base_port;
    }

    if(framework_environment.host.base_port == 0) {
        if(framework_environment.host.ssh_base_port == 0) {
            log_error("[framework-env] host.ssh_base_port unknown\n");
            return NTS_ERR_FAILED;
        }

        if(framework_environment.host.tls_base_port == 0) {
            log_error("[framework-env] host.tls_base_port unknown\n");
            return NTS_ERR_FAILED;
        }

        if(framework_environment.host.ftp_base_port == 0) {
            log_error("[framework-env] host.ftp_base_port unknown\n");
            return NTS_ERR_FAILED;
        }

        if(framework_environment.host.sftp_base_port == 0) {
            log_error("[framework-env] host.sftp_base_port unknown\n");
            return NTS_ERR_FAILED;
        }
    }
    
    log_add_verbose(2, "[framework-env] host.ip = %s\n", framework_environment.host.ip);
    if(framework_environment.settings.ip_v6_enabled) {
        if(strstr(framework_environment.host.ip, ".")) {
            log_error("[framework-env] host.ip is an invalid IP v6\n");
            return NTS_ERR_FAILED;
        }
    }
    else {
        if(strstr(framework_environment.host.ip, ":")) {
            log_error("[framework-env] host.ip is an invalid IP v4\n");
            return NTS_ERR_FAILED;
        }
    }

    log_add_verbose(2, "[framework-env] host.base_port = %d\n", framework_environment.host.base_port);
    log_add_verbose(2, "[framework-env] host.ssh_base_port = %d\n", framework_environment.host.ssh_base_port);
    log_add_verbose(2, "[framework-env] host.tls_base_port = %d\n", framework_environment.host.tls_base_port);
    log_add_verbose(2, "[framework-env] host.ftp_base_port = %d\n", framework_environment.host.ftp_base_port);
    log_add_verbose(2, "[framework-env] host.sftp_base_port = %d\n", framework_environment.host.sftp_base_port);
    
    log_add_verbose(2, "[framework-env] sdn_controller.protocol = %s\n", framework_environment.sdn_controller.protocol);
    log_add_verbose(2, "[framework-env] sdn_controller.ip = %s\n", framework_environment.sdn_controller.ip);
    log_add_verbose(2, "[framework-env] sdn_controller.port = %d\n", framework_environment.sdn_controller.port);
    log_add_verbose(2, "[framework-env] sdn_controller.callhome_ip = %s\n", framework_environment.sdn_controller.callhome_ip);
    log_add_verbose(2, "[framework-env] sdn_controller.callhome_port = %d\n", framework_environment.sdn_controller.callhome_port);
    log_add_verbose(2, "[framework-env] sdn_controller.username = %s\n", framework_environment.sdn_controller.username);
    log_add_verbose(2, "[framework-env] sdn_controller.password = %s\n", framework_environment.sdn_controller.password);
    log_add_verbose(2, "[framework-env] sdn_controller.port_absent = %d\n", framework_environment.sdn_controller.port_absent);

    log_add_verbose(2, "[framework-env] ves_endpoint.common_header_version = %s\n", framework_environment.ves_endpoint.common_header_version);
    log_add_verbose(2, "[framework-env] ves_endpoint.protocol = %s\n", framework_environment.ves_endpoint.protocol);
    log_add_verbose(2, "[framework-env] ves_endpoint.ip = %s\n", framework_environment.ves_endpoint.ip);
    log_add_verbose(2, "[framework-env] ves_endpoint.port = %d\n", framework_environment.ves_endpoint.port);
    log_add_verbose(2, "[framework-env] ves_endpoint.auth_method = %s\n", framework_environment.ves_endpoint.auth_method);
    log_add_verbose(2, "[framework-env] ves_endpoint.username = %s\n", framework_environment.ves_endpoint.username);
    log_add_verbose(2, "[framework-env] ves_endpoint.password = %s\n", framework_environment.ves_endpoint.password);
    log_add_verbose(2, "[framework-env] ves_endpoint.certificate = %s\n", framework_environment.ves_endpoint.certificate);
    log_add_verbose(2, "[framework-env] ves_endpoint.port_absent = %d\n", framework_environment.ves_endpoint.port_absent);

    log_add_verbose(2, "[framework-env] finished\n");
    return NTS_ERR_OK;
}

static int framework_config_init(void) {
    log_add_verbose(2, "[framework-config] started\n");

    //init app config
    framework_config.docker.excluded_modules = 0;
    framework_config.docker.excluded_modules_count = 0;
    framework_config.docker.excluded_features = 0;
    framework_config.docker.excluded_features_count = 0;

    framework_config.supervisor.rules_count = 0;
    framework_config.supervisor.rules = 0;

    framework_config.datastore_generate.debug_max_string_size = 0;
    framework_config.datastore_generate.excluded_modules = 0;
    framework_config.datastore_generate.excluded_modules_count = 0;
    framework_config.datastore_generate.default_list_instances = 1;
    framework_config.datastore_generate.custom_list_instances_count = 0;
    framework_config.datastore_generate.custom_list_instances = 0;
    framework_config.datastore_generate.restrict_schema_count = 0;
    framework_config.datastore_generate.restrict_schema = 0;

    framework_config.datastore_populate.random_generation_enabled = 1;
    framework_config.datastore_populate.preg_operational_count = 0;
    framework_config.datastore_populate.preg_operational = 0;
    framework_config.datastore_populate.preg_running_count = 0;
    framework_config.datastore_populate.preg_running = 0;

    //config init
    char *config_file = "config/config.json";
    if(file_exists("/opt/dev/config/config.json")) {
        config_file = "/opt/dev/config/config.json";
        log_add_verbose(1, LOG_COLOR_BOLD_MAGENTA"config.json is loaded from external volume!\n"LOG_COLOR_RESET);
    }
    else {
        if(!dir_exists("config")) {
            log_add_verbose(2, "[framework-config] config/ folder wasn't found; created.\n");
            mkdir("config", 0777);
        }

        if(!file_exists("config/config.json")) {
            log_add_verbose(2, "[framework-config] config.json file missing; created.\n");
            file_touch("config/config.json", "{}");
        }
    }

    log_add_verbose(2, "[framework-config] parsing config.json from %s\n", config_file);
    char *config_contents = file_read_content(config_file);
    cJSON *json = cJSON_Parse(config_contents);
    free(config_contents);
    if(!json) {
        log_error("[framework-config] config.json error: %s\n", cJSON_GetErrorPtr());
    }
    else {
        cJSON *main_node;
        cJSON *node;

        if(framework_arguments.nts_mode == NTS_MODE_CONTAINER_INIT) {
            main_node = cJSON_GetObjectItem(json, "container-rules");
            if(main_node) {
                node = cJSON_GetObjectItem(main_node, "excluded-modules");
                if(node) {
                    if(cJSON_IsArray(node)) {
                        cJSON *element;
                        cJSON_ArrayForEach(element, node) {
                            if(cJSON_IsString(element)) {
                                log_add_verbose(2, "[framework-config] adding container-rules/exclude-modules: %s\n", element->valuestring);
                                framework_config.docker.excluded_modules = (char **)realloc(framework_config.docker.excluded_modules, sizeof(char*) * (framework_config.docker.excluded_modules_count + 1));
                                if(!framework_config.docker.excluded_modules) {
                                    log_error("[framework-config] bad realloc\n");
                                }
                                framework_config.docker.excluded_modules[framework_config.docker.excluded_modules_count] = (char *)malloc(sizeof(char) * (strlen(element->valuestring) + 1));
                                if(!framework_config.docker.excluded_modules[framework_config.docker.excluded_modules_count]) {
                                    log_error("[framework-config] bad malloc\n");
                                }
                                strcpy(framework_config.docker.excluded_modules[framework_config.docker.excluded_modules_count], element->valuestring);
                                framework_config.docker.excluded_modules_count++;
                            }
                        }
                    }
                }

                node = cJSON_GetObjectItem(main_node, "excluded-features");
                if(node) {
                    if(cJSON_IsArray(node)) {
                        cJSON *element;
                        cJSON_ArrayForEach(element, node) {
                            if(cJSON_IsString(element)) {
                                log_add_verbose(2, "[framework-config] adding container-rules/excluded-features: %s\n", element->valuestring);
                                framework_config.docker.excluded_features = (char **)realloc(framework_config.docker.excluded_features, sizeof(char*) * (framework_config.docker.excluded_features_count + 1));
                                if(!framework_config.docker.excluded_features) {
                                    log_error("[framework-config] bad realloc\n");
                                }
                                framework_config.docker.excluded_features[framework_config.docker.excluded_features_count] = (char *)malloc(sizeof(char) * (strlen(element->valuestring) + 1));
                                if(!framework_config.docker.excluded_features[framework_config.docker.excluded_features_count]) {
                                    log_error("[framework-config] bad malloc\n");
                                }
                                strcpy(framework_config.docker.excluded_features[framework_config.docker.excluded_features_count], element->valuestring);
                                framework_config.docker.excluded_features_count++;
                            }
                        }
                    }
                }
            }
        }
        else if(framework_arguments.nts_mode == NTS_MODE_SUPERVISOR) {
            main_node = cJSON_GetObjectItem(json, "supervisor-rules");
            if(main_node) {
                cJSON *app;
                cJSON_ArrayForEach(app, main_node) {
                    if(cJSON_IsObject(app)) {
                        cJSON *object = cJSON_GetObjectItem(app, "path");
                        if(object) {
                            framework_config.supervisor.rules = (supervisor_rules_t *)realloc(framework_config.supervisor.rules, sizeof(supervisor_rules_t) * (framework_config.supervisor.rules_count + 1));
                            if(!framework_config.supervisor.rules) {
                                log_error("[framework-config] bad realloc\n");
                            }
                            
                            char *path = strdup(object->valuestring);
                            bool autorestart = false;
                            bool nomanual = false;
                            char *stdout_path = 0;
                            char *stderr_path = 0;

                            int args_count = 0;
                            char **args = 0;
                            cJSON *args_json = cJSON_GetObjectItem(app, "args");
                            if(args_json) {
                                args_count = cJSON_GetArraySize(args_json);
                                if(args_count) {
                                    args = malloc(sizeof(char *) * args_count);
                                    int i = 0;
                                    cJSON *arg;
                                    cJSON_ArrayForEach(arg, args_json) {
                                        args[i] = strdup(arg->valuestring);
                                        i++;
                                    }
                                }
                            }

                            object = cJSON_GetObjectItem(app, "autorestart");
                            if(object) {
                                autorestart = object->valueint;
                            }

                            object = cJSON_GetObjectItem(app, "nomanual");
                            if(object) {
                                nomanual = object->valueint;
                            }

                            object = cJSON_GetObjectItem(app, "stdout");
                            if(object) {
                                stdout_path = strdup(object->valuestring);
                            }

                            object = cJSON_GetObjectItem(app, "stderr");
                            if(object) {
                                stderr_path = strdup(object->valuestring);
                            }

                            framework_config.supervisor.rules[framework_config.supervisor.rules_count].name = strdup(app->string);
                            framework_config.supervisor.rules[framework_config.supervisor.rules_count].path = path;
                            framework_config.supervisor.rules[framework_config.supervisor.rules_count].args = args;
                            framework_config.supervisor.rules[framework_config.supervisor.rules_count].args_count = args_count;
                            framework_config.supervisor.rules[framework_config.supervisor.rules_count].autorestart = autorestart;
                            framework_config.supervisor.rules[framework_config.supervisor.rules_count].nomanual = nomanual;
                            framework_config.supervisor.rules[framework_config.supervisor.rules_count].stdout_path = stdout_path;
                            framework_config.supervisor.rules[framework_config.supervisor.rules_count].stderr_path = stderr_path;

                            log_add_verbose(2, "[framework-config] adding supervisor command: %s with autorestart: %d\n", path, autorestart);
                            framework_config.supervisor.rules_count++;
                        }
                    }
                }
            }
        }
        else {
            main_node = cJSON_GetObjectItem(json, "datastore-random-generation-rules");
            if(main_node) {
                node = cJSON_GetObjectItem(main_node, "excluded-modules");
                if(node) {
                    if(cJSON_IsArray(node)) {
                        cJSON *element;
                        cJSON_ArrayForEach(element, node) {
                            if(cJSON_IsString(element)) {
                                log_add_verbose(2, "[framework-config] adding datastore-random-generation-rules/excluded-modules: %s\n", element->valuestring);
                                framework_config.datastore_generate.excluded_modules = (char **)realloc(framework_config.datastore_generate.excluded_modules, sizeof(char*) * (framework_config.datastore_generate.excluded_modules_count + 1));
                                if(!framework_config.datastore_generate.excluded_modules) {
                                    log_error("[framework-config] bad realloc\n");
                                }
                                framework_config.datastore_generate.excluded_modules[framework_config.datastore_generate.excluded_modules_count] = (char *)malloc(sizeof(char) * (strlen(element->valuestring) + 1));
                                if(!framework_config.datastore_generate.excluded_modules[framework_config.datastore_generate.excluded_modules_count]) {
                                    log_error("[framework-config] bad malloc\n");
                                }
                                strcpy(framework_config.datastore_generate.excluded_modules[framework_config.datastore_generate.excluded_modules_count], element->valuestring);
                                framework_config.datastore_generate.excluded_modules_count++;
                            }
                        }
                    }
                }

                node = cJSON_GetObjectItem(main_node, "debug-max-string-size");
                if(node) {
                    framework_config.datastore_generate.debug_max_string_size = node->valueint;
                    log_add_verbose(2, "[framework-config] setting datastore-random-generation-rules/debug-max-string-size: %d\n", framework_config.datastore_generate.debug_max_string_size);
                }

                node = cJSON_GetObjectItem(main_node, "default-list-instances");
                if(node) {
                    if(cJSON_IsNumber(node)) {
                        framework_config.datastore_generate.default_list_instances = node->valueint;
                        log_add_verbose(2, "[framework-config] setting datastore-random-generation-rules/default-list-instances: %d\n", framework_config.datastore_generate.default_list_instances);
                    }
                }

                node = cJSON_GetObjectItem(main_node, "custom-list-instances");
                if(node) {
                    if(cJSON_IsArray(node)) {
                        cJSON *element;
                        cJSON_ArrayForEach(element, node) {
                            if(cJSON_IsObject(element)) {
                                cJSON *object;
                                cJSON_ArrayForEach(object, element) {
                                    char *path = object->string;
                                    int count = object->valueint;
                                    log_add_verbose(2, "[framework-config] adding datastore-random-generation-rules/custom-list-instances %s - %d\n", path, count);
                                    framework_config.datastore_generate.custom_list_instances = (custom_list_instances_t *)realloc(framework_config.datastore_generate.custom_list_instances, sizeof(custom_list_instances_t) * (framework_config.datastore_generate.custom_list_instances_count + 1));
                                    if(!framework_config.datastore_generate.custom_list_instances) {
                                        log_error("[framework-config] bad realloc\n");
                                    }
                                    
                                    framework_config.datastore_generate.custom_list_instances[framework_config.datastore_generate.custom_list_instances_count].path = (char *)malloc(sizeof(char) * (strlen(path) + 1));
                                    if(!framework_config.datastore_generate.custom_list_instances[framework_config.datastore_generate.custom_list_instances_count].path) {
                                        log_error("[framework-config] bad malloc\n");
                                    }
                                    strcpy(framework_config.datastore_generate.custom_list_instances[framework_config.datastore_generate.custom_list_instances_count].path, path);
                                    framework_config.datastore_generate.custom_list_instances[framework_config.datastore_generate.custom_list_instances_count].count = count;
                                    framework_config.datastore_generate.custom_list_instances_count++;
                                }
                            }
                        }
                    }
                }

                node = cJSON_GetObjectItem(main_node, "restrict-schema");
                if(node) {
                    if(cJSON_IsArray(node)) {
                        cJSON *element;
                        cJSON_ArrayForEach(element, node) {
                            if(cJSON_IsObject(element)) {
                                cJSON *object;
                                cJSON_ArrayForEach(object, element) {
                                    char *path = object->string;

                                    log_add_verbose(2, "[framework-config] adding datastore-random-generation-rules/restrict-schema: %s with values:", path);
                                    framework_config.datastore_generate.restrict_schema = (restrict_schema_t *)realloc(framework_config.datastore_generate.restrict_schema, sizeof(restrict_schema_t) * (framework_config.datastore_generate.restrict_schema_count + 1));
                                    if(!framework_config.datastore_generate.restrict_schema) {
                                        log_error("[framework-config] bad realloc\n");
                                    }
                                    
                                    framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].path = (char *)malloc(sizeof(char) * (strlen(path) + 1));
                                    if(!framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].path) {
                                        log_error("[framework-config] bad malloc\n");
                                    }
                                    strcpy(framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].path, path);


                                    framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values_count = 0;
                                    framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values = 0;
                                    framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].index = 0;
                                    cJSON *value;
                                    cJSON_ArrayForEach(value, object) {
                                        if(cJSON_IsString(value)) {
                                            framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values = (char **)realloc(framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values, sizeof(char*) * (framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values_count + 1));
                                            if(!framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values) {
                                                log_error("[framework-config] bad realloc\n");
                                            }
                                            framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values[framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values_count] = (char *)malloc(sizeof(char) * (strlen(value->valuestring) + 1));
                                            if(!framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values[framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values_count]) {
                                                log_error("[framework-config] bad malloc\n");
                                            }
                                            strcpy(framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values[framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values_count], value->valuestring);
                                            framework_config.datastore_generate.restrict_schema[framework_config.datastore_generate.restrict_schema_count].values_count++;

                                            log_add(2, " %s", value->valuestring);
                                        }
                                    }
                                    log_add(2, "\n");

                                    framework_config.datastore_generate.restrict_schema_count++;
                                }
                            }
                        }
                    }
                }
            }

            main_node = cJSON_GetObjectItem(json, "datastore-populate-rules");
            if(main_node) {
                node = cJSON_GetObjectItem(main_node, "random-generation-enabled");
                if(node) {
                    framework_config.datastore_populate.random_generation_enabled = node->valueint;
                    log_add_verbose(2, "[framework-config] setting datastore-populate-rules/random-generation-enabled: %d\n", framework_config.datastore_populate.random_generation_enabled);
                }
                else {
                    log_add_verbose(2, "[framework-config] setting datastore-populate-rules/random-generation-enabled: %d [default value]\n", framework_config.datastore_populate.random_generation_enabled);
                }
                
                node = cJSON_GetObjectItem(main_node, "pre-generated-operational-data");
                if(node) {
                    if(cJSON_IsArray(node)) {
                        cJSON *element;
                        cJSON_ArrayForEach(element, node) {
                            if(cJSON_IsString(element)) {
                                log_add_verbose(2, "[framework-config] adding datastore-populate-rules/pre-generated-operational-data: %s\n", element->valuestring);
                                framework_config.datastore_populate.preg_operational = (char **)realloc(framework_config.datastore_populate.preg_operational, sizeof(char*) * (framework_config.datastore_populate.preg_operational_count + 1));
                                if(!framework_config.datastore_populate.preg_operational) {
                                    log_error("[framework-config] bad realloc\n");
                                }
                                framework_config.datastore_populate.preg_operational[framework_config.datastore_populate.preg_operational_count] = (char *)malloc(sizeof(char) * (strlen(element->valuestring) + 1));
                                if(!framework_config.datastore_populate.preg_operational[framework_config.datastore_populate.preg_operational_count]) {
                                    log_error("[framework-config] bad malloc\n");
                                }
                                strcpy(framework_config.datastore_populate.preg_operational[framework_config.datastore_populate.preg_operational_count], element->valuestring);
                                framework_config.datastore_populate.preg_operational_count++;
                            }
                        }
                    }
                }

                node = cJSON_GetObjectItem(main_node, "pre-generated-running-data");
                if(node) {
                    if(cJSON_IsArray(node)) {
                        cJSON *element;
                        cJSON_ArrayForEach(element, node) {
                            if(cJSON_IsString(element)) {
                                log_add_verbose(2, "[framework-config] adding datastore-populate-rules/pre-generated-running-data: %s\n", element->valuestring);
                                framework_config.datastore_populate.preg_running = (char **)realloc(framework_config.datastore_populate.preg_running, sizeof(char*) * (framework_config.datastore_populate.preg_running_count + 1));
                                if(!framework_config.datastore_populate.preg_running) {
                                    log_error("[framework-config] bad realloc\n");
                                }
                                framework_config.datastore_populate.preg_running[framework_config.datastore_populate.preg_running_count] = (char *)malloc(sizeof(char) * (strlen(element->valuestring) + 1));
                                if(!framework_config.datastore_populate.preg_running[framework_config.datastore_populate.preg_running_count]) {
                                    log_error("[framework-config] bad malloc\n");
                                }
                                strcpy(framework_config.datastore_populate.preg_running[framework_config.datastore_populate.preg_running_count], element->valuestring);
                                framework_config.datastore_populate.preg_running_count++;
                            }
                        }
                    }
                }

            }
        }

        cJSON_Delete(json);
        
    }
    log_add_verbose(2, "[framework-config] finished parsing config.json\n");

    return NTS_ERR_OK;
}

void framework_free(void) {
    log_add_verbose(2, "[framework-config] framework_free()... ");

    signal(SIGINT, 0);
    signal(SIGTERM, 0);
    signal(SIGQUIT, 0);

    free((char *)argp_program_version);
    argp_program_version = 0;

    free(framework_environment.nts.version);
    free(framework_environment.nts.build_time);
    free(framework_environment.nts.function_type);
    free(framework_environment.nts.nf_standalone_start_features);
    free(framework_environment.nts.nf_mount_point_addressing_method);
    free(framework_environment.settings.ip_v4);
    free(framework_environment.settings.ip_v6);
    free(framework_environment.settings.docker_engine_version);
    free(framework_environment.settings.docker_repository);
    free(framework_environment.settings.hostname);
    free(framework_environment.host.ip);
    free(framework_environment.sdn_controller.protocol);
    free(framework_environment.sdn_controller.ip);
    free(framework_environment.sdn_controller.callhome_ip);
    free(framework_environment.sdn_controller.username);
    free(framework_environment.sdn_controller.password);
    free(framework_environment.ves_endpoint.common_header_version);
    free(framework_environment.ves_endpoint.protocol);
    free(framework_environment.ves_endpoint.ip);
    free(framework_environment.ves_endpoint.auth_method);
    free(framework_environment.ves_endpoint.username);
    free(framework_environment.ves_endpoint.password);
    free(framework_environment.ves_endpoint.certificate);

    free(framework_arguments.print_structure_xpath);
    framework_arguments.print_structure_xpath = 0;

    for(int i = 0; i < framework_config.supervisor.rules_count; i++) {
        free(framework_config.supervisor.rules[i].name);
        free(framework_config.supervisor.rules[i].path);
        for(int j = 0; j < framework_config.supervisor.rules[i].args_count; j++) {
            free(framework_config.supervisor.rules[i].args[j]);
        }
        free(framework_config.supervisor.rules[i].args);
        free(framework_config.supervisor.rules[i].stdout_path);
        free(framework_config.supervisor.rules[i].stderr_path);
    }

    free(framework_config.supervisor.rules);

    for(int i = 0; i < framework_config.docker.excluded_modules_count; i++) {
        free(framework_config.docker.excluded_modules[i]);
    }
    free(framework_config.docker.excluded_modules);

    for(int i = 0; i < framework_config.docker.excluded_features_count; i++) {
        free(framework_config.docker.excluded_features[i]);
    }
    free(framework_config.docker.excluded_features);
    
    for(int i = 0; i < framework_config.datastore_generate.excluded_modules_count; i++) {
        free(framework_config.datastore_generate.excluded_modules[i]);
    }
    free(framework_config.datastore_generate.excluded_modules);


    for(int i = 0; i < framework_config.datastore_generate.custom_list_instances_count; i++) {
        free(framework_config.datastore_generate.custom_list_instances[i].path);
        
    }
    free(framework_config.datastore_generate.custom_list_instances);

    for(int i = 0; i < framework_config.datastore_generate.restrict_schema_count; i++) {
        free(framework_config.datastore_generate.restrict_schema[i].path);
        for(int j = 0; j < framework_config.datastore_generate.restrict_schema[i].values_count; j++) {
            free(framework_config.datastore_generate.restrict_schema[i].values[j]);
        }
        free(framework_config.datastore_generate.restrict_schema[i].values);
    }
    free(framework_config.datastore_generate.restrict_schema);

    for(int i = 0; i < framework_config.datastore_populate.preg_operational_count; i++) {
        free(framework_config.datastore_populate.preg_operational[i]);
    }
    free(framework_config.datastore_populate.preg_operational);

    for(int i = 0; i < framework_config.datastore_populate.preg_running_count; i++) {
        free(framework_config.datastore_populate.preg_running[i]);
    }
    free(framework_config.datastore_populate.preg_running);


    log_add(2, "done\n");
    log_close();
}

static void framework_signal_handler(int signo) {
    framework_sigint = 1;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    framework_arguments_t *iter_arguments = state->input;
    switch (key) {
        case 'i':
            iter_arguments->nts_mode = NTS_MODE_CONTAINER_INIT;
            break;

        case 's':
            iter_arguments->nts_mode = NTS_MODE_SUPERVISOR;
            break;

        case 'm':
            iter_arguments->nts_mode = NTS_MODE_MANAGER;
            break;

        case 'f':
            iter_arguments->nts_mode = NTS_MODE_NETWORK_FUNCTION;
            break;

        case 'b':
            iter_arguments->nts_mode = NTS_MODE_BLANK;
            break;

        case 't':
            iter_arguments->nts_mode = NTS_MODE_TEST;
            break;

        case 'r':
            iter_arguments->no_rand = true;
            framework_arguments.fixed_seed = 0;
            int i = 0;
            while(arg[i]) {
                framework_arguments.fixed_seed *= 10;
                framework_arguments.fixed_seed += arg[i] - '0';
                i++;
            }
            break;

        case 'v':
            iter_arguments->verbosity_level = arg[0] - '0';
            break;

        case 'w':
            chdir(arg);
            break;

        case '1':
            iter_arguments->print_root_paths = true;
            break;

        case '2':
            iter_arguments->print_structure_xpath = (char *)malloc(sizeof(char) * (strlen(arg) + 1));
            if(!iter_arguments->print_structure_xpath) {
                log_error("[framework-arg] bad malloc\n");
                return 1;
            }
            strcpy(iter_arguments->print_structure_xpath, arg);
            if(arg[strlen(arg) - 1] == '/') {
                iter_arguments->print_structure_xpath[strlen(arg) - 1] = 0;
            }
            break;

        case ARGP_KEY_ARG:
            if (state->arg_num >= 2) {
                argp_usage(state);
            }
            break;

        case ARGP_KEY_END:

            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }
    
    return 0;
}
