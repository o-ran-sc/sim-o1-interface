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
framework_config_t framework_config;
framework_environment_t framework_environment;

const char *argp_program_version = "ntsim-ng v1.0.0";
const char *argp_program_bug_address = "<alexandru.stancu@highstreet-technologies.com> / <adrian.lita@highstreet-technologies.com>";
static char doc[] = "ntsim - new generation";

static struct argp_option options[] = {
    // docker init functionality, independent from rest of the app
    { "docker-init", 'i', 0, 0, "Runs initialization tasks for the Docker container that's being built. Do not run manually." },

    // daemon modes (choose only one)
    { "manager", 'm', 0, 0, "Run the daemon as manager." },
    { "network-function", 'f', 0, 0, "Run the daemon as network function." },

    // global settings, can be combined
    { "operational-only", 'o', 0, 0, "When this is set, the RUNNING datastore is actually the OPERATIONAL one." },
    { "fixed-rand", 'r', "SEED", 0, "Initialize RAND seed to a fixed value (for debugging purposes)." },
    { "verbose", 'v', "LEVEL", 0, "Verbosity level for printing to stdout (logs will still save everything). LEVEL is: 0=errors only, 1=requested info(default), 2=info" },
    { "workspace", 'w', "PATH", 0, "Initialize workspace to a different one than the current working directory." },

    // test modes (choose only one)
    { "test-mode", 't', 0, 0, "Test mode to be deleted after." },
    { "exhaustive-test", '0', 0, 0, "Do an automated test on the whole delpoy." },

    // functions, can be combined
    { "ls", '1', 0, 0, "Print all available root paths." },
    { "schema", '2', "XPATH", 0, "Print schema for XPATH." },
    { "populate", '3', 0, 0, "Populate everything." },
    { "enable-features", '4', 0, 0, "Enables features. Usually works combined with populate." },

    // function settings, can be combined with functions as well
    { "nc-server-init", 'n', 0, 0, "Sets netconf server configuration." },
    { "loop", 'l', 0, 0, "After doing the job, don't exit until CTRL+C is pressed." },
    { 0 } 
};

volatile sig_atomic_t framework_sigint;
static void framework_signal_handler(int signo);

static error_t parse_opt(int key, char *arg, struct argp_state *state);

void framework_init(int argc, char **argv) {
    //initialize app arguments
    framework_arguments.container_init = false;
    framework_arguments.nc_server_init = false;

    framework_arguments.manager = false;
    framework_arguments.network_function = false;
    
    framework_arguments.no_rand = false;
    framework_arguments.fixed_seed = 0;
    framework_arguments.operational_only = false;
    framework_arguments.verbosity_level = 1;
    framework_arguments.loop = false;
    framework_arguments.test_mode = false;
    
    framework_arguments.exhaustive_test = false;
    framework_arguments.print_root_paths = false;
    framework_arguments.print_structure_xpath = 0;
    framework_arguments.populate_all = false;
    framework_arguments.enable_features = false;

    framework_sigint = 0;
    signal(SIGINT, framework_signal_handler);
    signal(SIGTERM, framework_signal_handler);
    signal(SIGKILL, framework_signal_handler);
    signal(SIGQUIT, framework_signal_handler);

    //parse provided command line arguments
    struct argp argp = { options, parse_opt, 0, doc, 0, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, &framework_arguments);

    //disable buffering for stdout
    setbuf(stdout, NULL);

    int status = 0;

    //test whether log and config folders are ok
    if(!dir_exists("config")) {
        status |= 1;
        mkdir("config", 0777);
    }

    if(!dir_exists("log")) {
        status |= 2;
        mkdir("log", 0777);
    }

    //init logging subsystem
    log_init("log/log.txt");
    log_message(2, "app was called: ");
    for(int i = 0; i < argc; i++) {
        log_message(2, "%s ", argv[i]);
    }
    log_message(2, "\n");

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    log_message(2, "current working dir is: %s\n", cwd);

    if(status & 1) {
        log_message(2, "config folder wasn't found, and was created.\n");
    }

    if(status & 2) {
        log_message(2, "log folder wasn't found, and was created.\n");
    }

    if(!file_exists("config/config.json")) {
        log_message(2, "config.json file missing. created.\n");
        file_touch("config/config.json", "{}");
    }

    //init rand generator if needed
    if(framework_arguments.no_rand == false) {
        rand_init();
    }
    else {
        rand_init_fixed(framework_arguments.fixed_seed);
    }

    //init app config
    framework_config.docker_excluded_modules = 0;
    framework_config.docker_excluded_modules_count = 0;
    framework_config.docker_excluded_features = 0;
    framework_config.docker_excluded_features_count = 0;
    framework_config.debug_max_string_size = 0;
    framework_config.populate_excluded_modules = 0;
    framework_config.populate_excluded_modules_count = 0;
    framework_config.default_list_instances = 1;
    framework_config.custom_list_instances_count = 0;
    framework_config.custom_list_instances = 0;
    framework_config.restrict_schema_count = 0;
    framework_config.restrict_schema = 0;

    log_message(2, "starting parsing config.json\n");
    char *config_contents = file_read_content("config/config.json");
    cJSON *json = cJSON_Parse(config_contents);
    free(config_contents);
    if(!json) {
        log_error("config.json :%s", cJSON_GetErrorPtr());
    }
    else {
        cJSON *main_node;
        cJSON *node;

        main_node = cJSON_GetObjectItem(json, "docker-rules");
        if(main_node) {
            node = cJSON_GetObjectItem(main_node, "excluded-modules");
            if(node) {
                if(cJSON_IsArray(node)) {
                    cJSON *element;
                    cJSON_ArrayForEach(element, node) {
                        if(cJSON_IsString(element)) {
                            log_message(2, "adding docker-rules/exclude-modules: %s\n", element->valuestring);
                            framework_config.docker_excluded_modules = (char **)realloc(framework_config.docker_excluded_modules, sizeof(char*) * (framework_config.docker_excluded_modules_count + 1));
                            if(!framework_config.docker_excluded_modules) {
                                log_error("bad realloc");
                            }
                            framework_config.docker_excluded_modules[framework_config.docker_excluded_modules_count] = (char *)malloc(sizeof(char) * (strlen(element->valuestring) + 1));
                            if(!framework_config.docker_excluded_modules[framework_config.docker_excluded_modules_count]) {
                                log_error("bad malloc");
                            }
                            strcpy(framework_config.docker_excluded_modules[framework_config.docker_excluded_modules_count], element->valuestring);
                            framework_config.docker_excluded_modules_count++;
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
                            log_message(2, "adding docker-rules/excluded-features: %s\n", element->valuestring);
                            framework_config.docker_excluded_features = (char **)realloc(framework_config.docker_excluded_features, sizeof(char*) * (framework_config.docker_excluded_features_count + 1));
                            if(!framework_config.docker_excluded_features) {
                                log_error("bad realloc");
                            }
                            framework_config.docker_excluded_features[framework_config.docker_excluded_features_count] = (char *)malloc(sizeof(char) * (strlen(element->valuestring) + 1));
                            if(!framework_config.docker_excluded_features[framework_config.docker_excluded_features_count]) {
                                log_error("bad malloc");
                            }
                            strcpy(framework_config.docker_excluded_features[framework_config.docker_excluded_features_count], element->valuestring);
                            framework_config.docker_excluded_features_count++;
                        }
                    }
                }
            }
        }

        main_node = cJSON_GetObjectItem(json, "debug-max-string-size");
        if(main_node) {
            framework_config.debug_max_string_size = main_node->valueint;
            log_message(2, "setting debug-max-string-sizes: %d\n", framework_config.debug_max_string_size);
        }

        main_node = cJSON_GetObjectItem(json, "populate-rules");
        if(main_node) {
            node = cJSON_GetObjectItem(main_node, "excluded-modules");
            if(node) {
                if(cJSON_IsArray(node)) {
                    cJSON *element;
                    cJSON_ArrayForEach(element, node) {
                        if(cJSON_IsString(element)) {
                            log_message(2, "adding populate-rules/excluded-modules: %s\n", element->valuestring);
                            framework_config.populate_excluded_modules = (char **)realloc(framework_config.populate_excluded_modules, sizeof(char*) * (framework_config.populate_excluded_modules_count + 1));
                            if(!framework_config.populate_excluded_modules) {
                                log_error("bad realloc");
                            }
                            framework_config.populate_excluded_modules[framework_config.populate_excluded_modules_count] = (char *)malloc(sizeof(char) * (strlen(element->valuestring) + 1));
                            if(!framework_config.populate_excluded_modules[framework_config.populate_excluded_modules_count]) {
                                log_error("bad malloc");
                            }
                            strcpy(framework_config.populate_excluded_modules[framework_config.populate_excluded_modules_count], element->valuestring);
                            framework_config.populate_excluded_modules_count++;
                        }
                    }
                }
            }

            node = cJSON_GetObjectItem(main_node, "default-list-instances");
            if(node) {
                if(cJSON_IsNumber(node)) {
                    framework_config.default_list_instances = node->valueint;
                    log_message(2, "found populate-rules/default-list-instances to be: %d\n", framework_config.default_list_instances);
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
                                log_message(2, "adding populate-rules/custom-list-instances %s - %d\n", path, count);
                                framework_config.custom_list_instances = (custom_list_instances_t *)realloc(framework_config.custom_list_instances, sizeof(custom_list_instances_t) * (framework_config.custom_list_instances_count + 1));
                                if(!framework_config.custom_list_instances) {
                                    log_error("bad realloc");
                                }
                                
                                framework_config.custom_list_instances[framework_config.custom_list_instances_count].path = (char *)malloc(sizeof(char) * (strlen(path) + 1));
                                if(!framework_config.custom_list_instances[framework_config.custom_list_instances_count].path) {
                                    log_error("bad malloc");
                                }
                                strcpy(framework_config.custom_list_instances[framework_config.custom_list_instances_count].path, path);
                                framework_config.custom_list_instances[framework_config.custom_list_instances_count].count = count;
                                framework_config.custom_list_instances_count++;
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

                                log_message(2, "adding populate-rules/restrict-schema: %s with values:", path);
                                framework_config.restrict_schema = (restrict_schema_t *)realloc(framework_config.restrict_schema, sizeof(restrict_schema_t) * (framework_config.restrict_schema_count + 1));
                                if(!framework_config.restrict_schema) {
                                    log_error("bad realloc");
                                }
                                
                                framework_config.restrict_schema[framework_config.restrict_schema_count].path = (char *)malloc(sizeof(char) * (strlen(path) + 1));
                                if(!framework_config.restrict_schema[framework_config.restrict_schema_count].path) {
                                    log_error("bad malloc");
                                }
                                strcpy(framework_config.restrict_schema[framework_config.restrict_schema_count].path, path);


                                framework_config.restrict_schema[framework_config.restrict_schema_count].values_count = 0;
                                framework_config.restrict_schema[framework_config.restrict_schema_count].values = 0;
                                framework_config.restrict_schema[framework_config.restrict_schema_count].index = 0;
                                cJSON *value;
                                cJSON_ArrayForEach(value, object) {
                                    if(cJSON_IsString(value)) {
                                        framework_config.restrict_schema[framework_config.restrict_schema_count].values = (char **)realloc(framework_config.restrict_schema[framework_config.restrict_schema_count].values, sizeof(char*) * (framework_config.restrict_schema[framework_config.restrict_schema_count].values_count + 1));
                                        if(!framework_config.restrict_schema[framework_config.restrict_schema_count].values) {
                                            log_error("bad realloc");
                                        }
                                        framework_config.restrict_schema[framework_config.restrict_schema_count].values[framework_config.restrict_schema[framework_config.restrict_schema_count].values_count] = (char *)malloc(sizeof(char) * (strlen(value->valuestring) + 1));
                                        if(!framework_config.restrict_schema[framework_config.restrict_schema_count].values[framework_config.restrict_schema[framework_config.restrict_schema_count].values_count]) {
                                            log_error("bad malloc");
                                        }
                                        strcpy(framework_config.restrict_schema[framework_config.restrict_schema_count].values[framework_config.restrict_schema[framework_config.restrict_schema_count].values_count], value->valuestring);
                                        framework_config.restrict_schema[framework_config.restrict_schema_count].values_count++;

                                        log_message(2, " %s", value->valuestring);
                                    }
                                }
                                log_message(2, "\n");

                                framework_config.restrict_schema_count++;
                            }
                        }
                    }
                }
            }
        }

        cJSON_free(json);
        
    }
    log_message(2, "finished parsing config.json\n");

    //environment vars
    bool ip_ok = get_local_ips("eth0", &framework_environment.ip_v4, &framework_environment.ip_v6);
    if(!ip_ok) {
        log_error("could not get local IP addresses");
    }

    char *ipv6_env_var = getenv(ENV_VAR_IPV6ENABLED);
    if(ipv6_env_var == 0) {
        log_error("could not get the IPv6 Enabled env variable");
    }
    framework_environment.ip_v6_enabled = (strcmp(ipv6_env_var, "true") == 0) ? true : false;


    framework_environment.docker_engine_version = getenv(ENV_VAR_DOCKER_ENGINE_VERSION) ? strdup(getenv(ENV_VAR_DOCKER_ENGINE_VERSION)) : strdup("1.40");
    framework_environment.hostname = getenv(ENV_VAR_HOSTNAME) ? strdup(getenv(ENV_VAR_HOSTNAME)) : strdup("localhost");
    framework_environment.host_ip = getenv(ENV_VAR_HOST_IP) ? strdup(getenv(ENV_VAR_HOST_IP)) : strdup("127.0.0.1");
    framework_environment.host_base_port = get_int_from_string_with_default(getenv(ENV_VAR_HOST_BASE_PORT), 1000);
    framework_environment.ssh_connections = get_int_from_string_with_default(getenv(ENV_VAR_SSH_CONNECTIONS), 1);
    framework_environment.tls_connections = get_int_from_string_with_default(getenv(ENV_VAR_TLS_CONNECTIONS), 0);
    framework_environment.ftp_connections = 1;
    framework_environment.sftp_connections = 1;

    framework_environment.sdn_controller_ip = getenv(ENV_VAR_SDN_CONTROLLER_IP) ? strdup(getenv(ENV_VAR_SDN_CONTROLLER_IP)) : strdup("127.0.0.1");
    framework_environment.sdn_controller_port = get_int_from_string_with_default(getenv(ENV_VAR_SDN_CONTROLLER_PORT), 8181);
    framework_environment.sdn_controller_callhome_port = get_int_from_string_with_default(getenv(ENV_VAR_SDN_CONTROLLER_CALLHOME_PORT), 6666);
    framework_environment.sdn_controller_username = getenv(ENV_VAR_SDN_CONTROLLER_USERNAME) ? strdup(getenv(ENV_VAR_SDN_CONTROLLER_USERNAME)) : strdup("admin");
    framework_environment.sdn_controller_password = getenv(ENV_VAR_SDN_CONTROLLER_PASSWORD) ? strdup(getenv(ENV_VAR_SDN_CONTROLLER_PASSWORD)) : strdup("admin");

    framework_environment.ves_endpoint_protocol = getenv(ENV_VAR_VES_ENDPOINT_PROTOCOL) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_PROTOCOL)) : strdup("https");
    framework_environment.ves_endpoint_ip = getenv(ENV_VAR_VES_ENDPOINT_IP) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_IP)) : strdup("127.0.0.1");
    framework_environment.ves_endpoint_port = get_int_from_string_with_default(getenv(ENV_VAR_VES_ENDPOINT_PORT), 1234);
    framework_environment.ves_endpoint_auth_method = getenv(ENV_VAR_VES_ENDPOINT_AUTH_METHOD) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_AUTH_METHOD)) : strdup("no-auth");
    framework_environment.ves_endpoint_username = getenv(ENV_VAR_VES_ENDPOINT_USERNAME) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_USERNAME)) : strdup("admin");
    framework_environment.ves_endpoint_password = getenv(ENV_VAR_VES_ENDPOINT_PASSWORD) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_PASSWORD)) : strdup("admin");
    framework_environment.ves_endpoint_certificate = getenv(ENV_VAR_VES_ENDPOINT_CERTIFICATE) ? strdup(getenv(ENV_VAR_VES_ENDPOINT_CERTIFICATE)) : strdup("");

    log_message(2, "[env] ip_v6_enabled = %s\n", framework_environment.ip_v6_enabled ? "true" : "false");
    log_message(2, "[env] ip_v4 = %s\n", framework_environment.ip_v4);
    log_message(2, "[env] ip_v6 = %s\n", framework_environment.ip_v6);
    log_message(2, "[env] docker_engine_version = %s\n", framework_environment.docker_engine_version);
    log_message(2, "[env] hostname = %s\n", framework_environment.hostname);
    log_message(2, "[env] host_ip = %s\n", framework_environment.host_ip);
    log_message(2, "[env] host_base_port = %d\n", framework_environment.host_base_port);
    log_message(2, "[env] ssh_connections = %d\n", framework_environment.ssh_connections);
    log_message(2, "[env] tls_connections = %d\n", framework_environment.tls_connections);
    log_message(2, "[env] ftp_connections = %d\n", framework_environment.ftp_connections);
    log_message(2, "[env] sftp_connections = %d\n", framework_environment.sftp_connections);

    log_message(2, "[env] sdn_controller_ip = %s\n", framework_environment.sdn_controller_ip);
    log_message(2, "[env] sdn_controller_port = %d\n", framework_environment.sdn_controller_port);
    log_message(2, "[env] sdn_controller_callhome_port = %d\n", framework_environment.sdn_controller_callhome_port);
    log_message(2, "[env] sdn_controller_username = %s\n", framework_environment.sdn_controller_username);
    log_message(2, "[env] sdn_controller_password = %s\n", framework_environment.sdn_controller_password);

    log_message(2, "[env] ves_endpoint_protocol = %s\n", framework_environment.ves_endpoint_protocol);
    log_message(2, "[env] ves_endpoint_ip = %s\n", framework_environment.ves_endpoint_ip);
    log_message(2, "[env] ves_endpoint_port = %d\n", framework_environment.ves_endpoint_port);
    log_message(2, "[env] ves_endpoint_auth_method = %s\n", framework_environment.ves_endpoint_auth_method);
    log_message(2, "[env] ves_endpoint_username = %s\n", framework_environment.ves_endpoint_username);
    log_message(2, "[env] ves_endpoint_password = %s\n", framework_environment.ves_endpoint_password);
    log_message(2, "[env] ves_endpoint_certificate = %s\n", framework_environment.ves_endpoint_certificate);

    log_message(2, "finished environment vars\n");
}

void framework_free(void) {
    log_message(2, "framework_free()... ");

    free(framework_environment.ip_v4);
    free(framework_environment.ip_v6);
    free(framework_environment.docker_engine_version);
    free(framework_environment.hostname);
    free(framework_environment.host_ip);
    free(framework_environment.sdn_controller_ip);
    free(framework_environment.sdn_controller_username);
    free(framework_environment.sdn_controller_password);
    free(framework_environment.ves_endpoint_protocol);
    free(framework_environment.ves_endpoint_ip);
    free(framework_environment.ves_endpoint_auth_method);
    free(framework_environment.ves_endpoint_username);
    free(framework_environment.ves_endpoint_password);
    free(framework_environment.ves_endpoint_certificate);

    if(framework_arguments.print_structure_xpath) {
        free(framework_arguments.print_structure_xpath);
        framework_arguments.print_structure_xpath = 0;
    }

    if(framework_config.docker_excluded_modules_count) {
        for(int i = 0; i < framework_config.docker_excluded_modules_count; i++) {
            free(framework_config.docker_excluded_modules[i]);
        }
        free(framework_config.docker_excluded_modules);
    }

    if(framework_config.docker_excluded_features_count) {
        for(int i = 0; i < framework_config.docker_excluded_features_count; i++) {
            free(framework_config.docker_excluded_features[i]);
        }
        free(framework_config.docker_excluded_features);
    }

    if(framework_config.populate_excluded_modules_count) {
        for(int i = 0; i < framework_config.populate_excluded_modules_count; i++) {
            free(framework_config.populate_excluded_modules[i]);
        }
        free(framework_config.populate_excluded_modules);
    }

    for(int i = 0; i < framework_config.custom_list_instances_count; i++) {
        free(framework_config.custom_list_instances[i].path);
        
    }
    free(framework_config.custom_list_instances);

    for(int i = 0; i < framework_config.restrict_schema_count; i++) {
        free(framework_config.restrict_schema[i].path);
        for(int j = 0; j < framework_config.restrict_schema[i].values_count; j++) {
            free(framework_config.restrict_schema[i].values[j]);
        }
        free(framework_config.restrict_schema[i].values);
    }
    free(framework_config.restrict_schema);

    log_message(2, "done\n");
    log_close();
    if(framework_arguments.container_init) {
        rename("log/log.txt", "log/install_log.txt");
    }
}

bool framework_is_docker_excluded_module(const char *module) {
    assert(module);

    for(int i = 0; i < framework_config.docker_excluded_modules_count; i++) {
        if(strstr(module, framework_config.docker_excluded_modules[i]) != 0) {
            return true;
        }
    }
    
    return false;
}

bool framework_is_docker_excluded_feature(const char *feature) {
    assert(feature);

    for(int i = 0; i < framework_config.docker_excluded_features_count; i++) {
        if(strstr(feature, framework_config.docker_excluded_features[i]) != 0) {
            return true;
        }
    }
    
    return false;
}

bool framework_is_populate_excluded_module(const char *module) {
    assert(module);

    for(int i = 0; i < framework_config.populate_excluded_modules_count; i++) {
        if(strstr(module, framework_config.populate_excluded_modules[i]) != 0) {
            return true;
        }
    }
    
    return false;
}

int framework_populate_get_instance_count(const char *path) {
    assert(path);

    for(int i = 0; i < framework_config.custom_list_instances_count; i++) {
        if(strcmp(path, framework_config.custom_list_instances[i].path) == 0) {
            return framework_config.custom_list_instances[i].count;
        }
    }
    return framework_config.default_list_instances;
}

char *framework_populate_get_restrict_schema(const char *path) {
    assert(path);
    char *ret = 0;

    for(int i = 0; i < framework_config.restrict_schema_count; i++) {
        if(strcmp(path, framework_config.restrict_schema[i].path) == 0) {
            ret = strdup(framework_config.restrict_schema[i].values[framework_config.restrict_schema[i].index]);
            framework_config.restrict_schema[i].index++;
            if(framework_config.restrict_schema[i].index >= framework_config.restrict_schema[i].values_count) {
                framework_config.restrict_schema[i].index = 0;
            }
            break;
        }
    }

    return ret;
}

static void framework_signal_handler(int signo) {
    framework_sigint = 1;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    framework_arguments_t *iter_arguments = state->input;
    switch (key) {
        case 'i':
            iter_arguments->container_init = true;
            break;

        case 'n':
            iter_arguments->nc_server_init = true;
            break;

        case 'm':
            iter_arguments->manager = true;
            break;

        case 'f':
            iter_arguments->network_function = true;
            break;


        case 'l':
            iter_arguments->loop = true;
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

        case 'o':
            iter_arguments->operational_only = true;
            break;

        case 't':
            iter_arguments->test_mode = true;
            break;

        case 'v':
            iter_arguments->verbosity_level = arg[0] - '0';
            break;

        case 'w':
            chdir(arg);
            break;

        case '0':
            iter_arguments->exhaustive_test = true;
            break;

        case '1':
            iter_arguments->print_root_paths = true;
            break;

        case '2':
            iter_arguments->print_structure_xpath = (char *)malloc(sizeof(char) * (strlen(arg) + 1));
            if(!iter_arguments->print_structure_xpath) {
                log_error("very bad malloc failure here");
                return 1;
            }
            strcpy(iter_arguments->print_structure_xpath, arg);
            if(arg[strlen(arg) - 1] == '/') {
                iter_arguments->print_structure_xpath[strlen(arg) - 1] = 0;
            }
            break;

        case '3':
            iter_arguments->populate_all = true;
            break;

        case '4':
            iter_arguments->enable_features = true;
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
