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

#include "docker.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/http_client.h"
#include "core/framework.h"
#include "core/session.h"
#include "core/context.h"
#include <sysrepo.h>
#include <dirent.h>
#include <assert.h>
#include <sys/sysinfo.h>

#include <cjson/cJSON.h>

#define DOCKER_SOCK_FNAME       "/var/run/docker.sock"

static cJSON *docker_network_info = 0;

struct installable_module {
    char *name;
    char *fullpath;
    bool installed;
    bool submodule;
};

typedef struct {
    char *name;
    char *value;
} environment_var_t;

static environment_var_t *docker_environment_var;
static int docker_environment_var_count = 0;

static int get_installable_modules(struct installable_module **modules);    //list available modules for install
static void list_yangs(const char *path, struct installable_module **modules, int *total);

static char *docker_parse_json_message(const char *json_string);

static int docker_container_create(const char *image, manager_network_function_instance_t *instance);
static int docker_container_start(manager_network_function_instance_t *instance);
static int docker_container_inspect(manager_network_function_instance_t *instance);


bool docker_container_init(void) {
    int rc;

    sr_log_stderr(SR_LL_NONE);
    log_message(1, "Entering container-init mode...\n");

    // connect to sysrepo
    rc = sr_connect(0, &session_connection);
    if(SR_ERR_OK != rc) {
        log_error("sr_connect failed");
        return false;
    }

    /* get context */
    session_context = (struct ly_ctx *)sr_get_context(session_connection);
    if(session_context == 0) {
        log_error("sr_get_context failed");
        return false;
    }

    /* install yang files */
    log_message(1, "Installing yang files...\n");
    struct installable_module *modules;
    int total_modules = get_installable_modules(&modules);
    log_message(1, "Found total modules: %d\n", total_modules);

    int old_failed_installations = 1;
    int failed_installations = 0;
    int install_round = 0;
    while(failed_installations != old_failed_installations) {
        old_failed_installations = failed_installations;
        failed_installations = 0;
        install_round++;
        for(int i = 0; i < total_modules; i++) {
            if(!modules[i].installed) {
                modules[i].submodule = context_yang_is_module(modules[i].fullpath);
                if(!modules[i].submodule) {
                    if(!framework_is_docker_excluded_module(modules[i].name)) {
                        log_message(1, "[round %d] trying to install module %s from %s... ", install_round, modules[i].name, modules[i].fullpath);
                        if(!context_module_install(modules[i].name, modules[i].fullpath)) {
                            failed_installations++;
                            log_message(1, LOG_COLOR_BOLD_YELLOW"failed"LOG_COLOR_RESET"\n");
                        }
                        else {
                            log_message(1, LOG_COLOR_BOLD_GREEN"done"LOG_COLOR_RESET"\n");
                            modules[i].installed = true;
                        }
                    }
                    else {
                        log_message(1, "[round %d] not installing module %s as it's excluded in config.\n", install_round, modules[i].name);
                        modules[i].installed = true;
                    }
                }
                else {
                    log_message(1, "[round %d] %s is a submodule... "LOG_COLOR_BOLD_YELLOW"skipping"LOG_COLOR_RESET"\n", install_round, modules[i].name);
                    modules[i].installed = true;
                }
            }
        }
    }

    if(failed_installations != 0) {
        log_error("Failed to install all modules in %d rounds...", install_round);
        return false;
    }
    else {
        log_message(1, LOG_COLOR_BOLD_GREEN"successfully"LOG_COLOR_RESET" installed "LOG_COLOR_BOLD_GREEN"ALL"LOG_COLOR_RESET" modules in "LOG_COLOR_BOLD_YELLOW"%d"LOG_COLOR_RESET" rounds\n", (install_round - 1));
    }

    //set access for all installed modules
    log_message(1, "Setting access configuration for installed modules... ");
    for(int i = 0; i < total_modules; i++) {
        if((!framework_is_docker_excluded_module(modules[i].name)) && (!modules[i].submodule)) {
            if(!context_module_set_access(modules[i].name)) {
                log_error("Failed to set access to module %s...", modules[i].name);
                return false;
            }
        }
    }
    log_message(1, LOG_COLOR_BOLD_GREEN"done"LOG_COLOR_RESET"\n");

    //cleanup module-install used memory
    for(int i = 0; i < total_modules; i++) {
        free(modules[i].name);
        free(modules[i].fullpath);
    }
    free(modules);

    //get context
    session_context = (struct ly_ctx *)sr_get_context(session_connection);
    if(session_context == 0) {
        log_error("sr_get_context failed");
        return false;
    }

    //init context so we can see all the available modules, features, etc
    rc = context_init(session_context);
    if(rc != 0) {
        log_error("context_init() failed");
        return false;
    }

    /* enable features */
    log_message(1, "Enabling yang features...\n");
    char **available_features;
    int total_available_features;
    total_available_features = context_get_features(&available_features);
    log_message(1, "Found total features: %d\n", total_available_features);
    for(int i = 0; i < total_available_features; i++) {
        log_message(1, "feature %s: ", available_features[i]);

        if(!context_get_feature_enabled(available_features[i])) {
            if(!framework_is_docker_excluded_feature(available_features[i])) {
                if(context_feature_enable(available_features[i])) {
                    log_message(1, "enabling... "LOG_COLOR_BOLD_GREEN"done"LOG_COLOR_RESET"\n");
                }
                else {
                    log_error("enabling... failed\n");
                }
            }
            else {
                log_message(1, "excluded in config, skipping\n");
            }
        }
        else {
            log_message(1, "already "LOG_COLOR_BOLD_GREEN"enabled"LOG_COLOR_RESET", skipping.\n");
        }
    }
    for(int i = 0; i < total_available_features; i++) {
        free(available_features[i]);
    }
    free(available_features);

    sr_disconnect(session_connection);
    context_free();

    log_message(1, LOG_COLOR_BOLD_GREEN"ntsim successfully initialized Docker container"LOG_COLOR_RESET"\n");
    return true;
}

static int get_installable_modules(struct installable_module **modules) {
    int total = 0;
    *modules = 0;
    list_yangs("/opt/dev/deploy/yang", modules, &total);
    return total;
}

static void list_yangs(const char *path, struct installable_module **modules, int *total) {
    DIR *d;
    struct dirent *dir;
    d = opendir(path);
    if(d) {
        while((dir = readdir(d)) != NULL) {
            if(dir->d_type == DT_DIR) {
                if(strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
                {
                    char new_path[1024];
                    snprintf(new_path, sizeof(new_path), "%s/%s", path, dir->d_name);
                    list_yangs(new_path, modules, total);
                }
            } else {
                if(strstr(dir->d_name, ".yang") != 0) {
                    *modules = (struct installable_module *)realloc(*modules, sizeof(struct installable_module) * (*total + 1));
                    if(!*modules) {
                        log_error("could not realloc");
                        return;
                    }

                    (*modules)[*total].name = (char*)malloc(sizeof(char) * (strlen(dir->d_name) + 1));
                    if(!(*modules)[*total].name) {
                        log_error("could not alloc");
                        return;
                    }
                    strcpy((*modules)[*total].name, dir->d_name);
                    (*modules)[*total].name[strlen(dir->d_name) - 5] = 0;   //extract ".yang"
                    char *rev = strstr((*modules)[*total].name, "@");
                    if(rev) { //extract revision, if exists
                        *rev = 0;
                    }

                    (*modules)[*total].fullpath = (char*)malloc(sizeof(char) * (strlen(path) + 1 + strlen(dir->d_name) + 1));
                    if(!(*modules)[*total].fullpath) {
                        log_error("could not alloc");
                        return;
                    }
                    sprintf((*modules)[*total].fullpath, "%s/%s", path, dir->d_name);

                    (*modules)[*total].installed = false;
                    (*modules)[*total].submodule = false;

                    (*total)++;
                }
            }
        }
        closedir(d);
    }
}

int docker_device_init(void) {
    char *response = 0;
    char url[512];
    sprintf(url, "http://v%s/containers/%s/json", framework_environment.docker_engine_version, framework_environment.hostname);

    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "GET", 0, 0, &response);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed");
        return NTS_ERR_FAILED;
    }

    cJSON *json_response = cJSON_Parse(response);
    free(response);

    if(json_response == 0) {
        log_error("could not parse JSON response for url=\"%s\"", url);
        return NTS_ERR_FAILED;
    }

    cJSON *hostConfig = cJSON_GetObjectItemCaseSensitive(json_response, "HostConfig");
    if(hostConfig == 0) {
        log_error("could not get HostConfig object");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    cJSON *networkMode = cJSON_GetObjectItemCaseSensitive(hostConfig, "NetworkMode");
    if(networkMode == 0) {
        log_error("could not get NetworkMode object");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    docker_network_info = cJSON_Duplicate(networkMode, 1);
    cJSON_Delete(json_response);

    log_message(2, "finished parsing docker inspect...\n");


    docker_environment_var_count = 5;
    docker_environment_var = (environment_var_t *)malloc(sizeof(environment_var_t) * docker_environment_var_count);
    if(docker_environment_var == 0) {
        log_error("malloc failed");
        cJSON_Delete(networkMode);
        return NTS_ERR_FAILED;
    }
    
    //set env variables for network functions
    docker_environment_var[0].name = ENV_VAR_SSH_CONNECTIONS;
    asprintf(&docker_environment_var[0].value, "%d", framework_environment.ssh_connections);
    docker_environment_var[1].name = ENV_VAR_TLS_CONNECTIONS;
    asprintf(&docker_environment_var[1].value, "%d", framework_environment.tls_connections);
    docker_environment_var[2].name = ENV_VAR_IPV6ENABLED;
    docker_environment_var[2].value = framework_environment.ip_v6_enabled ? "true" : "false";
    docker_environment_var[3].name = ENV_VAR_HOST_IP;
    docker_environment_var[3].value = framework_environment.host_ip;
    docker_environment_var[4].name = ENV_VAR_HOST_BASE_PORT;
    // docker_environment_var[4].value = will be updated by docker_create...

    return NTS_ERR_OK;
}

int docker_device_start(const manager_network_function_type *function_type, manager_network_function_instance_t *instance) {
    assert(function_type);
    assert(instance);
    assert(docker_network_info);

    char image[512];
    if(function_type->docker_version_tag && (function_type->docker_version_tag[0] != 0)) {
        if(function_type->docker_repository && (function_type->docker_repository[0] != 0) && (strcmp(function_type->docker_repository, "local") != 0)) {
            sprintf(image, "%s/%s:%s", function_type->docker_repository, function_type->docker_image_name, function_type->docker_version_tag);    
        }
        else {
            sprintf(image, "%s:%s", function_type->docker_image_name, function_type->docker_version_tag);
        }
    }
    else {
        if(function_type->docker_repository && (function_type->docker_repository[0] != 0) && (strcmp(function_type->docker_repository, "local") != 0)) {
            sprintf(image, "%s/%s:latest", function_type->docker_repository, function_type->docker_image_name);    
        }
        else {
            sprintf(image, "%s:latest", function_type->docker_image_name);
        }
    }

    int rc = docker_container_create(image, instance);
    if(rc != NTS_ERR_OK) {
        log_error("docker_container_create failed");
        return NTS_ERR_FAILED;
    }

    rc = docker_container_start(instance);
    if(rc != NTS_ERR_OK) {
        log_error("docker_container_start failed");
        docker_device_stop(instance);
        return NTS_ERR_FAILED;
    }

    rc = docker_container_inspect(instance);
    if(rc != NTS_ERR_OK) {
        log_error("docker_container_inspect failed");
        docker_device_stop(instance);
        return NTS_ERR_FAILED;
    }

    log_message(2, "docker_device_start: docker_id: %s | name: %s | docker_ip: %s | host_port: %d\n", instance->docker_id, instance->name, instance->docker_ip, instance->host_port);

    return NTS_ERR_OK;
}

int docker_device_stop(manager_network_function_instance_t *instance) {
    assert(instance);

    char url[512];
    sprintf(url, "http://v%s/containers/%s?force=true", framework_environment.docker_engine_version, instance->docker_id);

    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "DELETE", "", 0, 0);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

docker_usage_t docker_usage_get(const manager_network_function_type *function_type, int function_type_count) {
    docker_usage_t ret;
    ret.cpu = 0;
    ret.mem = 0;

    char buffer[1024];
    char full_text[1024 * 1024];
    FILE* pipe = popen("docker stats --no-stream --format \"table {{.ID}}|{{.CPUPerc}}|{{.MemUsage}}|\"", "r");
    if (!pipe) {
        log_error("popen() failed");
        return ret;
    }

    int n = 1;
    int k = 0;
    while(n != 0) {
        n = fread(buffer, 1, sizeof(buffer), pipe);
        for(int i = 0; i < n; i++) {
            full_text[k++] = buffer[i];
        }
    }
    pclose(pipe);
    full_text[k] = 0;

    char *c = full_text;
    
    c = strstr(c, "\n");
    while(c) {
        char line[1024];
        line[0] = 0;

        char *d = strstr(c + 1, "\n");
        if(d) {
            for(char *i = c + 1; i < d; i++) {
                line[i - c - 1] = *i;
                line[i - c] = 0;
            }

            char container_name[1024];
            char buff[1024];
            float cpu = 0.0;
            float mem = 0.0;

            char *x = strstr(line, "|");
            for(char *i = line; i < x; i++) {
                container_name[i - line] = *i;
                container_name[i - line + 1] = 0;
            }

            char *start = x + 1;
            x = strstr(start, "|");
            for(char *i = start; i < x; i++) {
                if(((*i >= '0') && (*i <= '9')) || (*i == '.')) {
                    buff[i - start] = *i;
                }
                else {
                    buff[i - start] = 0;
                    break;
                }
            }

            cpu = strtof(buff, 0);

            int mul = 1;
            start = x + 1;
            x = strstr(start, "|");
            for(char *i = start; i < x; i++) {
                if(((*i >= '0') && (*i <= '9')) || (*i == '.')) {
                    buff[i - start] = *i;
                }
                else {
                    if(*i == 'G') {
                        mul = 1024;
                    }
                    buff[i - start] = 0;
                    break;
                }
            }

            mem = strtof(buff, 0) * mul;
            
            
            if(strcmp(container_name, framework_environment.hostname) == 0) {
                ret.cpu += cpu;
                ret.mem += mem;
            }
            else {
                for(int i = 0; i < function_type_count; i++) {
                    for(int j = 0; j < function_type[i].started_instances; j++) {
                        
                        if(strcmp(container_name, function_type[i].instance[j].docker_id) == 0) {
                            ret.cpu += cpu;
                            ret.mem += mem;
                            break;
                        }
                    }
                }
            }
        }
        
        c = d;
    }


    ret.cpu /= get_nprocs();

    return ret;
}

static char *docker_parse_json_message(const char *json_string) {
    assert(json_string);

    cJSON *json_response = cJSON_Parse(json_string);
    if(json_response == 0) {
        log_error("cJSON_Parse failed");
        return 0;
    }

    cJSON *message;
    message = cJSON_GetObjectItem(json_response, "message");
    if(message == 0) {
        log_error("json parsing failed");
        cJSON_Delete(json_response);
        return 0;
    }

    char *ret = strdup(message->valuestring);
    cJSON_Delete(json_response);
    return ret;
}

static int docker_container_create(const char *image, manager_network_function_instance_t *instance) {
    assert(image);
    assert(instance);

    cJSON *postDataJson = cJSON_CreateObject();
    if(cJSON_AddStringToObject(postDataJson, "Image", image) == 0) {
        log_error("could not create JSON object: Image");
        return NTS_ERR_FAILED;
    }

    if(cJSON_AddStringToObject(postDataJson, "Hostname", instance->name) == 0) {
        log_error("could not create JSON object: Hostname");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }    

    cJSON *hostConfig = cJSON_CreateObject();
    if(hostConfig == 0) {
        log_error("could not create JSON object: HostConfig");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    if(cJSON_AddItemToObject(postDataJson, "HostConfig", hostConfig) == 0) {
        log_error("cJSON_AddItemToObject failed");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }

    cJSON *portBindings = cJSON_CreateObject();
    if(portBindings == 0) {
        printf("could not create JSON object: PortBindings");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    if(cJSON_AddItemToObject(hostConfig, "PortBindings", portBindings) == 0) {
        log_error("cJSON_AddItemToObject failed");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    
    for(int i = 0; i < (framework_environment.ssh_connections + framework_environment.tls_connections + framework_environment.ftp_connections + framework_environment.sftp_connections); ++i) {
        cJSON *port = cJSON_CreateArray();
        if(port == 0) {
            log_error("could not create JSON object: port");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }

        char dockerContainerPort[20];
        if(i < framework_environment.ssh_connections + framework_environment.tls_connections) {
            sprintf(dockerContainerPort, "%d/tcp", STANDARD_NETCONF_PORT + i);
        }
        else if(i < (framework_environment.ssh_connections + framework_environment.tls_connections + framework_environment.ftp_connections)) {
            sprintf(dockerContainerPort, "%d/tcp", STANDARD_FTP_PORT);
        }
        else if(i < (framework_environment.ssh_connections + framework_environment.tls_connections + framework_environment.ftp_connections + framework_environment.sftp_connections)) {
            sprintf(dockerContainerPort, "%d/tcp", STANDARD_SFTP_PORT);
        }
        if(cJSON_AddItemToObject(portBindings, dockerContainerPort, port) == 0) {
            log_error("cJSON_AddItemToObject failed");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }

        cJSON *hostPort = cJSON_CreateObject();
        if(hostPort == 0) {
            log_error("could not create JSON object: HostPort");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }

        char dockerHostPort[20];
        sprintf(dockerHostPort, "%d", instance->host_port + i);
        if(cJSON_AddStringToObject(hostPort, "HostPort", dockerHostPort) == 0) {
            log_error("could not create JSON object: HostPortString");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }

        if(cJSON_AddStringToObject(hostPort, "HostIp", "0.0.0.0") == 0) {   //instance->host_ip
            log_error("could not create JSON object: HostIpString");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }

        if(cJSON_AddItemToArray(port, hostPort) == 0) {
            log_error("cJSON_AddItemToArray failed");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }
    }

    
    //environment vars start
    asprintf(&docker_environment_var[4].value, "%d", instance->host_port);

    cJSON *env_variables_array = cJSON_CreateArray();
    if(env_variables_array == 0) {
        log_error("Could not create JSON object: Env array");
        return NTS_ERR_FAILED;
    }
    cJSON_AddItemToObject(postDataJson, "Env", env_variables_array);

    for(int i = 0; i < docker_environment_var_count; i++) {
        if(docker_environment_var[i].value) {
            char *environment_var = 0;
            asprintf(&environment_var, "%s=%s", docker_environment_var[i].name, docker_environment_var[i].value);

            cJSON *env_var_obj = cJSON_CreateString(environment_var);
            if(env_var_obj == 0) {
                log_error("could not create JSON object");
                return NTS_ERR_FAILED;
            }
            cJSON_AddItemToArray(env_variables_array, env_var_obj);

            free(environment_var);
        }
    }

    free(docker_environment_var[4].value);
    //environment vars finished


    cJSON *netMode = cJSON_Duplicate(docker_network_info, 1);
    cJSON_AddItemToObject(hostConfig, "NetworkMode", netMode);

    char *post_data_string = 0;
    post_data_string = cJSON_PrintUnformatted(postDataJson);
    cJSON_Delete(postDataJson);

    char url[512];
    sprintf(url, "http:/v%s/containers/create?name=%s", framework_environment.docker_engine_version, instance->name);

    char *response = 0;
    int response_code = 0;
    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "POST", post_data_string, &response_code, &response);
    free(post_data_string);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed");
        return NTS_ERR_FAILED;
    }

    if(response_code != 201) {
        char *message = docker_parse_json_message(response);
        log_error("docker_container_create failed (%d): %s", response_code, message);
        free(message);
        free(response);
        return NTS_ERR_FAILED;
    }
    else {
        cJSON *json_response = cJSON_Parse(response);
        free(response);
        const cJSON *container_id = 0;

        container_id = cJSON_GetObjectItemCaseSensitive(json_response, "Id");

        if(cJSON_IsString(container_id) && (container_id->valuestring != 0)) {
            char container_id_short[13];
            memset(container_id_short, '\0', sizeof(container_id_short));
            strncpy(container_id_short, container_id->valuestring, 12);

            instance->docker_id = strdup(container_id_short);

            cJSON_Delete(json_response);
            return NTS_ERR_OK;
        }
        else {
            cJSON_Delete(json_response);
            return NTS_ERR_FAILED;
        }
    }
}

static int docker_container_start(manager_network_function_instance_t *instance) {
    assert(instance);

    char url[512];
    sprintf(url, "http://v%s/containers/%s/start", framework_environment.docker_engine_version, instance->docker_id);

    char *response = 0;
    int response_code = 0;
    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "POST", "", &response_code, &response);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed");
        return NTS_ERR_FAILED;
    }
    else {
        if(response_code == 304) {
            log_error("docker_container_start failed (%d): container already started\n", response_code);
            free(response);
            return NTS_ERR_FAILED;
        }
        else if(response_code != 204) {
            char *message = docker_parse_json_message(response);
            log_error("docker_container_start failed (%d): %s", response_code, message);
            free(message);
            free(response);
            return NTS_ERR_FAILED;
        }
        
    }

    return NTS_ERR_OK;
}

static int docker_container_inspect(manager_network_function_instance_t *instance) {
    assert(instance);

    char url[512];
    sprintf(url, "http://v%s/containers/%s/json", framework_environment.docker_engine_version, instance->docker_id);

    char *response = 0;    
    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "GET", "", 0, &response);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed");
        return NTS_ERR_FAILED;
    }

    cJSON *json_response = cJSON_Parse(response);
    free(response);
    if(json_response == 0) {
        log_error("cJSON_Parse failed");
        return NTS_ERR_FAILED;
    }


    cJSON *main_node = cJSON_GetObjectItem(json_response, "NetworkSettings");
    if(main_node == 0) {
        log_error("json parsing failed");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    cJSON *node = cJSON_GetObjectItem(main_node, "Networks");
    if(node == 0) {
        log_error("json parsing failed");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }
        
    node = node->child;   //get info from the first in array
    if(node == 0) {
        log_error("json parsing failed");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    cJSON *element;
    if(framework_environment.ip_v6_enabled) {
        element = cJSON_GetObjectItem(node, "GlobalIPv6Address");
    }
    else {
        element = cJSON_GetObjectItem(node, "IPAddress");
    } 

    if(element == 0) {
        log_error("json parsing failed");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    instance->docker_ip = strdup(element->valuestring);

    cJSON_Delete(json_response);
    return NTS_ERR_OK;
}
