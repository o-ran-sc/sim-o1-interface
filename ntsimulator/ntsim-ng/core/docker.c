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
#include "utils/nts_utils.h"
#include "utils/http_client.h"
#include "core/framework.h"
#include "core/session.h"
#include "core/context.h"
#include <sysrepo.h>
#include <assert.h>
#include <sys/sysinfo.h>

#include <cjson/cJSON.h>

#define DOCKER_SOCK_FNAME       "/var/run/docker.sock"

static cJSON *docker_network_info = 0;

typedef struct {
    char *name;
    char *value;
} environment_var_t;

static environment_var_t *docker_environment_var;
static int docker_environment_var_count = 0;

static char *docker_parse_json_message(const char *json_string);
static int docker_add_port(cJSON *portBindings, uint16_t docker_port, uint16_t host_port);

static int docker_populate_images(docker_context_t *context, int count, const char *min_version);
static int docker_container_create(const char *image, docker_container_t *container);
static int docker_container_start(docker_container_t *container);
static int docker_container_inspect(docker_container_t *container);

int docker_init(const char **filter, int filter_count, const char *min_version, docker_context_t **context) {
    assert(filter);
    assert(filter_count);
    assert(context);

    char *response = 0;
    char url[512];
    sprintf(url, "http://v%s/containers/%s/json", framework_environment.settings.docker_engine_version, framework_environment.settings.hostname);

    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "GET", 0, 0, &response);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed\n");
        return NTS_ERR_FAILED;
    }

    cJSON *json_response = cJSON_Parse(response);
    free(response);

    if(json_response == 0) {
        log_error("could not parse JSON response for url=\"%s\"\n", url);
        return NTS_ERR_FAILED;
    }

    cJSON *hostConfig = cJSON_GetObjectItemCaseSensitive(json_response, "HostConfig");
    if(hostConfig == 0) {
        log_error("could not get HostConfig object\n");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    cJSON *networkMode = cJSON_GetObjectItemCaseSensitive(hostConfig, "NetworkMode");
    if(networkMode == 0) {
        log_error("could not get NetworkMode object\n");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    docker_network_info = cJSON_Duplicate(networkMode, 1);
    cJSON_Delete(json_response);

    log_add_verbose(2, "finished parsing docker inspect...\n");

    docker_environment_var_count = 9;
    docker_environment_var = (environment_var_t *)malloc(sizeof(environment_var_t) * docker_environment_var_count);
    if(docker_environment_var == 0) {
        log_error("malloc failed\n");
        cJSON_Delete(networkMode);
        return NTS_ERR_FAILED;
    }
    
    //set env variables for network functions
    docker_environment_var[0].name = ENV_VAR_SSH_CONNECTIONS;
    asprintf(&docker_environment_var[0].value, "%d", framework_environment.settings.ssh_connections);
    docker_environment_var[1].name = ENV_VAR_TLS_CONNECTIONS;
    asprintf(&docker_environment_var[1].value, "%d", framework_environment.settings.tls_connections);
    docker_environment_var[2].name = ENV_VAR_IPV6ENABLED;
    docker_environment_var[2].value = framework_environment.settings.ip_v6_enabled ? "true" : "false";
    docker_environment_var[3].name = ENV_VAR_HOST_IP;
    docker_environment_var[3].value = framework_environment.host.ip;

    docker_environment_var[4].name = ENV_VAR_HOST_NETCONF_SSH_BASE_PORT;
    // docker_environment_var[4].value = will be updated by docker_create...
    docker_environment_var[5].name = ENV_VAR_HOST_NETCONF_TLS_BASE_PORT;
    // docker_environment_var[5].value = will be updated by docker_create...
    docker_environment_var[6].name = ENV_VAR_HOST_TRANSFER_FTP_BASE_PORT;
    // docker_environment_var[6].value = will be updated by docker_create...
    docker_environment_var[7].name = ENV_VAR_HOST_TRANSFER_SFTP_BASE_PORT;
    // docker_environment_var[7].value = will be updated by docker_create...

    docker_environment_var[8].name = ENV_VAR_VES_COMMON_HEADER_VERSION;
    docker_environment_var[8].value = framework_environment.ves_endpoint.common_header_version;



    //docker context build
    *context = (docker_context_t *)malloc(sizeof(docker_context_t) * filter_count);
    if(*context == 0) {
        log_error("bad malloc\n");
        free(docker_environment_var[0].value);
        free(docker_environment_var[1].value);
        free(docker_environment_var);
        return NTS_ERR_FAILED;
    }

    docker_context_t *ctx = *context;
    for(int i = 0; i < filter_count; i++) {
        ctx[i].image = strdup(filter[i]);
        ctx[i].available_images = 0;
        ctx[i].available_images_count = 0;
    }

    docker_populate_images(ctx, filter_count, min_version);

    return NTS_ERR_OK;
}

void docker_free(docker_context_t *context, int count) {
    free(docker_environment_var[0].value);
    free(docker_environment_var[1].value);
    free(docker_environment_var);

    for(int i = 0; i < count; i++) {
        free(context[i].image);
        for(int j = 0; j < context[i].available_images_count; j++) {
            free(context[i].available_images[j].repo);
            free(context[i].available_images[j].tag);
        }
        free(context[i].available_images);
    }
}

int docker_start(const char *container_name, const char *tag, const char *image, const char *repo, uint16_t host_netconf_ssh_port, uint16_t host_netconf_tls_port, uint16_t host_ftp_port, uint16_t host_sftp_port, docker_container_t *container) {
    assert(container_name);
    assert(image);
    assert(container);
    assert(docker_network_info);

    char image_full[512];
    if(tag && (tag[0] != 0)) {
        if(repo && (repo[0] != 0) && (strcmp(repo, "local") != 0)) {
            sprintf(image_full, "%s/%s:%s", repo, image, tag);    
        }
        else {
            sprintf(image_full, "%s:%s", image, tag);
        }
    }
    else {
        if(repo && (repo[0] != 0) && (strcmp(repo, "local") != 0)) {
            sprintf(image_full, "%s/%s:latest", repo, image);    
        }
        else {
            sprintf(image_full, "%s:latest", image);
        }
    }

    container->name = strdup(container_name);
    container->id = 0;
    container->docker_ip = 0;
    container->docker_netconf_ssh_port = STANDARD_NETCONF_PORT;
    container->docker_netconf_tls_port = container->docker_netconf_ssh_port + framework_environment.settings.ssh_connections;
    if(framework_environment.settings.ssh_connections == 0) {
        container->docker_netconf_ssh_port = 0;
    }
    if(framework_environment.settings.tls_connections == 0) {
        container->docker_netconf_tls_port = 0;
    }
    container->docker_ftp_port= STANDARD_FTP_PORT;
    container->docker_sftp_port= STANDARD_SFTP_PORT;

    container->host_ip = strdup(framework_environment.host.ip);
    container->host_netconf_ssh_port = host_netconf_ssh_port;
    container->host_netconf_tls_port = host_netconf_tls_port;
    container->host_ftp_port = host_ftp_port;
    container->host_sftp_port = host_sftp_port;

    int rc = docker_container_create(image_full, container);
    if(rc != NTS_ERR_OK) {
        log_error("docker_container_create failed\n");
        return NTS_ERR_FAILED;
    }

    rc = docker_container_start(container);
    if(rc != NTS_ERR_OK) {
        log_error("docker_container_start failed\n");
        docker_stop(container);
        return NTS_ERR_FAILED;
    }

    rc = docker_container_inspect(container);
    if(rc != NTS_ERR_OK) {
        log_error("docker_container_inspect failed\n");
        docker_stop(container);
        return NTS_ERR_FAILED;
    }

    log_add_verbose(2, "docker_start: name: %s | id: %s | docker_ip: %s | netconf_ssh_port: (%d:%d) | netconf_tls_port: (%d:%d) | ftp_port: (%d:%d) | sftp_port: (%d:%d)\n", container->name, container->id, container->docker_ip, container->docker_netconf_ssh_port, container->host_netconf_ssh_port, container->docker_netconf_tls_port, container->host_netconf_tls_port, container->docker_ftp_port, container->host_ftp_port, container->docker_sftp_port, container->host_sftp_port);

    return NTS_ERR_OK;
}

int docker_stop(docker_container_t *container) {
    assert(container);

    char url[512];
    sprintf(url, "http://v%s/containers/%s?force=true", framework_environment.settings.docker_engine_version, container->id);
    
    free(container->name);
    free(container->id);
    free(container->docker_ip);
    free(container->host_ip);

    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "DELETE", "", 0, 0);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed\n");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

int docker_usage_get(const char **instances_id, int count, docker_usage_t *usage) {
    assert(instances_id);
    assert(usage);

    usage->cpu = 0;
    usage->mem = 0;

    char buffer[1024];
    char full_text[1024 * 1024];
    FILE* pipe = popen("docker stats --no-stream --format \"table {{.ID}}|{{.CPUPerc}}|{{.MemUsage}}|\"", "r");
    if (!pipe) {
        log_error("popen() failed\n");
        return NTS_ERR_FAILED;
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
            
            
            if(strcmp(container_name, framework_environment.settings.hostname) == 0) {
                usage->cpu += cpu;
                usage->mem += mem;
            }
            else {
                for(int i = 0; i < count; i++) {   
                    if(strcmp(container_name, instances_id[i]) == 0) {
                        usage->cpu += cpu;
                        usage->mem += mem;
                        break;
                    }
                }
            }
        }
        
        c = d;
    }

    usage->cpu /= get_nprocs();

    return NTS_ERR_OK;
}

int docker_pull(const char *repo, const char *image, const char *tag) {
    assert(repo);
    assert(image);
    assert(tag);

    char image_full[256];
    if(tag && (tag[0] != 0)) {
        sprintf(image_full, "%s/%s:%s", repo, image, tag);
    }
    else {
        sprintf(image_full, "%s/%s:latest", repo, image);    
    }

    char url[512];
    sprintf(url, "http:/v%s/images/create?fromImage=%s", framework_environment.settings.docker_engine_version, image_full);

    char *response = 0;
    int response_code = 0;
    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "POST", 0, &response_code, &response);

    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed\n");
        return NTS_ERR_FAILED;
    }

    if(response_code != 200) {
        char *message = docker_parse_json_message(response);
        log_error("docker_pull failed (%d): %s\n", response_code, message);
        free(message);
        free(response);
        return NTS_ERR_FAILED;
    }
    
    return NTS_ERR_OK;
}

static char *docker_parse_json_message(const char *json_string) {
    assert(json_string);

    cJSON *json_response = cJSON_Parse(json_string);
    if(json_response == 0) {
        log_error("cJSON_Parse failed\n");
        return 0;
    }

    cJSON *message = cJSON_GetObjectItem(json_response, "message");
    if(message == 0) {
        log_error("json parsing failed\n");
        cJSON_Delete(json_response);
        return 0;
    }

    char *ret = strdup(message->valuestring);
    cJSON_Delete(json_response);
    return ret;
}

static int docker_add_port(cJSON *portBindings, uint16_t docker_port, uint16_t host_port) {
    assert(portBindings);

    cJSON *port = cJSON_CreateArray();
    if(port == 0) {
        log_error("could not create JSON object: port\n");
        return NTS_ERR_FAILED;
    }

    char dockerContainerPort[20];
    sprintf(dockerContainerPort, "%d/tcp", docker_port);

    if(cJSON_AddItemToObject(portBindings, dockerContainerPort, port) == 0) {
        log_error("cJSON_AddItemToObject failed\n");
        return NTS_ERR_FAILED;
    }

    cJSON *hostPort = cJSON_CreateObject();
    if(hostPort == 0) {
        log_error("could not create JSON object: HostPort\n");
        return NTS_ERR_FAILED;
    }

    char dockerHostPort[20];
    sprintf(dockerHostPort, "%d", host_port);
    if(cJSON_AddStringToObject(hostPort, "HostPort", dockerHostPort) == 0) {
        log_error("could not create JSON object: HostPortString\n");
        cJSON_Delete(hostPort);
        return NTS_ERR_FAILED;
    }

    if(cJSON_AddItemToArray(port, hostPort) == 0) {
        log_error("cJSON_AddItemToArray failed\n");
        cJSON_Delete(hostPort);
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int docker_populate_images(docker_context_t *context, int count, const char *min_version) {
    assert(context);
    assert(count);
    assert(min_version);

    char url[512];
    sprintf(url, "http://v%s/images/json", framework_environment.settings.docker_engine_version);

    char *response = 0;    
    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "GET", "", 0, &response);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed\n");
        return NTS_ERR_FAILED;
    }

    cJSON *json_response = cJSON_Parse(response);
    free(response);
    if(json_response == 0) {
        log_error("cJSON_Parse failed\n");
        return NTS_ERR_FAILED;
    }
    
    cJSON *element;
    cJSON_ArrayForEach(element, json_response) {
        cJSON *tag = cJSON_GetObjectItem(element, "RepoTags");
        if(tag) {
            cJSON *ctag;
            cJSON_ArrayForEach(ctag, tag) {
                char *tag_name = ctag->valuestring; //contains repo/image:tag
                for(int i = 0; i < count; i++) {
                    char *s = strstr(tag_name, context[i].image);
                    if(s != 0) {
                        char *tag = s + strlen(context[i].image);
                        if(*tag == ':') {
                            tag = strdup(s + strlen(context[i].image) + 1);
                        }
                        else if(*tag == 0) {
                            tag = strdup("");
                        }
                        else {
                            continue;
                        }

                        if(nts_vercmp(tag, min_version) >= 0) {
                            char *repo = 0;
                            if(s != tag_name) {
                                repo = strdup(tag_name);
                                *(strstr(repo, context[i].image) - 1) = 0;
                            }
                            else {
                                repo = strdup("");
                            }

                            context[i].available_images = (docker_available_images_t *)realloc(context[i].available_images, (sizeof(docker_available_images_t) * (context[i].available_images_count + 1)));
                            context[i].available_images[context[i].available_images_count].repo = repo;
                            context[i].available_images[context[i].available_images_count].tag = tag;
                            context[i].available_images_count++;
                        }
                        else {
                            free(tag);
                        }
                    }
                }
            }
        }
    }

    cJSON_Delete(json_response);

    return NTS_ERR_OK;
}

static int docker_container_create(const char *image, docker_container_t *container) {
    assert(image);
    assert(container);

    cJSON *postDataJson = cJSON_CreateObject();
    if(cJSON_AddStringToObject(postDataJson, "Image", image) == 0) {
        log_error("could not create JSON object: Image\n");
        return NTS_ERR_FAILED;
    }

    if(cJSON_AddStringToObject(postDataJson, "Hostname", container->name) == 0) {
        log_error("could not create JSON object: Hostname\n");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }    

    cJSON *hostConfig = cJSON_CreateObject();
    if(hostConfig == 0) {
        log_error("could not create JSON object: HostConfig\n");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    if(cJSON_AddItemToObject(postDataJson, "HostConfig", hostConfig) == 0) {
        log_error("cJSON_AddItemToObject failed\n");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }

    cJSON *capAdd = cJSON_CreateArray();
    if(capAdd == 0) {
        log_error("could not create JSON array: CapAdd\n");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    if(cJSON_AddItemToObject(hostConfig, "CapAdd", capAdd) == 0) {
        log_error("cJSON_AddItemToObject failed\n");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    cJSON *net_admin = cJSON_CreateString("NET_ADMIN");
    if(net_admin == 0) {
        log_error("could not create JSON string\n");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    if(cJSON_AddItemToArray(capAdd, net_admin) == 0) {
        log_error("cJSON_AddItemToArray failed\n");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    

    cJSON *portBindings = cJSON_CreateObject();
    if(portBindings == 0) {
        log_error("could not create JSON object: PortBindings\n");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    if(cJSON_AddItemToObject(hostConfig, "PortBindings", portBindings) == 0) {
        log_error("cJSON_AddItemToObject failed\n");
        cJSON_Delete(postDataJson);
        return NTS_ERR_FAILED;
    }
    
    for(int i = 0; i < framework_environment.settings.ssh_connections; i++) {
        if(docker_add_port(portBindings, container->docker_netconf_ssh_port + i, container->host_netconf_ssh_port + i) != NTS_ERR_OK) {
            log_error("docker_add_port() failed\n");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }
    }

    for(int i = 0; i < framework_environment.settings.tls_connections; i++) {
        if(docker_add_port(portBindings, container->docker_netconf_tls_port + i, container->host_netconf_tls_port + i) != NTS_ERR_OK) {
            log_error("docker_add_port() failed\n");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }
    }

    for(int i = 0; i < framework_environment.settings.ftp_connections; i++) {
        if(docker_add_port(portBindings, container->docker_ftp_port + i, container->host_ftp_port + i) != NTS_ERR_OK) {
            log_error("docker_add_port() failed\n");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }
    }

    for(int i = 0; i < framework_environment.settings.sftp_connections; i++) {
        if(docker_add_port(portBindings, container->docker_sftp_port + i, container->host_sftp_port + i) != NTS_ERR_OK) {
            log_error("docker_add_port() failed\n");
            cJSON_Delete(postDataJson);
            return NTS_ERR_FAILED;
        }
    }
    
    //environment vars start
    asprintf(&docker_environment_var[4].value, "%d", container->host_netconf_ssh_port);
    asprintf(&docker_environment_var[5].value, "%d", container->host_netconf_tls_port);
    asprintf(&docker_environment_var[6].value, "%d", container->host_ftp_port);
    asprintf(&docker_environment_var[7].value, "%d", container->host_sftp_port);

    cJSON *env_variables_array = cJSON_CreateArray();
    if(env_variables_array == 0) {
        log_error("Could not create JSON object: Env array\n");
        cJSON_Delete(postDataJson);
        free(docker_environment_var[4].value);
        free(docker_environment_var[5].value);
        free(docker_environment_var[6].value);
        free(docker_environment_var[7].value);
        return NTS_ERR_FAILED;
    }
    cJSON_AddItemToObject(postDataJson, "Env", env_variables_array);

    for(int i = 0; i < docker_environment_var_count; i++) {
        if(docker_environment_var[i].value) {
            char *environment_var = 0;
            asprintf(&environment_var, "%s=%s", docker_environment_var[i].name, docker_environment_var[i].value);

            cJSON *env_var_obj = cJSON_CreateString(environment_var);
            if(env_var_obj == 0) {
                log_error("could not create JSON object\n");
                cJSON_Delete(postDataJson);
                free(docker_environment_var[4].value);
                free(docker_environment_var[5].value);
                free(docker_environment_var[6].value);
                free(docker_environment_var[7].value);
                free(environment_var);
                return NTS_ERR_FAILED;
            }
            cJSON_AddItemToArray(env_variables_array, env_var_obj);

            free(environment_var);
        }
    }

    free(docker_environment_var[4].value);
    free(docker_environment_var[5].value);
    free(docker_environment_var[6].value);
    free(docker_environment_var[7].value);
    //environment vars finished

    cJSON *netMode = cJSON_Duplicate(docker_network_info, 1);
    cJSON_AddItemToObject(hostConfig, "NetworkMode", netMode);

    char *post_data_string = 0;
    post_data_string = cJSON_PrintUnformatted(postDataJson);
    cJSON_Delete(postDataJson);

    char url[512];
    sprintf(url, "http:/v%s/containers/create?name=%s", framework_environment.settings.docker_engine_version, container->name);

    char *response = 0;
    int response_code = 0;
    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "POST", post_data_string, &response_code, &response);
    free(post_data_string);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed\n");
        return NTS_ERR_FAILED;
    }

    if(response_code != 201) {
        char *message = docker_parse_json_message(response);
        log_error("docker_container_create failed (%d): %s\n", response_code, message);
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

            container->id = strdup(container_id_short);

            cJSON_Delete(json_response);
            return NTS_ERR_OK;
        }
        else {
            cJSON_Delete(json_response);
            return NTS_ERR_FAILED;
        }
    }
}

static int docker_container_start(docker_container_t *container) {
    assert(container);

    char url[512];
    sprintf(url, "http://v%s/containers/%s/start", framework_environment.settings.docker_engine_version, container->id);

    char *response = 0;
    int response_code = 0;
    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "POST", "", &response_code, &response);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed\n");
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
            log_error("docker_container_start failed (%d): %s\n", response_code, message);
            free(message);
            free(response);
            return NTS_ERR_FAILED;
        }
        
    }

    return NTS_ERR_OK;
}

static int docker_container_inspect(docker_container_t *container) {
    assert(container);

    char url[512];
    sprintf(url, "http://v%s/containers/%s/json", framework_environment.settings.docker_engine_version, container->id);

    char *response = 0;    
    int rc = http_socket_request(url, DOCKER_SOCK_FNAME, "GET", "", 0, &response);
    if(rc != NTS_ERR_OK) {
        log_error("http_socket_request failed\n");
        free(response);
        return NTS_ERR_FAILED;
    }

    cJSON *json_response = cJSON_Parse(response);
    free(response);
    if(json_response == 0) {
        log_error("cJSON_Parse failed\n");
        return NTS_ERR_FAILED;
    }


    cJSON *main_node = cJSON_GetObjectItem(json_response, "NetworkSettings");
    if(main_node == 0) {
        log_error("json parsing failed\n");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    cJSON *node = cJSON_GetObjectItem(main_node, "Networks");
    if(node == 0) {
        log_error("json parsing failed\n");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }
        
    node = node->child;   //get info from the first in array
    if(node == 0) {
        log_error("json parsing failed\n");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    cJSON *element;
    if(framework_environment.settings.ip_v6_enabled) {
        element = cJSON_GetObjectItem(node, "GlobalIPv6Address");
    }
    else {
        element = cJSON_GetObjectItem(node, "IPAddress");
    } 

    if(element == 0) {
        log_error("json parsing failed\n");
        cJSON_Delete(json_response);
        return NTS_ERR_FAILED;
    }

    container->docker_ip = strdup(element->valuestring);

    cJSON_Delete(json_response);
    return NTS_ERR_OK;
}
