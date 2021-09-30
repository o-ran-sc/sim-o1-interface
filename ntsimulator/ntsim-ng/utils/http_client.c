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

#include "http_client.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <curl/curl.h>

struct memory {
    char *response;
    size_t size;
};

static size_t curl_write_cb(void *data, size_t size, size_t nmemb, void *userp);
 
int http_request(const char *url, const char *username, const char* password, const char *method, const char *send_data, int *response_code, char **recv_data) {
    assert(url);
    assert(method);

    const char *send_data_good = send_data;
    if(!send_data_good) {
        send_data_good = "";
    }

    CURL *curl = curl_easy_init();
    if(curl == 0) {
        log_error("could not initialize cURL\n");
        return NTS_ERR_FAILED;
    }

    // set curl options
    struct curl_slist *header = 0;
    header = curl_slist_append(header, "Content-Type: application/json");
    if(!header) {
        log_error("curl_slist_append failed\n");
        curl_easy_cleanup(curl);
        return NTS_ERR_FAILED;
    }

    header = curl_slist_append(header, "Accept: application/json");
    if(!header) {
        log_error("curl_slist_append failed\n");
        curl_easy_cleanup(curl);
        return NTS_ERR_FAILED;
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);     //seconds timeout for a connection
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);            //seconds timeout for an operation
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    // disable SSL verifications
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, send_data_good);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    if((username) && (password)) {
        char *credentials = 0;
        asprintf(&credentials, "%s:%s", username, password);
        if(credentials == 0) {
            log_error("asprintf failed\n");
            curl_slist_free_all(header);
            curl_easy_cleanup(curl);
            return NTS_ERR_FAILED;
        }
        curl_easy_setopt(curl, CURLOPT_USERPWD, credentials);
        free(credentials);
    }

    struct memory response_data = {0};
    if(recv_data) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response_data);
    }
    
    log_add_verbose(2, "%s-ing cURL to url=\"%s\" with body=\"%s\"... ", method, url, send_data_good);
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(header);

    if(res != CURLE_OK) {
        log_add(2, "failed with error: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return NTS_ERR_FAILED;
    }
    else {
        log_add(2, "success\n");
    }

    if(response_code) {
        long http_rc;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
        *response_code = http_rc;
    }

    if(recv_data) {
        *recv_data = response_data.response;
    }

    curl_easy_cleanup(curl);
    return NTS_ERR_OK;
}

int http_socket_request(const char *url, const char *sock_fname, const char *method, const char *send_data, int *response_code, char **recv_data) {
    assert(url);
    assert(sock_fname);
    assert(method);

    const char *send_data_good = send_data;
    if(!send_data_good) {
        send_data_good = "";
    }

    CURL *curl = curl_easy_init();
    if(curl == 0) {
        log_error("could not initialize cURL\n");
        return NTS_ERR_FAILED;
    }

    // set curl options
    struct curl_slist *header = 0;
    header = curl_slist_append(header, "Content-Type: application/json");
    if(!header) {
        log_error("curl_slist_append failed\n");
        curl_easy_cleanup(curl);
        return NTS_ERR_FAILED;
    }

    header = curl_slist_append(header, "Accept: application/json");
    if(!header) {
        log_error("curl_slist_append failed\n");
        curl_easy_cleanup(curl);
        return NTS_ERR_FAILED;
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);     //seconds timeout for a connection
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);            //seconds timeout for an operation
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, send_data_good);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, sock_fname);

    struct memory response_data = {0};
    if(recv_data) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response_data);
    }
    
    log_add_verbose(2, "%s-ing cURL to url=\"%s\" with body=\"%s\"\n", method, url, send_data_good);
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(header);

    if(res != CURLE_OK) {
        log_add(2, "failed with error %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return NTS_ERR_FAILED;
    }
    else {
        log_add(2, "success\n");
    }

    if(response_code) {
        long http_rc;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
        *response_code = http_rc;
    }

    if(recv_data) {
        *recv_data = response_data.response;
    }

    curl_easy_cleanup(curl);
    return NTS_ERR_OK;
}

static size_t curl_write_cb(void *data, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *)userp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if(ptr == NULL) {
        log_error("realloc failed\n");
        return 0;  /* out of memory! */
    }

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}
