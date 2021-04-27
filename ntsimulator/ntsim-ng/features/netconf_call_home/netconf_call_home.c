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

#include "netconf_call_home.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/rand_utils.h"
#include "utils/http_client.h"
#include "utils/nts_utils.h"
#include <stdio.h>
#include <assert.h>

#include "core/session.h"
#include "core/framework.h"
#include "core/xpath.h"

#define NETCONF_CALLHOME_CURL_SEND_PAYLOAD_FORMAT   "{\"odl-netconf-callhome-server:device\":[{\"odl-netconf-callhome-server:unique-id\":\"%s\",\"odl-netconf-callhome-server:ssh-host-key\":\"%s\",\"odl-netconf-callhome-server:credentials\":{\"odl-netconf-callhome-server:username\":\"netconf\",\"odl-netconf-callhome-server:passwords\":[\"netconf!\"]}}]}"

static int create_ssh_callhome_endpoint(sr_session_ctx_t *current_session, struct lyd_node *netconf_node);
static int create_tls_callhome_endpoint(sr_session_ctx_t *current_session, struct lyd_node *netconf_node);
static int send_odl_callhome_configuration(sr_session_ctx_t *current_session);

static int netconf_call_home_status = 0;

int netconf_call_home_feature_get_status(void) {
    return netconf_call_home_status;
}

int netconf_call_home_feature_start(sr_session_ctx_t *current_session) {
    assert(current_session);
    assert_session();

    sr_val_t *value = 0;

    bool callhome_enabled = false;
    int rc = sr_get_item(current_session, NTS_NF_NETCONF_CALLHOME_ENABLED_SCHEMA_PATH, 0, &value);
    if(rc == SR_ERR_OK) {
        callhome_enabled = value->data.bool_val;
        sr_free_val(value);
    }
    else {
        // if value is not set yet, feature enable means we want to start call-home
        if(strlen(framework_environment.nts.nf_standalone_start_features)) {
            callhome_enabled = true;
        }
    }

    if(callhome_enabled == false) {
        log_add_verbose(2, "NETCONF CallHome is not enabled, not configuring NETCONF Server.\n");
        return NTS_ERR_OK;
    }

    struct lyd_node *netconf_node = 0;
    netconf_node = lyd_new_path(NULL, session_context, IETF_NETCONF_SERVER_SCHEMA_XPATH, 0, 0, 0);
    if(netconf_node == 0) {
        log_error("could not create a new lyd_node\n");
        return NTS_ERR_FAILED;
    }

    rc = create_ssh_callhome_endpoint(current_session, netconf_node);
    if(rc != NTS_ERR_OK) {
        log_error("could not create SSH CallHome endpoint on the NETCONF Server\n");
        return NTS_ERR_FAILED;
    }

    rc = create_tls_callhome_endpoint(current_session, netconf_node);
    if(rc != NTS_ERR_OK) {
        log_error("could not create TLS CallHome endpoint on the NETCONF Server\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_edit_batch(current_session, netconf_node, "merge");
    if(rc != SR_ERR_OK) {
        log_error("could not edit batch on datastore\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_validate(current_session, IETF_NETCONF_SERVER_MODULE, 0);
    if(rc != SR_ERR_OK) {
        log_error("sr_validate issues on STARTUP\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(current_session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore\n");
        return NTS_ERR_FAILED;
    }

    lyd_free_withsiblings(netconf_node);
    netconf_call_home_status = 1;

    return NTS_ERR_OK;
}


static int create_ssh_callhome_endpoint(sr_session_ctx_t *current_session, struct lyd_node *netconf_node) {
    assert(current_session);
    assert(netconf_node);

    controller_details_t *controller = controller_details_get(current_session);
    if(controller == 0) {
        log_error("controller_details_get failed\n");
        return NTS_ERR_FAILED;
    }

    char *controller_ip = strdup(controller->ip);
    uint16_t controller_callhome_port = controller->nc_callhome_port;
    controller_details_free(controller);

    if(controller_ip == 0) {
        log_error("strdup failed\n");
        return NTS_ERR_FAILED;
    }

    
    struct lyd_node *rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_TCP_CLIENT_SCHEMA_XPATH"/keepalives/idle-time", "1", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        free(controller_ip);
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_TCP_CLIENT_SCHEMA_XPATH"/keepalives/max-probes", "10", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        free(controller_ip);
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_TCP_CLIENT_SCHEMA_XPATH"/keepalives/probe-interval", "5", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        free(controller_ip);
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_TCP_CLIENT_SCHEMA_XPATH"/remote-address", controller_ip, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        free(controller_ip);
        return NTS_ERR_FAILED;
    }
    free(controller_ip);

    char port[20];
    sprintf(port, "%d", controller_callhome_port);
    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_TCP_CLIENT_SCHEMA_XPATH"/remote-port", port, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_SERVER_PARAMS_SCEHMA_XPATH"/server-identity/host-key[name='default-key']/public-key/keystore-reference", KS_KEY_NAME, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_SERVER_PARAMS_SCEHMA_XPATH"/client-authentication/supported-authentication-methods/publickey", "", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_SERVER_PARAMS_SCEHMA_XPATH"/client-authentication/supported-authentication-methods/passsword", "", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_SERVER_PARAMS_SCEHMA_XPATH"/client-authentication/supported-authentication-methods/other", "interactive", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_SSH_SERVER_PARAMS_SCEHMA_XPATH"/client-authentication/users", "", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }
    rcl = lyd_new_path(netconf_node, 0, IETF_NETCONF_SERVER_CH_CONN_PERSISTENT_SCHEMA_XPATH, "", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    int rc = send_odl_callhome_configuration(current_session);
    if(rc != NTS_ERR_OK) {
        log_add_verbose(2, "could not send ODL Call Home configuration.\n");
    }

    return NTS_ERR_OK;
}

static int create_tls_callhome_endpoint(sr_session_ctx_t *current_session, struct lyd_node *netconf_node) {
    assert(current_session);
    assert(netconf_node);

    // checkAS future usage, TLS endpoint yet supported in ODL
    
    return NTS_ERR_OK;
}


static int send_odl_callhome_configuration(sr_session_ctx_t *current_session) {
    assert(current_session);

    char *public_ssh_key = read_key(SERVER_PUBLIC_SSH_KEY_PATH);
    if(public_ssh_key == 0) {
        log_error("could not read the public ssh key from file %s\n", SERVER_PUBLIC_SSH_KEY_PATH);
        return NTS_ERR_FAILED;
    }

    char *ssh_key_string;
    ssh_key_string = strtok(public_ssh_key, " ");
    ssh_key_string = strtok(NULL, " ");
    ssh_key_string[strlen(ssh_key_string) - 1] = 0; // trim the newline character

    // checkAS we have hardcoded here the username and password of the NETCONF Server
    char *odl_callhome_payload = 0;
    asprintf(&odl_callhome_payload, NETCONF_CALLHOME_CURL_SEND_PAYLOAD_FORMAT, framework_environment.settings.hostname, ssh_key_string);
    free(public_ssh_key);
    if(odl_callhome_payload == 0) {
        log_error("bad asprintf\n");
        return NTS_ERR_FAILED;
    }

    controller_details_t *controller = controller_details_get(current_session);
    if(controller == 0) {
        log_error("controller_details_get failed\n");
        return NTS_ERR_FAILED;
    }
    
    char *url = 0;
    asprintf(&url, "%s/rests/data/odl-netconf-callhome-server:netconf-callhome-server/allowed-devices/device=%s", controller->base_url, framework_environment.settings.hostname);
    if(url == 0) {
        log_error("bad asprintf\n");
        controller_details_free(controller);
        return NTS_ERR_FAILED;
    }

    int rc = http_request(url, controller->username, controller->password, "PUT", odl_callhome_payload, 0, 0);
    if(rc != NTS_ERR_OK) {
        log_error("http_request failed\n");
    }
    
    free(url);
    controller_details_free(controller);
    free(odl_callhome_payload);

    return rc;
}
