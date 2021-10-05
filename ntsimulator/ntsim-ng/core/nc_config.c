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

#include "nc_config.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include "utils/http_client.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include <libyang/libyang.h>
#include "core/session.h"
#include "core/xpath.h"
#include "core/framework.h"

#define GEN_KEY_SCRIPT                              "/home/netconf/.ssh/generate-ssh-keys.sh"
#define SERVER_PRIVATE_KEY_PATH                     "/home/netconf/.ssh/melacon.server.key"
#define SERVER_PUBLIC_KEY_PATH                      "/home/netconf/.ssh/melacon.server.key.pub.pem"
#define CA_CERT_PATH                                "/home/netconf/.ssh/ca.pem"

static int nc_config_netconf_port = STANDARD_NETCONF_PORT;

static int load_ssh_keys(sr_session_ctx_t *session);
static int load_trusted_certificates(sr_session_ctx_t *session);
static int configure_nacm(sr_session_ctx_t *session);
static int create_ssh_listen_endpoints(struct lyd_node *netconf_node, int ssh_connections);
static int create_tls_listen_endpoints(struct lyd_node *netconf_node, int tls_connections);
static int configure_endpoints_connections(sr_session_ctx_t *session);

int netconf_configure(void) {
    int rc = NTS_ERR_OK;

    nc_config_netconf_port = STANDARD_NETCONF_PORT;

    //check if was already ran
    sr_val_t *val = 0;
    rc = sr_get_item(session_running, IETF_KEYSTORE_SCHEMA_XPATH, 0, &val);
    if(rc != SR_ERR_OK) {
        log_error("sr_get_item failed\n");
        return NTS_ERR_FAILED;
    }
    
    bool already_done = (val->dflt == false);
    sr_free_val(val);
    val = 0;
    if(already_done) {
        log_add_verbose(2, "netconf_configure() already ran, skipping...\n");
        return NTS_ERR_OK;
    }

    // generate and load private keys
    log_add_verbose(1, "ietf-keystore startup datastore configuration...");
    rc = load_ssh_keys(session_running);
    if(rc != 0) {
        log_error("could not load SSH keys\n");
        return NTS_ERR_FAILED;
    }
    log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);

    // load trusted certificates
    log_add_verbose(1, "ietf-truststore startup datastore configuration...");
    rc = load_trusted_certificates(session_running);
    if(rc != 0) {
        log_error("could not load trusted certificates\n");
        return NTS_ERR_FAILED;
    }
    log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);

    // configuring NACM
    log_add_verbose(1, "configuring NACM...");
    rc = configure_nacm(session_running);
    if(rc != 0) {
        log_error("could not configure NACM\n");
        return NTS_ERR_FAILED;
    }
    log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);

    // configure SSH connections
    log_add_verbose(1, "Configuring connection endpoints...");
    rc = configure_endpoints_connections(session_running);
    if(rc != 0) {
        log_error("could not configure endpoint connections for NETCONF Server\n");
        return NTS_ERR_FAILED;
    }
    log_add(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);

    return NTS_ERR_OK;
}

static int load_ssh_keys(sr_session_ctx_t *session) {
    assert(session);

    int rc = NTS_ERR_OK;
    char xpath[500];
    struct lyd_node *rcl = 0;

    rc = system(GEN_KEY_SCRIPT);
    if(rc != 0) {
        log_error("could not generate the SSH keys\n");
        return NTS_ERR_FAILED;
    }

    struct lys_module *module;
    module = (struct lys_module *)ly_ctx_get_module(session_context, IETF_KEYSTORE_MODULE, 0, 0);
    if(module == 0) {
        log_error("could not get module %s from context\n", IETF_KEYSTORE_MODULE);
        return NTS_ERR_FAILED;
    }
    
    struct lyd_node *keystore_node = 0;
    keystore_node = lyd_new(NULL, module, "keystore");
    if(keystore_node == 0) {
        log_error("could not create a new lyd_node\n");
        return NTS_ERR_FAILED;
    }

    sprintf(xpath, IETF_KEYSTORE_ASYMETRIC_KEY_SCHEMA_XPATH"/algorithm", KS_KEY_NAME);
    rcl = lyd_new_path(keystore_node, 0, xpath, "rsa2048", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    char *private_key = read_key(SERVER_PRIVATE_KEY_PATH);
    if(private_key == 0) {
        log_error("could not read the private key from path=%s\n", SERVER_PRIVATE_KEY_PATH);
        return NTS_ERR_FAILED;
    }
    log_add_verbose(2, "Private Key that was built: \n%s\n", private_key);

    sprintf(xpath, IETF_KEYSTORE_ASYMETRIC_KEY_SCHEMA_XPATH"/private-key", KS_KEY_NAME);
    rcl = lyd_new_path(keystore_node, 0, xpath, private_key, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    free(private_key);

    char *public_key = read_key(SERVER_PUBLIC_KEY_PATH);
    if(public_key == 0) {
        log_error("could not read the public key from path=%s\n", SERVER_PUBLIC_KEY_PATH);
        return NTS_ERR_FAILED;
    }
    log_add_verbose(2, "Public Key that was built: \n%s\n", public_key);

    sprintf(xpath, IETF_KEYSTORE_ASYMETRIC_KEY_SCHEMA_XPATH"/public-key", KS_KEY_NAME);
    rcl = lyd_new_path(keystore_node, 0, xpath, public_key, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    free(public_key);

    char *certificate = read_key(SERVER_CERT_PATH);
    if(certificate == 0) {
        log_error("could not read the certificate from path=%s\n", SERVER_CERT_PATH);
        return NTS_ERR_FAILED;
    }
    log_add_verbose(2, "Certificate that was built: \n%s\n", certificate);

    sprintf(xpath, IETF_KEYSTORE_ASYMETRIC_KEY_SCHEMA_XPATH"/certificates/certificate[name='%s']/cert", KS_KEY_NAME, KS_CERT_NAME);
    rcl = lyd_new_path(keystore_node, 0, xpath, certificate, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }

    free(certificate);

    rc = sr_edit_batch(session, keystore_node, "replace");
    if(rc != SR_ERR_OK) {
        log_error("could not edit batch on datastore\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_validate(session, IETF_KEYSTORE_MODULE, 0);
    if(rc != SR_ERR_OK) {
        struct ly_err_item *err = ly_err_first(session_context);
        log_error("sr_validate issues on STARTUP: %s\n", err->msg);
        return false;
    }

    rc = sr_apply_changes(session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore\n");
        return NTS_ERR_FAILED;
    }
    
    return NTS_ERR_OK;
}

static int load_trusted_certificates(sr_session_ctx_t *session) {
    assert(session);

    int rc = NTS_ERR_OK;
    struct lyd_node *rcl = 0;

    struct lyd_node *trusted_certificate_node = 0;
    struct lys_module *module;
    module = (struct lys_module *)ly_ctx_get_module(session_context, IETF_TRUSTSTORE_MODULE, 0, 0);
    if(module == 0) {
        log_error("could not get module %s from context\n", IETF_TRUSTSTORE_MODULE);
        return NTS_ERR_FAILED;
    }

    trusted_certificate_node = lyd_new(NULL, module, "truststore");
    if(trusted_certificate_node == 0) {
        log_error("could not create a new lyd_node\n");
        return NTS_ERR_FAILED;
    }

    char *client_cert = read_key(CLIENT_CERT_PATH);
    rcl = lyd_new_path(trusted_certificate_node, 0, IETF_TRUSTSTORE_CERT_PATH_SCHEMA_XPATH, client_cert, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }
    free(client_cert);

    char *ca_cert = read_key(CA_CERT_PATH);
    rcl = lyd_new_path(trusted_certificate_node, 0, IETF_TRUSTSTORE_CA_CERT_PATH_SCHEMA_XPATH, ca_cert, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path\n");
        return NTS_ERR_FAILED;
    }
    free(ca_cert);

    rc = sr_edit_batch(session, trusted_certificate_node, "replace");
    if(rc != SR_ERR_OK) {
        log_error("could not edit batch on datastore\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_validate(session, IETF_TRUSTSTORE_MODULE, 0);
    if(rc != SR_ERR_OK) {
        struct ly_err_item *err = ly_err_first(session_context);
        log_error("sr_validate issues: %s\n", err->msg);
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore\n");
        return NTS_ERR_FAILED;
    }
 
    return NTS_ERR_OK;
}

static int configure_nacm(sr_session_ctx_t *session) {
    assert(session);

    int rc = NTS_ERR_OK;
    struct lyd_node *rcl = 0;

    struct lys_module *module = 0;
    module = (struct lys_module *) ly_ctx_get_module(session_context, IETF_NETCONF_ACM_MODULE, 0, 0);
    if(module == 0) {
        log_error("could not get module %s from context\n", IETF_NETCONF_ACM_MODULE);
        return NTS_ERR_FAILED;
    }

    struct lyd_node *nacm_node = 0;
    nacm_node = lyd_new(NULL, module, "nacm");
    if(nacm_node == 0) {
        log_error("could not create a new lyd_node\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(nacm_node, 0, IETF_NETCONF_ACM_ENABLE_NACM_SCHEMA_XPATH, "true", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not create yang path\n");
        return NTS_ERR_FAILED;
    }

    // we hardcoded here the username to be used
    rcl = lyd_new_path(nacm_node, 0, IETF_NETCONF_ACM_GROUPS_SCHEMA_XPATH"/group[name='sudo']/user-name", "netconf", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not create yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(nacm_node, 0, IETF_NETCONF_ACM_RULE_LIST_SCHEMA_XPATH"[name='sudo-rules']/group", "sudo", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not create yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(nacm_node, 0, IETF_NETCONF_ACM_RULE_LIST_SCHEMA_XPATH"[name='sudo-rules']/rule[name='allow-all-sudo']/module-name", "*", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not create yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(nacm_node, 0, IETF_NETCONF_ACM_RULE_LIST_SCHEMA_XPATH"[name='sudo-rules']/rule[name='allow-all-sudo']/path", "/", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not create yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(nacm_node, 0, IETF_NETCONF_ACM_RULE_LIST_SCHEMA_XPATH"[name='sudo-rules']/rule[name='allow-all-sudo']/access-operations", "*", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not create yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(nacm_node, 0, IETF_NETCONF_ACM_RULE_LIST_SCHEMA_XPATH"[name='sudo-rules']/rule[name='allow-all-sudo']/action", "permit", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not create yang path\n");
        return NTS_ERR_FAILED;
    }

    rcl = lyd_new_path(nacm_node, 0, IETF_NETCONF_ACM_RULE_LIST_SCHEMA_XPATH"[name='sudo-rules']/rule[name='allow-all-sudo']/comment", "Corresponds all the rules under the sudo group as defined in O-RAN.WG4.MP.0-v05.00", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not create yang path\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_edit_batch(session, nacm_node, "replace");
    if(rc != SR_ERR_OK) {
        log_error("could not edit batch on datastore\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_validate(session, IETF_NETCONF_ACM_MODULE, 0);
    if(rc != SR_ERR_OK) {
        struct ly_err_item *err = ly_err_first(session_context);
        log_error("sr_validate issues: %s\n", err->msg);
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore\n");
        return NTS_ERR_FAILED;
    }
    
    return NTS_ERR_OK;
}

static int create_ssh_listen_endpoints(struct lyd_node *netconf_node, int ssh_connections) {
    assert(netconf_node);

    char xpath[500];
    char local_ip[30];
    struct lyd_node *rcl = 0;

    
    if(framework_environment.settings.ip_v6_enabled) {
        sprintf(local_ip, "::");
    }
    else {
        sprintf(local_ip, "0.0.0.0");
    } 

    char *public_ssh_key = read_key(SERVER_PUBLIC_SSH_KEY_PATH);
    if(public_ssh_key == 0) {
        log_error("could not read the public ssh key from file %s\n", SERVER_PUBLIC_SSH_KEY_PATH);
        return NTS_ERR_FAILED;
    }

    char *ssh_key_string;

    ssh_key_string = strtok(public_ssh_key, " ");
    ssh_key_string = strtok(NULL, " ");

    for(int i = 0; i < ssh_connections; ++i) {
        char endpoint_name[100];
        sprintf(endpoint_name, "mng-ssh-%d", i);

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_TCP_SERVER_PARAM_SCHEMA_XPATH"/local-address", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, local_ip, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        char local_port[10];
        sprintf(local_port, "%d", nc_config_netconf_port++);
        sprintf(xpath, IETF_NETCONF_SERVER_SSH_TCP_SERVER_PARAM_SCHEMA_XPATH"/local-port", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, local_port, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_TCP_SERVER_PARAM_SCHEMA_XPATH"/keepalives/idle-time", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "1", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_TCP_SERVER_PARAM_SCHEMA_XPATH"/keepalives/max-probes", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "10", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_TCP_SERVER_PARAM_SCHEMA_XPATH"/keepalives/probe-interval", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "5", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_SERVER_PARAM_SCHEMA_XPATH"/server-identity/host-key[name='default-key']/public-key/keystore-reference", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, KS_KEY_NAME, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/supported-authentication-methods/publickey", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/supported-authentication-methods/passsword", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/supported-authentication-methods/other", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "interactive", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/users/user[name='netconf']/authorized-key[name='%s']/algorithm", endpoint_name, KS_KEY_NAME);
        rcl = lyd_new_path(netconf_node, 0, xpath, "ssh-rsa", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_SSH_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/users/user[name='netconf']/authorized-key[name='%s']/key-data", endpoint_name, KS_KEY_NAME);
        rcl = lyd_new_path(netconf_node, 0, xpath, ssh_key_string, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }
    } 

    free(public_ssh_key);

    return NTS_ERR_OK;
}

static int create_tls_listen_endpoints(struct lyd_node *netconf_node, int tls_connections) {
    assert(netconf_node);

    struct lyd_node *rcl = 0;
    char xpath[500];
    char local_ip[30];

    if(framework_environment.settings.ip_v6_enabled) {
        sprintf(local_ip, "::");
    }
    else {
        sprintf(local_ip, "0.0.0.0");
    } 

    for(int i = 0; i < tls_connections + 1; ++i) {
        char endpoint_name[100];
        char local_port[10];
        
        

        if(i == tls_connections) {
            //manager connection port
            sprintf(endpoint_name, "manger-tls-internal");
            sprintf(local_port, "%d", CLIENT_CONFIG_TLS_PORT);
        }
        else {
            sprintf(endpoint_name, "mng-tls-%d", i);
            sprintf(local_port, "%d", nc_config_netconf_port++);
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_TCP_SERVER_PARAM_SCHEMA_XPATH"/local-address", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, local_ip, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_TCP_SERVER_PARAM_SCHEMA_XPATH"/local-port", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, local_port, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_TCP_SERVER_PARAM_SCHEMA_XPATH"/keepalives/idle-time", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "1", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_TCP_SERVER_PARAM_SCHEMA_XPATH"/keepalives/max-probes", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "10", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_TCP_SERVER_PARAM_SCHEMA_XPATH"/keepalives/probe-interval", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "5", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_SERVER_PARAM_SCHEMA_XPATH"/server-identity/keystore-reference/asymmetric-key", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, KS_KEY_NAME, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_SERVER_PARAM_SCHEMA_XPATH"/server-identity/keystore-reference/certificate", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, KS_CERT_NAME, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/required", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/ca-certs", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "cacerts", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/client-certs", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "clientcerts", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/cert-maps/cert-to-name[id='1']/fingerprint", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "02:E9:38:1F:F6:8B:62:DE:0A:0B:C5:03:81:A8:03:49:A0:00:7F:8B:F3", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/cert-maps/cert-to-name[id='1']/map-type", endpoint_name);
        rcl = lyd_new_path(netconf_node, session_context, xpath, "ietf-x509-cert-to-name:specified", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, IETF_NETCONF_SERVER_TLS_SERVER_PARAM_SCHEMA_XPATH"/client-authentication/cert-maps/cert-to-name[id='1']/name", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "netconf", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path\n");
            return NTS_ERR_FAILED;
        }
    }

    return NTS_ERR_OK;
}

static int configure_endpoints_connections(sr_session_ctx_t *session) {
    assert(session);

    int rc = NTS_ERR_OK;

    struct lys_module *module = 0;
    module = (struct lys_module *)ly_ctx_get_module(session_context, IETF_NETCONF_SERVER_MODULE, 0, 0);
    if(module == 0) {
        log_error("could not get module %s from context\n", IETF_NETCONF_SERVER_MODULE);
        return NTS_ERR_FAILED;
    }


    struct lyd_node *netconf_node = 0;
    netconf_node = lyd_new_path(NULL, session_context, IETF_NETCONF_SERVER_SCHEMA_XPATH, 0, 0, 0);
    if(netconf_node == 0) {
        log_error("could not create a new lyd_node\n");
        return NTS_ERR_FAILED;
    }

    // create the SSH endpoints in ietf-netconf-server
    int ssh_connections = 0;
    if(framework_arguments.nts_mode == NTS_MODE_MANAGER) {
        ssh_connections = 1;
    }
    else {
        ssh_connections = framework_environment.settings.ssh_connections;
    }

    if(ssh_connections + framework_environment.settings.tls_connections == 0) {
        log_error("ssh_connections + tls_connections must be at least 1\n");
        return NTS_ERR_FAILED;
    }

    rc = create_ssh_listen_endpoints(netconf_node, ssh_connections);
    if(rc != NTS_ERR_OK) {
        log_error("could not create %d SSH Listen endpoints on the NETCONF Server\n", ssh_connections);
        return NTS_ERR_FAILED;
    }

    // create the TLS endpoints in ietf-netconf-server
    if(framework_arguments.nts_mode != NTS_MODE_MANAGER) {
        rc = create_tls_listen_endpoints(netconf_node, framework_environment.settings.tls_connections);
        if(rc != NTS_ERR_OK) {
            log_error("could not create %d TLS Listen endpoints on the NETCONF Server\n", framework_environment.settings.tls_connections);
            return NTS_ERR_FAILED;
        }
    }
    
    rc = sr_edit_batch(session, netconf_node, "replace");
    if(rc != SR_ERR_OK) {
        log_error("could not edit batch on datastore\n");
        return NTS_ERR_FAILED;
    }

    rc = sr_validate(session, IETF_NETCONF_SERVER_MODULE, 0);
    if(rc != SR_ERR_OK) {
        struct ly_err_item *err = ly_err_first(session_context);
        log_error("sr_validate issues on STARTUP: %s\n", err->msg);
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore\n");
        return NTS_ERR_FAILED;
    }
    
    return NTS_ERR_OK;
}
