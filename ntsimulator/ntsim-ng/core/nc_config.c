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
#include <stdio.h>
#include <assert.h>

#include <libyang/libyang.h>
#include "core/session.h"
#include "core/framework.h"

#define GEN_KEY_SCRIPT                              "/home/netconf/.ssh/generate-ssh-keys.sh"
#define KS_CERT_NAME                                "melacon_server_cert"
#define SERVER_PRIVATE_KEY_PATH                     "/home/netconf/.ssh/melacon.server.key"
#define SERVER_PUBLIC_KEY_PATH                      "/home/netconf/.ssh/melacon.server.key.pub.pem"
#define SERVER_CERT_PATH                            "/home/netconf/.ssh/melacon.server.crt"
#define CLIENT_CERT_PATH                            "/home/netconf/.ssh/client.crt"
#define CA_CERT_PATH                                "/home/netconf/.ssh/ca.pem"

static int nc_config_netconf_port = STANDARD_NETCONF_PORT;

static int load_ssh_keys(sr_session_ctx_t *session);
static int load_trusted_certificates(sr_session_ctx_t *session);
static int remove_nacm(sr_session_ctx_t *session);
static int create_ssh_listen_endpoints(struct lyd_node *netconf_node, int ssh_connections);
static int create_tls_listen_endpoints(struct lyd_node *netconf_node, int tls_connections);
static int configure_endpoints_connections(sr_session_ctx_t *session);

int netconf_configure(void) {
    int rc = NTS_ERR_OK;

    nc_config_netconf_port = STANDARD_NETCONF_PORT;

    sr_session_ctx_t *current_session;
    rc = sr_session_start(session_connection, SR_DS_RUNNING, &current_session);
    if(rc != 0) {
        log_error("could not start session on running datastore");
        return NTS_ERR_FAILED;
    }

    // generate and load private keys
    log_message(1, "ietf-keystore startup datastore configuration...");     //checkAS e ok aici ?
    rc = load_ssh_keys(current_session);
    if(rc != 0) {
        log_error("could not load SSH keys");
        return NTS_ERR_FAILED;
    }
    log_message(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);

    // load trusted certificates
    log_message(1, "ietf-truststore startup datastore configuration...");
    rc = load_trusted_certificates(current_session);
    if(rc != 0) {
        log_error("could not load trusted certificates");
        return NTS_ERR_FAILED;
    }
    log_message(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);

    // remove NACM
    log_message(1, "Removing NACM...");
    rc = remove_nacm(current_session);
    if(rc != 0) {
        log_error("could not remove NACM");
        return NTS_ERR_FAILED;
    }
    log_message(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);

    // configure SSH connections
    log_message(1, "Configuring connection endpoints...");
    rc = configure_endpoints_connections(current_session);
    if(rc != 0) {
        log_error("could not configure endpoint connections forNETCONF Server");
        return NTS_ERR_FAILED;
    }
    log_message(1, LOG_COLOR_BOLD_GREEN"done\n"LOG_COLOR_RESET);

    rc = sr_session_stop(current_session);
    if(rc != 0) {
        log_error("could not configure stop current sysrepo session");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

static int load_ssh_keys(sr_session_ctx_t *session) {
    assert(session);

    int rc = NTS_ERR_OK;
    char xpath[500];
    struct lyd_node *rcl = 0;

    rc = system(GEN_KEY_SCRIPT);
    if(rc != 0) {
        log_error("could not generate the SSH keys");
        return NTS_ERR_FAILED;
    }

    struct lys_module *module;
    module = (struct lys_module *)ly_ctx_get_module(session_context, "ietf-keystore", 0, 0);
    if(module == 0) {
        log_error("could not get module %s from context", "ietf-keystore");
        return NTS_ERR_FAILED;
    }
    
    struct lyd_node *keystore_node = 0;
    keystore_node = lyd_new(NULL, module, "keystore");
    if(keystore_node == 0) {
        log_error("could not create a new lyd_node");
        return NTS_ERR_FAILED;
    }

    sprintf(xpath, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']/algorithm", KS_KEY_NAME);
    rcl = lyd_new_path(keystore_node, 0, xpath, "rsa2048", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path");
        return NTS_ERR_FAILED;
    }

    char *private_key = read_key(SERVER_PRIVATE_KEY_PATH);
    if(private_key == 0) {
        log_error("could not read the private key from path=%s", SERVER_PRIVATE_KEY_PATH);
        return NTS_ERR_FAILED;
    }
    log_message(2, "Private Key that was built: \n%s\n", private_key);

    sprintf(xpath, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']/private-key", KS_KEY_NAME);
    rcl = lyd_new_path(keystore_node, 0, xpath, private_key, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path");
        return NTS_ERR_FAILED;
    }

    free(private_key);

    char *public_key = read_key(SERVER_PUBLIC_KEY_PATH);
    if(public_key == 0) {
        log_error("could not read the public key from path=%s", SERVER_PUBLIC_KEY_PATH);
        return NTS_ERR_FAILED;
    }
    log_message(2, "Public Key that was built: \n%s\n", public_key);

    sprintf(xpath, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']/public-key", KS_KEY_NAME);
    rcl = lyd_new_path(keystore_node, 0, xpath, public_key, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path");
        return NTS_ERR_FAILED;
    }

    free(public_key);

    char *certificate = read_key(SERVER_CERT_PATH);
    if(certificate == 0) {
        log_error("could not read the certificate from path=%s", SERVER_CERT_PATH);
        return NTS_ERR_FAILED;
    }
    log_message(2, "Certificate that was built: \n%s\n", certificate);

    sprintf(xpath, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']/certificates/certificate[name='%s']/cert", KS_KEY_NAME, KS_CERT_NAME);
    rcl = lyd_new_path(keystore_node, 0, xpath, certificate, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path");
        return NTS_ERR_FAILED;
    }

    free(certificate);

    rc = sr_edit_batch(session, keystore_node, "replace");
    if(rc != SR_ERR_OK) {
        log_error("could not edit batch on datastore");
        return NTS_ERR_FAILED;
    }

    rc = sr_validate(session, "ietf-keystore", 0);
    if(rc != SR_ERR_OK) {
        struct ly_err_item *err = ly_err_first(session_context);
        log_error("sr_validate issues on STARTUP: %s", err->msg);
        return false;
    }

    rc = sr_apply_changes(session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore");
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
    module = (struct lys_module *)ly_ctx_get_module(session_context, "ietf-truststore", 0, 0);
    if(module == 0) {
        log_error("could not get module %s from context", "ietf-truststore");
        return NTS_ERR_FAILED;
    }

    trusted_certificate_node = lyd_new(NULL, module, "truststore");
    if(trusted_certificate_node == 0) {
        log_error("could not create a new lyd_node");
        return NTS_ERR_FAILED;
    }

    char xpath[500];

    sprintf(xpath, "/ietf-truststore:truststore/certificates[name='clientcerts']/certificate[name='clientcert']/cert");
    char *client_cert = read_key(CLIENT_CERT_PATH);
    rcl = lyd_new_path(trusted_certificate_node, 0, xpath, client_cert, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path");
        return NTS_ERR_FAILED;
    }
    free(client_cert);

    sprintf(xpath, "/ietf-truststore:truststore/certificates[name='cacerts']/certificate[name='cacert']/cert");
    char *ca_cert = read_key(CA_CERT_PATH);
    rcl = lyd_new_path(trusted_certificate_node, 0, xpath, ca_cert, 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path");
        return NTS_ERR_FAILED;
    }
    free(ca_cert);

    rc = sr_edit_batch(session, trusted_certificate_node, "replace");
    if(rc != SR_ERR_OK) {
        log_error("could not edit batch on datastore");
        return NTS_ERR_FAILED;
    }

    rc = sr_validate(session, "ietf-truststore", 0);
    if(rc != SR_ERR_OK) {
        struct ly_err_item *err = ly_err_first(session_context);
        log_error("sr_validate issues on STARTUP: %s", err->msg);
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore");
        return NTS_ERR_FAILED;
    }
 
    return NTS_ERR_OK;
}

static int remove_nacm(sr_session_ctx_t *session) {
    assert(session);

    int rc = NTS_ERR_OK;
    struct lyd_node *rcl = 0;
    char xpath[100];

    struct lys_module *module = 0;
    module = (struct lys_module *) ly_ctx_get_module(session_context, "ietf-netconf-acm", 0, 0);
    if(module == 0) {
        log_error("could not get module %s from context", "ietf-netconf-acm");
        return NTS_ERR_FAILED;
    }

    struct lyd_node *nacm_node = 0;
    nacm_node = lyd_new(NULL, module, "nacm");
    if(nacm_node == 0) {
        log_error("could not create a new lyd_node");
        return NTS_ERR_FAILED;
    }

    sprintf(xpath, "/ietf-netconf-acm:nacm/enable-nacm");
    rcl = lyd_new_path(nacm_node, 0, xpath, "false", 0, LYD_PATH_OPT_NOPARENTRET);
    if(rcl == 0) {
        log_error("could not created yang path");
        return NTS_ERR_FAILED;
    }

    rc = sr_edit_batch(session, nacm_node, "replace");
    if(rc != SR_ERR_OK) {
        log_error("could not edit batch on datastore");
        return NTS_ERR_FAILED;
    }

    rc = sr_validate(session, "ietf-netconf-acm", 0);
    if(rc != SR_ERR_OK) {
        struct ly_err_item *err = ly_err_first(session_context);
        log_error("sr_validate issues on STARTUP: %s", err->msg);
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore");
        return NTS_ERR_FAILED;
    }
    
    return NTS_ERR_OK;
}

static int create_ssh_listen_endpoints(struct lyd_node *netconf_node, int ssh_connections) {
    assert(netconf_node);

    char xpath[500];
    char local_ip[30];
    struct lyd_node *rcl = 0;

    
    if(framework_environment.ip_v6_enabled) {
        sprintf(local_ip, "::");
    }
    else {
        sprintf(local_ip, "0.0.0.0");
    } 

    char *public_ssh_key = read_key(SERVER_PUBLIC_SSH_KEY_PATH);
    if(public_ssh_key == 0) {
        log_error("could not read the public ssh key from file %s", SERVER_PUBLIC_SSH_KEY_PATH);
        return NTS_ERR_FAILED;
    }

    char *ssh_key_string;

    ssh_key_string = strtok(public_ssh_key, " ");
    ssh_key_string = strtok(NULL, " ");

    for(int i=0; i < ssh_connections; ++i) {
        char endpoint_name[100];
        sprintf(endpoint_name, "mng-ssh-%d", i);

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/tcp-server-parameters/local-address", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, local_ip, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        char local_port[10];
        sprintf(local_port, "%d", nc_config_netconf_port++);
        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/tcp-server-parameters/local-port", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, local_port, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/tcp-server-parameters/keepalives/idle-time", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "1", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/tcp-server-parameters/keepalives/max-probes", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "10", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/tcp-server-parameters/keepalives/probe-interval", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "5", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/host-key[name='default-key']/public-key/keystore-reference", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, KS_KEY_NAME, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/supported-authentication-methods/publickey", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/supported-authentication-methods/passsword", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/supported-authentication-methods/other", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "interactive", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='netconf']/authorized-key[name='%s']/algorithm", endpoint_name, KS_KEY_NAME);
        rcl = lyd_new_path(netconf_node, 0, xpath, "ssh-rsa", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='netconf']/authorized-key[name='%s']/key-data", endpoint_name, KS_KEY_NAME);
        rcl = lyd_new_path(netconf_node, 0, xpath, ssh_key_string, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
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

    if(framework_environment.ip_v6_enabled) {
        sprintf(local_ip, "::");
    }
    else {
        sprintf(local_ip, "0.0.0.0");
    } 

    for(int i=0; i < tls_connections; ++i) {
        char endpoint_name[100];
        sprintf(endpoint_name, "mng-tls-%d", i);

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tcp-server-parameters/local-address", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, local_ip, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        char local_port[10];
        sprintf(local_port, "%d", nc_config_netconf_port++);
        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tcp-server-parameters/local-port", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, local_port, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tcp-server-parameters/keepalives/idle-time", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "1", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tcp-server-parameters/keepalives/max-probes", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "10", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tcp-server-parameters/keepalives/probe-interval", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "5", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/server-identity/keystore-reference/asymmetric-key", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, KS_KEY_NAME, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/server-identity/keystore-reference/certificate", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, KS_CERT_NAME, 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/required", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ca-certs", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "cacerts", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/client-certs", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "clientcerts", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/cert-maps/cert-to-name[id='1']/fingerprint", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "02:E9:38:1F:F6:8B:62:DE:0A:0B:C5:03:81:A8:03:49:A0:00:7F:8B:F3", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/cert-maps/cert-to-name[id='1']/map-type", endpoint_name);
        rcl = lyd_new_path(netconf_node, session_context, xpath, "ietf-x509-cert-to-name:specified", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }

        sprintf(xpath, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/cert-maps/cert-to-name[id='1']/name", endpoint_name);
        rcl = lyd_new_path(netconf_node, 0, xpath, "netconf-tls", 0, LYD_PATH_OPT_NOPARENTRET);
        if(rcl == 0) {
            log_error("could not created yang path");
            return NTS_ERR_FAILED;
        }
    }

    return NTS_ERR_OK;
}

static int configure_endpoints_connections(sr_session_ctx_t *session) {
    assert(session);

    int rc = NTS_ERR_OK;

    struct lys_module *module = 0;
    module = (struct lys_module *)ly_ctx_get_module(session_context, "ietf-netconf-server", 0, 0);
    if(module == 0) {
        log_error("could not get module %s from context", "ietf-netconf-server");
        return NTS_ERR_FAILED;
    }


    struct lyd_node *netconf_node = 0;
    netconf_node = lyd_new_path(NULL, session_context, "/ietf-netconf-server:netconf-server", 0, 0, 0);
    if(netconf_node == 0) {
        log_error("could not create a new lyd_node");
        return NTS_ERR_FAILED;
    }

    // create the SSH endpoints in ietf-netconf-server
    int ssh_connections = 0;
    if(framework_arguments.manager) {
        ssh_connections = 1;
    }
    else {
        ssh_connections = framework_environment.ssh_connections;
    }

    if(ssh_connections == 0) {
        log_error("ssh_connections must be at least 1");
        return NTS_ERR_FAILED;
    }

    rc = create_ssh_listen_endpoints(netconf_node, ssh_connections);
    if(rc != NTS_ERR_OK) {
        log_error("could not create %d SSH Listen endpoints on the NETCONF Server", ssh_connections);
        return NTS_ERR_FAILED;
    }

    // create the TLS endpoints in ietf-netconf-server
    if(framework_arguments.manager == false) {
        rc = create_tls_listen_endpoints(netconf_node, framework_environment.tls_connections);
        if(rc != NTS_ERR_OK) {
            log_error("could not create %d TLS Listen endpoints on the NETCONF Server", framework_environment.tls_connections);
            return NTS_ERR_FAILED;
        }
    }
    
    rc = sr_edit_batch(session, netconf_node, "replace");
    if(rc != SR_ERR_OK) {
        log_error("could not edit batch on datastore");
        return NTS_ERR_FAILED;
    }

    rc = sr_validate(session, "ietf-netconf-server", 0);
    if(rc != SR_ERR_OK) {
        struct ly_err_item *err = ly_err_first(session_context);
        log_error("sr_validate issues on STARTUP: %s", err->msg);
        return NTS_ERR_FAILED;
    }

    rc = sr_apply_changes(session, 0, 0);
    if(rc != SR_ERR_OK) {
        log_error("could not apply changes on datastore");
        return NTS_ERR_FAILED;
    }
    
    return NTS_ERR_OK;
}
