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

#include "nc_client.h"
#include "utils/log_utils.h"
#include "utils/sys_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "core/session.h"
#include "core/nc_config.h"

#include <libnetconf2/session.h>
#include <libnetconf2/session_client.h>
#include <libnetconf2/messages_client.h>

static char *nc_client_pass_cb(const char *username, const char *hostname, void *priv) {
    nc_client_t *client = (nc_client_t *)priv;
    return strdup(client->password);
}

static int nc_client_auth_hostkey_check(const char *hostname, ssh_session session, void *priv) {
    return 0;   //auto-authorize
}

nc_client_t *nc_client_ssh_connect(const char *host, uint16_t port, const char *username, const char *password) {
    assert(host);
    assert(port > 20);
    assert(username);
    assert(password);

    nc_client_t *client = (nc_client_t *)malloc(sizeof(nc_client_t));
    if(client == 0) {
        return 0;
    }

    client->edit_batch_root = 0;

    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, 3);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, -1);

    nc_client_ssh_set_username(username);
    client->password = strdup(password);
    if(client->password == 0) {
        log_error("strdup failed\n");
        free(client);
        return 0;
    }

    nc_client_ssh_set_auth_password_clb(nc_client_pass_cb, client);
    nc_client_ssh_set_auth_hostkey_check_clb(nc_client_auth_hostkey_check, 0);

    client->session = nc_connect_ssh(host, port, 0);
    if(client->session == 0) {
        log_error("nc_connect_ssh failed\n");
        free(client->password);
        free(client);
        return 0;
    }

    return client;
}

nc_client_t *nc_client_tls_connect(const char *host, uint16_t port) {
    assert(host);
    assert(port > 20);

    nc_client_t *client = (nc_client_t *)malloc(sizeof(nc_client_t));
    if(client == 0) {
        return 0;
    }

    client->edit_batch_root = 0;
    client->password = 0;
    int rc = nc_client_tls_set_cert_key_paths(CLIENT_CERT_PATH, CLIENT_KEY_PATH);
    if(rc != 0) {
        log_error("nc_client_tls_set_cert_key_paths failed\n");
        return 0;
    }

    rc = nc_client_tls_set_trusted_ca_paths(CLIENT_CA_FILE, 0);
    if(rc != 0) {
        log_error("nc_client_tls_set_trusted_ca_paths failed\n");
        return 0;
    }

    client->session = nc_connect_tls(host, port, 0);
    if(client->session == 0) {
        log_error("nc_connect_tls failed\n");
        free(client);
        return 0;
    }

    return client;
}

int nc_client_disconnect(nc_client_t *client) {
    assert(client);
    
    nc_session_free(client->session, 0);
    free(client->password);
    free(client);

    return NTS_ERR_OK;
}

struct lyd_node *nc_client_send_rpc(nc_client_t *client, struct lyd_node *data, int timeout) {
    assert(client);
    assert(data);

    struct nc_rpc *rpc;
    struct nc_reply *reply;
    NC_MSG_TYPE send_ret;
    NC_MSG_TYPE reply_ret;
    uint64_t msg_id;

    char *xmldata = 0;
    if(lyd_print_mem(&xmldata, data, LYD_XML, 0) != 0) {
        log_error("lyd_print_mem failed\n");
        return 0;
    }

    rpc = nc_rpc_act_generic_xml(xmldata, NC_PARAMTYPE_CONST);
    if(rpc == 0) {
        log_error("could not create rpc\n");
        free(xmldata);
        return 0;
    }

    msg_id = 0;
    send_ret = nc_send_rpc(client->session, rpc, timeout, &msg_id);
    if(send_ret != NC_MSG_RPC) {
        log_error("could not send rpc\n");
        free(xmldata);
        nc_rpc_free(rpc);
        return 0;
    }

    repeat_nc_recv_reply:
    reply_ret = nc_recv_reply(client->session, rpc, msg_id, timeout, LYD_OPT_DESTRUCT | LYD_OPT_NOSIBLINGS, &reply);
    if(reply_ret != NC_MSG_REPLY) {
        if(reply_ret == NC_MSG_NOTIF) {
            goto repeat_nc_recv_reply;
        }

        log_error("could not get rpc reply\n");
        free(xmldata);
        nc_rpc_free(rpc);
        return 0;
    }

    if(reply->type != NC_RPL_DATA) {
        log_error("reply has no data\n");
        free(xmldata);
        nc_rpc_free(rpc);
        nc_reply_free(reply);
        return 0;
    }

    char *ret_data_xml = strdup("");    //libyang does not support having the parent RPC in XML
    struct lyd_node *chd = 0;
    LY_TREE_FOR(((struct nc_reply_data *)reply)->data->child, chd) {
        char *temp_xml = 0;
        if(lyd_print_mem(&temp_xml, chd, LYD_XML, 0) != 0) {
            log_error("lyd_print_mem failed\n");
            free(ret_data_xml);
            free(xmldata);
            nc_rpc_free(rpc);
            nc_reply_free(reply);
            return 0;
        }

        ret_data_xml = (char *)realloc(ret_data_xml, sizeof(char) * (strlen(ret_data_xml) + strlen(temp_xml) + 1));
        strcat(ret_data_xml, temp_xml);
        free(temp_xml);
    }
    
    free(xmldata);
    nc_reply_free(reply);
    nc_rpc_free(rpc);

    struct lyd_node *ret_data = lyd_parse_mem(session_context, ret_data_xml, LYD_XML, LYD_OPT_RPCREPLY | LYD_OPT_NOEXTDEPS, data, 0);
    free(ret_data_xml);
    return ret_data;
}

struct lyd_node *nc_client_get_batch(nc_client_t *client, const char *xpath, int timeout) {
    assert(client);
    assert(xpath);

    struct nc_rpc *rpc;
    struct nc_reply *reply;
    NC_MSG_TYPE send_ret;
    NC_MSG_TYPE reply_ret;
    uint64_t msg_id;

    rpc = nc_rpc_get(xpath, NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
    if(rpc == 0) {
        log_error("could not create rpc\n");
        return 0;
    }

    msg_id = 0;
    send_ret = nc_send_rpc(client->session, rpc, timeout, &msg_id);
    if(send_ret != NC_MSG_RPC) {
        log_error("could not send rpc\n");
        nc_rpc_free(rpc);
        return 0;
    }

    repeat_nc_recv_reply:
    reply_ret = 0;
    reply_ret = nc_recv_reply(client->session, rpc, msg_id, timeout, LYD_OPT_DESTRUCT | LYD_OPT_NOSIBLINGS, &reply);
    if(reply_ret != NC_MSG_REPLY) {
        if(reply_ret == NC_MSG_NOTIF) {
            goto repeat_nc_recv_reply;
        }

        log_error("could not get rpc reply\n");
        nc_rpc_free(rpc);
        return 0;
    }

    if(reply->type != NC_RPL_DATA) {
        log_error("reply has no data\n");
        nc_rpc_free(rpc);
        nc_reply_free(reply);
        return 0;
    }

    char *ret_data_xml = 0;
    if(lyd_print_mem(&ret_data_xml, ((struct nc_reply_data *)reply)->data, LYD_XML, 0) != 0) {
        log_error("lyd_print_mem failed\n");
        nc_reply_free(reply);
        nc_rpc_free(rpc);
        return 0;
    }
    
    nc_reply_free(reply);
    nc_rpc_free(rpc);

    struct lyd_node *ret_data = lyd_parse_mem(session_context, ret_data_xml, LYD_XML, LYD_OPT_DATA | LYD_OPT_NOSIBLINGS);
    free(ret_data_xml);
    return ret_data;
}

int nc_client_edit_batch(nc_client_t *client, struct lyd_node *data, int timeout) {
    assert(client);
    assert(data);

    struct nc_rpc *rpc;
    struct nc_reply *reply;
    NC_MSG_TYPE send_ret;
    NC_MSG_TYPE reply_ret;
    uint64_t msg_id;

    char *content = 0;
    int rc = lyd_print_mem(&content, data, LYD_XML, 0);
    if(rc != 0) {
        log_error("lyd_print_mem failed\n");
        return NTS_ERR_FAILED;
    }

    rpc = nc_rpc_edit(NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_MERGE, NC_RPC_EDIT_TESTOPT_SET, NC_RPC_EDIT_ERROPT_STOP, content, NC_PARAMTYPE_CONST);
    if(rpc == 0) {
        log_error("could not create rpc\n");
        free(content);
        return NTS_ERR_FAILED;
    }
    
    msg_id = 0;
    send_ret = nc_send_rpc(client->session, rpc, timeout, &msg_id);
    if(send_ret != NC_MSG_RPC) {
        log_error("could not send rpc\n");
        free(content);
        nc_rpc_free(rpc);
        return NTS_ERR_FAILED;
    }

    reply_ret = nc_recv_reply(client->session, rpc, msg_id, timeout, LYD_OPT_DESTRUCT | LYD_OPT_NOSIBLINGS, &reply);
    if((reply_ret != NC_MSG_REPLY) || (reply->type != NC_RPL_OK)) {
        log_error("could not get rpc reply\n");

        free(content);
        nc_rpc_free(rpc);
        return NTS_ERR_FAILED;
    }
    
    free(content);
    nc_reply_free(reply);
    nc_rpc_free(rpc);

    return NTS_ERR_OK;
}

int nc_client_set_item_str(nc_client_t *client, const char *xpath, const char *value) {
    assert(client);
    assert(xpath);
    assert(value);

    if(client->edit_batch_root) {
        struct lyd_node *n = lyd_new_path(client->edit_batch_root, 0, xpath, (void*)value, LYD_ANYDATA_CONSTSTRING, 0);
        if(n == 0) {
            log_error("lyd_new_path error\n");
            return NTS_ERR_FAILED;
        }
    }
    else {
        client->edit_batch_root = lyd_new_path(0, session_context, xpath, (void*)value, LYD_ANYDATA_CONSTSTRING, 0);
        if(client->edit_batch_root == 0) {
            log_error("lyd_new_path error\n");
            return NTS_ERR_FAILED;
        }
    }

    return NTS_ERR_OK;
}

int nc_client_edit_apply_changes(nc_client_t *client, int timeout) {
    assert(client);
    assert(client->edit_batch_root);

    int rc = nc_client_edit_batch(client, client->edit_batch_root, timeout);
    lyd_free_withsiblings(client->edit_batch_root);
    client->edit_batch_root = 0;
    return rc;
}

int lyd_utils_dup(sr_session_ctx_t *session, const char *xpath_s, const char *xpath_d, struct lyd_node **tree) {
    assert(session);
    assert(xpath_s);
    assert(xpath_d);
    assert(tree);

    if(*tree == 0) {
        *tree = lyd_new_path(0, session_context, xpath_d, 0, LYD_ANYDATA_CONSTSTRING, 0);
        if(*tree == 0) {
            return NTS_ERR_FAILED;
        }
    }

    struct lyd_node *data_s = 0;
    int rc = sr_get_data(session, xpath_s, 0, 0, 0, &data_s);
    if(rc != SR_ERR_OK) {
        log_error("could not get value for xPath=%s from the datastore\n", xpath_s);
        lyd_free(*tree);
        return NTS_ERR_FAILED;
    }

    struct lyd_node *next = 0;
    struct lyd_node *snode = 0;
    LY_TREE_DFS_BEGIN(data_s, next, snode) {
        char *xpath_c = lyd_path(snode);
        if((snode->schema->nodetype == LYS_LEAF) || (snode->schema->nodetype == LYS_LEAFLIST)) {
            const char *value = ((struct lyd_node_leaf_list*)snode)->value_str;
            char *new_xpath = str_replace(xpath_c, xpath_s, xpath_d);
            
            // ly_log_options(0);
            ly_verb(LY_LLERR);  //checkAL
            lyd_new_path(*tree, 0, new_xpath, (void*)value, LYD_ANYDATA_CONSTSTRING, 0);
            free(xpath_c);
            free(new_xpath);
        }
        LY_TREE_DFS_END(data_s, next, snode);
    }

    lyd_free(data_s);
    return NTS_ERR_OK;
}
