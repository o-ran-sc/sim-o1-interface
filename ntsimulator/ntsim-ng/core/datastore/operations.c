/*************************************************************************
*
* Copyright 2021 highstreet technologies GmbH and others
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

#include "operations.h"
#include "utils/log_utils.h"

int datastore_operations_add_sr_val(struct lyd_node *datastore, const sr_val_t *val) {
    char *sval = sr_val_to_str(val);
    struct lyd_node *rc = lyd_new_path(datastore, 0, val->xpath, sval, 0, LYD_PATH_OPT_UPDATE);
    free(sval);
    if(rc == 0) {
        log_error("lyd_new_path failed\n");
        return NTS_ERR_FAILED;
    }

    return NTS_ERR_OK;
}

int datastore_operations_change_sr_val(struct lyd_node *datastore, const sr_val_t *val) {
    return datastore_operations_add_sr_val(datastore, val);
}

int datastore_operations_free_path(struct lyd_node *datastore, const char *xpath) {
    struct ly_set *set = lyd_find_path(datastore, xpath);
    if(set && set->number) {
        struct lyd_node *node = set->set.d[0];
        lyd_free(node);
    }
    else {
        log_error("lyd_find_path error on %s\n", xpath);
        ly_set_free(set);
        return NTS_ERR_FAILED;
    }
    ly_set_free(set);

    return NTS_ERR_OK;
}

struct lyd_node *datastore_operations_get_lyd_node(struct lyd_node *datastore, const char *xpath) {
    struct ly_set *set = lyd_find_path(datastore, xpath);
    struct lyd_node *node = 0;
    if(set && set->number) {
        node = set->set.d[0];
    }
    ly_set_free(set);

    return node;
}
