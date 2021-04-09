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

#include "type_utils.h"
#include "log_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

const char* typeutils_yang_type_to_str(const LY_DATA_TYPE type_base) {
    switch(type_base) {
        case LY_TYPE_DER:
            return "LY_TYPE_DER";
            break;

        case LY_TYPE_BINARY:
            return "LY_TYPE_BINARY";
            break;

        case LY_TYPE_BITS:
            return "LY_TYPE_BITS";
            break;

        case LY_TYPE_BOOL:
            return "LY_TYPE_BOOL";
            break;

        case LY_TYPE_DEC64:
            return "LY_TYPE_DEC64";
            break;

        case LY_TYPE_EMPTY:
            return "LY_TYPE_EMPTY";
            break;

        case LY_TYPE_ENUM:
            return "LY_TYPE_ENUM";
            break;

        case LY_TYPE_IDENT:
            return "LY_TYPE_IDENT";
            break;

        case LY_TYPE_INST:
            return "LY_TYPE_INST";
            break;

        case LY_TYPE_LEAFREF:
            return "LY_TYPE_LEAFREF";
            break;

        case LY_TYPE_STRING:
            return "LY_TYPE_STRING";
            break;

        case LY_TYPE_UNION:
            return "LY_TYPE_UNION";
            break;

        case LY_TYPE_INT8:
            return "LY_TYPE_INT8";
            break;

        case LY_TYPE_UINT8:
            return "LY_TYPE_UINT8";
            break;

        case LY_TYPE_INT16:
            return "LY_TYPE_INT16";
            break;

        case LY_TYPE_UINT16:
            return "LY_TYPE_UINT16";
            break;

        case LY_TYPE_INT32:
            return "LY_TYPE_INT32";
            break;

        case LY_TYPE_UINT32:
            return "LY_TYPE_UINT32";
            break;

        case LY_TYPE_INT64:
            return "LY_TYPE_INT64";
            break;

        case LY_TYPE_UINT64:
            return "LY_TYPE_UINT64";
            break;

        case LY_TYPE_UNKNOWN:
            return "LY_TYPE_UNKNOWN";
            break;
    }

    return "(unknown LY_TYPE)";
}

const char* typeutils_yang_nodetype_to_str(const LYS_NODE nodetype) {
    switch(nodetype) {
        case LYS_UNKNOWN:
            return "LYS_UNKNOWN";
            break;

        case LYS_CONTAINER:
            return "LYS_CONTAINER";
            break;

        case LYS_CHOICE:
            return "LYS_CHOICE";
            break;

        case LYS_LEAF:
            return "LYS_LEAF";
            break;

        case LYS_LEAFLIST:
            return "LYS_LEAFLIST";
            break;

        case LYS_LIST:
            return "LYS_LIST";
            break;

        case LYS_ANYXML:
            return "LYS_ANYXML";
            break;

        case LYS_CASE:
            return "LYS_CASE";
            break;

        case LYS_NOTIF:
            return "LYS_NOTIF";
            break;

        case LYS_RPC:
            return "LYS_RPC";
            break;

        case LYS_INPUT:
            return "LYS_INPUT";
            break;

        case LYS_OUTPUT:
            return "LYS_OUTPUT";
            break;

        case LYS_GROUPING:
            return "LYS_GROUPING";
            break;

        case LYS_USES:
            return "LYS_USES";
            break;

        case LYS_AUGMENT:
            return "LYS_AUGMENT";
            break;

        case LYS_ACTION:
            return "LYS_ACTION";
            break;

        case LYS_ANYDATA:
            return "LYS_ANYDATA";
            break;

        case LYS_EXT:
            return "LYS_EXT";
            break;

        default:
            return "(unknown node type)";
            break;

    }
}

char* typeutils_type_to_str(const struct lys_type *type) {
    assert(type);

    struct lys_ident *ref = 0;
    char *ret = 0;

    switch(type->base) {
        case LY_TYPE_ENUM:
            if(type->info.enums.count) {
                ret = (char*)realloc(ret, sizeof(char) * 1024 * 1024);
                if(!ret) {
                    log_error("bad malloc\n");
                    return 0;
                }

                sprintf(ret, "enum(%d):", type->info.enums.count);
                for(int i = 0; i < type->info.enums.count; i++) {
                    char *add = 0;
                    asprintf(&add, " %s(%d)", type->info.enums.enm[i].name, type->info.enums.enm[i].value);
                    strcat(ret, add);
                    free(add);
                }

                ret = (char*)realloc(ret, sizeof(char) * (strlen(ret) + 1));    //resize back
            }
            else {
                if(type->der) {
                    char *add = typeutils_type_to_str(&type->der->type);
                    if(type->der->module) {
                        asprintf(&ret, "%s:%s >>> %s", type->der->module->name, type->der->name, add);
                    }
                    else  {
                        asprintf(&ret, "%s >>> %s", type->der->name, add);
                    }
                    free(add);
                }
            }
            break;

        case LY_TYPE_IDENT:         
            if(type->info.ident.count) {
                ref = type->info.ident.ref[0];
                if(ref) {
                    if(ref->module) {
                        asprintf(&ret, "ident: %s:%s", ref->module->name, ref->name);
                    }
                    else  {
                        asprintf(&ret, "ident: %s", ref->name);
                    }
                }
            }
            else if(type->der->module) {
                return typeutils_type_to_str(&type->der->type);
            }
            break;

        case LY_TYPE_UNION:
            if(type->der) {
                if(type->der->module) {
                    asprintf(&ret, "union: %s:%s", type->der->module->name, type->der->name);
                }
                else  {
                    asprintf(&ret, "union: %s", type->der->name);
                }
            }
            break;

        case LY_TYPE_STRING:
            if(type->info.str.length) {
                asprintf(&ret, "%s:%s", type->der->name, type->info.str.length->expr);
            }
            else {
                asprintf(&ret, "%s", type->der->name);
            }
            break;

        default:
            if(type->der) {
                if(type->der->module) {
                    asprintf(&ret, "%s:%s", type->der->module->name, type->der->name);
                }
                else  {
                    asprintf(&ret, "%s", type->der->name);
                }
            }
            break;
    }

    return ret;
}
