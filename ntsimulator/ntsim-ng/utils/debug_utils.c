#include "debug_utils.h"
#include "log_utils.h"

#include <inttypes.h>

void debug_print_sr_val(const sr_val_t *value) {
    if (NULL == value) {
        return;
    }

    log_add(1, "%s ", value->xpath);

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        log_add(1, "(container)");
        break;
    case SR_LIST_T:
        log_add(1, "(list instance)");
        break;
    case SR_STRING_T:
        log_add(1, "= %s", value->data.string_val);
        break;
    case SR_BOOL_T:
        log_add(1, "= %s", value->data.bool_val ? "true" : "false");
        break;
    case SR_DECIMAL64_T:
        log_add(1, "= %g", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        log_add(1, "= %" PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        log_add(1, "= %" PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        log_add(1, "= %" PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        log_add(1, "= %" PRId64, value->data.int64_val);
        break;
    case SR_UINT8_T:
        log_add(1, "= %" PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        log_add(1, "= %" PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        log_add(1, "= %" PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        log_add(1, "= %" PRIu64, value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        log_add(1, "= %s", value->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        log_add(1, "= %s", value->data.instanceid_val);
        break;
    case SR_BITS_T:
        log_add(1, "= %s", value->data.bits_val);
        break;
    case SR_BINARY_T:
        log_add(1, "= %s", value->data.binary_val);
        break;
    case SR_ENUM_T:
        log_add(1, "= %s", value->data.enum_val);
        break;
    case SR_LEAF_EMPTY_T:
        log_add(1, "(empty leaf)");
        break;
    default:
        log_add(1, "(unprintable)");
        break;
    }

    switch (value->type) {
    case SR_UNKNOWN_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LIST_T:
    case SR_LEAF_EMPTY_T:
        break;

    default:
        log_add(1, "%s", value->dflt ? " [default]" : "");
        break;
    }
}

void debug_print_sr_change(sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val) {
    switch (op) {
        case SR_OP_CREATED:
            log_add_verbose(1, "CREATED: ");
            debug_print_sr_val(new_val);
            break;
        case SR_OP_DELETED:
            log_add_verbose(1, "DELETED: ");
            debug_print_sr_val(old_val);
            break;
        case SR_OP_MODIFIED:
            log_add_verbose(1, "MODIFIED: ");
            debug_print_sr_val(old_val);
            log_add(1, "to ");
            debug_print_sr_val(new_val);
            break;
        case SR_OP_MOVED:
            log_add_verbose(1, "MOVED: %s\n", new_val->xpath);
            break;
    }

    log_add(1, "\n");
}

void debug_print_lyd_value(struct lyd_node *node) {
    switch(node->schema->nodetype) {
        case LYS_UNKNOWN:
        case LYS_CONTAINER:
        case LYS_CHOICE:
        case LYS_LIST:
        case LYS_ANYXML:
        case LYS_CASE:
        case LYS_NOTIF:
        case LYS_RPC:
        case LYS_INPUT:
        case LYS_OUTPUT:
        case LYS_GROUPING:
        case LYS_USES:
        case LYS_AUGMENT:
        case LYS_ACTION:
        case LYS_ANYDATA:
        case LYS_EXT:
        default:
            log_add(1, "[unprintable]");
            break;

        case LYS_LEAF:
        case LYS_LEAFLIST:
            log_add(1, LOG_COLOR_BOLD_MAGENTA"%s"LOG_COLOR_RESET, ((struct lyd_node_leaf_list *)node)->value_str);
            break;
    }
}

void debug_print_lyd_node(struct lyd_node *node) {
    struct lyd_node *start = node;
    struct lyd_node *elem = 0;
    struct lyd_node *next = 0;
    
debug_print_dfs:
    LY_TREE_DFS_BEGIN(start, next, elem) {
        char elemtype = ((elem->schema->flags & LYS_CONFIG_W) == 0) ? 'O' : 'R';

        char *xpath = lyd_path(elem);
        log_add_verbose(1, "[%c] %s: ", elemtype, xpath);
        free(xpath);
        
        debug_print_lyd_value(elem);
        
        log_add(1, "\n");
        LY_TREE_DFS_END(start, next, elem);
    }

    if(start->next) {
        start = start->next;
        goto debug_print_dfs;
    }
}

void debug_print_siblings(const struct lyd_node *node) {
    struct lyd_node *start = (struct lyd_node *)node;
    struct lyd_node *elem = 0;

    elem = start;
    while(elem) {
        elem = elem->prev;

        char elemtype = ((elem->schema->flags & LYS_CONFIG_W) == 0) ? 'O' : 'R';

        log_add_verbose(1, "[%c] %s: ", elemtype, lyd_path(elem));
        
        debug_print_lyd_value(elem);
        
        log_add(1, "\n");

        if(elem == start) {
            break;
        }
    }
}
