#include <ngx_http_acl_module_util.h>
#include <ngx_http_acl_module_mem_pool.h>
#include <ngx_http_acl_module_core.h>

extern ngx_module_t ngx_http_acl_module;

extern void ngx_http_acl_handler_cleanup(void *data);
static void free_acl_rule(acl_rule_t * acl_rule);
ngx_int_t parse_comparative_expression(mem_pool_t * pool, char * exp_str, comparative_expression_t * exp_node, ngx_log_t * log);


/*---------------------------- Definition of global variables ---------------------------------*/
static char field_str[FIELD_COUNT][20] = {"Cookie", "Geo", "IP", "Referer", "RequestMethod", "URI Path", "URI Query String", "UserAgent", "Header", "Request Frequency", "AS Num", "Response Frequency"};
static char operator_str[OPERATOR_COUNT][20] = {"equals", "contains", "is in", "does not equals", "does not contain", "is not in", ">", ">=", "<", "<=", "=="};

/*---------------------------- Definition of functions ---------------------------------------*/

void free_acl_rule(acl_rule_t * acl_rule)
{
    if (acl_rule == NULL)
        return;
    
    for (int i = 0 ; i < acl_rule->acl_rule_node_list_count ; i ++) {
        if (acl_rule->acl_rule_node_list[i].type == ACL_RULE_TOKEN_NODE && acl_rule->acl_rule_node_list[i].exp_node != NULL) {
            if (acl_rule->acl_rule_node_list[i].exp_node->exp_str) {
                mem_pool_free(&acl_rule->pool, acl_rule->acl_rule_node_list[i].exp_node->exp_str);
            }
            if (acl_rule->acl_rule_node_list[i].exp_node->name_str) {
                mem_pool_free(&acl_rule->pool, acl_rule->acl_rule_node_list[i].exp_node->name_str);
            }
            mem_pool_free(&acl_rule->pool, acl_rule->acl_rule_node_list[i].exp_node);
        }
    }
    
    mem_pool_free(&acl_rule->pool, acl_rule->acl_rule_node_list);
}

ngx_int_t parse_comparative_expression(mem_pool_t *pool, char * exp_str, comparative_expression_t * exp_node, ngx_log_t * log) {
    if (pool == NULL || exp_str == NULL || exp_node == NULL || log == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    //parse : ["Geo","-", "is in","Asia, China, Guangdong"]
    //parse : ["Header","Content-Type","is in","aaa, bbb, ccc"] 

    int i;
    char delim[] = "\",";
    char *token = NULL;
    char *temp_pointer = NULL;

    field_e filed_type = Field_Unknown;
    operator_e operator_type = Operator_Unknown;
    char * value = NULL;
    char * name = NULL;
    char * temp = NULL;
    
    token = ngx_strstr(exp_str, delim); // ","is in","Asia, China, Guangdong"]
    if (token == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to get field from exp string.");
        goto fail_parse_comparative_expression;
    } else {
        int length = token - exp_str;
        temp = mem_pool_calloc(pool, length + 1);
        if (temp == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to aclloc temp string.");
            goto fail_parse_comparative_expression;
        }

        ngx_cpystrn((u_char*)temp, (u_char*)exp_str, length + 1);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : Field is '%s'", temp + 2);
        
        for (i = 0 ; i < FIELD_COUNT ; i ++) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : current Field is '%s', and original field is '%s'", temp + 2, field_str[i]);
            if (ngx_strncmp(temp + 2, field_str[i], ngx_strlen(field_str[i])) == 0) {
                filed_type = i;
                ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl: found field %d", i);
                break;
            }
        }
        if (filed_type == Field_Unknown) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to get correct field from exp string.");
            goto fail_parse_comparative_expression;
        }
    }
    token += ngx_strlen(delim); // "Content-Type","is in","aaa, bbb, ccc"]

    temp_pointer = ngx_strstr(token, delim); // ","is in","aaa, bbb, ccc"]
    if (temp_pointer == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to get name from exp string.");
        goto fail_parse_comparative_expression;
    } else {
        int length = temp_pointer - token;
        name = mem_pool_calloc(pool, length);
        if (name == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to alloc name.");
            goto fail_parse_comparative_expression;
        }
        name[0] = '\0';
        ngx_cpystrn((u_char*)name, (u_char*)(token + 1), length);
        name[length - 1] = '\0';
        
        ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : Name is '%s'", name);

    }
    temp_pointer += ngx_strlen(delim); // "is in","aaa, bbb, ccc"]
    token = temp_pointer + 1; // is in","aaa, bbb, ccc"]

    temp_pointer = ngx_strstr(token, delim); // ","aaa, bbb, ccc"]
    if (temp_pointer == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to get operator from exp string.");
        goto fail_parse_comparative_expression;
    } else {
        char temp[1024];
        int length = temp_pointer - token;
        ngx_cpystrn((u_char*)temp, (u_char*)token, length + 1);

        ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : Operator is '%s'", temp);
        for (i = 0 ; i < OPERATOR_COUNT ; i ++) {
            if (ngx_strncmp(temp, operator_str[i], ngx_strlen(temp)) == 0) {
                operator_type = i;
                break;
            }
        }
        if (operator_type == Operator_Unknown) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to get correct operator from exp string.");
            goto fail_parse_comparative_expression;
        }
    }
    temp_pointer += ngx_strlen(delim); // "Asia, China, Guangdong"]
    token = temp_pointer + 1; // Asia, China, Guangdong"]

    if (token == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to get value from exp string.");
        goto fail_parse_comparative_expression;
    } else {
        int length = ngx_strlen(token) - 2;
        value = mem_pool_calloc(pool, length + 1);
        if (value == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to alloc value.");
            goto fail_parse_comparative_expression;
        }
        ngx_cpystrn((u_char*)value, (u_char*)token, length + 1);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : value is '%s'\n", value);
    }

    exp_node->exp_str = value;
    exp_node->name_str = name;
    exp_node->op = operator_type;
    exp_node->field = filed_type;
    exp_node->exp_value = NGX_HTTP_ACL_FALSE;

    return NGX_HTTP_ACL_SUCCESS;
    
fail_parse_comparative_expression:
    if (temp) {
        mem_pool_free(pool, temp);
    }
    if (name) {
        mem_pool_free(pool, name);
    }
    if(value) {
        mem_pool_free(pool, value);
    }
    return NGX_HTTP_ACL_FAIL;
}

void dump_acl_rule(acl_rule_t * acl_rule_p, ngx_log_t * log)
{
    if (acl_rule_p == NULL || log == NULL)
        return;
#ifndef NGX_HTTP_ACL_NO_DEBUG
    int i;
    ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_acl_debug:    acl_rule_p is %p", (void *)acl_rule_p);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_acl_debug:    Action is %d", acl_rule_p->action);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_acl_debug:    priority is %d", acl_rule_p->priority);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_acl_debug:    intermediate_node_list_index is %d", acl_rule_p->acl_rule_node_list_count);
    
    for (i = 0 ; i < acl_rule_p->acl_rule_node_list_count ; i ++) {
        switch (acl_rule_p->acl_rule_node_list[i].type) {
            case ACL_RULE_TOKEN_NODE: {
                if (acl_rule_p->acl_rule_node_list[i].exp_node) {
                    ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : %s, %s, %s, %d", 
                        field_str[acl_rule_p->acl_rule_node_list[i].exp_node->field], 
                        operator_str[acl_rule_p->acl_rule_node_list[i].exp_node->op], 
                        acl_rule_p->acl_rule_node_list[i].exp_node->exp_str, 
                        acl_rule_p->acl_rule_node_list[i].exp_node->exp_value);
                }
                break;
            }
            case ACL_RULE_TOKEN_AND:
                ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "AND");
                break;
            case ACL_RULE_TOKEN_OR:
                ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "OR");
                break;
            case ACL_RULE_TOKEN_LPAREN:
                ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "[");
                break;
            case ACL_RULE_TOKEN_RPAREN:
                ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "]");
                break;
            case ACL_RULE_TOKEN_END:
                ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "END");
                break;
            default:
                ngx_log_error(NGX_LOG_ERR, log, 0, "Unkown acl rule node type");
                break;
        }
        
    }
    
#endif
}


ngx_int_t parse_rule_action(char * str, acl_rule_t * acl_rule, ngx_log_t * log)
{
    if (str == NULL || acl_rule == NULL || log == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    char * str_action = ngx_strstr(str, "action");
    if (str_action == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : No action field is specified.\n");
        return NGX_HTTP_ACL_FAIL;
    }

    str_action = ngx_strstr(str_action, "=");
    if (str_action == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : No action field is specified.\n");
        return NGX_HTTP_ACL_FAIL;
    }
    
    str_action = str_action + 1;
    
    ngx_int_t action_id = ngx_atoi((u_char*)str_action, ngx_strlen(str_action));
    if (action_id == NGX_ERROR || action_id <= 0) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    switch (action_id) {
        case ACTION_ALLOW:
            ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : ACTION_ALLOW\n");
            acl_rule->action = ACTION_ALLOW;
            break;
        case ACTION_BLOCK:
            ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : ACTION_BLOCK\n");
            acl_rule->action = ACTION_BLOCK;
            break;
        case ACTION_HCAPTCHA:
            ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : ACTION_HCAPTCHA\n");
            acl_rule->action = ACTION_HCAPTCHA;
            break;
        default:
            ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : ACTION_UNKNOWN\n");
            acl_rule->action = ACTION_UNKNOWN;
            break;
    }

    return NGX_HTTP_ACL_SUCCESS;
}

ngx_int_t parse_rule_priority(char * str, acl_rule_t * acl_rule, ngx_log_t * log)
{
    if (str == NULL || acl_rule == NULL || log == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : str is '%s'", str);

    
    char * str_priority = ngx_strstr(str, "priority");
    if (str_priority == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : No priority field is specified.\n");
        return NGX_HTTP_ACL_FAIL;
    }

    str_priority = ngx_strstr(str_priority, "=");
    if (str_priority == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : No priority field is specified.\n");
        return NGX_HTTP_ACL_FAIL;
    }
    
    str_priority = str_priority + 1;
    
    ngx_int_t action_priority = ngx_atoi((u_char*)str_priority, ngx_strlen(str_priority));
    if (action_priority == NGX_ERROR || action_priority <= 0) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    acl_rule->priority = action_priority;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : priority is %d ", acl_rule->priority);
    
    return NGX_HTTP_ACL_SUCCESS;
}


ngx_int_t make_intermediate_list(char * str, acl_rule_t * acl_rule, ngx_log_t * log)
{
    char delim[] = "\n"; 

    acl_rule_node_t * intermediate_node_list = NULL;
    int intermediate_node_list_index = 0;
    int capacity = 10;
    
    char * save_ptr;
    char * token = strtok_r(str, delim, &save_ptr);

    if (str == NULL || acl_rule == NULL || log == NULL) {
        goto fail_make_intermediate_list;
    }
    
    intermediate_node_list = mem_pool_calloc(&acl_rule->pool, sizeof (acl_rule_node_t) * capacity);
    if (intermediate_node_list == NULL) {
        goto fail_make_intermediate_list;
    }

    while (token != NULL) {
        int token_length = ngx_strlen(token);
        int i = 0;

        // Remove space or tab from start string and end string. ex: '  ["Header","Content-Type","is in","aaa, bbb, ccc"]  ' -> '["Header","Content-Type","is in","aaa, bbb, ccc"]'
        while ((token[i] == ' ' || token[i] == '\t') && i < token_length)
            i ++;

        token = token + i;
        token_length = ngx_strlen(token);
        i = token_length - 1;

        while ((token[i] == ' ' || token[i] == '\t') && i >= 0)
            i --;
        token[i + 1] = '\0';

        token_length = ngx_strlen(token);
        
        if (token[0] == '[') {
            if (token_length == 1) {
                intermediate_node_list[intermediate_node_list_index].type = ACL_RULE_TOKEN_LPAREN;
                intermediate_node_list_index ++;
            }
            
            else if (token[token_length - 1] == ']') {
                comparative_expression_t * exp_node = NULL;
                exp_node = mem_pool_calloc(&acl_rule->pool, sizeof (comparative_expression_t));
                if (exp_node == NULL) {
                    ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to mem calloc for exp node");
                    acl_rule->acl_rule_node_list_count = intermediate_node_list_index;
                    free_acl_rule(acl_rule);
                    goto fail_make_intermediate_list;
                }
                
                ngx_int_t ret = parse_comparative_expression(&acl_rule->pool, token, exp_node, log);
                if (ret != NGX_HTTP_ACL_SUCCESS) {
                    ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Invalid expression is received.");
                    acl_rule->acl_rule_node_list_count = intermediate_node_list_index;
                    free_acl_rule(acl_rule);
                    goto fail_make_intermediate_list;
                }
                
                intermediate_node_list[intermediate_node_list_index].type = ACL_RULE_TOKEN_NODE;
                intermediate_node_list[intermediate_node_list_index].exp_node = exp_node;
                intermediate_node_list_index ++;
                
            }
        }
        else if (ngx_strncmp(token, "AND", 3) == 0) {
            intermediate_node_list[intermediate_node_list_index].type = ACL_RULE_TOKEN_AND;
            intermediate_node_list_index ++;
        }
        else if (ngx_strncmp(token, "OR", 2) == 0) {
            intermediate_node_list[intermediate_node_list_index].type = ACL_RULE_TOKEN_OR;
            intermediate_node_list_index ++;
        }
        else if (token_length == 1 && token[0] == ']') {
            intermediate_node_list[intermediate_node_list_index].type = ACL_RULE_TOKEN_RPAREN;
            intermediate_node_list_index ++;
        }

        if (intermediate_node_list_index >= capacity ) {
            capacity = capacity * 2;
            
            //intermediate_node_list = realloc(intermediate_node_list, (intermediate_node_list_index + 1) * sizeof (acl_rule_node_t));
            acl_rule_node_t * new_intermediate_node_list = mem_pool_calloc(&acl_rule->pool, sizeof (acl_rule_node_t) * capacity);
            if (new_intermediate_node_list == NULL) {
                ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to realloc new memory heap.");
                acl_rule->acl_rule_node_list_count = intermediate_node_list_index - 1;
                free_acl_rule(acl_rule);
                goto fail_make_intermediate_list;
            }

            ngx_memcpy(new_intermediate_node_list, intermediate_node_list, sizeof (acl_rule_node_t) * intermediate_node_list_index);
            mem_pool_free(&acl_rule->pool, intermediate_node_list);
            intermediate_node_list = new_intermediate_node_list;
        }
        
        token = strtok_r(NULL, delim, &save_ptr);
    }

    intermediate_node_list[intermediate_node_list_index].type = ACL_RULE_TOKEN_END;
    intermediate_node_list_index ++;
    
    acl_rule->acl_rule_node_list_count = intermediate_node_list_index;
    acl_rule->acl_rule_node_list = intermediate_node_list;
    
    dump_acl_rule(acl_rule, log);
    
    return NGX_HTTP_ACL_SUCCESS;
    
fail_make_intermediate_list:
    if (intermediate_node_list) {
        mem_pool_free(&acl_rule->pool, intermediate_node_list);
    }
    return NGX_HTTP_ACL_FAIL;
}




ngx_int_t remove_acl_rule_list(server_acl_rule_t * server_acl_rule_p, acl_rule_list_t * acl_rule_list_p, ngx_log_t * log)
{
    if (server_acl_rule_p == NULL || acl_rule_list_p == NULL || log == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    int i = 0;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : Remove acl rule with id %d", acl_rule_list_p->acl_rule_list_id);

    for (i = 0 ; i < acl_rule_list_p->acl_rule_count ; i ++) {
        acl_rule_t * acl_rule_p = &acl_rule_list_p->acl_rule_list[i];
        free_acl_rule(acl_rule_p);
        acl_rule_p = NULL;
    }

    mem_pool_free(&server_acl_rule_p->pool, acl_rule_list_p->acl_rule_list);

    acl_rule_list_p->acl_rule_list = NULL;

    acl_rule_list_t * st_next = acl_rule_list_p->next;
    acl_rule_list_t * st_prev = acl_rule_list_p->prev;

    mem_pool_free(&server_acl_rule_p->pool, acl_rule_list_p);
    acl_rule_list_p = NULL;

    if (st_prev == NULL && st_next == NULL) {
        server_acl_rule_p->head = NULL;
        server_acl_rule_p->tail = NULL;
    }
	else if (st_prev == NULL && st_next != NULL) {
        st_next->prev = NULL;
        server_acl_rule_p->head = st_next;
	}
	else if (st_prev != NULL && st_next == NULL) {
        st_prev->next = NULL;
        server_acl_rule_p->tail = st_prev;
    }
    else {
        st_prev->next = st_next;
        st_next->prev = st_prev;
    }

    return NGX_HTTP_ACL_SUCCESS;
}

ngx_int_t append_acl_rule_list(server_acl_rule_t * server_acl_rule_p, acl_rule_list_t * acl_rule_list_p, ngx_log_t * log)
{
    if (server_acl_rule_p == NULL || acl_rule_list_p == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (server_acl_rule_p->head == NULL || server_acl_rule_p->tail == NULL) {
        server_acl_rule_p->head  = acl_rule_list_p;
        server_acl_rule_p->tail  = acl_rule_list_p;
    } else {
        server_acl_rule_p->tail->next = acl_rule_list_p;
        acl_rule_list_p->prev = server_acl_rule_p->tail;
        server_acl_rule_p->tail = acl_rule_list_p;
    }
    return NGX_HTTP_ACL_SUCCESS;
}

ngx_int_t append_rule_into_rule_list(acl_rule_list_t * cur_acl_rule_list_p, acl_rule_t * acl_rule_p)
{
    if (cur_acl_rule_list_p == NULL || acl_rule_p == NULL)
        return NGX_HTTP_ACL_FAIL;

    int i, j;
    
    //cur_acl_rule_list_p->acl_rule_list = realloc (cur_acl_rule_list_p->acl_rule_list, (cur_acl_rule_list_p->acl_rule_count + 1) * sizeof (acl_rule_t));
    //if (cur_acl_rule_list_p->acl_rule_list == NULL)
    //    return NGX_HTTP_ACL_FAIL;


    acl_rule_t * new_acl_rule_list_p = mem_pool_calloc(&cur_acl_rule_list_p->pool, (cur_acl_rule_list_p->acl_rule_count + 1) * sizeof (acl_rule_t));
    if (new_acl_rule_list_p == NULL)
        return NGX_HTTP_ACL_FAIL;
    
    ngx_memzero(new_acl_rule_list_p, (cur_acl_rule_list_p->acl_rule_count + 1) * sizeof (acl_rule_t));
    
    if (cur_acl_rule_list_p->acl_rule_list != NULL && cur_acl_rule_list_p->acl_rule_count > 0) {
        ngx_memcpy(new_acl_rule_list_p, cur_acl_rule_list_p->acl_rule_list, (cur_acl_rule_list_p->acl_rule_count) * sizeof (acl_rule_t));
        mem_pool_free(&cur_acl_rule_list_p->pool, cur_acl_rule_list_p->acl_rule_list);
    }

    cur_acl_rule_list_p->acl_rule_list = new_acl_rule_list_p;
    ngx_memcpy(&cur_acl_rule_list_p->acl_rule_list[cur_acl_rule_list_p->acl_rule_count].pool, &acl_rule_p->pool, sizeof (mem_pool_t));
    cur_acl_rule_list_p->acl_rule_list[cur_acl_rule_list_p->acl_rule_count].action = acl_rule_p->action;
    cur_acl_rule_list_p->acl_rule_list[cur_acl_rule_list_p->acl_rule_count].priority = acl_rule_p->priority;
    cur_acl_rule_list_p->acl_rule_list[cur_acl_rule_list_p->acl_rule_count].acl_rule_node_list = acl_rule_p->acl_rule_node_list;
    cur_acl_rule_list_p->acl_rule_list[cur_acl_rule_list_p->acl_rule_count].acl_rule_node_list_count = acl_rule_p->acl_rule_node_list_count;
    cur_acl_rule_list_p->acl_rule_count ++;

    // Sort acl rules by priority

    for (i = 0 ; i < cur_acl_rule_list_p->acl_rule_count - 1 ; i ++) {
        if (cur_acl_rule_list_p->acl_rule_list[i].priority < acl_rule_p->priority)
            break;
    }

    for (j = cur_acl_rule_list_p->acl_rule_count - 1; j > i ; j --) {
        ngx_memcpy(&cur_acl_rule_list_p->acl_rule_list[j].pool, &cur_acl_rule_list_p->acl_rule_list[j-1].pool, sizeof (mem_pool_t));
        cur_acl_rule_list_p->acl_rule_list[j].action = cur_acl_rule_list_p->acl_rule_list[j-1].action;
        cur_acl_rule_list_p->acl_rule_list[j].priority = cur_acl_rule_list_p->acl_rule_list[j-1].priority;
        cur_acl_rule_list_p->acl_rule_list[j].acl_rule_node_list = cur_acl_rule_list_p->acl_rule_list[j-1].acl_rule_node_list;
        cur_acl_rule_list_p->acl_rule_list[j].acl_rule_node_list_count = cur_acl_rule_list_p->acl_rule_list[j-1].acl_rule_node_list_count;
    }
    
    ngx_memcpy(&cur_acl_rule_list_p->acl_rule_list[i].pool, &acl_rule_p->pool, sizeof (mem_pool_t));
    cur_acl_rule_list_p->acl_rule_list[i].action = acl_rule_p->action;
    cur_acl_rule_list_p->acl_rule_list[i].priority = acl_rule_p->priority;
    cur_acl_rule_list_p->acl_rule_list[i].acl_rule_node_list = acl_rule_p->acl_rule_node_list;
    cur_acl_rule_list_p->acl_rule_list[i].acl_rule_node_list_count = acl_rule_p->acl_rule_node_list_count;

    return NGX_HTTP_ACL_SUCCESS;
    
}


ngx_int_t add_acl_rule(server_acl_rule_t * server_acl_rule_p, ngx_log_t * log, int acl_rule_id, int action, int priority, char * str_rule_body)
{
    if (str_rule_body == NULL || server_acl_rule_p == NULL || log == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    acl_rule_list_t * acl_rule_list_p = server_acl_rule_p->head;
    while (acl_rule_list_p != NULL) {
        if (acl_rule_list_p->acl_rule_list_id == acl_rule_id)
            break;
        acl_rule_list_p = acl_rule_list_p->next;
    }
    
    if (acl_rule_list_p == NULL) {
        //acl_rule_list_p = calloc(1, sizeof (acl_rule_list_t));
        //if (acl_rule_list_p == NULL)
        //    return NGX_HTTP_ACL_FAIL;
        
        ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : Add new acl rule ... %p", server_acl_rule_p->pool.native_pool.slab_pool);
        
        acl_rule_list_p = mem_pool_calloc(&server_acl_rule_p->pool, sizeof (acl_rule_list_t));
        if (acl_rule_list_p == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to mem_pool_calloc new acl rule");
            return NGX_HTTP_ACL_FAIL;
        }
        
        ngx_log_debug(NGX_LOG_DEBUG_CORE, log, 0, "ngx_http_acl : acl_rule_list_p is newly created with mem_pool_calloc");
        
        ngx_memzero(acl_rule_list_p, sizeof (acl_rule_list_t));
        ngx_memcpy(&acl_rule_list_p->pool, &server_acl_rule_p->pool, sizeof(mem_pool_t));
        
        acl_rule_list_p->pool = server_acl_rule_p->pool;
        acl_rule_list_p->acl_rule_list_id = acl_rule_id;
        acl_rule_list_p->acl_rule_count = 0;
        acl_rule_list_p->acl_rule_list = NULL;
        acl_rule_list_p->prev = NULL;
        acl_rule_list_p->next = NULL;
        
        append_acl_rule_list(server_acl_rule_p, acl_rule_list_p, log);
    }

    acl_rule_t * acl_rule_p = mem_pool_calloc(&server_acl_rule_p->pool, sizeof (acl_rule_t));
    if (acl_rule_p == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to alloc acl rule");
        return NGX_HTTP_ACL_FAIL;
    }
    
    ngx_memzero(acl_rule_p, sizeof (acl_rule_t));
    ngx_memcpy(&acl_rule_p->pool, &server_acl_rule_p->pool, sizeof(mem_pool_t));
    acl_rule_p->action = action;
    acl_rule_p->priority = priority;

    if (make_intermediate_list(str_rule_body, acl_rule_p, log) != NGX_HTTP_ACL_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to make intermediate list for acl rule");
        mem_pool_free(&server_acl_rule_p->pool, acl_rule_p);
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (append_rule_into_rule_list(acl_rule_list_p, acl_rule_p) != NGX_HTTP_ACL_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ngx_http_acl : Failed to append rule in to intermediate list");
        mem_pool_free(&server_acl_rule_p->pool, acl_rule_p);
        return NGX_HTTP_ACL_FAIL;

    }
    mem_pool_free(&server_acl_rule_p->pool, acl_rule_p);
    return NGX_HTTP_ACL_SUCCESS;
}


char * ngx_http_acl_clone_c_str_len(ngx_http_request_t* r, char * src, int length) {
    if (r == NULL || r->pool == NULL || src == NULL || length <= 0) {
        return NULL;
    }
    
    char * res = ngx_palloc(r->pool, length + 1);
    if (res == NULL)
        return NULL;
    
    ngx_cpystrn((u_char*)res, (u_char*)src, length + 1);
    return res;
}


ngx_int_t parse_acl_rule(ngx_http_request_t* r, char * str_acl_rule, server_acl_rule_t * server_acl_rule_p) 
{
    int length;
    const char * delim_line = "\n";
    char * id_pointer = NULL;
    char * rules_pointer = NULL;
    char * rules_end_pointer = NULL;
    char * temp_pointer = NULL;
    char * str_id = NULL;
    char * str_rule = NULL;
    
    int id = -1, i;

    if (r == NULL || str_acl_rule == NULL || server_acl_rule_p == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    if (str_acl_rule[0] != '{')
        return NGX_HTTP_ACL_FALSE;
    id_pointer = ngx_strstr(str_acl_rule, delim_line);
    if (id_pointer == NULL)
        return NGX_HTTP_ACL_FALSE;
    id_pointer = id_pointer + 1;

    rules_pointer = ngx_strstr(id_pointer, delim_line);
    if (rules_pointer == NULL) 
        return NGX_HTTP_ACL_FALSE;

    length = rules_pointer - id_pointer;

    str_id = ngx_http_acl_clone_c_str_len(r, id_pointer, length - 1); // remove last ,
    if (str_id == NULL)
        return NGX_HTTP_ACL_FALSE;

    temp_pointer = ngx_strstr(str_id, "="); // id = 12
    if (temp_pointer == NULL)
        return NGX_HTTP_ACL_FALSE;

    temp_pointer = temp_pointer + 1;
    
    id = ngx_atoi((u_char*)temp_pointer, ngx_strlen(temp_pointer));
    if (id == NGX_ERROR || id <= 0) {
        return NGX_HTTP_ACL_FAIL;
    }

    rules_pointer = ngx_strstr(rules_pointer , "{");
    if (rules_pointer == NULL)
        return NGX_HTTP_ACL_FALSE;
    
    acl_rule_list_t * acl_rule_list_p = server_acl_rule_p->head;
    while (acl_rule_list_p != NULL) {
        if (acl_rule_list_p->acl_rule_list_id == id)
            break;
        acl_rule_list_p = acl_rule_list_p->next;
    }
    
    if (ngx_strstr(rules_pointer, "{{") == NULL) {
        //Remove current ACL rule with id
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "Trying to remove ACL rule with id %d", id);
        
        if (acl_rule_list_p == NULL) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "There is no acl rule with id = %d", id);
            return NGX_HTTP_ACL_TRUE;
        }
        // Remove current ACL rule list.
        remove_acl_rule_list(server_acl_rule_p, acl_rule_list_p, r->connection->log);
        return NGX_HTTP_ACL_TRUE;
    }
    
    //acl_rule_list_t * cur_acl_rule_list_p = calloc(1, sizeof (acl_rule_list_t));
    acl_rule_list_t * cur_acl_rule_list_p = mem_pool_calloc(&server_acl_rule_p->pool, sizeof (acl_rule_list_t));
    if (cur_acl_rule_list_p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to alloc acl rule list");
        return NGX_HTTP_ACL_FALSE;
    }
    
    ngx_memzero(cur_acl_rule_list_p, sizeof(acl_rule_list_t));
    ngx_memcpy(&cur_acl_rule_list_p->pool, &server_acl_rule_p->pool, sizeof (mem_pool_t));
    cur_acl_rule_list_p->acl_rule_list_id = id;
    cur_acl_rule_list_p->acl_rule_count = 0;
    cur_acl_rule_list_p->acl_rule_list = NULL;
    cur_acl_rule_list_p->prev = NULL;
    cur_acl_rule_list_p->next = NULL;
    
    while (rules_pointer != NULL) {
        rules_pointer = ngx_strstr(rules_pointer, "{{");
        if (rules_pointer == NULL)
            break;

        rules_pointer += 2;
        rules_end_pointer = ngx_strstr(rules_pointer, "}}");
        if (rules_end_pointer == NULL)
            break;
        
        length = rules_end_pointer - rules_pointer;
        
        str_rule = ngx_http_acl_clone_c_str_len(r, rules_pointer, length); // rules body

        if (str_rule == NULL)
            return NGX_HTTP_ACL_FALSE;

        //acl_rule_t * acl_rule_p = calloc (1, sizeof (acl_rule_t));
        acl_rule_t * acl_rule_p = mem_pool_calloc(&server_acl_rule_p->pool, sizeof (acl_rule_t));
        if (acl_rule_p == NULL)
            return NGX_HTTP_ACL_FALSE;
        ngx_memzero(acl_rule_p, sizeof(acl_rule_t));
        ngx_memcpy(&acl_rule_p->pool, &server_acl_rule_p->pool, sizeof(mem_pool_t));
        
        if (parse_rule_action(str_rule, acl_rule_p, r->connection->log) != NGX_HTTP_ACL_SUCCESS)
            return NGX_HTTP_ACL_FALSE;

        if (parse_rule_priority(str_rule, acl_rule_p, r->connection->log) != NGX_HTTP_ACL_SUCCESS)
            return NGX_HTTP_ACL_FALSE;

        char * str_rule_body = ngx_strstr(str_rule,"[");
        if (str_rule_body == NULL)
            return NGX_HTTP_ACL_FALSE;
        
        if (make_intermediate_list(str_rule_body, acl_rule_p, r->connection->log) != NGX_HTTP_ACL_SUCCESS) {
            if (acl_rule_p) {
                mem_pool_free(&server_acl_rule_p->pool, acl_rule_p);
            }

            for (i = 0 ; i < cur_acl_rule_list_p->acl_rule_count ; i ++) {
                acl_rule_t * acl_rule_p = &cur_acl_rule_list_p->acl_rule_list[i];
                free_acl_rule(acl_rule_p);
            }
            
            mem_pool_free(&server_acl_rule_p->pool, cur_acl_rule_list_p->acl_rule_list);
            mem_pool_free(&server_acl_rule_p->pool, cur_acl_rule_list_p);
            
            return NGX_HTTP_ACL_FALSE;
        }

        append_rule_into_rule_list(cur_acl_rule_list_p, acl_rule_p);
        
        if (acl_rule_p) {
            mem_pool_free(&server_acl_rule_p->pool, acl_rule_p);
        }
        
        rules_pointer = rules_end_pointer;
    }

    //Replace acl_rule_list in server calc rule.
    remove_acl_rule_list(server_acl_rule_p, acl_rule_list_p, r->connection->log);
    append_acl_rule_list(server_acl_rule_p, cur_acl_rule_list_p, r->connection->log);
    
    return NGX_HTTP_ACL_TRUE;
}

void ngx_http_acl_utarray_ngx_str_ctor(void *dst, const void *src) {
    if (dst == NULL || src == NULL) {
        return;
    }
    
    ngx_str_t* _dst = (ngx_str_t*)dst;
    const ngx_str_t* _src = (const ngx_str_t*)src;

    if (_src->data == NULL) {
        _dst->data = NULL;
        _dst->len = 0;
        return;
    }
    
    _dst->data = malloc(sizeof(u_char) * (_src->len + 1));
    if (_dst->data == NULL) {
        _dst->len = 0;
        return;
    }
    
    ngx_memcpy(_dst->data, _src->data, sizeof(u_char) * _src->len);
    _dst->data[_src->len] = '\0';
    _dst->len = _src->len;
}


void ngx_http_acl_utarray_ngx_str_dtor(void* elt) {
    if (elt == NULL) {
        return;
    }
    ngx_str_t* _elt = (ngx_str_t*)elt;
    if (_elt->data != NULL) {
        free(_elt->data);
        _elt->data = NULL;
    }
}

char* ngx_http_acl_to_c_str(u_char* destination, ngx_str_t ngx_str) {
    if (destination == NULL || ngx_str.data == NULL) {
        return NULL;
    }
    if (ngx_str.len > NGX_HTTP_ACL_RULE_MAX_LEN) {
        return NULL;
    }
    ngx_memcpy(destination, ngx_str.data, ngx_str.len);
    destination[ngx_str.len] = '\0';
    return (char*)destination + ngx_str.len;
}

ngx_int_t convert_ip_to_c_str(inx_addr_t addr, char *str, int mode) {
    if (str == NULL)
        return NGX_HTTP_ACL_FAIL;

    if (mode == AF_INET) {
        inet_ntop(AF_INET, &(addr), str, INET_ADDRSTRLEN);
        return NGX_HTTP_ACL_SUCCESS;
    } 
#if (NGX_HAVE_INET6)
    else if (mode == AF_INET6) {
        inet_ntop(AF_INET6, &(addr), str, INET6_ADDRSTRLEN);
        return NGX_HTTP_ACL_SUCCESS;
    }
#endif

    return NGX_HTTP_ACL_FAIL;
}

void make_lower_case_str(char *str) 
{
    int i;
    int length = ngx_strlen(str);

    for (i = 0 ; i < length ; i ++) {
        if (str[i] >= 'A' && str[i] <= 'Z')
            str[i] = str[i] + ('a' - 'A');
    }
}

void remove_space_in_str(char *str) {
    char* dest = str;

    while (*str != '\0') {
        if (*str != ' ') {
            *dest++ = *str;
        }
        str++;
    }

    *dest = '\0';
}

ngx_int_t check_contains_in_str(ngx_http_request_t* r, char *small_str, char * big_str, int case_sensitive) {
    if (small_str == NULL || big_str == NULL)
        return NGX_HTTP_ACL_FAIL;

    if (case_sensitive == NGX_HTTP_ACL_TRUE) {
        if (ngx_strstr(big_str, small_str) != NULL)
            return NGX_HTTP_ACL_SUCCESS;
        else
            return NGX_HTTP_ACL_FAIL;
    }
    char * lower_small = ngx_http_acl_clone_c_str(r, small_str);
    char * lower_big = ngx_http_acl_clone_c_str(r, big_str);

    if (lower_small == NULL || lower_big == NULL)
        return NGX_HTTP_ACL_FAIL;

    make_lower_case_str(lower_small);
    make_lower_case_str(lower_big);

    ngx_int_t ret = NGX_HTTP_ACL_FAIL;
    
    if (ngx_strstr(lower_big, lower_small) != NULL)
        ret = NGX_HTTP_ACL_SUCCESS;

    return ret;
}

ngx_int_t check_http_request_method_in_str(ngx_http_request_t * r, char * str_value) {
    if (str_value == NULL)
        return NGX_HTTP_ACL_FAIL;

    u_char str_method[64];
    u_char * p;
    int len = 0;
    
    str_method[0] = '\0';
    
    switch (r->method) {
        case NGX_HTTP_GET:
            p = ngx_snprintf(str_method, 32, "GET");
            len = p - str_method;
            break;
        case NGX_HTTP_HEAD:
            p = ngx_snprintf(str_method, 32, "HEAD");
            len = p - str_method;
            break;
        case NGX_HTTP_POST:
            p = ngx_snprintf(str_method, 32, "POST");
            len = p - str_method;
            break;
        case NGX_HTTP_PUT:
            p = ngx_snprintf(str_method, 32, "PUT");
            len = p - str_method;
            break;
        case NGX_HTTP_DELETE:
            p = ngx_snprintf(str_method, 32, "DELETE");
            len = p - str_method;
            break;
        case NGX_HTTP_MKCOL:
            p = ngx_snprintf(str_method, 32, "MKCOL");
            len = p - str_method;
            break;
        case NGX_HTTP_COPY:
            p = ngx_snprintf(str_method, 32, "COPY");
            len = p - str_method;
            break;
        case NGX_HTTP_MOVE:
            p = ngx_snprintf(str_method, 32, "MOVE");
            len = p - str_method;
            break;
        case NGX_HTTP_OPTIONS:
            p = ngx_snprintf(str_method, 32, "OPTIONS");
            len = p - str_method;
            break;
        case NGX_HTTP_PROPFIND:
            p = ngx_snprintf(str_method, 32, "PROPFIND");
            len = p - str_method;
            break;
        case NGX_HTTP_PROPPATCH:
            p = ngx_snprintf(str_method, 32, "PROPPATCH");
            len = p - str_method;
            break;
        case NGX_HTTP_LOCK:
            p = ngx_snprintf(str_method, 32, "LOCK");
            len = p - str_method;
            break;
        case NGX_HTTP_UNLOCK:
            p = ngx_snprintf(str_method, 32, "UNLOCK");
            len = p - str_method;
            break;
        case NGX_HTTP_PATCH:
            p = ngx_snprintf(str_method, 32, "PATCH");
            len = p - str_method;
            break;
        case NGX_HTTP_TRACE:
            p = ngx_snprintf(str_method, 32, "TRACE");
            len = p - str_method;
            break;
        case NGX_HTTP_CONNECT:
            p = ngx_snprintf(str_method, 32, "CONNECT");
            len = p - str_method;
            break;
        default:
            return NGX_HTTP_ACL_FAIL;
            break;
    }

    char * clone_str = ngx_http_acl_clone_c_str(r, str_value);
    if (clone_str == NULL)
        return NGX_HTTP_ACL_FAIL;
    
    remove_space_in_str(clone_str);
    
    // Split ip_addr_list with comma
    char *save_ptr;
    char *token = strtok_r(clone_str, ",", &save_ptr);
    
    while (token != NULL) {
        
        if (ngx_strncmp(str_method, token, len) == 0) {
            return NGX_HTTP_ACL_SUCCESS;
        }
        
        token = strtok_r(NULL, ",", &save_ptr);
    }

    return NGX_HTTP_ACL_FAIL;
    
}

ngx_int_t ngx_http_acl_str_split(ngx_pool_t * pool, ngx_str_t* str, u_char sep, size_t max_len, UT_array** array) {
    if (array == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    UT_icd icd = ngx_http_acl_make_utarray_ngx_str_icd();
    utarray_new(*array,&icd);

    if (str == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    ngx_str_t temp_str;
    temp_str.data = ngx_palloc(pool, sizeof(u_char) * (max_len + 1));
    ngx_memzero(temp_str.data, sizeof(u_char) * (max_len + 1));
    size_t str_index = 0;

    for (size_t i = 0; i < str->len; i++) {
        u_char c = str->data[i];
        if (c != sep) {
            if (str_index >= max_len) {
                return NGX_HTTP_ACL_FAIL;
            }
            temp_str.data[str_index++] = c;
        } else {
            temp_str.data[str_index] = '\0';
            temp_str.len = str_index;
            utarray_push_back(*array, &temp_str);
            str_index = 0;
        }
    }

    if (str_index != 0) {
        temp_str.data[str_index] = '\0';
        temp_str.len = str_index;
        utarray_push_back(*array, &temp_str);
        str_index = 0;
    }

    return NGX_HTTP_ACL_SUCCESS;
}

ngx_int_t compare_cookie_in_cookie_list(ngx_http_request_t* r, char * str_cookie, char *str_cookie_list) {
    if (str_cookie == NULL || str_cookie_list == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    char * str_temp = ngx_http_acl_clone_c_str(r, str_cookie_list);

    if (str_temp == NULL)
        return NGX_HTTP_ACL_FAIL;
    
    remove_space_in_str(str_temp);
    
    char *save_ptr;
    char *token = strtok_r(str_temp, ",", &save_ptr);
    
    while (token != NULL) {
        if (ngx_strcmp(str_cookie, token) == 0) {
            return NGX_HTTP_ACL_SUCCESS;
        }
        token = strtok_r(NULL, ";", &save_ptr);
    }
    return NGX_HTTP_ACL_FAIL;
}

ngx_int_t compare_header_value_in_list(ngx_http_request_t* r, char * str_value, char *str_value_list) {
    if (str_value == NULL || str_value_list == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    char * str_temp = ngx_http_acl_clone_c_str(r, str_value_list);

    if (str_temp == NULL)
        return NGX_HTTP_ACL_FAIL;
    
    remove_space_in_str(str_temp);

    char *save_ptr;
    char *token = strtok_r(str_temp, ",", &save_ptr);
    
    while (token != NULL) {
        if (compare_case_insensitive(r, str_value, token) == NGX_HTTP_ACL_SUCCESS) {
            return NGX_HTTP_ACL_SUCCESS;
        }
        token = strtok_r(NULL, ",", &save_ptr);
    }
    return NGX_HTTP_ACL_FAIL;
}

ngx_int_t compare_ip_in_ip_list(ngx_http_request_t* r, char * ip_addr, char *ip_addr_list) {
    if (ip_addr == NULL || ip_addr_list == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    char * str_temp = ngx_http_acl_clone_c_str(r, ip_addr_list);

    if (str_temp == NULL)
        return NGX_HTTP_ACL_FAIL;
    
    remove_space_in_str(str_temp);

    // Split ip_addr_list with comma
    char *save_ptr;
    char *token = strtok_r(str_temp, ",", &save_ptr);
    
    while (token != NULL) {
        if (ngx_strncmp(ip_addr, token, ngx_strlen(ip_addr)) == 0) {
            return NGX_HTTP_ACL_SUCCESS;
        }
        token = strtok_r(NULL, ",", &save_ptr);
    }
    return NGX_HTTP_ACL_FAIL;
}

char *ngx_http_acl_clone_c_str(ngx_http_request_t* r, char * src) {
    if (src == NULL)
        return NULL;
    
    int length = ngx_strlen((const char *)src);
    char * res = ngx_palloc(r->pool, length + 1);
    if (res == NULL)
        return NULL;

    ngx_memcpy(res, src, length);
    res[length] = '\0';
    return res;
}


ngx_int_t compare_case_insensitive(ngx_http_request_t* r, char * str1, char *str2) {
    if (str1 == NULL || str2 == NULL)
        return NGX_HTTP_ACL_FAIL;
    
    char * lower_str1 = ngx_http_acl_clone_c_str(r, str1);
    char * lower_str2 = ngx_http_acl_clone_c_str(r, str2);

    if (lower_str1 == NULL || lower_str2 == NULL)
        return NGX_HTTP_ACL_FAIL;

    make_lower_case_str(lower_str1);
    make_lower_case_str(lower_str2);

    ngx_int_t ret = NGX_HTTP_ACL_FAIL;
    
    if (ngx_strcmp(lower_str1, lower_str2) == 0)
        ret = NGX_HTTP_ACL_SUCCESS;

    return ret;
}


ngx_int_t ngx_http_acl_rand_str(u_char* dest, size_t len) {
    if (dest == NULL || len == 0) {
        return NGX_HTTP_ACL_FAIL;
    }

    for (size_t i = 0; i < len; i++) {
        //uint32_t num = randombytes_uniform(52);
        uint32_t num = ngx_random() % 52;
        if (num < 26) {
            dest[i] = (unsigned char)'A' + (unsigned char)num;
        } else {
            dest[i] = (unsigned char)'a' + (unsigned char)(num - 26);
        }
    }

    dest[len] = '\0';

    return NGX_HTTP_ACL_SUCCESS;
}

ngx_int_t parse_request_frequency_value(char *str, request_freq_t *req_freq_p) {
    if (str == NULL || req_freq_p == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    // Find "times" keyword
    char *times_ptr = ngx_strstr(str, "times");
    if (times_ptr == NULL || times_ptr == str) {
        return NGX_HTTP_ACL_FAIL;
    }

    // Parse the count before "times"
    ngx_str_t count_str;
    count_str.data = (u_char *)str;
    count_str.len = times_ptr - str;

    ngx_int_t count = ngx_atoi(count_str.data, count_str.len);
    if (count == NGX_ERROR || count <= 0) {
        return NGX_HTTP_ACL_FAIL;
    }
    req_freq_p->count = count;

    // Move past "times" and look for '/'
    char *slash_ptr = strchr(times_ptr + 5, '/'); // +5 to skip "times"
    if (slash_ptr == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    // Parse the duration after '/'
    char *duration_str = slash_ptr + 1;
    size_t duration_len = strlen(duration_str);
    if (duration_len == 0) {
        return NGX_HTTP_ACL_FAIL;
    }

    ngx_int_t multiplier = 1; // Default is seconds
    char unit = duration_str[duration_len - 1];

    if (unit == 's' || unit == 'm' || unit == 'h') {
        duration_len--; // Exclude the unit character
        switch (unit) {
            case 's':
                multiplier = 1;
                break;
            case 'm':
                multiplier = 60;
                break;
            case 'h':
                multiplier = 3600;
                break;
            default:
                return NGX_HTTP_ACL_FAIL;
        }
    }

    if (duration_len == 0) {
        return NGX_HTTP_ACL_FAIL;
    }

    ngx_str_t dur_str;
    dur_str.data = (u_char *)duration_str;
    dur_str.len = duration_len;

    ngx_int_t duration = ngx_atoi(dur_str.data, dur_str.len);
    if (duration == NGX_ERROR || duration <= 0) {
        return NGX_HTTP_ACL_FAIL;
    }

    req_freq_p->duration = duration * multiplier;

    return NGX_HTTP_ACL_SUCCESS;
}


ngx_int_t parse_response_code(char * str, int * code)
{
    int ret_code = 0;
    if (str == NULL || code == NULL)
        return NGX_HTTP_ACL_FAIL;

    ret_code = ngx_atoi((u_char*)str, ngx_strlen(str));
    if (ret_code == NGX_ERROR || ret_code <= 0) {
        return NGX_HTTP_ACL_FAIL;
    }

    if (!(ret_code >= 100 && ret_code < 600)) 
        return NGX_HTTP_ACL_FAIL;

    *code = ret_code;
    
    return NGX_HTTP_ACL_SUCCESS;
}

ngx_int_t ngx_http_acl_get_max_request_freq_time(server_acl_rule_t * server_acl_rule_p)
{
    int i, j;
    ngx_int_t ret_value = -1;
    
    if (server_acl_rule_p == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    acl_rule_list_t * acl_rule_list_p = server_acl_rule_p->head;

    while (acl_rule_list_p != NULL) {
        for (i = 0 ; i < acl_rule_list_p->acl_rule_count ; i ++) {
            acl_rule_t * acl_rule_p = &acl_rule_list_p->acl_rule_list[i];
            for (j = 0 ; j < acl_rule_p->acl_rule_node_list_count ; j ++) {
                acl_rule_node_t * intermediate_node_p = &acl_rule_p->acl_rule_node_list[j];
                if (intermediate_node_p->type == ACL_RULE_TOKEN_NODE 
                    && intermediate_node_p->exp_node 
                    && intermediate_node_p->exp_node->field == Field_Request_Frequency) {
                    request_freq_t req_freq;
                    if (parse_request_frequency_value(intermediate_node_p->exp_node->exp_str, &req_freq) == NGX_HTTP_ACL_SUCCESS) {
                        if (req_freq.duration > ret_value)
                            ret_value = req_freq.duration;
                    }
                }
            }
        }
        acl_rule_list_p = acl_rule_list_p->next;
    }
    
    return ret_value;
}

ngx_int_t ngx_http_acl_get_max_response_freq_time(server_acl_rule_t * server_acl_rule_p)
{
    int i, j;
    ngx_int_t ret_value = -1;
    
    if (server_acl_rule_p == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    acl_rule_list_t * acl_rule_list_p = server_acl_rule_p->head;

    while (acl_rule_list_p != NULL) {
        for (i = 0 ; i < acl_rule_list_p->acl_rule_count ; i ++) {
            acl_rule_t * acl_rule_p = &acl_rule_list_p->acl_rule_list[i];
            for (j = 0 ; j < acl_rule_p->acl_rule_node_list_count ; j ++) {
                acl_rule_node_t * intermediate_node_p = &acl_rule_p->acl_rule_node_list[j];
                if (intermediate_node_p->type == ACL_RULE_TOKEN_NODE 
                    && intermediate_node_p->exp_node 
                    && intermediate_node_p->exp_node->field == Field_Response_Frequency) {
                    
                    request_freq_t req_freq;
                    if (parse_request_frequency_value(intermediate_node_p->exp_node->exp_str, &req_freq) == NGX_HTTP_ACL_SUCCESS) {
                        if (req_freq.duration > ret_value)
                            ret_value = req_freq.duration;
                    }
                }
            }
        }
        acl_rule_list_p = acl_rule_list_p->next;
    }
    
    return ret_value;
}


ngx_int_t ngx_http_acl_update_response_codes(server_acl_rule_t * server_acl_rule_p, int code) {
    int i = 0;
    for (i = 0 ; i < (int)server_acl_rule_p->header_out_code_count ; i ++) {
        if (server_acl_rule_p->header_out_codes[i] == code) {
            break;
        }
    }

    server_acl_rule_p->header_out_code_count = server_acl_rule_p->header_out_code_count % MAX_HEADER_CODE_COUNT;
    server_acl_rule_p->header_out_codes[server_acl_rule_p->header_out_code_count] = code;
    server_acl_rule_p->header_out_code_count ++;

    return NGX_HTTP_ACL_SUCCESS;
}
ngx_int_t ngx_http_acl_get_response_codes(server_acl_rule_t * server_acl_rule_p)
{
    int i, j;
    
    if (server_acl_rule_p == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    acl_rule_list_t * acl_rule_list_p = server_acl_rule_p->head;

    while (acl_rule_list_p != NULL) {
        for (i = 0 ; i < acl_rule_list_p->acl_rule_count ; i ++) {
            acl_rule_t * acl_rule_p = &acl_rule_list_p->acl_rule_list[i];
            for (j = 0 ; j < acl_rule_p->acl_rule_node_list_count ; j ++) {
                acl_rule_node_t * intermediate_node_p = &acl_rule_p->acl_rule_node_list[j];
                if (intermediate_node_p->type == ACL_RULE_TOKEN_NODE 
                    && intermediate_node_p->exp_node 
                    && intermediate_node_p->exp_node->field == Field_Response_Frequency) {
                    int code = 0;
                    if (parse_response_code(intermediate_node_p->exp_node->name_str, &code) == NGX_HTTP_ACL_SUCCESS) {
                        ngx_http_acl_update_response_codes(server_acl_rule_p, code);
                    }
                }
            }
        }
        
        acl_rule_list_p = acl_rule_list_p->next;
    }
    
    return NGX_HTTP_ACL_SUCCESS;
}


void ngx_http_acl_get_ctx_and_conf(ngx_http_request_t* r, ngx_http_acl_main_conf_t** conf, ngx_http_acl_ctx_t** ctx) {
    if (ctx != NULL) {
        *ctx = NULL;
        *ctx = ngx_http_get_module_ctx(r, ngx_http_acl_module);
        if (*ctx == NULL) {
            ngx_http_cleanup_t* cln = NULL;
            for (cln = r->cleanup; cln != NULL; cln = cln->next) {
                if (cln->handler == ngx_http_acl_handler_cleanup) {
                    *ctx = cln->data;
                }
            }
        }
    }
    if (conf != NULL) {
        *conf = ngx_http_get_module_main_conf(r, ngx_http_acl_module);
    }
}

ngx_int_t ngx_http_acl_parse_time(u_char* str) {
    ngx_int_t ret = 0;
    size_t len = ngx_strlen(str);
    
    if (len == 1) {
        switch (str[0]) {
            case 's': return 1; break;
            case 'm': return 1 * 60; break;
            case 'h': return 1 * 60 * 60; break;
            case 'd': return 1 * 60 * 60 * 24; break;
            default: return NGX_ERROR; break;
        }
    }

    if (len < 2) {
        return NGX_ERROR;
    }

    ret = ngx_atoi(str, len - 1);
    if (ret == NGX_ERROR || ret <= 0) {
        return NGX_ERROR;
    }

    switch (str[len - 1]) {
        case 's': ret *= 1; break;
        case 'm': ret *= 1 * 60; break;
        case 'h': ret *= 1 * 60 * 60; break;
        case 'd': ret *= 1 * 60 * 60 * 24; break;
        default: return NGX_ERROR; break;
    }

    return ret;
}


time_node_t * ngx_http_alloc_time_node (ngx_http_request_t * r, mem_pool_t * pool) {
    time_node_t * time_node = mem_pool_calloc(pool, sizeof (time_node_t));
    
    if (time_node == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : Failed to alloc time node");
        return NULL;
    }
    
    time_node->next = NULL;
    time_node->prev = NULL;
    time_node->time = time(NULL);
    time_node->count = 1;

    return time_node;
}

