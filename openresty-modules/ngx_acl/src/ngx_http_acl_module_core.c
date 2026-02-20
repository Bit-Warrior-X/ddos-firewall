#include <nginx.h>
#include <ngx_http_acl_module_core.h>
#include <ngx_http_acl_module_type.h>
#include <ngx_http_acl_module_config.h>
#include <ngx_http_acl_module_util.h>
#include <ngx_http_acl_module_lru_cache.h>


static ngx_int_t ngx_http_acl_calc_comparative_expression(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_geo(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_ip(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_referer(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_request_method(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_uri_path(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_uri_query_string(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_user_agent(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_header(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_request_freq(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_asn(ngx_http_request_t* r, comparative_expression_t * exp_node);
static ngx_int_t ngx_http_acl_handler_check_response_freq(ngx_http_request_t* r, comparative_expression_t * exp_node);

static int acl_rule_node_parse_expression(ngx_http_request_t* r, acl_rule_node_t * acl_rule_node_list, int acl_rule_node_list_count, int *cur_index);
static int acl_rule_node_parse_term(ngx_http_request_t* r, acl_rule_node_t * acl_rule_node_list, int acl_rule_node_list_count, int *cur_index);
static int acl_rule_node_parse_factor(ngx_http_request_t* r, acl_rule_node_t * acl_rule_node_list, int acl_rule_node_list_count, int *cur_index);
static ngx_int_t evaluate_acl_rule(ngx_http_request_t* r, acl_rule_t * acl_rule);


static ngx_int_t ngx_http_acl_record_statistics(ngx_http_request_t* r);

static ngx_event_t * optimize_timer_event = NULL;
static ngx_event_t * monitor_timer_event = NULL;

typedef struct {
    ngx_int_t license_status;
    ngx_msec_t interval;
    ngx_event_t timer_event;
} ngx_lic_main_conf_t;

extern ngx_module_t ngx_lic_module;


static ngx_command_t ngx_http_acl_commands[] = {
    {
        ngx_string("acl_geo_database_path"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
        ngx_http_acl_geo_database_path_conf,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_acl_main_conf_t, acl_geo_database_path),
        NULL
   },
   {
        ngx_string("acl_isp_database_path"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
        ngx_http_acl_isp_database_path_conf,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_acl_main_conf_t, acl_isp_database_path),
        NULL
   },
   {
        ngx_string("acl_rule_shm_size"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
        ngx_http_acl_shm_size,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_acl_main_conf_t, acl_server_acl_shm_zone_size),
        NULL
   },
   {
        ngx_string("acl_req_shm_size"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
        ngx_http_acl_req_shm_size,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_acl_main_conf_t, acl_req_shm_zone_size),
        NULL
   },
   {
        ngx_string("acl_rsp_shm_size"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
        ngx_http_acl_rsp_shm_size,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_acl_main_conf_t, acl_rsp_shm_zone_size),
        NULL
   },
   {
        ngx_string("acl_captcha"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1234 | NGX_CONF_TAKE5 | NGX_CONF_TAKE6 | NGX_CONF_TAKE7,
        ngx_http_acl_captcha_conf,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("acl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_http_acl_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_acl_loc_conf_t, acl),
        NULL
   },
   {
        ngx_string("acl_optimize_period"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
        ngx_conf_set_sec_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_acl_main_conf_t, acl_optimize_period),
        NULL
   },
   ngx_null_command
};
        
static ngx_http_module_t  ngx_http_acl_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_acl_postconfig,               /* postconfiguration  ngx_http_acl_postconfig*/

    ngx_http_acl_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_acl_create_loc_conf,          /* create location configuration */
    ngx_http_acl_merge_loc_conf            /* merge location configuration */
};


ngx_module_t ngx_http_acl_module = {
    NGX_MODULE_V1,
    &ngx_http_acl_module_ctx,       /* module context */
    ngx_http_acl_commands,          /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    ngx_http_acl_init_process,      /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    ngx_http_acl_exit_process,      /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t ngx_http_acl_handle_str_acl_rule(ngx_http_request_t *r, char * str_acl_rule)
{
    if (r == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    ngx_http_acl_dp_func_start(r);
    
    if (str_acl_rule == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Received acl rule is NULL\n");
        return NGX_HTTP_ACL_FAIL;
    }

    ngx_http_acl_dpf(r, "str_acl_rule is\n'%s'", str_acl_rule);
    
    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;

    ngx_http_acl_loc_conf_t * loc_conf = NULL;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_acl_module);

    if (loc_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: Failed to get location configuration.");
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (loc_conf->acl == 0 || loc_conf->acl == NGX_CONF_UNSET) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_http_acl: ACL is not set, return true for checking.");
        return NGX_HTTP_ACL_SUCCESS;
    }
    
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: Failed to get main configuration.");
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (main_conf->server_acl_rule == NULL || main_conf->server_acl_rule == NGX_CONF_UNSET_PTR) {
         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: acl_rule_shm_size directive is not set or internal error");
        return NGX_HTTP_ACL_FAIL;
    }

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)main_conf->shm_zone_server_acl_rule->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    if (parse_acl_rule(r, str_acl_rule, main_conf->server_acl_rule) != NGX_HTTP_ACL_TRUE) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to parse received ACL rule\n");
        return NGX_HTTP_ACL_FAIL;
    }
    ngx_shmtx_unlock(&shpool->mutex);
    
    main_conf->server_acl_rule->max_req_freq_time = ngx_http_acl_get_max_request_freq_time(main_conf->server_acl_rule);
    main_conf->server_acl_rule->max_rsp_freq_time = ngx_http_acl_get_max_response_freq_time(main_conf->server_acl_rule);
    
    ngx_http_acl_get_response_codes(main_conf->server_acl_rule);
    
    ngx_http_acl_dp_func_end(r);
    
    return NGX_HTTP_ACL_SUCCESS;
}    


ngx_int_t ngx_http_acl_remove_acl_rule(ngx_http_request_t *r, int acl_rule_id)
{
    if (r == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    ngx_http_acl_dp_func_start(r);
    
    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;
    
    ngx_http_acl_loc_conf_t * loc_conf = NULL;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_acl_module);

    if (loc_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: Failed to get location configuration.");
        return NGX_HTTP_ACL_FAIL;
    }
    
    //if (loc_conf->acl == 0 || loc_conf->acl == NGX_CONF_UNSET) {
    //    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
    //        "ngx_http_acl: ACL is not set, return true for checking.");
    //    return NGX_HTTP_ACL_SUCCESS;
    //}

    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: Failed to get main configuration.");
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (main_conf->server_acl_rule == NULL || main_conf->server_acl_rule == NGX_CONF_UNSET_PTR) {
         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: acl_rule_shm_size directive is not set or internal error");
        return NGX_HTTP_ACL_FAIL;
    }
    
    
    server_acl_rule_t * server_acl_rule_p = main_conf->server_acl_rule;

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)main_conf->shm_zone_server_acl_rule->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    
    acl_rule_list_t * acl_rule_list_p = server_acl_rule_p->head;
    while (acl_rule_list_p != NULL) {
        if (acl_rule_list_p->acl_rule_list_id == acl_rule_id)
            break;
        acl_rule_list_p = acl_rule_list_p->next;
    }
    
    //Remove current ACL rule with id
    ngx_http_acl_dpf(r, "Trying to remove ACL rule with id %d", acl_rule_id);
    
    if (acl_rule_list_p == NULL) {
        ngx_http_acl_dpf(r, "There is no acl rule with id = %d", acl_rule_id);
    } else {
        // Remove current ACL rule list.
        if (remove_acl_rule_list(server_acl_rule_p, acl_rule_list_p, r->connection->log) != NGX_HTTP_ACL_SUCCESS) {
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to remove received ACL rule\n");
            return NGX_HTTP_ACL_FAIL;
        }

        // Update registered return header codes
        server_acl_rule_p->header_out_code_count = 0;
        memset(&server_acl_rule_p->header_out_codes, 0, sizeof (*server_acl_rule_p->header_out_codes));
        ngx_http_acl_get_response_codes(server_acl_rule_p);
        
    }
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_http_acl_dp_func_end(r);
    return NGX_HTTP_ACL_SUCCESS;
}

ngx_int_t ngx_http_acl_handle_acl_rule(ngx_http_request_t *r, int acl_rule_id, int action, int priority, char * str_rule)
{
    if (r == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    ngx_http_acl_dp_func_start(r);

    ngx_http_acl_loc_conf_t * loc_conf = NULL;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_acl_module);

    if (loc_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: Failed to get location configuration.");
        return NGX_HTTP_ACL_FAIL;
    }
    
    /*if (loc_conf->acl == 0 || loc_conf->acl == NGX_CONF_UNSET) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_http_acl: ACL is not set, return true for checking.");
        return NGX_HTTP_ACL_SUCCESS;
    }*/
    
    if (str_rule == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Received rule is NULL\n");
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (!(action == ACTION_ALLOW || action == ACTION_DROP || action == ACTION_DROP_BLOCK || action == ACTION_HCAPTCHA || action == ACTION_DENY)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Received Action is Unkown\n");
        return NGX_HTTP_ACL_FAIL;
    }
    
    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);

    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: Failed to get main configuration.");
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (main_conf->server_acl_rule == NULL || main_conf->server_acl_rule == NGX_CONF_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: acl_rule_shm_size directive is not set or internal error");
        return NGX_HTTP_ACL_FAIL;
    }

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)main_conf->shm_zone_server_acl_rule->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    
    if (add_acl_rule(main_conf->server_acl_rule, r->connection->log, acl_rule_id, action, priority, str_rule) != NGX_HTTP_ACL_SUCCESS) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to parse received ACL rule\n");
        return NGX_HTTP_ACL_FAIL;
    }
    
    main_conf->server_acl_rule->max_req_freq_time = ngx_http_acl_get_max_request_freq_time(main_conf->server_acl_rule);
    main_conf->server_acl_rule->max_rsp_freq_time = ngx_http_acl_get_max_response_freq_time(main_conf->server_acl_rule);
    
    ngx_http_acl_get_response_codes(main_conf->server_acl_rule);
    
    ngx_shmtx_unlock(&shpool->mutex);

    ngx_http_acl_dp_func_end(r);
    return NGX_HTTP_ACL_SUCCESS;
}

ngx_int_t ngx_http_acl_handler_check_cookie(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    ngx_http_acl_dp_func_start(r);
    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;
    
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }
    
#if (nginx_version < 1023000)
    if (r->headers_in.cookies.nelts == 0) {
        ngx_http_acl_dp(r, "cookie is empty.");
        if (exp_node->op == Operator_not_equals || exp_node->op == Operator_not_contains)
            ret_value = NGX_HTTP_ACL_TRUE;
    }
    
    else {
        ngx_table_elt_t** ppcookie = r->headers_in.cookies.elts;
        size_t i;
        ngx_int_t need_to_continue = NGX_HTTP_ACL_TRUE;
        
        for (i = 0; i < r->headers_in.cookies.nelts && need_to_continue == NGX_HTTP_ACL_TRUE; i++, ppcookie++) {
            ngx_str_t* native_cookies = &((**ppcookie).value);
            ngx_http_acl_dpf(r, "Native_cookie is '%s'", (char*)native_cookies->data);
            switch (exp_node->op) {
                case Operator_equals: {
                    if (compare_cookie_in_cookie_list(r, exp_node->exp_str, (char*)native_cookies->data) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_TRUE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                }
                case Operator_not_equals: {
                    ret_value = NGX_HTTP_ACL_TRUE;
                    if (compare_cookie_in_cookie_list(r, exp_node->exp_str, (char*)native_cookies->data) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_FALSE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                }
                case Operator_contains: {
                    if (check_contains_in_str(r, exp_node->exp_str, (char*)native_cookies->data, NGX_HTTP_ACL_TRUE) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_TRUE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                }
                case Operator_not_contains: {
                    ret_value = NGX_HTTP_ACL_TRUE;
                    if (check_contains_in_str(r, exp_node->exp_str, (char*)native_cookies->data, NGX_HTTP_ACL_TRUE) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_FALSE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                }
                default:
                    break;
            }
        }
    }
#else
    if (r->headers_in.cookie == NULL) {
        ngx_http_acl_dp(r, "cookie is empty.");
        if (exp_node->op == Operator_not_equals || exp_node->op == Operator_not_contains)
            ret_value = NGX_HTTP_ACL_TRUE;
    }
    else {
        ngx_table_elt_t* p = r->headers_in.cookie;
        ngx_int_t need_to_continue = NGX_HTTP_ACL_TRUE;

        for (p = r->headers_in.cookie; p != NULL && need_to_continue == NGX_HTTP_ACL_TRUE; p = p->next) {
            
            ngx_str_t cookie;
            cookie.len = p->value.len;
            cookie.data = p->value.data;

            ngx_http_acl_dpf(r, "Native_cookie is '%s'", (char*)cookie.data);

            switch (exp_node->op) {
                case Operator_equals: {
                    if (compare_cookie_in_cookie_list(r, exp_node->exp_str, (char*)cookie.data) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_TRUE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                }
                case Operator_not_equals: {
                    ret_value = NGX_HTTP_ACL_TRUE;
                    if (compare_cookie_in_cookie_list(r, exp_node->exp_str, (char*)cookie.data) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_FALSE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                }
                case Operator_contains: {
                    if (check_contains_in_str(r, exp_node->exp_str, (char*)cookie.data, NGX_HTTP_ACL_TRUE) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_TRUE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                }
                case Operator_not_contains: {
                    ret_value = NGX_HTTP_ACL_TRUE;
                    if (check_contains_in_str(r, exp_node->exp_str, (char*)cookie.data, NGX_HTTP_ACL_TRUE) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_FALSE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                }
                default:
                    break;
            }
         }
    }
#endif

    ngx_http_acl_dpf(r, "The Cookie compare process is fully completed with %d", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_geo(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }
     
    ngx_http_acl_dp_func_start(r);

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);

    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to get main configuration");
        return ret_value;
    }
    
    if (main_conf->geo_db_ctx == NULL) {
        if (exp_node->op == Operator_is_in) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to get location geo database context");
            return ret_value;
        } else {
            return NGX_HTTP_ACL_TRUE;
        }
    }

    MMDB_data_code_result_t continet_result;
    MMDB_data_code_result_t country_result;
    MMDB_data_code_result_t province_result;

    memset(&continet_result, 0, sizeof (MMDB_data_code_result_t));
    memset(&country_result, 0, sizeof (MMDB_data_code_result_t));
    memset(&province_result, 0, sizeof (MMDB_data_code_result_t));
    
    inx_addr_t inx_addr;
    
    if (r->connection->sockaddr->sa_family == AF_INET) {
        char str[INET_ADDRSTRLEN];
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        ngx_memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
        if (convert_ip_to_c_str(inx_addr, str, AF_INET) == NGX_HTTP_ACL_FAIL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to convert ip to c str");
            return ret_value;
        }

        continet_result = MMDB_get_continent_name_from_ip(main_conf->geo_db_ctx, str);
        country_result = MMDB_get_country_from_ip(main_conf->geo_db_ctx, str);
        province_result = MMDB_get_province_from_ip(main_conf->geo_db_ctx, str);
        
    }
    
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        char str[INET6_ADDRSTRLEN];
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        ngx_memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
        if (convert_ip_to_c_str(inx_addr, str, AF_INET6) == NGX_HTTP_ACL_FAIL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to convert ip to c str");
            return ret_value;
        }
        
        continet_result = MMDB_get_continent_name_from_ip(main_conf->geo_db_ctx, str);
        country_result = MMDB_get_country_from_ip(main_conf->geo_db_ctx, str);
        province_result = MMDB_get_province_from_ip(main_conf->geo_db_ctx, str);
    }
#endif

    unsigned char completed_geo_data[128];
    completed_geo_data[0] = '\0';
    
    size_t len = 0;
    if (continet_result.status == MMDB_SUCCESS) {
        len += ngx_snprintf(completed_geo_data + len, 128 - len, "%s", continet_result.data_code) - completed_geo_data;
    }
    if (country_result.status == MMDB_SUCCESS) {
        len += ngx_snprintf(completed_geo_data + len, 128 - len, ", %s", country_result.data_code) - (completed_geo_data + len);
    }
    if (province_result.status == MMDB_SUCCESS) {
        len += ngx_snprintf(completed_geo_data + len, 128 - len, ", %s", province_result.data_code) - (completed_geo_data + len);
    }

    ngx_http_acl_dpf(r, "completed_geo_data is '%s'", completed_geo_data);

    char * str_temp_exp = ngx_http_acl_clone_c_str(r, exp_node->exp_str);
    if (str_temp_exp == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to clone string");
        return ret_value;
    }
    
    remove_space_in_str(str_temp_exp);
    
    ngx_str_t ngx_str;
    
    ngx_str.data = (u_char*)str_temp_exp;
    ngx_str.len = strlen(str_temp_exp);
    
    UT_array* args = NULL;
    ngx_http_acl_str_split(r->pool, &ngx_str, ',', ngx_str.len, &args);
    
    ngx_str_t* p = NULL;
    while (p = (ngx_str_t*)utarray_next(args, p), p != NULL) {
        if (compare_case_insensitive(r, continet_result.data_code, (char*)p->data) == NGX_HTTP_ACL_SUCCESS) {
            ret_value = NGX_HTTP_ACL_TRUE;
            break;
        }
        if (compare_case_insensitive(r, country_result.data_code, (char*)p->data) == NGX_HTTP_ACL_SUCCESS) {
            ret_value = NGX_HTTP_ACL_TRUE;
            break;
        }
        if (compare_case_insensitive(r, province_result.data_code, (char*)p->data) == NGX_HTTP_ACL_SUCCESS) {
            ret_value = NGX_HTTP_ACL_TRUE;
            break;
        }
    }
    utarray_free(args);

    switch(exp_node->op) {
        case Operator_is_in:
            ngx_http_acl_dpf(r, "Operator_is_in and exp_node->exp_str is '%s'", exp_node->exp_str);
            break;
        case Operator_not_is_in: {
            ngx_http_acl_dpf(r, "Operator_not_is_in and exp_node->exp_str is '%s'", exp_node->exp_str);
            if (ret_value == NGX_HTTP_ACL_TRUE) 
                ret_value = NGX_HTTP_ACL_FALSE;
            else
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        }
        default:
            break;
    }
    
    ngx_http_acl_dpf(r, "The geo compare is fully completed with %d\n", ret_value);
    
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_ip(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }
    ngx_http_acl_dp_func_start(r);

    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;

    inx_addr_t inx_addr;
    char completed_ip_addr[64];
    completed_ip_addr[0] = '\0';
    
    if (r->connection->sockaddr->sa_family == AF_INET) {
        char str[INET_ADDRSTRLEN];
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        ngx_memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
        if (convert_ip_to_c_str(inx_addr, str, AF_INET) == NGX_HTTP_ACL_FAIL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to convert ip to c str");
            return ret_value;
        }
        snprintf(completed_ip_addr, 64, "%s", str);
        
    }
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        char str[INET6_ADDRSTRLEN];
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        ngx_memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
        if (convert_ip_to_c_str(inx_addr, str, AF_INET6) == NGX_HTTP_ACL_FAIL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to convert ip to c str");
            return ret_value;
        }
        snprintf(completed_ip_addr, 64, "%s", str);
    }
#endif

    ngx_http_acl_dpf(r, "completed_ip_data is '%s'", completed_ip_addr);
    int len_exp_str= strlen(exp_node->exp_str);
    char * exp_str =  ngx_palloc(r->pool, len_exp_str + 1);
    if (exp_str == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to alloc exp_str");
        return ret_value;
    }
    
    exp_str[0] = '\0';
    strncpy(exp_str, exp_node->exp_str, len_exp_str);
    exp_str[len_exp_str] = '\0';
    
    switch(exp_node->op) {
        case Operator_is_in:
            ngx_http_acl_dpf(r, "Operator_is_in and exp_node->exp_str is '%s'", exp_node->exp_str);
            if (compare_ip_in_ip_list(r, completed_ip_addr, exp_str) == NGX_HTTP_ACL_SUCCESS) {
                ret_value = NGX_HTTP_ACL_TRUE;
            }
            break;
        case Operator_not_is_in:
            ngx_http_acl_dpf(r, "Operator_not_is_in and exp_node->exp_str is '%s'", exp_node->exp_str);
            if (compare_ip_in_ip_list(r, completed_ip_addr, exp_str) != NGX_HTTP_ACL_SUCCESS) {
                ret_value = NGX_HTTP_ACL_TRUE;
            }
            break;
        default:
            break;
    }

    ngx_http_acl_dpf(r, "The ip compare is fully completed with %d", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_referer(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    ngx_http_acl_dp_func_start(r);

    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;
    
    ngx_str_t* p_referer = NULL;
    
    if (r->headers_in.referer == NULL) {
        ngx_http_acl_dp(r, "Referer is empty.");
    } else {
        p_referer = &r->headers_in.referer->value;
        ngx_http_acl_dpf(r, "Referer is %s.", (char*)p_referer->data);
    }
    
    switch (exp_node->op) {
        case Operator_equals:
            if (p_referer !=NULL && strcmp(exp_node->exp_str, (char *)p_referer->data) == 0)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_not_equals:
            if (p_referer == NULL || strcmp(exp_node->exp_str, (char *)p_referer->data) != 0)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_contains:
            if (p_referer !=NULL && check_contains_in_str(r, exp_node->exp_str, (char *)p_referer->data, NGX_HTTP_ACL_TRUE) == NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_not_contains:
            if (p_referer == NULL || check_contains_in_str(r, exp_node->exp_str, (char *)p_referer->data, NGX_HTTP_ACL_TRUE) != NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        default:
            break;
    }
    ngx_http_acl_dpf(r, "The referer compare is fully completed with %d", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_request_method(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }
    ngx_http_acl_dp_func_start(r);

    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;
    
    switch (exp_node->op) {
        case Operator_is_in:
            if (check_http_request_method_in_str(r, exp_node->exp_str) == NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_not_is_in:
            if (check_http_request_method_in_str(r, exp_node->exp_str) != NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        default:
            break;
    }
    ngx_http_acl_dpf(r, "The request method compare is fully completed with %d", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_uri_path(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    ngx_http_acl_dp_func_start(r);

    int i;
    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;
    
    ngx_str_t* p_uri = NULL;
    p_uri = &r->uri;

    // Remove HTTP version in uri path , /api/config HTTP/1.1

    char * str_uri = ngx_pcalloc(r->pool, p_uri->len + 1);
    if (str_uri == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to alloc memory");
        return NGX_HTTP_ACL_FALSE;
    }
    
    for (i = 0 ; i < (int)p_uri->len ; i ++) {
        if (p_uri->data[i] == ' ') {
            str_uri[i] = '\0';
            break;
        }
        str_uri[i] = p_uri->data[i];
    }
    if (str_uri[i] != '\0') 
        str_uri[i] = '\0';
    
    ngx_http_acl_dpf(r, "uri path is '%s'", str_uri);
    switch (exp_node->op) {
        case Operator_equals:
            if (compare_case_insensitive(r, exp_node->exp_str, str_uri) == NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_not_equals:
            if (compare_case_insensitive(r, exp_node->exp_str, str_uri) != NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_contains:
            if (check_contains_in_str(r, exp_node->exp_str, str_uri, NGX_HTTP_ACL_FALSE) == NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_not_contains:
            if (check_contains_in_str(r, exp_node->exp_str, str_uri, NGX_HTTP_ACL_FALSE) != NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_regex:
            if (compare_regex(r, exp_node->exp_str, str_uri) == NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        default:
            break;
    }

    ngx_http_acl_dpf(r, "The uri path compare is fully completed with %d", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_uri_query_string(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    ngx_http_acl_dp_func_start(r);
    
    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;

    ngx_str_t* p_args = &r->args;
    if (ngx_is_null_str(p_args)) {
        return ret_value;
    }
    
    ngx_http_acl_dpf(r, "uri query string is '%s'", (char*)p_args->data);
    switch (exp_node->op) {
        case Operator_equals: {
            UT_array* args = NULL;
            ngx_http_acl_str_split(r->pool, p_args, '&', p_args->len, &args);
            ngx_str_t* p = NULL;
            while (p = (ngx_str_t*)utarray_next(args, p), p != NULL) {
                if (compare_case_insensitive(r, exp_node->exp_str, (char*)p->data) == NGX_HTTP_ACL_SUCCESS) {
                    ret_value = NGX_HTTP_ACL_TRUE;
                    break;
                }
            }
            utarray_free(args);
            break;
        }
        
        case Operator_not_equals: {
            UT_array* args = NULL;
            ngx_http_acl_str_split(r->pool, p_args, '&', p_args->len, &args);
            ngx_str_t* p = NULL;
            ret_value = NGX_HTTP_ACL_TRUE;
            while (p = (ngx_str_t*)utarray_next(args, p), p != NULL) {
                if (compare_case_insensitive(r, exp_node->exp_str, (char*)p->data) == NGX_HTTP_ACL_SUCCESS) {
                    ret_value = NGX_HTTP_ACL_FALSE;
                    break;
                }
            }
            utarray_free(args);
            break;
        }
        case Operator_contains: {
            if (check_contains_in_str(r, exp_node->exp_str, (char*)p_args->data, NGX_HTTP_ACL_FALSE) == NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        }
        case Operator_not_contains: {
            if (check_contains_in_str(r, exp_node->exp_str, (char*)p_args->data, NGX_HTTP_ACL_FALSE) != NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        }
        default:
            break;
    }

    ngx_http_acl_dpf(r, "The uri query string compare is fully completed with %d", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_user_agent(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    ngx_http_acl_dp_func_start(r);

    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;

    ngx_str_t* p_ua = NULL;
    
    if (r->headers_in.user_agent == NULL) {
        ngx_http_acl_dp(r, "User agent is empty.");
    } else {
        p_ua = &r->headers_in.user_agent->value;
        ngx_http_acl_dpf(r, "User agent is '%s'", (char*)p_ua->data);
    }
    
    switch (exp_node->op) {
        case Operator_equals:
            if (p_ua != NULL && p_ua->data !=NULL && ngx_strcmp(exp_node->exp_str, (char *)p_ua->data) == 0)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_not_equals:
            if (!(p_ua != NULL && p_ua->data != NULL && ngx_strcmp(exp_node->exp_str, (char *)p_ua->data) == 0))
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_contains:
            if (p_ua != NULL && p_ua->data != NULL && check_contains_in_str(r, exp_node->exp_str, (char *)p_ua->data, NGX_HTTP_ACL_TRUE) == NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_not_contains:
            if (!(p_ua != NULL && p_ua->data != NULL && check_contains_in_str(r, exp_node->exp_str, (char *)p_ua->data, NGX_HTTP_ACL_TRUE) == NGX_HTTP_ACL_SUCCESS))
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_regex:
            if (p_ua != NULL && p_ua->data != NULL && compare_regex(r, exp_node->exp_str, (char *)p_ua->data) == NGX_HTTP_ACL_SUCCESS)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        default:
            break;
    }
    
    ngx_http_acl_dpf(r, "The user agent compare is fully completed %d", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_header(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    ngx_http_acl_dp_func_start(r);
    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;
    
    ngx_int_t need_to_continue = NGX_HTTP_ACL_TRUE;
    
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_uint_t                   i;
    
    part = &r->headers_in.headers.part;
    header = part->elts;

    switch(exp_node->op) {
        case Operator_not_is_in:
            ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_not_contains:
            ret_value = NGX_HTTP_ACL_TRUE;
            break;
        default:
            break;
    }

    for (i = 0; /* void */; i++) {
        if (need_to_continue == NGX_HTTP_ACL_FALSE)
            break;
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        ngx_http_acl_dpf(r, "header key is '%s', value is '%s'", (char *)header[i].key.data, (char *)header[i].value.data);
        if (compare_case_insensitive(r, (char *)header[i].key.data, exp_node->name_str) == NGX_HTTP_ACL_SUCCESS) {
            switch (exp_node->op) {
                case Operator_is_in:
                    if (compare_header_value_in_list(r, (char *)header[i].value.data, exp_node->exp_str) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_TRUE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                case Operator_not_is_in:
                    if (compare_header_value_in_list(r, (char *)header[i].value.data, exp_node->exp_str) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_FALSE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                case Operator_contains:
                    if (check_contains_in_str(r, exp_node->exp_str, (char *)header[i].value.data, NGX_HTTP_ACL_FALSE) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_TRUE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                case Operator_not_contains:
                    if (check_contains_in_str(r, exp_node->exp_str, (char *)header[i].value.data, NGX_HTTP_ACL_FALSE) == NGX_HTTP_ACL_SUCCESS) {
                        ret_value = NGX_HTTP_ACL_FALSE;
                        need_to_continue = NGX_HTTP_ACL_FALSE;
                    }
                    break;
                default:
                    break;
            }
        }
    }
    
    ngx_http_acl_dpf(r, "The head compare is fully completed with %d", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_request_freq(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    ngx_http_acl_dp_func_start(r);
    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);

    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to get loc");
        return ret_value;
    }

    ngx_int_t ip_type = r->connection->sockaddr->sa_family;
    
    inx_addr_t inx_addr;
    ngx_memset(&inx_addr, 0, sizeof(inx_addr_t));

    if (ip_type == AF_INET) {
        struct sockaddr_in* s_addr_in = (struct sockaddr_in*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr.ipv4), &(s_addr_in->sin_addr), sizeof(struct in_addr));
    } 
#if (NGX_HAVE_INET6)
    else if (ip_type == AF_INET6) {
        struct sockaddr_in6* s_addr_in6 = (struct sockaddr_in6*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr.ipv6), &(s_addr_in6->sin6_addr), sizeof(struct in6_addr));
    }
#endif

    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) main_conf->shm_zone_cc_req_deny->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    //if (robust_mutex_lock(&main_conf->robust_ip_access_mutex, r->connection->log) != NGX_OK ) {
    //    return NGX_HTTP_ACL_FAIL;
    //}

    ip_statis_t* statis = NULL;
    int match_count = 0 ;
    request_freq_t req_freq;
    
    if (parse_request_frequency_value(exp_node->exp_str, &req_freq) == NGX_HTTP_ACL_FAIL) {
        //robust_mutex_unlock(&main_conf->robust_ip_access_mutex, r->connection->log);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_HTTP_ACL_FAIL;
    }
    
    lru_cache_find_result_t tmp0 = lru_cache_find(main_conf->ip_access_statistics, &inx_addr, sizeof(inx_addr_t));
    if (tmp0.status == NGX_HTTP_ACL_KEY_EXISTS) {
        statis = *(tmp0).data;
        if (statis == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : statis must not be NULL");
            //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
            ngx_shmtx_unlock(&shpool->mutex);
            return ret_value;
        }
        if (statis->u.req_time_rec == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : statis->u.req_time_rec must not be NULL");
            //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
            ngx_shmtx_unlock(&shpool->mutex);
            return ret_value;
        }
        
        time_node_t * time_node_p = statis->u.req_time_rec->tail;
        time_t now = time(NULL);
        while (time_node_p != NULL) {
            double diff_second = difftime(now, time_node_p->time);
            if (diff_second > req_freq.duration) {
                break;
            }
            match_count += time_node_p->count;

            if (match_count > req_freq.count) // || time_node_p == statis->u.req_time_rec->head)
                break;
            
            time_node_p = time_node_p->prev;
        }
    } else {
        match_count = 0;
    }

    switch (exp_node->op) {
        case Operator_bigger:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_bigger and req_freq.count is %d", match_count, req_freq.count);
            if (match_count > req_freq.count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_bigger_equal:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_bigger_equal and req_freq.count is %d", match_count, req_freq.count);
            if (match_count >= req_freq.count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_small:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_small and req_freq.count is %d", match_count, req_freq.count);
            if (match_count < req_freq.count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_small_equal:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_small_equal and req_freq.count is %d", match_count, req_freq.count);
            if (match_count <= req_freq.count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_equal_equal:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_equal_equal and req_freq.count is %d", match_count, req_freq.count);
            if (req_freq.count == match_count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        default:
            break;
    }

    ngx_shmtx_unlock(&shpool->mutex);
    //robust_mutex_unlock(&main_conf->robust_ip_access_mutex, r->connection->log);
    ngx_http_acl_dpf(r, "The request frequency compare is fully completed with %d.", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_asn(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;
    
    ngx_http_acl_dp_func_start(r);

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);

    if (main_conf == NULL || main_conf->isp_db_ctx == NULL) {
        if (exp_node->op == Operator_is_in) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to get location isp database context");
            return ret_value;
        } else {
            return NGX_HTTP_ACL_TRUE;
        }
    }

    MMDB_data_asn_result_t asn_result;

    memset(&asn_result, 0, sizeof (MMDB_data_asn_result_t));
    
    inx_addr_t inx_addr;
    
    if (r->connection->sockaddr->sa_family == AF_INET) {
        char str[INET_ADDRSTRLEN];
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        ngx_memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
        if (convert_ip_to_c_str(inx_addr, str, AF_INET) == NGX_HTTP_ACL_FAIL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to convert ip to c str");
            return ret_value;
        }

        asn_result = MMDB_get_asn_code_from_ip(main_conf->isp_db_ctx, str);
        if (asn_result.status != MMDB_SUCCESS) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to get ASN code from IP");
          return ret_value;
        }
    }
    
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        char str[INET6_ADDRSTRLEN];
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        ngx_memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
        if (convert_ip_to_c_str(inx_addr, str, AF_INET6) == NGX_HTTP_ACL_FAIL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to convert ip to c str");
            return ret_value;
        }
        asn_result = MMDB_get_asn_code_from_ip(main_conf->isp_db_ctx, str);
        if (asn_result.status != MMDB_SUCCESS) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to get ASN code from IP");
          return ret_value;
        }
    }
#endif

    if (exp_node->op == Operator_Unknown) {
        ngx_http_acl_dp(r, "Operator is Unknown");
        return NGX_HTTP_ACL_FALSE;
    }

    char completed_asn_data[128];

    if (asn_result.status == MMDB_SUCCESS) {
      snprintf(completed_asn_data, 128, "%d", asn_result.asn);
    }
    
    ngx_http_acl_dpf(r, "completed_sn_data is '%s'", completed_asn_data);
    
    if (exp_node->op == Operator_is_in || exp_node->op == Operator_not_is_in) {
        
        char * str_temp_exp = ngx_http_acl_clone_c_str(r, exp_node->exp_str);
        if (str_temp_exp == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to clone string");
            return ret_value;
        }
        
        remove_space_in_str(str_temp_exp);
        
        ngx_str_t ngx_str;
        
        ngx_str.data = (u_char*)str_temp_exp;
        ngx_str.len = strlen(str_temp_exp);
        
        UT_array* args = NULL;
        ngx_http_acl_str_split(r->pool, &ngx_str, ',', ngx_str.len, &args);
        
        ngx_str_t* p = NULL;
        while (p = (ngx_str_t*)utarray_next(args, p), p != NULL) {
            if (compare_case_insensitive(r, completed_asn_data, (char*)p->data) == NGX_HTTP_ACL_SUCCESS) {
                ret_value = NGX_HTTP_ACL_TRUE;
                break;
            }
        }
        utarray_free(args);
        
        switch(exp_node->op) {
            case Operator_is_in:
                ngx_http_acl_dpf(r, "Operator_is_in and exp_node->exp_str is '%s'", exp_node->exp_str);
                break;
            case Operator_not_is_in: {
                ngx_http_acl_dpf(r, "Operator_not_is_in and exp_node->exp_str is '%s'", exp_node->exp_str);
                if (ret_value == NGX_HTTP_ACL_TRUE) 
                    ret_value = NGX_HTTP_ACL_FALSE;
                else
                    ret_value = NGX_HTTP_ACL_TRUE;
                break;
            }
            default:
                break;
        }
        ngx_http_acl_dpf(r, "The asn compare is fully completed with %d", ret_value);
        return ret_value;
    }
    
    if (exp_node->exp_str == NULL) {
        ngx_http_acl_dp(r, "exp string is NULL");
        return NGX_HTTP_ACL_FALSE;
    }
    
    int exp_asn = ngx_atoi((u_char*)exp_node->exp_str, strlen(exp_node->exp_str));
    if (exp_asn == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid ASN number: %s", exp_node->exp_str);
        return NGX_HTTP_ACL_FALSE;
    }
    
    if (exp_node->op == Operator_bigger) {
        if (asn_result.asn > exp_asn)
            ret_value = NGX_HTTP_ACL_TRUE;
        else
            ret_value = NGX_HTTP_ACL_FALSE;
    } else if (exp_node->op == Operator_bigger_equal) {
        if (asn_result.asn >= exp_asn)
            ret_value = NGX_HTTP_ACL_TRUE;
        else
            ret_value = NGX_HTTP_ACL_FALSE;
    } else if (exp_node->op == Operator_small) {
        if (asn_result.asn < exp_asn)
            ret_value = NGX_HTTP_ACL_TRUE;
        else
            ret_value = NGX_HTTP_ACL_FALSE;
    } else if (exp_node->op == Operator_small_equal) {
        if (asn_result.asn <= exp_asn)
            ret_value = NGX_HTTP_ACL_TRUE;
        else
            ret_value = NGX_HTTP_ACL_FALSE;
    } 
    
    ngx_http_acl_dpf(r, "The asn compare is fully completed with %d\n", ret_value);
    
    return ret_value;
}

static ngx_int_t ngx_http_acl_handler_check_response_freq(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    ngx_http_acl_dp_func_start(r);
    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);

    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : Failed to get loc");
        return ret_value;
    }

    ngx_int_t ip_type = r->connection->sockaddr->sa_family;
    
    inx_addr_t inx_addr;
    ngx_memset(&inx_addr, 0, sizeof(inx_addr_t));

    if (ip_type == AF_INET) {
        struct sockaddr_in* s_addr_in = (struct sockaddr_in*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr.ipv4), &(s_addr_in->sin_addr), sizeof(struct in_addr));
    } 
#if (NGX_HAVE_INET6)
    else if (ip_type == AF_INET6) {
        struct sockaddr_in6* s_addr_in6 = (struct sockaddr_in6*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr.ipv6), &(s_addr_in6->sin6_addr), sizeof(struct in6_addr));
    }
#endif

    //if (robust_mutex_lock(&main_conf->robust_ip_response_mutex, r->connection->log) != NGX_OK) {
    //    return ret_value;
    //}

    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) main_conf->shm_zone_cc_rsp_deny->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    ip_statis_t* statis = NULL;
    int match_count = 0 ;
    int header_code;
    request_freq_t req_freq;

    if (parse_response_code(exp_node->name_str, &header_code) == NGX_HTTP_ACL_FAIL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : Failed to parse response code");
        //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
        ngx_shmtx_unlock(&shpool->mutex);
        return ret_value;
    }
    
    if (parse_request_frequency_value(exp_node->exp_str, &req_freq) == NGX_HTTP_ACL_FAIL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : Failed to parse frequency value");
        //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
        ngx_shmtx_unlock(&shpool->mutex);
        return ret_value;
    }
    
    lru_cache_find_result_t tmp0 = lru_cache_find(main_conf->ip_response_statistics, &inx_addr, sizeof(inx_addr_t));
    
    if (tmp0.status == NGX_HTTP_ACL_KEY_EXISTS) {
        statis = *(tmp0).data;
        if (statis == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : statis must not be NULL");
            //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
            ngx_shmtx_unlock(&shpool->mutex);
            return ret_value;
        }
        if (statis->u.rsp_time_rec == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : statis->u.rsp_time_rec must not be NULL");
            //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
            ngx_shmtx_unlock(&shpool->mutex);
            return ret_value;
        }

        time_node_t * time_node_p = statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail;
    
        time_t now = time(NULL);
        while (time_node_p != NULL) {
            //double diff_second = difftime(now, time_node_p->time);
            
            long diff_second = now - time_node_p->time;
            if (diff_second > req_freq.duration) {
                break;
            }
            
            match_count += time_node_p->count;

            if (match_count > req_freq.count) //|| time_node_p == statis->u.rsp_time_rec->header_rsp_time_rec[i].rsp_time_rec.head)
                break;
            
            time_node_p = time_node_p->prev;
        }
    } else {
        match_count = 0;
    }

    switch (exp_node->op) {
        case Operator_bigger:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_bigger and req_freq.count is %d", match_count, req_freq.count);
            if (match_count > req_freq.count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_bigger_equal:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_bigger_equal and req_freq.count is %d", match_count, req_freq.count);
            if (match_count >= req_freq.count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_small:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_small and req_freq.count is %d", match_count, req_freq.count);
            if (match_count < req_freq.count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_small_equal:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_small_equal and req_freq.count is %d", match_count, req_freq.count);
            if (match_count <= req_freq.count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        case Operator_equal_equal:
            ngx_http_acl_dpf(r, "Match count is %d and op is Operator_equal_equal and req_freq.count is %d", match_count, req_freq.count);
            if (req_freq.count == match_count)
                ret_value = NGX_HTTP_ACL_TRUE;
            break;
        default:
            break;
    }

    //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
    ngx_shmtx_unlock(&shpool->mutex);
    
    ngx_http_acl_dpf(r, "The response frequency compare is fully completed with %d.", ret_value);
    return ret_value;
}

static ngx_int_t ngx_http_acl_record_statistics(ngx_http_request_t* r) {
    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);
    ngx_http_acl_dp_func_start(r);
    
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to ngx_http_acl_get_ctx_and_conf");
        return NGX_HTTP_ACL_FAIL;
    }

    if (main_conf->ip_access_statistics == NULL || main_conf->ip_access_statistics == NGX_CONF_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: acl_req_shm_size directive is not set or internal error");
        return NGX_HTTP_ACL_FAIL;
    }
    
    ngx_int_t ip_type = r->connection->sockaddr->sa_family;
    
    inx_addr_t inx_addr;
    ngx_memset(&inx_addr, 0, sizeof(inx_addr_t));

    if (ip_type == AF_INET) {
        struct sockaddr_in* s_addr_in = (struct sockaddr_in*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr.ipv4), &(s_addr_in->sin_addr), sizeof(struct in_addr));
    } 
#if (NGX_HAVE_INET6)
    else if (ip_type == AF_INET6) {
        struct sockaddr_in6* s_addr_in6 = (struct sockaddr_in6*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr.ipv6), &(s_addr_in6->sin6_addr), sizeof(struct in6_addr));
    }
#endif

    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) main_conf->shm_zone_cc_req_deny->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    
    //if (robust_mutex_lock(&main_conf->robust_ip_access_mutex, r->connection->log) != NGX_OK) {
    //    return NGX_HTTP_ACL_FAIL;
    //}
    
    ip_statis_t* statis = NULL;
    lru_cache_find_result_t tmp0 = lru_cache_find(main_conf->ip_access_statistics, &inx_addr, sizeof(inx_addr_t));

    if (tmp0.status == NGX_HTTP_ACL_KEY_EXISTS) {
        statis = *(tmp0).data;
    } else {
        lru_cache_add_result_t tmp1 = lru_cache_add(main_conf->ip_access_statistics, &inx_addr, sizeof(inx_addr_t));
        
        if (tmp1.status == NGX_HTTP_ACL_SUCCESS) {
            statis = mem_pool_calloc(&main_conf->ip_access_statistics->pool, sizeof(ip_statis_t));
            if (statis == NULL) {
                lru_cache_delete(main_conf->ip_access_statistics, &inx_addr, sizeof (inx_addr_t));
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : statis memory alloc is failed.");
                //robust_mutex_unlock(&main_conf->robust_ip_access_mutex, r->connection->log);
                ngx_shmtx_unlock(&shpool->mutex);
                return NGX_HTTP_ACL_FAIL;
            }
            *(tmp1.data) = statis;
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : lru cache add failed.");
            //robust_mutex_unlock(&main_conf->robust_ip_access_mutex, r->connection->log);
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_HTTP_ACL_FAIL;
        }
    }

    if (statis == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : statis node is null.");
        //robust_mutex_unlock(&main_conf->robust_ip_access_mutex, r->connection->log);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_HTTP_ACL_FAIL;
    }

    //Remove old time node
    
    if (statis->u.req_time_rec != NULL) {
        time_t standard_time = time(NULL) - main_conf->server_acl_rule->max_req_freq_time;
        
        time_node_t * temp_node = statis->u.req_time_rec->head;

        while (temp_node != NULL && temp_node->time < standard_time) {
            time_node_t * st_next = temp_node->next;
            mem_pool_free(&main_conf->ip_access_statistics->pool, temp_node);
            if (st_next != NULL) {
                st_next->prev = NULL;
                statis->u.req_time_rec->head = st_next;
            } else {
                statis->u.req_time_rec->head = NULL;
                statis->u.req_time_rec->tail = NULL;
                break;
            }
            temp_node = st_next;
        }
    }

    if (statis->u.req_time_rec == NULL) {
        statis->u.req_time_rec = mem_pool_calloc(&main_conf->ip_access_statistics->pool, sizeof (time_rec_t));
        if (statis->u.req_time_rec == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : Failed to alloc statis->u.req_time_rec.");
            //robust_mutex_unlock(&main_conf->robust_ip_access_mutex, r->connection->log);
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_HTTP_ACL_FAIL;
        }
    }
    
    time_node_t * time_node = NULL;
    
    if (statis->u.req_time_rec->head == NULL) {
        time_node = ngx_http_alloc_time_node(r, &main_conf->ip_access_statistics->pool);
        if (time_node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_HTTP_ACL_FAIL;
        }
        statis->u.req_time_rec->head = time_node;
        statis->u.req_time_rec->tail = time_node;
    } else if (statis->u.req_time_rec->tail == NULL) {
        statis->u.req_time_rec->tail = statis->u.req_time_rec->head;
    } else {
        if (statis->u.req_time_rec->tail->time  == time(NULL)) {
            statis->u.req_time_rec->tail->count ++;
        } else {
            time_node = ngx_http_alloc_time_node(r, &main_conf->ip_access_statistics->pool);
            if (time_node == NULL) {
                ngx_shmtx_unlock(&shpool->mutex);
                return NGX_HTTP_ACL_FAIL;
            }
            time_node->prev = statis->u.req_time_rec->tail;
            statis->u.req_time_rec->tail->next = time_node;
            statis->u.req_time_rec->tail= time_node;
        }
    }

    statis->ip_statis_type = IP_STATIS_REQUEST;
    
    //robust_mutex_unlock(&main_conf->robust_ip_access_mutex, r->connection->log);
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_http_acl_dp_func_end(r);
    return NGX_HTTP_ACL_SUCCESS;
}

static ngx_int_t ngx_http_acl_calc_comparative_expression(ngx_http_request_t* r, comparative_expression_t * exp_node) {
    if (r == NULL || exp_node == NULL || r->connection == NULL || r->connection->log == NULL) {
        return NGX_HTTP_ACL_FALSE;
    }

    ngx_int_t result = NGX_HTTP_ACL_FALSE;
    
    if (exp_node == NULL)
        return result;

    switch(exp_node->field) {
        case Field_Cookie:
            result = ngx_http_acl_handler_check_cookie(r, exp_node);
            break;
        case Field_Geo:
            result = ngx_http_acl_handler_check_geo(r, exp_node);
            break;
        case Field_IP:
            result = ngx_http_acl_handler_check_ip(r, exp_node);
            break;
        case Field_Referer:
            result = ngx_http_acl_handler_check_referer(r, exp_node);
            break;
        case Field_RequestMethod:
            result = ngx_http_acl_handler_check_request_method(r, exp_node);
            break;
        case Field_URIPath:
            result = ngx_http_acl_handler_check_uri_path(r, exp_node);
            break;
        case Field_URIQueryString:
            result = ngx_http_acl_handler_check_uri_query_string(r, exp_node);
            break;
        case Field_UserAgent:
            result = ngx_http_acl_handler_check_user_agent(r, exp_node);
            break;
        case Field_Header:
            result = ngx_http_acl_handler_check_header(r, exp_node);
            break;
        case Field_Request_Frequency:
            result = ngx_http_acl_handler_check_request_freq(r, exp_node);
            break;
        case Field_ASN:
            result = ngx_http_acl_handler_check_asn(r, exp_node);
            break;
        case Field_Response_Frequency:
            result = ngx_http_acl_handler_check_response_freq(r, exp_node);
            break;
        default:
            break;
    }

    return result;
}

static ngx_int_t evaluate_acl_rule(ngx_http_request_t* r, acl_rule_t * acl_rule)
{       
    if (r == NULL || acl_rule == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    if (acl_rule->acl_rule_node_list == NULL || acl_rule->acl_rule_node_list_count == 0)
        return NGX_HTTP_ACL_TRUE;
    
    int cur_index = 0;
    ngx_int_t result = NGX_HTTP_ACL_FALSE;
    result = acl_rule_node_parse_expression(r, acl_rule->acl_rule_node_list, acl_rule->acl_rule_node_list_count, &cur_index);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "ngx_http_acl: evaluate_acl_rule returns %d", (int)result);

    if (result != NGX_HTTP_ACL_FAIL) {
        if (cur_index < acl_rule->acl_rule_node_list_count && acl_rule->acl_rule_node_list[cur_index].type != ACL_RULE_TOKEN_END) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl: last node is not ACL_RULE_TOKEN_END");
            return NGX_HTTP_ACL_FAIL; 
        }
    }
    
    return result;
}

static int acl_rule_node_parse_expression(ngx_http_request_t* r, acl_rule_node_t * acl_rule_node_list, int acl_rule_node_list_count, int *cur_index) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "Input acl_rule_node_parse_expression cur_index is %d", *cur_index);
    int result = acl_rule_node_parse_term(r, acl_rule_node_list, acl_rule_node_list_count, cur_index);
    if (result == NGX_HTTP_ACL_FAIL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "acl_rule_node_parse_expression returns NGX_HTTP_ACL_FAIL and cur_index is %d", *cur_index);
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (*cur_index >= acl_rule_node_list_count) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "In acl_rule_node_parse_expression() current_token_index exceeds acl_rule_node_list_count");
        return NGX_HTTP_ACL_FAIL;
    }
    
    while (acl_rule_node_list[*cur_index].type == ACL_RULE_TOKEN_OR) {
        if (result == NGX_HTTP_ACL_TRUE) {
            while (acl_rule_node_list[*cur_index].type == ACL_RULE_TOKEN_OR) {
                *cur_index = (*cur_index + 1);
                int ret = acl_rule_node_parse_term(r, acl_rule_node_list, acl_rule_node_list_count, cur_index);
                if (ret == NGX_HTTP_ACL_FAIL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "acl_rule_node_parse_expression returns NGX_HTTP_ACL_FAIL and cur_index is %d", *cur_index);
                    return NGX_HTTP_ACL_FAIL;
                }
                if (*cur_index >= acl_rule_node_list_count) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "In acl_rule_node_parse_expression() current_token_index exceeds acl_rule_node_list_count");
                    return NGX_HTTP_ACL_FAIL;
                }
            }
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "acl_rule_node_parse_expression returns NGX_HTTP_ACL_TRUE and cur_index is %d", *cur_index);
            return NGX_HTTP_ACL_TRUE;
        }
        *cur_index = (*cur_index + 1); // Consume 'OR'

        if (*cur_index >= acl_rule_node_list_count) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "In acl_rule_node_parse_expression() current_token_index exceeds acl_rule_node_list_count");
            return NGX_HTTP_ACL_FAIL;
        }
        
        int rhs = acl_rule_node_parse_term(r, acl_rule_node_list, acl_rule_node_list_count, cur_index);
        if (rhs == NGX_HTTP_ACL_FAIL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "acl_rule_node_parse_expression returns NGX_HTTP_ACL_FAIL and cur_index is %d", *cur_index);
            return NGX_HTTP_ACL_FAIL;
        }
        result = result || rhs;
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "acl_rule_node_parse_expression returns %d and cur_index is %d", (int)result, *cur_index);
    return result;
}

static int acl_rule_node_parse_term(ngx_http_request_t* r, acl_rule_node_t * acl_rule_node_list, int acl_rule_node_list_count, int *cur_index) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "Input acl_rule_node_parse_term cur_index is %d", *cur_index);

    int result = acl_rule_node_parse_factor(r, acl_rule_node_list, acl_rule_node_list_count, cur_index);
    if (result == NGX_HTTP_ACL_FAIL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "acl_rule_node_parse_term returns  %d and cur_index is %d", NGX_HTTP_ACL_FAIL, *cur_index);
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (*cur_index >= acl_rule_node_list_count) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "In acl_rule_node_parse_term() current_token_index exceeds acl_rule_node_list_count");
        return NGX_HTTP_ACL_FAIL;
    }
    
    while (acl_rule_node_list[*cur_index].type == ACL_RULE_TOKEN_AND) {
        if (result == NGX_HTTP_ACL_FALSE) {
            while (acl_rule_node_list[*cur_index].type == ACL_RULE_TOKEN_AND) {
                *cur_index = (*cur_index + 1);
                if (*cur_index >= acl_rule_node_list_count) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "In acl_rule_node_parse_term() current_token_index exceeds acl_rule_node_list_count");
                    return NGX_HTTP_ACL_FAIL;
                }
                int ret = acl_rule_node_parse_factor(r, acl_rule_node_list, acl_rule_node_list_count, cur_index);
                if (ret == NGX_HTTP_ACL_FAIL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "acl_rule_node_parse_term returns NGX_HTTP_ACL_FAIL and cur_index is %d", *cur_index);
                    return NGX_HTTP_ACL_FAIL;
                }
            }
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "acl_rule_node_parse_term returns NGX_HTTP_ACL_FALSE and cur_index is %d", (int)result, *cur_index);
            return NGX_HTTP_ACL_FALSE;
        }
        *cur_index = (*cur_index + 1);
        if (*cur_index >= acl_rule_node_list_count) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "In acl_rule_node_parse_term() current_token_index exceeds acl_rule_node_list_count");
            return NGX_HTTP_ACL_FAIL;
        }
        int rhs = acl_rule_node_parse_factor(r, acl_rule_node_list, acl_rule_node_list_count, cur_index);
        if (rhs == NGX_HTTP_ACL_FAIL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "acl_rule_node_parse_term returns NGX_HTTP_ACL_FAIL and cur_index is %d", *cur_index);
            return NGX_HTTP_ACL_FAIL;
        }
        result = result && rhs;
    }
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "acl_rule_node_parse_term returns %d and cur_index is %d", (int)result, *cur_index);
    return result;
}

static int acl_rule_node_parse_factor(ngx_http_request_t* r, acl_rule_node_t * acl_rule_node_list, int acl_rule_node_list_count, int *cur_index) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "Input acl_rule_node_parse_factor cur_index is %d", *cur_index);
    
    if (*cur_index >= acl_rule_node_list_count) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "In acl_rule_node_parse_factor() current_token_index exceeds acl_rule_node_list_count");
        return NGX_HTTP_ACL_FAIL;
    }
    
    if (acl_rule_node_list[*cur_index].type == ACL_RULE_TOKEN_NODE) {
        int result = ngx_http_acl_calc_comparative_expression(r, acl_rule_node_list[*cur_index].exp_node);
        *cur_index = (*cur_index + 1);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "acl_rule_node_parse_factor returns %d and cur_index is %d", (int)result, *cur_index);
        return result;
    } else if (acl_rule_node_list[*cur_index].type == ACL_RULE_TOKEN_LPAREN) {
        *cur_index = (*cur_index + 1);
        int result = acl_rule_node_parse_expression(r, acl_rule_node_list, acl_rule_node_list_count, cur_index);

        if (*cur_index >= acl_rule_node_list_count) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "In acl_rule_node_parse_factor() current_token_index exceeds acl_rule_node_list_count");
            return NGX_HTTP_ACL_FAIL;
        }
        
        if (acl_rule_node_list[*cur_index].type != ACL_RULE_TOKEN_RPAREN) {
            // Error: Expected ']'
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "acl_rule_node_parse_factor() expected ] and cur_index is %d", *cur_index);
            return NGX_HTTP_ACL_FAIL;
        }
        *cur_index = (*cur_index + 1);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "acl_rule_node_parse_factor returns %d and cur_index is %d", (int)result, *cur_index);
        return result;
    } else {
        // Error: Invalid token at position current_token_index
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "acl_rule_node_parse_factor() Invalid token at position current_token_index and cur_index is %d", *cur_index);
        return NGX_HTTP_ACL_FAIL;
    }
}

ngx_int_t ngx_http_acl_process_acl_id(ngx_http_request_t* r, int acl_id) {
    ngx_http_acl_dp_func_start(r);
    ngx_int_t ret = ACL_RETURN_ALLOW_NO_RULE; // Allow request as default.

    int i;
    server_acl_rule_t * server_acl_rule_p;
    ngx_int_t match_rule_result = NGX_HTTP_ACL_FALSE;
    ngx_http_acl_ctx_t* ctx = NULL;
    
    ngx_lic_main_conf_t *lcf;
    /* Get the license configuration */
    lcf = (ngx_lic_main_conf_t *) ngx_http_get_module_main_conf(r, ngx_lic_module);
    if (lcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                      "ngx_lic module not configured");
        return NGX_DECLINED;
    }

    if (lcf->license_status == -2) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                      "l7 license is expired");
        return ACL_RETURN_NO_LICENSE;
    } else if (lcf->license_status == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                      "l7 license is invalid or mainuplated by user");
        return ACL_RETURN_NO_LICENSE;
    }
    
    ngx_http_acl_loc_conf_t * loc_conf = NULL;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_acl_module);
    
    if (loc_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: Failed to get location configuration.");
        return ACL_RETURN_INTERNAL_ERROR;
    }
    if (loc_conf->acl == 0 || loc_conf->acl == NGX_CONF_UNSET) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_http_acl: ACL is not set, return true for checking.");
        return ret;
    }
    
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);
    
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to ngx_http_acl_get_ctx_and_conf");
        return ACL_RETURN_INTERNAL_ERROR;
    }
    
    if (main_conf->server_acl_rule == NULL || main_conf->server_acl_rule == NGX_CONF_UNSET_PTR ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: acl_rule_shm_size directive is not set or internal error");
        return ACL_RETURN_INTERNAL_ERROR;
    }
    
    if (main_conf->server_acl_rule->head == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_http_acl: No ACL rule is registered");
        return ret;
    }
    
    if (ctx == NULL) {
        ngx_http_acl_dp(r, "Start allocating memory for storage contexts.");
        ngx_http_cleanup_t* cln = ngx_palloc(r->pool, sizeof(ngx_http_cleanup_t));
        ctx = ngx_palloc(r->pool, sizeof(ngx_http_acl_ctx_t));
        if (ctx == NULL || cln == NULL) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                "ngx_acl : The request context could not be created because the memory allocation failed.");
            return ACL_RETURN_INTERNAL_ERROR;
        }
        else {
            cln->handler = ngx_http_acl_handler_cleanup;
            cln->data = ctx;
            cln->next = NULL;

            ctx->read_body_done = NGX_HTTP_ACL_FALSE;
            ctx->has_req_body = NGX_HTTP_ACL_FALSE;
            ctx->waiting_more_body = NGX_HTTP_ACL_FALSE;
            
            ctx->matched = NGX_HTTP_ACL_FALSE;
            ctx->checked = NGX_HTTP_ACL_FALSE;
            ctx->register_content_handler = 0;

            ctx->action_chain = NULL;
            ctx->req_body.pos = NULL;
            ctx->req_body.last = NULL;
            ctx->req_body.memory = 1;
            ctx->req_body.temporary = 0;
            ctx->req_body.mmap = 0;

            ctx->time = time(NULL);

            if (r->cleanup == NULL) {
                r->cleanup = cln;
            } else {
                for (ngx_http_cleanup_t* i = r->cleanup; i != NULL; i = i->next) {
                    if (i->next == NULL) {
                        i->next = cln;
                        break;
                    }
                }
            }

            ngx_http_set_ctx(r, ctx, ngx_http_acl_module);
            
            ngx_http_acl_dpf(r, "ngx_acl : New Context (%p) initialization is complete", (void*)ctx);
        }
    } else if (ngx_http_get_module_ctx(r, ngx_http_acl_module) == NULL) {
        ngx_http_set_ctx(r, ctx, ngx_http_acl_module);
    }

    server_acl_rule_p = main_conf->server_acl_rule;

    //if (robust_mutex_lock(&main_conf->robust_server_acl_mutex, r->connection->log) != NGX_OK) {
    //    return ret;
    //}

    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) main_conf->shm_zone_server_acl_rule->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    acl_rule_list_t * acl_rule_list_p = server_acl_rule_p->head;

    while (acl_rule_list_p != NULL) {
        if (acl_rule_list_p->acl_rule_list_id == acl_id) {
            for (i = 0 ; i < acl_rule_list_p->acl_rule_count ; i ++ ) {
                acl_rule_t * acl_rule_p = &acl_rule_list_p->acl_rule_list[i];
                
                match_rule_result = evaluate_acl_rule(r, acl_rule_p);
                
                if (match_rule_result == NGX_HTTP_ACL_TRUE) {

                    ngx_http_acl_dp(r, "ngx_acl : Current request is matched with rule.");
                    dump_acl_rule(acl_rule_p, r->connection->log);

                    if (acl_rule_p->action == ACTION_DROP) {
                        ret = ACL_RETURN_DROP;
                    } else if (acl_rule_p->action == ACTION_HCAPTCHA) {
                        ret = ACL_RETURN_CAPTCHA_START;
                    } else if (acl_rule_p->action == ACTION_ALLOW) {
                        ret = ACL_RETURN_ALLOW_RULE;
                    } else if (acl_rule_p->action == ACTION_DROP_BLOCK) {
                        ret = ACL_RETURN_DROP_BLOCK;
                    } else if (acl_rule_p->action == ACTION_DENY) {
                        ret = ACL_RETURN_DENY;
                    } else {
                        ret = ACL_RETURN_INTERNAL_ERROR;
                    }
                    break;
                }
            }
            
            break;
       }
       acl_rule_list_p = acl_rule_list_p->next;
    }
    
    if (acl_rule_list_p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : There is no ACL rule which's id is %d.", acl_id);
    }


    ngx_int_t max_req_freq_time = server_acl_rule_p->max_req_freq_time;
    //robust_mutex_unlock(&main_conf->robust_server_acl_mutex, r->connection->log);
    ngx_shmtx_unlock(&shpool->mutex);
    
    if (max_req_freq_time != NGX_HTTP_ACL_FAIL && (ret == ACL_RETURN_ALLOW_RULE || ret == ACL_RETURN_ALLOW_NO_RULE || ret == ACL_RETURN_CAPTCHA_START))
    {
        ngx_http_acl_record_statistics(r);
    }

    ngx_http_acl_dpf(r, "ngx_acl : ngx_http_acl_process_acl_id() returns %d", ret);
    
    ngx_http_acl_dp_func_end(r);
    return ret;
}

void ngx_http_acl_handler_cleanup(void *data) {
    //This function is used as function pointer to get location and context
    return;
}

ngx_int_t ngx_http_acl_handler_log_phase(ngx_http_request_t* r) {
    ngx_http_acl_dp_func_start(r);

    int i;
    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t * main_conf = NULL;

    ngx_http_acl_loc_conf_t * loc_conf = NULL;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_acl_module);

    if (loc_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: Failed to get location configuration.");
        return NGX_HTTP_ACL_FAIL;
    }
        
    if (loc_conf->acl == 0 || loc_conf->acl == NGX_CONF_UNSET) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_http_acl: ACL is not set, return true for checking.");
        return NGX_DECLINED;
    }
    
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);
    
    ngx_uint_t header_code;
    header_code = r->headers_out.status;

    if (main_conf == NULL || main_conf->server_acl_rule == NULL || main_conf->server_acl_rule == NGX_CONF_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_acl_error: Failed to main loc");
        return NGX_DECLINED;
    }

    if (main_conf->ip_response_statistics == NULL || main_conf->ip_response_statistics == NGX_CONF_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_acl: acl_rsp_shm_size directive is not set or internal error");
        return NGX_DECLINED;
    }
    
    ngx_int_t ip_type = r->connection->sockaddr->sa_family;
    
    inx_addr_t inx_addr;
    ngx_memset(&inx_addr, 0, sizeof(inx_addr_t));

    if (ip_type == AF_INET) {
        struct sockaddr_in* s_addr_in = (struct sockaddr_in*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr.ipv4), &(s_addr_in->sin_addr), sizeof(struct in_addr));
    } 
#if (NGX_HAVE_INET6)
    else if (ip_type == AF_INET6) {
        struct sockaddr_in6* s_addr_in6 = (struct sockaddr_in6*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr.ipv6), &(s_addr_in6->sin6_addr), sizeof(struct in6_addr));
    }
#endif

    ngx_slab_pool_t  *shpool_server_acl_rule = (ngx_slab_pool_t *) main_conf->shm_zone_server_acl_rule->shm.addr;
    ngx_shmtx_lock(&shpool_server_acl_rule->mutex);
    for (i = 0 ; i < (int)main_conf->server_acl_rule->header_out_code_count ; i ++) {
        if (main_conf->server_acl_rule->header_out_codes[i] == (int)header_code)
            break;
    }
    ngx_shmtx_unlock(&shpool_server_acl_rule->mutex);

    //If header code is not registered in server_acl_rule, then pass it
    if (i == (int)main_conf->server_acl_rule->header_out_code_count) {
        return NGX_OK;
    }

    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) main_conf->shm_zone_cc_rsp_deny->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    
    ip_statis_t* statis = NULL;
    lru_cache_find_result_t tmp0 = lru_cache_find(main_conf->ip_response_statistics, &inx_addr, sizeof(inx_addr_t));

    if (tmp0.status == NGX_HTTP_ACL_KEY_EXISTS) {
        statis = *(tmp0).data;
    } else {
        lru_cache_add_result_t tmp1 = lru_cache_add(main_conf->ip_response_statistics, &inx_addr, sizeof(inx_addr_t));
        if (tmp1.status == NGX_HTTP_ACL_SUCCESS) {
            statis = mem_pool_calloc(&main_conf->ip_response_statistics->pool, sizeof(ip_statis_t));
            if (statis == NULL) {
                lru_cache_delete(main_conf->ip_response_statistics, &inx_addr, sizeof (inx_addr_t));
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : Failed to alloc statis in log phase");
                //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
                ngx_shmtx_unlock(&shpool->mutex);
                return NGX_DECLINED;
            }
            *(tmp1.data) = statis;
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : Failed to lru_cache_add");
            //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_DECLINED;
        }
    }

    if (statis == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_acl : statis is null in log phase");
        //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DECLINED;
    }
    
    if (statis->u.rsp_time_rec != NULL) {
        //Remove old time node
        time_t standard_time = time(NULL) - main_conf->server_acl_rule->max_rsp_freq_time;
        time_node_t * temp_node = statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head;
        
        while (temp_node != NULL && temp_node->time < standard_time) {
            time_node_t * st_next = temp_node->next;
            mem_pool_free(&main_conf->ip_response_statistics->pool, temp_node);
        
            if (st_next != NULL) {
                st_next->prev = NULL;
                statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head = st_next;
            } else {
                statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head = NULL;
                statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail = NULL;
            }
            temp_node = st_next;
        }
        
    } else {
        statis->u.rsp_time_rec = mem_pool_calloc(&main_conf->ip_response_statistics->pool, sizeof (header_rec_t));
        if (statis->u.rsp_time_rec == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0 , "ngx_http_acl : Failed to alloc statis->u.rsp_time_rec");
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_DECLINED;
        }
    }
    
    time_node_t * time_node = NULL;

    if (statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head == NULL) {
        time_node = ngx_http_alloc_time_node(r, &main_conf->ip_response_statistics->pool);
        if (time_node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_DECLINED;
        }
        statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head = time_node;
        statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail = time_node;
    } else if (statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail == NULL) {
        statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail = statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head;
    } else {

        if (statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail->time == time(NULL)) {
            statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail->count ++;
         }
        else {
            time_node = ngx_http_alloc_time_node(r, &main_conf->ip_response_statistics->pool);
            if (time_node == NULL) {
                ngx_shmtx_unlock(&shpool->mutex);
                return NGX_DECLINED;
            }
            time_node->prev = statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail;
            statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail->next = time_node;
            statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail= time_node;
        }
    }
    
    statis->ip_statis_type = IP_STATIS_RESPONSE;
    //robust_mutex_unlock(&main_conf->robust_ip_response_mutex, r->connection->log);
    ngx_shmtx_unlock(&shpool->mutex);
    
    ngx_http_acl_dp_func_end(r);
    return NGX_OK;
}

static void
ngx_http_acl_optimize_ip_access_time_tokens(mem_pool_t * pool, lru_cache_item_t * item, int period)
{
    if (item == NULL || item->data == NULL)
        return;

    ip_statis_t* statis = item->data;

    if (statis->u.req_time_rec != NULL) {
        time_t standard_time = time(NULL) - period;
        
        time_node_t * temp_node = statis->u.req_time_rec->head;

        while (temp_node != NULL && temp_node->time < standard_time) {
            time_node_t * st_next = temp_node->next;
            mem_pool_free(pool, temp_node);
            if (st_next != NULL) {
                st_next->prev = NULL;
                statis->u.req_time_rec->head = st_next;
            } else {
                statis->u.req_time_rec->head = NULL;
                statis->u.req_time_rec->tail = NULL;
                break;
            }
            temp_node = st_next;
        }
    }
}

static void
ngx_http_acl_optimize_ip_response_time_tokens(mem_pool_t * pool, lru_cache_item_t * item, int period)
{
    if (item == NULL || item->data == NULL)
        return;

    ip_statis_t* statis = item->data;

    for (size_t header_code = 100 ; header_code < MAX_HEADER_CODE_COUNT ; header_code ++) {
        if (statis->u.rsp_time_rec != NULL) {
            //Remove old time node
            time_t standard_time = time(NULL) - period;
            time_node_t * temp_node = statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head;
            
            while (temp_node != NULL && temp_node->time < standard_time) {
                time_node_t * st_next = temp_node->next;
                mem_pool_free(pool, temp_node);
                if (st_next != NULL) {
                    st_next->prev = NULL;
                    statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head = st_next;
                } else {
                    statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head = NULL;
                    statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail = NULL;
                }
                temp_node = st_next;
            }
        }
    }
}

static void
ngx_http_acl_optimze_period(ngx_event_t * ev) {
    if (ngx_quit || ngx_terminate || ngx_exiting)
        return;
    
    ngx_http_acl_main_conf_t * main_conf = NULL;
    ngx_cycle_t * cycle = ev->data;
    main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_acl_module);
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_http_acl : Failed to load main conf from cylce");
        return;
    }

    //ngx_log_debug(NGX_LOG_DEBUG_CORE, cycle->log, 0, "ngx_http_acl : Optimze timer callback is called");

    ngx_int_t need_to_optimize = 0;
    ngx_slab_pool_t  * shpool = (ngx_slab_pool_t *) main_conf->shm_zone_optimize_req->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    if ((time_t)(*main_conf->optimized_req_time) + main_conf->acl_optimize_period <= time(NULL)) {
        // No need to optimize;
        need_to_optimize = 1;
        *main_conf->optimized_req_time = time(NULL);
    }
    ngx_shmtx_unlock(&shpool->mutex);

    if (need_to_optimize == 1) {
        shpool = (ngx_slab_pool_t *) main_conf->shm_zone_cc_req_deny->shm.addr;
        ngx_shmtx_lock(&shpool->mutex);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, cycle->log, 0, "ngx_http_acl : Optimzing request time tokens %l", ngx_pid);
        lru_cache_iter_callback(main_conf->ip_access_statistics, ngx_http_acl_optimize_ip_access_time_tokens, main_conf->server_acl_rule->max_req_freq_time);
        ngx_shmtx_unlock(&shpool->mutex);
    }

    need_to_optimize = 0;
    shpool = (ngx_slab_pool_t *) main_conf->shm_zone_optimize_rsp->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    
    if ((time_t)(*main_conf->optimized_rsp_time) + main_conf->acl_optimize_period <= time(NULL)) {
        // No need to optimize;
        need_to_optimize = 1;
        *main_conf->optimized_rsp_time = time(NULL);
    }
    ngx_shmtx_unlock(&shpool->mutex);

    if (need_to_optimize == 1) {
        shpool = (ngx_slab_pool_t *) main_conf->shm_zone_cc_rsp_deny->shm.addr;
        ngx_shmtx_lock(&shpool->mutex);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, cycle->log, 0, "ngx_http_acl : Optimzing response time tokens %l", ngx_pid);
        lru_cache_iter_callback(main_conf->ip_response_statistics, ngx_http_acl_optimize_ip_response_time_tokens, main_conf->server_acl_rule->max_rsp_freq_time);
        ngx_shmtx_unlock(&shpool->mutex);
    }
    
    ngx_add_timer(ev, main_conf->acl_optimize_period * 1000);
}



static void
ngx_http_acl_monitor_period(ngx_event_t * ev) {

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        if (optimize_timer_event) {
            ngx_del_timer(optimize_timer_event);
            optimize_timer_event = NULL;
        }
        return;
    }
    
    ngx_add_timer(ev, 500);
}


ngx_int_t ngx_http_acl_init_process(ngx_cycle_t *cycle) {
    if (ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK; // Only initialize in worker processes
    }

    ngx_http_acl_main_conf_t * main_conf = NULL;
    main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_acl_module);
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_http_acl : Failed to load main conf from cylce");
        return NGX_ERROR;
    }
    
    if (main_conf->acl_optimize_period == NGX_CONF_UNSET || main_conf->acl_optimize_period <= 0)
        return NGX_OK;
    
    if (optimize_timer_event == NULL) {
        optimize_timer_event = ngx_pcalloc(cycle->pool, sizeof (ngx_event_t));
        if (optimize_timer_event == NULL) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_http_acl : Failed to palloc timer event");
            return NGX_ERROR;
        }

        optimize_timer_event->handler = ngx_http_acl_optimze_period;
        optimize_timer_event->log = cycle->log;
        optimize_timer_event->data = cycle;

        ngx_add_timer(optimize_timer_event, main_conf->acl_optimize_period * 1000);
    }
    
    if (monitor_timer_event == NULL) {
        monitor_timer_event = ngx_pcalloc(cycle->pool, sizeof (ngx_event_t));
        if (monitor_timer_event == NULL) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_http_acl : Failed to palloc timer event");
            return NGX_ERROR;
        }

        monitor_timer_event->handler = ngx_http_acl_monitor_period;
        monitor_timer_event->log = cycle->log;
        monitor_timer_event->data = NULL;

        ngx_add_timer(monitor_timer_event, 500);
    }
    
    return NGX_OK;
}

void ngx_http_acl_exit_process(ngx_cycle_t *cycle) {
    //if (optimize_timer_event)
    //    ngx_del_timer(optimize_timer_event);
    
    //if (monitor_timer_event)
    //    ngx_del_timer(monitor_timer_event);
}



