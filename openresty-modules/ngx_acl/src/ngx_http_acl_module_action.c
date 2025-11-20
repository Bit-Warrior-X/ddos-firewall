#include <ngx_http_acl_module_action.h>


typedef struct _captcha_cache_s {
    ngx_int_t count;
    ngx_uint_t error_page:1;    /**< 1: 返回 403, 0: CAPTCHA */
} _captcha_cache_t;


static ngx_int_t perform_action_return(ngx_http_request_t* r, action_t* action);


static ngx_int_t perform_action_decline(ngx_http_request_t* r, action_t* action);


static void perform_action_reg_content(ngx_http_request_t* r, action_t* action);


static ngx_int_t perform_action_html(ngx_http_request_t* r, action_t* action);


static ngx_int_t perform_action_str(ngx_http_request_t* r, action_t* action);


static ngx_int_t gen_response(ngx_http_request_t* r, ngx_str_t data, ngx_str_t content_type, ngx_uint_t http_status);


ngx_int_t ngx_http_acl_perform_action_at_access_end(ngx_http_request_t* r) {
    ngx_http_acl_dp_func_start(r);

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_get_ctx_and_conf(r, NULL, &ctx);

    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Context is NULL in ngx_http_acl_perform_action_at_access_end");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ngx_int_t ret_value = NGX_DECLINED;
    action_t *elt = NULL, *tmp = NULL;

    ngx_http_acl_dp(r, "looking action chain");

    DL_FOREACH_SAFE(ctx->action_chain, elt, tmp) {
        if (ngx_http_acl_check_flag(elt->flag, ACTION_FLAG_DECLINE)) {
            ngx_http_acl_dp(r, "action is decline");
            DL_DELETE(ctx->action_chain, elt);
            ret_value = perform_action_decline(r, elt);
            break;
            
        } else if (ngx_http_acl_check_flag(elt->flag, ACTION_FLAG_RETURN)) {
            ngx_http_acl_dp(r, "action is return");
            DL_DELETE(ctx->action_chain, elt);
            ret_value = perform_action_return(r, elt);
            break;

        } else if (ngx_http_acl_check_flag(elt->flag, ACTION_FLAG_REG_CONTENT)) {
            ngx_http_acl_dp(r, "action is reg content");
            DL_DELETE(ctx->action_chain, elt);
            perform_action_reg_content(r, elt);

        } else {
            ngx_http_acl_dp(r, "Unkown action flag is received in ngx_http_acl_perform_action_at_access_end()");
            elt->extra.http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            DL_DELETE(ctx->action_chain, elt);
            ret_value = perform_action_return(r, elt);
            break;
        }
    }

    ngx_http_acl_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_acl_perform_action_at_content(ngx_http_request_t* r) {
    ngx_http_acl_dp_func_start(r);

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_get_ctx_and_conf(r, NULL, &ctx);

    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Context is NULL in ngx_http_acl_perform_action_at_content");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ngx_int_t ret_value = NGX_DECLINED;
    action_t *elt = NULL, *tmp = NULL;

    ngx_http_acl_dp(r, "looking action chain");

    DL_FOREACH_SAFE(ctx->action_chain, elt, tmp) {
        if (elt == NULL)
            continue;
        
        if (ngx_http_acl_check_flag(elt->flag, ACTION_FLAG_STR)) {
            ngx_http_acl_dp(r, "action is str");
            DL_DELETE(ctx->action_chain, elt);
            ret_value = perform_action_str(r, elt);
            break;
            
        } else if (ngx_http_acl_check_flag(elt->flag, ACTION_FLAG_HTML)) {
            ngx_http_acl_dp(r, "action is html");
            DL_DELETE(ctx->action_chain, elt);
            ret_value = perform_action_html(r, elt);
            break;

        } else {
            ngx_http_acl_dp(r, "Unkown action flag is received in ngx_http_acl_perform_action_at_access_end()");
            elt->extra.http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            DL_DELETE(ctx->action_chain, elt);
            ret_value = perform_action_return(r, elt);
            break;
        }
    }

    ngx_http_acl_dp_func_end(r);
    return ret_value;
}


static ngx_int_t perform_action_return(ngx_http_request_t* r, action_t* action) {
    ngx_http_acl_dp_func_start(r);

    if (action == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Action is NULL in perform_action_return");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ngx_int_t ret = action->extra.http_status;
    ngx_http_acl_dpf(r, "return %i", ret);
    ngx_http_acl_dp_func_end(r);
    return ret;
}


static ngx_int_t perform_action_decline(ngx_http_request_t* r, action_t* action) {
    ngx_http_acl_dp_func_start(r);
    
    if (action == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Action is NULL in perform_action_decline");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ngx_http_acl_dp(r, "return NGX_DECLINED");
    ngx_http_acl_dp_func_end(r);
    return NGX_DECLINED;
    
}


static void perform_action_reg_content(ngx_http_request_t* r, action_t* action) {
    ngx_http_acl_dp_func_start(r);
    ngx_http_acl_register_content_handler(r);
    ngx_http_acl_dp_func_end(r);
}


static ngx_int_t perform_action_html(ngx_http_request_t* r, action_t* action) {
    ngx_http_acl_dp_func_start(r);
    ngx_str_t content_type = ngx_string("text/html");
    
    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;
    
    if (action == NULL || action->extra.extra_html.html == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid action in perform_action_html");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ret_value = gen_response(r, *action->extra.extra_html.html, content_type, action->extra.extra_html.http_status);

    ngx_http_acl_dp_func_end(r);
    return ret_value;
}


static ngx_int_t perform_action_str(ngx_http_request_t* r, action_t* action) {
    ngx_http_acl_dp_func_start(r);
    ngx_str_t content_type = ngx_string("text/plain");

    if (action == NULL || action->extra.extra_str.str == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid action in perform_action_str");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ngx_int_t ret_value = NGX_HTTP_ACL_FALSE;
    ret_value = gen_response(r, *action->extra.extra_str.str, content_type, action->extra.extra_str.http_status);
    
    ngx_http_acl_dp_func_end(r);
    return ret_value;
}


static ngx_int_t allocate_buffer(ngx_http_request_t* r, ngx_buf_t** buf_ptr, ngx_str_t data) {
    if (r == NULL || buf_ptr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }

    if (data.len > 0) {
        buf->pos = data.data;
        buf->last = data.data + data.len;
        buf->memory = 1; // Indicate that the buffer refers to memory that should not be modified
    } else {
        buf->pos = buf->last = NULL;
        buf->sync = 1; // Indicate an empty buffer
    }

    buf->last_buf = (r == r->main);
    buf->last_in_chain = 1;

    *buf_ptr = buf;
    return NGX_OK;
}

static ngx_int_t gen_response(ngx_http_request_t* r, ngx_str_t data, ngx_str_t content_type, ngx_uint_t http_status) {
    ngx_http_acl_dp_func_start(r);

    if (data.len > 0 && data.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Data is NULL in gen_response");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    // Discard any request body
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    
    ngx_http_acl_dpf(r, "getting response ''(%V)''", &data);

    // Set the Content-Type header
    r->headers_out.content_type = content_type;
    r->headers_out.content_type.len = content_type.len;

    // Set the HTTP status code
    r->headers_out.status = http_status;
    
    // Set the Content-Length header
    r->headers_out.content_length_n = data.len;

    if (ngx_http_acl_gen_no_cache_header(r) != NGX_HTTP_ACL_SUCCESS) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }

    // Send the response headers
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    // If only headers are required, return
    if (r->header_only) {
        return NGX_OK;
    }

    // Allocate and populate the buffer
    ngx_buf_t* buf;
    rc = allocate_buffer(r, &buf, data);
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_chain_t* out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (out == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }
    out->buf = buf;
    out->next = NULL;

    rc = ngx_http_output_filter(r, out);
    
    ngx_http_acl_dp_func_end(r);
    return rc;
}
