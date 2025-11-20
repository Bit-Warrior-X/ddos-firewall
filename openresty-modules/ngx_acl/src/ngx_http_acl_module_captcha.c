#include <ngx_http_acl_module_captcha.h>

typedef struct {
    u_char time[NGX_TIME_T_LEN + 1];
    u_char uid[NGX_HTTP_ACL_UID_LEN + 1];
    u_char hmac[crypto_hash_sha256_BYTES * 2 + 1];
} _info_t;


typedef struct _cache_info_s {
    ngx_int_t count;
} _cache_info_t;


static ngx_int_t _gen_info(ngx_http_request_t* r, _info_t* info);

static ngx_int_t _gen_verify_cookie(ngx_http_request_t *r, _info_t* info);

static ngx_int_t _gen_hmac(ngx_http_request_t* r, _info_t* info);

static ngx_int_t _verify_captcha_dispatcher(ngx_http_request_t* r);

static ngx_int_t _verify_hCaptcha(ngx_http_request_t* r, ngx_str_t captcha_token);

static ngx_int_t _verfiy_reCAPTCHA_compatible(ngx_http_request_t* r, 
    ngx_str_t captcha_token, 
    ngx_str_t secret,
    ngx_str_t url,
    ngx_int_t is_reCAPTCHA_v3,
    ngx_int_t score);


ngx_int_t ngx_http_acl_handler_captcha(ngx_http_request_t* r) {
    ngx_http_acl_dp_func_start(r);

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_get_ctx_and_conf(r, NULL, &ctx);

    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Context is NULL in ngx_http_acl_handler_captcha");
        return NGX_HTTP_ACL_FAULT;
    }
    
    ngx_http_acl_dpf(r, "verifying cookie (%p), (%p)", r, r->pool);
    switch (_verify_cookies(r)) {
        case NGX_HTTP_ACL_FAULT:
            ngx_http_acl_dp(r, "bad ... return");
            ngx_http_acl_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
            return NGX_HTTP_ACL_TRUE;
        case NGX_HTTP_ACL_SUCCESS:
            ngx_http_acl_dp(r, "success");
            return NGX_HTTP_ACL_TRUE;
        case NGX_HTTP_ACL_FAIL:
            ngx_http_acl_dp(r, "failed");
            ngx_http_acl_dp(r, "verifying captcha");
        
            switch (_verify_captcha_dispatcher(r)) {
                case NGX_HTTP_ACL_FAULT:
                    ngx_http_acl_dp(r, "bad ... return");
                    ngx_http_acl_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
                    return NGX_HTTP_ACL_TRUE;
                case NGX_HTTP_ACL_CAPTCHA_BAD:
                    ngx_http_acl_dp(r, "captcha bad ... return");
                    ngx_str_t* res_str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
                    ngx_str_set(res_str, "bad");
                    ngx_http_acl_append_action_str(r, res_str, NGX_HTTP_OK, ACTION_FLAG_FROM_CAPTCHA);
                    
                    return NGX_HTTP_ACL_TRUE;

                case NGX_HTTP_ACL_CAPTCHA_PASS:
                {
                    ngx_http_acl_dp(r, "pass");
                    ngx_http_acl_dpf(r, "generating releated info pool(%p) (%p)", r, r->pool);
                    _info_t* info = ngx_pcalloc(r->pool, sizeof(_info_t));
                    
                    if (info != NULL
                    &&  _gen_info(r, info) == NGX_HTTP_ACL_SUCCESS
                    &&  _gen_verify_cookie(r, info) == NGX_HTTP_ACL_SUCCESS) {
                        ngx_http_acl_dp(r, "success ... return");
                        ngx_str_t* res_str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
                        ngx_str_set(res_str, "good");
                        ngx_http_acl_append_action_str(r, res_str, NGX_HTTP_OK, ACTION_FLAG_FROM_CAPTCHA);
                    } else {
                        ngx_http_acl_dp(r, "failed ... return");
                        ngx_http_acl_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
                    }

                    return NGX_HTTP_ACL_TRUE;
                }
                case NGX_HTTP_ACL_FAIL:
                    ngx_http_acl_dp(r, "failed ... return");
                    ngx_http_acl_append_action_captcha(r, ACTION_FLAG_FROM_CAPTCHA);

                    return NGX_HTTP_ACL_TRUE;
                default:
                    ngx_http_acl_dp(r, "default ... return");
                    ngx_http_acl_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
                    return NGX_HTTP_ACL_TRUE;
            }
            break;
        default:
            ngx_http_acl_dp(r, "default ... return");
            ngx_http_acl_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
            return NGX_HTTP_ACL_TRUE;
    }

    ngx_http_acl_dp_func_end(r);
    return NGX_HTTP_ACL_FALSE;
}

static ngx_int_t _gen_info(ngx_http_request_t* r, _info_t* info) {
    ngx_http_acl_dp_func_start(r);

    if (r == NULL || info == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    time_t now = time(NULL);

    #if (NGX_TIME_T_SIZE == 4)
        ngx_snprintf(info->time, NGX_TIME_T_LEN, "%d", (int)now);
    #elif (NGX_TIME_T_SIZE == 8)
        ngx_snprintf(info->time, NGX_TIME_T_LEN, "%lld", (long long)now);
    #else
        #error The size of time_t is unexpected.
    #endif

    ngx_http_acl_dp(r, "generating random string");
    if (ngx_http_acl_rand_str(info->uid, sizeof(info->uid) - 1) != NGX_HTTP_ACL_SUCCESS) {
        ngx_http_acl_dp(r, "failed ... return");
        return NGX_HTTP_ACL_FAIL;
    }
    ngx_http_acl_dp(r, "success");

    ngx_http_acl_dp_func_end(r);
    return _gen_hmac(r, info);
}


static ngx_int_t _gen_verify_cookie(ngx_http_request_t *r, _info_t* info) {
    ngx_http_acl_dp_func_start(r);

    if (r == NULL || info == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
        
    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_get_ctx_and_conf(r, NULL, &ctx);

    ngx_http_acl_dpf(r, "generating cookie %s", "__acl_captcha_time");
    ngx_table_elt_t *header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        ngx_http_acl_dp(r, "failed ... return");
        return NGX_HTTP_ACL_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");

    ngx_palloc(r->pool, 100);
    header->value.data = ngx_pnalloc(r->pool, sizeof(info->time) + 64);
    if (header->value.data == NULL) {
        ngx_http_acl_dp(r, "failed to allocate memory for cookie value");
        return NGX_HTTP_ACL_FAIL;
    }
    
    u_char temp[200];
    u_char *p;
    p = ngx_snprintf((u_char*)temp, 200, "__acl_captcha_time=%s; Path=/", info->time);
    ngx_snprintf(header->value.data, header->value.len, "%s", temp);
    header->value.len = p - temp; //strlen(temp);
    
    ngx_http_acl_dpf(r, "success %V", &header->value);

    ngx_http_acl_dpf(r, "generating cookie %s", "__acl_captcha_uid");
    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        ngx_http_acl_dp(r, "failed ... return");
        return NGX_HTTP_ACL_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(info->uid) + 64);
    if (header->value.data == NULL) {
        ngx_http_acl_dp(r, "failed to alloc... return");
        return NGX_HTTP_ACL_FAIL;
    }
    ngx_snprintf(header->value.data, sizeof(info->uid) + 64, "__acl_captcha_uid=%s; Path=/", info->uid);
    header->value.len = ngx_strlen(header->value.data);
    
    ngx_http_acl_dpf(r, "success %V", &header->value);
    ngx_http_acl_dpf(r, "generating cookie %s", "__acl_captcha_hmac");
    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        ngx_http_acl_dp(r, "failed ... return");
        return NGX_HTTP_ACL_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(info->hmac) + 64);
    if (header->value.data == NULL) {
        ngx_http_acl_dp(r, "failed to alloc... return");
        return NGX_HTTP_ACL_FAIL;
    }
    ngx_snprintf(header->value.data, sizeof(info->hmac) + 64, "__acl_captcha_hmac=%s; Path=/", info->hmac);
    header->value.len = ngx_strlen(header->value.data);
    ngx_http_acl_dpf(r, "success %V", &header->value);

    ngx_http_acl_dp_func_end(r);
    return NGX_HTTP_ACL_SUCCESS;
}


static ngx_int_t _gen_hmac(ngx_http_request_t *r, _info_t* info) {
    ngx_http_acl_dp_func_start(r);
    
    if (r == NULL || info == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }
    
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, NULL);

    if (main_conf == NULL) {
        ngx_http_acl_dp(r, "Main configuration is NULL");
        return NGX_HTTP_ACL_FAIL;
    }
    
    struct {
        inx_addr_t inx_addr;
        u_char time[NGX_TIME_T_LEN + 1];
        u_char uid[NGX_HTTP_ACL_UID_LEN + 1];
        u_char salt[129];
    } buf;
    ngx_memzero(&buf, sizeof(buf));
    ngx_memcpy(buf.time, info->time, sizeof(buf.time));
    ngx_memcpy(buf.uid, info->uid, sizeof(buf.uid));
    ngx_memcpy(buf.salt, main_conf->random_str, sizeof(buf.salt));

    ngx_http_acl_dpf(r, "time=%s, uid=%s, salt=%s", buf.time, buf.uid, buf.salt);

    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)r->connection->sockaddr;
        ngx_memcpy(&(buf.inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));

    } 
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)r->connection->sockaddr;
        ngx_memcpy(&(buf.inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
    }
#endif

    ngx_memzero(info->hmac, sizeof(info->hmac));

    ngx_http_acl_dp(r, "getting hmac");
    ngx_int_t ret = ngx_http_acl_sha256(r->pool, info->hmac, sizeof(info->hmac), &buf, sizeof(buf));
    if (ret == NGX_HTTP_ACL_SUCCESS) {
        ngx_http_acl_dpf(r, "success(%s)", info->hmac);
    } else {
        ngx_http_acl_dp(r, "failed");
    }

    ngx_http_acl_dp_func_end(r);
    return ret;
}


ngx_int_t _verify_cookies(ngx_http_request_t* r) {
    ngx_http_acl_dp_func_start(r);

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);

    if (main_conf == NULL || ctx == NULL) {
        ngx_http_acl_dp(r, "Configuration or context is NULL");
        return NGX_HTTP_ACL_FAULT;
    }
        
    _info_t* under_attack_client = ngx_pcalloc(r->pool, sizeof(_info_t));
    _info_t* under_attack_expect = ngx_pcalloc(r->pool, sizeof(_info_t));

    if (under_attack_client == NULL || under_attack_expect == NULL) {
        ngx_http_acl_dp(r, "no memcoy ... return");
        return NGX_HTTP_ACL_FAULT;
    }

    ngx_memzero(under_attack_client, sizeof(_info_t));
    ngx_memzero(under_attack_expect, sizeof(_info_t));

#if (nginx_version >= 1023000)
    if (r->headers_in.cookie != NULL) {
        ngx_table_elt_t* cookies = r->headers_in.cookie;
#else
    if (r->headers_in.cookies.nelts > 0) {
        ngx_array_t* cookies = &(r->headers_in.cookies);
#endif
        ngx_str_t key, value;

        ngx_str_set(&key, "__acl_captcha_uid");
        ngx_str_null(&value);
        ngx_http_acl_dpf(r, "searching cookie %V", &key);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            ngx_http_acl_dpf(r, "found cookie %V", &value);
            ngx_memcpy(under_attack_client->uid, value.data, value.len);

        } else {
            ngx_http_acl_dpf(r, "not found cookie %V", &key);
        }

        ngx_str_set(&key, "__acl_captcha_hmac");
        ngx_str_null(&value);
        ngx_http_acl_dpf(r, "searching cookie %V", &key);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            ngx_http_acl_dpf(r, "found cookie %V", &value);
            ngx_memcpy(under_attack_client->hmac, value.data, value.len);

        } else {
            ngx_http_acl_dpf(r, "not found cookie %V", &key);
        }

        ngx_str_set(&key, "__acl_captcha_time");
        ngx_str_null(&value);
        ngx_http_acl_dpf(r, "searching cookie %V", &key);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            ngx_http_acl_dpf(r, "found cookie %V", &value);
            ngx_memcpy(under_attack_client->time, value.data, value.len);

        } else {
            ngx_http_acl_dpf(r, "not found cookie %V", &key);
        }
    }

    ngx_memcpy(under_attack_expect, under_attack_client, sizeof(_info_t));

    /* 计算正确的 HMAC */
    ngx_http_acl_dp(r, "generating hmac");
    if (_gen_hmac(r, under_attack_expect) != NGX_HTTP_ACL_SUCCESS) {
        ngx_http_acl_dp(r, "failed ... return");
        return NGX_HTTP_ACL_FAULT;
    }
    ngx_http_acl_dpf(r, "success(%s)", under_attack_expect->hmac);

    ngx_http_acl_dpf(r, "client.time=%s, client.uid=%s, client.hmac=%s", 
        under_attack_client->time, under_attack_client->uid, under_attack_client->hmac);

    ngx_http_acl_dpf(r, "expect.time=%s, expect.uid=%s, expect.hmac=%s", 
        under_attack_expect->time, under_attack_expect->uid, under_attack_expect->hmac);

    /* 验证 HMAC 是否正确 */
    ngx_http_acl_dp(r, "verifying hmac");
    if (ngx_memcmp(under_attack_client, under_attack_expect, sizeof(_info_t)) != 0) {
        ngx_http_acl_dp(r, "failed ... return");
        return NGX_HTTP_ACL_FAIL;
    }
    ngx_http_acl_dp(r, "success");

    ngx_http_acl_dpf(r, "expired(%s)?", under_attack_client->time);
    time_t client_time = ngx_atoi(under_attack_client->time, ngx_strlen(under_attack_client->time));
    if (difftime(time(NULL), client_time) > main_conf->acl_captcha_expire) {
        ngx_http_acl_dp(r, "yes");
        return NGX_HTTP_ACL_FAIL;
    }
    ngx_http_acl_dp(r, "no");

    ngx_http_acl_dp_func_end(r);
    return NGX_HTTP_ACL_SUCCESS;
}



static char* ngx_acl_get_captcha_response_token(ngx_http_request_t* r) {

    ngx_int_t need_to_continue = NGX_HTTP_ACL_TRUE;
    
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_uint_t                   i;
    char *                       response_token = NULL;
    
    part = &r->headers_in.headers.part;
    header = part->elts;

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

        if (ngx_strcmp(header[i].key.data, "H-Captcha-Response") == 0) {
            if (header[i].value.len > 0 ) {
                char * buf = ngx_pcalloc(r->pool, header[i].value.len  + 1);
                if (buf == NULL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory for response token");
                    return NULL;
                }
                
                ngx_memcpy(buf, header[i].value.data, header[i].value.len);
                buf[header[i].value.len] = '\0';
                response_token = buf;
            }
            need_to_continue = NGX_HTTP_ACL_FALSE;
        }
    }

    return response_token;
}
static ngx_int_t _verify_captcha_dispatcher(ngx_http_request_t* r) {
    ngx_http_acl_dp_func_start(r);

    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, NULL);
    char * captcha_token = NULL;
    
    captcha_token = ngx_acl_get_captcha_response_token(r);
    
    if (captcha_token != NULL &&  ngx_http_acl_check_flag(r->method, NGX_HTTP_GET)) {
        ngx_str_t token_str = ngx_null_string;
        token_str.data = (u_char*)captcha_token;
        token_str.len = strlen(captcha_token);

        ngx_int_t is_valid = NGX_HTTP_ACL_FALSE;
        if (main_conf->acl_captcha_type == NGX_HTTP_ACL_HCAPTCHA) {
            ngx_http_acl_dp(r, "verifying hCaptcha");
            is_valid = _verify_hCaptcha(r, token_str);
        }

        if(captcha_token) ngx_pfree(r->pool, captcha_token);
        
        if (is_valid == NGX_HTTP_ACL_SUCCESS) {
            ngx_http_acl_dp(r, "pass");
            return NGX_HTTP_ACL_CAPTCHA_PASS;
        } else {
            ngx_http_acl_dp(r, "bad");
            return NGX_HTTP_ACL_CAPTCHA_BAD;
        }
    }

    if (captcha_token) ngx_pfree(r->pool, captcha_token);
    
    ngx_http_acl_dp_func_end(r);
    return NGX_HTTP_ACL_FAIL;
}


static ngx_int_t _verify_hCaptcha(ngx_http_request_t* r, ngx_str_t captcha_token) {
    ngx_http_acl_dp_func_start(r);

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_main_conf_t* main_conf = NULL;
    ngx_http_acl_get_ctx_and_conf(r, &main_conf, &ctx);

    ngx_int_t ret = _verfiy_reCAPTCHA_compatible(r,
                                                 captcha_token,
                                                 main_conf->acl_captcha_hCaptcha_secret,
                                                 main_conf->acl_captcha_api,
                                                 NGX_HTTP_ACL_FALSE,
                                                 INT_MIN);
    
    ngx_http_acl_dp_func_end(r);
    
    return ret;
}

static ngx_int_t _verfiy_reCAPTCHA_compatible(ngx_http_request_t* r, 
    ngx_str_t captcha_token, 
    ngx_str_t secret,
    ngx_str_t url,
    ngx_int_t is_reCAPTCHA_v3,
    ngx_int_t score) {
    ngx_http_acl_dp_func_start(r);

    ngx_int_t ret = NGX_HTTP_ACL_SUCCESS;

    
    if (r == NULL || captcha_token.data == NULL || secret.data == NULL || url.data == NULL) {
        return NGX_HTTP_ACL_FAIL;
    }

    ngx_http_acl_ctx_t* ctx = NULL;
    ngx_http_acl_get_ctx_and_conf(r, NULL, &ctx);

    ngx_http_acl_dpf(r, "success(%V)", &captcha_token);

    char* json_str = NULL;
    ngx_http_acl_dpf(r, "using serect %V", &secret);

    ngx_http_acl_dp(r, "gererating request body for verification");

    u_char* in = NULL;
    u_char * p;
    int len = 0;
    
    in = ngx_pcalloc(r->pool, captcha_token.len + secret.len + 64);
    
    if (in == NULL) {
        ngx_http_acl_dp(r, "no memory ... releasing resources");
        ret = NGX_HTTP_ACL_FAIL;
        goto hash_map_free;
    }
    p = ngx_snprintf(in, captcha_token.len + secret.len + 64, "response=%s&secret=%s", (char*)(captcha_token.data), (char*)(secret.data));
    len = p - in;
    in[len] = '\0';
    
    ngx_http_acl_dpf(r, "success(%s)", (char *)in);
    ngx_http_acl_dpf(r, "sending a request to %V", &url);
    
    if (ngx_http_acl_http_post(r, (char*)url.data, (char *)in, &json_str) != NGX_HTTP_ACL_SUCCESS) {
        if (json_str != NULL) {
            ngx_http_acl_dpf(r, "failed(%s)", json_str);
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_acl: %s", json_str);
            free(json_str);
        } else {
            ngx_http_acl_dp(r, "failed");
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_acl: ngx_http_acl_http_post failed");
        }

        ngx_http_acl_dp(r, "releasing resources");
        goto hash_map_free;
    }
    ngx_http_acl_dpf(r, "success(%s)", json_str);

    ngx_http_acl_dpf(r, "parsing json_string(%s)", json_str);
    cJSON* json_obj = cJSON_Parse(json_str);
    free(json_str);
    if (json_obj == NULL) {
        ngx_http_acl_dp(r, "failed ... releasing resources");
        ret = NGX_HTTP_ACL_FAIL;
        goto hash_map_free;
    }
    ngx_http_acl_dp(r, "success");

    cJSON* json = json_obj->child;
    ngx_int_t flag = 0;
    while(json != NULL) {
        switch (json->type) {
            case cJSON_NULL:
                ngx_http_acl_dpf(r, "%s: null", json->string);
                break;
            case cJSON_True:
                ngx_http_acl_dpf(r, "%s: true", json->string);
                break;
            case cJSON_False:
                ngx_http_acl_dpf(r, "%s: false", json->string);
                break;
            case cJSON_Number:
                ngx_http_acl_dpf(r, "%s: %f", json->string, json->valuedouble);
                break;
            case cJSON_String:
                ngx_http_acl_dpf(r, "%s: %s", json->string, json->valuestring);
                break;
            default:
                break;
        }
        if (strcmp(json->string, "success") == 0 && json->type == cJSON_True) {
            ++flag;
        } else if (is_reCAPTCHA_v3 == NGX_HTTP_ACL_TRUE
               &&  strcmp(json->string, "score") == 0 
               &&  json->type == cJSON_Number
               &&  json->valuedouble >= score) {
            ++flag;
        }
        json = json->next;
    }

    if (flag == 2
    || (flag == 1 && is_reCAPTCHA_v3 == NGX_HTTP_ACL_FALSE)) {
        ret = NGX_HTTP_ACL_SUCCESS;
    } else {
        ret = NGX_HTTP_ACL_FAIL;
    }

    // json_free:
    cJSON_Delete(json_obj);

    hash_map_free:
    if (in) ngx_pfree (r->pool, in);

    ngx_http_acl_dp_func_end(r);
    return ret;
}