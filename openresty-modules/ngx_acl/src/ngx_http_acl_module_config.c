#include <ngx_http_acl_module_config.h>
#include <ngx_http_acl_module_util.h>
#include <ngx_http_acl_module_lru_cache.h>

extern ngx_module_t ngx_http_acl_module;


char* ngx_http_acl_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    if (cf == NULL || cmd == NULL || conf == NULL) {
        return NGX_CONF_ERROR;
    }
    if (ngx_conf_set_flag_slot(cf, cmd, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

char* ngx_http_acl_geo_database_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_acl_main_conf_t* main_conf = conf;

    if (cf == NULL || cmd == NULL || conf == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Invalid arguments in ngx_http_acl_geo_database_path_conf");
        return NGX_CONF_ERROR;
    }
    
    if (ngx_conf_set_str_slot(cf, cmd, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: %s", "the path of the geo database is not specified");
        return NGX_CONF_ERROR;
    }

    char* full_path = ngx_palloc(cf->pool, sizeof(char) * NGX_HTTP_ACL_RULE_MAX_LEN);
    if (full_path == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: Failed to alloc ngx_http_acl_geo_database_path_conf");
        return NGX_CONF_ERROR;
    }
    char* end = ngx_http_acl_to_c_str((u_char*)full_path, main_conf->acl_geo_database_path);
    *(end) = '\0';
    
    main_conf->geo_db_ctx = ngx_palloc(cf->pool, sizeof (MMDB_s));
    if (main_conf->geo_db_ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: %s", "Failed to allocate memory for geo database context");
        return NGX_CONF_ERROR;
    }

    int status;
    status = MMDB_open(full_path, MMDB_MODE_MMAP, main_conf->geo_db_ctx);
    
    if (MMDB_SUCCESS != status) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: Can't open %s - %s", full_path, MMDB_strerror(status));
        return NGX_CONF_ERROR;
    }
    
    ngx_pfree(cf->pool, full_path);
    
    return NGX_CONF_OK;
}

char* ngx_http_acl_isp_database_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_acl_main_conf_t* main_conf = conf;
    if (ngx_conf_set_str_slot(cf, cmd, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: %s", "the path of the isp database is not specified");
        return NGX_CONF_ERROR;
    }

    char* full_path = ngx_palloc(cf->pool, sizeof(char) * NGX_HTTP_ACL_RULE_MAX_LEN);
    if (full_path == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: Failed to alloc ngx_http_acl_isp_database_path_conf");
        return NGX_CONF_ERROR;
    }
    char* end = ngx_http_acl_to_c_str((u_char*)full_path, main_conf->acl_isp_database_path);
    if (end == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Failed to convert acl_geo_database_path to C string");
        ngx_pfree(cf->pool, full_path);
        return NGX_CONF_ERROR;
    }
    *(end) = '\0';
    
    main_conf->isp_db_ctx = ngx_palloc(cf->pool, sizeof (MMDB_s));
    if (main_conf->isp_db_ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Failed to allocate memory for geo_db_ctx");
        ngx_pfree(cf->pool, full_path);
        return NGX_CONF_ERROR;
    }

    int status;
    status = MMDB_open(full_path, MMDB_MODE_MMAP, main_conf->isp_db_ctx);
    
    if (MMDB_SUCCESS != status) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Can't open %s - %s", full_path, MMDB_strerror(status));
        ngx_pfree(cf->pool, full_path);
        return NGX_CONF_ERROR;
    }
    
    ngx_pfree(cf->pool, full_path);
    
    return NGX_CONF_OK;
}


char* ngx_http_acl_shm_size(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    if (cf == NULL || cmd == NULL || conf == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Invalid arguments in ngx_http_acl_shm_size");
        return NGX_CONF_ERROR;
    }

    ngx_http_acl_main_conf_t* main_conf = conf;
    if (ngx_conf_set_size_slot(cf, cmd, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: %s", "the size of acl_acl_rule_shm_size is not specified");
        return NGX_CONF_ERROR;
    }
    
    ngx_str_t name;
    u_char* raw_name = NULL;
    
    raw_name = ngx_pnalloc(cf->pool, sizeof(u_char) * 512);

    if (raw_name == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: Failed to alloc raw name");
        return NGX_CONF_ERROR;
    }
    
    ngx_http_acl_rand_str(raw_name, 16);
    //strcat((char*)raw_name, NGX_HTTP_ACL_SHARE_MEMORY_SERVER_ACL_NAME);
    ngx_snprintf(raw_name  + 16, 512 - 16, "%s", NGX_HTTP_ACL_SHARE_MEMORY_SERVER_ACL_NAME);
    
    name.data = raw_name;
    name.len = strlen((char*)raw_name);

    if (main_conf->acl_server_acl_shm_zone_size <= 0) 
        main_conf->acl_server_acl_shm_zone_size = NGX_HTTP_ACL_SHARE_MEMORY_SERVER_ACL_MIN_SIZE;
    
    main_conf->shm_zone_server_acl_rule = ngx_shared_memory_add(cf, &name, 
                                                        main_conf->acl_server_acl_shm_zone_size, 
                                                        &ngx_http_acl_module);

    if (main_conf->shm_zone_server_acl_rule == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
                "ngx_acl: failed to add shared memory for server acl rule");
        return NGX_CONF_ERROR;
    }
    main_conf->shm_zone_server_acl_rule->init = ngx_http_acl_shm_zone_server_acl_init;
    main_conf->shm_zone_server_acl_rule->data = main_conf;

     return NGX_CONF_OK;
    
}

char* ngx_http_acl_req_shm_size(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_acl_main_conf_t* main_conf = conf;
    if (ngx_conf_set_size_slot(cf, cmd, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: %s", "the size of acl_req_shm_size is not specified");
        return NGX_CONF_ERROR;
    }

    ngx_str_t req_name;
    
    u_char* raw_name = NULL;
    u_char* req_raw_name = NULL;

    raw_name = ngx_pnalloc(cf->pool, sizeof(u_char) * 512);
    if (raw_name == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: Failed to alloc raw name");
        return NGX_CONF_ERROR;
    }
    req_raw_name = ngx_pnalloc(cf->pool, sizeof(u_char) * 512);
    if (req_raw_name == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: Failed to alloc req_raw_name");
        return NGX_CONF_ERROR;
    }
    
    ngx_http_acl_rand_str(raw_name, 16);
    req_raw_name[0] = '\0';
    //strcat((char*)req_raw_name, (char*)raw_name);
    //strcat((char*)req_raw_name, NGX_HTTP_ACL_SHARE_MEMORY_CC_REQ_DNEY_NAME);
    
    ngx_snprintf(req_raw_name, 512, "%s", raw_name);
    ngx_snprintf(req_raw_name + 16, 512 - 16, "%s", NGX_HTTP_ACL_SHARE_MEMORY_CC_REQ_DNEY_NAME);
    
    req_name.data = req_raw_name;
    req_name.len = strlen((char*)req_raw_name);

    
    if (main_conf->acl_req_shm_zone_size <= 0) 
        main_conf->acl_req_shm_zone_size = NGX_HTTP_ACL_SHARE_MEMORY_REQ_MIN_SIZE;

    main_conf->shm_zone_cc_req_deny = ngx_shared_memory_add(cf, &req_name, 
                                                        main_conf->acl_req_shm_zone_size, 
                                                        &ngx_http_acl_module);
    
    if (main_conf->shm_zone_cc_req_deny == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
                "ngx_acl: failed to add shared memory for request");
        return NGX_CONF_ERROR;
    }
    
    main_conf->shm_zone_cc_req_deny->init = ngx_http_acl_shm_zone_cc_req_deny_init;
    main_conf->shm_zone_cc_req_deny->data = main_conf;

    ngx_str_t   optimize_req_name;
    optimize_req_name.data = raw_name;
    optimize_req_name.len = strlen((char*)raw_name);
    
    main_conf->shm_zone_optimize_req = ngx_shared_memory_add(cf, &optimize_req_name, 
                                                        NGX_HTTP_ACL_SHARE_MEMORY_OPTIMIZE_MIN_SIZE, 
                                                        &ngx_http_acl_module);
    
    if (main_conf->shm_zone_optimize_req == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
                "ngx_acl: failed to add shared memory for request");
        return NGX_CONF_ERROR;
    }
    
    main_conf->shm_zone_optimize_req->init = ngx_http_acl_shm_zone_optimize_req_init;
    main_conf->shm_zone_optimize_req->data = main_conf;
    
    return NGX_CONF_OK;
}


char* ngx_http_acl_rsp_shm_size(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_acl_main_conf_t* main_conf = conf;
    if (ngx_conf_set_size_slot(cf, cmd, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: %s", "the size of acl_rsp_shm_size is not specified");
        return NGX_CONF_ERROR;
    }

    ngx_str_t rsp_name;
    
    u_char* raw_name = NULL;
    u_char* rsp_raw_name = NULL;

    raw_name = ngx_pnalloc(cf->pool, sizeof(u_char) * 512);
    if (raw_name == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: Failed to alloc raw name");
        return NGX_CONF_ERROR;
    }
    
    
    rsp_raw_name = ngx_pnalloc(cf->pool, sizeof(u_char) * 512);
    if (rsp_raw_name == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_acl: Failed to alloc rsp_raw_name");
        return NGX_CONF_ERROR;
    }

    ngx_http_acl_rand_str(raw_name, 16);
    rsp_raw_name[0] = '\0';
    //strcat((char*)rsp_raw_name, (char*)raw_name);
    //strcat((char*)rsp_raw_name, NGX_HTTP_ACL_SHARE_MEMORY_CC_REQ_DNEY_NAME);
    
    ngx_snprintf(rsp_raw_name, 512, "%s", raw_name);
    ngx_snprintf(rsp_raw_name + 16, 512 - 16, "%s", NGX_HTTP_ACL_SHARE_MEMORY_CC_RSP_DNEY_NAME);
    
    rsp_name.data = rsp_raw_name;
    rsp_name.len = strlen((char*)rsp_raw_name);
    
    if (main_conf->acl_rsp_shm_zone_size <= 0) 
        main_conf->acl_rsp_shm_zone_size = NGX_HTTP_ACL_SHARE_MEMORY_RSP_MIN_SIZE;
    main_conf->shm_zone_cc_rsp_deny = ngx_shared_memory_add(cf, &rsp_name, 
                                                            main_conf->acl_rsp_shm_zone_size, 
                                                            &ngx_http_acl_module);
    if (main_conf->shm_zone_cc_rsp_deny == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
                "ngx_acl: failed to add shared memory for response ");
        return NGX_CONF_ERROR;
    }
    
    main_conf->shm_zone_cc_rsp_deny->init = ngx_http_acl_shm_zone_cc_rsp_deny_init;
    main_conf->shm_zone_cc_rsp_deny->data = main_conf;


    ngx_str_t   optimize_rsp_name;
    optimize_rsp_name.data = raw_name;
    optimize_rsp_name.len = strlen((char*)raw_name);
    
    main_conf->shm_zone_optimize_rsp = ngx_shared_memory_add(cf, &optimize_rsp_name, 
                                                        NGX_HTTP_ACL_SHARE_MEMORY_OPTIMIZE_MIN_SIZE, 
                                                        &ngx_http_acl_module);
    
    if (main_conf->shm_zone_optimize_rsp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
                "ngx_acl: failed to add shared memory for request");
        return NGX_CONF_ERROR;
    }
    
    main_conf->shm_zone_optimize_rsp->init = ngx_http_acl_shm_zone_optimize_rsp_init;
    main_conf->shm_zone_optimize_rsp->data = main_conf;
    
    return NGX_CONF_OK;
}

char* ngx_http_acl_captcha_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    if (cf == NULL || cmd == NULL || conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, "Invalid arguments in ngx_http_acl_captcha_conf");
        return NGX_CONF_ERROR;
    }
	// Do nothing here
	return NGX_CONF_OK;
}
ngx_int_t ngx_http_acl_postconfig(ngx_conf_t* cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;
/*
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_acl_handler_access_phase;
*/

    if (cf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, NULL, 0, "Configuration context is NULL in ngx_http_acl_postconfig");
        return NGX_ERROR;
    }
    
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Failed to get core main configuration");
        return NGX_ERROR;
    }
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_acl_handler_log_phase;

    return NGX_OK;
}

void* ngx_http_acl_create_main_conf(ngx_conf_t* cf) {
    ngx_http_acl_main_conf_t* main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_acl_main_conf_t));

    if (main_conf == NULL) {
        return NULL;
    }

    main_conf->acl_geo_database_path.len = NGX_CONF_UNSET_SIZE;
    
    main_conf->shm_zone_server_acl_rule = NGX_CONF_UNSET_PTR;
    main_conf->acl_server_acl_shm_zone_size =  NGX_CONF_UNSET;
    main_conf->server_acl_rule = NGX_CONF_UNSET_PTR;
    
    main_conf->geo_db_ctx = NGX_CONF_UNSET_PTR;
    main_conf->isp_db_ctx = NGX_CONF_UNSET_PTR;

    main_conf->shm_zone_cc_req_deny = NGX_CONF_UNSET_PTR;
    main_conf->shm_zone_cc_rsp_deny = NGX_CONF_UNSET_PTR;
    main_conf->acl_req_shm_zone_size =  NGX_CONF_UNSET;
    main_conf->acl_rsp_shm_zone_size =  NGX_CONF_UNSET;
    main_conf->ip_access_statistics = NGX_CONF_UNSET_PTR;
    main_conf->ip_response_statistics = NGX_CONF_UNSET_PTR;

    main_conf->acl_optimize_period = NGX_CONF_UNSET;

    main_conf->optimized_req_time = NGX_CONF_UNSET_PTR;
    main_conf->optimized_rsp_time = NGX_CONF_UNSET_PTR;

    static u_char s_rand_str[129] = { 0 };
    if (s_rand_str[0] == '\0') {
        ngx_http_acl_rand_str(s_rand_str, 128);
    }
    return main_conf;
}

void* ngx_http_acl_create_loc_conf(ngx_conf_t* cf) {
    if (cf == NULL) {
        return NULL;
    }

    ngx_http_acl_loc_conf_t* conf =  ngx_pcalloc(cf->pool, sizeof(ngx_http_acl_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    
    conf->acl = NGX_CONF_UNSET;
    
    return conf;
}

char* ngx_http_acl_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf) {
    if (cf == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_http_acl_loc_conf_t* parent = prev;
    ngx_http_acl_loc_conf_t* child = conf;

    if (parent == NULL || child == NULL)
        return NGX_CONF_OK;

    ngx_conf_merge_value(child->acl, parent->acl, NGX_CONF_UNSET);

    return NGX_CONF_OK;
}

ngx_int_t ngx_http_acl_shm_zone_cc_req_deny_init(ngx_shm_zone_t *zone, void *data) {
    if (zone == NULL || zone->shm.addr == NULL) {
        return NGX_ERROR;
    }

    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) zone->shm.addr;
    ngx_http_acl_main_conf_t* main_conf = (ngx_http_acl_main_conf_t*)(zone->data);
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, zone->shm.log, 0, "Main configuration is NULL in ngx_http_acl_shm_zone_cc_req_deny_init");
        return NGX_ERROR;
    }
    
    if (lru_cache_init(&main_conf->ip_access_statistics, SIZE_MAX, slab_pool, shpool) != NGX_OK)
        return NGX_ERROR;
    
    return NGX_OK;
}

ngx_int_t ngx_http_acl_shm_zone_cc_rsp_deny_init(ngx_shm_zone_t *zone, void *data) {
    if (zone == NULL || zone->shm.addr == NULL) {
        return NGX_ERROR;
    }
    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) zone->shm.addr;
    ngx_http_acl_main_conf_t* main_conf = (ngx_http_acl_main_conf_t*)(zone->data);
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, zone->shm.log, 0, "Main configuration is NULL in ngx_http_acl_shm_zone_cc_req_deny_init");
        return NGX_ERROR;
    }
    if (lru_cache_init(&main_conf->ip_response_statistics, SIZE_MAX, slab_pool, shpool) != NGX_OK)
        return NGX_ERROR;

    return NGX_OK;
}


ngx_int_t ngx_http_acl_shm_zone_server_acl_init(ngx_shm_zone_t *zone, void *data) {
    if (zone == NULL || zone->shm.addr == NULL) {
        return NGX_ERROR;
    }
    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) zone->shm.addr;
    ngx_http_acl_main_conf_t* main_conf = (ngx_http_acl_main_conf_t*)(zone->data);
    
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, zone->shm.log, 0, "Main configuration is NULL in ngx_http_acl_shm_zone_cc_req_deny_init");
        return NGX_ERROR;
    }

    mem_pool_t pool;
    if (mem_pool_init(&pool, slab_pool, shpool) != NGX_HTTP_ACL_SUCCESS) {
        return NGX_ERROR;
    }
    
    server_acl_rule_t * server_acl_rule_p = mem_pool_calloc(&pool, sizeof(server_acl_rule_t));
    if (server_acl_rule_p == NULL) {
        return NGX_ERROR;
    }
    
    ngx_memzero(server_acl_rule_p, sizeof(server_acl_rule_t));
    ngx_memcpy(&server_acl_rule_p->pool, &pool, sizeof(mem_pool_t));

    main_conf->server_acl_rule = server_acl_rule_p;
    main_conf->server_acl_rule->head = NULL;
    main_conf->server_acl_rule->tail = NULL;

    return NGX_OK;
}

ngx_int_t ngx_http_acl_shm_zone_optimize_req_init(ngx_shm_zone_t *zone, void *data) {
    if (zone == NULL || zone->shm.addr == NULL) {
        return NGX_ERROR;
    }

    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) zone->shm.addr;
    ngx_http_acl_main_conf_t* main_conf = (ngx_http_acl_main_conf_t*)(zone->data);
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, zone->shm.log, 0, "Main configuration is NULL in ngx_http_acl_shm_zone_cc_req_deny_init");
        return NGX_ERROR;
    }

    mem_pool_t pool;
    if (mem_pool_init(&pool, slab_pool, shpool) != NGX_HTTP_ACL_SUCCESS)
        return NGX_ERROR;
    
    main_conf->optimized_req_time = mem_pool_calloc(&pool, sizeof(time_t));
    if (main_conf->optimized_req_time == NULL)
        return NGX_ERROR;
    
    return NGX_OK;
}

ngx_int_t ngx_http_acl_shm_zone_optimize_rsp_init(ngx_shm_zone_t *zone, void *data) {
    if (zone == NULL || zone->shm.addr == NULL) {
        return NGX_ERROR;
    }

    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) zone->shm.addr;
    ngx_http_acl_main_conf_t* main_conf = (ngx_http_acl_main_conf_t*)(zone->data);
    if (main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, zone->shm.log, 0, "Main configuration is NULL in ngx_http_acl_shm_zone_cc_req_deny_init");
        return NGX_ERROR;
    }

    mem_pool_t pool;
    if (mem_pool_init(&pool, slab_pool, shpool) != NGX_HTTP_ACL_SUCCESS)
        return NGX_ERROR;
    
    main_conf->optimized_rsp_time = mem_pool_calloc(&pool, sizeof(time_t));
    if (main_conf->optimized_rsp_time == NULL)
        return NGX_ERROR;
    
    return NGX_OK;
}

