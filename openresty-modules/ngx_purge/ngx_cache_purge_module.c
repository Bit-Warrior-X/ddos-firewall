#include <ngx_config.h>
#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <syslog.h>
#include <time.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libev.h>
#include <redis_nginx_adapter.h>

#include "ngx_cache_purge_module.h"

extern ngx_module_t  ngx_http_proxy_module;

redisAsyncContext *db_ctxs[NGX_MAX_PROCESSES];

static ngx_str_t CONTENT_TYPE = ngx_string("text/plain");

static ngx_command_t  ngx_http_cache_purge_module_commands[] = {
    {
        ngx_string("redis_cache_handler"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_http_proxy_cache_purge_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    { ngx_string("redis_cache_purge_query"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_cache_purge,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_purge_loc_conf_t, purge_query),
      NULL },

    { ngx_string("cache_purge_redis_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_cache_purge_main_conf_t, redis_host),
      NULL },

    { ngx_string("cache_purge_redis_port"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_cache_purge_main_conf_t, redis_port),
      NULL },

    { ngx_string("cache_purge_redis_database"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_cache_purge_main_conf_t, redis_database),
      NULL },

    { ngx_string("cache_purge_redis_password"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_cache_purge_main_conf_t, redis_password),
      NULL },

    { ngx_string("cache_purge_redis_socket_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_cache_purge_main_conf_t, redis_socket_path),
      NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_cache_purge_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_cache_purge_postconfig,            /* postconfiguration */

    ngx_cache_purge_create_main_conf,      /* create main configuration */
    ngx_cache_purge_init_main_conf,        /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_cache_purge_create_loc_conf,  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_cache_purge_module = {
    NGX_MODULE_V1,
    &ngx_http_cache_purge_module_ctx,      /* module context */
    ngx_http_cache_purge_module_commands,  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_cache_purge_handler(ngx_http_request_t *r)
{
    ngx_http_cache_purge_loc_conf_t     *conf;
    ngx_str_t                            vv_purge_query = ngx_null_string;
    ngx_purge_request_ctx_t             *ctx = NULL;
    ngx_http_proxy_loc_conf_t           *plcf;
    ngx_http_proxy_main_conf_t          *pmcf;
    ngx_http_cache_t                    *c;
    ngx_str_t                           *key;
    ngx_int_t                            rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_cache_purge_module);

    if (conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: conf is null");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    if (conf->enable == 0 || conf->enable == NGX_CONF_UNSET) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: redis_cache_handler flag is not set");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_FORBIDDEN, &CONTENT_TYPE);
    }

    ngx_http_complex_value(r, conf->purge_query, &vv_purge_query);

    if (vv_purge_query.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: purge_query is empty");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_BAD_REQUEST, &CONTENT_TYPE);
    }
    
    if (ngx_http_discard_request_body(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: could not discard body");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    if ((ctx = ngx_pcalloc(r->pool, sizeof(ngx_purge_request_ctx_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: could not allocate memory to request context");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: ngx_http_upstream_create() failed");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    r->upstream->conf = &plcf->upstream;

    pmcf = ngx_http_get_module_main_conf(r, ngx_http_proxy_module);
    r->upstream->caches = &pmcf->caches;

    c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));
    if (c == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: ngx_pcalloc() failed");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    rc = ngx_array_init(&c->keys, r->pool, 1, sizeof(ngx_str_t));
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: ngx_array_init() failed");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }


    key = ngx_array_push(&c->keys);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: ngx_array_push() failed");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    key->len = vv_purge_query.len - 1; // in /*a*, remove first /.
    key->data = ngx_pnalloc(r->pool, vv_purge_query.len);
    if (key->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge_handler: ngx_pnalloc() failed");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    ngx_memcpy(key->data, vv_purge_query.data + 1 , key->len);
    key->data[key->len] = '\0';

    r->cache = c;
    c->body_start = ngx_pagesize;
    c->file_cache = NULL;
    c->file.log = r->connection->log;

    ngx_http_set_ctx(r, ctx, ngx_http_cache_purge_module);
    r->main->count++;

    ctx->failed = 0;
    ctx->success = 0;
    ctx->start_scan_purge = clock();

    redis_nginx_purge_cache_by_scan(r);

    return NGX_DONE;
}


static char *
ngx_cache_purge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t             *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    char                                 *ret;

    if ((ret = ngx_http_set_complex_value_slot(cf, cmd, conf)) != NGX_CONF_OK) {
        return ret;
    }

    clcf->handler = ngx_cache_purge_handler;

    return NGX_CONF_OK;
}

char *
ngx_http_proxy_cache_purge_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_cache_purge_loc_conf_t   *cplcf;
    ngx_str_t                         *value;

    cplcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_cache_purge_module);

    /* check for duplicates / collisions */
    if (cplcf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if ((int)cf->args->nelts >= 2 && ngx_strcmp(value[1].data, "on") == 0) {
        cplcf->enable = 1;
    } else {
        cplcf->enable = 0;
    }

    db_ctxs[ngx_process_slot] = NULL;
    
    return NGX_CONF_OK;
}

void redis_nginx_check_ping_callback(redisAsyncContext *context, void *reply, void *privdata) {
    redisReply *response =  (redisReply *)reply;
    ngx_http_request_t *r = (ngx_http_request_t * )privdata;
    ngx_str_t    *key;
    ngx_str_t               *http_response;
    ngx_int_t               rc;

    if (response == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to execute ping command on Redis");
        //ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
        //return;
    }

    key = r->cache->keys.elts;
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Key is NULL");
        rc = ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cache_purge_module);
    
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "context is NULL");
        rc = ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
        ngx_http_finalize_request(r, rc);
        return;
    }
    
    clock_t t = clock() - ctx->start_scan_purge;
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 2, "Purging count for condition is %d and took %f seconds\n", ctx->success + ctx->failed, time_taken);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 2, "{\"Success\" : %d, \"Failed\" : %d}\n", ctx->success, ctx->failed);

    http_response = ngx_cache_purge_alloc_str(r->pool, 512);
    ngx_sprintf(http_response->data, "{\"key\":\"%s\",\"success\":%d,\"failed\":%d}\n", (char *)key[0].data, ctx->success, ctx->failed);
    
    rc = ngx_selective_cache_purge_send_response(r, http_response->data, http_response->len, NGX_HTTP_OK, &CONTENT_TYPE);
    ngx_http_finalize_request(r, rc);
    
}

void redis_nginx_get_value_callback(redisAsyncContext *context, void *reply, void *privdata) {
    redisReply *response = (redisReply *)reply;
    http_req_cahce_value_t *req_cache_value_p = (http_req_cahce_value_t *)privdata;

    if (response == NULL || req_cache_value_p == NULL) {
        return;
    }

    if (response->type != REDIS_REPLY_STRING) {
        return;
    }

    /*
    -  ENOENT  (2): This error indicates that the file does not exist.
    -  EACCES  (13): This error indicates that the user does not have sufficient permissions to delete the file.
    -  EISDIR  (21): This error indicates that the specified path is a directory, not a regular file.
    -  EROFS   (30): This error indicates that the file system is read-only, and the file cannot be removed.
    -  EINVAL  (22): This error indicates an invalid argument, such as an empty or malformed filename.
    */

    if (req_cache_value_p->r == NULL) {
        return;
    }
    
    ngx_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(req_cache_value_p->r, ngx_http_cache_purge_module);

    if (ctx == NULL) {
        return;
    }
    
    if (remove(response->str) == 0) {
        ctx->success ++ ;
    } else {
        if (errno == 2)
            ctx->success ++ ;
        else
            ctx->failed ++ ;
    }

    redisAsyncCommand(context, NULL, req_cache_value_p, DEL_KEY_BY_DATABASE_COMMAND, req_cache_value_p->cache_key->data, req_cache_value_p->cache_key->len);
}


void redis_nginx_scan_by_cache_key_callback(redisAsyncContext *c, void *rep, void *privdata)
{
    ngx_http_request_t *r = (ngx_http_request_t * )privdata;
    size_t i;
    redisReply *reply = rep;
    ngx_int_t          rc;
    ngx_str_t         *key;
    

    if (privdata == NULL) {
        return;
    }

    if (r->cache == NULL || r->cache->keys.elts == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Cache key is NULL");
        rc = ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
        ngx_http_finalize_request(r, rc);
        return;
    }

    key = r->cache->keys.elts;
    
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 1, 
                "redis_nginx_scan_by_cache_key_callback(%s) is called", key[0].data);
    
    if ((reply == NULL) || (reply->element == NULL)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Empty reply from redis scan callback.");
        rc = ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
        ngx_http_finalize_request(r, rc);
        return;
    }
    
    if (reply->type == REDIS_REPLY_ARRAY && reply->elements >= 2) {
        redisReply *keys = reply->element[1];
        for (i = 0; i < keys->elements; i++) {
            http_req_cahce_value_t *req_cache_value_p = NULL;
            
            req_cache_value_p = ngx_palloc(r->pool, sizeof (http_req_cahce_value_t));
            if (req_cache_value_p == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate http req cache value");
                rc = ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
                ngx_http_finalize_request(r, rc);
                return;
            }

            ngx_str_t *cache_key = ngx_cache_purge_alloc_str(r->pool, keys->element[i]->len);
            if (cache_key == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate http req cache key");
                rc = ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
                ngx_http_finalize_request(r, rc);
                return;
            }
            ngx_memcpy(cache_key->data, keys->element[i]->str, cache_key->len);
            
            req_cache_value_p->r = r;
            req_cache_value_p->cache_key = cache_key;
            
            redisAsyncCommand(c, redis_nginx_get_value_callback, req_cache_value_p, GET_VALUE_BY_DATABASE_COMMAND, keys->element[i]->str);
        }
        
        if (strncmp(reply->element[0]->str, "0", 1) == 0) {
            redisAsyncCommand(c, redis_nginx_check_ping_callback, r, "PING");
        } else {
            redisAsyncCommand(c, redis_nginx_scan_by_cache_key_callback, r, SCAN_BY_CACHE_DATABASE_COMMAND, reply->element[0]->str, key[0].data, key[0].len);
        }
    }
}

int redis_nginx_purge_cache_by_scan(ngx_http_request_t *r)
{
    redisAsyncContext *c = redis_nginx_open((redisAsyncContext **)&db_ctxs[ngx_process_slot]);
    
    if (c == NULL) {
        ngx_int_t rc;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to open Redis Server");
        rc = ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
        ngx_http_finalize_request(r, rc);
    }

    ngx_str_t         *key;
    key = r->cache->keys.elts;

    redisAsyncCommand(c, redis_nginx_scan_by_cache_key_callback, r, SCAN_BY_CACHE_DATABASE_COMMAND, "0", key[0].data, key[0].len);
    return 0;
}

void *
ngx_http_cache_purge_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_cache_purge_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cache_purge_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->*.method = { 0, NULL }
     *     conf->*.access = NULL
     *     conf->*.access6 = NULL
     *     conf->handler = NULL
     *     conf->original_handler = NULL
     */

    conf->enable = NGX_CONF_UNSET;
    conf->purge_query = NULL;
    return conf;
}

// main config
static void *
ngx_cache_purge_create_main_conf(ngx_conf_t *cf)
{
    ngx_cache_purge_main_conf_t    *conf = ngx_pcalloc(cf->pool, sizeof(ngx_cache_purge_main_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enabled = 0;
    conf->redis_socket_path.data = NULL;
    conf->redis_host.data = NULL;
    conf->redis_port = NGX_CONF_UNSET_UINT;
    conf->redis_database = NGX_CONF_UNSET_UINT;
    conf->redis_password.data = NULL;
    conf->redis_store_handler = NULL;
    return conf;
}

ngx_str_t *
ngx_cache_purge_alloc_str(ngx_pool_t *pool, uint len)
{
    ngx_str_t *aux = (ngx_str_t *) ngx_pcalloc(pool, sizeof(ngx_str_t) + len + 1);
    if (aux != NULL) {
        aux->data = (u_char *) (aux + 1);
        aux->len = len;
        ngx_memset(aux->data, '\0', len + 1);
    }
    return aux;
}

static ngx_int_t
ngx_selective_cache_purge_send_header(ngx_http_request_t *r, size_t len, ngx_uint_t status, ngx_str_t *content_type)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = len;
    r->header_only = len ? 0 : 1;
    r->keepalive = 0;

    r->headers_out.content_type.data = content_type->data;
    r->headers_out.content_type.len = content_type->len;
    r->headers_out.content_type_len = content_type->len;

    return ngx_http_send_header(r);
}

static ngx_int_t
ngx_selective_cache_purge_send_response_text(ngx_http_request_t *r, const u_char *text, uint len, ngx_flag_t last_buffer)
{
    ngx_buf_t     *b;
    ngx_chain_t   out;

    if ((r == NULL) || (text == NULL) || (r->connection->error)) {
        return NGX_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_copy(b->pos, text, len);
    b->memory = len ? 1 : 0;
    b->last_buf = (r == r->main) ? last_buffer : 0;
    b->last_in_chain = 1;
    b->flush = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


ngx_int_t
ngx_selective_cache_purge_send_response(ngx_http_request_t *r, u_char *data, size_t len, ngx_uint_t status, ngx_str_t *content_type)
{
    ngx_int_t rc;
    
    if (r == NULL) {
        return NGX_ERROR;
    }
    
    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return ngx_selective_cache_purge_send_header(r, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, content_type);
    }

    if ((r->method == NGX_HTTP_HEAD) || (len == 0)) {
        return ngx_selective_cache_purge_send_header(r, len, status, content_type);
    }

    rc = ngx_selective_cache_purge_send_header(r, len, status, content_type);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_selective_cache_purge_send_response_text(r, data, len, 1);
}


static char *
ngx_cache_purge_init_main_conf(ngx_conf_t *cf, void *parent)
{
#ifdef NGX_HTTP_CACHE
    ngx_cache_purge_main_conf_t     *conf = parent;

    if (conf->redis_host.data != NULL) {
        ngx_str_t *redis_host = ngx_cache_purge_alloc_str(cf->pool, conf->redis_host.len);
        ngx_snprintf(redis_host->data, conf->redis_host.len, "%V", &conf->redis_host);
        conf->redis_host.data = redis_host->data;

        conf->enabled = 1;
    }

    if (conf->redis_socket_path.data != NULL) {
        ngx_str_t *redis_socket_path = ngx_cache_purge_alloc_str(cf->pool, conf->redis_socket_path.len);
        ngx_snprintf(redis_socket_path->data, conf->redis_socket_path.len, "%V", &conf->redis_socket_path);
        conf->redis_socket_path.data = redis_socket_path->data;

        conf->enabled = 1;
    }

    if (conf->redis_password.data != NULL) {
        ngx_str_t *redis_password = ngx_cache_purge_alloc_str(cf->pool, conf->redis_password.len);
        ngx_snprintf(redis_password->data, conf->redis_password.len, "%V", &conf->redis_password);
        conf->redis_password.data = redis_password->data;
    }

    if (conf->redis_socket_path.data && conf->redis_host.data) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "cache_purge_redis_host and cache_purge_redis_socket_path are both specified\n");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->redis_port, conf->redis_port, 6379);
    ngx_conf_merge_uint_value(conf->redis_database, conf->redis_database, 0);

    
    if (conf->enabled) {
        conf->redis_store_handler = ngx_cache_purge_indexer_handler;
    }
    
#endif

    return NGX_CONF_OK;
}

redisAsyncContext * redis_nginx_open(redisAsyncContext **context)
{
    ngx_cache_purge_main_conf_t *conf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_cache_purge_module);

    if (context == NULL || conf == NULL)
        return NULL;
    
    if (conf->redis_host.data) {
        //syslog(LOG_INFO, "Host is %s , port is %d, database is %d", (char *)conf->redis_host.data, (int)conf->redis_port, (int)conf->redis_database);
        return redis_nginx_open_context((char *)conf->redis_host.data, conf->redis_port, conf->redis_database, (char *)conf->redis_password.data, context);
    }
    else if (conf->redis_socket_path.data) {
        //syslog(LOG_INFO, "Unix socket is %s, database is %d", (char *)conf->redis_socket_path.data, (int)conf->redis_database);
        return redis_nginx_open_context_unix((char *)conf->redis_socket_path.data, conf->redis_database, (char *)conf->redis_password.data, context);
    }
    else
        return NULL;
}

void
ngx_selective_cache_purge_register_cache_entry(ngx_http_request_t *r, ngx_str_t *cache_key)
{
#if NGX_HTTP_CACHE

    ngx_int_t inactive = 600;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "ngx_selective_cache_purge_register_cache_entry() is called");

    if (r->cache == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Cache is NULL");
        return;
    }

    if (r->cache->file_cache) {
        inactive = r->cache->file_cache->inactive;
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "inactive is %d", inactive);
    
    ngx_str_t *filename = ngx_cache_purge_alloc_str(r->pool, r->cache->file.name.len);
    
    if (filename == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate file name string");
        return;
    }
    ngx_memcpy(filename->data, r->cache->file.name.data, filename->len);
    
    redisAsyncContext *c = redis_nginx_open(&db_ctxs[ngx_process_slot]);
    if (c == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to open redis Server");
        return;
    }

    redisAsyncCommand(c, NULL, NULL, SET_DATABASE_COMMAND, cache_key->data, cache_key->len, inactive, filename->data, filename->len);
    
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "Cache_key is %s , File name is %s, ", (char *)cache_key->data, (char *)filename->data);
    
#endif
}


ngx_int_t
ngx_cache_purge_indexer_handler(ngx_http_request_t *r)
{
    ngx_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cache_purge_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "ngx_cache_purge_indexer_handler() is called");

    if (ctx == NULL) {
        ngx_str_t *cache_key = ngx_cache_purge_get_cache_key(r);

        if (cache_key != NULL) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 1, "Cache_key is %s", (char *)cache_key->data);
            ngx_selective_cache_purge_register_cache_entry(r, cache_key);
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_cache_purge_postconfig(ngx_conf_t *cf)
{
    ngx_cache_purge_main_conf_t *conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_cache_purge_module);

    if (!conf->enabled) {
        return NGX_OK;
    }
    
    db_ctxs[ngx_process_slot] = NULL;
    
    return NGX_OK;
}

ngx_str_t *
ngx_cache_purge_get_cache_key(ngx_http_request_t *r)
{
    ngx_str_t         *cache_key = NULL;

#if NGX_HTTP_CACHE
    ngx_uint_t         i;
    size_t             len = 0;
    u_char            *p = NULL;
    ngx_str_t         *key = NULL;
    
    if (r->cache && r->cache->node != NULL && r->cache->file.name.len > 0
        && r->cache->keys.nelts > 0) {

        key = r->cache->keys.elts;
        for (i = 0; i < r->cache->keys.nelts; i++) {
            len += key[i].len;
        }

        if ((cache_key = ngx_cache_purge_alloc_str(r->pool, len)) == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_cache_purge: could not alloc memory to write the cache_key");
            return NULL;
        }

        key = r->cache->keys.elts;
        p = cache_key->data;
        for (i = 0; i < r->cache->keys.nelts; i++) {
            p = ngx_copy(p, key[i].data, key[i].len);
        }
    }
#endif

    return cache_key;
}
