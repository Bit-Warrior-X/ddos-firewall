#include <ngx_http_slice_module.h>

static ngx_command_t  ngx_http_slice_commands[] = {
      ngx_null_command
};

static ngx_http_module_t  ngx_http_slice_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* init main configuration */
    NULL,                                  /* create main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_slice_module = {
    NGX_MODULE_V1,
    &ngx_http_slice_module_ctx,            /* module context */
    ngx_http_slice_commands,               /* module directives */
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

extern ngx_module_t  ngx_http_slice_filter_module;

ngx_int_t 
ngx_http_set_slice(ngx_http_request_t *r, size_t slice_size)
{
    ngx_http_slice_loc_conf_t       *slcf;
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);
    if (slcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_slice_error: Please set slice directive first\n");
        return NGX_ERROR;
    }
    
    if (slcf->slice == NGX_CONF_UNSET || slcf->slice == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_slice_error: Slice directive is unset or it's set to off\n");
        return NGX_ERROR;
    }

    if (slcf->size == NULL || slcf->size == NGX_CONF_UNSET_PTR) {
        ngx_slab_pool_t *shpool;
        shpool = (ngx_slab_pool_t *)slcf->shm_zone_slice_size->shm.addr;
        slcf->size = ngx_slab_alloc(shpool, sizeof (size_t));
        
        // Check if memory allocation was successful
        if (slcf->size == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_slice_error: Memory allocation failed\n");
            return NGX_ERROR;
        }
    }
    
    *slcf->size = slice_size;

    return NGX_OK;
}

