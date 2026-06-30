#ifndef NGX_HTTP_SLICE_MODULE_H
#define NGX_HTTP_SLICE_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_int_t            slice;
    size_t              *size;
    ngx_shm_zone_t      *shm_zone_slice_size;
} ngx_http_slice_loc_conf_t;

ngx_int_t ngx_http_set_slice(ngx_http_request_t *r, size_t slice_size);

#endif /* NGX_HTTP_SLICE_MODULE_H */