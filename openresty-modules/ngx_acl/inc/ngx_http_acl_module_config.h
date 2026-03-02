#ifndef NGX_HTTP_ACL_MODULE_CONFIG_H
#define NGX_HTTP_ACL_MODULE_CONFIG_H

#include <ngx_http_acl_module_type.h>
#include <ngx_http_acl_module_lexer.h>

ngx_int_t ngx_http_acl_handler_log_phase(ngx_http_request_t* r);

char* ngx_http_acl_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

char* ngx_http_acl_geo_database_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

char* ngx_http_acl_shm_size(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

char* ngx_http_acl_req_shm_size(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

char* ngx_http_acl_rsp_shm_size(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

char* ngx_http_acl_captcha_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

ngx_int_t ngx_http_acl_postconfig(ngx_conf_t* cf);

void* ngx_http_acl_create_main_conf(ngx_conf_t* cf);

void* ngx_http_acl_create_loc_conf(ngx_conf_t* cf);

char* ngx_http_acl_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

ngx_int_t ngx_http_acl_shm_zone_cc_req_deny_init(ngx_shm_zone_t *zone, void *data);

ngx_int_t ngx_http_acl_shm_zone_cc_rsp_deny_init(ngx_shm_zone_t *zone, void *data);

ngx_int_t ngx_http_acl_shm_zone_server_acl_init(ngx_shm_zone_t *zone, void *data);

ngx_int_t ngx_http_acl_shm_zone_optimize_req_init(ngx_shm_zone_t *zone, void *data);

ngx_int_t ngx_http_acl_shm_zone_optimize_rsp_init(ngx_shm_zone_t *zone, void *data);

#endif
