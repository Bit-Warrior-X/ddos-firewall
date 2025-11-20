
#ifndef NGX_HTTP_ACL_MODULE_CORE_H
#define NGX_HTTP_ACL_MODULE_CORE_H

#include <ngx_http_acl_module_type.h>

ngx_int_t ngx_http_acl_init_process(ngx_cycle_t *cycle);

void ngx_http_acl_exit_process(ngx_cycle_t *cycle);

ngx_int_t ngx_http_acl_handler_precontent_phase(ngx_http_request_t* r);

ngx_int_t ngx_http_acl_handle_str_acl_rule(ngx_http_request_t *r, char *str_acl_rule);

ngx_int_t ngx_http_acl_handle_acl_rule(ngx_http_request_t *r, int acl_rule_id, int action, int priority, char * str_rule);

ngx_int_t ngx_http_acl_remove_acl_rule(ngx_http_request_t* r, int acl_id);

ngx_int_t ngx_http_acl_process_acl_id(ngx_http_request_t* r, int acl_id);

void ngx_http_acl_handler_cleanup(void *data);

ngx_int_t ngx_http_acl_check_server_acl_rule(ngx_http_request_t* r, server_acl_rule_t * server_acl_rule_p);


#endif

