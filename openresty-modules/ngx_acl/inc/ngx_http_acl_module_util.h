#ifndef NGX_HTTP_ACL_MODULE_UTIL_H
#define NGX_HTTP_ACL_MODULE_UTIL_H

#include <ngx_http_acl_module_type.h>
#include <utarray.h>
#include <sodium.h>
#include <curl/curl.h>

char* ngx_http_acl_to_c_str(u_char* destination, ngx_str_t ngx_str);

char *ngx_http_acl_clone_c_str(ngx_http_request_t* r, char * src);

ngx_int_t convert_ip_to_c_str(inx_addr_t addr, char *str, int mode);

ngx_int_t compare_ip_in_ip_list(ngx_http_request_t* r, char * ip_addr, char *ip_addr_list);

ngx_int_t compare_cookie_in_cookie_list(ngx_http_request_t* r, char * str_cookie, char *str_cookie_list);

ngx_int_t compare_header_value_in_list(ngx_http_request_t* r, char * str_value, char *str_value_list);

ngx_int_t compare_case_insensitive(ngx_http_request_t* r, char * str1, char *str2);

ngx_int_t check_contains_in_str(ngx_http_request_t* r, char *small_str, char * big_str, int case_sensitive);

ngx_int_t check_http_request_method_in_str(ngx_http_request_t* r, char * str_value);

ngx_int_t ngx_http_acl_str_split(ngx_pool_t * pool, ngx_str_t* str, u_char sep, size_t max_len, UT_array** array);

ngx_int_t parse_request_frequency_value(char * str, request_freq_t * req_freq_p);

ngx_int_t parse_response_code(char * str, int * code);

ngx_int_t ngx_http_acl_get_max_request_freq_time(server_acl_rule_t * server_acl_rule_p);

ngx_int_t ngx_http_acl_get_max_response_freq_time(server_acl_rule_t * server_acl_rule_p);

ngx_int_t ngx_http_acl_get_response_codes(server_acl_rule_t * server_acl_rule_p);

ngx_int_t remove_acl_rule_list(server_acl_rule_t * server_acl_rule_p, acl_rule_list_t * acl_rule_list_p, ngx_log_t * log);

void remove_space_in_str(char * str);

ngx_int_t make_intermediate_list(char * str, acl_rule_t * acl_rule, ngx_log_t * log);

ngx_int_t add_acl_rule(server_acl_rule_t * server_acl_rule_p, ngx_log_t * log, int acl_rule_id, int action, int priority, char * str_rule_body);

ngx_int_t parse_acl_rule(ngx_http_request_t* r, char * str_acl_rule, server_acl_rule_t * server_acl_rule_p);

void dump_acl_rule(acl_rule_t * acl_rule_p, ngx_log_t * log);

void ngx_http_acl_utarray_ngx_str_ctor(void *dst, const void *src);

void ngx_http_acl_utarray_ngx_str_dtor(void* elt);

ngx_int_t ngx_http_acl_rand_str(u_char* dest, size_t len);

void ngx_http_acl_register_content_handler(ngx_http_request_t* r);

ngx_int_t ngx_http_acl_http_post(ngx_http_request_t* r, const char* url, char* in, char** out);

ngx_int_t ngx_http_acl_gen_no_cache_header(ngx_http_request_t* r);

void ngx_http_acl_get_ctx_and_conf(ngx_http_request_t* r, ngx_http_acl_main_conf_t** conf, ngx_http_acl_ctx_t** ctx);

void ngx_http_acl_make_inx_addr(ngx_http_request_t* r, inx_addr_t* inx_addr);

ngx_int_t ngx_http_acl_sha256(ngx_pool_t * pool, u_char* dst, size_t dst_len, const void* buf, size_t buf_len);

ngx_int_t ngx_http_acl_parse_time(u_char* str);

time_node_t * ngx_http_alloc_time_node (ngx_http_request_t * r, mem_pool_t * pool);

#define ngx_http_acl_make_utarray_ngx_str_icd() { sizeof(ngx_str_t), NULL, ngx_http_acl_utarray_ngx_str_ctor, ngx_http_acl_utarray_ngx_str_dtor }

#endif

