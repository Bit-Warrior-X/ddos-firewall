#ifndef __NGX_HTTP_ACL_MODULE_CAPTCHA_H__
#define __NGX_HTTP_ACL_MODULE_CAPTCHA_H__

#include <ngx_http_acl_module_type.h>
#include <ngx_http_acl_module_util.h>
#include <ngx_http_acl_module_action.h>
#include <cjson/cJSON.h>


ngx_int_t ngx_http_acl_handler_captcha(ngx_http_request_t* r);
ngx_int_t _verify_cookies(ngx_http_request_t* r);

#endif