#ifndef NGX_CACHE_PURGE_MODULE_H
#define NGX_CACHE_PURGE_MODULE_H

#define AUTH_COMMAND "AUTH %s"
#define SELECT_DATABASE_COMMAND "SELECT %d"
#define PING_DATABASE_COMMAND "PING"
#define SET_DATABASE_COMMAND "SETEX %b %d %b"
#define SCAN_BY_CACHE_DATABASE_COMMAND "SCAN %s MATCH %b COUNT 100"
#define GET_VALUE_BY_DATABASE_COMMAND "GET %s"
#define DEL_KEY_BY_DATABASE_COMMAND "DEL %b"


typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_http_proxy_vars_t;

#  if (nginx_version >= 1007009)

typedef struct {
    ngx_array_t                    caches;  /* ngx_http_file_cache_t * */
} ngx_http_proxy_main_conf_t;

#  endif /* nginx_version >= 1007009 */

#  if (nginx_version >= 1007008)

typedef struct {
    ngx_array_t                   *flushes;
    ngx_array_t                   *lengths;
    ngx_array_t                   *values;
    ngx_hash_t                     hash;
} ngx_http_proxy_headers_t;

#  endif /* nginx_version >= 1007008 */

typedef struct {
    ngx_http_upstream_conf_t       upstream;

#  if (nginx_version >= 1007008)
    ngx_array_t                   *body_flushes;
    ngx_array_t                   *body_lengths;
    ngx_array_t                   *body_values;
    ngx_str_t                      body_source;

    ngx_http_proxy_headers_t       headers;
    ngx_http_proxy_headers_t       headers_cache;
#  else
    ngx_array_t                   *flushes;
    ngx_array_t                   *body_set_len;
    ngx_array_t                   *body_set;
    ngx_array_t                   *headers_set_len;
    ngx_array_t                   *headers_set;
    ngx_hash_t                     headers_set_hash;
#  endif /* nginx_version >= 1007008 */

    ngx_array_t                   *headers_source;
#  if (nginx_version < 8040)
    ngx_array_t                   *headers_names;
#  endif /* nginx_version < 8040 */

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;
#  if (nginx_version >= 1001015)
    ngx_array_t                   *cookie_domains;
    ngx_array_t                   *cookie_paths;
#  endif /* nginx_version >= 1001015 */
#  if (nginx_version >= 1019003)
    ngx_array_t                   *cookie_flags;
#  endif /* nginx_version >= 1019003 */
#  if (nginx_version < 1007008)
    ngx_str_t                      body_source;
#  endif /* nginx_version < 1007008 */

#  if (nginx_version >= 1011006)
    ngx_http_complex_value_t      *method;
#  else
    ngx_str_t                      method;
#  endif /* nginx_version >= 1011006 */
    ngx_str_t                      location;
    ngx_str_t                      url;

    ngx_http_complex_value_t       cache_key;

    ngx_http_proxy_vars_t          vars;

    ngx_flag_t                     redirect;

#  if (nginx_version >= 1001004)
    ngx_uint_t                     http_version;
#  endif /* nginx_version >= 1001004 */

    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;

#  if (NGX_HTTP_SSL)
#    if (nginx_version >= 1005006)
    ngx_uint_t                     ssl;
    ngx_uint_t                     ssl_protocols;
    ngx_str_t                      ssl_ciphers;
#    endif /* nginx_version >= 1005006 */
#    if (nginx_version >= 1007000)
    ngx_uint_t                     ssl_verify_depth;
    ngx_str_t                      ssl_trusted_certificate;
    ngx_str_t                      ssl_crl;
#    endif /* nginx_version >= 1007000 */
#    if ((nginx_version >= 1007008) && (nginx_version < 1021000))
    ngx_str_t                      ssl_certificate;
    ngx_str_t                      ssl_certificate_key;
    ngx_array_t                   *ssl_passwords;
#    endif /* nginx_version >= 1007008 && nginx_version < 1021000 */
#    if (nginx_version >= 1019004)
    ngx_array_t                   *ssl_conf_commands;
#    endif /*nginx_version >= 1019004 */
#  endif
} ngx_http_proxy_loc_conf_t;

typedef struct {
    clock_t start_scan_purge;
    int success;
    int failed;
} ngx_purge_request_ctx_t;

typedef struct http_req_cahce_value_s {
    ngx_http_request_t *r;
    ngx_str_t *cache_key;
} http_req_cahce_value_t;

typedef struct {
    ngx_flag_t                    enable;
    ngx_http_complex_value_t     *purge_query;
} ngx_http_cache_purge_loc_conf_t;

typedef struct {
    ngx_flag_t                enabled;
    ngx_str_t                 redis_socket_path;
    ngx_str_t                 redis_host;
    ngx_uint_t                redis_port;
    ngx_uint_t                redis_database;
    ngx_str_t                 redis_password;
    ngx_http_handler_pt       redis_store_handler;
} ngx_cache_purge_main_conf_t;

char                *ngx_http_proxy_cache_purge_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
void                *ngx_http_cache_purge_create_loc_conf(ngx_conf_t *cf);
static void         *ngx_cache_purge_create_main_conf(ngx_conf_t *cf);
static char         *ngx_cache_purge_init_main_conf(ngx_conf_t *cf, void *parent);
static ngx_str_t    *ngx_cache_purge_get_cache_key(ngx_http_request_t *r);
void                 ngx_selective_cache_purge_register_cache_entry(ngx_http_request_t *r, ngx_str_t *cache_key);
ngx_str_t           *ngx_cache_purge_alloc_str(ngx_pool_t *pool, uint len);
static char         *ngx_cache_purge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t     ngx_cache_purge_postconfig(ngx_conf_t *cf);
ngx_int_t            ngx_selective_cache_purge_send_response(ngx_http_request_t *r, u_char *data, size_t len, ngx_uint_t status, ngx_str_t *content_type);
int                  redis_nginx_purge_cache_by_scan(ngx_http_request_t *r);
redisAsyncContext   *redis_nginx_open(redisAsyncContext **context);
ngx_int_t            ngx_cache_purge_indexer_handler(ngx_http_request_t *r);


#endif
