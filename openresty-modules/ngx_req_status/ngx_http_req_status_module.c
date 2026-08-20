/*
 * Copyright (C) Sogou, Inc
 */

 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_http.h>
 
 #include <syslog.h>
 #include <sys/time.h>
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 #include <unistd.h>
 #include <pthread.h>
 #include <sys/types.h>
 #include <sys/ipc.h>
 #include <sys/shm.h>
 #include <signal.h>
 
 
 #define SHM_SIZE 1024
 #define MEASURE_INTERVAL 10
 #define MAX_TOKENS 10
 #define MAX_TOKEN_LENGTH 100
 
 static ngx_int_t ngx_http_req_status_init_zone(ngx_shm_zone_t *shm_zone,
         void *data);
 static void ngx_http_req_status_rbtree_insert_value(ngx_rbtree_node_t *temp,
         ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
 static ngx_int_t ngx_http_req_status_init(ngx_conf_t *cf);
 static ngx_int_t ngx_http_req_status_handler(ngx_http_request_t *r);
 static void *ngx_http_req_status_lookup(void *conf, ngx_uint_t hash,
         ngx_str_t *key);
 static void ngx_http_req_status_expire(void *conf);
 
 static void *ngx_http_req_status_create_main_conf(ngx_conf_t *cf);
 static char *ngx_http_req_status_init_main_conf(ngx_conf_t *cf, void *conf);
 static void *ngx_http_req_status_create_loc_conf(ngx_conf_t *cf);
 static char *ngx_http_req_status_merge_loc_conf(ngx_conf_t *cf, void *parent,
         void *child);
 
 static char *ngx_http_req_status_zone(ngx_conf_t *cf, ngx_command_t *cmd,
         void *conf);
 static char *ngx_http_req_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
 static char *ngx_http_req_status_show(ngx_conf_t *cf, ngx_command_t *cmd,
         void *conf);
 
 static ngx_int_t ngx_http_req_status_show_json_handler(ngx_http_request_t *r);
 
 static ngx_int_t ngx_http_req_status_write_filter(ngx_http_request_t *r,
         off_t bsent);
 
 static ngx_int_t get_pid_shared_memory();
 static ngx_int_t save_pid_shared_memory();
 
 static ngx_int_t ngx_http_req_status_init_worker(ngx_cycle_t *cycle);
 
 typedef struct ngx_http_req_status_loc_conf_s ngx_http_req_status_loc_conf_t;
 
 typedef struct {
     ngx_uint_t                      requests;
     ngx_uint_t                      traffic;
     ngx_uint_t                      last_traffic;
     
     ngx_uint_t                      bandwidth;
     ngx_uint_t                      max_bandwidth;
     time_t                          last_bandwidth_update;
 
     ngx_uint_t                      max_active;
 } ngx_http_req_status_data_t;
 
 typedef struct {
     ngx_rbtree_node_t               node;
     ngx_queue_t                     queue;
 
     ngx_uint_t                      count; // ref count
 
     ngx_http_req_status_data_t      data;
 
     ngx_uint_t                      active;
     ngx_uint_t                      last_traffic;
     ngx_msec_t                      last_traffic_start;
     ngx_msec_t                      last_traffic_update;
 
     ngx_uint_t                      len;
     u_char                          key[0];
 } ngx_http_req_status_node_t;
 
 typedef struct {
     ngx_rbtree_t                    rbtree;
     ngx_rbtree_node_t               sentinel;
     ngx_queue_t                     queue;
     time_t                          expire_lock;
 } ngx_http_req_status_sh_t;
 
 typedef struct {
     ngx_str_t                       *zone_name;
     ngx_http_req_status_node_t      *node;
     ngx_http_req_status_data_t      *pdata;
     ngx_http_req_status_data_t      data[0];
 } ngx_http_req_status_print_item_t;
 
 typedef struct {
     ngx_http_req_status_sh_t        *sh;
     ngx_slab_pool_t                 *shpool;
     ngx_shm_zone_t                  *shm_zone;
     ngx_http_complex_value_t        key;
 } ngx_http_req_status_zone_t;
 
 typedef struct {
     ngx_http_req_status_zone_t      *zone;
     ngx_http_req_status_node_t      *node;
 } ngx_http_req_status_zone_node_t;
 
 typedef struct {
     ngx_array_t                     req_zones;
 } ngx_http_req_status_ctx_t;
 
 typedef struct {
     ngx_array_t                     zones;
     ngx_uint_t                      req_status_enable;
     ngx_msec_t                      interval;
     time_t                          lock_time;
 } ngx_http_req_status_main_conf_t;
 
 struct ngx_http_req_status_loc_conf_s {
     ngx_array_t                     req_zones;
     ngx_http_req_status_loc_conf_t *parent;
 };
 
 
 static ngx_http_module_t ngx_http_req_status_module_ctx = {
     NULL,                                 /* preconfiguration */
     ngx_http_req_status_init,             /* postconfiguration */
 
     ngx_http_req_status_create_main_conf, /* create main configuration */
     ngx_http_req_status_init_main_conf,   /* init main configuration */
 
     NULL,                                 /* create server configuration */
     NULL,                                 /* merge server configuration */
 
     ngx_http_req_status_create_loc_conf,  /* create location configration */
     ngx_http_req_status_merge_loc_conf    /* merge location configration */
 };
 
 
 static ngx_command_t ngx_http_req_status_commands[] = {
     { ngx_string("req_status_interval"),
       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_msec_slot,
       0,
       offsetof(ngx_http_req_status_main_conf_t, interval),
       NULL },
 
     { ngx_string("req_status_lock_time"),
       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_sec_slot,
       0,
       offsetof(ngx_http_req_status_main_conf_t, lock_time),
       NULL },
       
     { ngx_string("req_status_enable"),
       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_flag_slot,
       0,
       offsetof(ngx_http_req_status_main_conf_t, req_status_enable),
       NULL },
       
     { ngx_string("req_status_zone"),
       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
       ngx_http_req_status_zone,
       0,
       0,
       NULL
     },
 
     { ngx_string("req_status"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
       ngx_http_req_status,
       NGX_HTTP_LOC_CONF_OFFSET,
       0,
       NULL
     },
 
     { ngx_string("req_status_show"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
       ngx_http_req_status_show,
       0,
       0,
       NULL
     },
 
     ngx_null_command
 };
 
 
 ngx_module_t ngx_http_req_status_module = {
     NGX_MODULE_V1,
     &ngx_http_req_status_module_ctx,
     ngx_http_req_status_commands,
     NGX_HTTP_MODULE,                          /* module type */
     NULL,                                     /* init master */
     NULL,                                     /* init module */
     ngx_http_req_status_init_worker,          /* init process */
     NULL,                                     /* init thread */
     NULL,                                     /* exit thread */
     NULL,                                     /* exit process */
     NULL,                                     /* exit master */
     NGX_MODULE_V1_PADDING
 };
 
 static ngx_int_t
 ngx_http_req_status_write_filter(ngx_http_request_t *r, off_t bsent)
 {
     off_t                                   bytes;
     ngx_uint_t                              i;
     //ngx_msec_t                              td;
     ngx_http_req_status_ctx_t              *r_ctx;
     ngx_http_req_status_data_t             *data;
     ngx_http_req_status_zone_node_t        *pzn;
     //ngx_http_req_status_main_conf_t        *rmcf;
 
     r_ctx = ngx_http_get_module_ctx(r, ngx_http_req_status_module);
     if (r_ctx == NULL || r_ctx->req_zones.nelts == 0){
         return NGX_DECLINED;
     }
 
     //rmcf = ngx_http_get_module_main_conf(r, ngx_http_req_status_module);
 
     pzn = r_ctx->req_zones.elts;
 
     bytes = r->connection->sent - bsent;
 
     for (i = 0; i < r_ctx->req_zones.nelts; i++){
         data = &pzn[i].node->data;
 
         ngx_shmtx_lock(&pzn[i].zone->shpool->mutex);
 
         data->traffic += bytes;
         data->last_traffic += bytes;
 
         /*if (ngx_current_msec > pzn[i].node->last_traffic_start){
 
             td = ngx_current_msec - pzn[i].node->last_traffic_start;
 
             if (td >= rmcf->interval){
                 data->bandwidth = pzn[i].node->last_traffic * 1000 / td;
                 if (data->bandwidth > data->max_bandwidth){
                     data->max_bandwidth = data->bandwidth;
                 }
 
                 pzn[i].node->last_traffic = 0;
                 pzn[i].node->last_traffic_start = ngx_current_msec;
             }
         }*/
 
         pzn[i].node->last_traffic += bytes;
 
         /*if (ngx_current_msec > pzn[i].node->last_traffic_update){
             pzn[i].node->last_traffic_update = ngx_current_msec;
         }*/
 
         ngx_shmtx_unlock(&pzn[i].zone->shpool->mutex);
     }
 
     return NGX_DECLINED;
 }
 
 static void
 ngx_http_req_status_rbtree_insert_value(ngx_rbtree_node_t *temp,
         ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
 {
     ngx_rbtree_node_t               **p;
     ngx_http_req_status_node_t      *cn, *cnt;
 
     for ( ;; ) {
 
         if (node->key < temp->key) {
 
             p = &temp->left;
 
         } else if (node->key > temp->key) {
 
             p = &temp->right;
 
         } else { /* node->key == temp->key */
 
             cn = (ngx_http_req_status_node_t *) node;
             cnt = (ngx_http_req_status_node_t *) temp;
 
             p = (ngx_memn2cmp(cn->key, cnt->key, cn->len, cnt->len) < 0)
                 ? &temp->left : &temp->right;
         }
 
         if (*p == sentinel) {
             break;
         }
 
         temp = *p;
     }
 
     *p = node;
     node->parent = temp;
     node->left = sentinel;
     node->right = sentinel;
     ngx_rbt_red(node);
 }
 
 static void
 ngx_http_req_status_cleanup(void *data)
 {
     ngx_uint_t                          i;
     ngx_http_req_status_ctx_t          *r_ctx = data;
     ngx_http_req_status_zone_node_t    *pzn;
 
     if (r_ctx->req_zones.nelts == 0)
         return;
 
     pzn = r_ctx->req_zones.elts;
 
     for (i = 0; i < r_ctx->req_zones.nelts; i++){
         ngx_shmtx_lock(&pzn[i].zone->shpool->mutex);
 
         pzn[i].node->count --;
         pzn[i].node->active --;
 
         ngx_shmtx_unlock(&pzn[i].zone->shpool->mutex);
     }
 }
 
 static ngx_int_t
 ngx_http_req_status_handler(ngx_http_request_t *r)
 {
     size_t                              len;
     uint32_t                            hash;
     ngx_str_t                           key;
     ngx_uint_t                          i;
     ngx_shm_zone_t                    **pzone;
     ngx_pool_cleanup_t                 *cln;
     ngx_http_req_status_ctx_t          *r_ctx;
     ngx_http_req_status_zone_t         *ctx;
     ngx_http_req_status_node_t         *ssn;
     ngx_http_req_status_loc_conf_t     *rlcf;
     ngx_http_req_status_zone_node_t    *pzn;
 
     r_ctx = ngx_http_get_module_ctx(r, ngx_http_req_status_module);
     
     rlcf = ngx_http_get_module_loc_conf(r, ngx_http_req_status_module);
 
     do {
         pzone = rlcf->req_zones.elts;
 
         for (i = 0; i < rlcf->req_zones.nelts; i++) {
             ctx = pzone[i]->data;
 
             if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
                 continue;
             }
 
             if (key.len == 0) {
                 continue;
             }
 
             if (key.len > 65535) {
                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                         "req-status, the value of the \"%V\" variable "
                         "is more than 65535 bytes: \"%v\"",
                         &ctx->key.value, &key);
                 continue;
             }
 
             if (r_ctx == NULL) {
                 
                 r_ctx = ngx_palloc(r->pool, sizeof(ngx_http_req_status_ctx_t));
                 if (r_ctx == NULL) {
                     return NGX_HTTP_INTERNAL_SERVER_ERROR;
                 }
 
                 if (ngx_array_init(&r_ctx->req_zones, r->pool, 2,
                             sizeof(ngx_http_req_status_zone_node_t))
                         != NGX_OK)
                 {
                     return NGX_HTTP_INTERNAL_SERVER_ERROR;
                 }
 
                 cln = ngx_pool_cleanup_add(r->pool, 0);
                 if (cln == NULL) {
                     return NGX_HTTP_INTERNAL_SERVER_ERROR;
                 }
 
                 cln->handler = ngx_http_req_status_cleanup;
                 cln->data = r_ctx;
 
                 ngx_http_set_ctx(r, r_ctx, ngx_http_req_status_module);
             }
 
             hash = ngx_crc32_short(key.data, key.len);
 
             ngx_shmtx_lock(&ctx->shpool->mutex);
 
             ssn = ngx_http_req_status_lookup(ctx, hash, &key);
 
             if (ssn == NULL) {
                 len  = sizeof(ngx_http_req_status_node_t) + key.len + 1;
 
                 ssn = ngx_slab_alloc_locked(ctx->shpool, len);
                 if (ssn == NULL) {
                     ngx_http_req_status_expire(ctx);
 
                     ssn = ngx_slab_alloc_locked(ctx->shpool, len);
                     if (ssn == NULL) {
                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                 "req-status, slab alloc fail, zone = \"%V\", "
                                 "key = \"%V\", size = %uz",
                                 &ctx->shm_zone->shm.name, &key, len);
 
                         ngx_shmtx_unlock(&ctx->shpool->mutex);
 
                         continue;
                     }
                 }
 
                 ssn->node.key = hash;
                 ssn->len = key.len;
                 ssn->count = 1;
 
                 ngx_memzero(&ssn->data, sizeof(ssn->data));
                 ngx_memcpy(ssn->key, key.data, key.len);
                 ssn->key[key.len] = '\0';
                 ssn->last_traffic_update = 0;
 
                 ngx_rbtree_insert(&ctx->sh->rbtree, &ssn->node);
             }
 
             ssn->data.requests ++;
             ssn->active ++;
             if (ssn->active > ssn->data.max_active) {
                 ssn->data.max_active = ssn->active;
             }
 
             ngx_queue_insert_head(&ctx->sh->queue, &ssn->queue);
 
             ngx_shmtx_unlock(&ctx->shpool->mutex);
 
             pzn = ngx_array_push(&r_ctx->req_zones);
             if (pzn == NULL) {
                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
             }
 
             pzn->node = ssn;
             pzn->zone = ctx;
         }
 
         rlcf = rlcf->parent;
     } while (rlcf);
 
     return NGX_DECLINED;
 }
 
 static void *
 ngx_http_req_status_lookup(void *conf, ngx_uint_t hash, ngx_str_t *key)
 {
     ngx_int_t                       rc;
     ngx_rbtree_node_t              *node, *sentinel;
     ngx_http_req_status_node_t     *ssn;
     ngx_http_req_status_zone_t     *ctx = conf;
 
     node = ctx->sh->rbtree.root;
     sentinel = ctx->sh->rbtree.sentinel;
 
     while (node != sentinel) {
         if (hash < node->key) {
             node = node->left;
             continue;
         }
 
         if (hash > node->key) {
             node = node->right;
             continue;
         }
 
         /* hash == node->key */
         ssn = (ngx_http_req_status_node_t *)node;
 
         rc = ngx_memn2cmp(key->data, ssn->key, key->len, ssn->len);
         if (rc == 0){
             ngx_queue_remove(&ssn->queue);
 
             ssn->count ++;
 
             return ssn;
         }
 
         node = (rc < 0) ? node->left : node->right;
     }
 
     return NULL;
 }
 
 static void
 ngx_http_req_status_expire(void *conf)
 {
     ngx_queue_t                     *q;
     ngx_http_req_status_zone_t      *ctx = conf;
     ngx_http_req_status_node_t      *ssn;
 
     if (ngx_queue_empty(&ctx->sh->queue)) {
         return;
     }
 
     if (ctx->sh->expire_lock > ngx_time()){
         return;
     }
 
     q =  ngx_queue_last(&ctx->sh->queue);
 
     ssn = ngx_queue_data(q, ngx_http_req_status_node_t, queue);
 
     if (!ssn->data.requests /*|| (ngx_current_msec > ssn->last_traffic_update &&
                 ngx_current_msec - ssn->last_traffic_update >= 10 * 1000)*/){
         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                 "req-status, release node, zone = \"%V\", key = \"%s\"",
                 &ctx->shm_zone->shm.name, ssn->key);
 
         ngx_queue_remove(q);
 
         ngx_rbtree_delete(&ctx->sh->rbtree, &ssn->node);
 
         ngx_slab_free_locked(ctx->shpool, ssn);
     }
 }
 
 #if 0
 static u_char *
 ngx_http_req_status_format_size(u_char *buf, ngx_uint_t v)
 {
     u_char              scale;
     ngx_uint_t          size;
 
     if (v > 1024 * 1024 * 1024 - 1) {
         size = v / (1024 * 1024 * 1024);
         if ((v % (1024 * 1024 * 1024)) > (1024 * 1024 * 1024 / 2 - 1)) {
             size++;
         }
         scale = 'G';
     } else if (v > 1024 * 1024 - 1) {
         size = v / (1024 * 1024);
         if ((v % (1024 * 1024)) > (1024 * 1024 / 2 - 1)) {
             size++;
         }
         scale = 'M';
     } else if (v > 9999) {
         size = v / 1024;
         if (v % 1024 > 511) {
             size++;
         }
         scale = 'K';
     } else {
         size = v;
         scale = '\0';
     }
 
     if (scale) {
         return ngx_sprintf(buf, "%ui%c", size, scale);
     }
 
     return ngx_sprintf(buf, "%ui", size);
 }
 #endif
 
 static int ngx_libc_cdecl
 ngx_http_req_status_cmp_items(const void *one, const void *two)
 {
     ngx_http_req_status_print_item_t *first = (ngx_http_req_status_print_item_t*) one;
     ngx_http_req_status_print_item_t *second = (ngx_http_req_status_print_item_t*) two;
 
     return (int)(first->zone_name == second->zone_name) ? 
         ngx_strcmp(first->node->key, second->node->key) :
         ngx_strncmp(first->zone_name->data, second->zone_name->data, first->zone_name->len);
 }
 
 static ngx_int_t
 ngx_arg_split(char* str, char** tokens, const char* delimiter) 
 {
     ngx_int_t count = 0;
     char* token = strtok(str, delimiter);
 
     while (token != NULL && count < MAX_TOKENS) {
         tokens[count++] = token;
         token = strtok(NULL, delimiter);
     }
 
     return count;
 }
 
 #define FILTER_TIMESTAMP            0b000000001
 #define FILTER_DOMAIN               0b000000010
 #define FILTER_ZONENAME             0b000000100
 #define FILTER_BANDWIDTH            0b000001000
 #define FILTER_MAXBANDWIDTH         0b000010000
 #define FILTER_TRAFFIC              0b000100000
 #define FILTER_REQUESTS             0b001000000
 #define FILTER_MAX_ACTIVE           0b010000000
 #define FILTER_ACTIVE               0b100000000
 
 static ngx_int_t
 ngx_http_req_status_show_json_handler(ngx_http_request_t *r)
 {
     size_t                              size, item_size;
     ngx_int_t                           rc;
     ngx_buf_t                          *b;
     ngx_uint_t                          i, j;
     ngx_array_t                         items;
     ngx_queue_t                        *q;
     ngx_chain_t                         out;
     ngx_http_req_status_zone_t        **pzone;
     ngx_http_req_status_node_t         *rsn;
     ngx_http_req_status_main_conf_t    *rmcf;
     ngx_http_req_status_print_item_t   *item;
     ngx_int_t                           timestamp_written = 0;
     char*                               tokens[MAX_TOKENS];
 
     ngx_int_t                           filter = 0;
 
     ngx_int_t                           filter_timestamp = 0;
     char                                filter_domain[64];
     char                                filter_zone_name[32];
     ngx_int_t                           filter_bandwidth = 0;
     ngx_int_t                           filter_max_bw = 0;
     ngx_int_t                           filter_traffic = 0;
     ngx_int_t                           filter_requests = 0;
     ngx_int_t                           filter_max_active = 0;
     ngx_int_t                           filter_active = 0;
     
 
     if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
         return NGX_HTTP_NOT_ALLOWED;
     }
 
     rc = ngx_http_discard_request_body(r);
 
     if (rc != NGX_OK) {
         return rc;
     }
 
     ngx_str_set(&r->headers_out.content_type, "text/plain");
 
     if (r->method == NGX_HTTP_HEAD) {
         r->headers_out.status = NGX_HTTP_OK;
 
         rc = ngx_http_send_header(r);
 
         if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
             return rc;
         }
     }
 
     item_size = sizeof(ngx_http_req_status_print_item_t);
 
     if (ngx_array_init(&items, r->pool, 40, item_size) != NGX_OK){
         return NGX_HTTP_INTERNAL_SERVER_ERROR;
     }
     
     if (r->args.len)
     {
         ngx_int_t tokenCount;
         tokenCount = ngx_arg_split((char *)r->args.data, tokens, "& ");
         for (i = 0; i < (ngx_uint_t)tokenCount; i++) {
             char name[32], value[32];
             name[0] = '\0', value[0] = '\0';
             for (j = 0 ; j < (ngx_uint_t)strlen(tokens[i]) ; j ++) {
                 if (tokens[i][j] == '=') {
                     strncat(name, tokens[i], j);
                     strcat(value, tokens[i] + j + 1);
                 }
             }
             
             if(strcmp(name, "timestamp") == 0) {
                 filter |= FILTER_TIMESTAMP;
                 filter_timestamp = atoi(value);
             }
             else if(strcmp(name, "domain") == 0) {
                 filter |= FILTER_DOMAIN;
                 strcpy(filter_domain, value);
             }
             else if(strcmp(name, "zone_name") == 0) {
                 filter |= FILTER_ZONENAME;
                 strcpy(filter_zone_name, value);
             }
             else if(strcmp(name, "bandwidth") == 0) {
                 filter |= FILTER_BANDWIDTH;
                 if (strcmp(value, "true") == 0)
                     filter_bandwidth = 1;
                 else
                     filter_bandwidth = 0;
             }
             else if(strcmp(name, "max_bw") == 0) {
                 filter |= FILTER_MAXBANDWIDTH;
                 if (strcmp(value, "true") == 0)
                     filter_max_bw = 1;
                 else
                     filter_max_bw = 0;
             }
             else if(strcmp(name, "traffic") == 0) {
                 filter |= FILTER_TRAFFIC;
                 if (strcmp(value, "true") == 0)
                     filter_traffic = 1;
                 else
                     filter_traffic = 0;
             }
             else if(strcmp(name, "requests") == 0) {
                 filter |= FILTER_REQUESTS;
                 if (strcmp(value, "true") == 0)
                     filter_requests = 1;
                 else
                     filter_requests = 0;
             }
             else if(strcmp(name, "max_active") == 0) {
                 filter |= FILTER_MAX_ACTIVE;
                 if (strcmp(value, "true") == 0)
                     filter_max_active = 1;
                 else
                     filter_max_active = 0;
             }
             else if(strcmp(name, "active") == 0) {
                 filter |= FILTER_ACTIVE;
                 if (strcmp(value, "true") == 0)
                     filter_active = 1;
                 else
                     filter_active = 0;
             }
         }
     }
     
     size = strlen("\"timestamp\": ") + (NGX_INT64_LEN) + 1024; // extra characters;
     
     rmcf = ngx_http_get_module_main_conf(r, ngx_http_req_status_module);
 
     pzone = rmcf->zones.elts;
     
     for (i = 0; i < rmcf->zones.nelts; i++){
         ngx_shmtx_lock(&pzone[i]->shpool->mutex);
 
         for (q = ngx_queue_last(&pzone[i]->sh->queue);
                 q != ngx_queue_sentinel(&pzone[i]->sh->queue);
                 q = ngx_queue_prev(q))
         {
             rsn = ngx_queue_data(q, ngx_http_req_status_node_t, queue);
             if (!rsn->data.requests){
                 continue;
             }
 
             if (filter & FILTER_TIMESTAMP) {
                 //syslog(LOG_INFO, "FILTER_TIMESTAMP, %d\n", filter_timestamp);
                 if (filter_timestamp != rsn->data.last_bandwidth_update)
                     continue;
             }
             if (filter & FILTER_DOMAIN) {
                 //syslog(LOG_INFO, "FILTER_DOMAIN, %d\n", filter_domain);
                 if (strncmp(filter_domain, (char *)rsn->key, rsn->len) != 0)
                     continue;
             }
             if (filter & FILTER_ZONENAME) {
                 //syslog(LOG_INFO, "FILTER_ZONENAME, %s\n", filter_zone_name);
                 if (strcmp(filter_zone_name, (char *)pzone[i]->shm_zone->shm.name.data) != 0)
                     continue;
             }
             if (filter & FILTER_BANDWIDTH) {
                 //syslog(LOG_INFO, "FILTER_BANDWIDTH, %d\n", filter_bandwidth);
                 if (filter_bandwidth == 1 && rsn->data.bandwidth == 0)
                     continue;
                 if (filter_bandwidth == 0 && rsn->data.bandwidth != 0)
                     continue;
             }
             if (filter & FILTER_MAXBANDWIDTH) {
                 if (filter_max_bw == 1 && rsn->data.max_bandwidth == 0)
                     continue;
                 if (filter_max_bw == 0 && rsn->data.max_bandwidth != 0)
                     continue;
             }
             if (filter & FILTER_TRAFFIC) {
                 if (filter_traffic == 1 && rsn->data.traffic == 0)
                     continue;
                 if (filter_traffic == 0 && rsn->data.traffic != 0)
                     continue;
             }
             if (filter & FILTER_REQUESTS) {
                 if (filter_requests == 1 && rsn->data.requests == 0)
                     continue;
                 if (filter_requests == 0 && rsn->data.requests != 0)
                     continue;
             }
             if (filter & FILTER_MAX_ACTIVE) {
                 if (filter_max_active == 1 && rsn->data.max_active == 0)
                     continue;
                 if (filter_max_active == 0 && rsn->data.max_active != 0)
                     continue;
             }
             if (filter & FILTER_ACTIVE) {
                 if (filter_active == 1 && rsn->active == 0)
                     continue;
                 if (filter_active == 0 && rsn->active != 0)
                     continue;
             }
             
             size += rsn->len + strlen("\"domain\": ") + 10;
             size += pzone[i]->shm_zone->shm.name.len + strlen("\"zone_name\": ") + 10;
             size += (NGX_INT64_LEN) + strlen("\"bandwidth\": ") + 10;
             size += (NGX_INT64_LEN) + strlen("\"max_bw\": ") + 10;
             size += (NGX_INT64_LEN) + strlen("\"traffic\": ") + 10;
             size += (NGX_INT64_LEN) + strlen("\"requests\": ") + 10;
             size += (NGX_INT64_LEN) + strlen("\"max_active\": ") + 10;
             size += (NGX_INT64_LEN) + strlen("\"active\": ") + 10;
             
             item = ngx_array_push(&items);
             if (item == NULL){
                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
             }
 
             item->zone_name = &pzone[i]->shm_zone->shm.name;
             item->node = rsn;
 
             item->pdata = &rsn->data;
         }
 
         pzone[i]->sh->expire_lock = ngx_time() + rmcf->lock_time;
 
         ngx_shmtx_unlock(&pzone[i]->shpool->mutex);
     }
 
     if (items.nelts > 1) {
         ngx_qsort(items.elts, (size_t) items.nelts, item_size,
                 ngx_http_req_status_cmp_items);
     }
 
     b = ngx_create_temp_buf(r->pool, size);
     if (b == NULL) {
         return NGX_HTTP_INTERNAL_SERVER_ERROR;
     }
 
     item = items.elts;
 
     for (i = 0; i < items.nelts; i++){
         if (i) {
             item = (ngx_http_req_status_print_item_t *)
                 ((u_char *)item + item_size);
         }
 
         /* set pdata here because of qsort above */
         if (item->pdata == NULL){
             item->pdata = &item->data[0];
         }
 
         if (timestamp_written == 0) {
             b->last = ngx_sprintf(b->last, "{\"timestamp\": %d, \"data\": [", item->pdata->last_bandwidth_update);
             timestamp_written = 1;
         }
 
         b->last = ngx_sprintf(b->last, "{\"domain\": \"");
         b->last = ngx_cpymem(b->last, item->node->key, item->node->len);
         b->last = ngx_sprintf(b->last, "\", \"zone_name\": \"");
         b->last = ngx_cpymem(b->last, item->zone_name->data, item->zone_name->len);
         b->last = ngx_sprintf(b->last, "\", \"bandwidth\": ");
         //b->last = ngx_http_req_status_format_size(b->last, item->pdata->bandwidth * 8);
         b->last = ngx_sprintf(b->last, "%d", item->pdata->bandwidth * 8);
         b->last = ngx_sprintf(b->last, ", \"active\": ");
         b->last = ngx_sprintf(b->last, "%ui}", item->node->active);
 
         if (i == items.nelts - 1) {
             b->last = ngx_sprintf(b->last, "]}");
         } else {
             b->last = ngx_sprintf(b->last, ",");
         }
         
     }
     b->last = ngx_sprintf(b->last, "\n");
     out.buf = b;
     out.next = NULL;
 
     r->headers_out.status = NGX_HTTP_OK;
     r->headers_out.content_length_n = b->last - b->pos;
 
     b->last_buf = 1;
 
     rc = ngx_http_send_header(r);
 
     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
         return rc;
     }
 
     return ngx_http_output_filter(r, &out);
 
 }
 
 
 static void *
 ngx_http_req_status_create_main_conf(ngx_conf_t *cf)
 {
     ngx_http_req_status_main_conf_t   *rmcf;
 
     rmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_req_status_main_conf_t));
     if (rmcf == NULL) {
         return NULL;
     }
 
     if (ngx_array_init(&rmcf->zones, cf->pool, 4,
                 sizeof(ngx_http_req_status_zone_t *)) != NGX_OK)
     {
         return NULL;
     }
 
     rmcf->interval = NGX_CONF_UNSET_MSEC;
     rmcf->lock_time = NGX_CONF_UNSET;
     rmcf->req_status_enable = NGX_CONF_UNSET;
 
     return rmcf;
 }
 
 static char *
 ngx_http_req_status_init_main_conf(ngx_conf_t *cf, void *conf)
 {
     ngx_http_req_status_main_conf_t *rmcf = conf;
 
     ngx_conf_init_msec_value(rmcf->interval, 5 * 60 * 1000);
     ngx_conf_init_value(rmcf->lock_time, 100);
 
     return NGX_CONF_OK;
 }
 
 static void *
 ngx_http_req_status_create_loc_conf(ngx_conf_t *cf)
 {
     ngx_http_req_status_loc_conf_t *rlcf;
 
     rlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_req_status_loc_conf_t));
     if (rlcf == NULL) {
         return NULL;
     }
 
     rlcf->parent = NGX_CONF_UNSET_PTR;
 
     return rlcf;
 }
 
 static char *
 ngx_http_req_status_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
 {
     ngx_http_req_status_loc_conf_t *prev = parent;
     ngx_http_req_status_loc_conf_t *conf = child;
     ngx_http_req_status_loc_conf_t *rlcf;
 
     if (conf->parent == NGX_CONF_UNSET_PTR){
         rlcf = prev;
 
         if (rlcf->parent == NGX_CONF_UNSET_PTR) {
             rlcf->parent = NULL;
         } else {
             while (rlcf->parent && rlcf->req_zones.nelts == 0) {
                 rlcf = rlcf->parent;
             }
         }
 
         conf->parent = rlcf->req_zones.nelts ? rlcf : NULL;
     }
 
     return NGX_CONF_OK;
 }
 
 static ngx_int_t
 ngx_http_req_status_init_zone(ngx_shm_zone_t *shm_zone, void *data)
 {
     size_t                      len;
     ngx_http_req_status_zone_t *ctx = shm_zone->data;
     ngx_http_req_status_zone_t *octx = data;
 
     if (octx){
         if (ngx_strcmp(&octx->key.value, &ctx->key.value) != 0) {
             ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                     "req_status \"%V\" uses the \"%V\" variable "
                     "while previously it used the \"%V\" variable",
                     &shm_zone->shm.name, &ctx->key.value, &octx->key.value);
             return NGX_ERROR;
         }
 
         ctx->sh = octx->sh;
         ctx->shpool = octx->shpool;
 
         return NGX_OK;
     }
 
     ctx->shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
 
     if (shm_zone->shm.exists){
         ctx->sh = ctx->shpool->data;
 
         return NGX_OK;
     }
 
     ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_req_status_sh_t));
     if (ctx->sh == NULL){
         return NGX_ERROR;
     }
 
     ctx->shpool->data = ctx->sh;
 
     ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
             ngx_http_req_status_rbtree_insert_value);
 
     ngx_queue_init(&ctx->sh->queue);
 
     ctx->sh->expire_lock = 0;
 
     len = sizeof("in req_status zone \"\"") + shm_zone->shm.name.len;
 
     ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
     if (ctx->shpool->log_ctx == NULL) {
         return NGX_ERROR;
     }
 
     ngx_sprintf(ctx->shpool->log_ctx, " in req_status zone \"%V\"%Z",
             &shm_zone->shm.name);
 
     return NGX_OK;
 }
 
 static char *
 ngx_http_req_status_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
     ssize_t                             size;
     ngx_str_t                          *value;
     ngx_http_req_status_zone_t         *ctx, **pctx;
     ngx_http_req_status_main_conf_t    *rmcf;
     ngx_http_compile_complex_value_t    ccv;
 
     value = cf->args->elts;
 
     size = ngx_parse_size(&value[3]);
 
     if (size == NGX_ERROR) {
         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                 "invalid size of %V \"%V\"", &cmd->name, &value[3]);
         return NGX_CONF_ERROR;
     }
 
     if (size < (ssize_t) (8 * ngx_pagesize)) {
         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                 "%V \"%V\" is too small", &cmd->name, &value[1]);
         return NGX_CONF_ERROR;
     }
 
     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_req_status_zone_t));
     if (ctx == NULL){
         return NGX_CONF_ERROR;
     }
 
     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
 
     ccv.cf = cf;
     ccv.value = &value[2];
     ccv.complex_value = &ctx->key;
 
     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
         return NGX_CONF_ERROR;
     }
 
     ctx->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
             &ngx_http_req_status_module);
     if (ctx->shm_zone == NULL) {
         return NGX_CONF_ERROR;
     }
 
     if (ctx->shm_zone->data) {
         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                 "%V \"%V\" is already bound",
                 &cmd->name, &value[1]);
         return NGX_CONF_ERROR;
     }
 
     ctx->shm_zone->init = ngx_http_req_status_init_zone;
     ctx->shm_zone->data = ctx;
 
     rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_req_status_module);
 
     pctx = ngx_array_push(&rmcf->zones);
 
     if (pctx == NULL){
         return NGX_CONF_ERROR;
     }
 
     *pctx = ctx;
 
     return NGX_CONF_OK;
 }
 
 static char *
 ngx_http_req_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
     ngx_http_req_status_loc_conf_t *rlcf = conf;
 
     ngx_str_t                      *value;
     ngx_uint_t                      i, m;
     ngx_shm_zone_t                 *shm_zone, **zones, **pzone;
 
     value = cf->args->elts;
 
     zones = rlcf->req_zones.elts;
 
     for (i = 1; i < cf->args->nelts; i++){
         if (value[i].data[0] == '@') {
             rlcf->parent = NULL;
 
             if (value[i].len == 1) {
                 continue;
             }
 
             value[i].data ++;
             value[i].len --;
         }
 
         shm_zone = ngx_shared_memory_add(cf, &value[i], 0,
                 &ngx_http_req_status_module);
         if (shm_zone == NULL) {
             return NGX_CONF_ERROR;
         }
 
         if (zones == NULL) {
             if (ngx_array_init(&rlcf->req_zones, cf->pool, 2, sizeof(ngx_shm_zone_t *))
                     != NGX_OK)
             {
                 return NGX_CONF_ERROR;
             }
 
             zones = rlcf->req_zones.elts;
         }
 
         for (m = 0; m < rlcf->req_zones.nelts; m++) {
             if (shm_zone == zones[m]) {
                 return "is duplicate";
             }
         }
 
         pzone = ngx_array_push(&rlcf->req_zones);
         if (pzone == NULL){
             return NGX_CONF_ERROR;
         }
 
         *pzone = shm_zone;
     }
 
     return NGX_CONF_OK;
 }
 
 static char *
 ngx_http_req_status_show(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
     ngx_http_req_status_main_conf_t   *rmcf;
     
     rmcf = ngx_http_cycle_get_module_main_conf(cf->cycle, ngx_http_req_status_module);
     if (rmcf == NULL)
         return NGX_CONF_ERROR;
 
     if (rmcf->req_status_enable != 1) {
         ngx_log_error(NGX_LOG_ERR, cf->log, 0, "req_status_show directive can be specified when req_status_enable directive is on");
         return NGX_CONF_ERROR;
     }
     
     ngx_http_core_loc_conf_t  *clcf;
     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
     clcf->handler = ngx_http_req_status_show_json_handler;
     return NGX_CONF_OK;
 }
 
 static ngx_int_t
 ngx_http_req_status_init(ngx_conf_t *cf)
 {
     ngx_http_handler_pt               *h;
     ngx_http_core_main_conf_t         *cmcf;
     ngx_http_req_status_main_conf_t   *rmcf;
     
     rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_req_status_module);
 
     if (rmcf->zones.nelts == 0){
         return NGX_OK;
     }
 
     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
 
     h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
     if (h == NULL) {
         return NGX_ERROR;
     }
 
     *h = ngx_http_req_status_handler;
 
     ngx_http_top_write_filter = ngx_http_req_status_write_filter;
 
     return NGX_OK;
 }
 
 static ngx_int_t save_pid_shared_memory()
 {
     int shmid;
     key_t key;
     char *shm;
 
     // Generate a unique key
     key = ftok(".", 'a');
 
     // Get the shared memory segment ID
     shmid = shmget(key, SHM_SIZE, 0666 | IPC_CREAT);
     if (shmid == -1) {
         perror("shmget");
         return -1;
     }
 
     // Attach the shared memory segment
     shm = (char *)shmat(shmid, NULL, 0);
     if (shm == (char *) -1) {
         perror("shmat");
         return -1;
     }
     
     pid_t pid = getpid();
     
     sprintf(shm, "%d", pid);
 
     //syslog(LOG_INFO, "Data written to shared memory: %d\n", pid);
 
     return 0;
 
 }
 
 static ngx_int_t get_pid_shared_memory()
 {
     int shmid;
     key_t key;
     char *shm;
 
     // Generate a unique key
     key = ftok(".", 'a');
 
     // Get the shared memory segment ID
     shmid = shmget(key, SHM_SIZE, 0666 | IPC_CREAT);
     if (shmid == -1) {
         syslog(LOG_INFO, "shmget error\n");
         return -1;
     }
 
     // Attach the shared memory segment
     shm = (char *)shmat(shmid, NULL, 0);
     if (shm == (char *) -1) {
         syslog(LOG_INFO, "shmat error\n");
         return -1;
     }
     
     int shared_pid = atoi(shm);
     
     // Detach the shared memory segment
     if (shmdt(shm) == -1) {
         syslog(LOG_INFO, "shmdt error\n");
         return -1;
     }
 
     return shared_pid;
 }
 
 // Timer callback function
 static void
 ngx_http_req_status_timer_callback(ngx_event_t *ev) {
     ngx_http_req_status_main_conf_t   *rmcf;
     ngx_cycle_t * cycle = ev->data;
 
     rmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_req_status_module);
     
     if (rmcf == NULL) {
         ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Failed to get main conf from ngx_http_req_status_module");
         return;
     }
 
     ngx_log_debug(NGX_LOG_DEBUG_CORE, cycle->log, 0, "Timer callback is started");
 
     pid_t pid = getpid();
     if (get_pid_shared_memory() != pid) {
         return;
     }
 
     //Re-add the timer
     ngx_add_timer(ev, MEASURE_INTERVAL * 1000);
 
     ngx_uint_t                          i;
     ngx_queue_t                        *q;
     ngx_http_req_status_zone_t        **pzone;
     ngx_http_req_status_node_t         *rsn;
     
     pzone = rmcf->zones.elts;
 
     for (i = 0; i < rmcf->zones.nelts; i++){
         ngx_shmtx_lock(&pzone[i]->shpool->mutex);
 
         for (q = ngx_queue_last(&pzone[i]->sh->queue);
                 q != ngx_queue_sentinel(&pzone[i]->sh->queue);
                 q = ngx_queue_prev(q))
         {
             rsn = ngx_queue_data(q, ngx_http_req_status_node_t, queue);
             if (!rsn->data.requests){
                 continue;
             }
             
             rsn->data.bandwidth = rsn->data.last_traffic / MEASURE_INTERVAL;
             if (rsn->data.bandwidth > rsn->data.max_bandwidth)
                 rsn->data.max_bandwidth = rsn->data.bandwidth;
             //syslog(LOG_INFO, "rsn->data.bandwidth is %d\n", (int)rsn->data.bandwidth);
             rsn->data.last_traffic = 0;
             rsn->data.last_bandwidth_update = time(NULL);;
         }
         ngx_shmtx_unlock(&pzone[i]->shpool->mutex);
     }
     
     ngx_log_debug(NGX_LOG_DEBUG_CORE, cycle->log, 0, "Timer callback ends with setting zero bandwidth");
 }
 
 
 static ngx_int_t ngx_http_req_status_init_worker(ngx_cycle_t *cycle)
 {
 
     ngx_http_req_status_main_conf_t   *rmcf;
     
     rmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_req_status_module);
 
     if (rmcf == NULL) {
         ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Failed to get main conf from ngx_http_req_status_module");
         return NGX_ERROR;
     }
 
     if (rmcf->req_status_enable == 1) {
 
         ngx_event_t *ev;
 
         ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
         if (ev == NULL) {
             return NGX_ERROR;
         }
 
         ev->data = cycle;
         ev->handler = ngx_http_req_status_timer_callback;
         ev->log = cycle->log;
 
         save_pid_shared_memory();
         ngx_add_timer(ev, 2000); // Set for 2 seconds
         
     }
 
     return NGX_OK;
 }
 
 
 