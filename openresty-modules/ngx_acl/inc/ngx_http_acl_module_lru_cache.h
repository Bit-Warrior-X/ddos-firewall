/**
 * @file ngx_http_acl_module_lru_cache.h.h
 * @brief LRU cache
*/

#include <ngx_http_acl_module_type.h>
#include <ngx_http_acl_module_mem_pool.h>

#ifndef __NGX_HTTP_ACL_MODULE_LRU_CACHE_H__
#define __NGX_HTTP_ACL_MODULE_LRU_CACHE_H__


ngx_int_t lru_cache_init(lru_cache_t** lru, size_t capacity, mem_pool_type_e pool_type, void* native_pool);


lru_cache_add_result_t lru_cache_add(lru_cache_t* lru, void* key, size_t key_len);


lru_cache_find_result_t lru_cache_find(lru_cache_t* lru, void* key, size_t key_len);


void* lru_cache_calloc(lru_cache_t* lru, size_t size);


void lru_cache_free(lru_cache_t* lru, void* addr);


void lru_cache_delete(lru_cache_t* lru, void* key, size_t key_len);


void lru_cache_eliminate(lru_cache_t* lru, size_t count);


void lru_cache_destory(lru_cache_t* lru);

void lru_cache_iter_callback(lru_cache_t* lru, void (*callback_func)(mem_pool_t * , lru_cache_item_t *, int), int period);

#endif