#include <ngx_http_acl_module_lru_cache.h>


lru_cache_item_t* _lru_cache_hash_find(lru_cache_t* lru, void* key, size_t key_len);


void _lru_cache_hash_add(lru_cache_t* lru, lru_cache_item_t* item);


void _lru_cache_hash_delete(lru_cache_t* lru, lru_cache_item_t* item);


void* _lru_cache_hash_calloc(lru_cache_t* lru, size_t n);


void _lru_cache_hash_free(lru_cache_t* lru, void* addr);


ngx_int_t lru_cache_init(lru_cache_t** lru, size_t capacity, mem_pool_type_e pool_type, void* native_pool) {
    if (lru == NULL)
        return NGX_ERROR;

    lru_cache_t* _lru;
    
    if (pool_type != std) {
        if (native_pool == NULL)
            return NGX_ERROR;
    }

    mem_pool_t pool;
    if (mem_pool_init(&pool, pool_type, native_pool) != NGX_HTTP_ACL_SUCCESS)
        return NGX_ERROR;

    _lru = mem_pool_calloc(&pool, sizeof(lru_cache_t));
    if (_lru == NULL)
        return NGX_ERROR;

    ngx_memzero(_lru, sizeof(lru_cache_t));

    ngx_memcpy(&_lru->pool, &pool, sizeof(mem_pool_t));
    _lru->last_eliminate = time(NULL);
    _lru->capacity = capacity;
    _lru->hash_head = NULL;
    _lru->chain_head = NULL;

    *lru = _lru;
    
    return NGX_OK;
}


lru_cache_add_result_t lru_cache_add(lru_cache_t* lru, void* key, size_t key_len) {
    lru_cache_add_result_t ret;
    
    if(lru == NULL || key == NULL || key_len == 0) {
        ret.status = NGX_HTTP_ACL_BAD;
        ret.data = NULL;
        return ret;
    }

    lru_cache_item_t* item = _lru_cache_hash_find(lru, key, key_len);
    if (item != NULL) {
        CDL_DELETE(lru->chain_head, item);
        CDL_PREPEND(lru->chain_head, item);
        ret.status = NGX_HTTP_ACL_KEY_EXISTS;
        ret.data = &item->data;
        return ret;
    }

    if (HASH_COUNT(lru->hash_head) >= lru->capacity) {
        lru_cache_eliminate(lru, 1);
    }


    item = mem_pool_calloc(&lru->pool, sizeof(lru_cache_item_t));
    while (item == NULL && HASH_COUNT(lru->hash_head) != 0) {
        lru_cache_eliminate(lru, 1);
        item = mem_pool_calloc(&lru->pool, sizeof(lru_cache_item_t));
    }

    if (item == NULL) {
        ret.status = NGX_HTTP_ACL_MALLOC_ERROR;
        ret.data = NULL;
        return ret;
    }

    item->key_ptr = mem_pool_calloc(&lru->pool, key_len);
    while (item->key_ptr == NULL && HASH_COUNT(lru->hash_head) != 0) {
        lru_cache_eliminate(lru, 1);
        item->key_ptr = mem_pool_calloc(&lru->pool, key_len);
    }

    if (item->key_ptr == NULL) {
        mem_pool_free(&lru->pool, item);
        ret.status = NGX_HTTP_ACL_MALLOC_ERROR;
        ret.data = NULL;
        return ret;
    }

    ngx_memcpy(item->key_ptr, key, key_len);
    item->key_byte_length = key_len;
    CDL_PREPEND(lru->chain_head, item);
    _lru_cache_hash_add(lru, item);

    ret.status = NGX_HTTP_ACL_SUCCESS;
    ret.data = &item->data;

    return ret;
}


lru_cache_find_result_t lru_cache_find(lru_cache_t* lru, void* key, size_t key_len) {
    lru_cache_find_result_t ret;

    if(lru == NULL || key == NULL || key_len == 0) {
        ret.status = NGX_HTTP_ACL_BAD;
        ret.data = NULL;
        return ret;
    }

    lru_cache_item_t* item = _lru_cache_hash_find(lru, key, key_len);
    if (item != NULL) {
        CDL_DELETE(lru->chain_head, item);
        CDL_PREPEND(lru->chain_head, item);
        ret.status = NGX_HTTP_ACL_KEY_EXISTS;
        ret.data = &item->data;
    } else {
        ret.status = NGX_HTTP_ACL_KEY_NOT_EXISTS;
        ret.data = NULL;
    }

    return ret;
}


void* lru_cache_calloc(lru_cache_t* lru, size_t size) {
    if(lru == NULL || size == 0)
        return NULL;
    return mem_pool_calloc(&lru->pool, size);
}


void lru_cache_free(lru_cache_t* lru, void* addr) {
    if (lru == NULL || addr == NULL || addr == NGX_CONF_UNSET_PTR)
        return;
    
    ip_statis_t * statis = (ip_statis_t *)addr;

    if (statis == NULL) {
        mem_pool_free(&lru->pool, addr);
        return;
    }
    
    if (statis->ip_statis_type == IP_STATIS_REQUEST && statis->u.req_time_rec != NULL) {
        if (statis->u.req_time_rec->head != NULL && statis->u.req_time_rec->tail != NULL) {
            time_node_t * temp_node = statis->u.req_time_rec->head;
            while (temp_node != NULL) {
                time_node_t * next_node = temp_node->next;
                mem_pool_free(&lru->pool, temp_node);
                temp_node = next_node;
            }
        }
        mem_pool_free(&lru->pool, statis->u.req_time_rec);
        
    } else if (statis->ip_statis_type == IP_STATIS_RESPONSE && statis->u.rsp_time_rec != NULL) {
        int header_code;
        for (header_code = 100 ; header_code < MAX_HEADER_CODE_COUNT ; header_code ++) {
            if (statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head != NULL && 
                statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.tail != NULL) {
                time_node_t * temp_node = statis->u.rsp_time_rec->header_rsp_time_rec[header_code].rsp_time_rec.head;
                while (temp_node != NULL) {
                    time_node_t * next_node = temp_node->next;
                    mem_pool_free(&lru->pool, temp_node);
                    temp_node = next_node;
                }
            }
        }
        mem_pool_free(&lru->pool, statis->u.rsp_time_rec);
    }
        
    mem_pool_free(&lru->pool, addr);
}


void lru_cache_delete(lru_cache_t* lru, void* key, size_t key_len) {
    if (lru == NULL || key == NULL || key_len == 0)
        return;

    lru_cache_item_t* item = _lru_cache_hash_find(lru, key, key_len);
    if (item != NULL) {
        _lru_cache_hash_delete(lru, item);
        CDL_DELETE(lru->chain_head, item);

        if (item->data != NULL) {
            lru_cache_free(lru, item->data);
        }

        mem_pool_free(&lru->pool, item->key_ptr);
        mem_pool_free(&lru->pool, item);
    }
}


void lru_cache_eliminate(lru_cache_t* lru, size_t count) {
    if (lru == NULL || count == 0)
        return;

    for (size_t i = 0; i < count; i++) {
        if (lru->chain_head != NULL) {
            lru_cache_item_t* tail = lru->chain_head->prev;
            lru_cache_delete(lru, tail->key_ptr, tail->key_byte_length);
        }
    }
}


void lru_cache_destory(lru_cache_t* lru) {
    mem_pool_free(&lru->pool, lru);
}

void lru_cache_iter_callback(lru_cache_t* lru, void (*callback_func)(mem_pool_t * , lru_cache_item_t *, int), int period) {
    lru_cache_item_t * item;
    lru_cache_item_t * tmp;
    
    HASH_ITER(hh, lru->hash_head , item, tmp) {
        callback_func(&lru->pool,item, period);
    }
}

lru_cache_item_t* _lru_cache_hash_find(lru_cache_t* lru, void* key, size_t key_len) {
    lru_cache_item_t* ret;
    HASH_FIND(hh, lru->hash_head, key, key_len, ret);
    return ret;
}

void _lru_cache_hash_add(lru_cache_t* lru, lru_cache_item_t* item) {
    #undef uthash_malloc
    #undef uthash_free
    #define uthash_malloc(n) _lru_cache_hash_calloc(lru, n)
    #define uthash_free(ptr,sz) _lru_cache_hash_free(lru, ptr)
    HASH_ADD_KEYPTR(hh, lru->hash_head, item->key_ptr, item->key_byte_length, item);
    #undef uthash_malloc
    #undef uthash_free
    #define uthash_malloc(n) malloc(n)
    #define uthash_free(ptr, sz) free(ptr)
}


void _lru_cache_hash_delete(lru_cache_t* lru, lru_cache_item_t* item) {
    #undef uthash_malloc
    #undef uthash_free
    #define uthash_malloc(n) _lru_cache_hash_calloc(lru, n)
    #define uthash_free(ptr,sz) _lru_cache_hash_free(lru, ptr)
    HASH_DELETE(hh, lru->hash_head, item);
    #undef uthash_malloc
    #undef uthash_free
    #define uthash_malloc(n) malloc(n)
    #define uthash_free(ptr, sz) free(ptr)
}


void* _lru_cache_hash_calloc(lru_cache_t* lru, size_t n) {
    void* ret = mem_pool_calloc(&lru->pool, n);
    while (ret == NULL && HASH_COUNT(lru->hash_head) != 0) {
        lru_cache_eliminate(lru, 1);
        ret = mem_pool_calloc(&lru->pool, n);
    }
    if (ret == NULL) return NULL;
    return ret;
}


void _lru_cache_hash_free(lru_cache_t* lru, void* addr) {
    mem_pool_free(&lru->pool, addr);
}
