#include <ngx_http_acl_module_mem_pool.h>

ngx_int_t mem_pool_init(mem_pool_t* pool, mem_pool_type_e type, void* native_pool) {
    if (pool == NULL || (type != std && native_pool == NULL)) {
        return NGX_HTTP_ACL_FAIL;
    }

    pool->type = type;
    switch (type) {
        case std:
            pool->native_pool.general_pool = NULL;
            pool->native_pool.slab_pool = NULL;
            break;
        case general_pool:
            pool->native_pool.general_pool = (ngx_pool_t*)native_pool;
            pool->native_pool.slab_pool = NULL;
            break;
        case slab_pool:
            pool->native_pool.general_pool = NULL;
            pool->native_pool.slab_pool = (ngx_slab_pool_t*)native_pool;
            break;
        default:
            return NGX_HTTP_ACL_FAIL;
    }

    return NGX_HTTP_ACL_SUCCESS;
}

void* mem_pool_calloc(mem_pool_t* pool, ngx_uint_t byte_size) {

    if (pool == NULL)
        return NULL;
    
    void* addr = NULL;
    switch (pool->type) {
        case std: 
            addr = malloc(byte_size); 
            if (addr != NULL) {
                ngx_memzero(addr, byte_size);
            }
            break;
        case general_pool:
            if (pool->native_pool.general_pool == NULL) {
                return NULL;
            }
            addr = ngx_pcalloc(pool->native_pool.general_pool, byte_size);
            break;
        case slab_pool:
            if (pool->native_pool.slab_pool == NULL) {
                return NULL;
            }
            addr = ngx_slab_calloc_locked(pool->native_pool.slab_pool, byte_size);
            break;
        default:
            return NULL;
    }
    return addr;
}

ngx_int_t mem_pool_free(mem_pool_t* pool, void* buffer) {
    if (pool == NULL || buffer == NULL)
        return NGX_HTTP_ACL_FAIL;
    
    switch (pool->type) {
        case std:
            free(buffer);
            break;
        case general_pool:
            if (pool->native_pool.general_pool == NULL) {
                return NGX_HTTP_ACL_FAIL;
            }
            ngx_pfree(pool->native_pool.general_pool, buffer);
            break;
        case slab_pool:
            if (pool->native_pool.slab_pool == NULL) {
                return NGX_HTTP_ACL_FAIL;
            }
            ngx_slab_free_locked(pool->native_pool.slab_pool, buffer);
            break;
        default:
            return NGX_HTTP_ACL_FAIL;
    }
    return NGX_HTTP_ACL_SUCCESS;
}
