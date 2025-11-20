/**
 * @file ngx_http_acl_module_memory_pool.h
 * @brief memory pool
*/

#include <ngx_http_acl_module_type.h>


#ifndef __NGX_HTTP_ACL_MODULE_MEMORY_POOL_H__
#define __NGX_HTTP_ACL_MODULE_MEMORY_POOL_H__


/**
  * @brief initialize a memory pool
  * @param[out] pool The memory pool to be initialized
  * @param[in] type memory pool type
  * @param[in] native_pool memory pool
  * @return NGX_HTTP_ACL_SUCCESS if successful, otherwise not.
*/
ngx_int_t mem_pool_init(mem_pool_t* pool, mem_pool_type_e type, void* native_pool);

/**
  * @brief apply for a continuous memory
  * @param[in] pool The memory pool to be operated on
  * @param[in] byte_size number of bytes of memory
  * @return If successful, return the first memory address, otherwise NULL.
*/
void* mem_pool_calloc(mem_pool_t* pool, ngx_uint_t byte_size);

/**
  * @brief Release a continuous memory
  * @param[in] pool The memory pool to be operated on
  * @param[in] The first address of buffer memory
  * @return NGX_HTTP_ACL_SUCCESS if successful, otherwise not.
*/
ngx_int_t mem_pool_free(mem_pool_t* pool, void* buffer);

#endif