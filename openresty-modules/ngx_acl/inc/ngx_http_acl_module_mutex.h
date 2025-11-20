#ifndef NGX_HTTP_ACL_MODULE_MUTEX_H
#define NGX_HTTP_ACL_MODULE_MUTEX_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <pthread.h>
#include <errno.h>

ngx_int_t init_robust_mutex(pthread_mutex_t *mutex, ngx_log_t *log);

ngx_int_t robust_mutex_lock(pthread_mutex_t *mutex, ngx_log_t *log);

ngx_int_t robust_mutex_unlock(pthread_mutex_t *mutex, ngx_log_t *log);

#endif

