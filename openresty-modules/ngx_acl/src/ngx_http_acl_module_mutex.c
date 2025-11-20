#include <ngx_http_acl_module_mutex.h>

ngx_int_t init_robust_mutex(pthread_mutex_t *mutex, ngx_log_t *log) {
    if (mutex == NULL || log == NULL) {
        return NGX_ERROR;
    }

    pthread_mutexattr_t attr;
    int rc;

    rc = pthread_mutexattr_init(&attr);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, rc, "pthread_mutexattr_init failed");
        return NGX_ERROR;
    }

    rc = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, rc, "pthread_mutexattr_setpshared failed");
        pthread_mutexattr_destroy(&attr);
        return NGX_ERROR;
    }

    rc = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, rc, "pthread_mutexattr_setrobust failed");
        pthread_mutexattr_destroy(&attr);
        return NGX_ERROR;
    }

    rc = pthread_mutex_init(mutex, &attr);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, rc, "pthread_mutex_init failed");
        pthread_mutexattr_destroy(&attr);
        return NGX_ERROR;
    }

    pthread_mutexattr_destroy(&attr);
    return NGX_OK;
}

ngx_int_t robust_mutex_lock(pthread_mutex_t *mutex, ngx_log_t *log) {
    if (mutex == NULL || log == NULL) {
        return NGX_ERROR;
    }

    int rc = pthread_mutex_lock(mutex);
    if (rc == 0) {
        // Successfully locked the mutex
        return NGX_OK;
    }

    if (rc == EOWNERDEAD) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "Mutex owner died, making it consistent");

        rc = pthread_mutex_consistent(mutex);
        if (rc != 0) {
            ngx_log_error(NGX_LOG_ERR, log, rc, "pthread_mutex_consistent failed");
            return NGX_ERROR;
        }

        // Mutex is now consistent and locked
        // Perform any necessary recovery of shared data here

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ERR, log, rc, "pthread_mutex_lock failed");
    return NGX_ERROR;
}

ngx_int_t robust_mutex_unlock(pthread_mutex_t *mutex, ngx_log_t *log) {
    if (mutex == NULL || log == NULL) {
        return NGX_ERROR;
    }

    int rc = pthread_mutex_unlock(mutex);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, rc, "pthread_mutex_unlock failed");
        return NGX_ERROR;
    }
    return NGX_OK;
}


