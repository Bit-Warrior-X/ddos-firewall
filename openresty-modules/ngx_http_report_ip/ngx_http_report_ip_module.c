/*
 * ngx_http_report_ip_tcp.c
 *
 * Threaded TCP reporter: push "block:<ip> <duration>\n" into a queue,
 * background thread pops and sends to remote host:port over TCP.
 *
 * Replace your previous module file with this content (or merge).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h> /* offsetof */
#include <fcntl.h>   /* add to top of file */

#define CONNECT_TIMEOUT_MS 2000  /* connect timeout in milliseconds */

/* -----------------------------------------------------------------
 * Data structures
 * ----------------------------------------------------------------- */

/* Per-worker main config (holds queue + thread info) */
typedef struct report_item {
    char                  *target;   /* host:port NUL-terminated string (malloc'd) */
    char                  *msg;      /* message string e.g. "block:1.2.3.4 300\n" (malloc'd) */
    struct report_item    *next;
} report_item_t;

typedef struct {
    ngx_msec_t                health_interval;   /* kept for compatibility (unused in TCP design) */
    ngx_array_t              *loc_confs;         /* array of ngx_http_report_ip_loc_conf_t* */

    /* Queue & thread primitives */
    pthread_t                 reporter_thread;
    pthread_mutex_t           queue_mutex;
    pthread_cond_t            queue_cond;
    int                       thread_running;

    /* Queue head/tail */
    report_item_t            *queue_head;
    report_item_t            *queue_tail;

    ngx_log_t                *log;               /* optional log pointer stored from cycle */
} ngx_http_report_ip_main_conf_t;

/* Location config - largely same as before, but socket_path now holds host:port */
typedef struct {
    ngx_uint_t    methods_mask;     /* allowed methods bitmask */
    ngx_str_t     socket_path;      /* now expected to be "host:port" */
    ngx_uint_t    block_duration;   /* block duration */
    /* old unix-socket fields removed/ignored */
    ngx_flag_t    check;
} ngx_http_report_ip_loc_conf_t;

/* license main conf (unchanged usage from your code) */
typedef struct {
    ngx_int_t license_status;
    ngx_msec_t interval;
    ngx_event_t timer_event;
} ngx_lic_main_conf_t;

extern ngx_module_t ngx_lic_module;

/* -----------------------------------------------------------------
 * Forward declarations
 * ----------------------------------------------------------------- */

static void * ngx_http_report_ip_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_report_ip_init_main_conf(ngx_conf_t *cf, void *conf);

static void * ngx_http_report_ip_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_report_ip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_report_ip_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_report_ip_init_process(ngx_cycle_t *cycle);
static void ngx_http_report_ip_exit_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_report_ip_handler(ngx_http_request_t *r);
static char * ngx_http_report_ip_set_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* queue helpers and thread */
static void report_queue_push(ngx_http_report_ip_main_conf_t *mcf, const char *target, const char *msg);
static report_item_t * report_queue_pop(ngx_http_report_ip_main_conf_t *mcf);
static void * reporter_thread_func(void *arg);

/* -----------------------------------------------------------------
 * Module directives
 * ----------------------------------------------------------------- */

static ngx_command_t ngx_http_report_ip_commands[] = {

    { ngx_string("report_healthcheck_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_report_ip_main_conf_t, health_interval),
      NULL },

    { ngx_string("report_available_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_report_ip_set_methods,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_report_ip_loc_conf_t, methods_mask),
      NULL },

    { ngx_string("report_module_check"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_report_ip_loc_conf_t, check),
      NULL },

    { ngx_string("report_block_duration"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_report_ip_loc_conf_t, block_duration),
      NULL },

    { ngx_string("report_socket_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_report_ip_loc_conf_t, socket_path),
      NULL },

    ngx_null_command
};

/* -----------------------------------------------------------------
 * Module context & definition
 * ----------------------------------------------------------------- */

static ngx_http_module_t ngx_http_report_ip_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_report_ip_init,               /* postconfiguration */

    ngx_http_report_ip_create_main_conf,   /* create main_conf */
    ngx_http_report_ip_init_main_conf,     /* init main_conf */

    NULL,                                  /* create server_conf */
    NULL,                                  /* merge server_conf */

    ngx_http_report_ip_create_loc_conf,    /* create loc_conf */
    ngx_http_report_ip_merge_loc_conf      /* merge loc_conf */
};

ngx_module_t ngx_http_report_ip_module = {
    NGX_MODULE_V1,
    &ngx_http_report_ip_module_ctx,       /* module context */
    ngx_http_report_ip_commands,          /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    ngx_http_report_ip_init_process,      /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    ngx_http_report_ip_exit_process,      /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};

/* -----------------------------------------------------------------
 * create & init main conf
 * ----------------------------------------------------------------- */

static void *
ngx_http_report_ip_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_report_ip_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_report_ip_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    mcf->health_interval = NGX_CONF_UNSET_MSEC;
    mcf->loc_confs = ngx_array_create(cf->pool, 4, sizeof(ngx_http_report_ip_loc_conf_t *));
    if (mcf->loc_confs == NULL) {
        return NULL;
    }

    mcf->queue_head = mcf->queue_tail = NULL;
    mcf->thread_running = 0;
    mcf->log = NULL;

    return mcf;
}

static char *
ngx_http_report_ip_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_report_ip_main_conf_t *mcf = conf;

    if (mcf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (mcf->health_interval == NGX_CONF_UNSET_MSEC) {
        mcf->health_interval = 1000; /* default, unused for TCP mode but keep for compatibility */
    }

    return NGX_CONF_OK;
}

/* -----------------------------------------------------------------
 * create & merge loc conf
 * ----------------------------------------------------------------- */

static void *
ngx_http_report_ip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_report_ip_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_report_ip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->methods_mask = NGX_CONF_UNSET_UINT;
    ngx_str_null(&conf->socket_path);
    conf->check = NGX_CONF_UNSET;
    conf->block_duration = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_report_ip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_report_ip_loc_conf_t  *prev = parent;
    ngx_http_report_ip_loc_conf_t  *conf = child;
    ngx_http_report_ip_main_conf_t *mcf;

    ngx_conf_merge_uint_value(conf->methods_mask,
                              prev->methods_mask,
                              (NGX_HTTP_GET|NGX_HTTP_POST));

    ngx_conf_merge_str_value(conf->socket_path,
                             prev->socket_path,
                             "");

    ngx_conf_merge_value(conf->check, prev->check, NGX_CONF_UNSET);

    if (conf->check == 1 && conf->socket_path.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "report_socket_path must be specified");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->block_duration, prev->block_duration, 0);

    /* Register this loc_conf into main_conf->loc_confs so we have a list */
    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_report_ip_module);
    if (mcf == NULL || mcf->loc_confs == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "internal error: loc_confs array not created");
        return NGX_CONF_ERROR;
    }

    ngx_http_report_ip_loc_conf_t **slot = ngx_array_push(mcf->loc_confs);
    if (slot == NULL) {
        return NGX_CONF_ERROR;
    }
    *slot = conf;

    return NGX_CONF_OK;
}

/* -----------------------------------------------------------------
 * parse methods
 * ----------------------------------------------------------------- */

static char *
ngx_http_report_ip_set_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_report_ip_loc_conf_t  *lcf = conf;
    ngx_str_t                      *value;
    ngx_uint_t                      i;

    value = cf->args->elts;
    lcf->methods_mask = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcasecmp(value[i].data, (u_char *) "GET") == 0) {
            lcf->methods_mask |= NGX_HTTP_GET;
            continue;
        }
        if (ngx_strcasecmp(value[i].data, (u_char *) "HEAD") == 0) {
            lcf->methods_mask |= NGX_HTTP_HEAD;
            continue;
        }
        if (ngx_strcasecmp(value[i].data, (u_char *) "POST") == 0) {
            lcf->methods_mask |= NGX_HTTP_POST;
            continue;
        }
        if (ngx_strcasecmp(value[i].data, (u_char *) "PUT") == 0) {
            lcf->methods_mask |= NGX_HTTP_PUT;
            continue;
        }
        if (ngx_strcasecmp(value[i].data, (u_char *) "DELETE") == 0) {
            lcf->methods_mask |= NGX_HTTP_DELETE;
            continue;
        }
        if (ngx_strcasecmp(value[i].data, (u_char *) "OPTIONS") == 0) {
            lcf->methods_mask |= NGX_HTTP_OPTIONS;
            continue;
        }
        if (ngx_strcasecmp(value[i].data, (u_char *) "PATCH") == 0) {
            lcf->methods_mask |= NGX_HTTP_PATCH;
            continue;
        }
        if (ngx_strcasecmp(value[i].data, (u_char *) "TRACE") == 0) {
            lcf->methods_mask |= NGX_HTTP_TRACE;
            continue;
        }
        if (ngx_strcasecmp(value[i].data, (u_char *) "CONNECT") == 0) {
            lcf->methods_mask |= NGX_HTTP_CONNECT;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid method \"%V\" in \"report_available_methods\"",
                           &value[i]);
        return NGX_CONF_ERROR;
    }

    if (lcf->methods_mask == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"report_available_methods\" requires at least one method");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* -----------------------------------------------------------------
 * request handler - push into queue
 * ----------------------------------------------------------------- */

static ngx_int_t
ngx_http_report_ip_handler(ngx_http_request_t *r)
{
    ngx_http_report_ip_loc_conf_t  *conf;
    ngx_str_t                       addr_text;
    ngx_log_t                      *log;
    u_char                          tmpmsg[256];
    u_char                         *p;
    size_t                          msg_len;
    char                            targetbuf[256];

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "ngx_http_report_ip_handler is received");

    ngx_lic_main_conf_t *lcf;
    lcf = (ngx_lic_main_conf_t *) ngx_http_get_module_main_conf(r, ngx_lic_module);
    if (lcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_lic module not configured");
        return NGX_DECLINED;
    }

    if (lcf->license_status == -2) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "l7 license is expired");
        return NGX_DECLINED;
    } else if (lcf->license_status == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "l7 license is invalid or manipulated by user");
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_report_ip_module);
    log  = r->connection->log;

    if (conf == NULL) {
        return NGX_DECLINED;
    }

    if (conf->check == 0 || conf->check == NGX_CONF_UNSET) {
        return NGX_DECLINED;
    }

    /* If method allowed, do nothing */
    if (r->method & conf->methods_mask) {
        return NGX_DECLINED;
    }

    /* Get client IP text */
    addr_text = r->connection->addr_text;
    if (addr_text.len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "report_ip: cannot retrieve client addr_text");
        return NGX_DECLINED;
    }

    /* Prepare message: "block:<ip> <duration>\n" */
    ngx_uint_t block_duration = 0;
    if (conf->block_duration != NGX_CONF_UNSET_UINT) {
        block_duration = conf->block_duration;
    }

    p = ngx_snprintf(tmpmsg, sizeof(tmpmsg), "block:%V %d", &addr_text, (int)block_duration);
    msg_len = (size_t)(p - tmpmsg);

    if (msg_len == 0 || msg_len >= sizeof(tmpmsg)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "report_ip: message too long for \"%V\"", &addr_text);
        return NGX_DECLINED;
    }
    tmpmsg[msg_len] = '\0';

    /* Prepare target string (host:port) from conf->socket_path */
    if (conf->socket_path.len == 0 || conf->socket_path.len >= (sizeof(targetbuf) - 1)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "report_ip: bad target endpoint: \"%V\"", &conf->socket_path);
        return NGX_DECLINED;
    }
    memcpy(targetbuf, conf->socket_path.data, conf->socket_path.len);
    targetbuf[conf->socket_path.len] = '\0';

    /* Push into main conf queue */
    ngx_http_report_ip_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_report_ip_module);
    if (mcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "report_ip: main conf missing");
        return NGX_DECLINED;
    }

    /* offer the message (allocate copies for queue) */
    report_queue_push(mcf, targetbuf, (const char *) tmpmsg);

    /* define return code*/
    // Drop silently (close socket) NGX_ERROR
    // Block with HTTP 403 NGX_HTTP_FORBIDDEN
    // Finish processing, no response yet NGX_DONE

    return NGX_ERROR;
}

/* -----------------------------------------------------------------
 * report queue helpers and thread
 * ----------------------------------------------------------------- */

static void
report_queue_push(ngx_http_report_ip_main_conf_t *mcf, const char *target, const char *msg)
{
    if (mcf == NULL || target == NULL || msg == NULL) {
        return;
    }
    
    report_item_t *it = malloc(sizeof(*it));
    if (it == NULL) {
        return;
    }

    it->target = strdup(target);
    it->msg = strdup(msg);
    it->next = NULL;

    if (it->target == NULL || it->msg == NULL) {
        free(it->target);
        free(it->msg);
        free(it);
        return;
    }

    pthread_mutex_lock(&mcf->queue_mutex);
    if (mcf->queue_tail == NULL) {
        mcf->queue_head = mcf->queue_tail = it;
    } else {
        mcf->queue_tail->next = it;
        mcf->queue_tail = it;
    }
    pthread_cond_signal(&mcf->queue_cond);
    pthread_mutex_unlock(&mcf->queue_mutex);

    ngx_log_debug(NGX_LOG_DEBUG_CORE, mcf->log, 0, "report block message is pushed. target = %s, message = %s", target, msg);
}

static report_item_t *
report_queue_pop(ngx_http_report_ip_main_conf_t *mcf)
{
    report_item_t *it = NULL;

    pthread_mutex_lock(&mcf->queue_mutex);
    while (mcf->queue_head == NULL && mcf->thread_running) {
        pthread_cond_wait(&mcf->queue_cond, &mcf->queue_mutex);
    }
    if (mcf->queue_head) {
        it = mcf->queue_head;
        mcf->queue_head = it->next;
        if (mcf->queue_head == NULL) {
            mcf->queue_tail = NULL;
        }
    }
    pthread_mutex_unlock(&mcf->queue_mutex);

    return it;
}

/* Helper: send message `it->msg` to host:port specified in it->target */
static void
send_report_via_tcp(report_item_t *it)
{
    if (it == NULL || it->target == NULL || it->msg == NULL) return;

    char *host = NULL, *port = NULL;
    char *tcopy = strdup(it->target);
    if (tcopy == NULL) return;

    /* support basic IPv6 literal [::1]:1234 or host:port */
    if (tcopy[0] == '[') {
        char *endb = strchr(tcopy, ']');
        if (endb) {
            *endb = '\0';
            host = tcopy + 1;
            if (*(endb + 1) == ':') port = endb + 2;
            else port = NULL;
        } else {
            free(tcopy);
            return;
        }
    } else {
        char *sep = strrchr(tcopy, ':'); /* last ':' for safety */
        if (sep) {
            *sep = '\0';
            host = tcopy;
            port = sep + 1;
        } else {
            free(tcopy);
            return;
        }
    }

    if (host == NULL || port == NULL || *port == '\0') {
        free(tcopy);
        return;
    }

    struct addrinfo hints, *res = NULL, *rp;
    int sfd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        free(tcopy);
        return;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd < 0) continue;

        /* Set non-blocking */
        int flags = fcntl(sfd, F_GETFL, 0);
        if (flags == -1) flags = 0;
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK);

        int c = connect(sfd, rp->ai_addr, rp->ai_addrlen);
        if (c == 0) {
            /* immediate success (rare) */
            /* restore blocking mode (optional) */
            fcntl(sfd, F_SETFL, flags);
            break;
        } else if (c < 0 && errno == EINPROGRESS) {
            /* connection in progress — wait for writable or except */
            fd_set wfds, efds;
            struct timeval tv;
            FD_ZERO(&wfds);
            FD_ZERO(&efds);
            FD_SET(sfd, &wfds);
            FD_SET(sfd, &efds);
            tv.tv_sec = CONNECT_TIMEOUT_MS / 1000;
            tv.tv_usec = (CONNECT_TIMEOUT_MS % 1000) * 1000;

            int sel = select(sfd + 1, NULL, &wfds, &efds, &tv);
            if (sel > 0) {
                if (FD_ISSET(sfd, &wfds) || FD_ISSET(sfd, &efds)) {
                    int so_err = 0;
                    socklen_t len = sizeof(so_err);
                    if (getsockopt(sfd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0) {
                        close(sfd);
                        sfd = -1;
                        continue; /* try next addr */
                    }
                    if (so_err == 0) {
                        /* connected */
                        /* restore blocking mode (optional) */
                        fcntl(sfd, F_SETFL, flags);
                        break;
                    } else {
                        /* connect failed */
                        close(sfd);
                        sfd = -1;
                        continue; /* try next addr */
                    }
                } else {
                    /* unexpected: no fd set */
                    close(sfd);
                    sfd = -1;
                    continue;
                }
            } else if (sel == 0) {
                /* timeout */
                close(sfd);
                sfd = -1;
                continue; /* try next addr */
            } else {
                /* select error */
                close(sfd);
                sfd = -1;
                continue;
            }
        } else {
            /* immediate error */
            close(sfd);
            sfd = -1;
            continue;
        }
    }

    if (sfd >= 0) {
        /* send the message (blocking send is fine) */
        size_t to_write = strlen(it->msg);
        size_t written = 0;
        const char *buf = it->msg;
        while (written < to_write) {
            ssize_t n = send(sfd, buf + written, to_write - written, 0);
            if (n <= 0) {
                /* send failed */
                break;
            }
            
            written += (size_t) n;
        }
        close(sfd);
    } else {
        /* failed to connect to any addr — nothing to do (optionally log) */
    }

    freeaddrinfo(res);
    free(tcopy);
}

/* Thread function */
static void * reporter_thread_func(void *arg)
{
    ngx_http_report_ip_main_conf_t *mcf = arg;

    while (mcf->thread_running) {
        report_item_t *it = report_queue_pop(mcf);
        if (it == NULL) {
            /* might be shutdown or spurious wakeup */
            continue;
        }

        send_report_via_tcp(it);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, mcf->log, 0, "Sent report ip to L4. target=%s, message=%s", it->target, it->msg);

        free(it->msg);
        free(it->target);
        free(it);
    }

    /* Drain remaining items (attempt best-effort delivery or free) */
    while (1) {
        pthread_mutex_lock(&mcf->queue_mutex);
        report_item_t *it = mcf->queue_head;
        if (it) {
            mcf->queue_head = it->next;
            if (mcf->queue_head == NULL) mcf->queue_tail = NULL;
        }
        pthread_mutex_unlock(&mcf->queue_mutex);
        if (it == NULL) break;

        /* attempt one last send */
        send_report_via_tcp(it);
        free(it->msg);
        free(it->target);
        free(it);
    }

    return NULL;
}

/* -----------------------------------------------------------------
 * init_process: start the reporter thread for this worker
 * ----------------------------------------------------------------- */

static ngx_int_t
ngx_http_report_ip_init_process(ngx_cycle_t *cycle)
{
    ngx_http_report_ip_main_conf_t *mcf;
    ngx_uint_t n;

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_report_ip_module);
    if (mcf == NULL) {
        return NGX_OK;
    }

    n = (mcf->loc_confs ? mcf->loc_confs->nelts : 0);
    if (n == 0) {
        return NGX_OK;
    }

    /* record log pointer */
    mcf->log = cycle->log;

    mcf->queue_head = mcf->queue_tail = NULL;
    pthread_mutex_init(&mcf->queue_mutex, NULL);
    pthread_cond_init(&mcf->queue_cond, NULL);
    mcf->thread_running = 1;

    if (pthread_create(&mcf->reporter_thread, NULL, reporter_thread_func, mcf) != 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "report_ip: failed to create reporter thread");
        mcf->thread_running = 0;
        pthread_mutex_destroy(&mcf->queue_mutex);
        pthread_cond_destroy(&mcf->queue_cond);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* -----------------------------------------------------------------
 * exit_process: stop thread and cleanup
 * ----------------------------------------------------------------- */

static void
ngx_http_report_ip_exit_process(ngx_cycle_t *cycle)
{
    ngx_http_report_ip_main_conf_t *mcf;

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_report_ip_module);
    if (mcf == NULL) return;

    /* signal thread to stop */
    pthread_mutex_lock(&mcf->queue_mutex);
    mcf->thread_running = 0;
    pthread_cond_broadcast(&mcf->queue_cond);
    pthread_mutex_unlock(&mcf->queue_mutex);

    /* join thread */
    pthread_join(mcf->reporter_thread, NULL);

    pthread_mutex_destroy(&mcf->queue_mutex);
    pthread_cond_destroy(&mcf->queue_cond);

    /* free remaining items if any */
    report_item_t *it;
    while ((it = mcf->queue_head) != NULL) {
        mcf->queue_head = it->next;
        free(it->msg);
        free(it->target);
        free(it);
    }
    mcf->queue_tail = NULL;
}

/* -----------------------------------------------------------------
 * post-configuration: register handler (kept in POST_READ phase as before)
 * ----------------------------------------------------------------- */

static ngx_int_t
ngx_http_report_ip_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    /* Insert our handler into the POST_READ phase (change to ACCESS_PHASE if desired) */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_report_ip_handler;
    return NGX_OK;
}
