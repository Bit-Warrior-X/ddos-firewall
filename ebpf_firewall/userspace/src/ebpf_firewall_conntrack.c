/*
 * ebpf_firewall_conntrack.c — v3 complete rewrite
 *
 * Fixes:
 *   1. Skip blocked IPs during conntrack processing — don't insert
 *      blocked IPs into tcp_established_map or count their connections
 *   2. Fix connection counter — read current count before adjusting,
 *      and deduplicate UPDATE events (only increment on first ESTABLISHED)
 *   3. Track inbound (orig) direction only in tcp_established_map (Phase 0 C2:
 *      reply-tuple keys like server:443 let spoofed packets fast-path)
 *   4. Suppress log spam — only log once when connection limit first reached
 *   5. Initial dump uses BPF_NOEXIST to avoid double-counting
 *   6. Require a real SYN-seen handshake (IP_CT_TCP_FLAG_SEEN_SYN) when the
 *      attr is available; with tcp_loose=0, loose pickups are rare (C4)
 */

 #include <ebpf_firewall_common.h>
 #include <ebpf_firewall_conntrack.h>
 #include <ebpf_firewall_log.h>
 #include <ebpf_firewall_config.h>
 
 #define MAX_EVENTS 10
 #define MAX_RETRIES 3
 #define RECOVERY_DELAY_US 1000
 #define BUFFER_SIZE        (2 * 1024 * 1024)
 #define BUFFER_SIZE_MAX    (256 * 1024 * 1024)
 /* A full dump of a multi-million-entry table under flood is itself expensive. */
 #define RECOVERY_DUMP_MIN_INTERVAL_S 10
 /*
  * nf_conntrack ATTR_TCP_FLAGS_* are IP_CT_TCP_FLAG_* bits, not wire TCP flags.
  * 0x02 is IP_CT_TCP_FLAG_SACK_PERM (not SYN). 0x10 is IP_CT_TCP_FLAG_SEEN_SYN.
  */
 #define CT_TCP_FLAG_SEEN_SYN  0x10
 
 static struct nfct_handle *h = NULL;
 extern int exiting;
 extern struct global_firewall_config global_fw_config;
 
 static int ct_family = AF_INET;
 static size_t current_buf_size = BUFFER_SIZE;
 static int established_map_fd;
 static int connection_map_fd;
 static int block_ips_map_fd;
 
 /* Flag: set to 1 after the initial conntrack dump completes.
  * During the dump, we use BPF_NOEXIST for the connection counter
  * to avoid double-counting entries that appear multiple times. */
 static volatile int initial_dump_complete = 0;
 
 static void set_socket_buffer_size(int fd, size_t size) {
     if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0) {
         LOG_E("setsockopt SO_RCVBUF %s\n", strerror(errno));
 #ifdef SO_RCVBUFFORCE
         if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0) {
             LOG_E("setsockopt SO_RCVBUFFORCE %s\n", strerror(errno));
         }
 #endif
     }
 }
 
 static inline __u64 make_established_key(__u32 ip, __u16 port)
 {
     __u64 key = port;
     key = ((key << 32) | ip);
     return key;
 }
 
 static void established_map_add(__u32 ip, __u16 port)
 {
     __u64 key = make_established_key(ip, port);
     __u8 val = 1;
     bpf_map_update_elem(established_map_fd, &key, &val, BPF_ANY);
 }
 
 static void established_map_del(__u32 ip, __u16 port)
 {
     __u64 key = make_established_key(ip, port);
     bpf_map_delete_elem(established_map_fd, &key);
 }
 
 /*
  * Check if an IP is currently in the blocked_ips BPF map.
  * Returns 1 if blocked, 0 if not.
  */
 static int is_ip_blocked(__u32 ip)
 {
     __u64 expire = 0;
     if (bpf_map_lookup_elem(block_ips_map_fd, &ip, &expire) != 0)
         return 0;  /* not found → not blocked */
 
     /* Check if the block has expired. We use CLOCK_MONOTONIC to match
      * the XDP-side bpf_ktime_get_ns() timescale. */
     if (expire == (__u64)-1)
         return 1;  /* permanent block */
 
     struct timespec ts;
     if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
         return 1;  /* can't check time → assume blocked for safety */
 
     __u64 now = (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
     return (now < expire) ? 1 : 0;
 }
 
 static int flush_conntrack_for_ip(__u32 ip_net_order)
{
    struct nfct_handle *fh = nfct_open(CONNTRACK, 0);
    if (!fh) {
        LOG_E("nfct_open for flush: %s\n", strerror(errno));
        return -1;
    }

    struct nf_conntrack *ct = nfct_new();
    if (!ct) {
        LOG_E("nfct_new: %s\n", strerror(errno));
        nfct_close(fh);
        return -1;
    }

    /* Set filter: IPv4 TCP from this source IP */
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, ip_net_order);

    int ret = nfct_query(fh, NFCT_Q_DESTROY, ct);
    /* ENOENT is fine — no matching entries */
    if (ret < 0 && errno != ENOENT) {
        /* Per-IP destroy might not be supported on all kernels.
         * Fall through — the conntrack callback's is_ip_blocked()
         * check will handle it. */
        LOG_D("nfct_query(DESTROY) for IP: %s (non-fatal)\n", strerror(errno));
    }

    nfct_destroy(ct);
    nfct_close(fh);
    return 0;
}

/* tcp_established_map key: low 32 bits = IP, upper = port (see make_established_key). */
static void established_map_remove_all_for_ip(int est_fd, __u32 ip_net_order)
{
    if (est_fd < 0)
        return;

    for (;;) {
        __u64 key, next_key;
        int deleted = 0;

        if (bpf_map_get_next_key(est_fd, NULL, &next_key) != 0)
            break;

        do {
            key = next_key;
            if ((__u32)key == ip_net_order) {
                bpf_map_delete_elem(est_fd, &key);
                deleted = 1;
                break;
            }
        } while (bpf_map_get_next_key(est_fd, &key, &next_key) == 0);

        if (!deleted)
            break;
    }
}

void clear_tracked_tcp_state_for_blocked_ip(int tcp_established_fd,
                                            int tcp_connection_map_fd,
                                            __u32 ip_net_order)
{
    established_map_remove_all_for_ip(tcp_established_fd, ip_net_order);

    if (tcp_connection_map_fd >= 0)
        bpf_map_delete_elem(tcp_connection_map_fd, &ip_net_order);

    flush_conntrack_for_ip(ip_net_order);
}

static int cmp_u32(const void *a, const void *b)
{
    __u32 x = *(const __u32 *)a, y = *(const __u32 *)b;
    return (x > y) - (x < y);
}

void clear_tracked_tcp_state_for_blocked_ips(int tcp_established_fd,
                                             int tcp_connection_map_fd,
                                             __u32 *ips_net_order, size_t n)
{
    if (!ips_net_order || n == 0)
        return;

    qsort(ips_net_order, n, sizeof(*ips_net_order), cmp_u32);

    if (tcp_established_fd >= 0) {
        /* Collect first: deleting while iterating restarts get_next_key. */
        size_t cap = 1024, cnt = 0;
        __u64 *victims = malloc(cap * sizeof(*victims));
        __u64 key, next_key;
        int has = victims && bpf_map_get_next_key(tcp_established_fd, NULL, &next_key) == 0;

        while (has) {
            key = next_key;
            __u32 ip = (__u32)key;
            if (bsearch(&ip, ips_net_order, n, sizeof(*ips_net_order), cmp_u32)) {
                if (cnt == cap) {
                    __u64 *grown = realloc(victims, cap * 2 * sizeof(*victims));
                    if (!grown)
                        break;
                    victims = grown;
                    cap *= 2;
                }
                victims[cnt++] = key;
            }
            has = bpf_map_get_next_key(tcp_established_fd, &key, &next_key) == 0;
        }

        for (size_t i = 0; i < cnt; i++)
            bpf_map_delete_elem(tcp_established_fd, &victims[i]);
        free(victims);
    }

    for (size_t i = 0; i < n; i++) {
        if (tcp_connection_map_fd >= 0)
            bpf_map_delete_elem(tcp_connection_map_fd, &ips_net_order[i]);
        flush_conntrack_for_ip(ips_net_order[i]);
    }
}

int reconcile_blocked_ips_tracked_state(struct bpf_object *obj)
{
    int est_fd, conn_fd, blocked_fd;

    est_fd = bpf_object__find_map_fd_by_name(obj, "tcp_established_map");
    conn_fd = bpf_object__find_map_fd_by_name(obj, "tcp_connection_map");
    blocked_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (est_fd < 0 || conn_fd < 0 || blocked_fd < 0) {
        LOG_E("reconcile_blocked_ips: missing BPF map fd\n");
        return -1;
    }

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(blocked_fd, &info, &len)) {
        LOG_E("reconcile_blocked_ips: bpf_obj_get_info_by_fd: %s\n", strerror(errno));
        return -1;
    }

    void *key  = calloc(1, info.key_size);
    void *next = calloc(1, info.key_size);
    if (!key || !next) {
        free(key);
        free(next);
        return -1;
    }

    if (bpf_map_get_next_key(blocked_fd, NULL, next) == 0) {
        do {
            __u32 ip = *(__u32 *)next;
            clear_tracked_tcp_state_for_blocked_ip(est_fd, conn_fd, ip);
            memcpy(key, next, info.key_size);
        } while (bpf_map_get_next_key(blocked_fd, key, next) == 0);
    }

    free(key);
    free(next);
    return 0;
}

/*
 * Iterate blocked_ips BPF map and flush conntrack for each blocked IP.
 * Call this AFTER loading blocked IPs from SQLite but BEFORE init_conntrack().
 */
int purge_conntrack_for_blocked_ips(int blocked_ips_fd)
{
    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(blocked_ips_fd, &info, &len)) {
        LOG_E("bpf_obj_get_info_by_fd: %s\n", strerror(errno));
        return -1;
    }

    void *key  = calloc(1, info.key_size);
    void *next = calloc(1, info.key_size);
    if (!key || !next) {
        free(key); free(next);
        return -1;
    }

    int count = 0;
    if (bpf_map_get_next_key(blocked_ips_fd, NULL, next) == 0) {
        do {
            __u32 ip = *(__u32 *)next;
            flush_conntrack_for_ip(ip);
            count++;
            memcpy(key, next, info.key_size);
        } while (bpf_map_get_next_key(blocked_ips_fd, key, next) == 0);
    }

    free(key);
    free(next);
    LOG_I("Purged conntrack entries for %d blocked IPs\n", count);
    return 0;
}

 /*
  * Adjust the per-IP connection count in tcp_connection_map.
  * Reads the current count, adjusts, writes back.
  * Only blocks the IP if the limit is exceeded AND the count increased.
  */
 static void connection_count_adjust(__u32 sip, int delta)
 {
     if (global_fw_config.g_tcp_connection_config.check == 0)
         return;
 
     __u32 con_count = 0;
     bpf_map_lookup_elem(connection_map_fd, &sip, &con_count);
 
     __u32 old_count = con_count;
 
     if (delta > 0) {
         con_count += (__u32)delta;
     } else {
         __u32 dec = (__u32)(-delta);
         con_count = (con_count >= dec) ? (con_count - dec) : 0;
     }
 
     bpf_map_update_elem(connection_map_fd, &sip, &con_count, BPF_ANY);
 
     /* Only log and block when we CROSS the threshold (not on every increment above it) */
     __u32 limit = global_fw_config.g_tcp_connection_config.limit_cnt;
     if (delta > 0 && con_count >= limit && old_count < limit) {
         struct in_addr in;
         char src_str[INET_ADDRSTRLEN];
         in.s_addr = sip;
         inet_ntop(AF_INET, &in, src_str, sizeof(src_str));
         LOG_C("TCP connection limit reached [%s] -> %u (limit=%u)\n",
               src_str, con_count, limit);
        
        print_firewall_status(NULL, EVENT_TCP_CONNECTION_LIMIT_REACHED, sip, 0);

         struct timespec ts;
         if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
             __u64 now = (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
             __u64 expire = now + global_fw_config.g_config.black_ip_duration;
             bpf_map_update_elem(block_ips_map_fd, &sip, &expire, BPF_ANY);
             clear_tracked_tcp_state_for_blocked_ip(established_map_fd,
                                                    connection_map_fd, sip);
         }
     }
 }
 
 
 /* 1 if conntrack saw a real SYN for this flow (not a loose mid-stream pickup). */
 static int conntrack_saw_syn(const struct nf_conntrack *ct)
 {
     uint8_t flags = 0;
     int have_flags = 0;

     if (nfct_attr_is_set(ct, ATTR_TCP_FLAGS_ORIG)) {
         flags |= nfct_get_attr_u8(ct, ATTR_TCP_FLAGS_ORIG);
         have_flags = 1;
     }
     if (nfct_attr_is_set(ct, ATTR_TCP_FLAGS_REPL)) {
         flags |= nfct_get_attr_u8(ct, ATTR_TCP_FLAGS_REPL);
         have_flags = 1;
     }
     /* No flag attrs: allow only when loose is off (sysctl). Prefer SEEN_SYN. */
     if (!have_flags)
         return 1;
     return (flags & CT_TCP_FLAG_SEEN_SYN) != 0;
 }

 /* Connection event callback */
 static int event_cb(enum nf_conntrack_msg_type type,
                     struct nf_conntrack *ct,
                     void *data)
 {
     uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
     if (proto != IPPROTO_TCP)
         return NFCT_CB_CONTINUE;
 
     uint8_t state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
 
     /* Only process ESTABLISHED state for NEW/UPDATE events */
     if ((type == NFCT_T_NEW || type == NFCT_T_UPDATE) &&
         state != TCP_CONNTRACK_ESTABLISHED)
         return NFCT_CB_CONTINUE;
 
     /* Get both directions */
     uint32_t orig_sip   = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
     uint32_t orig_dip   = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
     uint16_t orig_sport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
     uint16_t orig_dport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
 
     uint32_t repl_sip   = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
     uint16_t repl_sport = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);
 
     /*
      * FIX #1: Skip blocked IPs entirely.
      * If either the original source or the reply source is blocked,
      * do NOT add them to tcp_established_map and do NOT count their connections.
      * This prevents blocked IPs from getting established-connection fast-path
      * treatment in the XDP handlers.
      */
     if (is_ip_blocked(orig_sip) || is_ip_blocked(repl_sip)) {
         /* If this is a DESTROY event, still clean up any stale map entries */
         if (type == NFCT_T_DESTROY) {
             established_map_del(orig_sip, orig_sport);
             established_map_del(repl_sip, repl_sport);
         }
         return NFCT_CB_CONTINUE;
     }
 
     if (type == NFCT_T_NEW || type == NFCT_T_UPDATE) {
         /* nf_conntrack_tcp_loose picks up a raw PSH+ACK as ESTABLISHED.
          * xdp_main would then skip STOMP/HANDSHAKE for that flow, so the
          * attack counter stays far below the PSH+ACK flag count. */
         if (!conntrack_saw_syn(ct))
             return NFCT_CB_CONTINUE;

         /*
          * FIX #2: Deduplicate established map insertions.
          * During the initial dump, the same connection may appear multiple times.
          * Use BPF_NOEXIST during the dump to avoid re-counting.
          * After the dump, use BPF_ANY (idempotent — value is always 1).
          */
         /* Phase 0 C2: insert only the inbound (orig) 4-tuple endpoint.
          * Reply keys such as (server_ip, 443) let any spoof from that tuple
          * skip flood checks toward any destination. */
         __u8 val = 1;
         __u64 key_orig = make_established_key(orig_sip, orig_sport);
 
         if (!initial_dump_complete) {
             int orig_new = (bpf_map_update_elem(established_map_fd, &key_orig, &val, BPF_NOEXIST) == 0);
             if (orig_new)
                 connection_count_adjust(orig_sip, +1);
         } else {
             int is_new = (bpf_map_update_elem(established_map_fd, &key_orig, &val, BPF_NOEXIST) == 0);
             if (is_new)
                 connection_count_adjust(orig_sip, +1);
         }
     }
 
     if (type == NFCT_T_DESTROY) {
         __u64 key_orig = make_established_key(orig_sip, orig_sport);
         __u8 val;
         int was_tracked = (bpf_map_lookup_elem(established_map_fd, &key_orig, &val) == 0);
 
         established_map_del(orig_sip, orig_sport);
         /* Drop any legacy reply-tuple entries left from older builds. */
         established_map_del(repl_sip, repl_sport);
 
         if (was_tracked)
             connection_count_adjust(orig_sip, -1);
     }
 
     return NFCT_CB_CONTINUE;
 }
 
 
 static void *conntrack_thread(void *arg) {
     struct nfct_handle *handle = (struct nfct_handle *)arg;
     int epoll_fd, nfctfd;
     struct epoll_event ev, events[MAX_EVENTS];
 
     nfctfd = nfct_fd(handle);
 
     epoll_fd = epoll_create1(0);
     if (epoll_fd < 0) {
         LOG_E("epoll_create1 %s\n", strerror(errno));
         return NULL;
     }
     ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
     ev.data.fd = nfctfd;
     if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, nfctfd, &ev) < 0) {
         LOG_E("epoll_ctl %s\n", strerror(errno));
         close(epoll_fd);
         return NULL;
     }
 
     time_t last_recovery_dump = 0;
     unsigned long overflows_suppressed = 0;

     while (!exiting) {
         int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
         if (n < 0) {
             if (errno == EINTR) continue;
             LOG_E("epoll_wait %s\n", strerror(errno));
             break;
         }
         for (int i = 0; i < n; i++) {
             if (events[i].data.fd == nfctfd) {
                 int ret = nfct_catch(handle);
                 if (ret < 0 && errno == ENOBUFS) {
                     time_t now = time(NULL);
                     if (now - last_recovery_dump < RECOVERY_DUMP_MIN_INTERVAL_S) {
                         overflows_suppressed++;
                         continue;
                     }
                     LOG_W("Conntrack buffer overflow, recovering... (suppressed=%lu)\n",
                           overflows_suppressed);
                     overflows_suppressed = 0;
                     last_recovery_dump = now;
                     usleep(RECOVERY_DELAY_US);
                     if (current_buf_size < BUFFER_SIZE_MAX) {
                         current_buf_size *= 2;
                         set_socket_buffer_size(nfctfd, current_buf_size);
                     }
                     if (nfct_query(handle, NFCT_Q_DUMP, &ct_family) < 0) {
                         LOG_E("Recovery dump failed: %s\n", strerror(errno));
                     } else {
                         LOG_D("Recovery sync successful\n");
                     }
                     continue;
                 } else if (ret < 0) {
                     LOG_E("nfct_catch: %s\n", strerror(errno));
                     exiting = 1;
                     break;
                 }
             }
         }
     }
 
     close(epoll_fd);
     return NULL;
 }
 
 
 
/*
 * Flush ALL TCP conntrack entries.
 * Call this right before bpf_xdp_attach() to ensure the conntrack
 * table is clean when XDP starts and the dump has no stale entries.
 */
int flush_all_tcp_conntrack(void)
{
    struct nfct_handle *fh = nfct_open(CONNTRACK, 0);
    if (!fh) {
        LOG_E("nfct_open for flush_all: %s\n", strerror(errno));
        return -1;
    }

    struct nf_conntrack *ct = nfct_new();
    if (!ct) {
        LOG_E("nfct_new: %s\n", strerror(errno));
        nfct_close(fh);
        return -1;
    }

    /* Filter: only TCP, IPv4 */
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);

    int ret = nfct_query(fh, NFCT_Q_FLUSH, ct);
    if (ret < 0 && errno != ENOENT) {
        LOG_W("nfct_query(FLUSH) for TCP: %s\n", strerror(errno));
        /* Non-fatal — fall back to per-IP purge or let is_ip_blocked() handle it */
    } else {
        LOG_I("Flushed all TCP conntrack entries\n");
    }

    nfct_destroy(ct);
    nfct_close(fh);
    return 0;
}

/*
 * tcp_loose=1 lets conntrack adopt every mid-stream ACK/PSH+ACK that reaches the
 * stack as a new ESTABLISHED entry (one NEW event per spoofed packet). sysctl.d
 * cannot set it if nf_conntrack loads after boot-time sysctl, so enforce it here,
 * after nfct_open has the module loaded.
 */
static void enforce_tcp_loose_off(void)
{
    const char *path = "/proc/sys/net/netfilter/nf_conntrack_tcp_loose";
    int cur = -1;
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_W("%s: %s\n", path, strerror(errno));
        return;
    }
    if (fscanf(f, "%d", &cur) != 1)
        cur = -1;
    fclose(f);
    if (cur == 0)
        return;

    f = fopen(path, "w");
    if (!f || fputs("0\n", f) < 0 || fclose(f) != 0) {
        LOG_W("set %s=0 failed: %s\n", path, strerror(errno));
        return;
    }
    LOG_I("nf_conntrack_tcp_loose %d -> 0\n", cur);
}

 int init_conntrack(int tcp_established_fd, int tcp_connection_fd, int block_ips_fd) {
     pthread_t ct_thread;
 
     LOG_D("Initializing conntrack map(%d,%d,%d)\n",
           tcp_established_fd, tcp_connection_fd, block_ips_fd);
 
     h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
     if (!h) {
         LOG_E("nfct_open %s\n", strerror(errno));
         return -1;
     }
     enforce_tcp_loose_off();
 
     set_socket_buffer_size(nfct_fd(h), current_buf_size);
     established_map_fd = tcp_established_fd;
     connection_map_fd  = tcp_connection_fd;
     block_ips_map_fd   = block_ips_fd;
 
     if (nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL) < 0) {
         LOG_E("nfct_callback_register %s\n", strerror(errno));
         nfct_close(h);
         return -1;
     }
 
     LOG_D("Loading existing connections...\n");
 
     /* Mark that we're in the initial dump phase.
      * During this phase, event_cb uses BPF_NOEXIST to avoid double-counting. */
     initial_dump_complete = 0;
 
     int retry = 0;
     while (retry < MAX_RETRIES) {
         if (nfct_query(h, NFCT_Q_DUMP, &ct_family) < 0) {
             if (errno == ENOBUFS) {
                 LOG_W("WARNING: Initial dump buffer overflow (attempt %d/%d)\n",
                       retry + 1, MAX_RETRIES);
                 retry++;
                 usleep(RECOVERY_DELAY_US);
                 current_buf_size *= 2;
                 set_socket_buffer_size(nfct_fd(h), current_buf_size);
                 continue;
             }
             LOG_E("nfct_query %s\n", strerror(errno));
             nfct_close(h);
             return -1;
         }
         break;
     }
 
     /* Initial dump complete — switch to normal mode */
     initial_dump_complete = 1;
     LOG_I("Conntrack initial dump complete, now monitoring live events\n");
 
     if (pthread_create(&ct_thread, NULL, conntrack_thread, h) != 0) {
         LOG_E("pthread_create %s\n", strerror(errno));
         nfct_close(h);
         return -1;
     }
 
     return 0;
 }
 
 void close_conntrack() {
     if (h) nfct_close(h);
 }