#include <ebpf_firewall_common.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_nginx.h>
#include <ebpf_firewall_config.h>
#include <ebpf_firewall_conntrack.h>
#include <ebpf_firewall_geo.h>
#include <ebpf_firewall_core.h>
#include <ebpf_firewall_utils.h>
#include <ebpf_firewall_shadow.h>
#include <ebpf_firewall_mapsize.h>
#include <unistd.h>
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <base64.h>
#include <fcntl.h>
#include <unistd.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/un.h>

extern char token[128];             // Token used for expiration check
extern char ifname[IFNAMSIZ];       // Network interface name
extern __u32 attach_mode;           // Attach mode of ebpf
extern int n_cpus;                  // CPU count
extern __u64 time_offset_ns;        // Timeo offset ns
extern long tz_offset_sec;          // Timezone offset
extern char geo_db_ipv4_path[512];       // Geo Ipv4 block database path 
extern char geo_db_location_path[512]; // Geo location code database path

extern struct global_firewall_config global_fw_config;


/* PERCPU map ABI: each CPU slot is round_up(value_size, 8) bytes; count CPUs via libbpf. */
static inline size_t bpf_percpu_stride(__u32 value_size)
{
    return (size_t)(((unsigned)value_size + 7U) & ~7U);
}

static int bpf_percpu_nr_cpus(void)
{
    int n = libbpf_num_possible_cpus();
    return (n > 0) ? n : n_cpus;
}

static void stats_config_sum_percpu(const void *raw, size_t stride, int nr,
                                    struct stats_config *sum)
{
    memset(sum, 0, sizeof(*sum));
    for (int cpu = 0; cpu < nr; cpu++) {
        const struct stats_config *p =
            (const struct stats_config *)((const char *)raw + cpu * stride);
        sum->syn += p->syn;
        sum->ack += p->ack;
        sum->rst += p->rst;
        sum->fin += p->fin;
        sum->psh += p->psh;
        sum->urg += p->urg;
        sum->syn_ack += p->syn_ack;
        sum->fin_ack += p->fin_ack;
        sum->rst_ack += p->rst_ack;
        sum->psh_ack += p->psh_ack;
        sum->icmp += p->icmp;
        sum->udp += p->udp;
        sum->gre += p->gre;
    }
}

static void traffic_stats_config_sum_percpu(const void *raw, size_t stride, int nr,
                                           struct traffic_stats_config *sum)
{
    memset(sum, 0, sizeof(*sum));
    for (int cpu = 0; cpu < nr; cpu++) {
        const struct traffic_stats_config *p =
            (const struct traffic_stats_config *)((const char *)raw + cpu * stride);
        sum->total_traffic += p->total_traffic;
        sum->allowed_traffic += p->allowed_traffic;
        sum->blocked_traffic += p->blocked_traffic;
        sum->syn += p->syn;
        sum->ack += p->ack;
        sum->rst += p->rst;
        sum->tcp += p->tcp;
        sum->udp += p->udp;
        sum->icmp += p->icmp;
        sum->gre += p->gre;
        sum->other += p->other;
    }
}

static void log_map_memory_usage(struct bpf_object *obj)
{
    struct bpf_map *map;
    __u64 total_bytes = 0;

    bpf_object__for_each_map(map, obj) {
        struct bpf_map_info info = {};
        __u32 len = sizeof(info);
        int fd = bpf_map__fd(map);

        if (fd < 0) continue;
        if (bpf_obj_get_info_by_fd(fd, &info, &len)) continue;

        /*
         * Rough memory estimate per entry for LRU_HASH:
         *   key_size + value_size + ~128 bytes overhead (hash bucket, LRU pointers, etc.)
         * For PERCPU_ARRAY:
         *   (value_size * nr_cpus) * max_entries
         * For LPM_TRIE:
         *   ~(key_size + value_size + 64) * max_entries (with NO_PREALLOC)
         */
        __u64 per_entry;
        switch (info.type) {
        case BPF_MAP_TYPE_LRU_HASH:
        case BPF_MAP_TYPE_HASH:
            per_entry = info.key_size + info.value_size + 128;
            break;
        case BPF_MAP_TYPE_PERCPU_ARRAY:
            per_entry = info.value_size * (__u64)bpf_percpu_nr_cpus();
            break;
        case BPF_MAP_TYPE_LPM_TRIE:
            per_entry = info.key_size + info.value_size + 64;
            break;
        case BPF_MAP_TYPE_RINGBUF:
            per_entry = 1;  /* max_entries IS the byte size */
            break;
        default:
            per_entry = info.key_size + info.value_size + 64;
        }

        __u64 map_bytes;
        if (info.type == BPF_MAP_TYPE_RINGBUF)
            map_bytes = info.max_entries;
        else
            map_bytes = per_entry * info.max_entries;

        total_bytes += map_bytes;

        if (map_bytes > (1024 * 1024)) {  /* only log maps > 1MB */
            LOG_D("Map %-64s  entries=%-8u  entry≈%-5llu B  total≈%.1f MB\n",
                  info.name, info.max_entries, per_entry,
                  (double)map_bytes / (1024.0 * 1024.0));
        }
    }

    LOG_I("Total estimated BPF map memory: %.1f MB\n",
          (double)total_bytes / (1024.0 * 1024.0));
}


struct stats_config global_receive_stats = {0};
struct stats_config global_passed_stats = {0};
struct fixed_ip_pkt_stats global_max_ip_pkt_stats = {0};
struct det_snapshot global_det_stats = {0};

struct traffic_stats_config global_traffic_stats[TRAFFIC_STATS_SLOTS] = {0};

int exiting = 0;
char **process_argv = NULL;
struct bpf_object *obj;

#define FIFO_MSG_QUEUE_CAPACITY 16384
static char *fifo_msg_queue[FIFO_MSG_QUEUE_CAPACITY];
static int fifo_q_head = 0;
static int fifo_q_tail = 0;
static int fifo_q_size = 0;
static int fifo_q_dropped = 0;
static pthread_mutex_t fifo_q_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fifo_q_cv = PTHREAD_COND_INITIALIZER;
static pthread_once_t fifo_sender_once = PTHREAD_ONCE_INIT;
static pthread_t fifo_sender_thr;
static int api_parser_sock_fd = -1;
static struct sockaddr_un api_parser_sock_addr;


static int send_message_to_api_parser_direct(const char *message);

static void * fifo_sender_worker(void *arg)
{
    (void)arg;

    while (!exiting) {
        char *msg = NULL;

        pthread_mutex_lock(&fifo_q_mutex);
        while (!exiting && fifo_q_size == 0) {
            pthread_cond_wait(&fifo_q_cv, &fifo_q_mutex);
        }

        if (fifo_q_size > 0) {
            msg = fifo_msg_queue[fifo_q_head];
            fifo_msg_queue[fifo_q_head] = NULL;
            fifo_q_head = (fifo_q_head + 1) % FIFO_MSG_QUEUE_CAPACITY;
            fifo_q_size--;
        }
        pthread_mutex_unlock(&fifo_q_mutex);

        if (!msg) {
            continue;
        }

        (void)send_message_to_api_parser_direct(msg);
        free(msg);
    }

    return NULL;
}

/*
 * Block events from the BPF ring buffer used to call append_block_ip_to_sqlite() on the
 * poll thread. Opening SQLite and doing one INSERT per event synchronously stalls the whole
 * daemon (and anything sharing that thread) under SYN flood. Queue rows and flush in a
 * dedicated worker with batched transactions + WAL.
 */
#define SQLITE_BLOCK_Q_CAP 16384
typedef struct {
    char ip[INET_ADDRSTRLEN];
    int block_duration;
    char reason[512];
} sqlite_block_job_t;

static sqlite_block_job_t sqlite_block_q[SQLITE_BLOCK_Q_CAP];
static int sqlite_block_q_head;
static int sqlite_block_q_tail;
static int sqlite_block_q_size;
static int sqlite_block_q_dropped;
static pthread_mutex_t sqlite_block_q_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sqlite_block_q_cv = PTHREAD_COND_INITIALIZER;
static pthread_once_t sqlite_worker_once = PTHREAD_ONCE_INIT;
static pthread_t sqlite_worker_thr;
static int sqlite_worker_thr_valid;

static void *sqlite_block_worker_main(void *arg)
{
    (void)arg;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO blocked_ips (ip, type, duration, reason, created) "
        "VALUES (?, 'Auto', ?, ?, ?);";

    while (!stmt) {
        if (exiting)
            return NULL;
        const char *dbpath = ebpf_sqlite_db_path();
        if (sqlite3_open(dbpath, &db) != SQLITE_OK) {
            LOG_E("sqlite worker: cannot open '%s', retrying\n", dbpath);
            sleep(1);
            continue;
        }
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
        sqlite3_busy_timeout(db, 5000);
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            LOG_E("sqlite worker: prepare failed: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            db = NULL;
            sleep(1);
            continue;
        }
    }

    for (;;) {
        pthread_mutex_lock(&sqlite_block_q_mutex);
        while (sqlite_block_q_size == 0 && !exiting)
            pthread_cond_wait(&sqlite_block_q_cv, &sqlite_block_q_mutex);

        if (sqlite_block_q_size == 0 && exiting) {
            pthread_mutex_unlock(&sqlite_block_q_mutex);
            break;
        }

        sqlite_block_job_t batch[512];
        int n = 0;
        while (sqlite_block_q_size > 0 && n < 512) {
            batch[n++] = sqlite_block_q[sqlite_block_q_head];
            sqlite_block_q_head = (sqlite_block_q_head + 1) % SQLITE_BLOCK_Q_CAP;
            sqlite_block_q_size--;
        }
        pthread_mutex_unlock(&sqlite_block_q_mutex);

        if (n == 0)
            continue;

        if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
            LOG_E("sqlite worker: BEGIN failed: %s\n", sqlite3_errmsg(db));
            continue;
        }

        for (int i = 0; i < n; i++) {
            char duration_str[1024];
            if (batch[i].block_duration == 0)
                snprintf(duration_str, sizeof(duration_str), "%lld",
                         global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS);
            else
                snprintf(duration_str, sizeof(duration_str), "%d", batch[i].block_duration);

            char created[32];
            time_t now = time(NULL);
            struct tm gmt;
            gmtime_r(&now, &gmt);
            strftime(created, sizeof(created), "%Y-%m-%d %H:%M:%S", &gmt);

            sqlite3_bind_text(stmt, 1, batch[i].ip, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, duration_str, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, batch[i].reason, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, created, -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_DONE)
                LOG_E("sqlite worker: insert: %s\n", sqlite3_errmsg(db));
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
        }

        if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
            LOG_E("sqlite worker: COMMIT failed: %s\n", sqlite3_errmsg(db));
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return NULL;
}

static void sqlite_worker_start_once(void)
{
    if (pthread_create(&sqlite_worker_thr, NULL, sqlite_block_worker_main, NULL) != 0) {
        LOG_E("pthread_create sqlite_block_worker: %s\n", strerror(errno));
        sqlite_worker_thr_valid = 0;
        return;
    }
    sqlite_worker_thr_valid = 1;
}

static void init_fifo_sender_worker_once(void)
{
    int sndbuf_bytes = 4 * 1024 * 1024;

    memset(&api_parser_sock_addr, 0, sizeof(api_parser_sock_addr));
    api_parser_sock_addr.sun_family = AF_UNIX;
    strncpy(api_parser_sock_addr.sun_path, API_PARSER_UNIX_DGRAM_PATH,
            sizeof(api_parser_sock_addr.sun_path) - 1);

    /*
     * Use blocking mode in dedicated sender thread so we naturally apply
     * backpressure instead of busy-failing with EAGAIN under burst traffic.
     */
    api_parser_sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (api_parser_sock_fd < 0) {
        LOG_E("Failed to create AF_UNIX DGRAM socket: %s\n", strerror(errno));
    }
    if (api_parser_sock_fd >= 0 &&
        setsockopt(api_parser_sock_fd, SOL_SOCKET, SO_SNDBUF,
                   &sndbuf_bytes, sizeof(sndbuf_bytes)) != 0) {
        LOG_W("Failed to set AF_UNIX DGRAM SO_SNDBUF: %s\n", strerror(errno));
    }

    if (pthread_create(&fifo_sender_thr, NULL, fifo_sender_worker, NULL) != 0) {
        LOG_E("pthread_create for fifo_sender_thr %s\n", strerror(errno));
    }
}

static void sig_handler(int signo)
{
    exiting = 1;
}

static inline __u64 now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Counters only move forward. A drop means the map was cleared; keep the new value. */
static __u64 traffic_counter_delta(__u64 now, __u64 *prev)
{
    __u64 delta = (now >= *prev) ? (now - *prev) : now;
    *prev = now;
    return delta;
}

/* Bytes over elapsed_ns, expressed as bytes per one second. */
static __u64 traffic_per_second(__u64 bytes, __u64 elapsed_ns)
{
    if (elapsed_ns == 0)
        return bytes;
    return (__u64)((long double)bytes * (long double)ONE_SECOND_NS / (long double)elapsed_ns + 0.5L);
}

/* Sleep until the next whole wall-clock second; returns that second. */
static time_t sleep_until_next_second(void)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct timespec target = { .tv_sec = now.tv_sec + 1, .tv_nsec = 0 };
    while (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &target, NULL) == EINTR) {
        if (exiting)
            break;
    }
    return target.tv_sec;
}

static void * global_traffic_stats_check_worker(void * arg) {
    struct bpf_object *obj = (struct bpf_object*)arg;
    int map_fd = bpf_object__find_map_fd_by_name(obj, "global_income_pkt_traffic");
    if (map_fd < 0) {
        LOG_E( "Failed to find global_income_pkt_traffic eBPF map\n");
        return NULL;
    }

    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len)) {
        LOG_E("bpf_obj_get_info_by_fd %s\n", strerror(errno));
        return NULL;
    }

    int nr = bpf_percpu_nr_cpus();
    size_t stride = bpf_percpu_stride(info.value_size);
    size_t buf_sz = stride * (size_t)nr;
    void *raw = calloc(1, buf_sz);
    if (!raw)
        return NULL;

    /*
     * The map is a cumulative per-CPU counter. Sampling is current - previous,
     * so an increment that lands during the read stays in the map for the next
     * second instead of being wiped by a zeroing update.
     *
     * Reads happen on whole wall-clock seconds, and each delta is divided by the
     * monotonic time that really passed. If the thread wakes late and misses
     * seconds, the bytes are spread over every missed second instead of one
     * doubled sample followed by a missing timestamp.
     */
    struct traffic_stats_config baseline = {0};
    int have_baseline = 0;
    int index = 0;
    __u32 key = 0;
    time_t prev_label = 0;
    __u64 prev_mono = 0;

    while (!exiting && !have_baseline) {
        time_t label = sleep_until_next_second();
        if (bpf_map_lookup_elem(map_fd, &key, raw) == 0) {
            traffic_stats_config_sum_percpu(raw, stride, nr, &baseline);
            prev_mono = now_ns();
            prev_label = label;
            have_baseline = 1;
            break;
        }
        LOG_E("bpf_map_lookup_elem global_income_pkt_traffic: %s\n", strerror(errno));
    }

    while (!exiting) {
        time_t label = sleep_until_next_second();

        if (bpf_map_lookup_elem(map_fd, &key, raw)) {
            LOG_E("bpf_map_lookup_elem global_income_pkt_traffic: %s\n", strerror(errno));
            continue;
        }
        __u64 mono = now_ns();

        struct traffic_stats_config current = {0};
        traffic_stats_config_sum_percpu(raw, stride, nr, &current);

        struct traffic_stats_config delta = {0};
        delta.total_traffic = traffic_counter_delta(current.total_traffic, &baseline.total_traffic);
        delta.blocked_traffic = traffic_counter_delta(current.blocked_traffic, &baseline.blocked_traffic);
        delta.syn = traffic_counter_delta(current.syn, &baseline.syn);
        delta.ack = traffic_counter_delta(current.ack, &baseline.ack);
        delta.rst = traffic_counter_delta(current.rst, &baseline.rst);
        delta.tcp = traffic_counter_delta(current.tcp, &baseline.tcp);
        delta.udp = traffic_counter_delta(current.udp, &baseline.udp);
        delta.icmp = traffic_counter_delta(current.icmp, &baseline.icmp);
        delta.gre = traffic_counter_delta(current.gre, &baseline.gre);
        delta.other = traffic_counter_delta(current.other, &baseline.other);

        __u64 elapsed = mono - prev_mono;
        prev_mono = mono;

        /* Wall clock stepped backward, or jumped far ahead: keep the rate, write one slot. */
        long seconds = (long)(label - prev_label);
        if (seconds < 1 || seconds > 300)
            seconds = 1;
        prev_label = label;

        struct traffic_stats_config sample = {0};
        sample.total_traffic = traffic_per_second(delta.total_traffic, elapsed);
        sample.blocked_traffic = traffic_per_second(delta.blocked_traffic, elapsed);
        sample.syn = traffic_per_second(delta.syn, elapsed);
        sample.ack = traffic_per_second(delta.ack, elapsed);
        sample.rst = traffic_per_second(delta.rst, elapsed);
        sample.tcp = traffic_per_second(delta.tcp, elapsed);
        sample.udp = traffic_per_second(delta.udp, elapsed);
        sample.icmp = traffic_per_second(delta.icmp, elapsed);
        sample.gre = traffic_per_second(delta.gre, elapsed);
        sample.other = traffic_per_second(delta.other, elapsed);
        if (sample.blocked_traffic <= sample.total_traffic)
            sample.allowed_traffic = sample.total_traffic - sample.blocked_traffic;
        else
            sample.allowed_traffic = 0;

        for (long s = seconds - 1; s >= 0; s--) {
            sample.timestamp = (__u64)(label - s);
            memcpy(&global_traffic_stats[index], &sample, sizeof(sample));
            index = (index + 1) % TRAFFIC_STATS_SLOTS;
        }
    }

    free(raw);
    return NULL;
}


static void * global_attack_check_worker(void * arg) {

    int nr = bpf_percpu_nr_cpus();
    size_t vsize = sizeof(__u64) * (size_t)nr;
    __u64 *values = calloc((size_t)nr, sizeof(__u64));
    void *raw = NULL;
    void *det_raw = NULL;

    if (!values)
        goto cleanup; 

    struct bpf_object *obj = (struct bpf_object*)arg;

    int global_syn_pkt_counter_map_fd, global_ack_pkt_counter_map_fd, global_rst_pkt_counter_map_fd, global_icmp_pkt_counter_map_fd, global_udp_pkt_counter_map_fd, global_gre_pkt_counter_map_fd;

    int bss_map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    if (bss_map_fd < 0) {
        LOG_E("ERROR: finding .bss map fd: %d\n", bss_map_fd);
        goto cleanup;
    }
    
    global_syn_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_syn_pkt_counter");
    if (global_syn_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_syn_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_ack_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_ack_pkt_counter");
    if (global_ack_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_ack_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_rst_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_rst_pkt_counter");
    if (global_rst_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_rst_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_icmp_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_icmp_pkt_counter");
    if (global_icmp_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_icmp_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_udp_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_udp_pkt_counter");
    if (global_udp_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_udp_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_gre_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_gre_pkt_counter");
    if (global_gre_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_gre_pkt_counter eBPF map\n");
        goto cleanup;
    }

    int income_stats_fd = bpf_object__find_map_fd_by_name(obj, "global_income_pkt_counter");
    if (income_stats_fd < 0) {
        LOG_E( "Failed to find global_income_pkt_counter eBPF map\n");
        goto cleanup;
    }

    int tcp_connection_map_fd = bpf_object__find_map_fd_by_name(obj, "tcp_connection_map");
    if (tcp_connection_map_fd < 0) {
        LOG_E( "Failed to find tcp_connection eBPF map\n");
        goto cleanup;
    }

    int global_stomp_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_stomp_pkt_counter");
    if (global_stomp_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_stomp_pkt_counter eBPF map\n");
        goto cleanup;
    }
    int global_socket_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_socket_pkt_counter");
    if (global_socket_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_socket_pkt_counter eBPF map\n");
        goto cleanup;
    }
    (void)global_socket_pkt_counter_map_fd; /* kept for map presence check; H3 does not drain */
    int global_handshake_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_handshake_pkt_counter");
    if (global_handshake_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_handshake_pkt_counter eBPF map\n");
        goto cleanup;
    }
    int global_synack_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_synack_pkt_counter");
    if (global_synack_pkt_counter_map_fd < 0) {
        LOG_E( "Failed to find global_synack_pkt_counter eBPF map\n");
        goto cleanup;
    }
    int global_psh_ack_filtered_map_fd = bpf_object__find_map_fd_by_name(obj, "global_psh_ack_filtered");
    if (global_psh_ack_filtered_map_fd < 0) {
        LOG_E( "Failed to find global_psh_ack_filtered eBPF map\n");
        goto cleanup;
    }

    int det_class_totals_fd = bpf_object__find_map_fd_by_name(obj, "det_class_totals");
    if (det_class_totals_fd < 0) {
        LOG_E("Failed to find det_class_totals eBPF map\n");
        goto cleanup;
    }
    int invalid_totals_fd = bpf_object__find_map_fd_by_name(obj, "invalid_totals");
    if (invalid_totals_fd < 0) {
        LOG_E("Failed to find invalid_totals eBPF map\n");
        goto cleanup;
    }

    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(income_stats_fd, &info, &info_len)) {
        LOG_E("bpf_obj_get_info_by_fd %s\n", strerror(errno));
        goto cleanup;
    }
    size_t inc_stride = bpf_percpu_stride(info.value_size);
    size_t inc_buf = inc_stride * (size_t)nr;
    raw = calloc(1, inc_buf);
    if (!raw)
        goto cleanup;

    /* Phase 0 H3: cumulative counters; sample as current - previous (no zeroing). */
    __u64 prev_syn = 0, prev_ack = 0, prev_rst = 0, prev_icmp = 0, prev_udp = 0, prev_gre = 0;
    __u64 prev_stomp = 0, prev_handshake = 0, prev_synack = 0, prev_psh_filt = 0;
    struct stats_config prev_income = {0};
    struct det_snapshot prev_det = {0};
    int have_baseline = 0;
    int have_det_baseline = 0;

    size_t det_stride = bpf_percpu_stride(sizeof(struct det_val));
    size_t det_buf_sz = det_stride * (size_t)nr;
    det_raw = calloc(1, det_buf_sz);
    if (!det_raw)
        goto cleanup;

    while (!exiting) {
        __u32 key = 0;
        time_t now = time(NULL);     /* current epoch seconds */

        struct global_attack_stats * global_attack_stats_val =&global_fw_config.g_attack_stats;

        #define READ_PERCPU_SUM(map_fd, out) do { \
            if (bpf_map_lookup_elem((map_fd), &key, values)) { \
                LOG_E("bpf_map_lookup_elem"); \
                goto cleanup; \
            } \
            (out) = 0; \
            for (int cpu = 0; cpu < nr; cpu++) \
                (out) += values[cpu]; \
        } while (0)

        __u64 cur_syn = 0, cur_ack = 0, cur_rst = 0, cur_icmp = 0, cur_udp = 0, cur_gre = 0;
        __u64 cur_stomp = 0, cur_handshake = 0, cur_synack = 0, cur_psh_filt = 0;

        READ_PERCPU_SUM(global_syn_pkt_counter_map_fd, cur_syn);
        READ_PERCPU_SUM(global_ack_pkt_counter_map_fd, cur_ack);
        READ_PERCPU_SUM(global_rst_pkt_counter_map_fd, cur_rst);
        READ_PERCPU_SUM(global_icmp_pkt_counter_map_fd, cur_icmp);
        READ_PERCPU_SUM(global_udp_pkt_counter_map_fd, cur_udp);
        READ_PERCPU_SUM(global_gre_pkt_counter_map_fd, cur_gre);
        READ_PERCPU_SUM(global_stomp_pkt_counter_map_fd, cur_stomp);
        READ_PERCPU_SUM(global_handshake_pkt_counter_map_fd, cur_handshake);
        READ_PERCPU_SUM(global_synack_pkt_counter_map_fd, cur_synack);
        READ_PERCPU_SUM(global_psh_ack_filtered_map_fd, cur_psh_filt);
        #undef READ_PERCPU_SUM

        if (bpf_map_lookup_elem(income_stats_fd, &key, raw)) {
            LOG_E( "bpf_map_lookup_elem");
            goto cleanup;
        }
        struct stats_config cur_income = {0};
        stats_config_sum_percpu(raw, inc_stride, nr, &cur_income);

        if (!have_baseline) {
            prev_syn = cur_syn; prev_ack = cur_ack; prev_rst = cur_rst;
            prev_icmp = cur_icmp; prev_udp = cur_udp; prev_gre = cur_gre;
            prev_stomp = cur_stomp; prev_handshake = cur_handshake;
            prev_synack = cur_synack; prev_psh_filt = cur_psh_filt;
            prev_income = cur_income;
            have_baseline = 1;
            sleep(1);
            continue;
        }

        __u64 total_syn_cnt = traffic_counter_delta(cur_syn, &prev_syn);
        __u64 total_ack_cnt = traffic_counter_delta(cur_ack, &prev_ack);
        __u64 total_rst_cnt = traffic_counter_delta(cur_rst, &prev_rst);
        __u64 total_icmp_cnt = traffic_counter_delta(cur_icmp, &prev_icmp);
        __u64 total_udp_cnt = traffic_counter_delta(cur_udp, &prev_udp);
        __u64 total_gre_cnt = traffic_counter_delta(cur_gre, &prev_gre);
        __u64 total_stomp_cnt = traffic_counter_delta(cur_stomp, &prev_stomp);
        __u64 total_handshake_cnt = traffic_counter_delta(cur_handshake, &prev_handshake);
        __u64 total_synack_cnt = traffic_counter_delta(cur_synack, &prev_synack);
        __u64 total_psh_ack_filtered = traffic_counter_delta(cur_psh_filt, &prev_psh_filt);

        struct stats_config aggregate = {0};
        aggregate.syn = traffic_counter_delta(cur_income.syn, &prev_income.syn);
        aggregate.ack = traffic_counter_delta(cur_income.ack, &prev_income.ack);
        aggregate.rst = traffic_counter_delta(cur_income.rst, &prev_income.rst);
        aggregate.fin = traffic_counter_delta(cur_income.fin, &prev_income.fin);
        aggregate.psh = traffic_counter_delta(cur_income.psh, &prev_income.psh);
        aggregate.urg = traffic_counter_delta(cur_income.urg, &prev_income.urg);
        aggregate.syn_ack = traffic_counter_delta(cur_income.syn_ack, &prev_income.syn_ack);
        aggregate.fin_ack = traffic_counter_delta(cur_income.fin_ack, &prev_income.fin_ack);
        aggregate.rst_ack = traffic_counter_delta(cur_income.rst_ack, &prev_income.rst_ack);
        aggregate.psh_ack = traffic_counter_delta(cur_income.psh_ack, &prev_income.psh_ack);
        aggregate.icmp = traffic_counter_delta(cur_income.icmp, &prev_income.icmp);
        aggregate.udp = traffic_counter_delta(cur_income.udp, &prev_income.udp);
        aggregate.gre = traffic_counter_delta(cur_income.gre, &prev_income.gre);

        time_t rawtime;
        struct tm *tm_info;
        time(&rawtime);
        tm_info = localtime(&rawtime);

        __u8 need_to_update = false;
        __u8 syn_attack = false, ack_attack = false, rst_attack = false, icmp_attack = false, udp_attack = false, gre_attack = false, stomp_attack = false, handshake_attack = false;

        __u8 prefer_adaptive = global_fw_config.g_config.prefer_adaptive;

        /* Under prefer_adaptive, shadow owns START/END + attack flags. */
        if (prefer_adaptive)
            goto skip_classic_protection;

        if (total_syn_cnt >= global_fw_config.g_syn_config.syn_threshold) syn_attack = true;
        else syn_attack = false;

        if (syn_attack != global_attack_stats_val->syn_attack) {
            if (syn_attack == true) {
                if (now >= global_attack_stats_val->syn_protect_expire) {
                    global_attack_stats_val->syn_protect_expire = now + global_fw_config.g_syn_config.syn_protect_duration;
                    //LOG_D("Send backend to now is %lld, syn_protect_expire %lld\n", now, global_attack_stats_val->syn_protect_expire);

                    if (global_attack_stats_val->global_req_id == 0)
                        global_attack_stats_val->global_req_id = generate_attack_req_id();
                    print_firewall_status(tm_info, EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->syn_attack = syn_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->syn_protect_expire) {
                    //LOG_D("Send backend to now is %lld, syn_protect_expire %lld\n", now, global_attack_stats_val->syn_protect_expire);
                    print_firewall_status(tm_info, EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->syn_attack = syn_attack;
                    need_to_update = true;
                }
            }
        }

        if (total_ack_cnt >= global_fw_config.g_ack_config.ack_threshold) ack_attack = true;
        else ack_attack = false;
        if (ack_attack != global_attack_stats_val->ack_attack) {
            if (ack_attack == true) {
                if (now >= global_attack_stats_val->ack_protect_expire) {
                    global_attack_stats_val->ack_protect_expire = now + global_fw_config.g_ack_config.ack_protect_duration;
                    //LOG_D("Send backend to now is %lld, ack_protect_expire %lld\n", now, global_attack_stats_val->ack_protect_expire);
                    if (global_attack_stats_val->global_req_id == 0)
                        global_attack_stats_val->global_req_id = generate_attack_req_id();
                    print_firewall_status(tm_info, EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->ack_attack = ack_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->ack_protect_expire) {
                    //LOG_D("Send backend to now is %lld, ack_protect_expire %lld\n", now, global_attack_stats_val->ack_protect_expire);
                    print_firewall_status(tm_info, EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->ack_attack = ack_attack;
                    need_to_update = true;
                }
            }
        }

        if (total_rst_cnt >= global_fw_config.g_rst_config.rst_threshold) rst_attack = true;
        else rst_attack = false;
        if (rst_attack != global_attack_stats_val->rst_attack) {
            if (rst_attack == true) {
                if (now >= global_attack_stats_val->rst_protect_expire) {
                    global_attack_stats_val->rst_protect_expire = now + global_fw_config.g_rst_config.rst_protect_duration;
                    if (global_attack_stats_val->global_req_id == 0)
                        global_attack_stats_val->global_req_id = generate_attack_req_id();
                    print_firewall_status(tm_info, EVENT_TCP_RST_ATTACK_PROTECION_MODE_START, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->rst_attack = rst_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->rst_protect_expire) {
                    print_firewall_status(tm_info, EVENT_TCP_RST_ATTACK_PROTECION_MODE_END, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->rst_attack = rst_attack;
                    need_to_update = true;
                }
            }
        }

        if (total_icmp_cnt >= global_fw_config.g_icmp_config.icmp_threshold) icmp_attack = true;
        else icmp_attack = false;
        if (icmp_attack != global_attack_stats_val->icmp_attack) {
            if (icmp_attack == true) {
                if (now >= global_attack_stats_val->icmp_protect_expire) {
                    global_attack_stats_val->icmp_protect_expire = now + global_fw_config.g_icmp_config.icmp_protect_duration;
                    if (global_attack_stats_val->global_req_id == 0)
                        global_attack_stats_val->global_req_id = generate_attack_req_id();
                    print_firewall_status(tm_info, EVENT_ICMP_ATTACK_PROTECION_MODE_START, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->icmp_attack = icmp_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->icmp_protect_expire) {
                    print_firewall_status(tm_info, EVENT_ICMP_ATTACK_PROTECION_MODE_END, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->icmp_attack = icmp_attack;
                    need_to_update = true;
                }
            }
        }

        if (total_udp_cnt >= global_fw_config.g_udp_config.udp_threshold) udp_attack = true;
        else udp_attack = false;
        if (udp_attack != global_attack_stats_val->udp_attack) {
            if (udp_attack == true) {
                if (now >= global_attack_stats_val->udp_protect_expire) {
                    global_attack_stats_val->udp_protect_expire = now + global_fw_config.g_udp_config.udp_protect_duration;
                    if (global_attack_stats_val->global_req_id == 0)
                        global_attack_stats_val->global_req_id = generate_attack_req_id();
                    print_firewall_status(tm_info, EVENT_UDP_ATTACK_PROTECION_MODE_START, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->udp_attack = udp_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->udp_protect_expire) {
                    print_firewall_status(tm_info, EVENT_UDP_ATTACK_PROTECION_MODE_END, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->udp_attack = udp_attack;
                    need_to_update = true;
                }
            }
        }

        if (total_gre_cnt >= global_fw_config.g_gre_config.gre_threshold) gre_attack = true;
        else gre_attack = false;
        if (gre_attack != global_attack_stats_val->gre_attack) {
            if (gre_attack == true) {
                if (now >= global_attack_stats_val->gre_protect_expire) {
                    global_attack_stats_val->gre_protect_expire = now + global_fw_config.g_gre_config.gre_protect_duration;
                    if (global_attack_stats_val->global_req_id == 0)
                        global_attack_stats_val->global_req_id = generate_attack_req_id();
                    print_firewall_status(tm_info, EVENT_GRE_ATTACK_PROTECION_MODE_START, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->gre_attack = gre_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->gre_protect_expire) {
                    print_firewall_status(tm_info, EVENT_GRE_ATTACK_PROTECION_MODE_END, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->gre_attack = gre_attack;
                    need_to_update = true;
                }
            }
        }

        /* Phase 0 N2/H7: STOMP and HANDSHAKE are independent. SYN+ACK has its
         * own counter but reuses handshake_threshold / handshake_attack. */
        if (global_fw_config.g_stomp_config.valid &&
            total_stomp_cnt >= global_fw_config.g_stomp_config.stomp_threshold)
            stomp_attack = true;
        if (global_fw_config.g_handshake_config.valid) {
            __u32 hs_gate = global_fw_config.g_handshake_config.handshake_threshold;
            if (total_handshake_cnt >= hs_gate || total_synack_cnt >= hs_gate)
                handshake_attack = true;
        }

        if (stomp_attack != global_attack_stats_val->stomp_attack) {
            if (stomp_attack == true) {
                if (now >= global_attack_stats_val->stomp_protect_expire) {
                    global_attack_stats_val->stomp_protect_expire = now + global_fw_config.g_stomp_config.stomp_protect_duration;
                    if (global_attack_stats_val->global_req_id == 0)
                        global_attack_stats_val->global_req_id = generate_attack_req_id();
                    print_firewall_status(tm_info, EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_START, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->stomp_attack = stomp_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->stomp_protect_expire) {
                    print_firewall_status(tm_info, EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_END, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->stomp_attack = stomp_attack;
                    need_to_update = true;
                }
            }
        }

        if (handshake_attack != global_attack_stats_val->handshake_attack) {
            if (handshake_attack == true) {
                if (now >= global_attack_stats_val->handshake_protect_expire) {
                    global_attack_stats_val->handshake_protect_expire = now + global_fw_config.g_handshake_config.handshake_protect_duration;
                    if (global_attack_stats_val->global_req_id == 0)
                        global_attack_stats_val->global_req_id = generate_attack_req_id();
                    print_firewall_status(tm_info, EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_START, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->handshake_attack = handshake_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->handshake_protect_expire) {
                    print_firewall_status(tm_info, EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_END, 0, global_attack_stats_val->global_req_id);
                    global_attack_stats_val->handshake_attack = handshake_attack;
                    need_to_update = true;
                }
            }
        }

skip_classic_protection:
        if (need_to_update == true) {
            bpf_map_update_elem(bss_map_fd, &key, &global_fw_config, BPF_ANY);
        }

        LOG_T(
            "SYN:%5llu/%-5llu "
            "ACK:%5llu/%-5llu "
            "RST:%4llu/%-4llu "
            "PSH:%4llu "
            "FIN:%4llu "
            "URG:%4llu "
            "SYN+ACK:%5llu/%-5llu "
            "FIN+ACK:%4llu "
            "RST+ACK:%4llu "
            "PSH+ACK:%4llu/%-5llu "
            "STOMP:%5llu "
            "HANDSHAKE:%5llu "
            "ICMP:%4llu/%-4llu "
            "UDP:%5llu/%-5llu "
            "GRE:%llu/%llu\n",
            aggregate.syn,  total_syn_cnt,
            aggregate.ack,  total_ack_cnt,
            aggregate.rst,  total_rst_cnt,
            aggregate.psh,
            aggregate.fin,
            aggregate.urg,
            aggregate.syn_ack, total_synack_cnt,
            aggregate.fin_ack,
            aggregate.rst_ack,
            aggregate.psh_ack, total_psh_ack_filtered,
            total_stomp_cnt,
            total_handshake_cnt,
            aggregate.icmp, total_icmp_cnt,
            aggregate.udp,  total_udp_cnt,
            aggregate.gre,  total_gre_cnt);
        
        memcpy(&global_receive_stats, &aggregate, sizeof (struct stats_config));
        
        global_passed_stats.syn = total_syn_cnt;
        global_passed_stats.ack = total_ack_cnt;
        global_passed_stats.rst = total_rst_cnt;
        global_passed_stats.psh = aggregate.psh;
        global_passed_stats.fin = aggregate.fin;
        global_passed_stats.urg = aggregate.urg;
        global_passed_stats.syn_ack = total_synack_cnt;
        global_passed_stats.fin_ack = aggregate.fin_ack;
        global_passed_stats.rst_ack = aggregate.rst_ack;
        global_passed_stats.psh_ack = total_stomp_cnt + total_handshake_cnt;
        global_passed_stats.icmp = total_icmp_cnt;
        global_passed_stats.udp = total_udp_cnt;
        global_passed_stats.gre = total_gre_cnt;

        /* Phase 1: host-wide {class,invalid} totals (monotonic deltas). */
        {
            struct det_snapshot cur = {0};
            for (__u32 c = 0; c < DET_CLASS_MAX; c++) {
                if (bpf_map_lookup_elem(det_class_totals_fd, &c, det_raw) != 0)
                    continue;
                for (int cpu = 0; cpu < nr; cpu++) {
                    const struct det_val *p =
                        (const struct det_val *)((const char *)det_raw + cpu * det_stride);
                    cur.class_pkts[c] += p->pkts;
                    cur.class_bytes[c] += p->bytes;
                }
            }
            for (__u32 r = 0; r < INVALID_REASON_MAX; r++) {
                if (bpf_map_lookup_elem(invalid_totals_fd, &r, values) != 0)
                    continue;
                for (int cpu = 0; cpu < nr; cpu++)
                    cur.invalid_pkts[r] += values[cpu];
            }
            for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++) {
                cur.total_pkts += cur.class_pkts[c];
                cur.total_bytes += cur.class_bytes[c];
            }

            if (!have_det_baseline) {
                prev_det = cur;
                have_det_baseline = 1;
            } else {
                struct det_snapshot delta = {0};
                for (__u32 c = 0; c < DET_CLASS_MAX; c++) {
                    delta.class_pkts[c] =
                        traffic_counter_delta(cur.class_pkts[c], &prev_det.class_pkts[c]);
                    delta.class_bytes[c] =
                        traffic_counter_delta(cur.class_bytes[c], &prev_det.class_bytes[c]);
                }
                for (__u32 r = 0; r < INVALID_REASON_MAX; r++) {
                    delta.invalid_pkts[r] =
                        traffic_counter_delta(cur.invalid_pkts[r], &prev_det.invalid_pkts[r]);
                }
                for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++) {
                    delta.total_pkts += delta.class_pkts[c];
                    delta.total_bytes += delta.class_bytes[c];
                }
                global_det_stats = delta;
                LOG_T("DET pkts=%llu bytes=%llu SYN=%llu ACK=%llu SYNACK=%llu RST=%llu "
                      "DATA=%llu SOCKET=%llu ICMP=%llu UDP=%llu GRE=%llu OTHER=%llu "
                      "STOMP_lbl=%llu HS_lbl=%llu inv=%llu\n",
                      delta.total_pkts, delta.total_bytes,
                      delta.class_pkts[DET_CLASS_SYN],
                      delta.class_pkts[DET_CLASS_ACK],
                      delta.class_pkts[DET_CLASS_SYNACK],
                      delta.class_pkts[DET_CLASS_RST],
                      delta.class_pkts[DET_CLASS_DATA],
                      delta.class_pkts[DET_CLASS_SOCKET],
                      delta.class_pkts[DET_CLASS_ICMP],
                      delta.class_pkts[DET_CLASS_UDP],
                      delta.class_pkts[DET_CLASS_GRE],
                      delta.class_pkts[DET_CLASS_OTHER],
                      delta.class_pkts[DET_CLASS_STOMP],
                      delta.class_pkts[DET_CLASS_HANDSHAKE],
                      delta.invalid_pkts[INVALID_BAD_IHL] +
                          delta.invalid_pkts[INVALID_BAD_DOFF] +
                          delta.invalid_pkts[INVALID_LAND] +
                          delta.invalid_pkts[INVALID_TCP_FRAG] +
                          delta.invalid_pkts[INVALID_FLAG_NULL] +
                          delta.invalid_pkts[INVALID_FLAG_XMAS] +
                          delta.invalid_pkts[INVALID_FLAG_SYN_FIN] +
                          delta.invalid_pkts[INVALID_FLAG_SYN_RST] +
                          delta.invalid_pkts[INVALID_FLAG_SYN_URG] +
                          delta.invalid_pkts[INVALID_FLAG_FIN_ONLY]);
            }
        }

        sleep (1);
    }

cleanup:
    if (det_raw) free(det_raw);
    if (raw) free(raw);
    if (values) free (values);
    return NULL;
}

static void *blocked_ips_duration_check_worker(void *arg) {
    struct bpf_object *obj = (struct bpf_object*)arg;
    if (!obj) goto cleanup;

    int blocked_ips_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (blocked_ips_fd < 0) {
        LOG_E( "Failed to find blocked_ips\n");
        goto cleanup;
    }

    while (1) {
        struct bpf_map_info info = {};
        __u32 len = sizeof(info);
        if (bpf_obj_get_info_by_fd(blocked_ips_fd, &info, &len)) {
            LOG_E( "bpf_obj_get_info_by_fd failed\n");
            goto cleanup;
        }

        void *key  = calloc(1, info.key_size);
        void *next = calloc(1, info.key_size);
        void *val  = malloc(info.value_size);
        if (!key || !next || !val) {
            LOG_E( "Failed to allocate memory\n");
            goto cleanup;
        }

        const __u64 t_now = now_ns();
        char ip_str[INET_ADDRSTRLEN];

        // Dynamic array for expired keys
        void **keys_to_delete = NULL;
        size_t delete_capacity = 0;
        size_t delete_count = 0;

        // First pass: Identify expired keys
        while (!bpf_map_get_next_key(blocked_ips_fd, key, next)) {
            if (bpf_map_lookup_elem(blocked_ips_fd, next, val)) {
                break;
            }

            __u64 exp_ns = *(__u64 *)val;
            if (exp_ns != -1 && exp_ns <= t_now) {
                // Resize array if full
                if (delete_count >= delete_capacity) {
                    delete_capacity = delete_capacity ? delete_capacity * 2 : 16; // Start with 16, double when needed
                    void **new_array = realloc(keys_to_delete, delete_capacity * sizeof(void *));
                    if (!new_array) {
                        LOG_E( "Failed to realloc keys_to_delete\n");
                        goto delete_cleanup;
                    }
                    keys_to_delete = new_array;
                }

                // Store the key to delete
                keys_to_delete[delete_count] = malloc(info.key_size);
                if (!keys_to_delete[delete_count]) {
                    LOG_E( "Failed to malloc key storage\n");
                    goto delete_cleanup;
                }
                memcpy(keys_to_delete[delete_count], next, info.key_size);
                delete_count++;
            }
            memcpy(key, next, info.key_size);
        }

        time_t rawtime;
        struct tm *tm_info;
        time(&rawtime);
        tm_info = localtime(&rawtime);

        // Second pass: Delete expired keys
        for (size_t i = 0; i < delete_count; i++) {
            __u32 ip = *(__u32 *)keys_to_delete[i];
            print_firewall_status(tm_info, EVENT_IP_BLOCK_END, ip, 0);
            bpf_map_delete_elem(blocked_ips_fd, keys_to_delete[i]);
            free(keys_to_delete[i]);
        }

delete_cleanup:
        if (keys_to_delete) free(keys_to_delete);
        if (key) free(key); 
        if (next) free(next); 
        if (val) free(val);

        sleep(1);
    }

cleanup:
    return NULL;
}

static int ringbuf_handle_event(void *ctx, void *data, size_t size)
{
    struct event *e = data;
    /* Convert monotonic time to real time by adding the offset */
    __u64 real_time_ns = e->time + time_offset_ns;
    /* Apply timezone offset (CST = UTC+8) */
    real_time_ns += tz_offset_sec * ONE_SECOND_NS;
    time_t seconds = real_time_ns / ONE_SECOND_NS;

    struct tm tm_info;
    if (localtime_r(&seconds, &tm_info) == NULL) {
        LOG_E( "localtime_r error\n");
        return -1;
    }

    print_firewall_status(&tm_info, e->reason, e->srcip, e->req_id);
    return 0;
}

char str_fixed_ip_ring_buf_type[256][128] = {
    "UNKNOWN",
    "FIXED_IP_RING_BUF_SYN",        /* 1 */
    "FIXED_IP_RING_BUF_ACK",        /* 2 */
    "FIXED_IP_RING_BUF_RST",        /* 3 */
    "FIXED_IP_RING_BUF_PSH",        /* 4 */
    "FIXED_IP_RING_BUF_URG",        /* 5 */
    "FIXED_IP_RING_BUF_FIN",        /* 6 */
    "FIXED_IP_RING_BUF_SYN_ACK",    /* 7 */
    "FIXED_IP_RING_BUF_RST_ACK",    /* 8 */
    "FIXED_IP_RING_BUF_FIN_ACK",    /* 9 */
    "FIXED_IP_RING_BUF_UDP",        /* 10 */
    "FIXED_IP_RING_BUF_ICMP",       /* 11 */
    "FIXED_IP_RING_BUF_GRE",        /* 12 */
    "FIXED_IP_RING_BUF_STOMP",      /* 13 */
    "FIXED_IP_RING_BUF_HANDSHAKE",  /* 14 */
    "FIXED_IP_RING_BUF_SOCKET",     /* 15 */
};


static int fixed_ip_ringbuf_handle_event(void *ctx, void *data, size_t size)
{
    struct fixed_ip_event *e = data;

    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->srcip, src, sizeof(src));
    if (e->fixed_type >= 0 && e->fixed_type <= FIXED_IP_RING_BUF_SOCKET) {
        if (e->duration == 0) {
            LOG_E("Fixed checked duration is 0\n");
            return 0;
        }

        //LOG_D("Received fixed ip ringbuf handle event [%d] duration is [%llu]s\n", e->over_fixed, (__u64)e->duration / ONE_SECOND_NS);
        
        __u64 expected_pps = 0;

        if (e->over_fixed == 0) {
            LOG_D("[NORMAL] %s %s total:%llu -> %llupps\n", str_fixed_ip_ring_buf_type[e->fixed_type], src, e->pkt_count, (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS)));
        }

        switch (e->fixed_type) {
            case FIXED_IP_RING_BUF_SYN: {
                if (e->over_fixed == 0) {
                    expected_pps = (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.normal_syn < expected_pps) global_max_ip_pkt_stats.normal_syn = expected_pps;
                } else {
                    expected_pps = (__u64)((double)global_fw_config.g_syn_config.syn_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_syn_config.syn_fixed_check_duration / ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.attack_syn < expected_pps) global_max_ip_pkt_stats.attack_syn = expected_pps;
                }
                break;
            }
            case FIXED_IP_RING_BUF_ACK: {
                if (e->over_fixed == 0) {
                    expected_pps = (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.normal_ack < expected_pps) global_max_ip_pkt_stats.normal_ack = expected_pps;
                } else {
                    expected_pps = (__u64)((double)global_fw_config.g_ack_config.ack_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_ack_config.ack_fixed_check_duration / ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.attack_ack < expected_pps) global_max_ip_pkt_stats.attack_ack = expected_pps;
                }
                break;
            }
            case FIXED_IP_RING_BUF_RST: {
                if (e->over_fixed == 0) {
                    expected_pps = (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.normal_rst < expected_pps) global_max_ip_pkt_stats.normal_rst = expected_pps;
                } else {
                    expected_pps = (__u64)((double)global_fw_config.g_rst_config.rst_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_rst_config.rst_fixed_check_duration / ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.attack_rst < expected_pps) global_max_ip_pkt_stats.attack_rst = expected_pps;
                }
                break;
            }

            case FIXED_IP_RING_BUF_UDP: {
                if (e->over_fixed == 0) {
                    expected_pps = (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.normal_udp < expected_pps) global_max_ip_pkt_stats.normal_udp = expected_pps;
                } else {
                    expected_pps = (__u64)((double)global_fw_config.g_udp_config.udp_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_udp_config.udp_fixed_check_duration / ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.attack_udp < expected_pps) global_max_ip_pkt_stats.attack_udp = expected_pps;
                }
                break;
            }
            case FIXED_IP_RING_BUF_ICMP: {
                if (e->over_fixed == 0) {
                    expected_pps = (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.normal_icmp < expected_pps) global_max_ip_pkt_stats.normal_icmp = expected_pps;
                } else {
                    expected_pps = (__u64)((double)global_fw_config.g_icmp_config.icmp_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_icmp_config.icmp_fixed_check_duration / ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.attack_icmp < expected_pps) global_max_ip_pkt_stats.attack_icmp = expected_pps;
                }
                break;
            }
            case FIXED_IP_RING_BUF_GRE: {
                if (e->over_fixed == 0) {
                    expected_pps = (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.normal_gre < expected_pps) global_max_ip_pkt_stats.normal_gre = expected_pps;
                } else {
                    expected_pps = (__u64)((double)global_fw_config.g_gre_config.gre_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_gre_config.gre_fixed_check_duration / ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.attack_gre < expected_pps) global_max_ip_pkt_stats.attack_gre = expected_pps;
                }
                break;
            }
            case FIXED_IP_RING_BUF_STOMP: {
                if (e->over_fixed == 0) {
                    expected_pps = (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.normal_stomp < expected_pps) global_max_ip_pkt_stats.normal_stomp = expected_pps;
                } else {
                    expected_pps = (__u64)((double)global_fw_config.g_stomp_config.stomp_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_stomp_config.stomp_fixed_check_duration / ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.attack_stomp < expected_pps) global_max_ip_pkt_stats.attack_stomp = expected_pps;
                }
                break;
            }
            case FIXED_IP_RING_BUF_HANDSHAKE: {
                if (e->over_fixed == 0) {
                    expected_pps = (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.normal_handshake < expected_pps) global_max_ip_pkt_stats.normal_handshake = expected_pps;
                } else {
                    expected_pps = (__u64)((double)global_fw_config.g_handshake_config.handshake_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_handshake_config.handshake_fixed_check_duration / ONE_SECOND_NS));
                    if (global_max_ip_pkt_stats.attack_handshake < expected_pps) global_max_ip_pkt_stats.attack_handshake = expected_pps;
                }
                break;
            }

            case FIXED_IP_RING_BUF_PSH:
            case FIXED_IP_RING_BUF_URG:
            case FIXED_IP_RING_BUF_FIN:
            case FIXED_IP_RING_BUF_SYN_ACK:
            case FIXED_IP_RING_BUF_RST_ACK:
            case FIXED_IP_RING_BUF_FIN_ACK:
            {
                expected_pps = (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS));
                break;
            }
            // default: {
            //     expected_pps = (__u64)((double)global_fw_config.g_syn_config.syn_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_syn_config.syn_fixed_check_duration / ONE_SECOND_NS));
            //     break;
            // }
        }
        
        if (e->over_fixed == 1)
            LOG_C("DETECT over-fixed %s src=%s rate≈%llu pps\n",
                  str_fixed_ip_ring_buf_type[e->fixed_type], src, expected_pps);

    } else {
        LOG_E("Unknown fixed ip type\n");
    }
    
    return 0;
}

time_t convert_timet(const char* str) {
    const char* prefix = "skycloud-";
    const char* remaining = str + strlen(prefix);
    time_t time = (time_t)atoi(remaining);
    return time;
}


void handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt_aes256(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handle_errors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  handle_errors();
        ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_aes256(unsigned char *ciphertext, int ciphertext_len, unsigned char  *key, unsigned char *plaintext, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handle_errors();
        plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

static void phex(uint8_t* str, int len) {
    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

int check_token() {
  uint8_t iv[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };
  unsigned char key[] = "2023sKYcLOUdkEyskYcloUDkeY175201";
  
  if (strlen(token) == 0) {
    LOG_E("Please input token\n");
    return 1;
  }

  unsigned char base64DecodeOutput[1024], aesDecrypt[1024];
  int decoded_len = base64_decode(token, strlen(token), (unsigned char *)base64DecodeOutput); 
  LOG_D("Base64 decrypt: ");
  phex((unsigned char *)base64DecodeOutput, decoded_len);

  /* Encrypt the plaintext */
  int ciphertext_len = decrypt_aes256(base64DecodeOutput, decoded_len, key, aesDecrypt, iv);

  LOG_D("CBC decrypt: %s\n", aesDecrypt);

  time_t convertedTime = convert_timet((char *)aesDecrypt);
  LOG_D("Converted time_t: %ld\n", convertedTime);
  
  time_t epoch = time(NULL);
  LOG_D("current epoch: %lu\n", epoch);

  LOG_D("Time diff is %ld seconds\n", epoch - convertedTime);

  if (epoch - convertedTime > 100) {
    LOG_W("Old or bad Token\n");
    return 1;
  }
  
  return 0;
}

static void * fixed_ip_ringbuf_poll_worker(void * arg)
{
    int err;
    
    struct ring_buffer * fixed_ip_ringbuf = (struct ring_buffer *)arg;
    if (fixed_ip_ringbuf == NULL) {
        LOG_E( "Invalid arg is received\n");
        return NULL;

    }
    // Wait until terminated.
    while (!exiting) {
        err = ring_buffer__poll(fixed_ip_ringbuf, -1 /* block */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        
        if (err < 0) {
            LOG_E( "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    return NULL;
}


static void * license_check_worker(void * arg) 
{
    int transient_failures = 0;

    while (!exiting) {
        int ret = get_license_status();
        if (ret < 0) {
            if (ret == -3) {
                /* Transient read/open failure (e.g. fd pressure): retry. */
                transient_failures++;
                LOG_W("Transient license check failure (%d)\n", transient_failures);
                sleep(5);
                continue;
            } else if (ret == -2) {
                const char * message = "command:report_license\ndata:expired\n";
                send_message_to_api_parser(message);
            } else {
                const char * message = "command:report_license\ndata:manipulated\n";
                send_message_to_api_parser(message);
            }
            
            LOG_D("Exit process\n");
            exiting = 1;
            kill(getpid(), SIGINT);

            break;
        }
        transient_failures = 0;
        sleep(LICENSE_CHECK_INTERVAL);
    }
}

static int attack_episode_active(const struct global_attack_stats *stats)
{
    return stats->syn_attack || stats->ack_attack || stats->rst_attack ||
           stats->icmp_attack || stats->udp_attack || stats->gre_attack ||
           stats->stomp_attack || stats->handshake_attack ||
           stats->synack_attack || stats->socket_attack ||
           stats->fin_attack || stats->frag_attack || stats->other_attack;
}

static void format_active_attack_classes(const struct global_attack_stats *stats,
                                         char *buf, size_t buflen)
{
    size_t n = 0;
    buf[0] = '\0';
#define APPEND_CLASS(flag, name) do {                                         \
        if ((flag) && n + 12 < buflen) {                                      \
            n += (size_t)snprintf(buf + n, buflen - n, "%s%s",                \
                                  n ? "," : "", (name));                      \
        }                                                                     \
    } while (0)
    APPEND_CLASS(stats->syn_attack, "SYN");
    APPEND_CLASS(stats->ack_attack, "ACK");
    APPEND_CLASS(stats->rst_attack, "RST");
    APPEND_CLASS(stats->icmp_attack, "ICMP");
    APPEND_CLASS(stats->udp_attack, "UDP");
    APPEND_CLASS(stats->gre_attack, "GRE");
    /* DATA Attack arms both flags; report STOMP vs HANDSHAKE from length labels. */
    if (stats->stomp_attack || stats->handshake_attack) {
        if (shadow_data_overlay_is_handshake())
            APPEND_CLASS(1, "HANDSHAKE");
        else
            APPEND_CLASS(1, "STOMP");
    }
    APPEND_CLASS(stats->synack_attack, "SYNACK");
    APPEND_CLASS(stats->socket_attack, "SOCKET");
    APPEND_CLASS(stats->fin_attack, "FIN");
    APPEND_CLASS(stats->frag_attack, "FRAG");
    APPEND_CLASS(stats->other_attack, "OTHER");
#undef APPEND_CLASS
}

/* Shared so cleanup can flush STOP if the worker exits mid-episode. */
static volatile int episode_signal_sent = 0;
static pthread_t episode_worker_thr;
static int episode_worker_thr_valid = 0;

static void flush_attack_episode_stop(const char *why)
{
    char message[2048];
    char classes[128];
    struct alert_extra ex = {0};
    struct global_attack_stats *g_attack_stats = &global_fw_config.g_attack_stats;
    __u64 req_id;

    if (!episode_signal_sent)
        return;
    episode_signal_sent = 0;

    req_id = g_attack_stats->global_req_id;
    format_active_attack_classes(g_attack_stats, classes, sizeof(classes));
    ex.classes = classes;
    ex.source = global_fw_config.g_config.prefer_adaptive ? "adaptive" : "classic";
    ex.why = why ? why : "episode_close";
    attack_log_note("episode STOP source=%s classes=%s why=%s\n",
                    ex.source, classes[0] ? classes : "-", ex.why);
    build_attack_episode_message(0, req_id, message, sizeof(message), &ex);
    send_message_to_api_parser(message);
    if (g_attack_stats->global_req_id == req_id)
        g_attack_stats->global_req_id = 0;
    LOG_I("ALERT episode STOP req_id=%llu source=%s why=%s\n",
          (unsigned long long)req_id, ex.source, ex.why);
    attack_log_close(classes[0] ? classes : "-");
}

static void * report_attack_status_worker(void * arg)
{
    (void)arg;
    while (!exiting) {
        struct global_attack_stats *g_attack_stats = &global_fw_config.g_attack_stats;
        int active = attack_episode_active(g_attack_stats);
        char message[2048];
        __u64 req_id;

        if (active && episode_signal_sent == 0) {
            char classes[128];
            struct alert_extra ex = {0};

            if (g_attack_stats->global_req_id == 0)
                g_attack_stats->global_req_id = generate_attack_req_id();
            req_id = g_attack_stats->global_req_id;

            format_active_attack_classes(g_attack_stats, classes, sizeof(classes));
            ex.classes = classes;
            ex.source = global_fw_config.g_config.prefer_adaptive ? "adaptive" : "classic";
            ex.why = "episode_open";
            /* Classic path opens here; adaptive usually already opened in shadow. */
            if (attack_log_open(req_id, classes[0] ? classes : "-", ex.source) > 0)
                LOG_I("ATTACK archive open req_id=%llu\n",
                      (unsigned long long)req_id);
            attack_log_note("episode START source=%s classes=%s\n",
                            ex.source, classes[0] ? classes : "-");
            build_attack_episode_message(1, req_id, message, sizeof(message), &ex);
            send_message_to_api_parser(message);
            episode_signal_sent = 1;
            LOG_I("ALERT episode START req_id=%llu source=%s classes=%s\n",
                  (unsigned long long)req_id, ex.source, classes[0] ? classes : "-");
        } else if (!active && episode_signal_sent == 1) {
            flush_attack_episode_stop("episode_close");
        }

        usleep(100000);
    }

    /* Service stop / crash path: always close an open episode. */
    flush_attack_episode_stop("shutdown");
    return NULL;
}

int main(int argc, char **argv) {
    int map_plan = (argc >= 2 && strcmp(argv[1], "--map-plan") == 0);
    if (map_plan)
        set_main_log_path("off");   /* stdout only; keep the production log clean */
    else
        LOG_I("Starting EBPF-Firewall\n");
    int ifindex, err = -1;

    struct bpf_program *prog_main, *prog_parse_syn, *prog_parse_ack, *prog_parse_rst,
                       *prog_parse_icmp, *prog_parse_udp, *prog_parse_gre,
                       *prog_parse_stomp, *prog_parse_tcp_socket, *prog_parse_handshake,
                       *prog_parse_psh_ack, *prog_parse_synack;

    int attach_id = -1, prog_main_fd, prog_parse_syn_fd, prog_parse_ack_fd,
        prog_parse_rst_fd, prog_parse_icmp_fd, prog_parse_udp_fd, prog_parse_gre_fd,
        prog_parse_stomp_fd, prog_parse_tcp_socket_fd, prog_parse_handshake_fd,
        prog_parse_psh_ack_fd, prog_parse_synack_fd;

    int prog_array_map_fd;
    int tcp_established_map_fd, tcp_connection_map_fd, blocked_ips_map_fd;
    struct perf_buffer *pb = NULL;
    struct ring_buffer *ringbuf = NULL;
    struct ring_buffer *fixed_ip_ringbuf = NULL;

    if (get_license_status() < 0) {
        return 1;
    }

    // Open the BPF object file (compiled from xdp_prog.c).
    char* env_path = getenv(XDP_CORE_FILE);
    if (!env_path) {
        LOG_E( "ERROR: Failed to read env : %s\n", XDP_CORE_FILE);
        return 1;
    }
    
    obj = bpf_object__open_file(env_path, NULL);
    if (!obj) {
        LOG_E( "ERROR: opening BPF object file failed\n");
        return 1;
    }

    if (apply_host_map_sizing(obj) < 0) {
        LOG_E("Failed to apply host map sizing\n");
        goto cleanup;
    }
    /* Print the sizing plan for this host and exit (deploy-time check). */
    if (map_plan) {
        bpf_object__close(obj);
        return 0;
    }
    // Load the BPF object into the kernel.
    err = bpf_object__load(obj);
    if (err) {
        LOG_E( "ERROR: loading BPF object file: %d\n", err);
        goto cleanup;
    }

    log_map_memory_usage(obj);

    if (init_unix_socket() < 0) {
        LOG_E( "Failed to init unix socket\n");
        goto cleanup;
    }

    if (init_nginx_socket() < 0) {
        LOG_E( "Failed to init unix nginx socket\n");
        goto cleanup;
    }

    if (init_time_offset() < 0) {
        LOG_E( "Failed to initialize time offset\n");
        goto cleanup;
    }

    if (load_config(obj) < 0) {
        goto cleanup;
    }

    // Initialize openssl config
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    //OPENSSL_config(NULL);

#ifdef PRODUCTION_MODE
    LOG_I("Running EBPF-Firewall with Production mode\n");
    /* Optional CLI token (short-lived). systemd units normally omit it and
     * rely on LICENSE_PATH already verified by get_license_status() above. */
    if (argc >= 2 && argv[1] && argv[1][0]) {
        strncpy(token, argv[1], sizeof(token) - 1);
        token[sizeof(token) - 1] = '\0';
        if (check_token() != 0) {
            LOG_E("Failed to check token so exit.\n");
            goto cleanup;
        }
    } else {
        LOG_I("No CLI token; using verified license\n");
    }
#else
    LOG_W("Running EBPF-Firewall with Test mode\n");
#endif

    process_argv = argv;

    // Get interface index.
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        LOG_E( "ERROR: if_nametoindex(%s) failed\n", ifname);
        return 1;
    }

    // Find program sections.
    prog_main = bpf_object__find_program_by_name(obj, "xdp_main");
    prog_parse_syn = bpf_object__find_program_by_name(obj, "xdp_parse_syn");
    prog_parse_ack = bpf_object__find_program_by_name(obj, "xdp_parse_ack");
    prog_parse_rst = bpf_object__find_program_by_name(obj, "xdp_parse_rst");
    prog_parse_icmp = bpf_object__find_program_by_name(obj, "xdp_parse_icmp");
    prog_parse_udp = bpf_object__find_program_by_name(obj, "xdp_parse_udp");
    prog_parse_gre = bpf_object__find_program_by_name(obj, "xdp_parse_gre");

    if (!prog_main || !prog_parse_syn || !prog_parse_ack || !prog_parse_rst || !prog_parse_icmp || !prog_parse_udp || !prog_parse_gre) {
        LOG_E( "ERROR: could not find all program sections\n");
        goto cleanup;
    }

    prog_parse_stomp = bpf_object__find_program_by_name(obj, "xdp_parse_stomp");    
    prog_parse_tcp_socket = bpf_object__find_program_by_name(obj, "xdp_parse_tcp_socket");
    prog_parse_handshake = bpf_object__find_program_by_name(obj, "xdp_parse_handshake");
    prog_parse_psh_ack = bpf_object__find_program_by_name(obj, "xdp_parse_psh_ack");
    prog_parse_synack = bpf_object__find_program_by_name(obj, "xdp_parse_synack");

    if (!prog_main || !prog_parse_syn || !prog_parse_ack || !prog_parse_rst ||
        !prog_parse_icmp || !prog_parse_udp || !prog_parse_gre ||
        !prog_parse_stomp || !prog_parse_tcp_socket || !prog_parse_handshake ||
        !prog_parse_psh_ack || !prog_parse_synack) {
        LOG_E("ERROR: could not find all program sections\n");
        goto cleanup;
    }

    // Get file descriptors for the programs.
    prog_main_fd = bpf_program__fd(prog_main);
    prog_parse_syn_fd = bpf_program__fd(prog_parse_syn);
    prog_parse_ack_fd = bpf_program__fd(prog_parse_ack);
    prog_parse_rst_fd = bpf_program__fd(prog_parse_rst);
    prog_parse_icmp_fd = bpf_program__fd(prog_parse_icmp);
    prog_parse_udp_fd = bpf_program__fd(prog_parse_udp);
    prog_parse_gre_fd = bpf_program__fd(prog_parse_gre);
    prog_parse_stomp_fd = bpf_program__fd(prog_parse_stomp);
    prog_parse_tcp_socket_fd = bpf_program__fd(prog_parse_tcp_socket);
    prog_parse_handshake_fd = bpf_program__fd(prog_parse_handshake);
    prog_parse_psh_ack_fd = bpf_program__fd(prog_parse_psh_ack);
    prog_parse_synack_fd = bpf_program__fd(prog_parse_synack);


    // Find the prog_array map (declared as "prog_array" in our BPF program).
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "prog_array");
    if (!map) {
        LOG_E( "ERROR: could not find prog_array map\n");
        goto cleanup;
    }
    prog_array_map_fd = bpf_map__fd(map);
    
    // Update the prog_array map:
    // Key 0 -> xdp_parse_syn; Key 1 -> xdp_parse_ack.
    // Key 2 -> xdp_parse_rst; Key 3 -> xdp_parse_icmp. Key 4 -> xdp_parse_udp. Key 5 -> xdp_parse_gre.
    int key0 = 0, key1 = 1, key2 = 2, key3 = 3, key4 = 4, key5 = 5, key6 = 6, key7 = 7, key8 = 8, key9 = 9, key10 = 10;
    
    err = bpf_map_update_elem(prog_array_map_fd, &key0, &prog_parse_syn_fd, 0);
    if (err) {
        LOG_E( "ERROR: updating prog_array key 0 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key1, &prog_parse_ack_fd, 0);
    if (err) {
        LOG_E( "ERROR: updating prog_array key 1 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key2, &prog_parse_rst_fd, 0);
    if (err) {
        LOG_E( "ERROR: updating prog_array key 2 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key3, &prog_parse_icmp_fd, 0);
    if (err) {
        LOG_E( "ERROR: updating prog_array key 3 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key4, &prog_parse_udp_fd, 0);
    if (err) {
        LOG_E( "ERROR: updating prog_array key 4 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key5, &prog_parse_gre_fd, 0);
    if (err) {
        LOG_E( "ERROR: updating prog_array key 5 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key6, &prog_parse_psh_ack_fd, 0);
    if (err) {
        LOG_E("ERROR: updating prog_array key 6 (psh_ack) failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key7, &prog_parse_tcp_socket_fd, 0);
    if (err) {
        LOG_E("ERROR: updating prog_array key 7 (tcp_socket) failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key8, &prog_parse_handshake_fd, 0);
    if (err) {
        LOG_E("ERROR: updating prog_array key 8 (handshake) failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key9, &prog_parse_stomp_fd, 0);
    if (err) {
        LOG_E("ERROR: updating prog_array key 9 (stomp) failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key10, &prog_parse_synack_fd, 0);
    if (err) {
        LOG_E("ERROR: updating prog_array key 10 (synack) failed: %d\n", err);
        goto cleanup;
    }

    //Open ring_buf_events Ringbuf map
    int ring_buf_events_map_fd = bpf_object__find_map_fd_by_name(obj, "ring_buf_events");
    if (ring_buf_events_map_fd < 0) {
        LOG_E( "ERROR: finding map 'ring_buf_events'\n");
        goto cleanup;
    }
    
    // Set up ring buffer
    ringbuf = ring_buffer__new(ring_buf_events_map_fd, ringbuf_handle_event, NULL, NULL);
    if (!ringbuf) {
        LOG_E( "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    //Open fixed_ip_ring_buf_events Ringbuf map
    int fixed_ip_ring_buf_events_map_fd = bpf_object__find_map_fd_by_name(obj, "fixed_ip_ring_buf_events");
    if (fixed_ip_ring_buf_events_map_fd < 0) {
        LOG_E( "ERROR: finding map 'fixed_ip_ring_buf_events'\n");
        goto cleanup;
    }
    
    // Set up ring buffer
    fixed_ip_ringbuf = ring_buffer__new(fixed_ip_ring_buf_events_map_fd, fixed_ip_ringbuf_handle_event, NULL, NULL);
    if (!fixed_ip_ringbuf) {
        LOG_E( "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Get the map file descriptor
    tcp_established_map_fd = bpf_object__find_map_fd_by_name(obj, "tcp_established_map");
    if (tcp_established_map_fd < 0) {
        LOG_E( "Failed to find tcp_established_map eBPF map\n");
        goto cleanup;
    }

    tcp_connection_map_fd = bpf_object__find_map_fd_by_name(obj, "tcp_connection_map");
    if (tcp_connection_map_fd < 0) {
        LOG_E( "Failed to find tcp_connection eBPF map\n");
        goto cleanup;
    }

    blocked_ips_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (blocked_ips_map_fd < 0) {
        LOG_E( "Failed to find blocked_ips eBPF map\n");
        goto cleanup;
    }
    
#if 0
    if (purge_conntrack_for_blocked_ips(blocked_ips_map_fd) < 0) {
        LOG_E( "Failed to purge conntrack for blocked IPs\n");
        goto cleanup;
    }
#endif

    flush_all_tcp_conntrack();

    // Attach the main XDP program to the interface.
    attach_id = bpf_xdp_attach(ifindex, prog_main_fd, attach_mode, NULL);
    if (attach_id < 0) {
        LOG_E( "ERROR: attaching XDP program to %s (ifindex %d) return %d, failed: %d\n", ifname, ifindex, attach_id, err);
        goto cleanup;
    }

    /* TC egress: record outbound SYN for inbound SYN-ACK match (H7). */
    {
        struct bpf_program *tc_prog =
            bpf_object__find_program_by_name(obj, "tc_egress_record_syn");
        if (tc_prog && global_fw_config.g_config.svc.synack_match_outbound) {
            int tc_fd = bpf_program__fd(tc_prog);
            LIBBPF_OPTS(bpf_tc_hook, tc_hook,
                        .ifindex = ifindex,
                        .attach_point = BPF_TC_EGRESS);
            LIBBPF_OPTS(bpf_tc_opts, tc_opts,
                        .handle = 1,
                        .priority = 50,
                        .prog_fd = tc_fd);
            int tc_err = bpf_tc_hook_create(&tc_hook);
            if (tc_err && tc_err != -EEXIST)
                LOG_W("TC egress hook create: %d (SYN-ACK match may be off)\n", tc_err);
            tc_err = bpf_tc_attach(&tc_hook, &tc_opts);
            if (tc_err)
                LOG_W("TC egress attach failed: %d (SYN-ACK match degraded)\n", tc_err);
            else
                LOG_I("TC egress SYN recorder attached on %s\n", ifname);
        }
    }

    if (init_conntrack(tcp_established_map_fd, tcp_connection_map_fd, blocked_ips_map_fd) < 0) {
        LOG_E( "Failed to init conntrack\n");
        goto cleanup;
    }

    pthread_t global_attack_ch_thr, blocked_ips_duration_thr;
    if (pthread_create(&global_attack_ch_thr, NULL, global_attack_check_worker, obj) != 0) {
        LOG_E("pthread_create for global_attack_ch_thr %s\n", strerror(errno));
        goto cleanup;
    }

    if (start_shadow_control_loop(obj) < 0) {
        LOG_E("Failed to start shadow control loop\n");
        goto cleanup;
    }

    pthread_t global_traffic_stats_check_thr;
    if (pthread_create(&global_traffic_stats_check_thr, NULL, global_traffic_stats_check_worker, obj) != 0) {
        LOG_E("pthread_create for global_traffic_stats_check_thr %s\n", strerror(errno));
        goto cleanup;
    }

    if (pthread_create(&blocked_ips_duration_thr, NULL, blocked_ips_duration_check_worker, obj) != 0) {
        LOG_E("pthread_create for blocked_ips_duration_thr %s\n", strerror(errno));
        goto cleanup;
    }

    pthread_t fixed_ip_ringbuf_thr;
    if (pthread_create(&fixed_ip_ringbuf_thr, NULL, fixed_ip_ringbuf_poll_worker, fixed_ip_ringbuf) != 0) {
        LOG_E("pthread_create for fixed_ip_ringbuf_thr %s\n", strerror(errno));
        goto cleanup;
    }

    // Let's skip this logic right now

    pthread_t send_check_blocklist_thr;
    if (pthread_create(&send_check_blocklist_thr, NULL, report_attack_status_worker, NULL) != 0) {
        LOG_E("pthread_create for send_check_blocklist_thr %s\n", strerror(errno));
        goto cleanup;
    }
    episode_worker_thr = send_check_blocklist_thr;
    episode_worker_thr_valid = 1;

    pthread_t license_check_thr;
    if (pthread_create(&license_check_thr, NULL, license_check_worker, NULL) != 0) {
        LOG_E("pthread_create for license_check_thr %s\n", strerror(errno));
        goto cleanup;
    }

    LOG_I("XDP program successfully attached to interface %s (ifindex %d)\n", ifname, ifindex);
    LOG_I("Press Ctrl+C to exit and detach the program.\n");


    // Wait until terminated.
    while (!exiting) {
        err = ring_buffer__poll(ringbuf, -1 /* block */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            LOG_E( "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
cleanup:
    exiting = 1;
    stop_shadow_control_loop();

    pthread_cond_broadcast(&sqlite_block_q_cv);
    if (sqlite_worker_thr_valid)
        pthread_join(sqlite_worker_thr, NULL);

    /* Join episode worker before closing the API socket so STOP can be sent. */
    if (episode_worker_thr_valid) {
        pthread_join(episode_worker_thr, NULL);
        episode_worker_thr_valid = 0;
    }
    flush_attack_episode_stop("shutdown");

    if (ringbuf) ring_buffer__free(ringbuf);
    if (fixed_ip_ringbuf) ring_buffer__free(fixed_ip_ringbuf);
    if (obj) bpf_object__close(obj);
    if (attach_id >= 0) bpf_xdp_detach(ifindex, attach_mode, NULL);
    
    close_unix_socket();
    close_nginx_socket();
    close_conntrack();

    LOG_I("Program is ended\n");

    return err < 0 ? -err : 0;
}


int restart_fw() {
    int ret = -1;

    if (process_argv == NULL) {
        LOG_E( "Process argument is NULL\n");
        return -1;
    }

    ret = execvp(process_argv[0], process_argv);
    if (ret == -1) {
        LOG_E( "Process did not terminate correctly\n");
        return -1;
    }

    return ret;
}

int reload_fw() {
    if (!obj) {
        LOG_E( "BPF object not loaded\n");
        return -1;
    }
    if (load_config(obj) < 0) {
        LOG_E( "reload config failed\n");
        return -1;
    }
    if (reconcile_blocked_ips_tracked_state(obj) < 0) {
        LOG_E( "reload: failed to sync blocked IP conntrack/BPF maps\n");
        return -1;
    }
    LOG_I("Config reloaded successfully\n");
    return 0;
}


/* -------------------------------------------------------------- */
/* Core: count elements in map_fd, independent of key/value sizes */
static long count_map(int map_fd)
{
    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(map_fd, &info, &len)) {
        LOG_E("bpf_obj_get_info_by_fd %s\n", strerror(errno));
        return -1;
    }

#if defined(BPF_MAP_LOOKUP_BATCH)   /* kernel ≥ 5.6 ---------------------- */
    const __u32 BATCH = 256;
    void *keys = malloc(BATCH * info.key_size);
    void *vals = info.value_size ? malloc(BATCH * info.value_size) : NULL;
    void *in_key = NULL, *out_key = malloc(info.key_size);
    if (!keys || (!vals && info.value_size) || !out_key) {
        LOG_E( "OOM\n");
        goto err_batch;
    }

    long total = 0;
    for (;;) {
        __u32 cnt = BATCH;
        int err = bpf_map_lookup_batch(map_fd,
                                       in_key, out_key,
                                       keys, vals, &cnt, NULL);
        if (err) {
            if (errno == ENOENT)    /* map exhausted */
                break;
            perror("bpf_map_lookup_batch");
            goto err_batch;
        }
        total += cnt;
        if (cnt < BATCH)            /* short read → nothing left */
            break;
        in_key = out_key;           /* continue where we stopped */
    }

    free(keys); free(vals); free(out_key);
    return total;

err_batch:
    free(keys); free(vals); free(out_key);
    return -1;

#else                               /* fallback: GET_NEXT_KEY loop ------- */
    void *key = calloc(1, info.key_size);
    void *next = calloc(1, info.key_size);
    if (!key || !next) {
        LOG_E( "OOM\n");
        free(key); free(next);
        return -1;
    }

    long total = 0;
    /* first call: NULL → first key */
    if (bpf_map_get_next_key(map_fd, NULL, next))
        goto done;                  /* map empty */

    do {
        ++total;
        memcpy(key, next, info.key_size);
    } while (!bpf_map_get_next_key(map_fd, key, next));

done:
    free(key); free(next);
    return total;
#endif
}


int clear_batch_map(int map_fd)
{   
    const __u32 BATCH_SZ = 256;
    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    int err;

    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len)) {
        LOG_E("bpf_obj_get_info_by_fd %s\n", strerror(errno));
        return -1;
    }

    /* --- allocate buffers ------------------------------------------------ */
    void *keys   = calloc(BATCH_SZ, info.key_size);
    void *values = info.value_size ? calloc(BATCH_SZ, info.value_size) : NULL;
    void *next_key = malloc(info.key_size);          /* out_batch scratch */

    if (!keys || (info.value_size && !values) || !next_key) {
        LOG_E( "clear_map: out of memory\n");
        goto error;
    }

    /* --- iterate & delete ------------------------------------------------ */
    void *in_key = NULL;            /* start from beginning */
    __u32 total = 0;

    for (;;) {
        __u32 cnt = BATCH_SZ;

        err = bpf_map_lookup_and_delete_batch(map_fd,
                                              in_key,          /* in_batch  */
                                              next_key,        /* out_batch */
                                              keys,
                                              values,
                                              &cnt,
                                              NULL);
        if (err) {
            if (errno == ENOENT)         /* map already empty */
                break;
            LOG_E("bpf_map_lookup_and_delete_batch %s\n", strerror(errno));
            goto error;
        }

        if (cnt < BATCH_SZ)              /* short batch → nothing left */
            break;

        in_key = next_key;               /* continue from where we stopped */
    }

    free(keys); free(values); free(next_key);
    return 0;

error:
    free(keys); free(values); free(next_key);
    return -1;
}


int clear_geoip_trie_map(int map_fd) {
    __u8 next_key[sizeof(struct lpm_key)] = {};
    __u8 lookup_key[sizeof(struct lpm_key)] = {};
    __u8 value;
    int err;

    // Iterate through all keys and delete them
    while (1) {
        err = bpf_map_get_next_key(map_fd, lookup_key, next_key);
        if (err) {
            if (errno == ENOENT) {
                // No more entries - we're done
                break;
            }
            LOG_E("Failed to get next key: %s\n", strerror(errno));
            return -1;
        }

        // Delete the entry
        err = bpf_map_delete_elem(map_fd, next_key);
        if (err) {
            LOG_E("Failed to delete element: %s\n", strerror(errno));
            return -1;
        }

        // Prepare for next iteration
        memcpy(lookup_key, next_key, sizeof(lookup_key));
    }

    LOG_D("Successfully done clear_geoip_trie_map\n");
    return 0;
}


static int clear_pkt_counter_map(int map_fd) {
    __u32 key = 0;
    int nr = bpf_percpu_nr_cpus();
    __u64 *values = calloc((size_t)nr, sizeof(__u64));

    if (values == NULL)
        goto error;

    if (bpf_map_lookup_elem(map_fd, &key, values)) {
        LOG_E( "bpf_map_lookup_elem");
        goto error;
    }
    for (int cpu = 0; cpu < nr; cpu++) {
        values[cpu] = 0;
    }

    bpf_map_update_elem(map_fd, &key, values, 0);
    if (values) free (values);
    return 0;
error:
    if (values) free (values);
    return -1;
}

static int clear_global_attack_stats_map(int map_fd) {
    __u32 key = 0;
    struct global_attack_stats global_attack_stats_val;

    if (bpf_map_lookup_elem(map_fd, &key, &global_attack_stats_val)) {
        LOG_E( "bpf_map_lookup_elem");
        return -1;
    }
    memset(&global_attack_stats_val, 0 , sizeof (struct global_attack_stats));
    bpf_map_update_elem(map_fd, &key, &global_attack_stats_val, 0);
    return 0;
}

int clear_fw() {
    int tcp_established_map_fd;

    tcp_established_map_fd = bpf_object__find_map_fd_by_name(obj, "tcp_established_map");
    if (tcp_established_map_fd < 0) {
        LOG_E( "Failed to find tcp_established_map\n");
        return -1;
    }
    if (clear_batch_map(tcp_established_map_fd) < 0)
        return -1;
    LOG_D("tcp_established_map is cleared\n");

    int syn_validated_ips_fd;
    syn_validated_ips_fd = bpf_object__find_map_fd_by_name(obj, "syn_validated_ips");
    if (syn_validated_ips_fd < 0) {
        LOG_E( "Failed to find syn_validated_ips\n");
        return -1;
    }
    if (clear_batch_map(syn_validated_ips_fd) < 0)
        return -1;
    LOG_D("syn_validated_ips is cleared\n");

    int global_syn_pkt_counter_fd, syn_counter_fixed_fd, burst_syn_state_fd, syn_challenge_fd;
    global_syn_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_syn_pkt_counter");
    if (global_syn_pkt_counter_fd < 0) {
        LOG_E( "Failed to find global_syn_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_syn_pkt_counter_fd) < 0)
        return -1;
    LOG_D("global_syn_pkt_counter is cleared\n");  

    syn_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "syn_counter_fixed");
    if (syn_counter_fixed_fd < 0) {
        LOG_E( "Failed to find syn_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(syn_counter_fixed_fd) < 0)
        return -1;
    LOG_D("syn_counter_fixed is cleared\n");  

    burst_syn_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_syn_state");
    if (burst_syn_state_fd < 0) {
        LOG_E( "Failed to find burst_syn_state\n");
        return -1;
    }
    if (clear_batch_map(burst_syn_state_fd) < 0)
        return -1;
    LOG_D("burst_syn_state is cleared\n");  

    syn_challenge_fd = bpf_object__find_map_fd_by_name(obj, "syn_challenge");
    if (syn_challenge_fd < 0) {
        LOG_E( "Failed to find syn_challenge\n");
        return -1;
    }
    if (clear_batch_map(syn_challenge_fd) < 0)
        return -1;
    LOG_D("syn_challenge is cleared\n");  

    int global_ack_pkt_counter_fd, ack_counter_fixed_fd, burst_ack_state_fd;
    global_ack_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_ack_pkt_counter");
    if (global_ack_pkt_counter_fd < 0) {
        LOG_E( "Failed to find global_ack_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_ack_pkt_counter_fd) < 0)
        return -1;
    LOG_D("global_ack_pkt_counter is cleared\n");  

    ack_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "ack_counter_fixed");
    if (ack_counter_fixed_fd < 0) {
        LOG_E( "Failed to find ack_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(ack_counter_fixed_fd) < 0)
        return -1;
    LOG_D("ack_counter_fixed is cleared\n"); 

    burst_ack_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_ack_state");
    if (burst_ack_state_fd < 0) {
        LOG_E( "Failed to find burst_ack_state\n");
        return -1;
    }
    if (clear_batch_map(burst_ack_state_fd) < 0)
        return -1;
    LOG_D("burst_ack_state is cleared\n"); 

    int global_rst_pkt_counter_fd, rst_counter_fixed_fd, burst_rst_state_fd;
    global_rst_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_rst_pkt_counter");
    if (global_rst_pkt_counter_fd < 0) {
        LOG_E( "Failed to find global_rst_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_rst_pkt_counter_fd) < 0)
        return -1;
    LOG_D("global_rst_pkt_counter is cleared\n"); 

    rst_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "rst_counter_fixed");
    if (rst_counter_fixed_fd < 0) {
        LOG_E( "Failed to find rst_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(rst_counter_fixed_fd) < 0)
        return -1;
    LOG_D("rst_counter_fixed is cleared\n");

    burst_rst_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_rst_state");
    if (burst_rst_state_fd < 0) {
        LOG_E( "Failed to find burst_rst_state\n");
        return -1;
    }
    if (clear_batch_map(burst_rst_state_fd) < 0)
        return -1;
    LOG_D("burst_rst_state is cleared\n");

    int global_icmp_pkt_counter_fd, icmp_counter_fixed_fd, burst_icmp_state_fd;
    global_icmp_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_icmp_pkt_counter");
    if (global_icmp_pkt_counter_fd < 0) {
        LOG_E( "Failed to find global_icmp_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_icmp_pkt_counter_fd) < 0)
        return -1;
    LOG_D("global_icmp_pkt_counter is cleared\n");

    icmp_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "icmp_counter_fixed");
    if (icmp_counter_fixed_fd < 0) {
        LOG_E( "Failed to find icmp_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(icmp_counter_fixed_fd) < 0)
        return -1;
    LOG_D("icmp_counter_fixed is cleared\n");

    burst_icmp_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_icmp_state");
    if (burst_icmp_state_fd < 0) {
        LOG_E( "Failed to find burst_icmp_state\n");
        return -1;
    }
    if (clear_batch_map(burst_icmp_state_fd) < 0)
        return -1;
    LOG_D("burst_icmp_state is cleared\n");

    int global_udp_pkt_counter_fd, udp_counter_fixed_fd, burst_udp_state_fd;
    global_udp_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_udp_pkt_counter");
    if (global_udp_pkt_counter_fd < 0) {
        LOG_E( "Failed to find global_udp_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_udp_pkt_counter_fd) < 0)
        return -1;
    LOG_D("global_udp_pkt_counter is cleared\n");

    udp_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "udp_counter_fixed");
    if (udp_counter_fixed_fd < 0) {
        LOG_E( "Failed to find udp_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(udp_counter_fixed_fd) < 0)
        return -1;
    LOG_D("udp_counter_fixed is cleared\n");

    burst_udp_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_udp_state");
    if (burst_udp_state_fd < 0) {
        LOG_E( "Failed to find burst_udp_state\n");
        return -1;
    }
    if (clear_batch_map(burst_udp_state_fd) < 0)
        return -1;
    LOG_D("burst_udp_state is cleared\n");

    int global_gre_pkt_counter_fd, gre_counter_fixed_fd, burst_gre_state_fd;
    global_gre_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_gre_pkt_counter");
    if (global_gre_pkt_counter_fd < 0) {
        LOG_E( "Failed to find global_gre_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_gre_pkt_counter_fd) < 0)
        return -1;
    LOG_D("global_gre_pkt_counter is cleared\n");

    gre_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "gre_counter_fixed");
    if (gre_counter_fixed_fd < 0) {
        LOG_E( "Failed to find gre_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(gre_counter_fixed_fd) < 0)
        return -1;
    LOG_D("gre_counter_fixed is cleared\n");

    burst_gre_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_gre_state");
    if (burst_gre_state_fd < 0) {
        LOG_E( "Failed to find burst_gre_state\n");
        return -1;
    }
    if (clear_batch_map(burst_gre_state_fd) < 0)
        return -1;
    LOG_D("burst_gre_state is cleared\n");

    int fd;
    fd = bpf_object__find_map_fd_by_name(obj, "global_stomp_pkt_counter");
    if (fd >= 0) clear_pkt_counter_map(fd);
    LOG_D("global_stomp_pkt_counter is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "global_psh_ack_filtered");
    if (fd >= 0) clear_pkt_counter_map(fd);
    LOG_D("global_psh_ack_filtered is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "stomp_counter_fixed");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("stomp_counter_fixed is cleared\n");

    //fd = bpf_object__find_map_fd_by_name(obj, "stomp_counter_fixed_metrics");
    //if (fd >= 0) clear_batch_map(fd);
    //LOG_D("stomp_counter_fixed_metrics is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "burst_stomp_state");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("burst_stomp_state is cleared\n");

    /* --- SOCKET maps --- */
    fd = bpf_object__find_map_fd_by_name(obj, "global_socket_pkt_counter");
    if (fd >= 0) clear_pkt_counter_map(fd);
    LOG_D("global_socket_pkt_counter is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "socket_counter_fixed");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("socket_counter_fixed is cleared\n");

    /* --- Handshake maps --- */
    fd = bpf_object__find_map_fd_by_name(obj, "global_handshake_pkt_counter");
    if (fd >= 0) clear_pkt_counter_map(fd);
    LOG_D("global_handshake_pkt_counter is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "handshake_counter_fixed");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("handshake_counter_fixed is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "burst_handshake_state");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("burst_handshake_state is cleared\n");

    /* --- SYN+ACK maps (Phase 0 H7) --- */
    fd = bpf_object__find_map_fd_by_name(obj, "global_synack_pkt_counter");
    if (fd >= 0) clear_pkt_counter_map(fd);
    LOG_D("global_synack_pkt_counter is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "synack_counter_fixed");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("synack_counter_fixed is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "burst_synack_state");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("burst_synack_state is cleared\n");

    /* --- Phase 1 detection maps --- */
    fd = bpf_object__find_map_fd_by_name(obj, "det_counters");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("det_counters is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "invalid_counters");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("invalid_counters is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "mitigation_mode");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("mitigation_mode is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "drop_invalid_totals");
    if (fd >= 0) clear_pkt_counter_map(fd);
    LOG_D("drop_invalid_totals is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "src_buckets");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("src_buckets is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "dst_class_rate");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("dst_class_rate is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "drop_mode2_totals");
    if (fd >= 0) clear_pkt_counter_map(fd);
    LOG_D("drop_mode2_totals is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "drop_mode3_totals");
    if (fd >= 0) clear_pkt_counter_map(fd);
    LOG_D("drop_mode3_totals is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "flows");
    if (fd >= 0) clear_batch_map(fd);
    LOG_D("flows is cleared\n");

    fd = bpf_object__find_map_fd_by_name(obj, "drop_flow_totals");
    if (fd >= 0) clear_pkt_counter_map(fd);
    LOG_D("drop_flow_totals is cleared\n");

    {
        int nr = bpf_percpu_nr_cpus();
        size_t dstride = bpf_percpu_stride(sizeof(struct det_val));
        void *dzeros = calloc((size_t)nr, dstride);
        size_t istride = bpf_percpu_stride(sizeof(__u64));
        void *izeros = calloc((size_t)nr, istride);
        if (dzeros) {
            fd = bpf_object__find_map_fd_by_name(obj, "det_class_totals");
            if (fd >= 0) {
                for (__u32 c = 0; c < DET_CLASS_MAX; c++)
                    bpf_map_update_elem(fd, &c, dzeros, 0);
            }
            free(dzeros);
        }
        if (izeros) {
            fd = bpf_object__find_map_fd_by_name(obj, "invalid_totals");
            if (fd >= 0) {
                for (__u32 r = 0; r < INVALID_REASON_MAX; r++)
                    bpf_map_update_elem(fd, &r, izeros, 0);
            }
            free(izeros);
        }
        memset(&global_det_stats, 0, sizeof(global_det_stats));
    }

    return 0;
}

int stats_fw(struct stats_config * stats)
{
    return 0;
}

static int sb_append(char **buf, size_t *off, size_t *cap,
                     const char *fmt, ...)
{
    for (;;) {
        va_list ap;
        va_start(ap, fmt);
        int n = vsnprintf(*buf + *off, *cap - *off, fmt, ap);
        va_end(ap);

        if (n < 0)
            return -1;                           /* encoding error */

        if ((size_t)n < *cap - *off) {           /* fit */
            *off += n;
            return n;
        }
        /* need more space → double the buffer (or add n+1, whichever larger) */
        size_t new_cap = (*cap * 2 > *off + n + 1) ? *cap * 2 : *off + n + 1;
        char *tmp = realloc(*buf, new_cap);
        if (!tmp)
            return -1;                           /* OOM */
        *buf = tmp;
        *cap = new_cap;
    }
}

int list_block_ip(char **out) {
    *out = NULL;
    size_t off = 0, cap = 1024;          /* start with 1 kB, grow as needed */
    char *buf = malloc(cap);
    if (!buf)
        return -1;

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);

    int blocked_ips_fd;
    blocked_ips_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (blocked_ips_fd < 0) {
        LOG_E( "Failed to find blocked_ips\n");
        goto error;
    }

    if (bpf_obj_get_info_by_fd(blocked_ips_fd, &info, &len)) {
        LOG_E( "bpf_obj_get_info_by_fd");
        goto error;
    }

    LOG_D("‑‑ Map fd=%d  type=%u  max_entries=%u  key=%uB  value=%uB\n",
            blocked_ips_fd, info.type, info.max_entries, info.key_size, info.value_size);
            
    void *key  = calloc(1, info.key_size);
    void *next = calloc(1, info.key_size);
    void *val  = malloc(info.value_size);

    if (!key || !next || !val) {
        LOG_E( "Failed to malloc\n");
        goto error;
    }

    /* First call with NULL to get the first key (if any) */
    if (bpf_map_get_next_key(blocked_ips_fd, NULL, next)) {
        sb_append(&buf, &off, &cap, "(No ip address in blacklist)\n");
        goto done;           /* map empty */
    }

    const __u64 t_now = now_ns();
    char ip_str[INET_ADDRSTRLEN];
    char ts_str[80];

    do {
        if (bpf_map_lookup_elem(blocked_ips_fd, next, val)) {
            goto error;
        }

        /* key → dotted‑quad -------------------------------------------------- */
        struct in_addr addr = { .s_addr = *(__u32 *)next };   /* network order */
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        /* value is absolute expiration time in ns ---------------------------- */
        __u64 exp_ns = *(__u64 *)val;
        if (exp_ns == -1) {
            LOG_D("IP %-15s  Permanent block\n", ip_str);
            if (sb_append(&buf, &off, &cap,"IP %-15s  Permanent block\n",ip_str) < 0)
                goto error;
        }
        
        else {
            double remain = exp_ns > t_now ? (double)(exp_ns - t_now) / 1e9 : 0.0;
#if 0
            /* ---------- NEW: convert ns → human timestamp -------------------- */
            __u64 real_time_ns = exp_ns + time_offset_ns;
            /* Apply timezone offset (CST = UTC+8) */
            real_time_ns += tz_offset_sec * ONE_SECOND_NS;
            time_t seconds = real_time_ns / ONE_SECOND_NS;

            struct tm tm_info;
            if (localtime_r(&seconds, &tm_info) == NULL) {
                LOG_E( "localtime_r error\n");
                goto error;
            }

            strftime(ts_str, sizeof ts_str, "%Y-%m-%d %H:%M:%S", &tm_info);
#endif
            time_t rawtime;
            time(&rawtime); // Get current time in seconds since epoch
            rawtime += remain;

            struct tm *utc_time = gmtime(&rawtime);
            if (utc_time == NULL) {
                LOG_E( "gmtime error\n");
                goto error;
            }
            strftime(ts_str, sizeof(ts_str), "%Y-%m-%d %H:%M:%S UTC", utc_time);

            LOG_D("IP %-15s  expires_at=%s  (~%.3f s left)\n",
            ip_str, ts_str, remain);

            if (sb_append(&buf, &off, &cap,"IP %-15s  expires_at=%s  (~%.3f s left)\n",ip_str, ts_str, remain) < 0)
                goto error;
            
        }
        memcpy(key, next, info.key_size);
    } while (!bpf_map_get_next_key(blocked_ips_fd, key, next));

done:
    free(key); free(next); free(val);
    *out = buf;
    return 0;

error:
    free(key); free(next); free(val);
    return -1;
}

/* ===== JSON escaping into the string builder ===== */
static int json_escape_sb(char **buf, size_t *off, size_t *cap, const unsigned char *s)
{
    if (!s) {
        return sb_append(buf, off, cap, "null");
    }
    if (sb_append(buf, off, cap, "\"") < 0) return -1;

    for (const unsigned char *p = s; *p; ++p) {
        unsigned char c = *p;
        switch (c) {
            case '\"': if (sb_append(buf, off, cap, "\\\"") < 0) return -1; break;
            case '\\': if (sb_append(buf, off, cap, "\\\\") < 0) return -1; break;
            case '\b': if (sb_append(buf, off, cap, "\\b")  < 0) return -1; break;
            case '\f': if (sb_append(buf, off, cap, "\\f")  < 0) return -1; break;
            case '\n': if (sb_append(buf, off, cap, "\\n")  < 0) return -1; break;
            case '\r': if (sb_append(buf, off, cap, "\\r")  < 0) return -1; break;
            case '\t': if (sb_append(buf, off, cap, "\\t")  < 0) return -1; break;
            default:
                if (c < 0x20) {
                    if (sb_append(buf, off, cap, "\\u%04x", c) < 0) return -1;
                } else {
                    if (sb_append(buf, off, cap, "%c", c) < 0) return -1;
                }
        }
    }
    if (sb_append(buf, off, cap, "\"") < 0) return -1;
    return 0;
}

/* === Core: run the query and return JSON buffer (caller must free) === */
static char* query_blocked_ips_json(const char *filter_type,
                                    const char *filter_ip,
                                    const char *filter_dt /* "x" or "YYYY-MM-DD HH:MM:SS" UTC */)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char sql[1024] = "SELECT id, ip, type, duration, reason, created, timestamp "
                        "FROM blocked_ips WHERE 1=1";
    int bind_type = 0, bind_ip = 0, bind_dt = 0;

    /* Open DB */
    const char *dbpath = ebpf_sqlite_db_path();
    if (sqlite3_open(dbpath, &db) != SQLITE_OK) {
        LOG_E("Cannot open database '%s': %s\n", dbpath, sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        return NULL;
    }

    /* Build WHERE clause with parameters */
    if (strcmp(filter_type, "x") != 0) {
        strncat(sql, " AND type = ?", sizeof(sql) - strlen(sql) - 1);
        bind_type = 1;
    }
    if (strcmp(filter_ip, "x") != 0) {
        strncat(sql, " AND ip = ?", sizeof(sql) - strlen(sql) - 1);
        bind_ip = 1;
    }
    if (strcmp(filter_dt, "x") != 0) {
        /* UTC-aware comparison; julianday treats naive strings as UTC-scaled */
        strncat(sql, " AND julianday(created) >= julianday(?)",
                sizeof(sql) - strlen(sql) - 1);
        bind_dt = 1;
    }
    strncat(sql, " ORDER BY id ASC", sizeof(sql) - strlen(sql) - 1);

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        LOG_E("Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    int idx = 1;
    if (bind_type) sqlite3_bind_text(stmt, idx++, filter_type, -1, SQLITE_TRANSIENT);
    if (bind_ip)   sqlite3_bind_text(stmt, idx++, filter_ip,   -1, SQLITE_TRANSIENT);
    if (bind_dt)   sqlite3_bind_text(stmt, idx++, filter_dt,   -1, SQLITE_TRANSIENT);

    /* String builder buffer */
    size_t cap = 256, off = 0;
    char *out = (char*)malloc(cap);
    if (!out) {
        LOG_E("OOM\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return NULL;
    }
    out[0] = '\0';

    if (sb_append(&out, &off, &cap, "[\n") < 0) goto error;

    int first = 1;
    for (;;) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            if (!first) {
                if (sb_append(&out, &off, &cap, ",\n") < 0) goto error;
            }
            first = 0;

            int id = sqlite3_column_int(stmt, 0);
            const unsigned char *ip        = sqlite3_column_text(stmt, 1);
            const unsigned char *type      = sqlite3_column_text(stmt, 2);
            const unsigned char *duration  = sqlite3_column_text(stmt, 3);
            const unsigned char *reason    = sqlite3_column_text(stmt, 4);
            const unsigned char *created   = sqlite3_column_text(stmt, 5);

            if (sb_append(&out, &off, &cap, "  {\"id\": %d, \"ip\": ", id) < 0) goto error;
            if (json_escape_sb(&out, &off, &cap, ip) < 0) goto error;

            if (sb_append(&out, &off, &cap, ", \"type\": ") < 0) goto error;
            if (json_escape_sb(&out, &off, &cap, type) < 0) goto error;

            if (sb_append(&out, &off, &cap, ", \"duration\": ") < 0) goto error;
            if (json_escape_sb(&out, &off, &cap, duration) < 0) goto error;

            if (sb_append(&out, &off, &cap, ", \"reason\": ") < 0) goto error;
            if (json_escape_sb(&out, &off, &cap, reason) < 0) goto error;

            if (sb_append(&out, &off, &cap, ", \"created\": ") < 0) goto error;
            if (json_escape_sb(&out, &off, &cap, created) < 0) goto error;

            if (sb_append(&out, &off, &cap, "}") < 0) goto error;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            LOG_E("SQLite step error: %s\n", sqlite3_errmsg(db));
            goto error;
        }
    }

    if (sb_append(&out, &off, &cap, "\n]\n") < 0) goto error;

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;

error:
    if (out) free(out);
    if (stmt) sqlite3_finalize(stmt);
    if (db) sqlite3_close(db);
    return NULL;
}

int get_block_list_ips(char **out, char *filter_type, char *filter_ip, char * filter_date) {
    char *json = NULL;
    json = query_blocked_ips_json(filter_type, filter_ip, filter_date);
    if (!json) {
        LOG_E("Query failed.\n");
        return -1;
    }

    *out = json;
    return 0;
}

int clear_deny_ip(char * ip) {
    int blocked_ips_fd;
    blocked_ips_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (blocked_ips_fd < 0) {
        LOG_E( "Failed to find blocked_ips\n");
        return -1;
    }
    __u32 key;
    if (inet_pton(AF_INET, ip, &key) != 1) {
        LOG_E( "Invalid IP address: %s\n", ip);
        return -1;
    }

    int err = bpf_map_delete_elem(blocked_ips_fd, &key);
    if (err) {
        LOG_E("Failed to delete element from map %s\n", strerror(errno));
        return err;
    }
    return 0;
}

int clear_deny_ip_all() {
    int blocked_ips_fd;
    blocked_ips_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (blocked_ips_fd < 0) {
        LOG_E( "Failed to find blocked_ips\n");
        return -1;
    }
    if (clear_batch_map(blocked_ips_fd) < 0)
        return -1;
    LOG_D("blocked_ips_fd is cleared\n");
    return 0;
}


int add_block_ip(char *ip, int seconds) {
    __u64 expire_duration = (seconds == 0) 
                          ? now_ns() + global_fw_config.g_config.black_ip_duration 
                          : now_ns() + seconds * ONE_SECOND_NS;

    if (seconds == 0) { // Deault duration
        expire_duration = now_ns() + global_fw_config.g_config.black_ip_duration;
    } else if (seconds == -1) { // Permanent duration
        expire_duration = -1;
    } else { //Manual set duration
        expire_duration = now_ns() + seconds * ONE_SECOND_NS;
    }

    __u32 key;
    if (inet_pton(AF_INET, ip, &key) != 1) {
        LOG_E( "Invalid IP address: %s\n", ip);
        return -1;
    }

    int blocked_ips_fd;
    blocked_ips_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (blocked_ips_fd < 0) {
        LOG_E( "Failed to find blocked_ips\n");
        return -1;
    }
    
    __u64 existing_val;
    bool is_new_entry = (bpf_map_lookup_elem(blocked_ips_fd, &key, &existing_val) != 0);

    int err = bpf_map_update_elem(blocked_ips_fd, &key, &expire_duration, BPF_ANY);
    if (err) {
        LOG_E("Failed to update map %s\n", strerror(errno));
        return err;
    }

    int tcp_established_map_fd =
        bpf_object__find_map_fd_by_name(obj, "tcp_established_map");
    int tcp_connection_map_fd =
        bpf_object__find_map_fd_by_name(obj, "tcp_connection_map");
    if (tcp_established_map_fd >= 0 && tcp_connection_map_fd >= 0)
        clear_tracked_tcp_state_for_blocked_ip(tcp_established_map_fd,
                                               tcp_connection_map_fd, key);

    return is_new_entry ? 0 : 1;
}


// Append whitelist functions
int add_allow_ip(char *ip) {
    int allow_fd = bpf_object__find_map_fd_by_name(obj, "allowed_ips");
    if (allow_fd < 0) {
        LOG_E( "Failed to find allowed_ips\n");
        return -1;
    }
    __u32 key;
    if (inet_pton(AF_INET, ip, &key) != 1) {
        LOG_E( "Invalid IP address: %s\n", ip);
        return -1;
    }
    __u8 val = 1;
    return bpf_map_update_elem(allow_fd, &key, &val, BPF_ANY);
}

int clear_allow_ip(char *ip) {
    int allow_fd = bpf_object__find_map_fd_by_name(obj, "allowed_ips");
    if (allow_fd < 0) {
        LOG_E( "Failed to find allowed_ips\n");
        return -1;
    }
    __u32 key;
    if (inet_pton(AF_INET, ip, &key) != 1) {
        LOG_E( "Invalid IP address: %s\n", ip);
        return -1;
    }
    return bpf_map_delete_elem(allow_fd, &key);
}

int clear_allow_ip_all() {
    int allow_fd = bpf_object__find_map_fd_by_name(obj, "allowed_ips");
    if (allow_fd < 0) {
        LOG_E( "Failed to find allowed_ips\n");
        return -1;
    }
    return clear_batch_map(allow_fd);
}

int list_allow_ip(char **out) {
    *out = NULL;
    size_t off = 0, cap = 1024;
    char *buf = malloc(cap);
    if (!buf) return -1;

    struct bpf_map_info info = {}; __u32 len = sizeof(info);
    int allow_fd = bpf_object__find_map_fd_by_name(obj, "allowed_ips");
    if (allow_fd < 0) { LOG_E( "Failed to find allowed_ips\n"); free(buf); return -1; }
    if (bpf_obj_get_info_by_fd(allow_fd, &info, &len)) { free(buf); return -1; }

    void *key = calloc(1, info.key_size); void *next = calloc(1, info.key_size);
    if (!key || !next) { free(buf); free(key); free(next); return -1; }

    if (bpf_map_get_next_key(allow_fd, NULL, next)) {
        snprintf(buf, cap, "(No ip address in whitelist)\n");
        *out = buf; free(key); free(next); return 0;
    }

    char ip_str[INET_ADDRSTRLEN];
    do {
        struct in_addr addr = { .s_addr = *(__u32 *)next };
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        off += snprintf(buf + off, cap - off, "IP %s\n", ip_str);
        if (off >= cap - 16) { cap *= 2; buf = realloc(buf, cap); }
        memcpy(key, next, info.key_size);
    } while (!bpf_map_get_next_key(allow_fd, key, next));

    free(key); free(next);
    *out = buf;
    return 0;
}


int tcp_syn_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration,
                int challenge_timeout,
                int protection_duration)
{
    int key = 0;   
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    LOG_D("SYN Reset command is received (%d:%d:%d:%d:%d:%d:%d)\n", valid, threshold, burst_pkt, burst_counter, fixed_threshold, fixed_duration, challenge_timeout);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    if (burst_counter == 0) {
        LOG_E( "ERROR: burst count is zero\n");
        return -1;
    }

    global_fw_config.g_syn_config.valid = valid;
    global_fw_config.g_syn_config.syn_threshold = threshold;
    global_fw_config.g_syn_config.burst_pkt_threshold = burst_pkt;
    global_fw_config.g_syn_config.burst_count_threshold = burst_counter;
    global_fw_config.g_syn_config.syn_fixed_threshold = fixed_threshold;
    /* CLI sends seconds. The kernel compares this to bpf_ktime nanoseconds. */
    global_fw_config.g_syn_config.syn_fixed_check_duration = (__u64)fixed_duration * ONE_SECOND_NS;
    global_fw_config.g_syn_config.challenge_timeout = (__u64)challenge_timeout * ONE_SECOND_NS;
    global_fw_config.g_syn_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_syn_config.burst_count_threshold);
    global_fw_config.g_syn_config.syn_protect_duration = protection_duration;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }

    return 0;
}

int tcp_ack_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration,
                int protection_duration)
{
    int key = 0;   
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    LOG_D("ACK Reset command is received (%d:%d:%d:%d:%d:%d)\n", valid, threshold, burst_pkt, burst_counter, fixed_threshold, fixed_duration);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    if (burst_counter == 0) {
        LOG_E( "ERROR: burst count is zero\n");
        return -1;
    }

    global_fw_config.g_ack_config.valid = valid;
    global_fw_config.g_ack_config.ack_threshold = threshold;
    global_fw_config.g_ack_config.burst_pkt_threshold = burst_pkt;
    global_fw_config.g_ack_config.burst_count_threshold = burst_counter;
    global_fw_config.g_ack_config.ack_fixed_threshold = fixed_threshold;
    global_fw_config.g_ack_config.ack_fixed_check_duration = (__u64)fixed_duration * ONE_SECOND_NS;
    global_fw_config.g_ack_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_ack_config.burst_count_threshold);
    global_fw_config.g_ack_config.ack_protect_duration = protection_duration;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }

    return 0;
}


int tcp_rst_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration,
                int protection_duration)
{
    int key = 0;   
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    LOG_D("RST Reset command is received (%d:%d:%d:%d:%d:%d)\n", valid, threshold, burst_pkt, burst_counter, fixed_threshold, fixed_duration);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    if (burst_counter == 0) {
        LOG_E( "ERROR: burst count is zero\n");
        return -1;
    }

    global_fw_config.g_rst_config.valid = valid;
    global_fw_config.g_rst_config.rst_threshold = threshold;
    global_fw_config.g_rst_config.burst_pkt_threshold = burst_pkt;
    global_fw_config.g_rst_config.burst_count_threshold = burst_counter;
    global_fw_config.g_rst_config.rst_fixed_threshold = fixed_threshold;
    global_fw_config.g_rst_config.rst_fixed_check_duration = (__u64)fixed_duration * ONE_SECOND_NS;
    global_fw_config.g_rst_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_rst_config.burst_count_threshold);
    global_fw_config.g_rst_config.rst_protect_duration = protection_duration;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }
    
    return 0;
}

int tcp_stomp_set(int valid,
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration,
                int protection_duration)
{
    int key = 0;
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");

    LOG_D("STOMP command is received (%d:%d:%d:%d:%d:%d)\n", valid, threshold, burst_pkt, burst_counter, fixed_threshold, fixed_duration);

    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    if (burst_counter == 0) {
        LOG_E( "ERROR: burst count is zero\n");
        return -1;
    }

    global_fw_config.g_stomp_config.valid = valid;
    global_fw_config.g_stomp_config.stomp_threshold = threshold;
    global_fw_config.g_stomp_config.burst_pkt_threshold = burst_pkt;
    global_fw_config.g_stomp_config.burst_count_threshold = burst_counter;
    global_fw_config.g_stomp_config.stomp_fixed_threshold = fixed_threshold;
    global_fw_config.g_stomp_config.stomp_fixed_check_duration = (__u64)fixed_duration * ONE_SECOND_NS;
    global_fw_config.g_stomp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_stomp_config.burst_count_threshold);
    global_fw_config.g_stomp_config.stomp_protect_duration = protection_duration;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }

    return 0;
}

int tcp_socket_set(int valid,
                int fin_threshold,
                int fixed_threshold,
                int fixed_duration)
{
    int key = 0;
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");

    LOG_D("SOCKET command is received (%d:%d:%d:%d)\n", valid, fin_threshold, fixed_threshold, fixed_duration);

    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    global_fw_config.g_socket_config.valid = valid;
    global_fw_config.g_socket_config.socket_fin_threshold = fin_threshold;
    global_fw_config.g_socket_config.socket_fixed_threshold = fixed_threshold;
    global_fw_config.g_socket_config.socket_fixed_check_duration = (__u64)fixed_duration * ONE_SECOND_NS;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }

    return 0;
}

int icmp_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration,
                int protection_duration)
{
    int key = 0;   
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    LOG_D("ICMP Reset command is received (%d:%d:%d:%d:%d:%d)\n", valid, threshold, burst_pkt, burst_counter, fixed_threshold, fixed_duration);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    if (burst_counter == 0) {
        LOG_E( "ERROR: burst count is zero\n");
        return -1;
    }

    global_fw_config.g_icmp_config.valid = valid;
    global_fw_config.g_icmp_config.icmp_threshold = threshold;
    global_fw_config.g_icmp_config.burst_pkt_threshold = burst_pkt;
    global_fw_config.g_icmp_config.burst_count_threshold = burst_counter;
    global_fw_config.g_icmp_config.icmp_fixed_threshold = fixed_threshold;
    global_fw_config.g_icmp_config.icmp_fixed_check_duration = (__u64)fixed_duration * ONE_SECOND_NS;
    global_fw_config.g_icmp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_icmp_config.burst_count_threshold);
    global_fw_config.g_icmp_config.icmp_protect_duration = protection_duration;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }
    
    return 0;
}

int udp_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration,
                int protection_duration)
{
    int key = 0;   
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    LOG_D("UDP Reset command is received (%d:%d:%d:%d:%d:%d)\n", valid, threshold, burst_pkt, burst_counter, fixed_threshold, fixed_duration);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    if (burst_counter == 0) {
        LOG_E( "ERROR: burst count is zero\n");
        return -1;
    }

    global_fw_config.g_udp_config.valid = valid;
    global_fw_config.g_udp_config.udp_threshold = threshold;
    global_fw_config.g_udp_config.burst_pkt_threshold = burst_pkt;
    global_fw_config.g_udp_config.burst_count_threshold = burst_counter;
    global_fw_config.g_udp_config.udp_fixed_threshold = fixed_threshold;
    global_fw_config.g_udp_config.udp_fixed_check_duration = (__u64)fixed_duration * ONE_SECOND_NS;
    global_fw_config.g_udp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_udp_config.burst_count_threshold);
    global_fw_config.g_udp_config.udp_protect_duration = protection_duration;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }
    
    return 0;
}

int gre_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration,
                int protection_duration)
{
    int key = 0;   
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    LOG_D("GRE Reset command is received (%d:%d:%d:%d:%d:%d)\n", valid, threshold, burst_pkt, burst_counter, fixed_threshold, fixed_duration);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    if (burst_counter == 0) {
        LOG_E( "ERROR: burst count is zero\n");
        return -1;
    }

    global_fw_config.g_gre_config.valid = valid;
    global_fw_config.g_gre_config.gre_threshold = threshold;
    global_fw_config.g_gre_config.burst_pkt_threshold = burst_pkt;
    global_fw_config.g_gre_config.burst_count_threshold = burst_counter;
    global_fw_config.g_gre_config.gre_fixed_threshold = fixed_threshold;
    global_fw_config.g_gre_config.gre_fixed_check_duration = (__u64)fixed_duration * ONE_SECOND_NS;
    global_fw_config.g_gre_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_gre_config.burst_count_threshold);
    global_fw_config.g_gre_config.gre_protect_duration = protection_duration;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }
    
    return 0;
}

int tcp_seg_set(int valid)
{
   int key = 0;   
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    LOG_D("TCP SEG SET command is received (%d)\n", valid);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    global_fw_config.g_config.tcp_seg_check = valid;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }
    
    return 0;
}

int geo_set(int valid, 
            char * countries)
{
    int key = 0;   
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    if (valid && countries == NULL) {
        LOG_E( "Received countries is NULL\n");
        return -1;
    }

    LOG_D("Geo Set command is received (%d:%s)\n", valid, countries == NULL ? "NULL" : countries);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    global_fw_config.g_geo_config.check = valid;

    if (global_fw_config.g_geo_config.check) {
        int geo_map_fd = -1;
        if (global_fw_config.g_geo_config.check == 1) {
            LOG_D("Clearing geoip_trie_map\n");
            geo_map_fd = bpf_object__find_map_fd_by_name(obj, "geoip_trie_map");
            if (geo_map_fd < 0) {
                LOG_E( "ERROR: finding geo_map_fd: %d\n", geo_map_fd);
                return -1;
            }
        } else {
            LOG_D("Clearing geoip_trie_block_map\n");
            geo_map_fd = bpf_object__find_map_fd_by_name(obj, "geoip_trie_block_map");
            if (geo_map_fd < 0) {
                LOG_E( "ERROR: finding geo_block_map_fd: %d\n", geo_map_fd);
                return -1;
            }
        }
        

        if (clear_geoip_trie_map(geo_map_fd) < 0) {
            LOG_E("Failed to clear geoip_trie_map\n");    
        } else 
            LOG_D("geoip_trie_map is cleared\n");
        
        char isos[256][3];
        int nisos = 0;

        char * str_token = strtok(countries, ",");
        while (str_token != NULL) {
            if (nisos >= 255) break;
            strncpy(isos[nisos], str_token, 2);
            isos[nisos][2] = '\0';
            LOG_D("Parsed country iso is %s\n", isos[nisos]);
            nisos ++;
            str_token = strtok(NULL, ",");
        }

        if (init_geo(geo_db_location_path, geo_db_ipv4_path, isos, nisos, geo_map_fd) < 0) {
            LOG_E("Failed to update geoip_trie_map");
            return -1;
        }
    }

    {
        __u32 g = global_fw_config.g_geo_config.cache_generation + 1;
        if (g == 0)
            g = 1;
        global_fw_config.g_geo_config.cache_generation = g;
    }

    if (bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
        return -1;
    }

    return 0;
}


int tcp_conn_limit_set(int valid, 
            int count)
{
    int key = 0;   
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    LOG_D("TCP conn limit Reset command is received (%d:%d)\n", valid, count);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    global_fw_config.g_tcp_connection_config.check = valid;
    global_fw_config.g_tcp_connection_config.limit_cnt = count;

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem\n");
        return -1;
    }
    
    return 0;
}


static int send_message_to_api_parser_direct(const char *message)
{
    if (api_parser_sock_fd < 0) {
        LOG_E("AF_UNIX DGRAM sender is not initialized\n");
        return -1;
    }

    for (int attempt = 0; attempt < 50; attempt++) {
        ssize_t written = sendto(api_parser_sock_fd, message, strlen(message), 0,
                                 (const struct sockaddr *)&api_parser_sock_addr,
                                 sizeof(api_parser_sock_addr));
        if (written >= 0) {
            return 0;
        }

        if (errno == EAGAIN || errno == ENOBUFS || errno == EINTR ||
            errno == ENOENT || errno == ECONNREFUSED) {
            usleep(10 * 1000);
            continue;
        }

        LOG_E("Failed to send AF_UNIX dgram '%s': %s\n",
              API_PARSER_UNIX_DGRAM_PATH, strerror(errno));
        return -1;
    }

    LOG_E("Failed to send AF_UNIX dgram '%s' after retries: %s\n",
          API_PARSER_UNIX_DGRAM_PATH, strerror(errno));
    return -1;
}

int send_message_to_api_parser(const char *message) {
    if (!message) {
        return -1;
    }

    //LOG_D("%s", message);
    (void)pthread_once(&fifo_sender_once, init_fifo_sender_worker_once);

    char *msg_copy = strdup(message);
    if (!msg_copy) {
        LOG_E("Failed to allocate FIFO message copy\n");
        return -1;
    }

    pthread_mutex_lock(&fifo_q_mutex);
    if (fifo_q_size >= FIFO_MSG_QUEUE_CAPACITY) {
        fifo_q_dropped++;
        if ((fifo_q_dropped % 100) == 1) {
            LOG_W("API parser queue is full, dropping messages (dropped=%d)\n", fifo_q_dropped);
        }
        pthread_mutex_unlock(&fifo_q_mutex);
        free(msg_copy);
        return -1;
    }

    fifo_msg_queue[fifo_q_tail] = msg_copy;
    fifo_q_tail = (fifo_q_tail + 1) % FIFO_MSG_QUEUE_CAPACITY;
    fifo_q_size++;
    pthread_cond_signal(&fifo_q_cv);
    pthread_mutex_unlock(&fifo_q_mutex);

    return 0;
}

static int append_block_ip_to_sqlite_sync(const char *ip_str, int block_duration, const char *reason)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;

    const char *dbpath = ebpf_sqlite_db_path();
    if (sqlite3_open(dbpath, &db) != SQLITE_OK) {
        LOG_E("Cannot open database '%s': %s\n", dbpath, sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        return -1;
    }

    char created[32];
    time_t now = time(NULL);
    struct tm gmt;
    gmtime_r(&now, &gmt);
    strftime(created, sizeof(created), "%Y-%m-%d %H:%M:%S", &gmt);

    char duration_str[1024];
    if (block_duration == 0)
        snprintf(duration_str, sizeof(duration_str), "%lld",
                 global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS);
    else
        snprintf(duration_str, sizeof(duration_str), "%d", block_duration);

    const char *sql =
        "INSERT INTO blocked_ips (ip, type, duration, reason, created) "
        "VALUES (?, 'Auto', ?, ?, ?);";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        LOG_E("Failed to prepare insert: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip_str, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, duration_str, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, reason ? reason : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, created, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        LOG_E("Failed to insert data: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int append_block_ip_to_sqlite(const char *ip_str, int block_duration, const char *reason)
{
    if (!ip_str)
        return -1;

    pthread_once(&sqlite_worker_once, sqlite_worker_start_once);
    if (!sqlite_worker_thr_valid)
        return append_block_ip_to_sqlite_sync(ip_str, block_duration, reason);

    pthread_mutex_lock(&sqlite_block_q_mutex);
    if (sqlite_block_q_size >= SQLITE_BLOCK_Q_CAP) {
        sqlite_block_q_dropped++;
        if ((sqlite_block_q_dropped % 100) == 1)
            LOG_W("SQLite block queue full, dropping rows (dropped=%d)\n", sqlite_block_q_dropped);
        pthread_mutex_unlock(&sqlite_block_q_mutex);
        return -1;
    }

    sqlite_block_job_t *slot = &sqlite_block_q[sqlite_block_q_tail];
    strncpy(slot->ip, ip_str, sizeof(slot->ip) - 1);
    slot->ip[sizeof(slot->ip) - 1] = '\0';
    slot->block_duration = block_duration;
    if (reason) {
        strncpy(slot->reason, reason, sizeof(slot->reason) - 1);
        slot->reason[sizeof(slot->reason) - 1] = '\0';
    } else {
        slot->reason[0] = '\0';
    }
    sqlite_block_q_tail = (sqlite_block_q_tail + 1) % SQLITE_BLOCK_Q_CAP;
    sqlite_block_q_size++;
    pthread_cond_signal(&sqlite_block_q_cv);
    pthread_mutex_unlock(&sqlite_block_q_mutex);
    return 0;
}

int append_allow_ip_to_sqlite(const char *ip_str, const char *reason) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;

    const char *dbpath = ebpf_sqlite_db_path();
    if (sqlite3_open(dbpath, &db) != SQLITE_OK) {
        LOG_E("Cannot open database '%s': %s\n", dbpath, sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        return -1;
    }

    char created[32];
    time_t now = time(NULL);
    struct tm gmt;
    gmtime_r(&now, &gmt);
    strftime(created, sizeof(created), "%Y-%m-%d %H:%M:%S", &gmt);

    const char *sql =
        "INSERT INTO white_ips (ip, reason, created) "
        "VALUES (?, ?, ?);";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        LOG_E("Failed to prepare whitelist insert: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip_str, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, reason ? reason : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, created, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        LOG_E("Failed to insert whitelist data: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}