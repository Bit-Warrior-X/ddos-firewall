#include <ebpf_firewall_common.h>
#include <ebpf_firewall_config.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_geo.h>
#include <ebpf_firewall_core.h>
#include <ebpf_firewall_utils.h>
#include <ebpf_firewall_shadow.h>

#include <stdio.h>
#include <dirent.h>
#include <sqlite3.h>

// Global configuration
char token[128];             // Token used for expiration check
char ifname[IFNAMSIZ];       // Network interface name
__u32 attach_mode;           // Attach mode of ebpf
int n_cpus = 1;              // CPU count
char log_path[512];          // Log path
FILE* log_file = NULL;       // Log file descriptor

char geo_db_ipv4_path[512];     // Geo Ipv4 block database path 
char geo_db_location_path[512]; // Geo location code database path


/* Global time offset (in nanoseconds) to convert from monotonic to real time */
__u64 time_offset_ns = 0;
long tz_offset_sec = 0;      // Timezone offset

struct capacity_profile global_capacity_profile = {0};
/* Optional overrides from redesign keys; -1 = use refresh defaults. */
static int cfg_http3_override = -1;
static int cfg_gre_tunnels_override = -1;
static int cfg_dns_override = -1;
static char gre_peers_buf[512];
static char udp_extra_ports_buf[256];

static int map_put_u16(int fd, __u16 k)
{
    __u8 one = 1;
    return bpf_map_update_elem(fd, &k, &one, BPF_ANY);
}

static int map_put_u8(int fd, __u8 k)
{
    __u8 one = 1;
    return bpf_map_update_elem(fd, &k, &one, BPF_ANY);
}

static int map_put_u32(int fd, __u32 k)
{
    __u8 one = 1;
    return bpf_map_update_elem(fd, &k, &one, BPF_ANY);
}

static __u64 cap_clamp(__u64 v, __u64 floor, __u64 cap)
{
    if (v < floor)
        return floor;
    if (v > cap)
        return cap;
    return v;
}

static __u32 read_sysfs_u32(const char *path, __u32 fallback)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return fallback;
    long v = -1;
    if (fscanf(f, "%ld", &v) != 1) {
        fclose(f);
        return fallback;
    }
    fclose(f);
    if (v <= 0)
        return fallback;
    return (__u32)v;
}

static __u32 count_combined_rx_queues(const char *dev)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", dev);
    DIR *d = opendir(path);
    if (!d)
        return 1;
    __u32 n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "rx-", 3) == 0)
            n++;
    }
    closedir(d);
    return n ? n : 1;
}

/* Phase 2: derive host/class ceilings from NIC line rate and RX/CPU budget.
 * Shadow only — does not change static gates until Phase 3+. */
int refresh_capacity_profile(void)
{
    struct capacity_profile p = {0};
    p.http3 = (cfg_http3_override >= 0) ? (cfg_http3_override ? 1 : 0) : 1;
    p.gre_tunnels = (cfg_gre_tunnels_override >= 0) ? (cfg_gre_tunnels_override ? 1 : 0) : 0;

    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", ifname);
    p.link_mbps = read_sysfs_u32(path, CAP_LINK_FALLBACK_MBPS);
    p.rx_queues = count_combined_rx_queues(ifname);

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 1)
        nproc = 1;
    p.xdp_cores = p.rx_queues < (__u32)nproc ? p.rx_queues : (__u32)nproc;
    if (p.xdp_cores < 1)
        p.xdp_cores = 1;

    /* 64B frame + 20B preamble/IFG → bits per minimum packet on the wire. */
    __u64 link_bps = (__u64)p.link_mbps * 1000000ULL;
    p.line_pps = link_bps / ((64ULL + 20ULL) * 8ULL);
    p.cpu_pps = (__u64)p.xdp_cores * CAP_PER_CORE_PPS_DEFAULT;

    __u64 bottleneck = p.line_pps < p.cpu_pps ? p.line_pps : p.cpu_pps;
    p.host_ceiling_pps = (bottleneck * CAP_CEILING_FRACTION_NUM) / CAP_CEILING_FRACTION_DEN;
    p.host_ceiling_bps = (link_bps * 80ULL) / 100ULL;

    __u64 cap_syn = (p.host_ceiling_pps * 2ULL) / 100ULL;
    __u64 cap_ack = (p.host_ceiling_pps * 5ULL) / 100ULL;
    __u64 cap_rst = (p.host_ceiling_pps * 1ULL) / 100ULL;
    __u64 cap_icmp = (p.host_ceiling_pps * 5ULL) / 1000ULL;
    __u64 cap_udp = p.http3
                        ? (p.host_ceiling_pps * 15ULL) / 100ULL
                        : (p.host_ceiling_pps * 5ULL) / 100ULL;
    __u64 cap_gre = (p.host_ceiling_pps * 5ULL) / 1000ULL;
    __u64 cap_data = (p.host_ceiling_pps * 10ULL) / 100ULL;

    p.cap_syn = cap_clamp(cap_syn, 20000ULL, cap_syn ? cap_syn : 20000ULL);
    p.cap_ack = cap_clamp(cap_ack, 50000ULL, cap_ack ? cap_ack : 50000ULL);
    p.cap_rst = cap_clamp(cap_rst, 10000ULL, cap_rst ? cap_rst : 10000ULL);
    p.cap_icmp = cap_clamp(cap_icmp, 2000ULL, cap_icmp ? cap_icmp : 2000ULL);
    p.cap_udp = cap_clamp(cap_udp,
                          p.http3 ? 50000ULL : 20000ULL,
                          cap_udp ? cap_udp : (p.http3 ? 50000ULL : 20000ULL));
    /* No tunnels: GRE gate sits at the floor. */
    p.cap_gre = p.gre_tunnels
                    ? cap_clamp(cap_gre, 1000ULL, cap_gre ? cap_gre : 1000ULL)
                    : 1000ULL;
    p.cap_data = cap_clamp(cap_data, 50000ULL, cap_data ? cap_data : 50000ULL);

    global_capacity_profile = p;

    LOG_I("Capacity[%s]: link=%uMb/s queues=%u cores=%u line=%llu cpu=%llu "
          "ceiling=%llu pps  caps SYN=%llu ACK=%llu RST=%llu ICMP=%llu "
          "UDP=%llu GRE=%llu DATA=%llu (shadow)\n",
          ifname, p.link_mbps, p.rx_queues, p.xdp_cores,
          (unsigned long long)p.line_pps, (unsigned long long)p.cpu_pps,
          (unsigned long long)p.host_ceiling_pps,
          (unsigned long long)p.cap_syn, (unsigned long long)p.cap_ack,
          (unsigned long long)p.cap_rst, (unsigned long long)p.cap_icmp,
          (unsigned long long)p.cap_udp, (unsigned long long)p.cap_gre,
          (unsigned long long)p.cap_data);
    return 0;
}

struct global_firewall_config global_fw_config ={
    .g_attack_stats = {0},
    .g_config = {
        .tcp_seg_check = 0,
        .enforce_drop_invalid = 1, /* Phase 4 on by default */
        .prefer_adaptive = 1,      /* Phase 5: adaptive owns Attack start */
        .stats_detail_sample_divisor = 1,
        .black_ip_duration = 0,
        .block_initial_ns = 60ULL * ONE_SECOND_NS,
        .block_max_ns = 3600ULL * ONE_SECOND_NS,
        .svc = {
            .http3 = 1,
            .dns = 0,
            .gre_tunnels = 0,
            .quic_header_check = 1,
            .icmp_drop_fragments = 1,
            .synack_match_outbound = 1,
            .ipv6_enabled = 1,
        },
    },
    .g_syn_config = {
        .valid = 1,
        .syn_threshold = SYN_THRESHOLD,
        .burst_pkt_threshold = SYN_BURST_PKT_THRESHOLD,
        .burst_count_threshold = SYN_BURST_COUNT_THRESHOLD,
        .challenge_timeout = SYN_CHALLENGE_TIMEOUT_NS,
        .syn_fixed_threshold = SYN_FIXED_THRESHOLD,
        .syn_fixed_check_duration = SYN_FIXED_CHECK_DURATION_NS,
        .syn_protect_duration = SYN_PROTECTION_DURATION
    },
    .g_ack_config = {
        .valid = 1,
        .ack_threshold = ACK_THRESHOLD,
        .burst_pkt_threshold = ACK_BURST_PKT_THRESHOLD,
        .burst_count_threshold = ACK_BURST_COUNT_THRESHOLD,
        .ack_fixed_threshold = ACK_FIXED_THRESHOLD,
        .ack_fixed_check_duration = ACK_FIXED_CHECK_DURATION_NS,
        .ack_protect_duration = ACK_PROTECTION_DURATION
    },
    .g_rst_config = {
        .valid = 1,
        .rst_threshold = RST_THRESHOLD,
        .burst_pkt_threshold = RST_BURST_PKT_THRESHOLD,
        .burst_count_threshold = RST_BURST_COUNT_THRESHOLD,
        .rst_fixed_threshold = RST_FIXED_THRESHOLD,
        .rst_fixed_check_duration = RST_FIXED_CHECK_DURATION_NS,
        .rst_protect_duration = RST_PROTECTION_DURATION
    },
    .g_icmp_config = {
        .valid = 1,
        .icmp_threshold = ICMP_THRESHOLD,
        .burst_pkt_threshold = ICMP_BURST_PKT_THRESHOLD,
        .burst_count_threshold = ICMP_BURST_COUNT_THRESHOLD,
        .icmp_fixed_threshold = ICMP_FIXED_THRESHOLD,
        .icmp_fixed_check_duration = ICMP_FIXED_CHECK_DURATION_NS,
        .icmp_protect_duration = ICMP_PROTECTION_DURATION
    },
    .g_udp_config = {
        .valid = 1,
        .udp_threshold = UDP_THRESHOLD,
        .burst_pkt_threshold = UDP_BURST_PKT_THRESHOLD,
        .burst_count_threshold = UDP_BURST_COUNT_THRESHOLD,
        .udp_fixed_threshold = UDP_FIXED_THRESHOLD,
        .udp_fixed_check_duration = UDP_FIXED_CHECK_DURATION_NS,
        .udp_protect_duration = UDP_PROTECTION_DURATION
    },
    .g_gre_config = {
        .valid = 1,
        .gre_threshold = GRE_THRESHOLD,
        .burst_pkt_threshold = GRE_BURST_PKT_THRESHOLD,
        .burst_count_threshold = GRE_BURST_COUNT_THRESHOLD,
        .gre_fixed_threshold = GRE_FIXED_THRESHOLD,
        .gre_fixed_check_duration = GRE_FIXED_CHECK_DURATION_NS,
        .gre_protect_duration = GRE_PROTECTION_DURATION
    },
    .g_geo_config = {
        .check = 0,
        .cache_generation = 0,
    },
    .g_tcp_connection_config = {
        .check = 0,
        .limit_cnt = 0
    },
    .g_stomp_config = {
        .valid = 1,
        .stomp_threshold = STOMP_THRESHOLD,
        .burst_pkt_threshold = STOMP_BURST_PKT_THRESHOLD,
        .burst_count_threshold = STOMP_BURST_COUNT_THRESHOLD,
        .stomp_fixed_threshold = STOMP_FIXED_THRESHOLD,
        .stomp_fixed_check_duration = STOMP_FIXED_CHECK_DURATION_NS,
        .stomp_protect_duration = STOMP_PROTECTION_DURATION
    },
    .g_handshake_config = {
        .valid = 1,
        .handshake_threshold = HANDSHAKE_THRESHOLD,
        .burst_pkt_threshold = HANDSHAKE_BURST_PKT_THRESHOLD,
        .burst_count_threshold = HANDSHAKE_BURST_COUNT_THRESHOLD,
        .handshake_fixed_threshold = HANDSHAKE_FIXED_THRESHOLD,
        .handshake_fixed_check_duration = HANDSHAKE_FIXED_CHECK_DURATION_NS,
        .handshake_protect_duration = HANDSHAKE_PROTECTION_DURATION
    },
    .g_socket_config = {
        .valid = 1,
        .socket_fin_threshold = SOCKET_FIN_THRESHOLD,
        .socket_fixed_threshold = SOCKET_FIXED_THRESHOLD,
        .socket_fixed_check_duration = SOCKET_FIXED_CHECK_DURATION_NS
    }
};

static int calc_cpus_count(void)
{
    return sysconf(_SC_NPROCESSORS_CONF);
}

static long get_timezone_offset() {
    time_t t = time(NULL);
    struct tm local, utc;

    localtime_r(&t, &local);  // Local time (CST)
    gmtime_r(&t, &utc);       // UTC time

    // Calculate the difference in seconds
    long offset = (local.tm_hour - utc.tm_hour) * 3600
                + (local.tm_min - utc.tm_min) * 60
                + (local.tm_sec - utc.tm_sec);
    
    // Adjust for day difference (e.g., UTC+8 vs UTC-5)
    if (local.tm_mday != utc.tm_mday) {
        offset += (local.tm_mday > utc.tm_mday) ? 86400 : -86400;
    }
    
    return offset;
}

/* Context for loading blocked/whitelist from SQLite; used to prune expired blocked rows. */
struct load_block_white_ctx {
    struct bpf_object *obj;
    sqlite3_int64 *expired_blocked_ids;
    size_t expired_cap;
    size_t expired_n;
};

static int append_expired_blocked_id(struct load_block_white_ctx *ctx, sqlite3_int64 id)
{
    if (id <= 0)
        return 0;
    if (ctx->expired_n >= ctx->expired_cap) {
        size_t newcap = ctx->expired_cap ? ctx->expired_cap * 2 : 16;
        sqlite3_int64 *p = realloc(ctx->expired_blocked_ids,
                                   newcap * sizeof(*p));
        if (!p)
            return -1;
        ctx->expired_blocked_ids = p;
        ctx->expired_cap = newcap;
    }
    ctx->expired_blocked_ids[ctx->expired_n++] = id;
    return 0;
}

static int delete_expired_blocked_rows(sqlite3 *db, struct load_block_white_ctx *ctx)
{
    int any_err = 0;
    sqlite3_stmt *stmt = NULL;

    if (ctx->expired_n == 0)
        return 0;

    /* One transaction: per-row autocommit costs an fdatasync each, which after a
     * large episode (300k+ rows) delays XDP attach by hours. */
    if (sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL) != SQLITE_OK) {
        LOG_E("BEGIN for expired blocked_ips delete: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    if (sqlite3_prepare_v2(db, "DELETE FROM blocked_ips WHERE id=?;", -1, &stmt, NULL) != SQLITE_OK) {
        LOG_E("prepare expired blocked_ips delete: %s\n", sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }
    for (size_t i = 0; i < ctx->expired_n; i++) {
        sqlite3_bind_int64(stmt, 1, ctx->expired_blocked_ids[i]);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            LOG_E("Failed to delete expired blocked_ips row id %lld: %s\n",
                  (long long)ctx->expired_blocked_ids[i], sqlite3_errmsg(db));
            any_err = 1;
        }
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        LOG_E("COMMIT expired blocked_ips delete: %s\n", sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }
    LOG_I("Deleted %zu expired blocked_ips rows\n", ctx->expired_n);
    return any_err ? -1 : 0;
}

// Callback function for blocked_ips
int blocked_ips_callback(void *param_obj, int argc, char **argv, char **azColName) {
    struct load_block_white_ctx *ctx = (struct load_block_white_ctx *)param_obj;
    struct bpf_object *obj = ctx->obj;
    
    //LOG_D("Blocked IP Record:\n");

    __u32 ip = 0, duration = 0;
    __u64 created = 0;
    sqlite3_int64 row_id = 0;
    char reason[256] = {0};
    for(int i = 0; i < argc; i++) {
        //LOG_D("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        if (strncmp(azColName[i], "ip", 2) == 0 && argv[i]) {
            // Store IP address;
            struct in_addr addr;
            if (inet_pton(AF_INET, argv[i], &addr))
                ip = addr.s_addr;
        }
        if (strncmp(azColName[i], "duration", 8) == 0 && argv[i]) {
            // Store duration;
            if (strncmp(argv[i], "Permanent", strlen("Permanent")) == 0 || strncmp(argv[i], "permanent", strlen("permanent")) == 0) duration = -1;
            else duration = atoi(argv[i]);
        }
        if (strncmp(azColName[i], "created", 7) == 0 && argv[i]) {
            // Store created;
            struct tm tm = {0};
            int yr, mo, dy, hr, mi, sec;
            if (sscanf(argv[i], "%4d-%2d-%2d %2d:%2d:%2d",
                    &yr, &mo, &dy, &hr, &mi, &sec) == 6)
            {
                struct tm tm = { .tm_year = yr - 1900,
                                .tm_mon  = mo  - 1,
                                .tm_mday = dy,
                                .tm_hour = hr,
                                .tm_min  = mi,
                                .tm_sec  = sec };
                created = timegm(&tm);
            }
        }
        if (strncmp(azColName[i], "reason", 6) == 0 && argv[i]) {
            // Store reason;
            strncpy(reason, argv[i], sizeof(reason));
        }
        if (strcmp(azColName[i], "id") == 0 && argv[i])
            row_id = strtoll(argv[i], NULL, 10);
    }

    if (ip != 0) {
        int blocked_ips_fd;
        blocked_ips_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
        if (blocked_ips_fd < 0) {
            LOG_E( "Failed to find blocked_ips\n");
            return -1;
        }
        
        __u64 expire_duration;
        if (duration == -1) expire_duration = -1;
        else {
            struct tm tm;
            time_t t = time(NULL);
            gmtime_r(&t, &tm);  // Thread-safe UTC conversion
            __u64 current_epoch = timegm(&tm);  // Direct UTC conversion (non-standard but widely available)

            if (created + duration <= current_epoch) {
                if (append_expired_blocked_id(ctx, row_id) < 0)
                    return -1;
                return 0;
            }
            __u64 seconds =  created + duration - current_epoch;
            if (seconds < 0) return 0;
            {
                struct in_addr addr = { .s_addr = ip };
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                LOG_D("ip = %s, duration = %d, created = %ld expire in %llu seconds reason = %s\n",
                      ip_str, duration, created, (unsigned long long)seconds, reason);
            }

            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            __u64 nowns = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

            expire_duration = nowns + seconds * ONE_SECOND_NS;
        }

        bpf_map_update_elem(blocked_ips_fd, &ip, &expire_duration, BPF_ANY);
    }
    
    return 0;
}

// Callback function for white_ips
int white_ips_callback(void *param_obj, int argc, char **argv, char **azColName) {
    struct bpf_object *obj = (struct bpf_object *)param_obj;
    
    //LOG_D("Whitelisted IP Record:\n");
     __u32 ip = 0;
    __u64 created = 0;

    for(int i = 0; i < argc; i++) {
        //LOG_D("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        if (strncmp(azColName[i], "ip", 2) == 0 && argv[i]) {
            // Store IP address;
            struct in_addr addr;
            if (inet_pton(AF_INET, argv[i], &addr))
                ip = addr.s_addr;
        }
        if (strncmp(azColName[i], "created", 7) == 0 && argv[i]) {
            // Store created;
            struct tm tm = {0};
            int yr, mo, dy, hr, mi, sec;
            if (sscanf(argv[i], "%4d-%2d-%2d %2d:%2d:%2d",
                    &yr, &mo, &dy, &hr, &mi, &sec) == 6)
            {
                struct tm tm = { .tm_year = yr - 1900,
                                .tm_mon  = mo  - 1,
                                .tm_mday = dy,
                                .tm_hour = hr,
                                .tm_min  = mi,
                                .tm_sec  = sec };
                created = timegm(&tm);
            }
        }
    }

    if (ip != 0) {
        struct in_addr addr = { .s_addr = ip };
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        LOG_D("ip = %s created = %ld\n", ip_str, created);
        int white_ips_fd;
        white_ips_fd = bpf_object__find_map_fd_by_name(obj, "allowed_ips");
        if (white_ips_fd < 0) {
            LOG_E( "Failed to find allow_ips\n");
            return -1;
        }
        __u8 val = 1;
        bpf_map_update_elem(white_ips_fd, &ip, &val, BPF_ANY);
    }

    return 0;
}

static int load_block_white_list(struct bpf_object *obj) {
    sqlite3 *db;
    char *err_msg = 0;
    int rc;
    struct load_block_white_ctx ctx = {
        .obj = obj,
        .expired_blocked_ids = NULL,
        .expired_cap = 0,
        .expired_n = 0,
    };

    // Open database connection
    rc = sqlite3_open(ebpf_sqlite_db_path(), &db);
    
    if (rc != SQLITE_OK) {
        LOG_E("Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    /* Create tables if they don't exist */
    const char *sql_create_blocked =
        "CREATE TABLE IF NOT EXISTS blocked_ips ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip TEXT NOT NULL,"
        "type TEXT NOT NULL,"
        "duration TEXT NOT NULL,"
        "reason TEXT,"
        "created DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";

    rc = sqlite3_exec(db, sql_create_blocked, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        LOG_E("Failed to ensure blocked_ips table exists: %s\n",
              err_msg ? err_msg : "(unknown)");
        if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }
        rc = -1;
        goto cleanup;
    }
    if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }

    const char *sql_create_white =
        "CREATE TABLE IF NOT EXISTS white_ips ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip TEXT NOT NULL,"
        "reason TEXT,"
        "created DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";

    rc = sqlite3_exec(db, sql_create_white, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        LOG_E("Failed to ensure white_ips table exists: %s\n",
              err_msg ? err_msg : "(unknown)");
        if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }
        rc = -1;
        goto cleanup;
    }
    if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }
    
    // Read from blocked_ips table
    char *sql_blocked = "SELECT * FROM blocked_ips;";
    
    LOG_D("Reading blocked IPs...\n");
    rc = sqlite3_exec(db, sql_blocked, blocked_ips_callback, &ctx, &err_msg);
    
    if (rc != SQLITE_OK) {
        LOG_E("SQL error (blocked_ips): %s\n", err_msg ? err_msg : "(unknown)");
        if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }
        rc = -1;
        goto cleanup;  // <-- ensure DB is closed
    }
    if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }

    if (delete_expired_blocked_rows(db, &ctx) < 0)
        rc = -1;

    // Read from white_ips table
    char *sql_white = "SELECT * FROM white_ips;";
    
    LOG_D("Reading whitelisted IPs...\n");
    rc = sqlite3_exec(db, sql_white, white_ips_callback, obj, &err_msg);
    
    if (rc != SQLITE_OK) {
        LOG_E("SQL error (white_ips): %s\n", err_msg ? err_msg : "(unknown)");
        if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }
        rc = -1;
        goto cleanup;
    }
    if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }
    
cleanup:
    free(ctx.expired_blocked_ids);
    // Close database connection
    sqlite3_close(db);
    return (rc == 0) ? 0 : -1;
}

/* 
 * Initialize the time offset:
 *   time_offset = current_realtime - current_monotonic.
 */
int init_time_offset(void)
{
    struct timespec ts_realtime, ts_monotonic;
    if (clock_gettime(CLOCK_REALTIME, &ts_realtime) != 0) {
        perror("clock_gettime(CLOCK_REALTIME)");
        return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &ts_monotonic) != 0) {
        perror("clock_gettime(CLOCK_MONOTONIC)");
        return -1;
    }
    __u64 realtime_ns = ts_realtime.tv_sec * ONE_SECOND_NS + ts_realtime.tv_nsec;
    __u64 monotonic_ns = ts_monotonic.tv_sec * ONE_SECOND_NS + ts_monotonic.tv_nsec;
    /* Compute offset; this is the amount that needs to be added to a monotonic time
       to get a (UTC) epoch time */
    if (realtime_ns > monotonic_ns)
        time_offset_ns = realtime_ns - monotonic_ns;
    else
        time_offset_ns = 0;  /* Fallback if something is wrong */

    return 0;
}

// Trim whitespace from string
static void trim_whitespace(char *str) {
    char *end = str + strlen(str) - 1;
    while (end >= str && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    *(end + 1) = '\0';
}

/*
 * Pick the interface used for the IPv4 default route (lowest metric if several).
 * Returns 0 on success.
 */
static int read_default_route_iface(char *out, size_t outsz)
{
    FILE *rf = fopen("/proc/net/route", "r");
    char line[512];
    char iface[IFNAMSIZ];
    unsigned int dest;
    int metric;
    int best_metric = 0;
    int have_best = 0;
    char best[IFNAMSIZ] = {0};

    if (!rf)
        return -1;
    if (!fgets(line, sizeof(line), rf)) {
        fclose(rf);
        return -1;
    }
    while (fgets(line, sizeof(line), rf)) {
        if (sscanf(line, "%15s %x %*x %*x %*d %*d %d %*x",
                   iface, &dest, &metric) != 3)
            continue;
        if (dest != 0)
            continue;
        if (!have_best || metric < best_metric) {
            best_metric = metric;
            have_best = 1;
            strncpy(best, iface, IFNAMSIZ - 1);
            best[IFNAMSIZ - 1] = '\0';
        }
    }
    fclose(rf);
    if (!have_best)
        return -1;
    strncpy(out, best, outsz);
    out[outsz - 1] = '\0';
    return 0;
}

/*
 * If the configured iface does not resolve, log why and use the default-route
 * adapter (or eth0 as last resort).
 */
static int ensure_usable_ifname(void)
{
    char saved[IFNAMSIZ];

    if (ifname[0] != '\0' && if_nametoindex(ifname) != 0)
        return 0;

    strncpy(saved, ifname, IFNAMSIZ);
    saved[IFNAMSIZ - 1] = '\0';

    if (ifname[0] == '\0')
        LOG_W("Network device name from config is empty; selecting main adapter\n");
    else
        LOG_W("Network device '%s' from config is not available (%s); selecting main adapter instead\n",
              saved, strerror(errno));

    if (read_default_route_iface(ifname, IFNAMSIZ) == 0 && if_nametoindex(ifname) != 0) {
        LOG_I("Using default-route network adapter: %s\n", ifname);
        return 0;
    }

    strncpy(ifname, "eth0", IFNAMSIZ);
    ifname[IFNAMSIZ - 1] = '\0';
    if (if_nametoindex(ifname) != 0) {
        LOG_W("Could not resolve default-route interface; using eth0\n");
        return 0;
    }

    LOG_E("No usable network adapter (configured '%s', default route and eth0 unavailable)\n",
          saved[0] ? saved : "(empty)");
    return -1;
}

/* Populate validity allowlist maps from service profile + redesign keys. */
static int populate_validity_maps(struct bpf_object *obj)
{
    int udp_fd = bpf_object__find_map_fd_by_name(obj, "udp_allowed_dports");
    int refl_fd = bpf_object__find_map_fd_by_name(obj, "udp_reflection_sports");
    int icmp_fd = bpf_object__find_map_fd_by_name(obj, "icmp_allowed_types");
    int gre_fd = bpf_object__find_map_fd_by_name(obj, "gre_allowed_peers");
    if (udp_fd < 0 || refl_fd < 0 || icmp_fd < 0 || gre_fd < 0) {
        LOG_W("Validity maps missing; allowlists skipped\n");
        return 0;
    }

    struct service_profile *svc = &global_fw_config.g_config.svc;
    if (cfg_http3_override >= 0)
        svc->http3 = cfg_http3_override ? 1 : 0;
    if (cfg_gre_tunnels_override >= 0)
        svc->gre_tunnels = cfg_gre_tunnels_override ? 1 : 0;
    if (cfg_dns_override >= 0)
        svc->dns = cfg_dns_override ? 1 : 0;

    /* Clear by replacing entries — HASH maps: delete not required for boot. */
    if (svc->http3) {
        map_put_u16(udp_fd, 443);
    }
    if (svc->dns) {
        map_put_u16(udp_fd, 53);
    }
    /* Always allow common management / NTP when listed in redesign defaults —
     * only ports explicitly opened by service profile + extras are valid under mode≥1.
     * Add udp_extra_allowed_ports. */
    if (udp_extra_ports_buf[0]) {
        char *save = NULL;
        char buf[256];
        strncpy(buf, udp_extra_ports_buf, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            int p = atoi(tok);
            if (p > 0 && p < 65536)
                map_put_u16(udp_fd, (__u16)p);
        }
    }

    /* Reflection source ports (plan defaults). */
    static const __u16 refl[] = {19, 53, 123, 161, 389, 1900, 3702, 11211};
    for (unsigned i = 0; i < sizeof(refl) / sizeof(refl[0]); i++)
        map_put_u16(refl_fd, refl[i]);

    /* ICMP: echo reply/request, dest unreachable, time exceeded. */
    static const __u8 ict[] = {0, 3, 8, 11};
    for (unsigned i = 0; i < sizeof(ict); i++)
        map_put_u8(icmp_fd, ict[i]);

    if (svc->gre_tunnels && gre_peers_buf[0]) {
        char *save = NULL;
        char buf[512];
        strncpy(buf, gre_peers_buf, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            struct in_addr a;
            if (inet_pton(AF_INET, tok, &a) == 1)
                map_put_u32(gre_fd, a.s_addr);
        }
    }

    LOG_I("Validity maps: http3=%u dns=%u gre=%u synack_match=%u ipv6=%u\n",
          svc->http3, svc->dns, svc->gre_tunnels, svc->synack_match_outbound,
          svc->ipv6_enabled);
    return 0;
}


int load_config(struct bpf_object *obj) {
    char* env_path = getenv(CONFIG_FILE);
    if (!env_path) {
        LOG_E("Failed to open env : %s", CONFIG_FILE);
        return -1;
    }

    FILE *fp = fopen(env_path, "r");
    if (!fp) {
        LOG_E("Failed to open config file");
        return -1;
    }

    // Set default values
    
    strncpy(ifname, "eth0", IFNAMSIZ);
    ifname[IFNAMSIZ-1] = '\0';
    n_cpus = calc_cpus_count();
    geo_db_ipv4_path[0] = '\0';
    geo_db_location_path[0] = '\0';

    char isos[256][3];
    int nisos = 0;

    attach_mode = XDP_FLAGS_DRV_MODE;
    tz_offset_sec = get_timezone_offset();
    global_fw_config.g_config.black_ip_duration = BLOCK_DURATION_NS;

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;

        char key[128] = {0};
        char str_value[128] = {0};
        int int_value;
        
        // Try to parse as key=string first (for device name)
        if (sscanf(line, "%127[^=]= %127s", key, str_value) == 2) {
            trim_whitespace(key);
            trim_whitespace(str_value);
#if 0            
            if (strcmp(key, "token") == 0) {
                strcpy(token, str_value);
                LOG_I("Loaded config: %s = %s\n", key, token);
                continue;
            }
#endif
            if (strcmp(key, "log") == 0) {
                /* Directory (preferred) or legacy .log file path → hourly rotation
                 * under that folder: sparta-YYYYMMDD-HH.log + latest.log */
                set_main_log_path(str_value);
                ensure_main_log();
                LOG_I("Loaded config: %s = %s (hourly under log dir)\n", key, str_value);
                continue;
            }

            if (strcmp(key, "attack_log_dir") == 0) {
                set_attack_log_dir(str_value);
                LOG_I("Loaded config: %s = %s\n", key, str_value);
                continue;
            }

            if (strcmp(key, "dev") == 0) {
                strncpy(ifname, str_value, IFNAMSIZ);
                LOG_I("Loaded config: %s = %s\n", key, ifname);
                continue;
            }
            if (strcmp(key, "attach_mode") == 0) {
                /*XDP_FLAGS_UPDATE_IF_NOEXIST = (1 << 0)
                XDP_FLAGS_SKB_MODE = (1 << 1)
                XDP_FLAGS_DRV_MODE = (1 << 2)
                XDP_FLAGS_HW_MODE = (1 << 3)
                XDP_FLAGS_REPLACE = (1 << 4)*/
                LOG_I("Loaded config: %s = %s\n", key, str_value);
                if (strcmp(str_value, "skb") == 0 || strcmp(str_value, "generic") == 0)
                    attach_mode = XDP_FLAGS_SKB_MODE;
                else if (strcmp(str_value, "native") == 0 || strcmp(str_value, "auto") == 0)
                    attach_mode = 0; /* prefer native; loader falls back if needed */
                else if (strcmp(str_value, "drv") == 0)
                    attach_mode = XDP_FLAGS_DRV_MODE;
                else if (strcmp(str_value, "hw") == 0)
                    attach_mode = XDP_FLAGS_HW_MODE;
                else {
                    LOG_W("Unknown attach_mode '%s', keeping current\n", str_value);
                }
                continue;
            }
            /* Applied before bpf_object__load by apply_host_map_sizing(). */
            if (strcmp(key, "map_size_profile") == 0 ||
                strcmp(key, "map_memory_budget_percent") == 0) {
                LOG_I("Loaded config: %s = %s\n", key, str_value);
                continue;
            }
            if (strcmp(key, "geo_db_ipv4_path") == 0) {
                strcpy(geo_db_ipv4_path, str_value);
                LOG_I("Loaded config: %s = %s\n", key, geo_db_ipv4_path);
                continue;
            }
            if (strcmp(key, "geo_db_location_path") == 0) {
                strcpy(geo_db_location_path, str_value);
                LOG_I("Loaded config: %s = %s\n", key, geo_db_location_path);
                continue;
            }
            if (strcmp(key, "geo_countries") == 0) {
                LOG_I("Loaded config: %s = %s\n", key, str_value);
                char * str_token = strtok(str_value, ",");
                while (str_token != NULL) {
                    if (nisos >= 255) break;
                    strncpy(isos[nisos], str_token, 2);
                    isos[nisos][2] = '\0';
                    LOG_D("Parsed country iso is %s\n", isos[nisos]);
                    nisos ++;
                    str_token = strtok(NULL, ",");
                }
                continue;
            }
            if (strcmp(key, "gre_allowed_peers") == 0) {
                strncpy(gre_peers_buf, str_value, sizeof(gre_peers_buf) - 1);
                LOG_I("Loaded config: %s = %s\n", key, gre_peers_buf);
                continue;
            }
            if (strcmp(key, "udp_extra_allowed_ports") == 0) {
                strncpy(udp_extra_ports_buf, str_value, sizeof(udp_extra_ports_buf) - 1);
                LOG_I("Loaded config: %s = %s\n", key, udp_extra_ports_buf);
                continue;
            }
            if (strcmp(key, "baseline_seasonal") == 0) {
                shadow_cfg.seasonal_enable =
                    (strcmp(str_value, "hour_of_week") == 0 || strcmp(str_value, "1") == 0) ? 1 : 0;
                LOG_I("Loaded config: %s = %s\n", key, str_value);
                continue;
            }
            /* detection_level aliases (proficiency 1..10). */
            if (strcmp(key, "detection_level") == 0) {
                int lvl = -1;
                if (strcmp(str_value, "minimal") == 0) lvl = 1;
                else if (strcmp(str_value, "very_low") == 0) lvl = 2;
                else if (strcmp(str_value, "low") == 0) lvl = 3;
                else if (strcmp(str_value, "moderate_low") == 0) lvl = 4;
                else if (strcmp(str_value, "normal") == 0) lvl = 5;
                else if (strcmp(str_value, "moderate_high") == 0) lvl = 6;
                else if (strcmp(str_value, "elevated") == 0) lvl = 7;
                else if (strcmp(str_value, "high") == 0) lvl = 8;
                else if (strcmp(str_value, "very_high") == 0) lvl = 9;
                else if (strcmp(str_value, "max") == 0 ||
                         strcmp(str_value, "paranoid") == 0) lvl = 10;
                else {
                    char *end = NULL;
                    long v = strtol(str_value, &end, 10);
                    if (end != str_value && v >= 1 && v <= 10)
                        lvl = (int)v;
                }
                if (lvl >= 1 && lvl <= 10) {
                    shadow_cfg.detection_level = (__u32)lvl;
                    LOG_I("Loaded config: %s = %d\n", key, lvl);
                } else {
                    LOG_W("Invalid detection_level '%s' (use 1..10 or name)\n",
                          str_value);
                }
                continue;
            }
        }

        /* Float redesign keys (invalid_ratio, ceiling_fraction, …). */
        {
            double dbl_value = 0;
            if (sscanf(line, "%127[^=]= %lf", key, &dbl_value) == 2) {
                trim_whitespace(key);
                if (strcmp(key, "invalid_ratio") == 0) {
                    if (dbl_value > 0.0 && dbl_value < 1.0)
                        shadow_cfg.invalid_ratio = dbl_value;
                    LOG_I("Loaded config: %s = %g\n", key, dbl_value);
                    continue;
                }
                if (strcmp(key, "baseline_k") == 0 && dbl_value > 0.0) {
                    shadow_cfg.baseline_k = dbl_value;
                    LOG_I("Loaded config: %s = %g\n", key, dbl_value);
                    continue;
                }
                if (strcmp(key, "baseline_m") == 0 && dbl_value > 0.0) {
                    shadow_cfg.baseline_m = dbl_value;
                    LOG_I("Loaded config: %s = %g\n", key, dbl_value);
                    continue;
                }
            }
        }

        // Try to parse as key=integer
        if (sscanf(line, "%127[^=]= %d", key, &int_value) == 2) {
            trim_whitespace(key);
            
            LOG_I("Loaded config: %s = %d\n", key, int_value);
            
            // Global config
            if (strcmp(key, "black_ip_duration") == 0) {
                global_fw_config.g_config.black_ip_duration = int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "block_initial_seconds") == 0) {
                if (int_value > 0)
                    global_fw_config.g_config.block_initial_ns =
                        (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "block_max_seconds") == 0) {
                if (int_value > 0)
                    global_fw_config.g_config.block_max_ns =
                        (__u64)int_value * ONE_SECOND_NS;
            } 
            // SYN config
            else if (strcmp(key, "syn_valid") == 0) {
                global_fw_config.g_syn_config.valid = int_value;
            } else if (strcmp(key, "syn_threshold") == 0) {
                global_fw_config.g_syn_config.syn_threshold = (__u64)int_value;
            } else if (strcmp(key, "syn_burst_pkt") == 0) {
                global_fw_config.g_syn_config.burst_pkt_threshold = (__u64)int_value;
            } else if (strcmp(key, "syn_burst_count_per_sec") == 0) {
                global_fw_config.g_syn_config.burst_count_threshold = (__u64)int_value;
            } else if (strcmp(key, "challenge_timeout") == 0) {
                global_fw_config.g_syn_config.challenge_timeout = (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "syn_fixed_threshold") == 0) {
                global_fw_config.g_syn_config.syn_fixed_threshold = int_value;
            } else if (strcmp(key, "syn_fixed_check_duration") == 0) {
                global_fw_config.g_syn_config.syn_fixed_check_duration = (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "syn_protection_duration") == 0) {
                global_fw_config.g_syn_config.syn_protect_duration = int_value;
            } 
            //ACK config
            else if (strcmp(key, "ack_valid") == 0) {
                global_fw_config.g_ack_config.valid = int_value;
            } else if (strcmp(key, "ack_threshold") == 0) {
                global_fw_config.g_ack_config.ack_threshold = (__u64)int_value;
            } else if (strcmp(key, "ack_burst_pkt") == 0) {
                global_fw_config.g_ack_config.burst_pkt_threshold = (__u64)int_value;
            } else if (strcmp(key, "ack_burst_count_per_sec") == 0) {
                global_fw_config.g_ack_config.burst_count_threshold = (__u64)int_value;
            } else if (strcmp(key, "ack_fixed_threshold") == 0) {
                global_fw_config.g_ack_config.ack_fixed_threshold = int_value;
            } else if (strcmp(key, "ack_fixed_check_duration") == 0) {
                global_fw_config.g_ack_config.ack_fixed_check_duration = (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "ack_protection_duration") == 0) {
                global_fw_config.g_ack_config.ack_protect_duration = int_value;
            }  
            //RST config
            else if (strcmp(key, "rst_valid") == 0) {
                global_fw_config.g_rst_config.valid = int_value;
            } else if (strcmp(key, "rst_threshold") == 0) {
                global_fw_config.g_rst_config.rst_threshold = (__u64)int_value;
            } else if (strcmp(key, "rst_burst_pkt") == 0) {
                global_fw_config.g_rst_config.burst_pkt_threshold = (__u64)int_value;
            } else if (strcmp(key, "rst_burst_count_per_sec") == 0) {
                global_fw_config.g_rst_config.burst_count_threshold = (__u64)int_value;
            } else if (strcmp(key, "rst_fixed_threshold") == 0) {
                global_fw_config.g_rst_config.rst_fixed_threshold = int_value;
            } else if (strcmp(key, "rst_fixed_check_duration") == 0) {
                global_fw_config.g_rst_config.rst_fixed_check_duration = (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "rst_protection_duration") == 0) {
                global_fw_config.g_rst_config.rst_protect_duration = int_value;
            }  
            //ICMP config
            else if (strcmp(key, "icmp_valid") == 0) {
                global_fw_config.g_icmp_config.valid = int_value;
            } else if (strcmp(key, "icmp_threshold") == 0) {
                global_fw_config.g_icmp_config.icmp_threshold = (__u64)int_value;
            } else if (strcmp(key, "icmp_burst_pkt") == 0) {
                global_fw_config.g_icmp_config.burst_pkt_threshold = (__u64)int_value;
            } else if (strcmp(key, "icmp_burst_count_per_sec") == 0) {
                global_fw_config.g_icmp_config.burst_count_threshold = (__u64)int_value;
            } else if (strcmp(key, "icmp_fixed_threshold") == 0) {
                global_fw_config.g_icmp_config.icmp_fixed_threshold = int_value;
            } else if (strcmp(key, "icmp_fixed_check_duration") == 0) {
                global_fw_config.g_icmp_config.icmp_fixed_check_duration = (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "icmp_protection_duration") == 0) {
                global_fw_config.g_icmp_config.icmp_protect_duration = int_value;
            }  
            //UDP config
            else if (strcmp(key, "udp_valid") == 0) {
                global_fw_config.g_udp_config.valid = int_value;
            } else if (strcmp(key, "udp_threshold") == 0) {
                global_fw_config.g_udp_config.udp_threshold = (__u64)int_value;
            } else if (strcmp(key, "udp_burst_pkt") == 0) {
                global_fw_config.g_udp_config.burst_pkt_threshold = (__u64)int_value;
            } else if (strcmp(key, "udp_burst_count_per_sec") == 0) {
                global_fw_config.g_udp_config.burst_count_threshold = (__u64)int_value;
            } else if (strcmp(key, "udp_fixed_threshold") == 0) {
                global_fw_config.g_udp_config.udp_fixed_threshold = int_value;
            } else if (strcmp(key, "udp_fixed_check_duration") == 0) {
                global_fw_config.g_udp_config.udp_fixed_check_duration = (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "udp_protection_duration") == 0) {
                global_fw_config.g_udp_config.udp_protect_duration = int_value;
            }  
            //GRE config
            else if (strcmp(key, "gre_valid") == 0) {
                global_fw_config.g_gre_config.valid = int_value;
            } else if (strcmp(key, "gre_threshold") == 0) {
                global_fw_config.g_gre_config.gre_threshold = (__u64)int_value;
            } else if (strcmp(key, "gre_burst_pkt") == 0) {
                global_fw_config.g_gre_config.burst_pkt_threshold = (__u64)int_value;
            } else if (strcmp(key, "gre_burst_count_per_sec") == 0) {
                global_fw_config.g_gre_config.burst_count_threshold = (__u64)int_value;
            } else if (strcmp(key, "gre_fixed_threshold") == 0) {
                global_fw_config.g_gre_config.gre_fixed_threshold = int_value;
            } else if (strcmp(key, "gre_fixed_check_duration") == 0) {
                global_fw_config.g_gre_config.gre_fixed_check_duration = (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "gre_protection_duration") == 0) {
                global_fw_config.g_gre_config.gre_protect_duration = int_value;
            }
            //STOMP config
            else if (strcmp(key, "stomp_valid") == 0) {
                global_fw_config.g_stomp_config.valid = int_value;
            } else if (strcmp(key, "stomp_threshold") == 0) {
                global_fw_config.g_stomp_config.stomp_threshold = (__u64)int_value;
            } else if (strcmp(key, "stomp_burst_pkt") == 0) {
                global_fw_config.g_stomp_config.burst_pkt_threshold = (__u64)int_value;
            } else if (strcmp(key, "stomp_burst_count_per_sec") == 0) {
                global_fw_config.g_stomp_config.burst_count_threshold = (__u64)int_value;
            } else if (strcmp(key, "stomp_fixed_threshold") == 0) {
                global_fw_config.g_stomp_config.stomp_fixed_threshold = int_value;
            } else if (strcmp(key, "stomp_fixed_check_duration") == 0) {
                global_fw_config.g_stomp_config.stomp_fixed_check_duration = (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "stomp_protection_duration") == 0) {
                global_fw_config.g_stomp_config.stomp_protect_duration = int_value;
            }
            //HandShake config
            else if (strcmp(key, "handshake_valid") == 0) {
                global_fw_config.g_handshake_config.valid = int_value;
            } else if (strcmp(key, "handshake_threshold") == 0) {
                global_fw_config.g_handshake_config.handshake_threshold = (__u64)int_value;
            } else if (strcmp(key, "handshake_burst_pkt") == 0) {
                global_fw_config.g_handshake_config.burst_pkt_threshold = (__u64)int_value;
            } else if (strcmp(key, "handshake_burst_count_per_sec") == 0) {
                global_fw_config.g_handshake_config.burst_count_threshold = (__u64)int_value;
            } else if (strcmp(key, "handshake_fixed_threshold") == 0) {
                global_fw_config.g_handshake_config.handshake_fixed_threshold = int_value;
            } else if (strcmp(key, "handshake_fixed_check_duration") == 0) {
                global_fw_config.g_handshake_config.handshake_fixed_check_duration = (__u64)int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "handshake_protection_duration") == 0) {
                global_fw_config.g_handshake_config.handshake_protect_duration = int_value;
            }
            else if (strcmp(key, "socket_valid") == 0) {
                global_fw_config.g_socket_config.valid = int_value;
            } else if (strcmp(key, "socket_fin_threshold") == 0) {
                global_fw_config.g_socket_config.socket_fin_threshold = int_value;
            } else if (strcmp(key, "socket_fixed_threshold") == 0) {
                global_fw_config.g_socket_config.socket_fixed_threshold = int_value;
            } else if (strcmp(key, "socket_fixed_check_duration") == 0) {
                global_fw_config.g_socket_config.socket_fixed_check_duration = (__u64)int_value * ONE_SECOND_NS;
            }
            //TCP segment
            else if (strcmp(key, "tcp_seg_check") == 0) {
                global_fw_config.g_config.tcp_seg_check = int_value;
            }
            else if (strcmp(key, "stats_detail_sample_divisor") == 0) {
                if (int_value < 1)
                    int_value = 1;
                if (int_value > 64)
                    int_value = 64;
                global_fw_config.g_config.stats_detail_sample_divisor = (__u32)int_value;
            }
            //GEO check
            else if (strcmp(key, "geo_check") == 0) {
                global_fw_config.g_geo_config.check = int_value;
            }
            //TCP connection limit
            else if (strcmp(key, "tcp_connection_limit_check") == 0) {
                global_fw_config.g_tcp_connection_config.check = int_value;
            } else if (strcmp(key, "tcp_connection_limit_cnt") == 0) {
                global_fw_config.g_tcp_connection_config.limit_cnt = int_value;
            }
            /* Phase 4–5 / redesign subset (safe keys mapped into 0.4.0 structures). */
            else if (strcmp(key, "enforce_drop_invalid") == 0) {
                global_fw_config.g_config.enforce_drop_invalid = int_value ? 1 : 0;
            } else if (strcmp(key, "prefer_adaptive") == 0) {
                global_fw_config.g_config.prefer_adaptive = int_value ? 1 : 0;
            } else if (strcmp(key, "service_http3") == 0 || strcmp(key, "http3") == 0) {
                cfg_http3_override = int_value ? 1 : 0;
                global_fw_config.g_config.svc.http3 = int_value ? 1 : 0;
            } else if (strcmp(key, "service_gre_tunnels") == 0 || strcmp(key, "gre_tunnels") == 0) {
                cfg_gre_tunnels_override = int_value ? 1 : 0;
                global_fw_config.g_config.svc.gre_tunnels = int_value ? 1 : 0;
            } else if (strcmp(key, "service_dns") == 0) {
                cfg_dns_override = int_value ? 1 : 0;
                global_fw_config.g_config.svc.dns = int_value ? 1 : 0;
            } else if (strcmp(key, "quic_header_check") == 0) {
                global_fw_config.g_config.svc.quic_header_check = int_value ? 1 : 0;
            } else if (strcmp(key, "icmp_drop_fragments") == 0) {
                global_fw_config.g_config.svc.icmp_drop_fragments = int_value ? 1 : 0;
            } else if (strcmp(key, "synack_match_outbound") == 0) {
                global_fw_config.g_config.svc.synack_match_outbound = int_value ? 1 : 0;
            } else if (strcmp(key, "ipv6") == 0) {
                global_fw_config.g_config.svc.ipv6_enabled = int_value ? 1 : 0;
            } else if (strcmp(key, "cusum") == 0) {
                shadow_cfg.cusum_enable = int_value ? 1 : 0;
            } else if (strcmp(key, "nic_drop_trigger_seconds") == 0) {
                if (int_value > 0) shadow_cfg.nic_drop_trigger_seconds = (__u32)int_value;
            } else if (strcmp(key, "softirq_trigger_percent") == 0) {
                if (int_value > 0) shadow_cfg.softirq_trigger_percent = (__u32)int_value;
            } else if (strcmp(key, "softirq_trigger_seconds") == 0) {
                if (int_value > 0) shadow_cfg.softirq_trigger_seconds = (__u32)int_value;
            } else if (strcmp(key, "confirm_windows") == 0) {
                if (int_value > 0) shadow_cfg.confirm_windows = (__u32)int_value;
            } else if (strcmp(key, "exit_windows") == 0) {
                if (int_value > 0) shadow_cfg.exit_windows = (__u32)int_value;
            } else if (strcmp(key, "cooldown_seconds") == 0) {
                if (int_value > 0) shadow_cfg.cooldown_seconds = (__u32)int_value;
            } else if (strcmp(key, "quiet_clear_windows") == 0) {
                if (int_value > 0) shadow_cfg.quiet_clear_windows = (__u32)int_value;
            } else if (strcmp(key, "alert_hold_windows") == 0) {
                if (int_value > 0) shadow_cfg.alert_hold_windows = (__u32)int_value;
            } else if (strcmp(key, "escalate_after_windows") == 0) {
                if (int_value > 0) shadow_cfg.escalate_after_windows = (__u32)int_value;
            } else if (strcmp(key, "surge_factor") == 0) {
                if (int_value >= 0) shadow_cfg.surge_factor = (__u32)int_value; /* 0 = off */
            } else if (strcmp(key, "rearm_seconds") == 0) {
                if (int_value >= 0) shadow_cfg.rearm_seconds = (__u32)int_value;
            } else if (strcmp(key, "src_bucket_k") == 0) {
                if (int_value > 0) shadow_cfg.src_bucket_k = (__u32)int_value;
            } else if (strcmp(key, "flow_pps_k") == 0) {
                if (int_value > 0) shadow_cfg.flow_pps_k = (__u32)int_value;
            } else if (strcmp(key, "invalid_floor_pps") == 0) {
                if (int_value >= 0) shadow_cfg.invalid_floor_pps = (__u32)int_value;
            } else if (strcmp(key, "learning_days") == 0) {
                /* 0 = skip learning bootstrap (immediate baseline gates). */
                if (int_value >= 0) shadow_cfg.learning_days = (__u32)int_value;
            } else if (strcmp(key, "detection_level") == 0) {
                if (int_value >= 1 && int_value <= 10)
                    shadow_cfg.detection_level = (__u32)int_value;
                else
                    LOG_W("Invalid detection_level %d (use 1..10)\n", int_value);
            } else if (strcmp(key, "baseline_k") == 0) {
                if (int_value > 0) shadow_cfg.baseline_k = (double)int_value;
            } else if (strcmp(key, "baseline_m") == 0) {
                if (int_value > 0) shadow_cfg.baseline_m = (double)int_value;
            } else if (strcmp(key, "vlan_parse") == 0 ||
                       strcmp(key, "syn_cookies") == 0 ||
                       strcmp(key, "stage0_drop_invalid_flags") == 0 ||
                       strcmp(key, "stage0_drop_land") == 0 ||
                       strcmp(key, "data_class_by_payload") == 0 ||
                       strcmp(key, "labels_independent") == 0) {
                LOG_I("Accepted redesign key (no-op or default): %s = %d\n", key, int_value);
            }

            else {
                /* redesign.config and future keys: warn and continue (do not abort). */
                LOG_W("Ignoring unknown config key: %s = %d\n", key, int_value);
            }
        }
    }
    fclose(fp);

    if (ensure_usable_ifname() < 0)
        return -1;
    
    if (global_fw_config.g_syn_config.burst_count_threshold == 0) {
        LOG_E("Burst threshold of SYN is zero. Please reconfig it\n");
        return -1;
    }
    if (global_fw_config.g_ack_config.burst_count_threshold == 0) {
        LOG_E("Burst threshold of ACK is zero. Please reconfig it\n");
        return -1;
    }
    if (global_fw_config.g_rst_config.burst_count_threshold == 0) {
        LOG_E("Burst threshold of RST is zero. Please reconfig it\n");
        return -1;
    }
    if (global_fw_config.g_icmp_config.burst_count_threshold == 0) {
        LOG_E("Burst threshold of ICMP is zero. Please reconfig it\n");
        return -1;
    }
    if (global_fw_config.g_udp_config.burst_count_threshold == 0) {
        LOG_E("Burst threshold of UDP is zero. Please reconfig it\n");
        return -1;
    }
    if (global_fw_config.g_gre_config.burst_count_threshold == 0) {
        LOG_E("Burst threshold of GRE is zero. Please reconfig it\n");
        return -1;
    }
    if (global_fw_config.g_stomp_config.burst_count_threshold == 0) {
        LOG_E("Burst threshold of STOMP is zero. Please reconfig it\n");
        return -1;
    }
    if (global_fw_config.g_handshake_config.burst_count_threshold == 0) {
        LOG_E("Burst threshold of HANDSHAKE is zero. Please reconfig it\n");
        return -1;
    }

    // Calculate burst gap
    global_fw_config.g_syn_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_syn_config.burst_count_threshold);
    global_fw_config.g_ack_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_ack_config.burst_count_threshold);
    global_fw_config.g_rst_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_rst_config.burst_count_threshold);
    global_fw_config.g_icmp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_icmp_config.burst_count_threshold);
    global_fw_config.g_udp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_udp_config.burst_count_threshold);
    global_fw_config.g_gre_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_gre_config.burst_count_threshold);
    global_fw_config.g_stomp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_stomp_config.burst_count_threshold);
    global_fw_config.g_handshake_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_handshake_config.burst_count_threshold);

    int key = 0;
    
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    if (global_fw_config.g_geo_config.check) {
        int geo_map_fd = bpf_object__find_map_fd_by_name(obj, "geoip_trie_map");
        if (geo_map_fd < 0) {
            LOG_E( "ERROR: finding geo_map_fd: %d\n", geo_map_fd);
            return -1;
        }

        if (clear_geoip_trie_map(geo_map_fd) < 0) {
            LOG_E("Failed to clear geoip_trie_map\n");    
        } else 
            LOG_D("geoip_trie_map is cleared\n");

        if (init_geo(geo_db_location_path, geo_db_ipv4_path, isos, nisos, geo_map_fd) < 0) {
            LOG_E("Failed to update geoip_trie_map");
            return -1;
        }

        int geo_block_map_fd = bpf_object__find_map_fd_by_name(obj, "geoip_trie_block_map");
        if (geo_block_map_fd < 0) {
            LOG_E( "ERROR: finding geo_block_map_fd: %d\n", geo_block_map_fd);
            return -1;
        }

        if (clear_geoip_trie_map(geo_block_map_fd) < 0) {
            LOG_E("Failed to clear geoip_trie_map\n");    
        } else 
            LOG_D("geoip_trie_block_map is cleared\n");

        if (init_geo(geo_db_location_path, geo_db_ipv4_path, isos, nisos, geo_block_map_fd) < 0) {
            LOG_E("Failed to update geoip_trie_block_map");
            return -1;
        }
    }

    /* Bump generation so XDP geo_result_cache drops stale trie results; then push full .bss once. */
    {
        __u32 g = global_fw_config.g_geo_config.cache_generation + 1;
        if (g == 0)
            g = 1;
        global_fw_config.g_geo_config.cache_generation = g;
        if (bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
            LOG_E("bpf_map_update_elem");
            return -1;
        }
    }

    if (populate_validity_maps(obj) < 0) {
        LOG_W("Validity allowlist populate had issues (continuing)\n");
    }

    if (load_block_white_list(obj) < 0) {
        LOG_E("Failed to load white/block list ips from sqlite db\n");
        return -1;
    }

    refresh_capacity_profile();

    LOG_I("Setup config success\n");

    return 0;
}
