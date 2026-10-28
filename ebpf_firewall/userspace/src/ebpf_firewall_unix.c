
#include <stdarg.h>
#include <strings.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ebpf_firewall_common.h>
#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_core.h>
#include <ebpf_firewall_config.h>
#include <ebpf_firewall_shadow.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_utils.h>

static int srv_fd = -1;
extern int exiting;
extern struct stats_config global_receive_stats;
extern struct stats_config global_passed_stats;
extern struct fixed_ip_pkt_stats global_max_ip_pkt_stats;
extern struct det_snapshot global_det_stats;
extern struct traffic_stats_config global_traffic_stats[TRAFFIC_STATS_SLOTS];

#define BUF_SZ    1024
#define BULK_CMD      "ADD_BLOCK_IPS"
#define BULK_BUF_SZ   (64 * 1024)
#define BULK_MAX_IPS  4096
#define CLIENT_RCV_TIMEOUT_S 2
#if 0
static void reply(int cfd, const char *fmt, ...) {
    char buf[BUF_SZ];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0 || n >= (int)sizeof buf || write(cfd, buf, (size_t)n) != n)
        LOG_E( "short write when replying\n");
}
#endif

static void reply(int cfd, const char *fmt, ...)
{
    char   stack_buf[BUF_SZ];
    char  *out      = stack_buf;   /* will point to the final buffer */
    size_t out_sz   = BUF_SZ;      /* size of *out */
    int    need;                   /* bytes required (without '\0') */

    /* ------------ first try to format into the stack buffer ------------ */
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);              /* we may need a second pass */

    need = vsnprintf(stack_buf, out_sz, fmt, ap);
    if (need < 0) {                /* encoding error */
        va_end(ap); va_end(ap2);
        LOG_E( "vsnprintf failed in reply()\n");
        return;
    }
    if ((size_t)need >= out_sz) {  /* buffer too small → allocate */
        out_sz = (size_t)need + 1;             /* +1 for terminator */
        out = malloc(out_sz);
        if (!out) {
            va_end(ap); va_end(ap2);
            LOG_E( "reply: OOM\n");
            return;
        }
        /* re‑format with the copied va_list */
        need = vsnprintf(out, out_sz, fmt, ap2);
    }
    va_end(ap); va_end(ap2);

    /* ------------------ write all bytes, handling short writes --------- */
    size_t sent = 0;
    while (sent < (size_t)need) {
        ssize_t n = write(cfd, out + sent, (size_t)need - sent);
        if (n < 0) {
            if (errno == EINTR)
                continue;          /* interrupted → retry */
            LOG_E( "reply: write failed: %s\n", strerror(errno));
            break;
        }
        if (n == 0) {              /* should not happen on regular fds */
            LOG_E( "reply: unexpected EOF on fd %d\n", cfd);
            break;
        }
        sent += (size_t)n;
    }

    if (out != stack_buf)
        free(out);
}

/* ---------- stub command handlers -------------------------------------- */

static void handle_restart_fw(int cfd, char **argv, int argc) {
    LOG_D("handle_restart_fw: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    int ret = -1;
    ret = restart_fw();
    if (ret == -1 ) {
        reply(cfd, "Failed! FW restarted failed\n");
    } else {
        reply(cfd, "OK! FW restarted\n");
    }
}

static void handle_reload_fw(int cfd, char **argv, int argc) {
    LOG_D("handle_reload_fw: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    int ret = -1;
    ret = reload_fw();
    if (ret == -1 ) {
       reply(cfd, "failed\nReload config failed\n");
    } else {
        reply(cfd, "ok\nsuccess\n");
    }
}

static void handle_clear_fw(int cfd, char **argv, int argc) {
    LOG_D("handle_clear_fw: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    int ret = -1;
    ret = clear_fw();
    if (ret == -1) {
        reply(cfd, "Failed! FW clear stats failed\n");
    } else {
        reply(cfd, "OK! FW clear stats\n");
    }
}

static void handle_stats_shadow(int cfd, char **argv, int argc) {
    (void)argv;
    (void)argc;
    char buf[2048];
    if (shadow_format_status(buf, sizeof(buf)) < 0)
        reply(cfd, "Failed! DETECT status unavailable\n");
    else
        reply(cfd, "%s", buf);
}

static void handle_set_enforce(int cfd, char **argv, int argc) {
    extern struct bpf_object *obj;
    if (argc < 2) {
        reply(cfd, "Failed! usage: SET_ENFORCE 0|1\n");
        return;
    }
    int en = atoi(argv[1]);
    if (set_enforce_drop_invalid(obj, en) < 0)
        reply(cfd, "Failed! could not update enforce_drop_invalid\n");
    else
        reply(cfd, "OK! enforce_drop_invalid=%d\n", en ? 1 : 0);
}

static void handle_set_adaptive(int cfd, char **argv, int argc) {
    extern struct bpf_object *obj;
    if (argc < 2) {
        reply(cfd, "Failed! usage: SET_ADAPTIVE 0|1\n");
        return;
    }
    int en = atoi(argv[1]);
    if (set_prefer_adaptive(obj, en) < 0)
        reply(cfd, "Failed! could not update prefer_adaptive\n");
    else
        reply(cfd, "OK! prefer_adaptive=%d\n", en ? 1 : 0);
}

static void handle_stats_cap(int cfd, char **argv, int argc) {
    (void)argv;
    (void)argc;
    refresh_capacity_profile();
    struct capacity_profile *p = &global_capacity_profile;
    reply(cfd,
          "OK! CAP link_mbps=%u rx_queues=%u xdp_cores=%u "
          "line_pps=%llu cpu_pps=%llu host_ceiling_pps=%llu host_ceiling_bps=%llu "
          "cap_syn=%llu cap_ack=%llu cap_rst=%llu cap_icmp=%llu "
          "cap_udp=%llu cap_gre=%llu cap_data=%llu http3=%u gre_tunnels=%u\n",
          p->link_mbps, p->rx_queues, p->xdp_cores,
          (unsigned long long)p->line_pps, (unsigned long long)p->cpu_pps,
          (unsigned long long)p->host_ceiling_pps, (unsigned long long)p->host_ceiling_bps,
          (unsigned long long)p->cap_syn, (unsigned long long)p->cap_ack,
          (unsigned long long)p->cap_rst, (unsigned long long)p->cap_icmp,
          (unsigned long long)p->cap_udp, (unsigned long long)p->cap_gre,
          (unsigned long long)p->cap_data, p->http3, p->gre_tunnels);
}

static void handle_stats_det(int cfd, char **argv, int argc) {
    (void)argv;
    (void)argc;
    /* Last 1s Phase 1 snapshot; exclusive classes sum ≈ NIC IPv4 pps. */
    reply(cfd,
          "OK! DET total_pkts=%llu total_bytes=%llu "
          "SYN=%llu ACK=%llu SYNACK=%llu RST=%llu "
          "DATA=%llu SOCKET=%llu ICMP=%llu UDP=%llu GRE=%llu OTHER=%llu "
          "STOMP_lbl=%llu HANDSHAKE_lbl=%llu "
          "inv_ihl=%llu inv_doff=%llu inv_land=%llu inv_frag=%llu "
          "inv_null=%llu inv_xmas=%llu inv_synfin=%llu inv_synrst=%llu "
          "inv_synurg=%llu inv_fin=%llu\n",
          global_det_stats.total_pkts, global_det_stats.total_bytes,
          global_det_stats.class_pkts[DET_CLASS_SYN],
          global_det_stats.class_pkts[DET_CLASS_ACK],
          global_det_stats.class_pkts[DET_CLASS_SYNACK],
          global_det_stats.class_pkts[DET_CLASS_RST],
          global_det_stats.class_pkts[DET_CLASS_DATA],
          global_det_stats.class_pkts[DET_CLASS_SOCKET],
          global_det_stats.class_pkts[DET_CLASS_ICMP],
          global_det_stats.class_pkts[DET_CLASS_UDP],
          global_det_stats.class_pkts[DET_CLASS_GRE],
          global_det_stats.class_pkts[DET_CLASS_OTHER],
          global_det_stats.class_pkts[DET_CLASS_STOMP],
          global_det_stats.class_pkts[DET_CLASS_HANDSHAKE],
          global_det_stats.invalid_pkts[INVALID_BAD_IHL],
          global_det_stats.invalid_pkts[INVALID_BAD_DOFF],
          global_det_stats.invalid_pkts[INVALID_LAND],
          global_det_stats.invalid_pkts[INVALID_TCP_FRAG],
          global_det_stats.invalid_pkts[INVALID_FLAG_NULL],
          global_det_stats.invalid_pkts[INVALID_FLAG_XMAS],
          global_det_stats.invalid_pkts[INVALID_FLAG_SYN_FIN],
          global_det_stats.invalid_pkts[INVALID_FLAG_SYN_RST],
          global_det_stats.invalid_pkts[INVALID_FLAG_SYN_URG],
          global_det_stats.invalid_pkts[INVALID_FLAG_FIN_ONLY]);
}

static void handle_stats_fw(int cfd, char **argv, int argc) {
    LOG_D("handle_stats_fw: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    reply(cfd, "OK SYN:%llu/%llu ACK:%llu/%llu RST:%llu/%llu PSH:%llu/%llu FIN:%llu/%llu URG:%llu/%llu SYN_ACK:%llu/%llu FIN_ACK:%llu/%llu RST_ACK:%llu/%llu ICMP:%llu/%llu UDP:%llu/%llu GRE:%llu/%llu PKT_SYN:%llu/%llu PKT_ACK:%llu/%llu PKT_RST:%llu/%llu PKT_PSH:%llu/%llu PKT_FIN:%llu/%llu PKT_URG:%llu/%llu PKT_SYN_ACK:%llu/%llu PKT_FIN_ACK:%llu/%llu PKT_RST_ACK:%llu/%llu PKT_ICMP:%llu/%llu PKT_UDP:%llu/%llu PKT_GRE:%llu/%llu\n",
        global_receive_stats.syn, global_passed_stats.syn,
        global_receive_stats.ack, global_passed_stats.ack,
        global_receive_stats.rst, global_passed_stats.rst,
        global_receive_stats.psh, global_passed_stats.psh,
        global_receive_stats.fin, global_passed_stats.fin,
        global_receive_stats.urg, global_passed_stats.urg,
        global_receive_stats.syn_ack, global_passed_stats.syn_ack,
        global_receive_stats.fin_ack, global_passed_stats.fin_ack,
        global_receive_stats.rst_ack, global_passed_stats.rst_ack,
        global_receive_stats.icmp, global_passed_stats.icmp,
        global_receive_stats.udp, global_passed_stats.udp,
        global_receive_stats.gre, global_passed_stats.gre,

        global_max_ip_pkt_stats.normal_syn, global_max_ip_pkt_stats.attack_syn,
        global_max_ip_pkt_stats.normal_ack, global_max_ip_pkt_stats.attack_ack,
        global_max_ip_pkt_stats.normal_rst, global_max_ip_pkt_stats.attack_rst,
        global_max_ip_pkt_stats.normal_psh, global_max_ip_pkt_stats.attack_psh,
        global_max_ip_pkt_stats.normal_fin, global_max_ip_pkt_stats.attack_fin,
        global_max_ip_pkt_stats.normal_urg, global_max_ip_pkt_stats.attack_urg,
        global_max_ip_pkt_stats.normal_syn_ack, global_max_ip_pkt_stats.attack_syn_ack,
        global_max_ip_pkt_stats.normal_fin_ack, global_max_ip_pkt_stats.attack_fin_ack,
        global_max_ip_pkt_stats.normal_rst_ack, global_max_ip_pkt_stats.attack_rst_ack,
        global_max_ip_pkt_stats.normal_icmp, global_max_ip_pkt_stats.attack_icmp,
        global_max_ip_pkt_stats.normal_udp, global_max_ip_pkt_stats.attack_udp,
        global_max_ip_pkt_stats.normal_gre, global_max_ip_pkt_stats.attack_gre);
}

static void handle_list_block_ip(int cfd, char **argv, int argc) {
    LOG_D("handle_list_block_ip: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    int ret = -1;
    char * data = NULL;

    ret = list_block_ip(&data);
    if (ret == -1) {
        reply(cfd, "Failed! List IP is failed\n");    
    } else {
        reply(cfd, "OK\n%s\n", data);
    }
    if (data) free (data);
}


static void handle_clear_deny_ip(int cfd, char **argv, int argc) {
    LOG_D("handle_clear_deny_ip: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 2) { reply(cfd, "ERR usage: CLEAR_BLOCK_IP <ip>\n"); return; }
    int ret = -1;

    ret = clear_deny_ip(argv[1]);
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else if (ret == -ENOENT)
        reply(cfd, "ok\nBut ip %s was not registered\n", argv[1]);
    else
        reply(cfd, "failed\nError occured while removing %s in blacklist\n", argv[1]);
}

static void handle_clear_deny_ip_all(int cfd, char **argv, int argc) {
    LOG_D("handle_clear_deny_ip_all: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    int ret = -1;
    ret = clear_deny_ip_all();
    if (ret == 0) {        
        reply(cfd, "ok\nsuccess\n");
    } else {
        reply(cfd, "failed\nError occured while removing all ips in blacklist\n", argv[1]);
    }
}

static void handle_add_block_ip(int cfd, char **argv, int argc) {
    LOG_D("handle_add_block_ip: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc < 2 || argc > 3) {
        reply(cfd, "ERR usage: ADD_BLOCK_IP <ip> [seconds]\n"); return;
    }
    const char *ip = argv[1];
    int secs = (argc == 3) ? atoi(argv[2]) : 0; // default duration

#if 0
    if (secs < 0) {
        reply(cfd, "Failed! Duration should be greater than 0 seconds\n");
        return;
    }
#endif

    int ret = -1;
    ret = add_block_ip(argv[1], secs);

    if (ret == 0 || ret == 1) {
        append_block_ip_to_sqlite(ip, secs, "Manual blacklist");
        reply(cfd, "ok\nsuccess\n");
    } else {
        reply(cfd, "failed\nError occured while adding %s to blacklist\n", ip);
    }
}

/*
 * ADD_BLOCK_IPS <seconds> [reason]\n<ip>\n<ip>...\nEND\n
 * Used by OpenResty resty.l7_guard_flusher to escalate L7 offenders to XDP.
 * All map inserts happen before the reply; tracked TCP state is cleared after.
 */
static void handle_add_block_ips(int cfd, char *buf)
{
    char *save = NULL;
    char *line = strtok_r(buf, "\n", &save);
    char tag[64] = "bulk";
    int secs = 0;

    if (!line || sscanf(line, "%*s %d %63s", &secs, tag) < 1) {
        reply(cfd, "ERR usage: ADD_BLOCK_IPS <seconds> [reason]\\n<ip>\\n...\\nEND\n");
        return;
    }

    char **ips = malloc(BULK_MAX_IPS * sizeof(*ips));
    if (!ips) {
        reply(cfd, "failed\nout of memory\n");
        return;
    }

    int n = 0;
    while (n < BULK_MAX_IPS && (line = strtok_r(NULL, "\n", &save))) {
        size_t len = strlen(line);
        while (len && isspace((unsigned char)line[len - 1]))
            line[--len] = '\0';
        while (*line && isspace((unsigned char)*line))
            line++;
        if (strcmp(line, "END") == 0)
            break;
        if (*line)
            ips[n++] = line;
    }

    __u32 *keys = NULL;
    int added = 0;
    if (add_block_ips_bulk(ips, n, secs, &keys, &added) < 0) {
        reply(cfd, "failed\nError occured while adding IPs to blacklist\n");
        free(ips);
        return;
    }

    char reason[96];
    snprintf(reason, sizeof reason, "L7 abuse (%s)", tag);
    struct in_addr tmp;
    for (int i = 0; i < n; i++) {
        if (inet_pton(AF_INET, ips[i], &tmp) == 1)
            append_block_ip_to_sqlite(ips[i], secs, reason);
    }

    reply(cfd, "ok\nadded:%d\n", added);
    LOG_I("ADD_BLOCK_IPS: blocked %d/%d IPs for %ds (%s)\n", added, n, secs, tag);

    clear_tracked_tcp_state_bulk(keys, added);
    free(keys);
    free(ips);
}



/* -------------------- whitelist handlers -------------------- */
static void handle_list_allow_ip(int cfd, char **argv, int argc) {
    LOG_D("handle_list_allow_ip: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    char *data = NULL;
    if (list_allow_ip(&data) == -1) {
        reply(cfd, "Failed! List ALLOW_IP failed\n");
    } else {
        reply(cfd, "OK\n%s\n", data);
    }
    if (data) free(data);
}

static void handle_clear_allow_ip(int cfd, char **argv, int argc) {
    LOG_D("handle_clear_allow_ip: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 2) { reply(cfd, "ERR usage: CLEAR_ALLOW_IP <ip>\n"); return; }
    int ret = clear_allow_ip(argv[1]);
    if (ret == 0)
        reply(cfd, "ok\n%s removed from whitelist\n", argv[1]);
    else if (ret == -ENOENT)
        reply(cfd, "ok\nBut ip %s was not in whitelist\n", argv[1]);
    else
        reply(cfd, "failed\nError occured while removing %s from whitelist\n", argv[1]);
}

static void handle_clear_allow_ip_all(int cfd, char **argv, int argc) {
    LOG_D("handle_clear_allow_ip_all: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    int ret = clear_allow_ip_all();
    if (ret == 0) reply(cfd, "ok\nsuccess\n");
    else reply(cfd, "failed\nError occured while clearing whitelist\n");
}

static void handle_add_allow_ip(int cfd, char **argv, int argc) {
    LOG_D("handle_add_allow_ip: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 2) { reply(cfd, "ERR usage: ADD_ALLOW_IP <ip>\n"); return; }
    int ret = add_allow_ip(argv[1]);

    if (ret == 0) {
        append_allow_ip_to_sqlite(argv[1], "Manual whitelist");
        reply(cfd, "ok\n%s is added in allow list\n", argv[1]);
    } else {
        reply(cfd, "failed\nError occured while adding %s to allow list\n", argv[1]);
    }
}


static void handle_tcp_syn_set(int cfd, char **argv, int argc) {
    LOG_D("handle_tcp_syn_set: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 9) { reply(cfd, "failed\nUsage failed %d\n", argc); return; }
    int tcp_syn_valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) tcp_syn_valid = 1;
    else tcp_syn_valid = 0;

    int ret = tcp_syn_set(tcp_syn_valid, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]), atoi(argv[8]));
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_tcp_ack_set(int cfd, char **argv, int argc) {
    LOG_D("handle_tcp_ack_set: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 8) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = tcp_ack_set(valid, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]));
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_tcp_rst_set(int cfd, char **argv, int argc) {
    LOG_D("handle_tcp_rst_set: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 8) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = tcp_rst_set(valid, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]));
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_tcp_stomp_set(int cfd, char **argv, int argc) {
    LOG_D("handle_tcp_stomp_set: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 8) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = tcp_stomp_set(valid, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]));
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_tcp_socket_set(int cfd, char **argv, int argc) {
    LOG_D("handle_tcp_socket_set: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 5) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = tcp_socket_set(valid, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_icmp_set(int cfd, char **argv, int argc) {
    LOG_D("handle_icmp_set: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 8) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = icmp_set(valid, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]));
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_udp_set(int cfd, char **argv, int argc) {
    LOG_D("handle_udp_set: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 8) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = udp_set(valid, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]));
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_gre_set(int cfd, char **argv, int argc) {
    LOG_D("handle_gre_set: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 8) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = gre_set(valid, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]));
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_tcp_set_seg(int cfd, char **argv, int argc) {
    LOG_D("handle_tcp_set_seg: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 2) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = tcp_seg_set(valid);
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_set_geo(int cfd, char **argv, int argc) {
    LOG_D("handle_set_geo: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 2 && argc != 3) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "allow", 5) == 0) valid = 1;
    else if (strncmp(argv[1], "block", 5) == 0) valid = 2;
    else valid = 0;

    int ret = geo_set(valid, argv[2]);
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_set_conn_limit(int cfd, char **argv, int argc) {
    LOG_D("handle_set_conn_limit: %s\n", argv[0]);
    for (int i = 1; i < argc; i++) {
        LOG_D("argv[%d]: %s\n", i, argv[i]);
    }
    if (argc != 3) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = tcp_conn_limit_set(valid, atoi(argv[2]));
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_health_check(int cfd, char **argv, int argc) {
    reply(cfd, "ok\nsuccess\n");
}

//l4_cli GET_BLOCKLIST auto 1.1.2.4 '2025-8-12 12:30:29'
static void handle_getblocklist(int cfd, char **argv, int argc) {
    //LOG_D("handle_getblocklist: %s\n", argv[0]);
    //for (int i = 1; i < argc; i++) {
        //LOG_D("argv[%d]: %s\n", i, argv[i]);
    //}
    if (argc != 4) { reply(cfd, "failed\nUsage failed\n"); return; }

    int ret = -1;
    char * data = NULL;

    ret = get_block_list_ips(&data, argv[1], argv[2], argv[3]);

    if (ret == -1) {
        reply(cfd, "failed\nFailed to get filtered blocklist\n");    
    } else {
        reply(cfd, "ok\n%s\n", data);
    }
    if (data) free (data);
}

static void handle_getmachineid(int cfd, char **argv, int argc) {
    //LOG_D("handle_getmachineid: %s\n", argv[0]);
    //for (int i = 1; i < argc; i++) {
        //LOG_D("argv[%d]: %s\n", i, argv[i]);
    //}
    if (argc != 1) { reply(cfd, "failed\nUsage failed\n"); return; }

    int ret = -1;
    
    char machine_id[256];
    ret = get_machine_id(machine_id);

    if (ret == -1) {
        reply(cfd, "failed\nFailed to get machine_id\n");    
    } else {
        reply(cfd, "ok\n%s\n", machine_id);
    }
}

static void handle_traffic_timestamps(int cfd, char **argv, int argc) {
    //LOG_D("handle_traffic_timestamps: %s\n", argv[0]);
    //for (int i = 1; i < argc; i++) {
        //LOG_D("argv[%d]: %s\n", i, argv[i]);
    //}
    if (argc != 1) { reply(cfd, "failed\nUsage failed\n"); return; }

    int first_zero = -1;
    for (int i = 0; i < TRAFFIC_STATS_SLOTS; i++) {
        if (global_traffic_stats[i].timestamp == 0) {
            first_zero = i;
            break;
        }
    }

    /* Empty, or filled from slot 0 and not yet wrapped. */
    int oldest = 0;
    int count = 0;
    if (first_zero == 0) {
        reply(cfd, "ok\n\n");
        return;
    }
    if (first_zero > 0) {
        count = first_zero;
    } else {
        /* Full ring. The single step backward is where the writer wrapped. */
        int newest = TRAFFIC_STATS_SLOTS - 1;
        for (int i = 0; i < TRAFFIC_STATS_SLOTS - 1; i++) {
            if (global_traffic_stats[i].timestamp > global_traffic_stats[i + 1].timestamp) {
                newest = i;
                break;
            }
        }
        oldest = (newest + 1) % TRAFFIC_STATS_SLOTS;
        count = TRAFFIC_STATS_SLOTS;
    }

    /* 20 digits + comma per sample, plus "ok\n" and the trailing newline. */
    size_t cap = (size_t)count * 21 + 8;
    char *data = malloc(cap);
    if (!data) {
        reply(cfd, "failed\nOut of memory\n");
        return;
    }
    size_t len = 0;
    len += (size_t)snprintf(data + len, cap - len, "ok\n");
    for (int n = 0; n < count; n++) {
        int i = (oldest + n) % TRAFFIC_STATS_SLOTS;
        if (global_traffic_stats[i].timestamp == 0)
            continue;
        len += (size_t)snprintf(data + len, cap - len, "%llu,", global_traffic_stats[i].timestamp);
    }
    len += (size_t)snprintf(data + len, cap - len, "\n");
    reply(cfd, "%s", data);
    free(data);
}

static void handle_traffic_stats(int cfd, char **argv, int argc) {
    //LOG_D("handle_traffic_stats: %s\n", argv[0]);
    //for (int i = 1; i < argc; i++) {
        //LOG_D("argv[%d]: %s\n", i, argv[i]);
    //}
    if (argc != 2) { reply(cfd, "failed\nUsage failed\n"); return; }
    int ret = -1;
    int timestamp = atoi(argv[1]);
    int index = 0;
    for (int i = 0; i < TRAFFIC_STATS_SLOTS; i++) {
        if (global_traffic_stats[i].timestamp == (__u64)timestamp) {
            ret = 0;
            index = i;
            break;
        }
    }
    if (ret == -1) {
        reply(cfd, "failed\nNo data found for timestamp %d\n", timestamp);
    } else {    
        reply(cfd, "ok\ntotal:%llu,allow:%llu,block:%llu,syn:%llu,ack:%llu,rst:%llu,tcp:%llu,udp:%llu,icmp:%llu,gre:%llu,other:%llu\n",
            global_traffic_stats[index].total_traffic, global_traffic_stats[index].allowed_traffic, global_traffic_stats[index].blocked_traffic,
            global_traffic_stats[index].syn, global_traffic_stats[index].ack, global_traffic_stats[index].rst, global_traffic_stats[index].tcp,
            global_traffic_stats[index].udp, global_traffic_stats[index].icmp, global_traffic_stats[index].gre, global_traffic_stats[index].other);
    }
}


/* Table‐driven dispatch */
struct cmd_entry { const char *name; void (*fn)(int,char**,int); };
static const struct cmd_entry cmds[] = {
    {"RESTART_FW",  handle_restart_fw},
    {"RELOAD_FW",   handle_reload_fw},
    {"CLEAR_FW",    handle_clear_fw},
    {"STATS_FW",    handle_stats_fw},
    {"STATS_DET",   handle_stats_det},
    {"STATS_CAP",   handle_stats_cap},
    {"STATS_SHADOW", handle_stats_shadow},
    {"SET_ENFORCE", handle_set_enforce},
    {"SET_ADAPTIVE", handle_set_adaptive},
    {"LIST_BLOCK_IP",      handle_list_block_ip},
    {"LIST_ALLOW_IP",      handle_list_allow_ip},
    {"CLEAR_BLOCK_IP",     handle_clear_deny_ip},
    {"CLEAR_ALLOW_IP",     handle_clear_allow_ip},
    {"CLEAR_BLOCK_IP_ALL", handle_clear_deny_ip_all},
    {"CLEAR_ALLOW_IP_ALL", handle_clear_allow_ip_all},
    {"ADD_BLOCK_IP",       handle_add_block_ip},
    {"ADD_ALLOW_IP",       handle_add_allow_ip},
    {"TCP_SYN",    handle_tcp_syn_set},
    {"TCP_ACK",    handle_tcp_ack_set},
    {"TCP_RST",    handle_tcp_rst_set},
    {"TCP_STOMP", handle_tcp_stomp_set},
    {"TCP_SOCKET", handle_tcp_socket_set},
    {"ICMP",    handle_icmp_set},
    {"UDP",    handle_udp_set},
    {"GRE",    handle_gre_set},
    {"SET_TCP_SEG", handle_tcp_set_seg},
    {"SET_GEO", handle_set_geo},
    {"SET_CONN_LIMIT", handle_set_conn_limit},
    {"HEALTH_CHECK", handle_health_check},
    {"GET_BLOCKLIST", handle_getblocklist},
    {"GET_MACHINE_ID", handle_getmachineid},
    {"TRAFFIC_TIMESTAMPS", handle_traffic_timestamps},
    {"TRAFFIC_STATS", handle_traffic_stats},
};

static void dispatch(int cfd, char *line) {
    /* Tokenize in‑place */
    char *argv[10];
    int argc = 0;
    for (char *tok = strtok(line, " \t\r\n"); tok && argc < 10; tok = strtok(NULL, " \t\r\n"))
        argv[argc++] = tok;
    if (argc == 0) return;

    for (size_t i = 0; i < sizeof cmds / sizeof *cmds; ++i) {
        if (strcasecmp(argv[0], cmds[i].name) == 0) {
            cmds[i].fn(cfd, argv, argc);
            return;
        }
    }
    reply(cfd, "ERR unknown command\n");
}

/* Bulk requests span several reads: keep reading until the END line, EOF,
 * timeout or BULK_BUF_SZ. Returns a malloc'd NUL-terminated buffer. */
static char *read_bulk_request(int cfd, const char *first, size_t first_len)
{
    char *big = malloc(BULK_BUF_SZ);
    if (!big)
        return NULL;
    size_t len = first_len < BULK_BUF_SZ - 1 ? first_len : BULK_BUF_SZ - 1;
    memcpy(big, first, len);
    big[len] = '\0';

    while (len < BULK_BUF_SZ - 1) {
        if (strstr(big, "\nEND\n"))
            break;
        ssize_t n = read(cfd, big + len, BULK_BUF_SZ - 1 - len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        len += (size_t)n;
        big[len] = '\0';
    }
    return big;
}

static void * unix_socket_worker(void * arg)
{
    while (!exiting) 
    {
        int cfd = accept(srv_fd, NULL, NULL);
        if (cfd == -1) { if (errno == EINTR) continue; LOG_E("accept"); break; }

        /* A client that never sends must not stall this single-threaded server. */
        struct timeval tv = { .tv_sec = CLIENT_RCV_TIMEOUT_S, .tv_usec = 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        char buf[BUF_SZ];
        ssize_t n;
        /* Handle exactly one request per connection (simple) */
        if ((n = read(cfd, buf, sizeof buf - 1)) > 0) {
            buf[n] = '\0';
            if ((size_t)n >= sizeof(BULK_CMD) - 1 &&
                strncasecmp(buf, BULK_CMD, sizeof(BULK_CMD) - 1) == 0 &&
                (buf[sizeof(BULK_CMD) - 1] == ' ' || buf[sizeof(BULK_CMD) - 1] == '\n')) {
                char *big = read_bulk_request(cfd, buf, (size_t)n);
                if (big) {
                    handle_add_block_ips(cfd, big);
                    free(big);
                } else {
                    reply(cfd, "failed\nout of memory\n");
                }
            } else {
                dispatch(cfd, buf);
            }
        }
        close(cfd);
    }

    return NULL;
}

int init_unix_socket() {
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof addr.sun_path - 1);

    /* Clean start */
    unlink(SOCK_PATH);
    if ((srv_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOG_E("socket");
        return -1;
    }

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof addr) == -1) {
        LOG_E("bind");
        return -1;
    }

    if (listen(srv_fd, 8) == -1) {
        LOG_E("listen");
        return -1;
    }

    pthread_t unix_socket_worker_thr;
    if (pthread_create(&unix_socket_worker_thr, NULL, unix_socket_worker, NULL) != 0) {
        LOG_E("pthread_create for unix_socket_worker_thr");
        return -1;
    }

    return 0;
}

void close_unix_socket() {
    if (srv_fd != -1) 
        close(srv_fd);
    unlink(SOCK_PATH);
}