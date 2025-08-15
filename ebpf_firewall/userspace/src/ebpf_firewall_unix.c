
#include <stdarg.h>
#include <strings.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ebpf_firewall_common.h>
#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_core.h>
#include <ebpf_firewall_log.h>


static int srv_fd = -1;
extern int exiting;
extern struct stats_config global_receive_stats;
extern struct stats_config global_passed_stats;
extern struct fixed_ip_pkt_stats global_max_ip_pkt_stats;
#define BUF_SZ    1024
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
    int ret = -1;
    ret = restart_fw();
    if (ret == -1 ) {
        reply(cfd, "Failed! FW restarted failed\n");
    } else {
        reply(cfd, "OK! FW restarted\n");
    }
}

static void handle_reload_fw(int cfd, char **argv, int argc) {
    int ret = -1;
    ret = reload_fw();
    if (ret == -1 ) {
       reply(cfd, "failed\nReload config failed\n");
    } else {
        reply(cfd, "ok\nsuccess\n");
    }
}

static void handle_clear_fw(int cfd, char **argv, int argc) {
    int ret = -1;
    ret = clear_fw();
    if (ret == -1) {
        reply(cfd, "Failed! FW clear stats failed\n");
    } else {
        reply(cfd, "OK! FW clear stats\n");
    }
}

static void handle_stats_fw(int cfd, char **argv, int argc) {
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
    int ret = -1;
    ret = clear_deny_ip_all();
    if (ret == 0) {        
        reply(cfd, "ok\nsuccess\n");
    } else {
        reply(cfd, "failed\nError occured while removing all ips in blacklist\n", argv[1]);
    }
}

static void handle_add_block_ip(int cfd, char **argv, int argc) {
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

    if (ret == 0 || ret == 1)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while adding %s to blacklist\n", ip);
}



/* -------------------- whitelist handlers -------------------- */
static void handle_list_allow_ip(int cfd, char **argv, int argc) {
    char *data = NULL;
    if (list_allow_ip(&data) == -1) {
        reply(cfd, "Failed! List ALLOW_IP failed\n");
    } else {
        reply(cfd, "OK\n%s\n", data);
    }
    if (data) free(data);
}

static void handle_clear_allow_ip(int cfd, char **argv, int argc) {
    if (argc != 2) { reply(cfd, "ERR usage: CLEAR_ALLOW_IP <ip>\n"); return; }
    int ret = clear_allow_ip(argv[1]);
    if (ret == 0)
        reply(cfd, "OK %s removed from whitelist\n", argv[1]);
    else if (ret == -ENOENT)
        reply(cfd, "OK! But ip %s was not in whitelist\n", argv[1]);
    else
        reply(cfd, "Failed! Clear ALLOW_IP %s failed\n", argv[1]);
}

static void handle_clear_allow_ip_all(int cfd, char **argv, int argc) {
    int ret = clear_allow_ip_all();
    if (ret == 0) reply(cfd, "OK! Cleared whitelist\n");
    else reply(cfd, "Failed! Clear whitelist failed\n");
}

static void handle_add_allow_ip(int cfd, char **argv, int argc) {
    if (argc != 2) { reply(cfd, "ERR usage: ADD_ALLOW_IP <ip>\n"); return; }
    int ret = add_allow_ip(argv[1]);
    
    if (ret == 0)
        reply(cfd, "ok\n%s is added in allow list\n", argv[1]);
    else
        reply(cfd, "failed\nError occured while adding %s to allow list\n", argv[1]);
}


static void handle_tcp_syn_set(int cfd, char **argv, int argc) {
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

static void handle_icmp_set(int cfd, char **argv, int argc) {
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
    if (argc != 3) { reply(cfd, "failed\nUsage failed\n"); return; }
    int valid = 0;
    if (strncmp(argv[1], "on", 2) == 0) valid = 1;
    else valid = 0;

    int ret = geo_set(valid, argv[2]);
    if (ret == 0)
        reply(cfd, "ok\nsuccess\n");
    else
        reply(cfd, "failed\nError occured while setting parameters\n");
}

static void handle_set_conn_limit(int cfd, char **argv, int argc) {
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

/* Table‐driven dispatch */
struct cmd_entry { const char *name; void (*fn)(int,char**,int); };
static const struct cmd_entry cmds[] = {
    {"RESTART_FW",  handle_restart_fw},
    {"RELOAD_FW",   handle_reload_fw},
    {"CLEAR_FW",    handle_clear_fw},
    {"STATS_FW",    handle_stats_fw},
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
    {"ICMP",    handle_icmp_set},
    {"UDP",    handle_udp_set},
    {"GRE",    handle_gre_set},
    {"SET_TCP_SEG", handle_tcp_set_seg},
    {"SET_GEO", handle_set_geo},
    {"SET_CONN_LIMIT", handle_set_conn_limit},
    {"HEALTH_CHECK", handle_health_check},
    {"GET_BLOCKLIST", handle_getblocklist}
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

static void * unix_socket_worker(void * arg)
{
    while (!exiting) 
    {
        int cfd = accept(srv_fd, NULL, NULL);
        if (cfd == -1) { if (errno == EINTR) continue; LOG_E("accept"); break; }

        char buf[BUF_SZ];
        ssize_t n;
        /* Handle exactly one request per connection (simple) */
        if ((n = read(cfd, buf, sizeof buf - 1)) > 0) {
            buf[n] = '\0';
            dispatch(cfd, buf);
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