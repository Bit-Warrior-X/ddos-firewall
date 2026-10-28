// gcc -o firewall_cli firewall_cli.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>


#define FIREWALL_START "systemctl start ebpf-firewall"
#define FIREWALL_STOP  "systemctl stop ebpf-firewall"
#define FIREWALL_RESTART  "systemctl restart ebpf-firewall"

#define MAX_LINE_LENGTH 256
#define MAX_COMMENT_LENGTH 256
#define CONFIG_PATH "/usr/local/share/dorian/sparta/firewall.config"
#define TEMP_FILE_TEMPLATE "/tmp/firewall_config.XXXXXX"
#define SOCK_PATH "/tmp/ebpf_fw.sock"
#define BUF_SZ    1024

static void usage(void) {
    fputs(
"Usage: firewall_cli COMMAND [args]\n"
"Commands:\n"
"  START_FW <dev> <attach_method> : Start the firewall.\n"
"  STOP_FW <dev> <attach_method> : Stop the firewall.\n"
"  RESTART_FW <dev> <attach_method> : Restart the firewall.\n"
"  RELOAD_FW : Reload the firewall config.\n"
"  TCP_SYN <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> <challenge_timeout>: Set tcp syn parameters.\n"
"  TCP_ACK <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> : Set tcp ack parameters.\n"
"  TCP_RST <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> : Set tcp rst parameters.\n"
"  TCP_STOMP <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> : Set tcp stomp (PSH+ACK) parameters.\n"
"  TCP_SOCKET <status> <fin_threshold> <fixed_threshold> <fixed_duration> : Set tcp socket (unusual flag) parameters.\n"
"  ICMP <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> : Set icmp parameters.\n"
"  UDP <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> : Set udp parameters.\n"
"  GRE <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> : Set gre parameters.\n"
"  SET_TCP_SEG <status> : Set tcp segment status parameters.\n"
"  SET_GEO <status> <countries> : Set geo location status parameters. status can be allow or block or off\n"
"  SET_CONN_LIMIT <status> <count> : Set tcp connection limit parameters.\n"
"  CLEAR_FW : Clear all packet statistics. (Reset all statistics as zero).\n"
"  STATS_FW : Display all packet information captured. (SYN, ACK, RST, PSH, FIN, URG, SYN+ACK, FIN+ACK, RST+ACK, ICMP UDP, GRE)\n"
"  LIST_BLOCK_IP : Dump current blacklist ip. (ip expire_ns per line)\n"
"  CLEAR_BLOCK_IP <ip> : Remove ip from blacklist\n"
"  CLEAR_BLOCK_IP_ALL : Remove all ips from blacklist\n"
"  ADD_BLOCK_IP <ip> [seconds] : Add ip to blacklist. Default duration if seconds omitted.\n"
"  ADD_BLOCK_IPS <seconds> [reason] : Add IPs read from stdin (one per line) to blacklist.\n"
"  LIST_ALLOW_IP : Dump whitelist ip list\n"
"  CLEAR_ALLOW_IP <ip> : Remove ip from whitelist\n"
"  CLEAR_ALLOW_IP_ALL : Remove all ips from blacklist\n"
"  ADD_ALLOW_IP <ip> : Add ip to whitelist.\n"
"  HEALTH_CHECK : Check the health status of sparta\n"
"  GET_BLOCKLIST <filter_type> <filter_ip> <filter_date> : Get the filtered block list ips\n"
"  GET_MACHINE_ID : Get machine id\n"
"  TRAFFIC_TIMESTAMPS : Get all traffic timestamps\n"
"  TRAFFIC_STATS <timestamp> : Get traffic stats for a given timestamp\n"
, stderr);
    exit(EXIT_FAILURE);
}


typedef struct {
    // Global section
    char *log_path;
    char *dev;
    char *attach_mode;
    int black_ip_duration;
    
    // SYN section
    int syn_valid;
    int syn_threshold;
    int syn_burst_pkt;
    int syn_burst_count_per_sec;
    int syn_fixed_threshold;
    int syn_fixed_check_duration;
    int challenge_timeout;
    int syn_protection_duration;
    
    // ACK section
    int ack_valid;
    int ack_threshold;
    int ack_burst_pkt;
    int ack_burst_count_per_sec;
    int ack_fixed_threshold;
    int ack_fixed_check_duration;
    int ack_protection_duration;
    
    // RST section
    int rst_valid;
    int rst_threshold;
    int rst_burst_pkt;
    int rst_burst_count_per_sec;
    int rst_fixed_threshold;
    int rst_fixed_check_duration;
    int rst_protection_duration;

    // STOMP section (PSH+ACK)
    int stomp_valid;
    int stomp_threshold;
    int stomp_burst_pkt;
    int stomp_burst_count_per_sec;
    int stomp_fixed_threshold;
    int stomp_fixed_check_duration;
    int stomp_protection_duration;

    // HandShake section (preserved on rewrite; no live command yet)
    int handshake_valid;
    int handshake_threshold;
    int handshake_burst_pkt;
    int handshake_burst_count_per_sec;
    int handshake_fixed_threshold;
    int handshake_fixed_check_duration;
    int handshake_protection_duration;

    /* SOCKET: unusual TCP flags. No burst and no global attack mode. */
    int socket_valid;
    int socket_fin_threshold;
    int socket_fixed_threshold;
    int socket_fixed_check_duration;
    
    // ICMP section
    int icmp_valid;
    int icmp_threshold;
    int icmp_burst_pkt;
    int icmp_burst_count_per_sec;
    int icmp_fixed_threshold;
    int icmp_fixed_check_duration;
    int icmp_protection_duration;
    
    // UDP section
    int udp_valid;
    int udp_threshold;
    int udp_burst_pkt;
    int udp_burst_count_per_sec;
    int udp_fixed_threshold;
    int udp_fixed_check_duration;
    int udp_protection_duration;
    
    // GRE section
    int gre_valid;
    int gre_threshold;
    int gre_burst_pkt;
    int gre_burst_count_per_sec;
    int gre_fixed_threshold;
    int gre_fixed_check_duration;
    int gre_protection_duration;
    
    // TCP Segment check
    int tcp_seg_check;
    
    // Geo Location Check
    int geo_check;
    char *geo_db_ipv4_path;
    char *geo_db_location_path;
    char *geo_countries;
    
    // TCP Connection Limit
    int tcp_connection_limit_check;
    int tcp_connection_limit_cnt;
    
    // Comments and section headers
    char global_comment[MAX_COMMENT_LENGTH];
    char syn_comment[MAX_COMMENT_LENGTH];
    char ack_comment[MAX_COMMENT_LENGTH];
    char rst_comment[MAX_COMMENT_LENGTH];
    char stomp_comment[MAX_COMMENT_LENGTH];
    char handshake_comment[MAX_COMMENT_LENGTH];
    char socket_comment[MAX_COMMENT_LENGTH];
    char icmp_comment[MAX_COMMENT_LENGTH];
    char udp_comment[MAX_COMMENT_LENGTH];
    char gre_comment[MAX_COMMENT_LENGTH];
    char tcp_seg_comment[MAX_COMMENT_LENGTH];
    char geo_comment[MAX_COMMENT_LENGTH];
    char tcp_conn_comment[MAX_COMMENT_LENGTH];

    // Map sizing
    int map_size_blocked_ips;
    int map_size_syn;
    int map_size_ack;
    int map_size_rst;
    int map_size_icmp;
    int map_size_udp;
    int map_size_gre;
    int map_size_psh;
    int map_size_socket;
    int map_size_handshake;
    int map_size_tcp_established;
    int map_size_geo_cache;

} FirewallConfig;

void free_config(FirewallConfig *config) {
    if (config->log_path) free(config->log_path);
    if (config->dev) free(config->dev);
    if (config->attach_mode) free(config->attach_mode);
    if (config->geo_db_ipv4_path) free(config->geo_db_ipv4_path);
    if (config->geo_db_location_path) free(config->geo_db_location_path);
    if (config->geo_countries) free(config->geo_countries);
}


int parse_config(const char *filename, FirewallConfig *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open config file");
        return -1;
    }

    char line[MAX_LINE_LENGTH * 4];

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;
        line[strcspn(line, "\r")] = 0;

        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '#')
            continue;

        /* Strip inline comments so values like "native # note" parse cleanly. */
        char *hash = strchr(p, '#');
        if (hash)
            *hash = '\0';

        char *eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';

        char *key = p;
        char *key_end = eq;
        while (key_end > key && (key_end[-1] == ' ' || key_end[-1] == '\t'))
            key_end--;
        *key_end = '\0';

        char *value = eq + 1;
        while (*value == ' ' || *value == '\t')
            value++;
        char *value_end = value + strlen(value);
        while (value_end > value && (value_end[-1] == ' ' || value_end[-1] == '\t'))
            value_end--;
        *value_end = '\0';

        if (*key == '\0' || *value == '\0')
            continue;

        /* Match by key name only — adaptive configs have free-form comments
         * that used to false-trigger section detection (e.g. "SYN cookies"). */
        if (strcmp(key, "log") == 0) {
            free(config->log_path);
            config->log_path = strdup(value);
        } else if (strcmp(key, "dev") == 0) {
            free(config->dev);
            config->dev = strdup(value);
        } else if (strcmp(key, "attach_mode") == 0) {
            free(config->attach_mode);
            config->attach_mode = strdup(value);
        } else if (strcmp(key, "black_ip_duration") == 0) {
            config->black_ip_duration = atoi(value);
        } else if (strcmp(key, "syn_valid") == 0) {
            config->syn_valid = atoi(value);
        } else if (strcmp(key, "syn_threshold") == 0) {
            config->syn_threshold = atoi(value);
        } else if (strcmp(key, "syn_burst_pkt") == 0) {
            config->syn_burst_pkt = atoi(value);
        } else if (strcmp(key, "syn_burst_count_per_sec") == 0) {
            config->syn_burst_count_per_sec = atoi(value);
        } else if (strcmp(key, "syn_fixed_threshold") == 0) {
            config->syn_fixed_threshold = atoi(value);
        } else if (strcmp(key, "syn_fixed_check_duration") == 0) {
            config->syn_fixed_check_duration = atoi(value);
        } else if (strcmp(key, "challenge_timeout") == 0) {
            config->challenge_timeout = atoi(value);
        } else if (strcmp(key, "syn_protection_duration") == 0) {
            config->syn_protection_duration = atoi(value);
        } else if (strcmp(key, "ack_valid") == 0) {
            config->ack_valid = atoi(value);
        } else if (strcmp(key, "ack_threshold") == 0) {
            config->ack_threshold = atoi(value);
        } else if (strcmp(key, "ack_burst_pkt") == 0) {
            config->ack_burst_pkt = atoi(value);
        } else if (strcmp(key, "ack_burst_count_per_sec") == 0) {
            config->ack_burst_count_per_sec = atoi(value);
        } else if (strcmp(key, "ack_fixed_threshold") == 0) {
            config->ack_fixed_threshold = atoi(value);
        } else if (strcmp(key, "ack_fixed_check_duration") == 0) {
            config->ack_fixed_check_duration = atoi(value);
        } else if (strcmp(key, "ack_protection_duration") == 0) {
            config->ack_protection_duration = atoi(value);
        } else if (strcmp(key, "rst_valid") == 0) {
            config->rst_valid = atoi(value);
        } else if (strcmp(key, "rst_threshold") == 0) {
            config->rst_threshold = atoi(value);
        } else if (strcmp(key, "rst_burst_pkt") == 0) {
            config->rst_burst_pkt = atoi(value);
        } else if (strcmp(key, "rst_burst_count_per_sec") == 0) {
            config->rst_burst_count_per_sec = atoi(value);
        } else if (strcmp(key, "rst_fixed_threshold") == 0) {
            config->rst_fixed_threshold = atoi(value);
        } else if (strcmp(key, "rst_fixed_check_duration") == 0) {
            config->rst_fixed_check_duration = atoi(value);
        } else if (strcmp(key, "rst_protection_duration") == 0) {
            config->rst_protection_duration = atoi(value);
        } else if (strcmp(key, "stomp_valid") == 0) {
            config->stomp_valid = atoi(value);
        } else if (strcmp(key, "stomp_threshold") == 0) {
            config->stomp_threshold = atoi(value);
        } else if (strcmp(key, "stomp_burst_pkt") == 0) {
            config->stomp_burst_pkt = atoi(value);
        } else if (strcmp(key, "stomp_burst_count_per_sec") == 0) {
            config->stomp_burst_count_per_sec = atoi(value);
        } else if (strcmp(key, "stomp_fixed_threshold") == 0) {
            config->stomp_fixed_threshold = atoi(value);
        } else if (strcmp(key, "stomp_fixed_check_duration") == 0) {
            config->stomp_fixed_check_duration = atoi(value);
        } else if (strcmp(key, "stomp_protection_duration") == 0) {
            config->stomp_protection_duration = atoi(value);
        } else if (strcmp(key, "handshake_valid") == 0) {
            config->handshake_valid = atoi(value);
        } else if (strcmp(key, "handshake_threshold") == 0) {
            config->handshake_threshold = atoi(value);
        } else if (strcmp(key, "handshake_burst_pkt") == 0) {
            config->handshake_burst_pkt = atoi(value);
        } else if (strcmp(key, "handshake_burst_count_per_sec") == 0) {
            config->handshake_burst_count_per_sec = atoi(value);
        } else if (strcmp(key, "handshake_fixed_threshold") == 0) {
            config->handshake_fixed_threshold = atoi(value);
        } else if (strcmp(key, "handshake_fixed_check_duration") == 0) {
            config->handshake_fixed_check_duration = atoi(value);
        } else if (strcmp(key, "handshake_protection_duration") == 0) {
            config->handshake_protection_duration = atoi(value);
        } else if (strcmp(key, "socket_valid") == 0) {
            config->socket_valid = atoi(value);
        } else if (strcmp(key, "socket_fin_threshold") == 0) {
            config->socket_fin_threshold = atoi(value);
        } else if (strcmp(key, "socket_fixed_threshold") == 0) {
            config->socket_fixed_threshold = atoi(value);
        } else if (strcmp(key, "socket_fixed_check_duration") == 0) {
            config->socket_fixed_check_duration = atoi(value);
        } else if (strcmp(key, "icmp_valid") == 0) {
            config->icmp_valid = atoi(value);
        } else if (strcmp(key, "icmp_threshold") == 0) {
            config->icmp_threshold = atoi(value);
        } else if (strcmp(key, "icmp_burst_pkt") == 0) {
            config->icmp_burst_pkt = atoi(value);
        } else if (strcmp(key, "icmp_burst_count_per_sec") == 0) {
            config->icmp_burst_count_per_sec = atoi(value);
        } else if (strcmp(key, "icmp_fixed_threshold") == 0) {
            config->icmp_fixed_threshold = atoi(value);
        } else if (strcmp(key, "icmp_fixed_check_duration") == 0) {
            config->icmp_fixed_check_duration = atoi(value);
        } else if (strcmp(key, "icmp_protection_duration") == 0) {
            config->icmp_protection_duration = atoi(value);
        } else if (strcmp(key, "udp_valid") == 0) {
            config->udp_valid = atoi(value);
        } else if (strcmp(key, "udp_threshold") == 0) {
            config->udp_threshold = atoi(value);
        } else if (strcmp(key, "udp_burst_pkt") == 0) {
            config->udp_burst_pkt = atoi(value);
        } else if (strcmp(key, "udp_burst_count_per_sec") == 0) {
            config->udp_burst_count_per_sec = atoi(value);
        } else if (strcmp(key, "udp_fixed_threshold") == 0) {
            config->udp_fixed_threshold = atoi(value);
        } else if (strcmp(key, "udp_fixed_check_duration") == 0) {
            config->udp_fixed_check_duration = atoi(value);
        } else if (strcmp(key, "udp_protection_duration") == 0) {
            config->udp_protection_duration = atoi(value);
        } else if (strcmp(key, "gre_valid") == 0) {
            config->gre_valid = atoi(value);
        } else if (strcmp(key, "gre_threshold") == 0) {
            config->gre_threshold = atoi(value);
        } else if (strcmp(key, "gre_burst_pkt") == 0) {
            config->gre_burst_pkt = atoi(value);
        } else if (strcmp(key, "gre_burst_count_per_sec") == 0) {
            config->gre_burst_count_per_sec = atoi(value);
        } else if (strcmp(key, "gre_fixed_threshold") == 0) {
            config->gre_fixed_threshold = atoi(value);
        } else if (strcmp(key, "gre_fixed_check_duration") == 0) {
            config->gre_fixed_check_duration = atoi(value);
        } else if (strcmp(key, "gre_protection_duration") == 0) {
            config->gre_protection_duration = atoi(value);
        } else if (strcmp(key, "tcp_seg_check") == 0) {
            config->tcp_seg_check = atoi(value);
        } else if (strcmp(key, "geo_check") == 0) {
            config->geo_check = atoi(value);
        } else if (strcmp(key, "geo_db_ipv4_path") == 0) {
            free(config->geo_db_ipv4_path);
            config->geo_db_ipv4_path = strdup(value);
        } else if (strcmp(key, "geo_db_location_path") == 0) {
            free(config->geo_db_location_path);
            config->geo_db_location_path = strdup(value);
        } else if (strcmp(key, "geo_countries") == 0) {
            free(config->geo_countries);
            config->geo_countries = strdup(value);
        } else if (strcmp(key, "tcp_connection_limit_check") == 0) {
            config->tcp_connection_limit_check = atoi(value);
        } else if (strcmp(key, "tcp_connection_limit_cnt") == 0) {
            config->tcp_connection_limit_cnt = atoi(value);
        }
        /* Adaptive / unknown keys intentionally ignored here; merge write preserves them. */
    }

    fclose(file);
    return 0;
}

/*
 * Merge classic CLI-managed keys into an existing firewall.config.
 * Preserves adaptive/unknown keys, comments, and layout. Only rewrites
 * values for keys already present in the file (never appends classic-only
 * fields like black_ip_duration / *_threshold that adaptive configs omit).
 */
typedef struct {
    const char *key;
    char value[128];
} ConfigUpdate;

static int collect_classic_updates(const FirewallConfig *config, ConfigUpdate *out, int max_out)
{
    int n = 0;
#define ADD_I(k, v) do { \
        if (n >= max_out) return -1; \
        out[n].key = (k); \
        snprintf(out[n].value, sizeof out[n].value, "%d", (int)(v)); \
        n++; \
    } while (0)
#define ADD_S(k, v) do { \
        if (n >= max_out) return -1; \
        out[n].key = (k); \
        snprintf(out[n].value, sizeof out[n].value, "%s", (v) ? (v) : ""); \
        n++; \
    } while (0)

    ADD_S("log", config->log_path);
    ADD_S("dev", config->dev);
    ADD_S("attach_mode", config->attach_mode);
    ADD_I("black_ip_duration", config->black_ip_duration);

    ADD_I("syn_valid", config->syn_valid);
    ADD_I("syn_threshold", config->syn_threshold);
    ADD_I("syn_burst_pkt", config->syn_burst_pkt);
    ADD_I("syn_burst_count_per_sec", config->syn_burst_count_per_sec);
    ADD_I("syn_fixed_threshold", config->syn_fixed_threshold);
    ADD_I("syn_fixed_check_duration", config->syn_fixed_check_duration);
    ADD_I("challenge_timeout", config->challenge_timeout);
    ADD_I("syn_protection_duration", config->syn_protection_duration);

    ADD_I("ack_valid", config->ack_valid);
    ADD_I("ack_threshold", config->ack_threshold);
    ADD_I("ack_burst_pkt", config->ack_burst_pkt);
    ADD_I("ack_burst_count_per_sec", config->ack_burst_count_per_sec);
    ADD_I("ack_fixed_threshold", config->ack_fixed_threshold);
    ADD_I("ack_fixed_check_duration", config->ack_fixed_check_duration);
    ADD_I("ack_protection_duration", config->ack_protection_duration);

    ADD_I("rst_valid", config->rst_valid);
    ADD_I("rst_threshold", config->rst_threshold);
    ADD_I("rst_burst_pkt", config->rst_burst_pkt);
    ADD_I("rst_burst_count_per_sec", config->rst_burst_count_per_sec);
    ADD_I("rst_fixed_threshold", config->rst_fixed_threshold);
    ADD_I("rst_fixed_check_duration", config->rst_fixed_check_duration);
    ADD_I("rst_protection_duration", config->rst_protection_duration);

    ADD_I("stomp_valid", config->stomp_valid);
    ADD_I("stomp_threshold", config->stomp_threshold);
    ADD_I("stomp_burst_pkt", config->stomp_burst_pkt);
    ADD_I("stomp_burst_count_per_sec", config->stomp_burst_count_per_sec);
    ADD_I("stomp_fixed_threshold", config->stomp_fixed_threshold);
    ADD_I("stomp_fixed_check_duration", config->stomp_fixed_check_duration);
    ADD_I("stomp_protection_duration", config->stomp_protection_duration);

    ADD_I("handshake_valid", config->handshake_valid);
    ADD_I("handshake_threshold", config->handshake_threshold);
    ADD_I("handshake_burst_pkt", config->handshake_burst_pkt);
    ADD_I("handshake_burst_count_per_sec", config->handshake_burst_count_per_sec);
    ADD_I("handshake_fixed_threshold", config->handshake_fixed_threshold);
    ADD_I("handshake_fixed_check_duration", config->handshake_fixed_check_duration);
    ADD_I("handshake_protection_duration", config->handshake_protection_duration);

    ADD_I("socket_valid", config->socket_valid);
    ADD_I("socket_fin_threshold", config->socket_fin_threshold);
    ADD_I("socket_fixed_threshold", config->socket_fixed_threshold);
    ADD_I("socket_fixed_check_duration", config->socket_fixed_check_duration);

    ADD_I("icmp_valid", config->icmp_valid);
    ADD_I("icmp_threshold", config->icmp_threshold);
    ADD_I("icmp_burst_pkt", config->icmp_burst_pkt);
    ADD_I("icmp_burst_count_per_sec", config->icmp_burst_count_per_sec);
    ADD_I("icmp_fixed_threshold", config->icmp_fixed_threshold);
    ADD_I("icmp_fixed_check_duration", config->icmp_fixed_check_duration);
    ADD_I("icmp_protection_duration", config->icmp_protection_duration);

    ADD_I("udp_valid", config->udp_valid);
    ADD_I("udp_threshold", config->udp_threshold);
    ADD_I("udp_burst_pkt", config->udp_burst_pkt);
    ADD_I("udp_burst_count_per_sec", config->udp_burst_count_per_sec);
    ADD_I("udp_fixed_threshold", config->udp_fixed_threshold);
    ADD_I("udp_fixed_check_duration", config->udp_fixed_check_duration);
    ADD_I("udp_protection_duration", config->udp_protection_duration);

    ADD_I("gre_valid", config->gre_valid);
    ADD_I("gre_threshold", config->gre_threshold);
    ADD_I("gre_burst_pkt", config->gre_burst_pkt);
    ADD_I("gre_burst_count_per_sec", config->gre_burst_count_per_sec);
    ADD_I("gre_fixed_threshold", config->gre_fixed_threshold);
    ADD_I("gre_fixed_check_duration", config->gre_fixed_check_duration);
    ADD_I("gre_protection_duration", config->gre_protection_duration);

    ADD_I("tcp_seg_check", config->tcp_seg_check);
    ADD_I("geo_check", config->geo_check);
    ADD_S("geo_db_ipv4_path", config->geo_db_ipv4_path);
    ADD_S("geo_db_location_path", config->geo_db_location_path);
    ADD_S("geo_countries", config->geo_countries);
    ADD_I("tcp_connection_limit_check", config->tcp_connection_limit_check);
    ADD_I("tcp_connection_limit_cnt", config->tcp_connection_limit_cnt);

#undef ADD_I
#undef ADD_S
    return n;
}

static const char *lookup_update(const ConfigUpdate *updates, int n, const char *key)
{
    for (int i = 0; i < n; i++) {
        if (strcmp(updates[i].key, key) == 0)
            return updates[i].value;
    }
    return NULL;
}

int write_config(const char *filename, const FirewallConfig *config) {
    ConfigUpdate updates[96];
    int n_updates = collect_classic_updates(config, updates, 96);
    if (n_updates < 0) {
        fprintf(stderr, "Failed to collect config updates\n");
        return -1;
    }

    FILE *in = fopen(filename, "r");
    if (!in) {
        perror("Failed to open config file for merge");
        return -1;
    }

    char temp_filename[] = TEMP_FILE_TEMPLATE;
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        perror("Failed to create temporary file");
        fclose(in);
        return -1;
    }

    FILE *out = fdopen(fd, "w");
    if (!out) {
        perror("Failed to open temporary file");
        close(fd);
        unlink(temp_filename);
        fclose(in);
        return -1;
    }

    char line[MAX_LINE_LENGTH * 4];
    while (fgets(line, sizeof line, in)) {
        char *nl = strchr(line, '\n');
        int had_nl = nl != NULL;
        if (nl) *nl = '\0';
        if (had_nl && nl > line && nl[-1] == '\r')
            nl[-1] = '\0';

        char *hash = strchr(line, '#');
        char comment[MAX_LINE_LENGTH * 2] = "";
        if (hash) {
            strncpy(comment, hash, sizeof comment - 1);
            *hash = '\0';
        }

        char *eq = strchr(line, '=');
        if (!eq) {
            /* blank / comment-only / section header — keep as-is */
            fprintf(out, "%s%s\n", line, comment);
            continue;
        }

        /* Extract key (trim) */
        char keybuf[128];
        size_t key_len = (size_t)(eq - line);
        while (key_len > 0 && (line[key_len - 1] == ' ' || line[key_len - 1] == '\t'))
            key_len--;
        if (key_len >= sizeof keybuf)
            key_len = sizeof keybuf - 1;
        memcpy(keybuf, line, key_len);
        keybuf[key_len] = '\0';
        char *key = keybuf;
        while (*key == ' ' || *key == '\t')
            key++;

        const char *new_val = lookup_update(updates, n_updates, key);
        if (!new_val) {
            /* Unknown / adaptive key — restore comment and keep original */
            if (comment[0])
                fprintf(out, "%s%s\n", line, comment);
            else
                fprintf(out, "%s\n", line);
            continue;
        }

        /* Preserve key spacing before '='; rewrite value; keep trailing comment */
        *eq = '\0';
        if (comment[0])
            fprintf(out, "%s= %s %s\n", line, new_val, comment);
        else
            fprintf(out, "%s= %s\n", line, new_val);
    }

    fclose(in);
    if (ferror(out) || fclose(out) != 0) {
        perror("Failed writing merged config");
        unlink(temp_filename);
        return -1;
    }

    if (rename(temp_filename, filename) != 0) {
        perror("Failed to replace config file");
        unlink(temp_filename);
        return -1;
    }

    return 0;
}


static int send_and_print(const char *msg) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) { perror("socket"); return 2; }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof addr.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == -1) {
        printf("failed\nFirewall is not running\n");
        close(fd); return 2;
    }

    size_t len = strlen(msg);
    if (write(fd, msg, len) != (ssize_t)len) { perror("write"); close(fd); return 2; }

    char buf[BUF_SZ];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n > 0) {
            if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n) {
                fprintf(stderr, "failed\n%s\n", strerror(errno));
                close(fd);
                return 2;
            }
            continue;
        }
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        fprintf(stderr, "failed\n%s\n", strerror(errno));
        close(fd);
        return 2;
    }
    close(fd);
    return 0;
}

#define BULK_BUF_SZ (64 * 1024)

/* ADD_BLOCK_IPS <seconds> [reason] : IPs are read from stdin, one per line. */
static int send_bulk_block(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) usage();

    char *msg = malloc(BULK_BUF_SZ);
    if (!msg) { perror("malloc"); return 2; }
    size_t pos = (size_t)snprintf(msg, BULK_BUF_SZ, "ADD_BLOCK_IPS %d %s\n",
                                  atoi(argv[2]), argc == 4 ? argv[3] : "cli");

    char ip[64];
    while (fgets(ip, sizeof ip, stdin)) {
        size_t len = strcspn(ip, " \t\r\n");
        if (len == 0)
            continue;
        if (pos + len + sizeof("\nEND\n") >= BULK_BUF_SZ) {
            fputs("failed\ntoo many IPs (64KB request limit)\n", stderr);
            free(msg);
            return 2;
        }
        memcpy(msg + pos, ip, len);
        pos += len;
        msg[pos++] = '\n';
    }
    memcpy(msg + pos, "END\n", sizeof("END\n"));

    int ret = send_and_print(msg);
    free(msg);
    return ret;
}


int main(int argc, char *argv[]) {
    if (argc < 2) usage();

    FirewallConfig config = {0};
    if (parse_config(CONFIG_PATH, &config) != 0) {
        fprintf(stderr, "failed\nFirewall config file parsing failed\n");
        free_config(&config);
        return EXIT_FAILURE;
    }

    if (strncmp(argv[1], "START_FW", strlen("START_FW")) == 0) {
        if (argc != 4) usage();

        // Update the configuration
        free(config.dev);
        free(config.attach_mode);
        config.dev = strdup(argv[2]);
        config.attach_mode = strdup(argv[3]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }

        int ret = system(FIREWALL_START);
        if (ret == 0) {
            printf("ok\nsuccess\n");
        } else {
            fprintf(stderr, "failed\n%s\n", strerror(errno));
        }
        return EXIT_SUCCESS;
    } else if (strncmp(argv[1], "STOP_FW", strlen("STOP_FW")) == 0) {
        if (argc != 4) usage();
        int ret = system(FIREWALL_STOP);
        if (ret == 0) {
            char command[1024];
            snprintf(command, 1024, "xdp-loader unload --all %s", argv[2]);
            system(command);
            printf("ok\nsuccess\n");
        } else {
            fprintf(stderr, "failed\n%s\n", strerror(errno));
        }
        return EXIT_SUCCESS;
    } else if (strncmp(argv[1], "RESTART_FW", strlen("RESTART_FW")) == 0) {
        if (argc != 4) usage();

        // Update the configuration
        free(config.dev);
        free(config.attach_mode);
        config.dev = strdup(argv[2]);
        config.attach_mode = strdup(argv[3]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }

        int ret = system(FIREWALL_RESTART);
        if (ret == 0) {
            printf("ok\nsuccess\n");
        } else {
            fprintf(stderr, "failed\n %s\n", strerror(errno));
        }
        return EXIT_SUCCESS;
    } else if (strncmp(argv[1], "TCP_SYN", strlen("TCP_SYN")) == 0) {
        if (argc != 10) usage();

        // Update the configuration
        //argv[2] tcp_syn set or not

        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;

        config.syn_valid = valid;
        config.syn_threshold = atoi(argv[3]);
        config.syn_burst_pkt = atoi(argv[4]);
        config.syn_burst_count_per_sec = atoi(argv[5]);
        config.syn_fixed_threshold = atoi(argv[6]);
        config.syn_fixed_check_duration = atoi(argv[7]);
        config.challenge_timeout = atoi(argv[8]);
        config.syn_protection_duration = atoi(argv[9]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "TCP_ACK", strlen("TCP_ACK")) == 0) {
        if (argc != 9) usage();

        // Update the configuration
        //argv[2] tcp_ack set or not
        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.ack_valid = valid;
        config.ack_threshold = atoi(argv[3]);
        config.ack_burst_pkt = atoi(argv[4]);
        config.ack_burst_count_per_sec = atoi(argv[5]);
        config.ack_fixed_threshold = atoi(argv[6]);
        config.ack_fixed_check_duration = atoi(argv[7]);
        config.ack_protection_duration = atoi(argv[8]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "TCP_RST", strlen("TCP_RST")) == 0) {
        if (argc != 9) usage();

        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.rst_valid = valid;
        config.rst_threshold = atoi(argv[3]);
        config.rst_burst_pkt = atoi(argv[4]);
        config.rst_burst_count_per_sec = atoi(argv[5]);
        config.rst_fixed_threshold = atoi(argv[6]);
        config.rst_fixed_check_duration = atoi(argv[7]);
        config.rst_protection_duration = atoi(argv[8]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "TCP_STOMP", strlen("TCP_STOMP")) == 0) {
        if (argc != 9) usage();

        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.stomp_valid = valid;
        config.stomp_threshold = atoi(argv[3]);
        config.stomp_burst_pkt = atoi(argv[4]);
        config.stomp_burst_count_per_sec = atoi(argv[5]);
        config.stomp_fixed_threshold = atoi(argv[6]);
        config.stomp_fixed_check_duration = atoi(argv[7]);
        config.stomp_protection_duration = atoi(argv[8]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "TCP_SOCKET", strlen("TCP_SOCKET")) == 0) {
        if (argc != 6) usage();

        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.socket_valid = valid;
        config.socket_fin_threshold = atoi(argv[3]);
        config.socket_fixed_threshold = atoi(argv[4]);
        config.socket_fixed_check_duration = atoi(argv[5]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "ICMP", strlen("ICMP")) == 0) {
        if (argc != 9) usage();

        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.icmp_valid = valid;
        config.icmp_threshold = atoi(argv[3]);
        config.icmp_burst_pkt = atoi(argv[4]);
        config.icmp_burst_count_per_sec = atoi(argv[5]);
        config.icmp_fixed_threshold = atoi(argv[6]);
        config.icmp_fixed_check_duration = atoi(argv[7]);
        config.icmp_protection_duration = atoi(argv[8]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "UDP", strlen("UDP")) == 0) {
        if (argc != 9) usage();

        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.udp_valid = valid;
        config.udp_threshold = atoi(argv[3]);
        config.udp_burst_pkt = atoi(argv[4]);
        config.udp_burst_count_per_sec = atoi(argv[5]);
        config.udp_fixed_threshold = atoi(argv[6]);
        config.udp_fixed_check_duration = atoi(argv[7]);
        config.udp_protection_duration = atoi(argv[8]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "GRE", strlen("GRE")) == 0) {
        if (argc != 9) usage();

        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.gre_valid = valid;
        config.gre_threshold = atoi(argv[3]);
        config.gre_burst_pkt = atoi(argv[4]);
        config.gre_burst_count_per_sec = atoi(argv[5]);
        config.gre_fixed_threshold = atoi(argv[6]);
        config.gre_fixed_check_duration = atoi(argv[7]);
        config.gre_protection_duration = atoi(argv[8]);

        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "SET_TCP_SEG", strlen("SET_TCP_SEG")) == 0) {
        if (argc != 3) usage();

        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.tcp_seg_check = valid;
        
        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "SET_GEO", strlen("SET_GEO")) == 0) {
        if (argc != 4) usage();

        int valid = 0;
        if (strncmp(argv[2], "allow", 5) == 0) valid = 1;
        else if (strncmp(argv[2], "block", 5) == 0) valid = 2;
        else valid = 0;
        if (valid == 1) {
            if (config.geo_countries) free (config.geo_countries);
            config.geo_countries = strdup(argv[3]);
        } else if (valid == 2) {
            if (config.geo_countries) free (config.geo_countries);
            config.geo_countries = strdup(argv[3]);
        } else {
            if (config.geo_countries) free (config.geo_countries);
            config.geo_countries = NULL;
        }
        config.geo_check = valid;
        
        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    } else if (strncmp(argv[1], "SET_CONN_LIMIT", strlen("SET_CONN_LIMIT")) == 0) {
        if (argc != 4) usage();

        int valid = 0;
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.tcp_connection_limit_check = valid;
        config.tcp_connection_limit_cnt = atoi(argv[3]);
        
        if (write_config(CONFIG_PATH, &config) != 0) {
            fprintf(stderr, "failed\nFirewall config update failed\n");
            return EXIT_FAILURE;
        }
    }   

    if (strcmp(argv[1], "ADD_BLOCK_IPS") == 0)
        return send_bulk_block(argc, argv);

    /* Build the outgoing line */
    char line[BUF_SZ] = {0};
    size_t pos = 0;
    for (int i = 1; i < argc; ++i) {
        pos += snprintf(line + pos, sizeof line - pos, "%s%s",
                        i == 1 ? "" : " ", argv[i]);
        if (pos >= sizeof line - 2) { fputs("command too long\n", stderr); return 2; }
    }

    strcat(line, "\n");
    return send_and_print(line);
}