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
#define CONFIG_PATH "/usr/local/share/ebpf_firewall/firewall.config"
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
"  ICMP <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> : Set icmp parameters.\n"
"  UDP <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> : Set udp parameters.\n"
"  GRE <status> <threshold> <burst_pkt> <burst_counter> <fixed_threshold> <fixed_duration> : Set gre parameters.\n"
"  SET_TCP_SEG <status> : Set tcp segment status parameters.\n"
"  CLEAR_FW : Clear all packet statistics. (Reset all statistics as zero).\n"
"  STATS_FW : Display all packet information captured. (SYN, ACK, RST, PSH, FIN, URG, SYN+ACK, FIN+ACK, RST+ACK, ICMP UDP, GRE)\n"
"  LIST_BLOCK_IP : Dump current blacklist ip. (ip expire_ns per line)\n"
"  CLEAR_BLOCK_IP <ip> : Remove ip from blacklist\n"
"  CLEAR_BLOCK_IP_ALL : Remove all ips from blacklist\n"
"  ADD_BLOCK_IP <ip> [seconds] : Add ip to blacklist. Default duration if seconds omitted.\n"
"  LIST_ALLOW_IP : Dump whitelist ip list\n"
"  CLEAR_ALLOW_IP <ip> : Remove ip from whitelist\n"
"  CLEAR_ALLOW_IP_ALL : Remove all ips from blacklist\n"
"  ADD_ALLOW_IP <ip> : Add ip to whitelist.\n"
"  HEALTH_CHECK : Check the health status of ebpf-firewall\n"
"  GET_BLOCKLIST <filter_type> <filter_ip> <filter_date> : Get the filtered block list ips\n"
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
    char *geo_allow_countries;
    
    // TCP Connection Limit
    int tcp_connection_limit_check;
    int tcp_connection_limit_cnt;
    
    // Comments and section headers
    char global_comment[MAX_COMMENT_LENGTH];
    char syn_comment[MAX_COMMENT_LENGTH];
    char ack_comment[MAX_COMMENT_LENGTH];
    char rst_comment[MAX_COMMENT_LENGTH];
    char icmp_comment[MAX_COMMENT_LENGTH];
    char udp_comment[MAX_COMMENT_LENGTH];
    char gre_comment[MAX_COMMENT_LENGTH];
    char tcp_seg_comment[MAX_COMMENT_LENGTH];
    char geo_comment[MAX_COMMENT_LENGTH];
    char tcp_conn_comment[MAX_COMMENT_LENGTH];
} FirewallConfig;

void free_config(FirewallConfig *config) {
    if (config->log_path) free(config->log_path);
    if (config->dev) free(config->dev);
    if (config->attach_mode) free(config->attach_mode);
    if (config->geo_db_ipv4_path) free(config->geo_db_ipv4_path);
    if (config->geo_db_location_path) free(config->geo_db_location_path);
    if (config->geo_allow_countries) free(config->geo_allow_countries);
}

int parse_config(const char *filename, FirewallConfig *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open config file");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    char current_section[MAX_COMMENT_LENGTH] = {0};
    
    while (fgets(line, sizeof(line), file)) {
        // Trim trailing newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip empty lines
        if (line[0] == '\0') continue;
        
        // Check for section headers
        if (strstr(line, "GLOBAL") != NULL) {
            strncpy(config->global_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "GLOBAL");
            continue;
        } else if (strstr(line, "SYN") != NULL) {
            strncpy(config->syn_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "SYN");
            continue;
        } else if (strstr(line, "ACK") != NULL) {
            strncpy(config->ack_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "ACK");
            continue;
        } else if (strstr(line, "RST") != NULL) {
            strncpy(config->rst_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "RST");
            continue;
        } else if (strstr(line, "ICMP") != NULL) {
            strncpy(config->icmp_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "ICMP");
            continue;
        } else if (strstr(line, "UDP") != NULL) {
            strncpy(config->udp_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "UDP");
            continue;
        } else if (strstr(line, "GRE") != NULL) {
            strncpy(config->gre_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "GRE");
            continue;
        } else if (strstr(line, "TCP Segment check") != NULL) {
            strncpy(config->tcp_seg_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "TCP_SEG");
            continue;
        } else if (strstr(line, "Geo Location Check") != NULL) {
            strncpy(config->geo_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "GEO");
            continue;
        } else if (strstr(line, "TCP Connection Limit") != NULL) {
            strncpy(config->tcp_conn_comment, line, MAX_COMMENT_LENGTH);
            strcpy(current_section, "TCP_CONN");
            continue;
        }
        
        // Skip comments
        if (line[0] == '#') continue;
        
        // Parse key-value pairs
        char *key = strtok(line, " =");
        char *value = strtok(NULL, " =\n");
        
        if (!key || !value) continue;
        
        if (strcmp(current_section, "GLOBAL") == 0) {
            if (strcmp(key, "log") == 0) {
                config->log_path = strdup(value);
            } else if (strcmp(key, "dev") == 0) {
                config->dev = strdup(value);
            } else if (strcmp(key, "attach_mode") == 0) {
                config->attach_mode = strdup(value);
            } else if (strcmp(key, "black_ip_duration") == 0) {
                config->black_ip_duration = atoi(value);
            }
        }
        else if (strcmp(current_section, "SYN") == 0) {
            if (strcmp(key, "syn_valid") == 0) {
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
            }
        }
        else if (strcmp(current_section, "ACK") == 0) {
            if (strcmp(key, "ack_valid") == 0) {
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
            }
        }
        else if (strcmp(current_section, "RST") == 0) {
            if (strcmp(key, "rst_valid") == 0) {
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
            }
        }
        else if (strcmp(current_section, "ICMP") == 0) {
            if (strcmp(key, "icmp_valid") == 0) {
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
            }
        }
        else if (strcmp(current_section, "UDP") == 0) {
            if (strcmp(key, "udp_valid") == 0) {
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
            }
        }
        else if (strcmp(current_section, "GRE") == 0) {
            if (strcmp(key, "gre_valid") == 0) {
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
            }
        }
        else if (strcmp(current_section, "TCP_SEG") == 0) {
            if (strcmp(key, "tcp_seg_check") == 0) {
                config->tcp_seg_check = atoi(value);
            }
        }
        else if (strcmp(current_section, "GEO") == 0) {
            if (strcmp(key, "geo_check") == 0) {
                config->geo_check = atoi(value);
            } else if (strcmp(key, "geo_db_ipv4_path") == 0) {
                config->geo_db_ipv4_path = strdup(value);
            } else if (strcmp(key, "geo_db_location_path") == 0) {
                config->geo_db_location_path = strdup(value);
            } else if (strcmp(key, "geo_allow_countries") == 0) {
                config->geo_allow_countries = strdup(value);
            }
        }
        else if (strcmp(current_section, "TCP_CONN") == 0) {
            if (strcmp(key, "tcp_connection_limit_check") == 0) {
                config->tcp_connection_limit_check = atoi(value);
            } else if (strcmp(key, "tcp_connection_limit_cnt") == 0) {
                config->tcp_connection_limit_cnt = atoi(value);
            }
        }
    }

    fclose(file);
    return 0;
}

int write_config(const char *filename, const FirewallConfig *config) {
    char temp_filename[] = TEMP_FILE_TEMPLATE;
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        perror("Failed to create temporary file");
        return -1;
    }

    FILE *file = fdopen(fd, "w");
    if (!file) {
        perror("Failed to open temporary file");
        close(fd);
        unlink(temp_filename);
        return -1;
    }

    // Write GLOBAL section
    fprintf(file, "%s\n", config->global_comment);
    fprintf(file, "log = %s\n", config->log_path);
    fprintf(file, "dev = %s\n", config->dev);
    fprintf(file, "# mode can be skb, native, drv, hw\n");
    fprintf(file, "attach_mode = %s\n", config->attach_mode);
    fprintf(file, "black_ip_duration = %d\n", config->black_ip_duration);
    
    // Write SYN section
    fprintf(file, "%s\n", config->syn_comment);
    fprintf(file, "syn_valid = %d\n", config->syn_valid);
    fprintf(file, "syn_threshold = %d\n", config->syn_threshold);
    fprintf(file, "syn_burst_pkt = %d\n", config->syn_burst_pkt);
    fprintf(file, "syn_burst_count_per_sec = %d\n", config->syn_burst_count_per_sec);
    fprintf(file, "syn_fixed_threshold = %d\n", config->syn_fixed_threshold);
    fprintf(file, "syn_fixed_check_duration = %d\n", config->syn_fixed_check_duration);
    fprintf(file, "challenge_timeout = %d\n", config->challenge_timeout);
    fprintf(file, "syn_protection_duration = %d\n", config->syn_protection_duration);
    
    // Write ACK section
    fprintf(file, "%s\n", config->ack_comment);
    fprintf(file, "ack_valid = %d\n", config->ack_valid);
    fprintf(file, "ack_threshold = %d\n", config->ack_threshold);
    fprintf(file, "ack_burst_pkt = %d\n", config->ack_burst_pkt);
    fprintf(file, "ack_burst_count_per_sec = %d\n", config->ack_burst_count_per_sec);
    fprintf(file, "ack_fixed_threshold = %d\n", config->ack_fixed_threshold);
    fprintf(file, "ack_fixed_check_duration = %d\n", config->ack_fixed_check_duration);
    fprintf(file, "ack_protection_duration = %d\n", config->ack_protection_duration);
    
    // Write RST section
    fprintf(file, "%s\n", config->rst_comment);
    fprintf(file, "rst_valid = %d\n", config->rst_valid);
    fprintf(file, "rst_threshold = %d\n", config->rst_threshold);
    fprintf(file, "rst_burst_pkt = %d\n", config->rst_burst_pkt);
    fprintf(file, "rst_burst_count_per_sec = %d\n", config->rst_burst_count_per_sec);
    fprintf(file, "rst_fixed_threshold = %d\n", config->rst_fixed_threshold);
    fprintf(file, "rst_fixed_check_duration = %d\n", config->rst_fixed_check_duration);
    fprintf(file, "rst_protection_duration = %d\n", config->rst_protection_duration);
    
    // Write ICMP section
    fprintf(file, "%s\n", config->icmp_comment);
    fprintf(file, "icmp_valid = %d\n", config->icmp_valid);
    fprintf(file, "icmp_threshold = %d\n", config->icmp_threshold);
    fprintf(file, "icmp_burst_pkt = %d\n", config->icmp_burst_pkt);
    fprintf(file, "icmp_burst_count_per_sec = %d\n", config->icmp_burst_count_per_sec);
    fprintf(file, "icmp_fixed_threshold = %d\n", config->icmp_fixed_threshold);
    fprintf(file, "icmp_fixed_check_duration = %d\n", config->icmp_fixed_check_duration);
    fprintf(file, "icmp_protection_duration = %d\n", config->icmp_protection_duration);
    
    // Write UDP section
    fprintf(file, "%s\n", config->udp_comment);
    fprintf(file, "udp_valid = %d\n", config->udp_valid);
    fprintf(file, "udp_threshold = %d\n", config->udp_threshold);
    fprintf(file, "udp_burst_pkt = %d\n", config->udp_burst_pkt);
    fprintf(file, "udp_burst_count_per_sec = %d\n", config->udp_burst_count_per_sec);
    fprintf(file, "udp_fixed_threshold = %d\n", config->udp_fixed_threshold);
    fprintf(file, "udp_fixed_check_duration = %d\n", config->udp_fixed_check_duration);
    fprintf(file, "udp_protection_duration = %d\n", config->udp_protection_duration);
    
    // Write GRE section
    fprintf(file, "%s\n", config->gre_comment);
    fprintf(file, "gre_valid = %d\n", config->gre_valid);
    fprintf(file, "gre_threshold = %d\n", config->gre_threshold);
    fprintf(file, "gre_burst_pkt = %d\n", config->gre_burst_pkt);
    fprintf(file, "gre_burst_count_per_sec = %d\n", config->gre_burst_count_per_sec);
    fprintf(file, "gre_fixed_threshold = %d\n", config->gre_fixed_threshold);
    fprintf(file, "gre_fixed_check_duration = %d\n", config->gre_fixed_check_duration);
    fprintf(file, "gre_protection_duration = %d\n", config->gre_protection_duration);
    
    // Write TCP Segment check
    fprintf(file, "\n%s\n", config->tcp_seg_comment);
    fprintf(file, "tcp_seg_check = %d\n", config->tcp_seg_check);

    // Write Geo Location Check
    fprintf(file, "\n%s\n", config->geo_comment);
    fprintf(file, "geo_check = %d\n", config->geo_check);
    fprintf(file, "geo_db_ipv4_path = %s\n", config->geo_db_ipv4_path);
    fprintf(file, "geo_db_location_path = %s\n", config->geo_db_location_path);
    fprintf(file, "geo_allow_countries = %s\n", config->geo_allow_countries);
    
    // Write TCP Connection Limit
    fprintf(file, "\n%s\n", config->tcp_conn_comment);
    fprintf(file, "tcp_connection_limit_check = %d\n", config->tcp_connection_limit_check);
    fprintf(file, "tcp_connection_limit_cnt = %d\n", config->tcp_connection_limit_cnt);
    
    fprintf(file, "\n");

    fclose(file);

    // Replace the original file with the new one
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
        if (strncmp(argv[2], "on", 2) == 0) valid = 1;
        else valid = 0;
        config.geo_check = valid;
        if (config.geo_allow_countries) free (config.geo_allow_countries);
        config.geo_allow_countries = strdup(argv[3]);
        
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