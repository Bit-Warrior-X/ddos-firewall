#include <ebpf_firewall_common.h>
#include <ebpf_firewall_config.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_geo.h>
#include <ebpf_firewall_core.h>

#include <stdio.h>
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

struct global_firewall_config global_fw_config ={
    .g_attack_stats = {0},
    .g_config = {0},
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
        .check = 0
    },
    .g_tcp_connection_config = {
        .check = 0,
        .limit_cnt = 0
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

// Callback function for blocked_ips
int blocked_ips_callback(void *param_obj, int argc, char **argv, char **azColName) {
    struct bpf_object *obj = (struct bpf_object *)param_obj;
    
    LOG_D("Blocked IP Record:\n");

    __u32 ip = 0, duration = 0;
    __u64 created = 0;

    for(int i = 0; i < argc; i++) {
        LOG_D("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
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
    }

    if (ip != 0) {
        LOG_D("ip = %X, duration = %d, created = %ld\n", ip, duration, created);
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

            if (created + duration <= current_epoch) return 0;
            __u64 seconds =  created + duration - current_epoch;
            if (seconds < 0) return 0;
            
            LOG_D("expect seconds is %d\n", seconds);

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
    
    LOG_D("Whitelisted IP Record:\n");
     __u32 ip = 0;
    __u64 created = 0;

    for(int i = 0; i < argc; i++) {
        LOG_D("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
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
        LOG_D("ip = %X created = %ld\n", ip, created);
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
    
    // Open database connection
    rc = sqlite3_open(SQLITE_DB_NAME, &db);
    
    if (rc != SQLITE_OK) {
        LOG_E("Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // Read from blocked_ips table
    char *sql_blocked = "SELECT * FROM blocked_ips;";
    
    LOG_D("Reading blocked IPs...\n");
    rc = sqlite3_exec(db, sql_blocked, blocked_ips_callback, obj, &err_msg);
    
    if (rc != SQLITE_OK) {
        LOG_E("SQL error (blocked_ips): %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    
    // Read from white_ips table
    char *sql_white = "SELECT * FROM white_ips;";
    
    LOG_D("Reading whitelisted IPs...\n");
    rc = sqlite3_exec(db, sql_white, white_ips_callback, obj, &err_msg);
    
    if (rc != SQLITE_OK) {
        LOG_E("SQL error (white_ips): %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    
    // Close database connection
    sqlite3_close(db);
    
    return 0;
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
                if (str_value[0] == '/' || str_value[0] == '\\') {
                    strcpy(log_path, str_value);
                    if (log_file) fclose(log_file);
                    log_file = fopen(log_path, "a");
                }
                LOG_I("Loaded config: %s = %s\n", key, log_path);
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
                if (strcmp(str_value, "skb") == 0)
                    attach_mode = XDP_FLAGS_SKB_MODE;
                else if (strcmp(str_value, "native") == 0)
                    attach_mode = 0;
                else if (strcmp(str_value, "drv") == 0)
                    attach_mode = XDP_FLAGS_DRV_MODE;
                else if (strcmp(str_value, "hw") == 0)
                    attach_mode = XDP_FLAGS_HW_MODE;
                else {
                    LOG_E("Unkown attach_mode\n");
                    return -1;
                }
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
            if (strcmp(key, "geo_allow_countries") == 0) {
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
        }

        // Try to parse as key=integer
        if (sscanf(line, "%127[^=]= %d", key, &int_value) == 2) {
            trim_whitespace(key);
            
            LOG_I("Loaded config: %s = %d\n", key, int_value);
            
            // Global config
            if (strcmp(key, "black_ip_duration") == 0) {
                global_fw_config.g_config.black_ip_duration = int_value * ONE_SECOND_NS;
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
            //TCP segment
            else if (strcmp(key, "tcp_seg_check") == 0) {
                global_fw_config.g_config.tcp_seg_check = int_value;
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

            else {
                LOG_E("Unkown %s directive\n", key);
                return -1;
            }
        }
    }
    fclose(fp);
    
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

    // Calculate burst gap
    global_fw_config.g_syn_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_syn_config.burst_count_threshold);
    global_fw_config.g_ack_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_ack_config.burst_count_threshold);
    global_fw_config.g_rst_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_rst_config.burst_count_threshold);
    global_fw_config.g_icmp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_icmp_config.burst_count_threshold);
    global_fw_config.g_udp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_udp_config.burst_count_threshold);
    global_fw_config.g_gre_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_gre_config.burst_count_threshold);

    int key = 0;
    
    int map_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    if(bpf_map_update_elem(map_fd, &key, &global_fw_config, BPF_ANY)) {
        LOG_E("bpf_map_update_elem");
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
    }

    if (load_block_white_list(obj) < 0) {
        LOG_E("Failed to load white/block list ips from sqlite db");
        return -1;
    }

    LOG_I("Setup config success\n");

    return 0;
}
