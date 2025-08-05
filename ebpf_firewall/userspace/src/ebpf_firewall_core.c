#include <ebpf_firewall_common.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_config.h>
#include <ebpf_firewall_conntrack.h>
#include <ebpf_firewall_geo.h>

#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <base64.h>

extern char token[128];             // Token used for expiration check
extern char ifname[IFNAMSIZ];       // Network interface name
extern __u32 attach_mode;           // Attach mode of ebpf
extern int n_cpus;                  // CPU count
extern __u64 time_offset_ns;        // Timeo offset ns
extern long tz_offset_sec;          // Timezone offset
extern char geo_db_ipv4_path[512];       // Geo Ipv4 block database path 
extern char geo_db_location_path[512]; // Geo location code database path

extern struct global_firewall_config global_fw_config;

struct stats_config global_receive_stats = {0};
struct stats_config global_passed_stats = {0};
struct fixed_ip_pkt_stats global_max_ip_pkt_stats = {0};

int exiting = 0;
char **process_argv = NULL;
struct bpf_object *obj;

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

static void * global_attack_check_worker(void * arg) {

    size_t vsize = sizeof(__u64) * n_cpus;
    __u64 *values = calloc(n_cpus, sizeof(__u64));

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

    while (!exiting) {
        __u32 key = 0;
        time_t now = time(NULL);     /* current epoch seconds */

        struct global_firewall_config g_fw_config = {0};
        if (bpf_map_lookup_elem(bss_map_fd, &key, &g_fw_config) != 0) {
            LOG_E("bpf_map_lookup_elem %s\n", strerror(errno));
            goto cleanup;
        }
        
        struct global_attack_stats * global_attack_stats_val =&g_fw_config.g_attack_stats;
        
        __u64 total_syn_cnt = 0;
        if (bpf_map_lookup_elem(global_syn_pkt_counter_map_fd, &key, values)) {
            LOG_E( "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_syn_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_syn_pkt_counter_map_fd, &key, values, 0)) {
            LOG_E( "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_ack_cnt = 0;
        if (bpf_map_lookup_elem(global_ack_pkt_counter_map_fd, &key, values)) {
            LOG_E( "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_ack_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_ack_pkt_counter_map_fd, &key, values, 0)) {
            LOG_E( "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_rst_cnt = 0;
        if (bpf_map_lookup_elem(global_rst_pkt_counter_map_fd, &key, values)) {
            LOG_E( "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_rst_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_rst_pkt_counter_map_fd, &key, values, 0)) {
            LOG_E( "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_icmp_cnt = 0;
        if (bpf_map_lookup_elem(global_icmp_pkt_counter_map_fd, &key, values)) {
            LOG_E( "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_icmp_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_icmp_pkt_counter_map_fd, &key, values, 0)) {
            LOG_E( "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_udp_cnt = 0;
        if (bpf_map_lookup_elem(global_udp_pkt_counter_map_fd, &key, values)) {
            LOG_E( "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_udp_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_udp_pkt_counter_map_fd, &key, values, 0)) {
            LOG_E( "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_gre_cnt = 0;
        if (bpf_map_lookup_elem(global_gre_pkt_counter_map_fd, &key, values)) {
            LOG_E( "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_gre_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_gre_pkt_counter_map_fd, &key, values, 0)) {
            LOG_E( "bpf_map_update_elem");
            goto cleanup;
        }


        struct bpf_map_info info = {};
        __u32 info_len = sizeof(info);

        if (bpf_obj_get_info_by_fd(income_stats_fd, &info, &info_len)) {
            LOG_E("bpf_obj_get_info_by_fd %s\n", strerror(errno));
            goto cleanup;
        }

        size_t elem_sz = info.value_size;

        void *raw = calloc(n_cpus, elem_sz);
        if (!raw) {
            goto cleanup;
        }

        struct stats_config aggregate = {0};
        if (bpf_map_lookup_elem(income_stats_fd, &key, raw)) {
            LOG_E( "bpf_map_lookup_elem");
            free(raw);
            goto cleanup;
        }

         for (int cpu = 0; cpu < n_cpus; cpu++) {
            struct stats_config *per_cpu_stats =
                (struct stats_config *)((char *)raw + cpu * elem_sz);
            aggregate.syn += per_cpu_stats->syn;
            aggregate.ack += per_cpu_stats->ack;
            aggregate.rst += per_cpu_stats->rst;
            aggregate.fin += per_cpu_stats->fin;
            aggregate.psh += per_cpu_stats->psh;
            aggregate.urg += per_cpu_stats->urg;

            aggregate.syn_ack += per_cpu_stats->syn_ack;
            aggregate.fin_ack += per_cpu_stats->fin_ack;
            aggregate.rst_ack += per_cpu_stats->rst_ack;

            aggregate.icmp += per_cpu_stats->icmp;
            aggregate.udp += per_cpu_stats->udp;
            aggregate.gre += per_cpu_stats->gre;
        }

        memset(raw, 0, n_cpus * elem_sz);
        if (bpf_map_update_elem(income_stats_fd, &key, raw, 0)) {
            LOG_E( "bpf_map_update_elem");
            free(raw);
            goto cleanup;
        }
        free(raw);

        time_t rawtime;
        struct tm *tm_info;
        time(&rawtime);
        tm_info = localtime(&rawtime);

        __u8 need_to_update = false;
        __u8 syn_attack = false, ack_attack = false, rst_attack = false, icmp_attack = false, udp_attack = false, gre_attack = false;

        if (total_syn_cnt >= global_fw_config.g_syn_config.syn_threshold) syn_attack = true;
        else syn_attack = false;
        if (syn_attack != global_attack_stats_val->syn_attack) {
            if (syn_attack == true) {
                if (now >= global_attack_stats_val->syn_protect_expire) {
                    global_attack_stats_val->syn_protect_expire = now + global_fw_config.g_syn_config.syn_protect_duration;
                    print_firewall_status(tm_info, EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START, 0);
                    global_attack_stats_val->syn_attack = syn_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->syn_protect_expire) {
                    print_firewall_status(tm_info, EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END, 0);
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
                    print_firewall_status(tm_info, EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START, 0);
                    global_attack_stats_val->ack_attack = ack_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->ack_protect_expire) {
                    print_firewall_status(tm_info, EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END, 0);
                    global_attack_stats_val->ack_attack = ack_attack;
                    need_to_update = true;
                }
            }
            global_attack_stats_val->ack_attack = ack_attack;
            need_to_update = true;
        }

        if (total_rst_cnt >= global_fw_config.g_rst_config.rst_threshold) rst_attack = true;
        else rst_attack = false;
        if (rst_attack != global_attack_stats_val->rst_attack) {
            if (rst_attack == true) {
                if (now >= global_attack_stats_val->rst_protect_expire) {
                    global_attack_stats_val->rst_protect_expire = now + global_fw_config.g_rst_config.rst_protect_duration;
                    print_firewall_status(tm_info, EVENT_TCP_RST_ATTACK_PROTECION_MODE_START, 0);
                    global_attack_stats_val->rst_attack = rst_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->rst_protect_expire) {
                    print_firewall_status(tm_info, EVENT_TCP_RST_ATTACK_PROTECION_MODE_END, 0);
                    global_attack_stats_val->rst_attack = rst_attack;
                    need_to_update = true;
                }
            }
            global_attack_stats_val->rst_attack = rst_attack;
            need_to_update = true;
        }

        if (total_icmp_cnt >= global_fw_config.g_icmp_config.icmp_threshold) icmp_attack = true;
        else icmp_attack = false;
        if (icmp_attack != global_attack_stats_val->icmp_attack) {
            if (icmp_attack == true) {
                if (now >= global_attack_stats_val->icmp_protect_expire) {
                    global_attack_stats_val->icmp_protect_expire = now + global_fw_config.g_icmp_config.icmp_protect_duration;
                    print_firewall_status(tm_info, EVENT_ICMP_ATTACK_PROTECION_MODE_START, 0);
                    global_attack_stats_val->icmp_attack = icmp_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->icmp_protect_expire) {
                    print_firewall_status(tm_info, EVENT_ICMP_ATTACK_PROTECION_MODE_END, 0);
                    global_attack_stats_val->icmp_attack = icmp_attack;
                    need_to_update = true;
                }
            }
            global_attack_stats_val->icmp_attack = icmp_attack;
            need_to_update = true;
        }

        if (total_udp_cnt >= global_fw_config.g_udp_config.udp_threshold) udp_attack = true;
        else udp_attack = false;
        if (udp_attack != global_attack_stats_val->udp_attack) {
            if (udp_attack == true) {
                if (now >= global_attack_stats_val->udp_protect_expire) {
                    global_attack_stats_val->udp_protect_expire = now + global_fw_config.g_udp_config.udp_protect_duration;
                    print_firewall_status(tm_info, EVENT_UDP_ATTACK_PROTECION_MODE_START, 0);
                    global_attack_stats_val->udp_attack = udp_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->udp_protect_expire) {
                    print_firewall_status(tm_info, EVENT_UDP_ATTACK_PROTECION_MODE_END, 0);
                    global_attack_stats_val->udp_attack = udp_attack;
                    need_to_update = true;
                }
            }
            global_attack_stats_val->udp_attack = udp_attack;
            need_to_update = true;
        }

        if (total_gre_cnt >= global_fw_config.g_gre_config.gre_threshold) gre_attack = true;
        else gre_attack = false;
        if (gre_attack != global_attack_stats_val->gre_attack) {
            if (gre_attack == true) {
                if (now >= global_attack_stats_val->gre_protect_expire) {
                    global_attack_stats_val->gre_protect_expire = now + global_fw_config.g_gre_config.gre_protect_duration;
                    print_firewall_status(tm_info, EVENT_GRE_ATTACK_PROTECION_MODE_START, 0);
                    global_attack_stats_val->gre_attack = gre_attack;
                    need_to_update = true;
                }
            } else {
                if (now >= global_attack_stats_val->gre_protect_expire) {
                    print_firewall_status(tm_info, EVENT_GRE_ATTACK_PROTECION_MODE_END, 0);
                    global_attack_stats_val->gre_attack = gre_attack;
                    need_to_update = true;
                }
            }
            global_attack_stats_val->gre_attack = gre_attack;
            need_to_update = true;
        }

        if (need_to_update == true) {
            bpf_map_update_elem(bss_map_fd, &key, &g_fw_config, BPF_ANY);
        }

        LOG_T("STATS: SYN:%llu/%llu ACK:%llu/%llu RST:%llu/%llu PSH:%llu FIN:%llu URG:%llu SYN+ACK:%llu FIN+ACK:%llu RST+ACK:%llu ICMP:%llu/%llu UDP:%llu/%llu GRE:%llu/%llu\n",
                aggregate.syn, total_syn_cnt,
                aggregate.ack, total_ack_cnt,
                aggregate.rst, total_rst_cnt,
                aggregate.psh,
                aggregate.fin,
                aggregate.urg,
				aggregate.syn_ack,
                aggregate.fin_ack,
                aggregate.rst_ack,
                aggregate.icmp, total_icmp_cnt,
                aggregate.udp, total_udp_cnt,
                aggregate.gre, total_gre_cnt);
        
        memcpy(&global_receive_stats, &aggregate, sizeof (struct stats_config));
        
        global_passed_stats.syn = total_syn_cnt;
        global_passed_stats.ack = total_ack_cnt;
        global_passed_stats.rst = total_rst_cnt;
        global_passed_stats.psh = aggregate.psh;
        global_passed_stats.fin = aggregate.fin;
        global_passed_stats.urg = aggregate.urg;
        global_passed_stats.syn_ack = aggregate.syn_ack;
        global_passed_stats.fin_ack = aggregate.fin_ack;
        global_passed_stats.rst_ack = aggregate.rst_ack;
        global_passed_stats.icmp = total_icmp_cnt;
        global_passed_stats.udp = total_udp_cnt;
        global_passed_stats.gre = total_gre_cnt;

        sleep (1);
    }

cleanup:
    if (values) free (values);
    return NULL;
}

static void *blocked_ips_duration_check_worker(void *arg) {
    struct bpf_object *obj = (struct bpf_object*)arg;
    if (!obj) goto cleanup;

    while (1) {
        int blocked_ips_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
        if (blocked_ips_fd < 0) {
            LOG_E( "Failed to find blocked_ips\n");
            goto cleanup;
        }

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
            print_firewall_status(tm_info, EVENT_IP_BLOCK_END, ip);
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

    print_firewall_status(&tm_info, e->reason, e->srcip);
    return 0;
}

char str_fixed_ip_ring_buf_type[256][128] = {
    "UNKNOWN", 
    "FIXED_IP_RING_BUF_SYN", 
    "FIXED_IP_RING_BUF_ACK", 
    "FIXED_IP_RING_BUF_RST", 
    "FIXED_IP_RING_BUF_PSH", 
    "FIXED_IP_RING_BUF_URG", 
    "FIXED_IP_RING_BUF_FIN",
    "FIXED_IP_RING_BUF_SYN_ACK", 
    "FIXED_IP_RING_BUF_RST_ACK", 
    "FIXED_IP_RING_BUF_FIN_ACK",
    "FIXED_IP_RING_BUF_UDP", 
    "FIXED_IP_RING_BUF_ICMP", 
    "FIXED_IP_RING_BUF_GRE"
};

static int fixed_ip_ringbuf_handle_event(void *ctx, void *data, size_t size)
{
    struct fixed_ip_event *e = data;

    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->srcip, src, sizeof(src));

    if (e->fixed_type >= 0 && e->fixed_type <= FIXED_IP_RING_BUF_GRE) {
        if (e->duration == 0) {
            LOG_E("Fixed checked duration is 0\n");
            return 0;
        }

        LOG_D("Received fixed ip ringbuf handle event [%d] duration is [%llu]s\n", e->over_fixed, (__u64)e->duration / ONE_SECOND_NS);

        
        __u64 expected_pps = 0;

        if (e->over_fixed == 0) {
            LOG_I("[NORMAL] %s %s %llu %llu pps\n", str_fixed_ip_ring_buf_type[e->fixed_type], src, e->pkt_count, (__u64)((double)e->pkt_count / ((double)((__u64)e->duration)/ ONE_SECOND_NS)));
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

            case FIXED_IP_RING_BUF_PSH:
            case FIXED_IP_RING_BUF_URG:
            case FIXED_IP_RING_BUF_FIN:
            case FIXED_IP_RING_BUF_SYN_ACK:
            case FIXED_IP_RING_BUF_RST_ACK:
            case FIXED_IP_RING_BUF_FIN_ACK:
            default: {
                expected_pps = (__u64)((double)global_fw_config.g_syn_config.syn_fixed_check_duration / e->duration * e->pkt_count / ((double)global_fw_config.g_syn_config.syn_fixed_check_duration / ONE_SECOND_NS));
                break;
            }
        }
        
        if (e->over_fixed == 1)
            LOG_A("[OVER FIXED] %s %s %llu pps\n", str_fixed_ip_ring_buf_type[e->fixed_type], src, expected_pps);

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

int main(int argc, char **argv) {
    
    int ifindex, err;
    struct bpf_program *prog_main, *prog_parse_syn, *prog_parse_ack, *prog_parse_rst, *prog_parse_icmp, *prog_parse_udp, *prog_parse_gre;
    int attach_id = -1, prog_main_fd, prog_parse_syn_fd, prog_parse_ack_fd, prog_parse_rst_fd, prog_parse_icmp_fd, prog_parse_udp_fd, prog_parse_gre_fd;
    int prog_array_map_fd;
    int tcp_established_map_fd, tcp_connection_map_fd, blocked_ips_map_fd;
    struct perf_buffer *pb = NULL;
    struct ring_buffer *ringbuf = NULL;
    struct ring_buffer *fixed_ip_ringbuf = NULL;

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
    
    // Load the BPF object into the kernel.
    err = bpf_object__load(obj);
    if (err) {
        LOG_E( "ERROR: loading BPF object file: %d\n", err);
        goto cleanup;
    }

    if (init_unix_socket() < 0) {
        LOG_E( "Failed to init unix socket\n");
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
    if (argc < 2) {
        LOG_E("Please input token : {usage : %s token}\n", argv[0]);
        return EXIT_FAILURE;
    }
    strcpy(token, argv[1]);

    int ret;
    ret = check_token();
    if (ret != 0) {
        LOG_E("Failed to check token so exit.\n");
        goto cleanup;
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
    
    // Get file descriptors for the programs.
    prog_main_fd = bpf_program__fd(prog_main);
    prog_parse_syn_fd = bpf_program__fd(prog_parse_syn);
    prog_parse_ack_fd = bpf_program__fd(prog_parse_ack);
    prog_parse_rst_fd = bpf_program__fd(prog_parse_rst);
    prog_parse_icmp_fd = bpf_program__fd(prog_parse_icmp);
    prog_parse_udp_fd = bpf_program__fd(prog_parse_udp);
    prog_parse_gre_fd = bpf_program__fd(prog_parse_gre);
    
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
    int key0 = 0, key1 = 1, key2 = 2, key3 = 3, key4 = 4, key5 = 5;
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
    
    // Attach the main XDP program to the interface.
    attach_id = bpf_xdp_attach(ifindex, prog_main_fd, attach_mode, NULL);
    if (attach_id < 0) {
        LOG_E( "ERROR: attaching XDP program to %s (ifindex %d) return %d, failed: %d\n", ifname, ifindex, attach_id, err);
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

    if (init_conntrack(tcp_established_map_fd, tcp_connection_map_fd, blocked_ips_map_fd) < 0) {
        LOG_E( "Failed to init conntrack\n");
        goto cleanup;
    }

    pthread_t global_attack_ch_thr, blocked_ips_duration_thr;
    if (pthread_create(&global_attack_ch_thr, NULL, global_attack_check_worker, obj) != 0) {
        LOG_E("pthread_create for global_attack_ch_thr %s\n", strerror(errno));
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
    if (ringbuf) ring_buffer__free(ringbuf);
    if (fixed_ip_ringbuf) ring_buffer__free(fixed_ip_ringbuf);
    if (obj) bpf_object__close(obj);
    if (attach_id >= 0) bpf_xdp_detach(ifindex, attach_mode, NULL);
    
    close_unix_socket();
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

    LOG_D("Successfully cleared geoip_trie_map\n");
    return 0;
}


static int clear_pkt_counter_map(int map_fd) {
    __u32 key = 0;
    __u64 *values = calloc(n_cpus, sizeof(__u64));

    if (values == NULL)
        goto error;

    if (bpf_map_lookup_elem(map_fd, &key, values)) {
        LOG_E( "bpf_map_lookup_elem");
        goto error;
    }
    for (int cpu = 0; cpu < n_cpus; cpu++) {
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
                int challenge_timeout)
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
    global_fw_config.g_syn_config.syn_fixed_check_duration = fixed_duration;
    global_fw_config.g_syn_config.challenge_timeout = challenge_timeout;
    global_fw_config.g_syn_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_syn_config.burst_count_threshold);
    //global_fw_config.g_syn_config.syn_protect_duration = ;

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
                int fixed_duration)
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
    global_fw_config.g_ack_config.ack_fixed_check_duration = fixed_duration;
    global_fw_config.g_ack_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_ack_config.burst_count_threshold);
    //global_fw_config.g_ack_config.ack_protect_duration = ;

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
                int fixed_duration)
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
    global_fw_config.g_rst_config.rst_fixed_check_duration = fixed_duration;
    global_fw_config.g_rst_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_rst_config.burst_count_threshold);
    //global_fw_config.g_rst_config.rst_protect_duration = ;

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
                int fixed_duration)
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
    global_fw_config.g_icmp_config.icmp_fixed_check_duration = fixed_duration;
    global_fw_config.g_icmp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_icmp_config.burst_count_threshold);
    //global_fw_config.g_icmp_config.icmp_protect_duration = ;

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
                int fixed_duration)
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
    global_fw_config.g_udp_config.udp_fixed_check_duration = fixed_duration;
    global_fw_config.g_udp_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_udp_config.burst_count_threshold);
    //global_fw_config.g_udp_config.udp_protect_duration = ;

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
                int fixed_duration)
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
    global_fw_config.g_gre_config.gre_fixed_check_duration = fixed_duration;
    global_fw_config.g_gre_config.burst_gap_ns = ONE_SECOND_NS / (global_fw_config.g_gre_config.burst_count_threshold);
    //global_fw_config.g_gre_config.gre_protect_duration = ;

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
    
    if (countries == NULL) {
        LOG_E( "Received countries is NULL\n");
        return -1;
    }

    LOG_D("Geo Set command is received (%d:%s)\n", valid, countries);
    
    if (map_fd < 0) {
        LOG_E( "ERROR: finding .bss map fd: %d\n", map_fd);
        return -1;
    }

    global_fw_config.g_geo_config.check = valid;

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
        LOG_E("bpf_map_update_elem");
        return -1;
    }
    
    return 0;
}
