#include <ebpf_firewall_common.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_core.h>

extern FILE* log_file;

extern struct global_firewall_config global_fw_config;

void func_print(int id, const char* fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    
    char output_fmt[8192];
    char buffer[10000];

    time_t currentTime = time(NULL);
    struct tm * timeInfo;
    timeInfo = localtime(&currentTime);

    if (timeInfo == NULL) {
        va_end (args);
        return;
    }
    
    char timeString[30];
    strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", timeInfo);

#ifdef COLOR_IS_ON
    switch (id) {
    case 1: 
    case 2: 
    case 3:
        snprintf(output_fmt, 8192, ANSI_COLOR_FG_REV_RED"[%s]   %s", timeString, fmt);
        break;
    case 4:
        snprintf(output_fmt, 8192, "%s[%s]   %s", ANSI_COLOR_FG_RED, timeString, fmt);
        break;
    case 5:
        snprintf(output_fmt, 8192, "%s[%s]   %s", ANSI_COLOR_FG_YELLOW, timeString, fmt);
        break;
    case 6:
        snprintf(output_fmt, 8192, "%s[%s]   %s", ANSI_COLOR_FG_MAGENTA, timeString, fmt);
        break;
    case 7:
        snprintf(output_fmt, 8192, "%s[%s]   %s", ANSI_COLOR_FG_BLUE, timeString, fmt);
        break;
    case 8:
        snprintf(output_fmt, 8192, ANSI_COLOR_FG_GREEN"[%s]   %s", timeString, fmt);
        break;
    case 9:
        snprintf(output_fmt, 8192, "%s[%s]   %s", ANSI_COLOR_FG_WHITE, timeString, fmt);
        break;
    }
#else
    snprintf(output_fmt, 8192, "[%s]   %s", timeString, fmt);
#endif

    // Print to stdout (screen)
    va_list args_copy;
    va_copy(args_copy, args); // Create a copy of args for the second use
    vprintf(output_fmt, args);
    va_end(args); // Original args is consumed

    // Log to file if open
    if (log_file) {
        vsnprintf(buffer, sizeof(buffer), output_fmt, args_copy); // Use the copy
        fprintf(log_file, "%s", buffer);
        fflush(log_file);
    }
    va_end(args_copy); // Clean up the copy
}


enum {
    ATTACK_SLOT_SYN = 0,
    ATTACK_SLOT_ACK,
    ATTACK_SLOT_RST,
    ATTACK_SLOT_ICMP,
    ATTACK_SLOT_UDP,
    ATTACK_SLOT_GRE,
    ATTACK_SLOT_STOMP,
    ATTACK_SLOT_HANDSHAKE,
    ATTACK_SLOT_COUNT
};

static __u64 attack_req_seq;

static int attack_slot_for_reason(int reason)
{
    switch (reason) {
    case EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_SYN_ATTACK_BURST_BLOCK:
    case EVENT_TCP_SYN_ATTACK_FIXED_BLOCK:
        return ATTACK_SLOT_SYN;
    case EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_ACK_ATTACK_BURST_BLOCK:
    case EVENT_TCP_ACK_ATTACK_FIXED_BLOCK:
        return ATTACK_SLOT_ACK;
    case EVENT_TCP_RST_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_RST_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_RST_ATTACK_BURST_BLOCK:
    case EVENT_TCP_RST_ATTACK_FIXED_BLOCK:
        return ATTACK_SLOT_RST;
    case EVENT_ICMP_ATTACK_PROTECION_MODE_START:
    case EVENT_ICMP_ATTACK_PROTECION_MODE_END:
    case EVENT_ICMP_ATTACK_BURST_BLOCK:
    case EVENT_ICMP_ATTACK_FIXED_BLOCK:
        return ATTACK_SLOT_ICMP;
    case EVENT_UDP_ATTACK_PROTECION_MODE_START:
    case EVENT_UDP_ATTACK_PROTECION_MODE_END:
    case EVENT_UDP_ATTACK_BURST_BLOCK:
    case EVENT_UDP_ATTACK_FIXED_BLOCK:
        return ATTACK_SLOT_UDP;
    case EVENT_GRE_ATTACK_PROTECION_MODE_START:
    case EVENT_GRE_ATTACK_PROTECION_MODE_END:
    case EVENT_GRE_ATTACK_BURST_BLOCK:
    case EVENT_GRE_ATTACK_FIXED_BLOCK:
        return ATTACK_SLOT_GRE;
    case EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_STOMP_ATTACK_BURST_BLOCK:
    case EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK:
        return ATTACK_SLOT_STOMP;
    case EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK:
    case EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK:
        return ATTACK_SLOT_HANDSHAKE;
    default:
        return -1;
    }
}

static int reason_starts_attack(int reason)
{
    return reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START
        || reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START
        || reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_START
        || reason == EVENT_ICMP_ATTACK_PROTECION_MODE_START
        || reason == EVENT_UDP_ATTACK_PROTECION_MODE_START
        || reason == EVENT_GRE_ATTACK_PROTECION_MODE_START
        || reason == EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_START
        || reason == EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_START;
}

static int reason_ends_attack(int reason)
{
    return reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END
        || reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END
        || reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_END
        || reason == EVENT_ICMP_ATTACK_PROTECION_MODE_END
        || reason == EVENT_UDP_ATTACK_PROTECION_MODE_END
        || reason == EVENT_GRE_ATTACK_PROTECION_MODE_END
        || reason == EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_END
        || reason == EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_END;
}

static __u64 *attack_req_id_field(int reason)
{
    switch (attack_slot_for_reason(reason)) {
    case ATTACK_SLOT_SYN: return &global_fw_config.g_attack_stats.syn_req_id;
    case ATTACK_SLOT_ACK: return &global_fw_config.g_attack_stats.ack_req_id;
    case ATTACK_SLOT_RST: return &global_fw_config.g_attack_stats.rst_req_id;
    case ATTACK_SLOT_ICMP: return &global_fw_config.g_attack_stats.icmp_req_id;
    case ATTACK_SLOT_UDP: return &global_fw_config.g_attack_stats.udp_req_id;
    case ATTACK_SLOT_GRE: return &global_fw_config.g_attack_stats.gre_req_id;
    case ATTACK_SLOT_STOMP: return &global_fw_config.g_attack_stats.stomp_req_id;
    case ATTACK_SLOT_HANDSHAKE: return &global_fw_config.g_attack_stats.handshake_req_id;
    default: return NULL;
    }
}

__u64 generate_attack_req_id(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    __u64 seq = __sync_add_and_fetch(&attack_req_seq, 1);
    __u64 id = ((__u64)ts.tv_sec << 20) | (seq & 0xFFFFFu);
    if (id == 0)
        id = 1;
    return id;
}

/* START allocates the episode id and stores it for the kernel. END reports it and clears it. */
static __u64 req_id_for_reason(int reason, __u64 supplied)
{
    if (supplied)
        return supplied;

    __u64 *field = attack_req_id_field(reason);
    if (!field)
        return 0;

    if (reason_starts_attack(reason)) {
        __u64 id = generate_attack_req_id();
        *field = id;
        return id;
    }

    if (reason_ends_attack(reason)) {
        __u64 id = *field;
        *field = 0;
        return id;
    }

    return *field;
}

static void append_req_id(char *temp, size_t temp_size, int reason, __u64 supplied)
{
    if (attack_slot_for_reason(reason) < 0 || temp[0] == '\0')
        return;

    __u64 req_id = req_id_for_reason(reason, supplied);
    size_t n = strlen(temp);
    if (n + 40 >= temp_size)
        return;
    if (n >= 2 && temp[n - 1] == '\n' && temp[n - 2] == '\n')
        n -= 1;
    snprintf(temp + n, temp_size - n, "req_id:%llu\n\n", (unsigned long long)req_id);
}

void build_block_ip_message(int reason, __u32 srcip, __u64 req_id, char * build_message, size_t build_message_size) {
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcip, src, sizeof(src));
    char temp[1024];
    temp[0] = '\0';

    time_t rawtime;
    struct tm tm_info;
    char time_buf[32];

    time(&rawtime);
    localtime_r(&rawtime, &tm_info);

    if (strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info) == 0) {
        strcpy(time_buf, "0000-00-00 00:00:00");
    }

#if 0
    if (reason == EVENT_IP_BLOCK_END) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_IP_BLOCK_END\n\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }
#endif
    if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_TCP_SYN_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_SYN_ATTACK_BURST_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_TCP_SYN_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_SYN_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_TCP_ACK_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_ACK_ATTACK_BURST_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_TCP_ACK_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_ACK_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    


    else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_RST_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_RST_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_TCP_RST_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_RST_ATTACK_BURST_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_TCP_RST_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_RST_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }



    else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_ICMP_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_ICMP_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_ICMP_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_ICMP_ATTACK_BURST_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_ICMP_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_ICMP_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }   


    else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_UDP_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_UDP_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_UDP_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_UDP_ATTACK_BURST_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_UDP_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_UDP_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }


    else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_GRE_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_GRE_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf); 
    }
    else if (reason == EVENT_GRE_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_GRE_ATTACK_BURST_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_GRE_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_GRE_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    
    else if (reason == EVENT_IP_FRAG_MIDDLE_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_IP_FRAG_MIDDLE_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }

    else if (reason == EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_TCP_STOMP_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_STOMP_ATTACK_BURST_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }

    else if (reason == EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }


    else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }   
    else if (reason == EVENT_TCP_CONNECTION_LIMIT_REACHED) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_CONNECTION_LIMIT_REACHED\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    //append_req_id(temp, sizeof(temp), reason, req_id);

    struct global_attack_stats * global_attack_stats_val =&global_fw_config.g_attack_stats;
    append_req_id(temp, sizeof(temp), reason, global_attack_stats_val->global_req_id);
    snprintf(build_message, build_message_size, "%s", temp);

    return;
}
//Use this function carefully!!!!

void print_firewall_status(struct tm * tm_info, int reason, __u32 srcip, __u64 req_id) {
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcip, src, sizeof(src));

    char build_message[1024];
    build_block_ip_message(reason, srcip, req_id, build_message, sizeof(build_message));
    send_message_to_api_parser(build_message);

    if (reason == EVENT_IP_BLOCK_END) {
        LOG_I("EVENT_IP_BLOCK_END %s\n", src);
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END) {
        LOG_I("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_TCP_SYN_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_TCP_SYN_ATTACK_BURST_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp syn attack burst mode");
    } else if (reason == EVENT_TCP_SYN_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_TCP_SYN_ATTACK_FIXED_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp syn attack burst mode");
    }
    else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_TCP_ACK_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_TCP_ACK_ATTACK_BURST_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp ack attack burst mode");
    } else if (reason == EVENT_TCP_ACK_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_TCP_ACK_ATTACK_FIXED_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp ack attack fixed threshold mode");
    }

    else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_TCP_RST_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_TCP_RST_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_TCP_RST_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_TCP_RST_ATTACK_BURST_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp rst attack burst mode");
    } else if (reason == EVENT_TCP_RST_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_TCP_RST_ATTACK_FIXED_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp rst attack fixed threshold mode");
    }

    else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_ICMP_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_ICMP_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_ICMP_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_ICMP_ATTACK_BURST_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in icmp attack burst mode");
    } else if (reason == EVENT_ICMP_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_ICMP_ATTACK_FIXED_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in icmp attack fixed threshold mode");
    }

    else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_UDP_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_UDP_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_UDP_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_UDP_ATTACK_BURST_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in udp attack burst mode");
    } else if (reason == EVENT_UDP_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_UDP_ATTACK_FIXED_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in udp attack fixed threshold mode");
    }

    else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_GRE_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_GRE_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_GRE_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_GRE_ATTACK_BURST_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in gre attack burst mode");
    } else if (reason == EVENT_GRE_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_GRE_ATTACK_FIXED_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in gre attack fixed threshold mode");
    }
    
    else if (reason == EVENT_IP_FRAG_MIDDLE_BLOCK) {
        LOG_C("EVENT_IP_FRAG_MIDDLE_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp segmentation");
    }
    else if (reason == EVENT_TCP_STOMP_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_TCP_STOMP_ATTACK_BURST_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp stomp attack burst mode");
    } else if (reason == EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp stomp attack fixed threshold mode");
    }   
    else if (reason == EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp socket attack fixed threshold mode");
    }
    else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp handshake attack burst mode");
    } else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK %s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp handshake attack fixed threshold mode");
    }
    else if (reason == EVENT_TCP_CONNECTION_LIMIT_REACHED) {
        LOG_C("EVENT_TCP_CONNECTION_LIMIT_REACHED %s\n", src);
        append_block_ip_to_sqlite(src, 0, "TCP connection limit reached");
    }
}