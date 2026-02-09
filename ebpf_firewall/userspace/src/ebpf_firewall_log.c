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


void build_block_ip_message(int reason, __u32 srcip, char * build_message, size_t build_message_size) {
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcip, src, sizeof(src));
    char temp[1024];

    if (reason == EVENT_IP_BLOCK_END) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_IP_BLOCK_END\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }

    else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START\n"); 
    }
    else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END\n"); 
    }
    else if (reason == EVENT_TCP_SYN_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_SYN_ATTACK_BURST_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }
    else if (reason == EVENT_TCP_SYN_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_SYN_ATTACK_FIXED_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }




    else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START\n"); 
    }
    else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END\n"); 
    }
    else if (reason == EVENT_TCP_ACK_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_ACK_ATTACK_BURST_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }
    else if (reason == EVENT_TCP_ACK_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_ACK_ATTACK_FIXED_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }
    


    else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_RST_ATTACK_PROTECION_MODE_START\n"); 
    }
    else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_TCP_RST_ATTACK_PROTECION_MODE_END\n"); 
    }
    else if (reason == EVENT_TCP_RST_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_RST_ATTACK_BURST_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }
    else if (reason == EVENT_TCP_RST_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_RST_ATTACK_FIXED_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }



    else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_ICMP_ATTACK_PROTECION_MODE_START\n"); 
    }
    else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_ICMP_ATTACK_PROTECION_MODE_END\n"); 
    }
    else if (reason == EVENT_ICMP_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_ICMP_ATTACK_BURST_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }
    else if (reason == EVENT_ICMP_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_ICMP_ATTACK_FIXED_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }   


    else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_UDP_ATTACK_PROTECION_MODE_START\n"); 
    }
    else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_UDP_ATTACK_PROTECION_MODE_END\n"); 
    }
    else if (reason == EVENT_UDP_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_UDP_ATTACK_BURST_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }
    else if (reason == EVENT_UDP_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_UDP_ATTACK_FIXED_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }


    else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_GRE_ATTACK_PROTECION_MODE_START\n"); 
    }
    else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, 1024,    "command:report_protection\n"
                                "data:EVENT_GRE_ATTACK_PROTECION_MODE_END\n"); 
    }
    else if (reason == EVENT_GRE_ATTACK_BURST_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_GRE_ATTACK_BURST_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }
    else if (reason == EVENT_GRE_ATTACK_FIXED_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_GRE_ATTACK_FIXED_BLOCK\n",
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }
    
    else if (reason == EVENT_IP_FRAG_MIDDLE_BLOCK) {
        snprintf(temp, 1024,    "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_IP_FRAG_MIDDLE_BLOCK\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS); 
    }

    strncpy(build_message, temp, build_message_size - 1);
    build_message[build_message_size - 1] = '\0';
    return;
}
//Use this function carefully!!!!

void print_firewall_status(struct tm * tm_info, int reason, __u32 srcip) {
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcip, src, sizeof(src));

    char build_message[1024];
    build_block_ip_message(reason, srcip, build_message, sizeof(build_message));
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
}