#include <ebpf_firewall_common.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_core.h>

extern FILE* log_file;

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

//Use this function carefully!!!!

void print_firewall_status(struct tm * tm_info, int reason, __u32 srcip) {

    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcip, src, sizeof(src));
    char temp[1024];

    if (reason == EVENT_IP_BLOCK_END) {
        LOG_C("EVENT_IP_BLOCK_END %s\n", src);
        snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is expired in blocklist\n", src);
        send_message_to_api_parser(temp);
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START\n");
        const char * message = "command:report_log\ntype:critical\ndata:TCP syn flooding attack is detected and proxy is in syn protection mode\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END\n");
        const char * message = "command:report_log\ntype:info\ndata:TCP syn flooding protection mode is finished!\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_TCP_SYN_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_TCP_SYN_ATTACK_BURST_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in syn busrst method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in tcp syn attack burst mode");
    } else if (reason == EVENT_TCP_SYN_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_TCP_SYN_ATTACK_FIXED_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in syn fixed threshold method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in tcp syn attack fixed threshold mode");
    }
    
    else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START\n");
        const char * message = "command:report_log\ntype:critical\ndata:TCP ack flooding attack is detected and proxy is in ack protection mode\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END\n");
        const char * message = "command:report_log\ntype:info\ndata:TCP ack flooding protection mode is finished!\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_TCP_ACK_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_TCP_ACK_ATTACK_BURST_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in ack busrst method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in tcp ack attack burst mode");
    } else if (reason == EVENT_TCP_ACK_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_TCP_ACK_ATTACK_FIXED_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in ack fixed threshold method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in tcp ack attack fixed threshold mode");
    }

    else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_TCP_RST_ATTACK_PROTECION_MODE_START\n");
        const char * message = "command:report_log\ntype:critical\ndata:TCP rst flooding attack is detected and proxy is in rst protection mode\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_TCP_RST_ATTACK_PROTECION_MODE_END\n");
        const char * message = "command:report_log\ntype:info\ndata:TCP rst flooding protection mode is finished!\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_TCP_RST_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_TCP_RST_ATTACK_BURST_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in rst busrst method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in tcp rst attack burst mode");
    } else if (reason == EVENT_TCP_RST_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_TCP_RST_ATTACK_FIXED_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in rst fixed threshold method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in tcp rst attack fixed threshold mode");
    }

    else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_ICMP_ATTACK_PROTECION_MODE_START\n");
        const char * message = "command:report_log\ntype:critical\ndata:ICMP flooding attack is detected and proxy is in icmp protection mode\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_ICMP_ATTACK_PROTECION_MODE_END\n");
        const char * message = "command:report_log\ntype:info\ndata:ICMP flooding protection mode is finished!\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_ICMP_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_ICMP_ATTACK_BURST_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in icmp busrst method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in icmp attack burst mode");
    } else if (reason == EVENT_ICMP_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_ICMP_ATTACK_FIXED_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in icmp fixed threshold method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in icmp attack fixed threshold mode");
    }

    else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_UDP_ATTACK_PROTECION_MODE_START\n");
        const char * message = "command:report_log\ntype:critical\ndata:UDP flooding attack is detected and proxy is in udp protection mode\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_UDP_ATTACK_PROTECION_MODE_END\n");
        const char * message = "command:report_log\ntype:info\ndata:UDP flooding protection mode is finished!\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_UDP_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_UDP_ATTACK_BURST_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in udp busrst method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in udp attack burst mode");
    } else if (reason == EVENT_UDP_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_UDP_ATTACK_FIXED_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in udp fixed threshold method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in udp attack fixed threshold mode");
    }

    else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_START) {
        LOG_C("EVENT_GRE_ATTACK_PROTECION_MODE_START\n");
        const char * message = "command:report_log\ntype:critical\ndata:GRE flooding attack is detected and proxy is in gre protection mode\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_END) {
        LOG_C("EVENT_GRE_ATTACK_PROTECION_MODE_END\n");
        const char * message = "command:report_log\ntype:info\ndata:GRE flooding protection mode is finished!\n";
        send_message_to_api_parser(message);
    } else if (reason == EVENT_GRE_ATTACK_BURST_BLOCK) {
        LOG_C("EVENT_GRE_ATTACK_BURST_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in gre busrst method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in gre attack burst mode");
    } else if (reason == EVENT_GRE_ATTACK_FIXED_BLOCK) {
        LOG_C("EVENT_GRE_ATTACK_FIXED_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:info\ndata:%s is attacking in gre fixed threshold method\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in gre attack fixed threshold mode");
    }
    
    else if (reason == EVENT_IP_FRAG_MIDDLE_BLOCK) {
        LOG_C("EVENT_IP_FRAG_MIDDLE_BLOCK %s\n", src);
        //snprintf(temp, 1024, "command:report_log\ntype:critical\ndata:TCP segmentation attack is detected for %s\n", src);
        //send_message_to_api_parser(temp);
        append_block_ip_to_sqlite(src, "Attacking in tcp segmentation");
    }
}