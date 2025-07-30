#include <ebpf_firewall_common.h>
#include <ebpf_firewall_log.h>

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

void print_firewall_status(struct tm * tm_info, int reason, __u32 srcip) {

    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcip, src, sizeof(src));

#if 0
    char buffer[26];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    // Print the timestamp only once at the beginning
    printf("%s    ", buffer);
#endif

    if (reason == EVENT_IP_BLOCK_END) {
        LOG_A("EVENT_IP_BLOCK_END %s\n", src);
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START) {
        LOG_A("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END) {
        LOG_A("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_TCP_SYN_ATTACK_BURST_BLOCK) {
        LOG_A("EVENT_TCP_SYN_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_TCP_SYN_ATTACK_FIXED_BLOCK) {
        LOG_A("EVENT_TCP_SYN_ATTACK_FIXED_BLOCK %s\n", src);
    }
    
    else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START) {
        LOG_A("EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END) {
        LOG_A("EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_TCP_ACK_ATTACK_BURST_BLOCK) {
        LOG_A("EVENT_TCP_ACK_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_TCP_ACK_ATTACK_FIXED_BLOCK) {
        LOG_A("EVENT_TCP_ACK_ATTACK_FIXED_BLOCK %s\n", src);
    }

    else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_START) {
        LOG_A("EVENT_TCP_RST_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_END) {
        LOG_A("EVENT_TCP_RST_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_TCP_RST_ATTACK_BURST_BLOCK) {
        LOG_A("EVENT_TCP_RST_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_TCP_RST_ATTACK_FIXED_BLOCK) {
        LOG_A("EVENT_TCP_RST_ATTACK_FIXED_BLOCK %s\n", src);
    }

    else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_START) {
        LOG_A("EVENT_ICMP_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_END) {
        LOG_A("EVENT_ICMP_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_ICMP_ATTACK_BURST_BLOCK) {
        LOG_A("EVENT_ICMP_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_ICMP_ATTACK_FIXED_BLOCK) {
        LOG_A("EVENT_ICMP_ATTACK_FIXED_BLOCK %s\n", src);
    }

    else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_START) {
        LOG_A("EVENT_UDP_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_END) {
        LOG_A("EVENT_UDP_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_UDP_ATTACK_BURST_BLOCK) {
        LOG_A("EVENT_UDP_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_UDP_ATTACK_FIXED_BLOCK) {
        LOG_A("EVENT_UDP_ATTACK_FIXED_BLOCK %s\n", src);
    }

    else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_START) {
        LOG_A("EVENT_GRE_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_END) {
        LOG_A("EVENT_GRE_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_GRE_ATTACK_BURST_BLOCK) {
        LOG_A("EVENT_GRE_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_GRE_ATTACK_FIXED_BLOCK) {
        LOG_A("EVENT_GRE_ATTACK_FIXED_BLOCK %s\n", src);
    }
    
    else if (reason == EVENT_IP_FRAG_MIDDLE_BLOCK) {
        LOG_A("EVENT_IP_FRAG_MIDDLE_BLOCK %s\n", src);
    }
}