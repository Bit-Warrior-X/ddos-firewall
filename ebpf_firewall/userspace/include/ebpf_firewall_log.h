#ifndef EBPF_FIREWALL_LOG_H
#define EBPF_FIREWALL_LOG_H

#include <time.h>
#include <stdio.h>
#include <stdarg.h>

void func_print(int id, const char* fmt, ...);

#define ANSI_COLOR_FG_BLACK        "\x1b[0;30m"
#define ANSI_COLOR_FG_RED          "\x1b[0;31m"
#define ANSI_COLOR_FG_GREEN        "\x1b[0;32m"
#define ANSI_COLOR_FG_YELLOW       "\x1b[0;33m"
#define ANSI_COLOR_FG_BLUE         "\x1b[0;34m"
#define ANSI_COLOR_FG_MAGENTA      "\x1b[0;35m"
#define ANSI_COLOR_FG_CYAN         "\x1b[0;36m"
#define ANSI_COLOR_FG_WHITE        "\x1b[0;37m"
#define ANSI_COLOR_BG_BLACK        "\x1b[0;40m"
#define ANSI_COLOR_BG_RED          "\x1b[0;41m"
#define ANSI_COLOR_BG_GREEN        "\x1b[0;42m"
#define ANSI_COLOR_BG_YELLOW       "\x1b[0;43m"
#define ANSI_COLOR_BG_BLUE         "\x1b[0;44m"
#define ANSI_COLOR_BG_MAGENTA      "\x1b[0;45m"
#define ANSI_COLOR_BG_CYAN         "\x1b[0;46m"
#define ANSI_COLOR_BG_WHITE        "\x1b[0;47m"

#define ANSI_COLOR_FG_REV_BLACK        "\x1b[7;30m"
#define ANSI_COLOR_FG_REV_RED          "\x1b[7;31m"
#define ANSI_COLOR_FG_REV_GREEN        "\x1b[7;32m"
#define ANSI_COLOR_FG_REV_YELLOW       "\x1b[7;33m"
#define ANSI_COLOR_FG_REV_BLUE         "\x1b[7;34m"
#define ANSI_COLOR_FG_REV_MAGENTA      "\x1b[7;35m"
#define ANSI_COLOR_FG_REV_CYAN         "\x1b[7;36m"
#define ANSI_COLOR_FG_REV_WHITE        "\x1b[7;37m"
#define ANSI_COLOR_BG_REV_BLACK        "\x1b[7;40m"
#define ANSI_COLOR_BG_REV_RED          "\x1b[7;41m"
#define ANSI_COLOR_BG_REV_GREEN        "\x1b[7;42m"
#define ANSI_COLOR_BG_REV_YELLOW       "\x1b[7;43m"
#define ANSI_COLOR_BG_REV_BLUE         "\x1b[7;44m"
#define ANSI_COLOR_BG_REV_MAGENTA      "\x1b[7;45m"
#define ANSI_COLOR_BG_REV_CYAN         "\x1b[7;46m"
#define ANSI_COLOR_BG_REV_WHITE        "\x1b[7;47m"

#define ANSI_COLOR_RESET        "\x1b[0m"
#define ANSI_COLOR_BOLD_ON      "\x1b[1m"
#define ANSI_COLOR_UNDERSCORE   "\x1b[4m"
#define ANSI_COLOR_BLINK_ON     "\x1b[5m"
#define ANSI_COLOR_REV_VIDEO_ON "\x1b[7m"
#define ANSI_COLOR_CONCEALED_ON "\x1b[8m"

#ifndef COLOR_IS_ON
    #define COLOR_IS_ON
#endif

#if defined(COLOR_IS_ON)
#  define LOG_G(x, args...) func_print(1, "EMERGE  %-*.*s:%04u   "x""ANSI_COLOR_RESET, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_A(x, args...) func_print(2, "ALERT   %-*.*s:%04u   "x""ANSI_COLOR_RESET, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_C(x, args...) func_print(3, "CRITIC  %-*.*s:%04u   "x""ANSI_COLOR_RESET, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_E(x, args...) func_print(4, "ERROR   %-*.*s:%04u   "x""ANSI_COLOR_RESET, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_W(x, args...) func_print(5, "WARNING %-*.*s:%04u   "x""ANSI_COLOR_RESET, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_N(x, args...) func_print(6, "NOTICE  %-*.*s:%04u   "x""ANSI_COLOR_RESET, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_I(x, args...) func_print(7, "INFO    %-*.*s:%04u   "x""ANSI_COLOR_RESET, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_D(x, args...) func_print(8, "DEBUG   %-*.*s:%04u   "x""ANSI_COLOR_RESET, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_T(x, args...) func_print(9, ""x""ANSI_COLOR_RESET, ##args)
#else
#  define LOG_G(x, args...) func_print(1, "EMERGE  %-*.*s:%04u   "x, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_A(x, args...) func_print(2, "ALERT   %-*.*s:%04u   "x, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_C(x, args...) func_print(3, "CRITIC  %-*.*s:%04u   "x, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_E(x, args...) func_print(4, "ERROR   %-*.*s:%04u   "x, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_W(x, args...) func_print(5, "WARNING %-*.*s:%04u   "x, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_N(x, args...) func_print(6, "NOTICE  %-*.*s:%04u   "x, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_I(x, args...) func_print(7, "INFO    %-*.*s:%04u   "x, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_D(x, args...) func_print(8, "DEBUG   %-*.*s:%04u   "x, 30, 80, __FILE__, __LINE__, ##args)
#  define LOG_T(x, args...) func_print(9, ""x, ##args)
#endif

void print_firewall_status(struct tm * tm_info, int reason, __u32 srcip, __u64 req_id);
void print_firewall_status_ex(struct tm *tm_info, int reason, __u32 srcip, __u64 req_id,
                              const struct alert_extra *extra);
void build_block_ip_message(int reason, __u32 srcip, __u64 req_id,
                            char *build_message, size_t build_message_size);
void build_block_ip_message_ex(int reason, __u32 srcip, __u64 req_id,
                               char *build_message, size_t build_message_size,
                               const struct alert_extra *extra);
void build_attack_episode_message(int is_start, __u64 req_id,
                                  char *build_message, size_t build_message_size,
                                  const struct alert_extra *extra);
const char *alert_class_for_reason(int reason);
__u64 generate_attack_req_id(void);

/* Main daemon log under log_dir: hourly files sparta-YYYYMMDD-HH.log + latest.log */
void set_main_log_path(const char *path);
void ensure_main_log(void);

/* Per-episode attack archive under attack_log_dir (one file per req_id). */
void set_attack_log_dir(const char *dir);
int attack_log_open(__u64 req_id, const char *classes, const char *source);
void attack_log_note(const char *fmt, ...);
void attack_log_close(const char *classes);

#endif