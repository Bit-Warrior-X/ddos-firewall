#include <ebpf_firewall_common.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_core.h>

#include <sys/stat.h>

extern FILE* log_file;
extern char log_path[512];

extern struct global_firewall_config global_fw_config;

static pthread_mutex_t main_log_mu = PTHREAD_MUTEX_INITIALIZER;
static char main_log_dir[512] = "/usr/local/share/dorian/sparta/logs";
static char main_log_prefix[64] = "sparta";
static char main_log_hour_key[20]; /* YYYYMMDD-HH of open file */
static char main_log_curpath[768];
static int main_log_disabled;

static pthread_mutex_t attack_log_mu = PTHREAD_MUTEX_INITIALIZER;
static FILE *attack_log_file;
static char attack_log_dir[512] = "/usr/local/share/dorian/sparta/logs/attacks";
static char attack_log_curpath[768];
static __u64 attack_log_req_id;
static time_t attack_log_started;
static int attack_log_disabled;

static void strip_ansi(char *s)
{
    char *r = s, *w = s;

    while (*r) {
        if (*r == '\033' && r[1] == '[') {
            r += 2;
            while (*r && !((*r >= '@' && *r <= 'Z') || (*r >= 'a' && *r <= 'z')))
                r++;
            if (*r)
                r++;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

static int mkdir_p(const char *path)
{
    char tmp[512];
    size_t len;
    char *p;

    if (!path || !*path)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len == 0)
        return -1;
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';
    for (p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

/*
 * Configure main log destination.
 *   /usr/local/share/dorian/sparta/logs → hourly files under that directory
 *   .../logs/foo.log                    → hourly files in .../logs (prefix=foo)
 *   off / none / -                      → disable file logging
 */
void set_main_log_path(const char *path)
{
    char tmp[512];
    char *slash;
    size_t len;

    pthread_mutex_lock(&main_log_mu);
    if (!path || !*path ||
        strcmp(path, "off") == 0 || strcmp(path, "0") == 0 ||
        strcmp(path, "-") == 0 || strcmp(path, "none") == 0) {
        main_log_disabled = 1;
        if (log_file) {
            fclose(log_file);
            log_file = NULL;
        }
        main_log_hour_key[0] = '\0';
        main_log_curpath[0] = '\0';
        log_path[0] = '\0';
        pthread_mutex_unlock(&main_log_mu);
        return;
    }

    main_log_disabled = 0;
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
        len--;
    }

    /* Path ends with .log → treat as legacy file path; rotate in its directory. */
    if (len > 4 && strcmp(tmp + len - 4, ".log") == 0) {
        slash = strrchr(tmp, '/');
        if (slash && slash > tmp) {
            *slash = '\0';
            snprintf(main_log_dir, sizeof(main_log_dir), "%s", tmp);
            snprintf(main_log_prefix, sizeof(main_log_prefix), "%s", slash + 1);
            /* strip .log from prefix */
            len = strlen(main_log_prefix);
            if (len > 4 && strcmp(main_log_prefix + len - 4, ".log") == 0)
                main_log_prefix[len - 4] = '\0';
            if (main_log_prefix[0] == '\0')
                snprintf(main_log_prefix, sizeof(main_log_prefix), "sparta");
        } else {
            snprintf(main_log_dir, sizeof(main_log_dir),
                     "/usr/local/share/dorian/sparta/logs");
            snprintf(main_log_prefix, sizeof(main_log_prefix), "sparta");
        }
    } else {
        snprintf(main_log_dir, sizeof(main_log_dir), "%s", tmp);
        snprintf(main_log_prefix, sizeof(main_log_prefix), "sparta");
    }

    snprintf(log_path, 512, "%s", main_log_dir);
    /* Force reopen on next write */
    main_log_hour_key[0] = '\0';
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    pthread_mutex_unlock(&main_log_mu);
}

void ensure_main_log(void)
{
    time_t now;
    struct tm tm_info;
    char hour_key[20];
    char path[768];
    char linkpath[768];
    FILE *fp;

    if (main_log_disabled || !main_log_dir[0])
        return;

    now = time(NULL);
    if (!localtime_r(&now, &tm_info))
        return;
    /* Readable hourly stamp: 20261026-17 */
    if (strftime(hour_key, sizeof(hour_key), "%Y%m%d-%H", &tm_info) == 0)
        return;

    pthread_mutex_lock(&main_log_mu);
    if (log_file && strcmp(main_log_hour_key, hour_key) == 0) {
        pthread_mutex_unlock(&main_log_mu);
        return;
    }

    if (mkdir_p(main_log_dir) < 0) {
        fprintf(stderr, "main_log: mkdir %s failed: %s\n",
                main_log_dir, strerror(errno));
        pthread_mutex_unlock(&main_log_mu);
        return;
    }

    snprintf(path, sizeof(path), "%s/%s-%s.log",
             main_log_dir, main_log_prefix, hour_key);
    fp = fopen(path, "a");
    if (!fp) {
        fprintf(stderr, "main_log: open %s failed: %s\n", path, strerror(errno));
        pthread_mutex_unlock(&main_log_mu);
        return;
    }

    if (log_file) {
        fflush(log_file);
        fclose(log_file);
    }
    log_file = fp;
    snprintf(main_log_hour_key, sizeof(main_log_hour_key), "%s", hour_key);
    snprintf(main_log_curpath, sizeof(main_log_curpath), "%s", path);
    snprintf(log_path, 512, "%.*s", 511, path);

    snprintf(linkpath, sizeof(linkpath), "%s/latest.log", main_log_dir);
    unlink(linkpath);
    if (symlink(path, linkpath) < 0)
        (void)0;

    pthread_mutex_unlock(&main_log_mu);
}

void set_attack_log_dir(const char *dir)
{
    if (!dir || !*dir ||
        strcmp(dir, "off") == 0 || strcmp(dir, "0") == 0 ||
        strcmp(dir, "-") == 0 || strcmp(dir, "none") == 0) {
        attack_log_disabled = 1;
        attack_log_dir[0] = '\0';
        return;
    }
    attack_log_disabled = 0;
    strncpy(attack_log_dir, dir, sizeof(attack_log_dir) - 1);
    attack_log_dir[sizeof(attack_log_dir) - 1] = '\0';
}

int attack_log_open(__u64 req_id, const char *classes, const char *source)
{
    time_t now;
    struct tm tm_info;
    char ts[32];
    char linkpath[768];
    FILE *fp;
    int already;

    if (attack_log_disabled || !attack_log_dir[0] || req_id == 0)
        return 0;

    pthread_mutex_lock(&attack_log_mu);
    already = (attack_log_file && attack_log_req_id == req_id);
    if (already) {
        if (classes && *classes)
            fprintf(attack_log_file, "# class join: %s\n", classes);
        fflush(attack_log_file);
        pthread_mutex_unlock(&attack_log_mu);
        return 0;
    }
    if (attack_log_file) {
        fclose(attack_log_file);
        attack_log_file = NULL;
    }
    pthread_mutex_unlock(&attack_log_mu);

    if (mkdir_p(attack_log_dir) < 0) {
        /* Avoid LOG_* while designing open path; stderr is fine once. */
        fprintf(stderr, "attack_log: mkdir %s failed: %s\n",
                attack_log_dir, strerror(errno));
        return -1;
    }

    now = time(NULL);
    localtime_r(&now, &tm_info);
    if (strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", &tm_info) == 0)
        strcpy(ts, "00000000-000000");

    snprintf(attack_log_curpath, sizeof(attack_log_curpath),
             "%s/%s-req_%llu.log", attack_log_dir, ts,
             (unsigned long long)req_id);

    fp = fopen(attack_log_curpath, "a");
    if (!fp) {
        fprintf(stderr, "attack_log: open %s failed: %s\n",
                attack_log_curpath, strerror(errno));
        return -1;
    }

    fprintf(fp, "#==============================================================================\n");
    fprintf(fp, "# Sparta attack archive\n");
    fprintf(fp, "# req_id   : %llu\n", (unsigned long long)req_id);
    fprintf(fp, "# started  : %04d-%02d-%02d %02d:%02d:%02d\n",
            tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);
    fprintf(fp, "# source   : %s\n", source && *source ? source : "-");
    fprintf(fp, "# classes  : %s\n", classes && *classes ? classes : "-");
    fprintf(fp, "#==============================================================================\n");
    fflush(fp);

    snprintf(linkpath, sizeof(linkpath), "%s/latest.log", attack_log_dir);
    unlink(linkpath);
    if (symlink(attack_log_curpath, linkpath) < 0)
        (void)0;

    pthread_mutex_lock(&attack_log_mu);
    if (attack_log_file) {
        fclose(attack_log_file);
        attack_log_file = NULL;
    }
    attack_log_file = fp;
    attack_log_req_id = req_id;
    attack_log_started = now;
    pthread_mutex_unlock(&attack_log_mu);

    return 1;
}

void attack_log_note(const char *fmt, ...)
{
    va_list ap;
    char buf[2048];
    time_t now;
    struct tm tm_info;
    char timeString[32];

    pthread_mutex_lock(&attack_log_mu);
    if (!attack_log_file) {
        pthread_mutex_unlock(&attack_log_mu);
        return;
    }
    now = time(NULL);
    localtime_r(&now, &tm_info);
    if (strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", &tm_info) == 0)
        strcpy(timeString, "0000-00-00 00:00:00");
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(attack_log_file, "[%s]   NOTE    %s", timeString, buf);
    if (buf[0] && buf[strlen(buf) - 1] != '\n')
        fputc('\n', attack_log_file);
    fflush(attack_log_file);
    pthread_mutex_unlock(&attack_log_mu);
}

void attack_log_close(const char *classes)
{
    time_t now;
    struct tm tm_info;
    char path[768];
    __u64 req_id;
    time_t started;
    FILE *fp;
    long duration;

    pthread_mutex_lock(&attack_log_mu);
    fp = attack_log_file;
    attack_log_file = NULL;
    req_id = attack_log_req_id;
    started = attack_log_started;
    snprintf(path, sizeof(path), "%s", attack_log_curpath);
    attack_log_req_id = 0;
    attack_log_started = 0;
    attack_log_curpath[0] = '\0';
    pthread_mutex_unlock(&attack_log_mu);

    if (!fp)
        return;

    now = time(NULL);
    localtime_r(&now, &tm_info);
    duration = (started > 0) ? (long)(now - started) : 0;
    fprintf(fp, "#------------------------------------------------------------------------------\n");
    fprintf(fp, "# ended    : %04d-%02d-%02d %02d:%02d:%02d\n",
            tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);
    fprintf(fp, "# duration : %ld s\n", duration);
    fprintf(fp, "# req_id   : %llu\n", (unsigned long long)req_id);
    fprintf(fp, "# classes  : %s\n", classes && *classes ? classes : "-");
    fprintf(fp, "#==============================================================================\n");
    fflush(fp);
    fclose(fp);

    /* LOG after close so this line stays in the main log only. */
    LOG_I("ATTACK archive closed req_id=%llu path=%s duration=%lds\n",
          (unsigned long long)req_id, path[0] ? path : "-", duration);
}

void func_print(int id, const char* fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    
    char output_fmt[8192];
    char plain_fmt[8192];
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
    snprintf(plain_fmt, sizeof(plain_fmt), "[%s]   %s", timeString, fmt);

    // Print to stdout (screen / journald)
    va_list args_copy;
    va_list args_attack;
    va_copy(args_copy, args);
    va_copy(args_attack, args);
    vprintf(output_fmt, args);
    va_end(args);

    // Hourly file under sparta/logs (plain text, no ANSI)
    ensure_main_log();
    pthread_mutex_lock(&main_log_mu);
    if (log_file) {
        vsnprintf(buffer, sizeof(buffer), plain_fmt, args_copy);
        strip_ansi(buffer);
        fprintf(log_file, "%s", buffer);
        fflush(log_file);
    }
    pthread_mutex_unlock(&main_log_mu);
    va_end(args_copy);

    /* Mirror into the active per-attack archive (plain text, no ANSI). */
    pthread_mutex_lock(&attack_log_mu);
    if (attack_log_file) {
        vsnprintf(buffer, sizeof(buffer), plain_fmt, args_attack);
        strip_ansi(buffer);
        fprintf(attack_log_file, "%s", buffer);
        fflush(attack_log_file);
    }
    pthread_mutex_unlock(&attack_log_mu);
    va_end(args_attack);
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
    if (temp[0] == '\0')
        return;

    __u64 req_id = supplied;
    if (!req_id && attack_slot_for_reason(reason) >= 0)
        req_id = req_id_for_reason(reason, supplied);
    if (!req_id)
        req_id = global_fw_config.g_attack_stats.global_req_id;
    if (!req_id)
        return;

    size_t n = strlen(temp);
    if (n + 40 >= temp_size)
        return;
    if (n >= 2 && temp[n - 1] == '\n' && temp[n - 2] == '\n')
        n -= 1;
    snprintf(temp + n, temp_size - n, "req_id:%llu\n\n", (unsigned long long)req_id);
}

static void trim_trailing_blank(char *temp)
{
    size_t n = strlen(temp);
    while (n >= 2 && temp[n - 1] == '\n' && temp[n - 2] == '\n') {
        temp[n - 1] = '\0';
        n--;
    }
}

static void append_alert_extra(char *temp, size_t temp_size, const struct alert_extra *ex)
{
    if (!ex || temp[0] == '\0')
        return;
    trim_trailing_blank(temp);

    size_t n;
#define ALERT_APPEND_STR(key, val) do {                                      \
        if ((val) && (val)[0]) {                                             \
            n = strlen(temp);                                                \
            if (n + 64 < temp_size)                                          \
                snprintf(temp + n, temp_size - n, "%s:%s\n", (key), (val));  \
        }                                                                    \
    } while (0)
#define ALERT_APPEND_U64(key, val) do {                                      \
        n = strlen(temp);                                                    \
        if (n + 48 < temp_size)                                              \
            snprintf(temp + n, temp_size - n, "%s:%llu\n", (key),            \
                     (unsigned long long)(val));                             \
    } while (0)

    ALERT_APPEND_STR("class", ex->class_name);
    ALERT_APPEND_STR("state", ex->state);
    ALERT_APPEND_STR("mode", ex->mode);
    ALERT_APPEND_STR("why", ex->why);
    ALERT_APPEND_STR("source", ex->source);
    ALERT_APPEND_STR("classes", ex->classes);
    if (ex->has_metrics) {
        ALERT_APPEND_U64("rate", ex->rate);
        ALERT_APPEND_U64("enter", ex->enter_pps);
        ALERT_APPEND_U64("exit", ex->exit_pps);
        ALERT_APPEND_U64("peak", ex->peak);
    }
#undef ALERT_APPEND_STR
#undef ALERT_APPEND_U64

    n = strlen(temp);
    if (n + 2 < temp_size && (n == 0 || temp[n - 1] != '\n'))
        snprintf(temp + n, temp_size - n, "\n");
}

const char *alert_class_for_reason(int reason)
{
    switch (reason) {
    case EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_SYN_ATTACK_BURST_BLOCK:
    case EVENT_TCP_SYN_ATTACK_FIXED_BLOCK:
        return "SYN";
    case EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_ACK_ATTACK_BURST_BLOCK:
    case EVENT_TCP_ACK_ATTACK_FIXED_BLOCK:
        return "ACK";
    case EVENT_TCP_RST_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_RST_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_RST_ATTACK_BURST_BLOCK:
    case EVENT_TCP_RST_ATTACK_FIXED_BLOCK:
        return "RST";
    case EVENT_ICMP_ATTACK_PROTECION_MODE_START:
    case EVENT_ICMP_ATTACK_PROTECION_MODE_END:
    case EVENT_ICMP_ATTACK_BURST_BLOCK:
    case EVENT_ICMP_ATTACK_FIXED_BLOCK:
        return "ICMP";
    case EVENT_UDP_ATTACK_PROTECION_MODE_START:
    case EVENT_UDP_ATTACK_PROTECION_MODE_END:
    case EVENT_UDP_ATTACK_BURST_BLOCK:
    case EVENT_UDP_ATTACK_FIXED_BLOCK:
        return "UDP";
    case EVENT_GRE_ATTACK_PROTECION_MODE_START:
    case EVENT_GRE_ATTACK_PROTECION_MODE_END:
    case EVENT_GRE_ATTACK_BURST_BLOCK:
    case EVENT_GRE_ATTACK_FIXED_BLOCK:
        return "GRE";
    case EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_STOMP_ATTACK_BURST_BLOCK:
    case EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK:
        return "DATA";
    case EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_END:
    case EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK:
    case EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK:
        return "HANDSHAKE";
    case EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK:
    case EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_END:
        return "SOCKET";
    case EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_END:
        return "SYNACK";
    case EVENT_TCP_FIN_ATTACK_PROTECION_MODE_START:
    case EVENT_TCP_FIN_ATTACK_PROTECION_MODE_END:
        return "FIN";
    case EVENT_IP_FRAG_MIDDLE_BLOCK:
    case EVENT_IP_FRAG_ATTACK_PROTECION_MODE_START:
    case EVENT_IP_FRAG_ATTACK_PROTECION_MODE_END:
        return "FRAG";
    case EVENT_OTHER_ATTACK_PROTECION_MODE_START:
    case EVENT_OTHER_ATTACK_PROTECION_MODE_END:
        return "OTHER";
    case EVENT_TCP_CONNECTION_LIMIT_REACHED:
        return "CONNTRACK";
    default:
        return NULL;
    }
}

void build_block_ip_message(int reason, __u32 srcip, __u64 req_id,
                            char *build_message, size_t build_message_size)
{
    struct alert_extra classic = {
        .class_name = alert_class_for_reason(reason),
        .source = "classic",
        .why = "classic",
    };
    build_block_ip_message_ex(reason, srcip, req_id, build_message, build_message_size, &classic);
}

void build_block_ip_message_ex(int reason, __u32 srcip, __u64 req_id,
                               char *build_message, size_t build_message_size,
                               const struct alert_extra *extra)
{
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcip, src, sizeof(src));
    char temp[2048];
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
        snprintf(temp, sizeof(temp), "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }   
    else if (reason == EVENT_TCP_CONNECTION_LIMIT_REACHED) {
        snprintf(temp, sizeof(temp), "command:report_block_ip\n"
                                "ip:%s\n"
                                "ttl:%llds\n"
                                "attack_type:EVENT_TCP_CONNECTION_LIMIT_REACHED\n"
                                "time:%s\n\n", 
                                src, global_fw_config.g_config.black_ip_duration / ONE_SECOND_NS, time_buf); 
    }
    else if (reason == EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_TCP_FIN_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_TCP_FIN_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_TCP_FIN_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_TCP_FIN_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_IP_FRAG_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_IP_FRAG_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_IP_FRAG_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_IP_FRAG_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_OTHER_ATTACK_PROTECION_MODE_START) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_OTHER_ATTACK_PROTECION_MODE_START\n"
                                "time:%s\n\n", time_buf);
    }
    else if (reason == EVENT_OTHER_ATTACK_PROTECION_MODE_END) {
        snprintf(temp, sizeof(temp), "command:report_protection\n"
                                "data:EVENT_OTHER_ATTACK_PROTECION_MODE_END\n"
                                "time:%s\n\n", time_buf);
    }

    struct alert_extra derived = {0};
    const struct alert_extra *use = extra;
    if (!use) {
        derived.class_name = alert_class_for_reason(reason);
        derived.source = "classic";
        derived.why = "classic";
        use = &derived;
    } else if (!use->class_name) {
        derived = *use;
        derived.class_name = alert_class_for_reason(reason);
        use = &derived;
    }
    append_alert_extra(temp, sizeof(temp), use);

    __u64 stamp = req_id ? req_id : global_fw_config.g_attack_stats.global_req_id;
    append_req_id(temp, sizeof(temp), reason, stamp);
    snprintf(build_message, build_message_size, "%s", temp);
}

void build_attack_episode_message(int is_start, __u64 req_id,
                                  char *build_message, size_t build_message_size,
                                  const struct alert_extra *extra)
{
    char time_buf[32];
    time_t rawtime;
    struct tm tm_info;
    char temp[2048];

    time(&rawtime);
    localtime_r(&rawtime, &tm_info);
    if (strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info) == 0)
        strcpy(time_buf, "0000-00-00 00:00:00");

    snprintf(temp, sizeof(temp),
             "command:report_attack\ndata:%s\nreq_id:%llu\ntime:%s\n",
             is_start ? "attack_start" : "attack_stop",
             (unsigned long long)req_id, time_buf);
    append_alert_extra(temp, sizeof(temp), extra);
    {
        size_t n = strlen(temp);
        if (n + 2 < sizeof(temp) && (n == 0 || temp[n - 1] != '\n'))
            snprintf(temp + n, sizeof(temp) - n, "\n");
    }
    snprintf(build_message, build_message_size, "%s", temp);
}

void print_firewall_status(struct tm * tm_info, int reason, __u32 srcip, __u64 req_id) {
    struct alert_extra classic = {
        .class_name = alert_class_for_reason(reason),
        .source = "classic",
        .why = "classic",
    };
    print_firewall_status_ex(tm_info, reason, srcip, req_id, &classic);
}

void print_firewall_status_ex(struct tm *tm_info, int reason, __u32 srcip, __u64 req_id,
                              const struct alert_extra *extra)
{
    (void)tm_info;
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcip, src, sizeof(src));

    char build_message[2048];
    build_block_ip_message_ex(reason, srcip, req_id, build_message, sizeof(build_message), extra);
    send_message_to_api_parser(build_message);

    /* Human-readable DETECT / BLOCK lines (API payloads unchanged above). */
    if (reason == EVENT_IP_BLOCK_END) {
        LOG_I("UNBLOCK src=%s (ttl expired)\n", src);
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT SYN flood protection START\n");
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT SYN flood protection END\n");
    } else if (reason == EVENT_TCP_SYN_ATTACK_BURST_BLOCK) {
        LOG_C("BLOCK SYN burst src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp syn attack burst mode");
    } else if (reason == EVENT_TCP_SYN_ATTACK_FIXED_BLOCK) {
        LOG_C("BLOCK SYN fixed-rate src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp syn attack burst mode");
    }
    else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT ACK flood protection START\n");
    } else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT ACK flood protection END\n");
    } else if (reason == EVENT_TCP_ACK_ATTACK_BURST_BLOCK) {
        LOG_C("BLOCK ACK burst src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp ack attack burst mode");
    } else if (reason == EVENT_TCP_ACK_ATTACK_FIXED_BLOCK) {
        LOG_C("BLOCK ACK fixed-rate src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp ack attack fixed threshold mode");
    }

    else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT RST flood protection START\n");
    } else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT RST flood protection END\n");
    } else if (reason == EVENT_TCP_RST_ATTACK_BURST_BLOCK) {
        LOG_C("BLOCK RST burst src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp rst attack burst mode");
    } else if (reason == EVENT_TCP_RST_ATTACK_FIXED_BLOCK) {
        LOG_C("BLOCK RST fixed-rate src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp rst attack fixed threshold mode");
    }

    else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT ICMP flood protection START\n");
    } else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT ICMP flood protection END\n");
    } else if (reason == EVENT_ICMP_ATTACK_BURST_BLOCK) {
        LOG_C("BLOCK ICMP burst src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in icmp attack burst mode");
    } else if (reason == EVENT_ICMP_ATTACK_FIXED_BLOCK) {
        LOG_C("BLOCK ICMP fixed-rate src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in icmp attack fixed threshold mode");
    }

    else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT UDP flood protection START\n");
    } else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT UDP flood protection END\n");
    } else if (reason == EVENT_UDP_ATTACK_BURST_BLOCK) {
        LOG_C("BLOCK UDP burst src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in udp attack burst mode");
    } else if (reason == EVENT_UDP_ATTACK_FIXED_BLOCK) {
        LOG_C("BLOCK UDP fixed-rate src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in udp attack fixed threshold mode");
    }

    else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT GRE flood protection START\n");
    } else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT GRE flood protection END\n");
    } else if (reason == EVENT_GRE_ATTACK_BURST_BLOCK) {
        LOG_C("BLOCK GRE burst src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in gre attack burst mode");
    } else if (reason == EVENT_GRE_ATTACK_FIXED_BLOCK) {
        LOG_C("BLOCK GRE fixed-rate src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in gre attack fixed threshold mode");
    }

    else if (reason == EVENT_IP_FRAG_MIDDLE_BLOCK) {
        LOG_C("BLOCK FRAG middle-fragment src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp segmentation");
    }
    else if (reason == EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT DATA/STOMP flood protection START\n");
    } else if (reason == EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT DATA/STOMP flood protection END\n");
    } else if (reason == EVENT_TCP_STOMP_ATTACK_BURST_BLOCK) {
        LOG_C("BLOCK DATA/STOMP burst src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp stomp attack burst mode");
    } else if (reason == EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK) {
        LOG_C("BLOCK DATA/STOMP fixed-rate src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp stomp attack fixed threshold mode");
    }
    else if (reason == EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK) {
        LOG_C("BLOCK SOCKET concurrent-cap src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp socket attack fixed threshold mode");
    }
    else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT HANDSHAKE flood protection START\n");
    } else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT HANDSHAKE flood protection END\n");
    } else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK) {
        LOG_C("BLOCK HANDSHAKE burst src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp handshake attack burst mode");
    } else if (reason == EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK) {
        LOG_C("BLOCK HANDSHAKE fixed-rate src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "Attacking in tcp handshake attack fixed threshold mode");
    }
    else if (reason == EVENT_TCP_CONNECTION_LIMIT_REACHED) {
        LOG_C("BLOCK CONNTRACK limit src=%s\n", src);
        append_block_ip_to_sqlite(src, 0, "TCP connection limit reached");
    }
    else if (reason == EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT SOCKET flood protection START\n");
    } else if (reason == EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT SOCKET flood protection END\n");
    }
    else if (reason == EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT SYNACK flood protection START\n");
    } else if (reason == EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT SYNACK flood protection END\n");
    }
    else if (reason == EVENT_TCP_FIN_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT FIN flood protection START\n");
    } else if (reason == EVENT_TCP_FIN_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT FIN flood protection END\n");
    }
    else if (reason == EVENT_IP_FRAG_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT FRAG flood protection START\n");
    } else if (reason == EVENT_IP_FRAG_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT FRAG flood protection END\n");
    }
    else if (reason == EVENT_OTHER_ATTACK_PROTECION_MODE_START) {
        LOG_C("DETECT OTHER flood protection START\n");
    } else if (reason == EVENT_OTHER_ATTACK_PROTECION_MODE_END) {
        LOG_I("DETECT OTHER flood protection END\n");
    }
}