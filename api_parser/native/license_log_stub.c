#include <stdarg.h>
#include <ebpf_firewall_log.h>

/* Silence ebpf_firewall_utils LOG_* output when linked into api_parser. */
void func_print(int id, const char* fmt, ...)
{
    (void)id;
    (void)fmt;
    va_list args;
    va_start(args, fmt);
    va_end(args);
}
