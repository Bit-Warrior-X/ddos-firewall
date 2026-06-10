#include <stdio.h>
#include <stdarg.h>
#include <ebpf_firewall_log.h>

void func_print(int id, const char* fmt, ...)
{
    (void)id;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}
