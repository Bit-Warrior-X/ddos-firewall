#ifndef EBPF_FIREWALL_UTILS_H
#define EBPF_FIREWALL_UTILS_H

#include <stddef.h>

int get_machine_id(char * machine_id);
int get_license_status();

typedef struct {
    int status;
    int feature;
    char license_type[32];
    long long days_left;
} license_info_t;

int get_license_info(license_info_t *out);

const char *ebpf_sqlite_db_path(void);

#endif