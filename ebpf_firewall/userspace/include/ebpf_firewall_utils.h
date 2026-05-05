#ifndef EBPF_FIREWALL_UTILS_H
#define EBPF_FIREWALL_UTILS_H

int get_machine_id(char * machine_id);
int get_license_status();

const char *ebpf_sqlite_db_path(void);

#endif