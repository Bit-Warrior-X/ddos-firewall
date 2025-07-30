#ifndef EBPF_FIREWALL_GEO_H
#define EBPF_FIREWALL_GEO_H

int init_geo(char * loc_path, 
             char * ipv4_path, 
             char   isos[][3], int nisos, 
             int map_fd);

#endif