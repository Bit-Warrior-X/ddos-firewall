#ifndef EBPF_FIREWALL_CONNTRACK_H
#define EBPF_FIREWALL_CONNTRACK_H

int init_conntrack(int tcp_established_fd, int tcp_connection_map_fd, int block_ips_map_fd);
void close_conntrack();

#endif