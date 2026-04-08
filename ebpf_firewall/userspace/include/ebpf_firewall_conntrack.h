#ifndef EBPF_FIREWALL_CONNTRACK_H
#define EBPF_FIREWALL_CONNTRACK_H

#include <linux/types.h>

struct bpf_object;

int init_conntrack(int tcp_established_fd, int tcp_connection_map_fd, int block_ips_map_fd);
int purge_conntrack_for_blocked_ips(int blocked_ips_fd);
int flush_all_tcp_conntrack(void);

/*
 * When an IP is added to blocked_ips: drop its TCP conntrack entries in the
 * kernel, remove all tcp_established_map keys for that IP, and delete its
 * tcp_connection_map counter. Safe if map fds are negative (no-op for BPF maps).
 */
void clear_tracked_tcp_state_for_blocked_ip(int tcp_established_fd,
                                            int tcp_connection_map_fd,
                                            __u32 ip_net_order);

/* After reloading blocked_ips from DB into the BPF map, sync kernel + BPF maps. */
int reconcile_blocked_ips_tracked_state(struct bpf_object *obj);

void close_conntrack();

#endif