#ifndef EBPF_FIREWALL_MAPSIZE_H
#define EBPF_FIREWALL_MAPSIZE_H

/* Resize maps for this host. Call between bpf_object__open and bpf_object__load. */
int apply_host_map_sizing(struct bpf_object *obj);

#endif
