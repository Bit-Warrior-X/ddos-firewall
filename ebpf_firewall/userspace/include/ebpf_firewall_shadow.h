#ifndef EBPF_FIREWALL_SHADOW_H
#define EBPF_FIREWALL_SHADOW_H

#include "common.h"
#include <bpf/libbpf.h>

int start_shadow_control_loop(struct bpf_object *obj);
void stop_shadow_control_loop(void);

extern struct shadow_host_summary global_shadow_summary;
extern struct shadow_runtime_cfg shadow_cfg;

/* Fill a short human-readable status line into buf. */
int shadow_format_status(char *buf, size_t buflen);

/* 1 when adaptive DATA Attack is primarily HANDSHAKE (variable PSH len),
 * 0 when primarily STOMP (constant PSH len). */
int shadow_data_overlay_is_handshake(void);

/* Phase 4–5 runtime switches (pushed into .bss). */
int set_enforce_drop_invalid(struct bpf_object *obj, int enable);
int set_prefer_adaptive(struct bpf_object *obj, int enable);

#endif
