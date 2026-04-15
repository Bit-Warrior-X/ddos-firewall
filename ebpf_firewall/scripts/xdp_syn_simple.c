// xdp_syn_whitelist_static.c
//
// Build (BTF required for `ip link set ... xdp` with libbpf — use -g):
//   clang -O2 -g -target bpf -c xdp_syn_whitelist_static.c -o xdp.o
//

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define NSEC_PER_SEC 1000000000ULL

// Convert IP to network byte order manually
#define IP1 __constant_htonl(0x3202B832)  // 50.2.184.50
#define IP2 __constant_htonl(0xC08E2C8C)  // 192.142.44.140
#define IP3 __constant_htonl(0x5D5F74AE)  // 93.95.116.174
#define IP4 __constant_htonl(0xC08E391E)  // 192.142.57.30
#define IP5 __constant_htonl(0xC08E270A)  // 192.142.39.10

static __always_inline int is_whitelisted(__u32 ip)
{
    if (ip == IP1) return 1;
    if (ip == IP2) return 1;
    if (ip == IP3) return 1;
    if (ip == IP4) return 1;
    if (ip == IP5) return 1;
    return 0;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (!is_whitelisted(iph->saddr)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
