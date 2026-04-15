// xdp_syn_whitelist_static.c
//
// Build (BTF required for `ip link set ... xdp` with libbpf — use -g):
//   clang -O2 -g -target bpf -c xdp_syn_whitelist_static.c -o xdp.o
//
// Metrics: one line per 1s wall time (serialized with bpf_spin_lock; multi-queue safe).
//   sudo cat /sys/kernel/debug/tracing/trace_pipe
// utc_tai_s is whole seconds (tai/1e9): every print in the same calendar second shares it;
// subns is the remainder. (Not duplicate wall time — same second, different ns.)
// Left column time (e.g. 226601.115174) is ftrace seconds since boot, not utc_tai_*.
// If the link is idle, nothing prints until the next packet (no XDP timer here).
// Or read maps (exact totals): bpftool map dump name total_pkts / name drop_pkts
//
// Timestamps use bpf_ktime_get_tai_ns() (UTC/TAI-style wall time, ns since Unix epoch).
// Requires Linux 6.1+ for that BPF helper; older kernels will reject program load.
// bpf_spin_lock in pps_log_map needs a kernel that supports spin locks in map values (5.1+).
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
//#define IP4 __constant_htonl(0xC08E1414)  // 192.142.20.20
#define IP5 __constant_htonl(0xC08E270A)  // 192.142.39.10

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} total_pkts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_pkts SEC(".maps");

struct pps_window {
    struct bpf_spin_lock lock;
    __u64 last_ns;
    __u64 last_total;
    __u64 last_drop;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pps_window);
} pps_log_map SEC(".maps");

static __always_inline int is_whitelisted(__u32 ip)
{
    if (ip == IP1) return 1;
    if (ip == IP2) return 1;
    if (ip == IP3) return 1;
    //if (ip == IP4) return 1;
    if (ip == IP5) return 1;
    return 0;
}

/* Count every packet; print at most once per second (counts since last print). */
static __always_inline void account_total_and_maybe_print_pps(void)
{
    __u32 k = 0;
    __u64 *tp = bpf_map_lookup_elem(&total_pkts, &k);
    if (!tp)
        return;

    __sync_fetch_and_add(tp, 1);
    __u64 cur = *tp;
    __u64 *dp = bpf_map_lookup_elem(&drop_pkts, &k);
    __u64 dcur = dp ? *dp : 0;

    struct pps_window *lg = bpf_map_lookup_elem(&pps_log_map, &k);
    if (!lg)
        return;

    /*
     * Hold lock only on pps_log_map. Do not touch other maps while locked (verifier).
     * cur/dcur are sampled just before lock — tiny skew vs a perfect snapshot; OK for logs.
     * bpf_ktime_get_ns() must run before bpf_spin_lock — helpers are not allowed while
     * holding a map spin lock.
     */
    __u64 now = bpf_ktime_get_ns();
    bpf_spin_lock(&lg->lock);

    if (lg->last_ns == 0) {
        lg->last_ns = now;
        lg->last_total = cur;
        lg->last_drop = dcur;
        bpf_spin_unlock(&lg->lock);
        return;
    }

    if (now - lg->last_ns < NSEC_PER_SEC) {
        bpf_spin_unlock(&lg->lock);
        return;
    }

    if (cur < lg->last_total || dcur < lg->last_drop) {
        /* Stale counter snapshot vs another CPU; skip this print window. */
        bpf_spin_unlock(&lg->lock);
        return;
    }

    __u64 total_pps = cur - lg->last_total;
    __u64 drop_pps = dcur - lg->last_drop;
    __u64 allow_pps = total_pps - drop_pps;

    lg->last_ns = now;
    lg->last_total = cur;
    lg->last_drop = dcur;

    bpf_spin_unlock(&lg->lock);

    __u64 tai = bpf_ktime_get_tai_ns();
    bpf_printk("xdp_syn_whitelist_static: utc_tai_s=%llu subns=%llu pps tot=%llu drp=%llu ok=%llu",
               tai / NSEC_PER_SEC, tai % NSEC_PER_SEC,
               total_pps, drop_pps, allow_pps);
}

static __always_inline void account_drop(void)
{
    __u32 k = 0;
    __u64 *dp = bpf_map_lookup_elem(&drop_pkts, &k);
    if (dp)
        __sync_fetch_and_add(dp, 1);
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    account_total_and_maybe_print_pps();

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
        account_drop();
        return XDP_DROP;
    }

#if 0
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void*)(tcph + 1) > data_end)
        return XDP_DROP;

    // Only filter SYN packets
    if (tcph->syn && !tcph->ack) {
        if (!is_whitelisted(iph->saddr)) {
            return XDP_DROP;
        }
    }
#endif

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
