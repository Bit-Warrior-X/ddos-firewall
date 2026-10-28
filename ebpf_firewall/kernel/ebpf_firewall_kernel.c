// ebpf_firewall_kernel.c
// Optimized XDP anti-DDoS kernel with STOMP, SOCKET, and Handshake flood protection
// Map sizes tuned for 20GB+ RAM enterprise deployment (~2-3GB total map footprint)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/*
 * Map sizing rationale for 20GB+ RAM:
 *
 * Per-IP tracking maps (flood_stats = 17B, burst_state = 24B, challenge_state = 13B):
 *   524288 entries × ~160B overhead ≈ 80MB per map
 *   With ~30 per-IP maps ≈ 2.4GB total — fits easily in 20GB
 *
 * blocked_ips: 524288 — can hold 500K+ blocked IPs simultaneously
 * SYN maps: 524288 — SYN floods generate the most unique source IPs
 * ACK/RST/UDP/PSH maps: 524288 — matching SYN capacity for uniform defense
 * ICMP/GRE maps: 262144 — these floods tend to use fewer unique IPs
 * tcp_established_map: 1048576 (1M) — supports 1M concurrent connections
 * geo_result_cache: 524288 — cache for fast geo lookups
 * SOCKET/Handshake maps: 262144 — less common attack vectors
 */

#define MAP_SIZE_LARGE    524288   /* SYN, ACK, RST, UDP, PSH, blocked */
#define MAP_SIZE_MEDIUM   262144   /* ICMP, GRE, SOCKET, Handshake, geo cache */
#define MAP_SIZE_CONNTRACK 1048576  /* tcp_established, tcp_connection, allowed */

volatile struct global_firewall_config global_fw_config SEC(".bss");

/* Tail call map:
 * Key 0 -> xdp_parse_syn
 * Key 1 -> xdp_parse_ack
 * Key 2 -> xdp_parse_rst
 * Key 3 -> xdp_parse_icmp
 * Key 4 -> xdp_parse_udp
 * Key 5 -> xdp_parse_gre
 * Key 6 -> xdp_parse_psh_ack      (PSH+ACK classifier: STOMP vs HANDSHAKE)
 * Key 7 -> xdp_parse_tcp_socket   (TCP SOCKET)
 * Key 8 -> xdp_parse_handshake    (HANDSHAKE / variable-length PSH+ACK)
 * Key 9 -> xdp_parse_stomp        (STOMP / constant-length PSH+ACK)
 * Key 10 -> xdp_parse_synack      (SYN+ACK; own counter, handshake config)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 11);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

/* Common LRU on purpose: BPF_F_NO_COMMON_LRU splits capacity per CPU, so the
 * userspace loader (one CPU) could hold only max_entries / nr_cpus blocks. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, __u64);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_buf_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} fixed_ip_ring_buf_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_psh_ack_filtered SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_CONNTRACK);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips SEC(".maps");

/* Grace after SYN cookie ACK (or legacy challenge). Defined early so
 * should_drop_invalid / xdp_main can write it. */
#define SYN_GRACE_PERIOD_NS  (120ULL * ONE_SECOND_NS)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, __u64);    /* grace expiration time in ns */
} syn_validated_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_CONNTRACK);
    __type(key, __u64);
    __type(value, __u8);
} tcp_established_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_config);
} global_income_pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct traffic_stats_config);
} global_income_pkt_traffic SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 700000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u8);
} geoip_trie_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 700000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u8);
} geoip_trie_block_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, struct geo_cache_val);
} geo_result_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_CONNTRACK);
    __type(key, __u32);
    __type(value, __u32);
} tcp_connection_map SEC(".maps");

/* Phase 1: per-{dst,class} and invalid counters (before verdict). */
#define DET_MAP_SIZE 131072

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, DET_MAP_SIZE);
    __type(key, struct det_key);
    __type(value, struct det_val);
} det_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DET_CLASS_MAX);
    __type(key, __u32);
    __type(value, struct det_val);
} det_class_totals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, DET_MAP_SIZE);
    __type(key, struct invalid_key);
    __type(value, __u64);
} invalid_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, INVALID_REASON_MAX);
    __type(key, __u32);
    __type(value, __u64);
} invalid_totals SEC(".maps");

/* Phase 4: mitigation mode per {dst,class}. dst=0 is host-wide. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DET_MAP_SIZE);
    __type(key, struct det_key);
    __type(value, struct mode_val);
} mitigation_mode SEC(".maps");

/* Drop-invalid packets dropped by Phase 4 path (host-wide). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_invalid_totals SEC(".maps");

/* Phase 5: limits and buckets for modes 2–3. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, DET_CLASS_MAX);
    __type(key, __u32);
    __type(value, struct mode_limits);
} mode_limits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, struct src_bucket_key);
    __type(value, struct rate_win);
} src_buckets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DET_MAP_SIZE);
    __type(key, struct det_key);
    __type(value, struct rate_win);
} dst_class_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_mode2_totals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_mode3_totals SEC(".maps");

/* Layer 4: per-flow state (4-tuple). RSS keeps a flow on one CPU → plain LRU_HASH. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_CONNTRACK);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_flow_totals SEC(".maps");

/* Validity allowlists (populated from service profile / redesign.config). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);   /* host-order dest UDP port */
    __type(value, __u8);
} udp_allowed_dports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u16);   /* host-order source UDP port (reflection) */
    __type(value, __u8);
} udp_reflection_sports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u8);    /* ICMP type */
    __type(value, __u8);
} icmp_allowed_types SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* GRE peer IPv4 */
    __type(value, __u8);
} gre_allowed_peers SEC(".maps");

/* TC egress records outbound SYN; XDP matches SYN-ACK ack_seq-1. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct outbound_syn_key);
    __type(value, struct outbound_syn_val);
} outbound_syn SEC(".maps");

/* Escalating block TTL offence counter (proven sources only). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, struct block_offense_val);
} block_offense SEC(".maps");

/* Layer-4: new flows / connection attempts per source and /24. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32); /* src */
    __type(value, struct rate_win);
} src_new_flows SEC(".maps");

/* SYN count per window (socket_fixed_check_duration). Nothing decrements on
 * close, so an unwindowed counter turns into a lifetime SYN total. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32); /* src */
    __type(value, struct rate_win);
} src_conn_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_MEDIUM);
    __type(key, __u32); /* saddr & 0xffffff00 in network order for /24 */
    __type(value, struct rate_win);
} prefix24_conn_count SEC(".maps");

/* Middle fragments are always dropped; report each source at most once per interval. */
#define FRAG_EVENT_INTERVAL_NS (10ULL * ONE_SECOND_NS)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_MEDIUM);
    __type(key, __u32);   /* src */
    __type(value, __u64); /* last event ns */
} frag_event_last SEC(".maps");


/*-------------------------------------------- Static Functions ------------------------------------*/
static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

/* Match tools/testing/selftests/bpf/progs/xdp_synproxy_kern.c */
static __always_inline __u16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
                                               __u32 len, __u8 proto, __u32 csum)
{
    __u64 s = csum;
    s += (__u32)saddr;
    s += (__u32)daddr;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    s += proto + len;
#else
    s += (__u32)(proto + len) << 8;
#endif
    s = (s & 0xffffffff) + (s >> 32);
    s = (s & 0xffffffff) + (s >> 32);
    return csum_fold((__u32)s);
}

static __always_inline void count_psh_ack_filtered(void)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&global_psh_ack_filtered, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

static __always_inline __u8 is_geo_allowed(__u32 ip)
{
    volatile struct geo_config *geo = &global_fw_config.g_geo_config;
    __u8 mode = geo->check;
    if (!mode)
        return 1;

    __u32 gen = geo->cache_generation;
    struct geo_cache_val *cached = bpf_map_lookup_elem(&geo_result_cache, &ip);
    if (cached && cached->generation == gen && cached->mode == mode)
        return cached->allowed;

    struct lpm_key key = { .prefixlen = 32, .ip = ip };
    __u8 allowed;
    if (mode == 1) {
        __u8 *a = bpf_map_lookup_elem(&geoip_trie_map, &key);
        allowed = (a && *a != 0) ? 1 : 0;
    } else {
        __u8 *b = bpf_map_lookup_elem(&geoip_trie_block_map, &key);
        allowed = (!b || *b == 0) ? 1 : 0;
    }

    struct geo_cache_val nv = { .generation = gen, .allowed = allowed, .mode = mode, ._reserved = 0 };
    bpf_map_update_elem(&geo_result_cache, &ip, &nv, BPF_ANY);
    return allowed;
}

static __always_inline __u8 is_tcp_established(__u32 src_ip, __u16 src_port)
{
    __u64 key = src_port;
    key = ((key << 32) | src_ip);
    __u8 *val = bpf_map_lookup_elem(&tcp_established_map, &key);
    return val ? 1 : 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PASS_REASON_MAX);
    __type(key, __u32);
    __type(value, __u64);
} valid_pass_reasons SEC(".maps");

static __always_inline void count_valid_pass(__u32 reason)
{
    __u64 *c = bpf_map_lookup_elem(&valid_pass_reasons, &reason);
    if (c)
        *c += 1;
}

/* Prefer kernel socket table when available; fall back to conntrack mirror (C2).
 * bpf_skc_lookup_tcp falls back to the listener for any open port, so a LISTEN
 * match proves nothing about the 4-tuple — only established / request / timewait do.
 * Returns PASS_REASON_SOCKET + 1 / PASS_REASON_MIRROR + 1, or 0 when out of state. */
static __always_inline __u8 tcp_flow_valid(struct xdp_md *ctx, struct iphdr *iph,
                                           struct tcphdr *tcph)
{
    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.saddr = iph->saddr;
    tuple.ipv4.daddr = iph->daddr;
    tuple.ipv4.sport = tcph->source;
    tuple.ipv4.dport = tcph->dest;
    struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
                                             BPF_F_CURRENT_NETNS, 0);
    if (sk) {
        __u32 state = sk->state;
        bpf_sk_release(sk);
        if (state != BPF_TCP_LISTEN)
            return PASS_REASON_SOCKET + 1;
    }
    return is_tcp_established(iph->saddr, tcph->source) ? PASS_REASON_MIRROR + 1 : 0;
}

static __always_inline __u64 attack_req_id_for_reason(__u16 reason)
{
    volatile struct global_attack_stats *st = &global_fw_config.g_attack_stats;
    switch (reason) {
    case EVENT_TCP_SYN_ATTACK_BURST_BLOCK:
    case EVENT_TCP_SYN_ATTACK_FIXED_BLOCK:
        return st->syn_req_id;
    case EVENT_TCP_ACK_ATTACK_BURST_BLOCK:
    case EVENT_TCP_ACK_ATTACK_FIXED_BLOCK:
        return st->ack_req_id;
    case EVENT_TCP_RST_ATTACK_BURST_BLOCK:
    case EVENT_TCP_RST_ATTACK_FIXED_BLOCK:
        return st->rst_req_id;
    case EVENT_ICMP_ATTACK_BURST_BLOCK:
    case EVENT_ICMP_ATTACK_FIXED_BLOCK:
        return st->icmp_req_id;
    case EVENT_UDP_ATTACK_BURST_BLOCK:
    case EVENT_UDP_ATTACK_FIXED_BLOCK:
        return st->udp_req_id;
    case EVENT_GRE_ATTACK_BURST_BLOCK:
    case EVENT_GRE_ATTACK_FIXED_BLOCK:
        return st->gre_req_id;
    case EVENT_TCP_STOMP_ATTACK_BURST_BLOCK:
    case EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK:
        return st->stomp_req_id;
    case EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK:
    case EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK:
        return st->handshake_req_id;
    default:
        return 0;
    }
}

/* Drop without blacklist/report (fallback when already handled / no report needed). */
static __always_inline int drop_spoofable(
    struct traffic_stats_config *traffic_stats, __u64 packet_size)
{
    traffic_stats->blocked_traffic += packet_size;
    return XDP_DROP;
}

/*
 * Blacklist source + emit FIXED/BURST block event → userspace report_block_ip.
 * Used for all flood classes once per-IP rate/burst threshold is crossed.
 */
static __always_inline int block_ip_with_event(
    __u32 src_ip, __u64 now, __u16 reason,
    struct traffic_stats_config *traffic_stats, __u64 packet_size)
{
    volatile struct global_config *gcfg = &global_fw_config.g_config;
    /* Escalating TTL: initial, then double per offence up to max. */
    __u64 initial = gcfg->block_initial_ns ? gcfg->block_initial_ns : gcfg->black_ip_duration;
    __u64 max_ttl = gcfg->block_max_ns ? gcfg->block_max_ns : (initial ? initial : BLOCK_DURATION_NS);
    if (!initial)
        initial = BLOCK_DURATION_NS;
    if (max_ttl < initial)
        max_ttl = initial;

    __u64 ttl = initial;
    struct block_offense_val *off = bpf_map_lookup_elem(&block_offense, &src_ip);
    if (off) {
        __u32 n = off->count + 1;
        if (n > 16)
            n = 16;
        off->count = n;
        off->last_block_ns = now;
        __u32 shift = n - 1;
        if (shift > 20)
            shift = 20;
        ttl = initial << shift;
        if (ttl < initial || ttl > max_ttl)
            ttl = max_ttl;
    } else {
        struct block_offense_val nov = { .count = 1, .last_block_ns = now };
        bpf_map_update_elem(&block_offense, &src_ip, &nov, BPF_ANY);
    }

    __u64 block_exp = now + ttl;
    __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (!blocked_time_p)
        bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp, BPF_ANY);
    else
        *blocked_time_p = block_exp;

    struct event evt = {0};
    evt.time = now;
    evt.srcip = src_ip;
    evt.reason = reason;
    evt.req_id = attack_req_id_for_reason(reason);
    bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

    traffic_stats->blocked_traffic += packet_size;
    return XDP_DROP;
}


/*=============================================================================================================
 *                         Phase 1 detection counters (pre-verdict)
 *============================================================================================================*/
static __always_inline void det_count(__u32 dst, __u8 class, __u64 bytes)
{
    if (class >= DET_CLASS_MAX)
        return;

    struct det_key dk = { .dst = dst, .class = class };
    struct det_val *dv = bpf_map_lookup_elem(&det_counters, &dk);
    if (dv) {
        dv->pkts += 1;
        dv->bytes += bytes;
    } else {
        struct det_val init = { .pkts = 1, .bytes = bytes };
        bpf_map_update_elem(&det_counters, &dk, &init, BPF_ANY);
    }

    __u32 ck = class;
    struct det_val *tot = bpf_map_lookup_elem(&det_class_totals, &ck);
    if (tot) {
        tot->pkts += 1;
        tot->bytes += bytes;
    }
}

static __always_inline void invalid_count(__u32 dst, __u8 reason)
{
    if (reason >= INVALID_REASON_MAX)
        return;

    struct invalid_key ik = { .dst = dst, .reason = reason };
    __u64 *iv = bpf_map_lookup_elem(&invalid_counters, &ik);
    if (iv) {
        *iv += 1;
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&invalid_counters, &ik, &one, BPF_ANY);
    }

    __u32 rk = reason;
    __u64 *tot = bpf_map_lookup_elem(&invalid_totals, &rk);
    if (tot)
        *tot += 1;
}

static __always_inline void count_drop_invalid(void)
{
    __u32 k = 0;
    __u64 *c = bpf_map_lookup_elem(&drop_invalid_totals, &k);
    if (c)
        *c += 1;
}

static __always_inline void count_drop_mode2(void)
{
    __u32 k = 0;
    __u64 *c = bpf_map_lookup_elem(&drop_mode2_totals, &k);
    if (c)
        *c += 1;
}

static __always_inline void count_drop_mode3(void)
{
    __u32 k = 0;
    __u64 *c = bpf_map_lookup_elem(&drop_mode3_totals, &k);
    if (c)
        *c += 1;
}

static __always_inline void count_drop_flow(void)
{
    __u32 k = 0;
    __u64 *c = bpf_map_lookup_elem(&drop_flow_totals, &k);
    if (c)
        *c += 1;
}

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

/* Skip 802.1Q / QinQ; return L3 header start and host-order ethertype. */
static __always_inline void *eth_skip_vlan(struct ethhdr *eth, void *data_end, __u16 *eth_proto)
{
    void *p = (void *)(eth + 1);
    __u16 proto = bpf_ntohs(eth->h_proto);
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != ETH_P_8021Q && proto != ETH_P_8021AD)
            break;
        if (p + 4 > data_end)
            return NULL;
        __u16 tagged = *(__u16 *)(p + 2);
        proto = bpf_ntohs(tagged);
        p += 4;
    }
    *eth_proto = proto;
    return p;
}

/* Parse Ethernet (+VLAN) → IPv4. Returns iph or NULL. */
static __always_inline struct iphdr *parse_ipv4(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return NULL;
    __u16 proto = 0;
    void *l3 = eth_skip_vlan(eth, data_end, &proto);
    if (!l3 || proto != ETH_P_IP)
        return NULL;
    struct iphdr *iph = l3;
    if ((void *)(iph + 1) > data_end)
        return NULL;
    return iph;
}

#define TCP_MAXLEN 60
#define IPV4_MAXLEN 60

/* Re-parse eth/vlan/ipv4/tcp after xdp_adjust_tail. */
static __always_inline int syn_cookie_reparse(struct xdp_md *ctx,
                                              struct ethhdr **eth_out,
                                              struct iphdr **iph_out,
                                              struct tcphdr **tcph_out)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    __u16 proto = 0;
    void *l3 = eth_skip_vlan(eth, data_end, &proto);
    if (!l3 || proto != ETH_P_IP)
        return -1;
    struct iphdr *iph = l3;
    /* Need IPV4_MAXLEN headroom so ihl*4 stays in bounds for the verifier. */
    if ((void *)iph + IPV4_MAXLEN > data_end)
        return -1;
    if (iph->ihl < 5 || iph->version != 4)
        return -1;
    struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
    if ((void *)tcph + TCP_MAXLEN > data_end)
        return -1;
    *eth_out = eth;
    *iph_out = iph;
    *tcph_out = tcph;
    return 0;
}

/*
 * Rewrite inbound SYN into a SYN-ACK cookie reply and XDP_TX it.
 * Grows the TCP header to TCP_MAXLEN first so bpf_tcp_raw_gen_syncookie_ipv4
 * passes the verifier (same pattern as xdp_synproxy_kern.c).
 */
static __always_inline int syn_cookie_tx_reply(struct xdp_md *ctx, struct ethhdr *eth,
                                               struct iphdr *iph, struct tcphdr *tcph)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 th_len = (__u32)tcph->doff * 4;
    if (th_len < sizeof(*tcph) || th_len > TCP_MAXLEN)
        return XDP_DROP;
    if ((void *)tcph + th_len > data_end)
        return XDP_DROP;
    if (tcph->fin || tcph->rst)
        return XDP_DROP;

    /* Grow so helper may safely read up to TCP_MAXLEN from tcph. */
    __u32 old_pkt_size = (__u32)((long)data_end - (long)data);
    if (bpf_xdp_adjust_tail(ctx, (int)TCP_MAXLEN - (int)th_len))
        return XDP_DROP;
    if (syn_cookie_reparse(ctx, &eth, &iph, &tcph))
        return XDP_DROP;

    th_len = (__u32)tcph->doff * 4;
    if (th_len < sizeof(*tcph) || th_len > TCP_MAXLEN)
        return XDP_DROP;

    __u32 client_seq = tcph->seq;
    __u16 client_sport = tcph->source;
    __u16 client_dport = tcph->dest;
    __u32 client_saddr = iph->saddr;
    __u32 client_daddr = iph->daddr;

    __s64 cookie_ret = bpf_tcp_raw_gen_syncookie_ipv4(iph, tcph, th_len);
    if (cookie_ret < 0)
        return XDP_DROP;
    __u32 cookie = (__u32)cookie_ret;

    /* Swap L2 */
    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, tmp_mac, 6);

    /* Minimal IPv4 + 20-byte TCP SYN-ACK (drop IP/TCP options). */
    iph->saddr = client_daddr;
    iph->daddr = client_saddr;
    iph->ttl = 64;
    iph->tos = 0;
    iph->id = 0;
    iph->ihl = sizeof(*iph) / 4;
    iph->tot_len = bpf_htons((__u16)(sizeof(*iph) + sizeof(struct tcphdr)));
    iph->check = 0;

    tcph = (void *)iph + sizeof(*iph);
    data_end = (void *)(long)ctx->data_end;
    if ((void *)(tcph + 1) > data_end)
        return XDP_DROP;

    tcph->source = client_dport;
    tcph->dest = client_sport;
    tcph->ack_seq = bpf_htonl(bpf_ntohl(client_seq) + 1);
    tcph->seq = bpf_htonl(cookie);
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->ece = 0;
    tcph->cwr = 0;
    tcph->window = bpf_htons(65535);
    tcph->urg_ptr = 0;
    tcph->check = 0;

    {
        __u32 tcp_len = sizeof(struct tcphdr);
        __s64 sum = bpf_csum_diff((__be32 *)0, 0, (__be32 *)tcph, tcp_len, 0);
        if (sum < 0)
            return XDP_DROP;
        tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len,
                                        IPPROTO_TCP, (__u32)sum);
        sum = bpf_csum_diff((__be32 *)0, 0, (__be32 *)iph, sizeof(*iph), 0);
        if (sum < 0)
            return XDP_DROP;
        iph->check = csum_fold((__u32)sum);
    }

    /* Shrink to eth(+vlan) + sizeof(iphdr) + sizeof(tcphdr). */
    {
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        __u32 new_pkt_size = (__u32)((long)(void *)(tcph + 1) - (long)data);
        int delta = (int)new_pkt_size - (int)((long)data_end - (long)data);
        (void)old_pkt_size;
        if (delta != 0 && bpf_xdp_adjust_tail(ctx, delta))
            return XDP_DROP;
    }

    return XDP_TX;
}

/* Fold IPv6 address into a 32-bit det key (per-VIP later). */
static __always_inline __u32 ipv6_addr_hash(const struct in6_addr *a)
{
    return a->s6_addr32[0] ^ a->s6_addr32[1] ^ a->s6_addr32[2] ^ a->s6_addr32[3];
}

static __always_inline __u16 csum_ipv6_magic(const struct in6_addr *saddr,
                                            const struct in6_addr *daddr,
                                            __u32 len, __u8 proto, __u32 csum)
{
    __u64 sum = csum;
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
        sum += (__u32)saddr->s6_addr32[i];
#pragma unroll
    for (i = 0; i < 4; i++)
        sum += (__u32)daddr->s6_addr32[i];
    sum += bpf_htonl(len);
    sum += bpf_htonl(proto);
    sum = (sum & 0xffffffff) + (sum >> 32);
    sum = (sum & 0xffffffff) + (sum >> 32);
    return csum_fold((__u32)sum);
}

static __always_inline int syn_cookie_reparse_v6(struct xdp_md *ctx,
                                                 struct ethhdr **eth_out,
                                                 struct ipv6hdr **ip6_out,
                                                 struct tcphdr **tcph_out)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    __u16 proto = 0;
    void *l3 = eth_skip_vlan(eth, data_end, &proto);
    if (!l3 || proto != ETH_P_IPV6)
        return -1;
    struct ipv6hdr *ip6 = l3;
    if ((void *)(ip6 + 1) > data_end)
        return -1;
    if (ip6->nexthdr != IPPROTO_TCP)
        return -1;
    struct tcphdr *tcph = (void *)(ip6 + 1);
    if ((void *)tcph + TCP_MAXLEN > data_end)
        return -1;
    *eth_out = eth;
    *ip6_out = ip6;
    *tcph_out = tcph;
    return 0;
}

/* IPv6 SYN → SYN-ACK cookie via XDP_TX (no extension headers). */
static __always_inline int syn_cookie_tx_reply_v6(struct xdp_md *ctx, struct ethhdr *eth,
                                                  struct ipv6hdr *ip6, struct tcphdr *tcph)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 th_len = (__u32)tcph->doff * 4;
    if (th_len < sizeof(*tcph) || th_len > TCP_MAXLEN)
        return XDP_DROP;
    if ((void *)tcph + th_len > data_end)
        return XDP_DROP;
    if (tcph->fin || tcph->rst)
        return XDP_DROP;

    if (bpf_xdp_adjust_tail(ctx, (int)TCP_MAXLEN - (int)th_len))
        return XDP_DROP;
    if (syn_cookie_reparse_v6(ctx, &eth, &ip6, &tcph))
        return XDP_DROP;

    th_len = (__u32)tcph->doff * 4;
    if (th_len < sizeof(*tcph) || th_len > TCP_MAXLEN)
        return XDP_DROP;

    __u32 client_seq = tcph->seq;
    __u16 client_sport = tcph->source;
    __u16 client_dport = tcph->dest;
    struct in6_addr client_saddr = ip6->saddr;
    struct in6_addr client_daddr = ip6->daddr;

    __s64 cookie_ret = bpf_tcp_raw_gen_syncookie_ipv6(ip6, tcph, th_len);
    if (cookie_ret < 0)
        return XDP_DROP;
    __u32 cookie = (__u32)cookie_ret;

    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, tmp_mac, 6);

    ip6->saddr = client_daddr;
    ip6->daddr = client_saddr;
    ip6->hop_limit = 64;
    ip6->payload_len = bpf_htons(sizeof(struct tcphdr));
    *(__be32 *)ip6 = bpf_htonl(0x60000000); /* version=6, traffic=0, flow=0 */

    tcph = (void *)(ip6 + 1);
    data_end = (void *)(long)ctx->data_end;
    if ((void *)(tcph + 1) > data_end)
        return XDP_DROP;

    tcph->source = client_dport;
    tcph->dest = client_sport;
    tcph->ack_seq = bpf_htonl(bpf_ntohl(client_seq) + 1);
    tcph->seq = bpf_htonl(cookie);
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->ece = 0;
    tcph->cwr = 0;
    tcph->window = bpf_htons(65535);
    tcph->urg_ptr = 0;
    tcph->check = 0;

    {
        __u32 tcp_len = sizeof(struct tcphdr);
        __s64 sum = bpf_csum_diff((__be32 *)0, 0, (__be32 *)tcph, tcp_len, 0);
        if (sum < 0)
            return XDP_DROP;
        tcph->check = csum_ipv6_magic(&ip6->saddr, &ip6->daddr, tcp_len,
                                      IPPROTO_TCP, (__u32)sum);
    }

    {
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        __u32 new_pkt_size = (__u32)((long)(void *)(tcph + 1) - (long)data);
        int delta = (int)new_pkt_size - (int)((long)data_end - (long)data);
        if (delta != 0 && bpf_xdp_adjust_tail(ctx, delta))
            return XDP_DROP;
    }
    return XDP_TX;
}

#ifndef NEXTHDR_HOP
#define NEXTHDR_HOP        0
#define NEXTHDR_ROUTING    43
#define NEXTHDR_FRAGMENT   44
#define NEXTHDR_DEST       60
#endif

/* Skip common IPv6 extension headers; return L4 start or NULL. */
static __always_inline void *ipv6_skip_exthdr(struct ipv6hdr *ip6, void *data_end,
                                             __u8 *nexthdr_out)
{
    void *p = (void *)(ip6 + 1);
    __u8 nexthdr = ip6->nexthdr;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (nexthdr == NEXTHDR_HOP || nexthdr == NEXTHDR_ROUTING ||
            nexthdr == NEXTHDR_DEST) {
            if (p + 2 > data_end)
                return NULL;
            __u8 hdrlen = *((__u8 *)p + 1);
            nexthdr = *(__u8 *)p;
            p += ((__u32)hdrlen + 1) * 8;
            if (p > data_end)
                return NULL;
        } else if (nexthdr == NEXTHDR_FRAGMENT) {
            if (p + 8 > data_end)
                return NULL;
            nexthdr = *(__u8 *)p;
            p += 8;
        } else {
            break;
        }
    }
    *nexthdr_out = nexthdr;
    return p;
}

/* Update / create flow entry. Returns 1 if mode2 per-flow limit exceeded. */
static __always_inline int flow_observe_and_limit(
    struct iphdr *iph, struct tcphdr *tcph, __u64 now, __u64 packet_size,
    __u16 payload_len, __u8 mode, __u32 flow_pps_limit)
{
    struct flow_key fk = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .sport = tcph->source,
        .dport = tcph->dest,
        .proto = IPPROTO_TCP,
    };
    struct flow_val *fv = bpf_map_lookup_elem(&flows, &fk);
    if (!fv) {
        struct flow_val init = {0};
        init.pkts = 1;
        init.bytes = packet_size;
        init.last_ts = now;
        init.first_ts = now;
        init.win_pkts = 1;
        init.win_start = now;
        init.first_payload = payload_len;
        if (!tcph->syn)
            init.handshake_done = 1;
        bpf_map_update_elem(&flows, &fk, &init, BPF_ANY);
        return 0;
    }

    fv->pkts += 1;
    fv->bytes += packet_size;
    fv->last_ts = now;
    if (!tcph->syn)
        fv->handshake_done = 1;
    if (payload_len > 0) {
        if (fv->first_payload == 0)
            fv->first_payload = payload_len;
        else if (payload_len != fv->first_payload)
            fv->differ_cnt++;
    }

    if (now - fv->win_start > ONE_SECOND_NS) {
        fv->win_pkts = 1;
        fv->win_start = now;
        return 0;
    }
    fv->win_pkts += 1;

    if (mode >= MODE_RATE_LIMIT && flow_pps_limit > 0 &&
        fv->handshake_done && payload_len > 0 &&
        fv->win_pkts > flow_pps_limit)
        return 1;
    return 0;
}

/* Returns 1 if over limit (caller should drop). Window = 1 second. */
static __always_inline int rate_win_over(struct rate_win *w, __u64 now, __u32 limit)
{
    if (!w || limit == 0)
        return 0;
    if (now - w->last_ts > ONE_SECOND_NS) {
        w->count = 1;
        w->last_ts = now;
        return 0;
    }
    w->count += 1;
    return w->count > limit;
}

static __always_inline int src_bucket_over(__u32 src, __u8 class, __u64 now, __u32 limit)
{
    if (limit == 0)
        return 0;
    struct src_bucket_key sk = { .src = src, .class = class };
    struct rate_win *w = bpf_map_lookup_elem(&src_buckets, &sk);
    if (w)
        return rate_win_over(w, now, limit);
    struct rate_win init = { .count = 1, .last_ts = now };
    bpf_map_update_elem(&src_buckets, &sk, &init, BPF_ANY);
    return 0;
}

static __always_inline int dst_cap_over(__u32 dst, __u8 class, __u64 now, __u32 limit)
{
    if (limit == 0)
        return 0;
    struct det_key dk = { .dst = dst, .class = class };
    struct rate_win *w = bpf_map_lookup_elem(&dst_class_rate, &dk);
    if (w)
        return rate_win_over(w, now, limit);
    struct rate_win init = { .count = 1, .last_ts = now };
    bpf_map_update_elem(&dst_class_rate, &dk, &init, BPF_ANY);
    return 0;
}

/* Returns 1 if source exceeded new-flow PPS (HANDSHAKE layer-4). */
static __always_inline int src_new_flow_over(__u32 src, __u64 now, __u32 limit)
{
    if (limit == 0)
        return 0;
    struct rate_win *w = bpf_map_lookup_elem(&src_new_flows, &src);
    if (w)
        return rate_win_over(w, now, limit);
    struct rate_win init = { .count = 1, .last_ts = now };
    bpf_map_update_elem(&src_new_flows, &src, &init, BPF_ANY);
    return 0;
}

static __always_inline __u32 prefix24_of(__u32 addr)
{
    return addr & bpf_htonl(0xffffff00);
}

static __always_inline int conn_win_over(void *map, __u32 key, __u64 now,
                                         __u64 win, __u32 cap)
{
    struct rate_win *w = bpf_map_lookup_elem(map, &key);
    if (!w) {
        struct rate_win init = { .count = 1, .last_ts = now };
        bpf_map_update_elem(map, &key, &init, BPF_ANY);
        return 0;
    }
    if (now - w->last_ts > win) {
        w->count = 1;
        w->last_ts = now;
        return 0;
    }
    w->count += 1;
    return w->count > cap;
}

#define SOCKET_CAP_SRC  1  /* this source is over its own cap → blacklist */
#define SOCKET_CAP_P24  2  /* only its /24 is over → drop, do not blacklist */

/* Connection attempts per src and /24 within the SOCKET window. */
static __always_inline int socket_conn_cap_over(__u32 src, __u32 src_cap, __u32 p24_cap,
                                                __u64 now)
{
    __u64 win = global_fw_config.g_socket_config.socket_fixed_check_duration;
    if (win == 0)
        win = SOCKET_FIXED_CHECK_DURATION_NS;
    if (src_cap > 0 && conn_win_over(&src_conn_count, src, now, win, src_cap))
        return SOCKET_CAP_SRC;
    if (p24_cap > 0 &&
        conn_win_over(&prefix24_conn_count, prefix24_of(src), now, win, p24_cap))
        return SOCKET_CAP_P24;
    return 0;
}

/* Effective mitigation mode for {dst,class}; host-wide fallback dst=0. */
static __always_inline __u8 mitigation_mode_for(__u32 dst, __u8 class, __u64 now)
{
    struct det_key k = { .dst = dst, .class = class };
    struct mode_val *m = bpf_map_lookup_elem(&mitigation_mode, &k);
    if ((!m || m->mode == MODE_OFF) && dst != 0) {
        k.dst = 0;
        m = bpf_map_lookup_elem(&mitigation_mode, &k);
    }
    if (!m || m->mode == MODE_OFF)
        return MODE_OFF;
    /* Watchdog fail-closed: stale publish → keep drop-invalid, not observe-only. */
    if (m->expires_ns != 0 && now > m->expires_ns)
        return MODE_DROP_INVALID;
    return m->mode;
}

/* Phase 4: drop packets that fail cheap validity when mode ≥ DROP_INVALID.
 * Returns 1 if caller should XDP_DROP. */
static __always_inline int should_drop_invalid(
    struct xdp_md *ctx, struct iphdr *iph,
    __u8 dclass, __u8 mode,
    __u8 have_tcp, void *l4, void *data_end,
    __u8 tcp_syn, __u8 tcp_ack, __u8 tcp_fin, __u8 tcp_rst)
{
    if (mode < MODE_DROP_INVALID)
        return 0;

    volatile struct service_profile *svc = &global_fw_config.g_config.svc;

    /* SOCKET / flag anomalies: do NOT silent-drop here. Tail-call key 7
     * (xdp_parse_tcp_socket) rate-limits and report_block_ip's the source.
     * Dropping here left SOCKET Attack with zero reported IPs. */

    /* UDP: allowlisted dest ports; reflection source ports are invalid. */
    if (dclass == DET_CLASS_UDP && l4 &&
        (void *)((struct udphdr *)l4 + 1) <= data_end) {
        struct udphdr *uh = l4;
        __u16 dport = bpf_ntohs(uh->dest);
        __u16 sport = bpf_ntohs(uh->source);
        if (bpf_map_lookup_elem(&udp_reflection_sports, &sport))
            return 1;
        if (!bpf_map_lookup_elem(&udp_allowed_dports, &dport))
            return 1;
        /* Optional QUIC: UDP/443 long-header Initial should be ≥ 1200. */
        if (svc->quic_header_check && dport == 443) {
            __u16 ulen = bpf_ntohs(uh->len);
            if (ulen >= sizeof(*uh) + 1) {
                __u8 *payload = (__u8 *)(uh + 1);
                if ((void *)(payload + 1) <= data_end) {
                    __u8 first = *payload;
                    /* Long header: form bit set (0x80). */
                    if (first & 0x80) {
                        __u16 plen = ulen - sizeof(*uh);
                        if (plen < 1200)
                            return 1;
                    }
                }
            }
        }
        return 0;
    }

    /* ICMP: only allowed types. */
    if (dclass == DET_CLASS_ICMP && l4 &&
        (void *)((struct icmphdr *)l4 + 1) <= data_end) {
        struct icmphdr *ih = l4;
        __u8 itype = ih->type;
        if (svc->icmp_drop_fragments) {
            __u16 frag_off_host = bpf_ntohs(iph->frag_off);
            if (frag_off_host & 0x1FFF)
                return 1;
        }
        if (!bpf_map_lookup_elem(&icmp_allowed_types, &itype))
            return 1;
        return 0;
    }

    /* GRE: drop all unless tunnels enabled and peer allowlisted. */
    if (dclass == DET_CLASS_GRE) {
        if (!svc->gre_tunnels)
            return 1;
        if (!bpf_map_lookup_elem(&gre_allowed_peers, &iph->saddr))
            return 1;
        return 0;
    }

    /* SYN-ACK: must match a recently recorded outbound SYN (H7). */
    if (dclass == DET_CLASS_SYNACK && have_tcp && l4 &&
        (void *)((struct tcphdr *)l4 + 1) <= data_end &&
        svc->synack_match_outbound) {
        struct tcphdr *tcph = l4;
        struct outbound_syn_key ok = {
            .saddr = iph->daddr,
            .daddr = iph->saddr,
            .sport = tcph->dest,
            .dport = tcph->source,
        };
        struct outbound_syn_val *ov = bpf_map_lookup_elem(&outbound_syn, &ok);
        if (!ov)
            return 1;
        __u32 expect = bpf_htonl(bpf_ntohl(ov->seq) + 1);
        if (tcph->ack_seq != expect)
            return 1;
        bpf_map_delete_elem(&outbound_syn, &ok);
        return 0;
    }

    /* Out-of-state TCP: socket lookup miss and no conntrack mirror → invalid.
     * Exception: valid SYN-cookie ACK (XDP issued the cookie SYN-ACK). */
    if (have_tcp && l4 && (void *)((struct tcphdr *)l4 + 1) <= data_end) {
        struct tcphdr *tcph = l4;
        if (!tcp_syn) {
            if (dclass == DET_CLASS_ACK || dclass == DET_CLASS_DATA ||
                dclass == DET_CLASS_RST ||
                (tcp_fin && tcp_ack && !tcp_syn && !tcp_rst)) {
                __u8 valid = tcp_flow_valid(ctx, iph, tcph);
                if (valid) {
                    count_valid_pass(valid - 1);
                } else {
                    if (tcp_ack && !tcp_rst && !tcp_fin &&
                        bpf_tcp_raw_check_syncookie_ipv4(iph, tcph) == 0) {
                        __u64 grace = bpf_ktime_get_ns() + SYN_GRACE_PERIOD_NS;
                        __u32 sip = iph->saddr;
                        bpf_map_update_elem(&syn_validated_ips, &sip, &grace, BPF_ANY);
                        count_valid_pass(PASS_REASON_COOKIE);
                        return 0;
                    }
                    return 1;
                }
            }
        }
    }

    return 0;
}

static __always_inline __u16 tcp_payload_bytes(struct iphdr *iph, struct tcphdr *tcph)
{
    __u16 tot = bpf_ntohs(iph->tot_len);
    __u32 ihl = (__u32)iph->ihl * 4;
    __u32 doff = (__u32)tcph->doff * 4;
    if (tot < ihl + doff)
        return 0;
    return (__u16)(tot - ihl - doff);
}

/* Exclusive class for one IPv4 packet. Also emits invalid_* counters when
 * stage-0 anomalies are visible (instrumentation only — drops unchanged). */
static __always_inline __u8 det_classify_and_invalid(
    struct iphdr *iph, void *l4, void *data_end, __u8 have_tcp,
    __u8 tcp_syn, __u8 tcp_ack, __u8 tcp_fin, __u8 tcp_rst,
    __u8 tcp_psh, __u8 tcp_urg)
{
    __u32 dst = iph->daddr;
    __u32 src = iph->saddr;

    if (iph->ihl < 5)
        invalid_count(dst, INVALID_BAD_IHL);
    if (src == dst)
        invalid_count(dst, INVALID_LAND);
    {
        __u16 frag_off_host = bpf_ntohs(iph->frag_off);
        if (frag_off_host & 0x1FFF) {
            if (iph->protocol == IPPROTO_TCP)
                invalid_count(dst, INVALID_TCP_FRAG);
            /* Exclusive FRAG class for rate (stage0 still drops TCP frags). */
            return DET_CLASS_FRAG;
        }
    }
    {
        /* N4: tot_len must fit remaining frame from L3 start. */
        void *l3 = (void *)iph;
        __u32 avail = (__u32)((long)data_end - (long)l3);
        __u16 tot = bpf_ntohs(iph->tot_len);
        if (tot < sizeof(*iph) || tot > avail)
            invalid_count(dst, INVALID_BAD_TOTLEN);
    }

    if (iph->protocol == IPPROTO_ICMP)
        return DET_CLASS_ICMP;
    if (iph->protocol == IPPROTO_UDP)
        return DET_CLASS_UDP;
    if (iph->protocol == IPPROTO_GRE)
        return DET_CLASS_GRE;
    if (!have_tcp)
        return DET_CLASS_OTHER;

    struct tcphdr *tcph = l4;
    if ((void *)(tcph + 1) > data_end)
        return DET_CLASS_OTHER;
    if (tcph->doff < 5)
        invalid_count(dst, INVALID_BAD_DOFF);

    __u8 flags = 0;
    if (tcp_fin) flags |= 0x01;
    if (tcp_syn) flags |= 0x02;
    if (tcp_rst) flags |= 0x04;
    if (tcp_psh) flags |= 0x08;
    if (tcp_ack) flags |= 0x10;
    if (tcp_urg) flags |= 0x20;

    if (flags == 0x00) {
        invalid_count(dst, INVALID_FLAG_NULL);
        return DET_CLASS_SOCKET;
    }
    if (flags == 0x29 || flags == 0x39) { /* XMAS / XMAS+ACK */
        invalid_count(dst, INVALID_FLAG_XMAS);
        return DET_CLASS_SOCKET;
    }
    if (tcp_syn && tcp_fin) {
        invalid_count(dst, INVALID_FLAG_SYN_FIN);
        return DET_CLASS_SOCKET;
    }
    if (tcp_syn && tcp_rst) {
        invalid_count(dst, INVALID_FLAG_SYN_RST);
        return DET_CLASS_SOCKET;
    }
    if (tcp_syn && tcp_urg) {
        invalid_count(dst, INVALID_FLAG_SYN_URG);
        return DET_CLASS_SOCKET;
    }
    if (tcp_fin && !tcp_ack && !tcp_syn && !tcp_rst) {
        invalid_count(dst, INVALID_FLAG_FIN_ONLY);
        return DET_CLASS_SOCKET;
    }
    /* URG+ACK scan (no PSH) — was swallowed by bare ACK and mislabeled. */
    if (tcp_urg && tcp_ack && !tcp_psh && !tcp_syn && !tcp_rst) {
        invalid_count(dst, INVALID_FLAG_NULL);
        return DET_CLASS_SOCKET;
    }
    /* PSH without ACK — not a valid data segment. */
    if (tcp_psh && !tcp_ack && !tcp_syn && !tcp_rst) {
        invalid_count(dst, INVALID_FLAG_NULL);
        return DET_CLASS_SOCKET;
    }
    /* FIN+PSH (±URG) without a normal ACK data path. */
    if (tcp_fin && tcp_psh && !tcp_syn && !tcp_rst) {
        invalid_count(dst, INVALID_FLAG_XMAS);
        return DET_CLASS_SOCKET;
    }

    if (tcp_syn && tcp_ack)
        return DET_CLASS_SYNACK;
    if (tcp_syn && !tcp_ack) {
        __u16 syn_plen = tcp_payload_bytes(iph, tcph);
        if (syn_plen > 0)
            invalid_count(dst, INVALID_SYN_PAYLOAD);
        return DET_CLASS_SYN;
    }
    if (tcp_rst)
        return DET_CLASS_RST;

    __u16 plen = tcp_payload_bytes(iph, tcph);
    /*
     * DATA / STOMP path: PSH+ACK with payload only.
     * ACK+payload without PSH is a common ACK-flood tool pattern and must
     * stay in DET_CLASS_ACK (not STOMP) — otherwise ACK:N / PSH+ACK:≪N
     * floods are mis-reported as DATA/STOMP.
     */
    if (plen > 0 && tcp_psh && tcp_ack && !tcp_syn && !tcp_rst && !tcp_urg && !tcp_fin)
        return DET_CLASS_DATA;
    /* FIN(+ACK) — exclusive FIN class (not SOCKET), unless PSH/URG above. */
    if (tcp_fin && tcp_ack && !tcp_psh && !tcp_urg)
        return DET_CLASS_FIN;
    if (tcp_ack && !tcp_urg && !tcp_fin)
        return DET_CLASS_ACK;
    return DET_CLASS_SOCKET;
}

/*=============================================================================================================
 *                                      XDP Main
 *============================================================================================================*/
SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 key = 0;
    struct traffic_stats_config *traffic_stats = bpf_map_lookup_elem(&global_income_pkt_traffic, &key);
    if (!traffic_stats) return XDP_PASS;

    /* Byte counters see every frame the NIC delivers, like /proc/net/dev and nload:
     * non-IPv4 (ARP, IPv6, VLAN) and whitelisted sources included. */
    __u64 packet_size = (__u64)((unsigned long)data_end - (unsigned long)data);
    traffic_stats->total_traffic += packet_size;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        traffic_stats->other += packet_size;
        return XDP_PASS;
    }

    /* C5: peel 802.1Q / QinQ; IPv4 full path, IPv6 det/stage0 path. */
    __u16 eth_proto = 0;
    void *l3 = eth_skip_vlan(eth, data_end, &eth_proto);
    if (!l3) {
        traffic_stats->other += packet_size;
        return XDP_PASS;
    }

    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end) {
            traffic_stats->other += packet_size;
            return XDP_PASS;
        }
        __u8 nexthdr = 0;
        void *l4v6 = ipv6_skip_exthdr(ip6, data_end, &nexthdr);
        __u32 dst6 = ipv6_addr_hash(&ip6->daddr);
        __u32 src6 = ipv6_addr_hash(&ip6->saddr);
        __u8 dclass6 = DET_CLASS_OTHER;
        __u8 tcp_syn6 = 0, tcp_ack6 = 0, tcp_fin6 = 0, tcp_rst6 = 0;
        __u8 tcp_psh6 = 0, tcp_urg6 = 0;

        if (nexthdr == IPPROTO_TCP && l4v6 &&
            (void *)((struct tcphdr *)l4v6 + 1) <= data_end) {
            struct tcphdr *t6 = l4v6;
            traffic_stats->tcp += packet_size;
            tcp_syn6 = t6->syn; tcp_ack6 = t6->ack;
            tcp_fin6 = t6->fin; tcp_rst6 = t6->rst;
            tcp_psh6 = t6->psh; tcp_urg6 = t6->urg;
            if (tcp_syn6 && tcp_ack6)
                dclass6 = DET_CLASS_SYNACK;
            else if (tcp_syn6)
                dclass6 = DET_CLASS_SYN;
            else if (tcp_rst6)
                dclass6 = DET_CLASS_RST;
            else if (tcp_ack6) {
                __u32 doff6 = (__u32)t6->doff * 4;
                __u16 plen6 = bpf_ntohs(ip6->payload_len);
                /* Same as IPv4: only PSH+ACK+payload → DATA/STOMP. */
                if (plen6 > doff6 && tcp_psh6 && !tcp_syn6 && !tcp_rst6)
                    dclass6 = DET_CLASS_DATA;
                else if (tcp_fin6)
                    dclass6 = DET_CLASS_FIN;
                else
                    dclass6 = DET_CLASS_ACK;
            } else {
                dclass6 = DET_CLASS_SOCKET;
            }
            /* Flag anomalies */
            if ((!tcp_syn6 && !tcp_ack6 && !tcp_fin6 && !tcp_rst6 &&
                 !tcp_psh6 && !tcp_urg6) ||
                (tcp_syn6 && tcp_fin6) || (tcp_syn6 && tcp_rst6) ||
                (tcp_syn6 && tcp_urg6) ||
                (tcp_fin6 && !tcp_ack6 && !tcp_syn6 && !tcp_rst6))
                dclass6 = DET_CLASS_SOCKET;
            if (tcp_syn6 && !tcp_ack6)
                traffic_stats->syn += packet_size;
        } else if (nexthdr == IPPROTO_UDP) {
            traffic_stats->udp += packet_size;
            dclass6 = DET_CLASS_UDP;
        } else if (nexthdr == IPPROTO_ICMPV6) {
            traffic_stats->icmp += packet_size;
            dclass6 = DET_CLASS_ICMP;
        } else {
            traffic_stats->other += packet_size;
        }

        det_count(dst6, dclass6, packet_size);
        if (!global_fw_config.g_config.svc.ipv6_enabled) {
            traffic_stats->other += packet_size;
            return XDP_PASS; /* observe-only when ipv6=0 */
        }
        if (src6 == dst6 || dclass6 == DET_CLASS_SOCKET) {
            count_drop_invalid();
            traffic_stats->blocked_traffic += packet_size;
            return XDP_DROP;
        }

        __u64 now6 = bpf_ktime_get_ns();
        volatile struct global_config *gcfg6 = &global_fw_config.g_config;
        if (gcfg6->enforce_drop_invalid) {
            __u8 mode6 = mitigation_mode_for(dst6, dclass6, now6);
            if (mode6 >= MODE_DROP_INVALID) {
                /* UDP allowlist / reflection (same maps as v4). */
                if (dclass6 == DET_CLASS_UDP && l4v6 &&
                    (void *)((struct udphdr *)l4v6 + 1) <= data_end) {
                    struct udphdr *uh6 = l4v6;
                    __u16 dport = bpf_ntohs(uh6->dest);
                    __u16 sport = bpf_ntohs(uh6->source);
                    if (bpf_map_lookup_elem(&udp_reflection_sports, &sport) ||
                        !bpf_map_lookup_elem(&udp_allowed_dports, &dport)) {
                        count_drop_invalid();
                        traffic_stats->blocked_traffic += packet_size;
                        return XDP_DROP;
                    }
                }
                if (nexthdr == IPPROTO_TCP && l4v6 &&
                    (void *)((struct tcphdr *)l4v6 + 1) <= data_end) {
                    struct tcphdr *t6 = l4v6;
                    /* IPv6 SYN cookie via XDP_TX when mitigating. */
                    if (dclass6 == DET_CLASS_SYN && mode6 >= MODE_DROP_INVALID) {
                        int cret = syn_cookie_tx_reply_v6(ctx, eth, ip6, t6);
                        if (cret == XDP_TX) {
                            traffic_stats->blocked_traffic += packet_size;
                            return XDP_TX;
                        }
                        traffic_stats->blocked_traffic += packet_size;
                        return XDP_DROP;
                    }
                    if (!tcp_syn6 && (dclass6 == DET_CLASS_ACK ||
                                      dclass6 == DET_CLASS_DATA ||
                                      dclass6 == DET_CLASS_RST)) {
                        if (tcp_ack6 && !tcp_rst6 && !tcp_fin6 &&
                            bpf_tcp_raw_check_syncookie_ipv6(ip6, t6) == 0) {
                            __u64 grace = now6 + SYN_GRACE_PERIOD_NS;
                            bpf_map_update_elem(&syn_validated_ips, &src6, &grace, BPF_ANY);
                            return XDP_PASS;
                        }
                    }
                }
                if (mode6 >= MODE_RATE_LIMIT) {
                    __u32 lim_key = dclass6;
                    struct mode_limits *lim = bpf_map_lookup_elem(&mode_limits, &lim_key);
                    if (lim && lim->src_pps > 0 &&
                        src_bucket_over(src6, dclass6, now6, lim->src_pps)) {
                        count_drop_mode2();
                        traffic_stats->blocked_traffic += packet_size;
                        return XDP_DROP;
                    }
                    if (lim && mode6 >= MODE_DST_CAP && lim->dst_pps > 0 &&
                        dst_cap_over(dst6, dclass6, now6, lim->dst_pps)) {
                        count_drop_mode3();
                        traffic_stats->blocked_traffic += packet_size;
                        return XDP_DROP;
                    }
                }
            }
        }
        return XDP_PASS;
    }

    if (eth_proto != ETH_P_IP) {
        traffic_stats->other += packet_size;
        return XDP_PASS;
    }

    struct iphdr *iph = l3;
    if ((void *)(iph + 1) > data_end) {
        traffic_stats->other += packet_size;
        return XDP_PASS;
    }

    __u8 have_tcp = 0;
    __u8 tcp_syn = 0, tcp_ack = 0, tcp_fin = 0, tcp_rst = 0, tcp_psh = 0, tcp_urg = 0;
    void *l4 = NULL;

    if (iph->protocol == IPPROTO_TCP) {
        traffic_stats->tcp += packet_size;
        int ip_hdr_len = iph->ihl * 4;
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void*)(tcph + 1) <= data_end) {
            have_tcp = 1;
            l4 = tcph;
            tcp_syn = tcph->syn;
            tcp_ack = tcph->ack;
            tcp_fin = tcph->fin;
            tcp_rst = tcph->rst;
            tcp_psh = tcph->psh;
            tcp_urg = tcph->urg;
            if (tcp_syn && !tcp_ack)
                traffic_stats->syn += packet_size;
            if (tcp_rst && !tcp_ack)
                traffic_stats->rst += packet_size;
            if (tcp_ack && !tcp_syn && !tcp_fin && !tcp_rst && !tcp_psh)
                traffic_stats->ack += packet_size;
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        traffic_stats->icmp += packet_size;
    } else if (iph->protocol == IPPROTO_UDP) {
        traffic_stats->udp += packet_size;
    } else if (iph->protocol == IPPROTO_GRE) {
        traffic_stats->gre += packet_size;
    } else {
        traffic_stats->other += packet_size;
    }

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;

    /* Phase 1 H2/M6: count {dst,class} before any verdict, including whitelist. */
    __u8 dclass = det_classify_and_invalid(
        iph, l4, data_end, have_tcp,
        tcp_syn, tcp_ack, tcp_fin, tcp_rst, tcp_psh, tcp_urg);
    det_count(dst_ip, dclass, packet_size);

    __u8 *whitelisted = bpf_map_lookup_elem(&allowed_ips, &src_ip);
    if (whitelisted)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();

    /* Stage 0: always-on drops (land, flag anomalies, bad lens, TCP frags, SYN+data). */
    {
        __u8 stage0 = 0;
        if (src_ip == dst_ip || dclass == DET_CLASS_SOCKET)
            stage0 = 1;
        if (iph->ihl < 5)
            stage0 = 1;
        {
            __u32 avail = (__u32)((long)data_end - (long)(void *)iph);
            __u16 tot = bpf_ntohs(iph->tot_len);
            if (tot < sizeof(*iph) || tot > avail)
                stage0 = 1;
        }
        if (have_tcp && l4 && (void *)((struct tcphdr *)l4 + 1) <= data_end) {
            struct tcphdr *t0 = l4;
            if (t0->doff < 5)
                stage0 = 1;
            {
                __u16 frag_off_host = bpf_ntohs(iph->frag_off);
                if (frag_off_host & 0x1FFF)
                    stage0 = 1;
            }
            if (tcp_syn && !tcp_ack && tcp_payload_bytes(iph, t0) > 0)
                stage0 = 1;
        }
        if (stage0) {
            count_drop_invalid();
            traffic_stats->blocked_traffic += packet_size;
            return XDP_DROP;
        }
    }

    volatile struct global_config *gcfg = &global_fw_config.g_config;

    /* Phase 4–5: adaptive mitigation modes. */
    if (gcfg->enforce_drop_invalid) {
        __u8 mode = mitigation_mode_for(dst_ip, dclass, now);
        if (should_drop_invalid(ctx, iph, dclass, mode, have_tcp, l4, data_end,
                                tcp_syn, tcp_ack, tcp_fin, tcp_rst)) {
            count_drop_invalid();
            traffic_stats->blocked_traffic += packet_size;
            return XDP_DROP;
        }
        if (mode >= MODE_RATE_LIMIT || mode >= MODE_DST_CAP) {
            __u32 lim_key = dclass;
            struct mode_limits *lim = bpf_map_lookup_elem(&mode_limits, &lim_key);
            if (lim) {
                if (mode >= MODE_RATE_LIMIT &&
                    src_bucket_over(src_ip, dclass, now, lim->src_pps)) {
                    count_drop_mode2();
                    traffic_stats->blocked_traffic += packet_size;
                    return XDP_DROP;
                }
                /* HANDSHAKE: new-flow rate per source (SYNs creating new 4-tuples). */
                if (mode >= MODE_RATE_LIMIT && dclass == DET_CLASS_SYN &&
                    lim->new_flow_pps > 0 &&
                    src_new_flow_over(src_ip, now, lim->new_flow_pps)) {
                    count_drop_mode2();
                    traffic_stats->blocked_traffic += packet_size;
                    return XDP_DROP;
                }
                /* SOCKET: connection-attempt caps per src and /24.
                 * Report as SOCKET (not silent SYN drop) so backend sees IPs. */
                if (mode >= MODE_RATE_LIMIT && dclass == DET_CLASS_SYN &&
                    (lim->socket_src_cap > 0 || lim->socket_prefix24_cap > 0)) {
                    int cap_hit = socket_conn_cap_over(src_ip, lim->socket_src_cap,
                                                       lim->socket_prefix24_cap, now);
                    if (cap_hit) {
                        count_drop_mode2();
                        det_count(dst_ip, DET_CLASS_SOCKET, packet_size);
                        __u64 *bl = bpf_map_lookup_elem(&blocked_ips, &src_ip);
                        if (bl || cap_hit == SOCKET_CAP_P24) {
                            traffic_stats->blocked_traffic += packet_size;
                            return XDP_DROP;
                        }
                        return block_ip_with_event(src_ip, now,
                            EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK,
                            traffic_stats, packet_size);
                    }
                }
                /* Per-flow DATA limit (layer 4). */
                if (mode >= MODE_RATE_LIMIT && have_tcp && l4 &&
                    dclass == DET_CLASS_DATA && lim->flow_pps > 0) {
                    struct tcphdr *tcph_fl = l4;
                    if ((void *)(tcph_fl + 1) <= data_end) {
                        __u16 plen = tcp_payload_bytes(iph, tcph_fl);
                        if (flow_observe_and_limit(iph, tcph_fl, now, packet_size,
                                                   plen, mode, lim->flow_pps)) {
                            count_drop_flow();
                            traffic_stats->blocked_traffic += packet_size;
                            return XDP_DROP;
                        }
                    }
                } else if (have_tcp && l4 && (void *)((struct tcphdr *)l4 + 1) <= data_end) {
                    /* Still observe flows outside DATA attack for baselines. */
                    struct tcphdr *tcph_fl = l4;
                    __u16 plen = (dclass == DET_CLASS_DATA) ?
                                 tcp_payload_bytes(iph, tcph_fl) : 0;
                    flow_observe_and_limit(iph, tcph_fl, now, packet_size, plen, 0, 0);
                }
                if (mode >= MODE_DST_CAP &&
                    dst_cap_over(dst_ip, dclass, now, lim->dst_pps)) {
                    count_drop_mode3();
                    traffic_stats->blocked_traffic += packet_size;
                    return XDP_DROP;
                }
            }
        } else if (have_tcp && l4 && (void *)((struct tcphdr *)l4 + 1) <= data_end) {
            /* Observe flows even when not in Attack (for learning / labels). */
            struct tcphdr *tcph_fl = l4;
            __u16 plen = (dclass == DET_CLASS_DATA) ?
                         tcp_payload_bytes(iph, tcph_fl) : 0;
            flow_observe_and_limit(iph, tcph_fl, now, packet_size, plen, 0, 0);
        }
    }

    struct stats_config *pkt_stats = bpf_map_lookup_elem(&global_income_pkt_counter, &key);
    if (!pkt_stats) return XDP_PASS;
    __u32 sdiv = gcfg->stats_detail_sample_divisor;
    if (sdiv == 0) sdiv = 1;
    if (sdiv > 64) sdiv = 64;
    __u32 det_scale = 1;
    if (sdiv > 1) {
        if (bpf_get_prandom_u32() % sdiv != 0)
            det_scale = 0;
        else
            det_scale = sdiv;
    }

    if (det_scale) {
        if (have_tcp) {
            if (tcp_syn && !tcp_ack)
                pkt_stats->syn += det_scale;
            if (tcp_rst && !tcp_ack)
                pkt_stats->rst += det_scale;
            if (tcp_urg && !tcp_ack)
                pkt_stats->urg += det_scale;
            if (tcp_psh && !tcp_syn && !tcp_ack && !tcp_rst)
                pkt_stats->psh += det_scale;
            if (tcp_fin && !tcp_ack)
                pkt_stats->fin += det_scale;
            if (tcp_ack && !tcp_syn && !tcp_fin && !tcp_rst && !tcp_psh)
                pkt_stats->ack += det_scale;
            if (tcp_syn && tcp_ack)
                pkt_stats->syn_ack += det_scale;
            if (tcp_fin && tcp_ack)
                pkt_stats->fin_ack += det_scale;
            if (tcp_rst && tcp_ack)
                pkt_stats->rst_ack += det_scale;
            if (tcp_psh && tcp_ack)
                pkt_stats->psh_ack += det_scale;
        } else if (iph->protocol == IPPROTO_ICMP) {
            pkt_stats->icmp += det_scale;
        } else if (iph->protocol == IPPROTO_UDP) {
            pkt_stats->udp += det_scale;
        } else if (iph->protocol == IPPROTO_GRE) {
            pkt_stats->gre += det_scale;
        }
    }

    /* Blocklist check */
    __u64 *blocked_exp = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked_exp) {
        if (now < *blocked_exp) {
            if (have_tcp && tcp_psh && tcp_ack && !tcp_syn && !tcp_rst)
                count_psh_ack_filtered();
            traffic_stats->blocked_traffic += packet_size;
            return XDP_DROP;
        }
        struct event evt = {0};
        evt.time = now; evt.srcip = src_ip; evt.reason = EVENT_IP_BLOCK_END;
        bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
        bpf_map_delete_elem(&blocked_ips, &src_ip);
    }

    /* Fragment mitigation */
    __u8 tcp_seg_check = gcfg->tcp_seg_check;
    if (tcp_seg_check) {
        __u16 frag_off_host = bpf_ntohs(iph->frag_off);
        if (frag_off_host & 0x1FFF) {
            __u64 *last = bpf_map_lookup_elem(&frag_event_last, &src_ip);
            if (!last || now - *last > FRAG_EVENT_INTERVAL_NS) {
                struct event evt = {0};
                evt.time = now; evt.srcip = src_ip; evt.reason = EVENT_IP_FRAG_MIDDLE_BLOCK;
                bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
                bpf_map_update_elem(&frag_event_last, &src_ip, &now, BPF_ANY);
            }
            traffic_stats->blocked_traffic += packet_size;
            return XDP_DROP;
        }
    }

    if (have_tcp && !tcp_syn) {
        int ip_hdr_len_fp = iph->ihl * 4;
        struct tcphdr *tcph_fp = (void *)iph + ip_hdr_len_fp;
        if ((void*)(tcph_fp + 1) <= data_end) {
            /* During a PSH+ACK flood, do not fast-path these packets.
             * The selected STOMP or HANDSHAKE handler applies the fixed-window
             * and burst filter, including flows conntrack already marked established. */
            __u8 psh_ack = tcp_psh && tcp_ack && !tcp_rst;
            volatile struct global_attack_stats *atk = &global_fw_config.g_attack_stats;
            __u8 psh_under_attack = psh_ack && (atk->stomp_attack || atk->handshake_attack);
            if (!psh_under_attack && is_tcp_established(src_ip, tcph_fp->source)) {
                /* Known established connection — pass without rate limiting.
                 * Still count in traffic stats and check geo. */
                if (!is_geo_allowed(src_ip)) {
                    traffic_stats->blocked_traffic += packet_size;
                    return XDP_DROP;
                }
                return XDP_PASS;
            }
        }
    }

    /* Geo: pure SYN is handled in xdp_parse_syn (tail call) so we do not pay LPM/cache
     * work in xdp_main before tail_call — cuts per-packet cost on the hottest path. */
    if (!(have_tcp && tcp_syn && !tcp_ack)) {
        if (!is_geo_allowed(src_ip)) {
            traffic_stats->blocked_traffic += packet_size;
            return XDP_DROP;
        }
    }
    
    /* TCP dispatch: DATA = PSH+ACK+payload → STOMP/HS; bare/padded ACK → ACK. */
    if (have_tcp) {
        if (dclass == DET_CLASS_SYN)
            bpf_tail_call(ctx, &prog_array, 0);
        if (dclass == DET_CLASS_SYNACK)
            bpf_tail_call(ctx, &prog_array, 10);
        if (dclass == DET_CLASS_DATA)
            bpf_tail_call(ctx, &prog_array, 6);       /* STOMP / HANDSHAKE labels */
        if (dclass == DET_CLASS_ACK)
            bpf_tail_call(ctx, &prog_array, 1);
        if (dclass == DET_CLASS_RST || tcp_rst)
            bpf_tail_call(ctx, &prog_array, 2);
        bpf_tail_call(ctx, &prog_array, 7);           /* SOCKET / other TCP */
    } else if (iph->protocol == IPPROTO_ICMP) {
        int ip_hdr_len = iph->ihl * 4;
        struct icmphdr *icmph = (void *)iph + ip_hdr_len;
        if ((void*)(icmph + 1) > data_end) return XDP_PASS;
        bpf_tail_call(ctx, &prog_array, 3);
    } else if (iph->protocol == IPPROTO_UDP) {
        int ip_hdr_len = iph->ihl * 4;
        struct udphdr *udphdr = (void *)iph + ip_hdr_len;
        if ((void*)(udphdr + 1) > data_end) return XDP_PASS;
        bpf_tail_call(ctx, &prog_array, 4);
    } else if (iph->protocol == IPPROTO_GRE) {
        bpf_tail_call(ctx, &prog_array, 5);
    }

    return XDP_PASS;
}


/*=============================================================================================================
 *                                      XDP SYN Defense (Key 0)
 *============================================================================================================*/
 struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_syn_pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, struct flood_stats);
} syn_counter_fixed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, struct burst_state);
} burst_syn_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, struct challenge_state);
} syn_challenge SEC(".maps");

/*
 * SYN path (Attack): SYN cookie via bpf_tcp_raw_gen_syncookie_ipv4 + XDP_TX.
 * Cookie ACKs write syn_validated_ips in should_drop_invalid.
 */
SEC("xdp")
int xdp_parse_syn(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();
    __u64 packet_size = ctx->data_end - ctx->data;
    __u32 key = 0;

    struct traffic_stats_config *traffic_stats = bpf_map_lookup_elem(&global_income_pkt_traffic, &key);
    if (!traffic_stats) return XDP_PASS;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct iphdr *ip = parse_ipv4(data, data_end);
    if (!ip) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    int ihl = ip->ihl * 4;
    if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end) return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void*)(tcp + 1) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    key = 0;


    __u8 *whitelisted = bpf_map_lookup_elem(&allowed_ips, &src_ip);
    if (whitelisted)
        return XDP_PASS;

    __u64 *blocked_exp = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked_exp) {
        if (now < *blocked_exp) {
            traffic_stats->blocked_traffic += packet_size;
            return XDP_DROP;
        }
        struct event evt = {0};
        evt.time = now; evt.srcip = src_ip; evt.reason = EVENT_IP_BLOCK_END;
        bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
        bpf_map_delete_elem(&blocked_ips, &src_ip);
    }

    if (!is_geo_allowed(src_ip)) {
        traffic_stats->blocked_traffic += packet_size;
        return XDP_DROP;
    }

    volatile struct syn_config *config = &global_fw_config.g_syn_config;
    __u64 *pkt_cnt = bpf_map_lookup_elem(&global_syn_pkt_counter, &key);
    if (!pkt_cnt) return XDP_PASS;

    /* ---- If SYN protection is disabled, pass everything ---- */
    if (config->valid == 0) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }

    /* ---- FAST PATH 1: IP has existing established connections ---- */
    if (is_tcp_established(src_ip, tcp->source)) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }

    /*
     * Count every SYN from sources not in the established fast-path toward global PPS.
     * Must run before any XDP_DROP / XDP_TX so userspace sees flood volume.
     */
    __sync_fetch_and_add(pkt_cnt, 1);

    volatile struct global_attack_stats *g_atk = &global_fw_config.g_attack_stats;
    volatile struct global_config *gcfg = &global_fw_config.g_config;
    __u8 syn_mitigating = g_atk->syn_attack;
    if (!syn_mitigating && gcfg->enforce_drop_invalid)
        syn_mitigating = mitigation_mode_for(dst_ip, DET_CLASS_SYN, now) >= MODE_DROP_INVALID;
    if (!syn_mitigating)
        return XDP_PASS;

    /* ======================================================================
     * ATTACK MODE — fixed window (all SYNs) + burst + cookie for the rest
     * Fixed window MUST run before cookies: otherwise high-rate bots are only
     * challenged and never report_block_ip'd (cookie path never reached fixed).
     * ====================================================================== */

    /* ---- Fixed window rate limiting (per-IP) — every SYN in Attack ---- */
    {
        struct flood_stats *fixed_stats = bpf_map_lookup_elem(&syn_counter_fixed, &src_ip);
        if (fixed_stats) {
            __u64 td = now - fixed_stats->last_ts;
            if (config->syn_fixed_check_duration > 0 && td > config->syn_fixed_check_duration) {
                fixed_stats->count = 1; fixed_stats->last_ts = now;
            } else {
                fixed_stats->count += 1;
            }
        } else {
            struct flood_stats ns = {0}; ns.count = 1; ns.last_ts = now;
            bpf_map_update_elem(&syn_counter_fixed, &src_ip, &ns, BPF_ANY);
            fixed_stats = bpf_map_lookup_elem(&syn_counter_fixed, &src_ip);
        }

        if (fixed_stats && fixed_stats->count > config->syn_fixed_threshold) {
            if (fixed_stats->count == config->syn_fixed_threshold + 1) {
                struct fixed_ip_event fe = {0};
                fe.srcip = src_ip; fe.fixed_type = FIXED_IP_RING_BUF_SYN;
                fe.duration = (now - fixed_stats->last_ts);
                fe.pkt_count = fixed_stats->count; fe.over_fixed = 1;
                bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);
                return block_ip_with_event(src_ip, now, EVENT_TCP_SYN_ATTACK_FIXED_BLOCK,
                                           traffic_stats, packet_size);
            }
            {
                __u64 *bl = bpf_map_lookup_elem(&blocked_ips, &src_ip);
                if (bl) {
                    traffic_stats->blocked_traffic += packet_size;
                    return XDP_DROP;
                }
                return block_ip_with_event(src_ip, now, EVENT_TCP_SYN_ATTACK_FIXED_BLOCK,
                                           traffic_stats, packet_size);
            }
        }
    }

    /* ---- Burst detection ---- */
    struct burst_state *state = bpf_map_lookup_elem(&burst_syn_state, &src_ip);
    if (!state) {
        struct burst_state ns = {0};
        ns.last_pkt_time = now; ns.last_reset = now; ns.current_burst_count = 1;
        bpf_map_update_elem(&burst_syn_state, &src_ip, &ns, BPF_ANY);
    } else {
        if (state->burst_count >= config->burst_count_threshold) {
            if (state->burst_count == config->burst_count_threshold) {
                struct fixed_ip_event fe = {0};
                fe.srcip = src_ip; fe.fixed_type = FIXED_IP_RING_BUF_SYN;
                fe.duration = (now - state->last_reset);
                fe.pkt_count = state->current_burst_count; fe.over_fixed = 1;
                bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);
                state->burst_count = config->burst_count_threshold + 1;
                return block_ip_with_event(src_ip, now, EVENT_TCP_SYN_ATTACK_BURST_BLOCK,
                                           traffic_stats, packet_size);
            }
            {
                __u64 *bl = bpf_map_lookup_elem(&blocked_ips, &src_ip);
                if (bl) {
                    traffic_stats->blocked_traffic += packet_size;
                    return XDP_DROP;
                }
                return block_ip_with_event(src_ip, now, EVENT_TCP_SYN_ATTACK_BURST_BLOCK,
                                           traffic_stats, packet_size);
            }
        }
        if (now - state->last_reset >= ONE_SECOND_NS) {
            state->last_reset = now; state->current_burst_count = 1;
            state->burst_count = 0; state->last_pkt_time = now;
        } else {
            if (now - state->last_pkt_time > config->burst_gap_ns) {
                if (state->current_burst_count >= config->burst_pkt_threshold)
                    state->burst_count++;
                state->current_burst_count = 1;
            } else { state->current_burst_count++; }
            state->last_pkt_time = now;
        }
    }

    /* ---- Already cookie-validated: pass under fixed/burst limits ---- */
    {
        __u64 *grace_exp = bpf_map_lookup_elem(&syn_validated_ips, &src_ip);
        if (grace_exp) {
            if (now < *grace_exp)
                return XDP_PASS;
            bpf_map_delete_elem(&syn_validated_ips, &src_ip);
        }
    }

    /* ---- SYN cookie via XDP_TX ---- */
    {
        int cret = syn_cookie_tx_reply(ctx, eth, ip, tcp);
        if (cret == XDP_TX) {
            traffic_stats->blocked_traffic += packet_size;
            return XDP_TX;
        }
        traffic_stats->blocked_traffic += packet_size;
        return XDP_DROP;
    }
}


/*=============================================================================================================
 *  Macro: generic flood handler body (ACK, RST, ICMP, UDP, GRE share identical logic)
 *  This avoids 500+ lines of copy-paste per handler. Each handler just declares maps + calls this.
 *============================================================================================================*/
#define COUNT_PKT_ON  __sync_fetch_and_add(pkt_cnt, 1);
#define COUNT_PKT_OFF do { } while (0);

/* ALLOW_BLACKLIST: 1 = blacklist + report_block_ip to backend (all flood classes).
 * Backend decides which attacker IPs to display; we always report over-threshold sources. */
#define DEFINE_FLOOD_HANDLER(FUNC_NAME, PROTO_CHECK, PROTO_TYPE, HDR_TYPE, HDR_SIZE_CHECK,    \
    GLOBAL_PKT_MAP, FIXED_MAP, FIXED_METRICS_MAP, BURST_MAP,                                  \
    CONFIG_PTR, CONFIG_VALID, CONFIG_FIXED_DUR, CONFIG_FIXED_THRESH,                           \
    CONFIG_BURST_GAP, CONFIG_BURST_PKT, CONFIG_BURST_CNT,                                     \
    ATTACK_FLAG, BURST_EVENT, FIXED_EVENT, RING_TYPE,                                          \
    USE_CONNTRACK, FILTERED_ON_DROP, COUNT_PKT, ALLOW_BLACKLIST)                               \
SEC("xdp")                                                                                    \
int FUNC_NAME(struct xdp_md *ctx) {                                                           \
    void *data = (void *)(long)ctx->data;                                                     \
    void *data_end = (void *)(long)ctx->data_end;                                             \
    __u64 now = bpf_ktime_get_ns();                                                           \
    __u64 packet_size = ctx->data_end - ctx->data;                                            \
    __u32 key = 0;                                                                            \
    struct traffic_stats_config *traffic_stats = bpf_map_lookup_elem(&global_income_pkt_traffic, &key); \
    if (!traffic_stats) return XDP_PASS;                                                      \
    struct iphdr *ip = parse_ipv4(data, data_end);                                            \
    if (!ip) return XDP_PASS;                                                                 \
    PROTO_CHECK                                                                               \
    HDR_SIZE_CHECK                                                                            \
    __u32 src_ip = ip->saddr;                                                                \
    key = 0;                                                                                  \
    volatile typeof(*CONFIG_PTR) *config = CONFIG_PTR;                                        \
    __u64 *pkt_cnt = bpf_map_lookup_elem(&GLOBAL_PKT_MAP, &key);                             \
    if (!pkt_cnt) return XDP_PASS;                                                            \
    if (config->CONFIG_VALID == 0) {                                                          \
        COUNT_PKT                                                                             \
        return XDP_PASS;                                                                      \
    }                                                                                         \
    if (USE_CONNTRACK) {                                                                      \
        int ihl2 = ip->ihl * 4;                                                              \
        struct tcphdr *tcp2 = (void *)ip + ihl2;                                              \
        if ((void*)(tcp2 + 1) <= data_end) {                                                  \
            if (is_tcp_established(src_ip, tcp2->source)) {                                   \
                COUNT_PKT                                                                     \
                return XDP_PASS;                                                              \
            }                                                                                 \
        }                                                                                     \
    }                                                                                         \
    struct flood_stats *fixed_stats = bpf_map_lookup_elem(&FIXED_METRICS_MAP, &src_ip);       \
    if (fixed_stats) {                                                                        \
        __u64 td = now - fixed_stats->last_ts;                                                \
        if (config->CONFIG_FIXED_DUR > 0 && td > config->CONFIG_FIXED_DUR) {                  \
            struct fixed_ip_event fe = {0};                                                   \
            fe.srcip = src_ip; fe.fixed_type = RING_TYPE;                                     \
            fe.duration = td; fe.pkt_count = fixed_stats->count; fe.over_fixed = 0;           \
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);               \
            fixed_stats->count = 1; fixed_stats->last_ts = now;                               \
        } else { fixed_stats->count += 1; }                                                   \
    } else {                                                                                  \
        struct flood_stats ns = {0}; ns.count = 1; ns.last_ts = now;                          \
        bpf_map_update_elem(&FIXED_METRICS_MAP, &src_ip, &ns, BPF_ANY);                      \
    }                                                                                         \
    volatile struct global_attack_stats *g_atk = &global_fw_config.g_attack_stats;            \
    if (g_atk->ATTACK_FLAG == 0) {                                                            \
        COUNT_PKT                                                                             \
        return XDP_PASS;                                                                      \
    }                                                                                         \
    struct burst_state *state = bpf_map_lookup_elem(&BURST_MAP, &src_ip);                     \
    if (!state) {                                                                             \
        struct burst_state ns = {0};                                                          \
        ns.last_pkt_time = now; ns.last_reset = now; ns.current_burst_count = 1;              \
        bpf_map_update_elem(&BURST_MAP, &src_ip, &ns, BPF_ANY);                              \
    } else {                                                                                  \
        if (state->burst_count >= config->CONFIG_BURST_CNT) {                                 \
            /* Emit + blacklist once on first cross; later packets only drop. */              \
            if (state->burst_count == config->CONFIG_BURST_CNT) {                             \
                struct fixed_ip_event fe = {0};                                               \
                fe.srcip = src_ip; fe.fixed_type = RING_TYPE;                                 \
                fe.duration = (now - state->last_reset);                                      \
                fe.pkt_count = state->current_burst_count; fe.over_fixed = 1;                 \
                bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);           \
                state->burst_count = config->CONFIG_BURST_CNT + 1; /* mark emitted */         \
                FILTERED_ON_DROP                                                              \
                if (ALLOW_BLACKLIST)                                                          \
                    return block_ip_with_event(src_ip, now, BURST_EVENT,                      \
                                               traffic_stats, packet_size);                   \
                return drop_spoofable(traffic_stats, packet_size);                            \
            }                                                                                 \
            FILTERED_ON_DROP                                                                      \
            if (ALLOW_BLACKLIST) {                                                            \
                __u64 *bl = bpf_map_lookup_elem(&blocked_ips, &src_ip);                      \
                if (bl) {                                                                     \
                    traffic_stats->blocked_traffic += packet_size;                            \
                    return XDP_DROP;                                                          \
                }                                                                             \
                return block_ip_with_event(src_ip, now, BURST_EVENT,                          \
                                           traffic_stats, packet_size);                       \
            }                                                                                 \
            return drop_spoofable(traffic_stats, packet_size);                                \
        }                                                                                     \
        if (now - state->last_reset >= ONE_SECOND_NS) {                                       \
            state->last_reset = now; state->current_burst_count = 1;                          \
            state->burst_count = 0; state->last_pkt_time = now;                               \
        } else {                                                                              \
            if (now - state->last_pkt_time > config->CONFIG_BURST_GAP) {                      \
                if (state->current_burst_count >= config->CONFIG_BURST_PKT)                   \
                    state->burst_count++;                                                     \
                state->current_burst_count = 1;                                               \
            } else { state->current_burst_count++; }                                          \
            state->last_pkt_time = now;                                                       \
        }                                                                                     \
    }                                                                                         \
    fixed_stats = bpf_map_lookup_elem(&FIXED_MAP, &src_ip);                                   \
    if (fixed_stats) {                                                                        \
        __u64 td = now - fixed_stats->last_ts;                                                \
        if (config->CONFIG_FIXED_DUR > 0 && td > config->CONFIG_FIXED_DUR) {                  \
            fixed_stats->count = 1; fixed_stats->last_ts = now;                               \
        } else { fixed_stats->count += 1; }                                                   \
    } else {                                                                                  \
        struct flood_stats ns = {0}; ns.count = 1; ns.last_ts = now;                          \
        bpf_map_update_elem(&FIXED_MAP, &src_ip, &ns, BPF_ANY);                              \
    }                                                                                         \
    if (fixed_stats && fixed_stats->count > config->CONFIG_FIXED_THRESH) {                    \
        /* Emit + blacklist once on first cross; later packets only drop. */                  \
        if (fixed_stats->count == config->CONFIG_FIXED_THRESH + 1) {                          \
            struct fixed_ip_event fe = {0};                                                   \
            fe.srcip = src_ip; fe.fixed_type = RING_TYPE;                                     \
            fe.duration = (now - fixed_stats->last_ts);                                       \
            fe.pkt_count = fixed_stats->count; fe.over_fixed = 1;                             \
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);               \
            FILTERED_ON_DROP                                                                  \
            if (ALLOW_BLACKLIST)                                                              \
                return block_ip_with_event(src_ip, now, FIXED_EVENT,                          \
                                           traffic_stats, packet_size);                       \
            return drop_spoofable(traffic_stats, packet_size);                                \
        }                                                                                     \
        FILTERED_ON_DROP                                                                          \
        if (ALLOW_BLACKLIST) {                                                                \
            __u64 *bl = bpf_map_lookup_elem(&blocked_ips, &src_ip);                          \
            if (bl) {                                                                         \
                traffic_stats->blocked_traffic += packet_size;                                \
                return XDP_DROP;                                                              \
            }                                                                                 \
            return block_ip_with_event(src_ip, now, FIXED_EVENT,                              \
                                       traffic_stats, packet_size);                           \
        }                                                                                     \
        return drop_spoofable(traffic_stats, packet_size);                                    \
    }                                                                                         \
    COUNT_PKT                                                                                 \
    return XDP_PASS;                                                                          \
}

/* Protocol check macros */
#define TCP_PROTO_CHECK   if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
#define ICMP_PROTO_CHECK  if (ip->protocol != IPPROTO_ICMP) return XDP_PASS;
#define UDP_PROTO_CHECK   if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
#define GRE_PROTO_CHECK   if (ip->protocol != IPPROTO_GRE) return XDP_PASS;

#define TCP_HDR_CHECK     { int ihl = ip->ihl * 4; if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end) return XDP_PASS; }
#define ICMP_HDR_CHECK    { int ihl = ip->ihl * 4; if ((void *)ip + ihl + sizeof(struct icmphdr) > data_end) return XDP_PASS; }
#define UDP_HDR_CHECK     { int ihl = ip->ihl * 4; if ((void *)ip + ihl + sizeof(struct udphdr) > data_end) return XDP_PASS; }
#define NO_HDR_CHECK      /* nothing */
#define NO_PSH_FILTERED   do { } while (0);
#define COUNT_PSH_FILTERED count_psh_ack_filtered();
#define COUNT_PSH_FILTERED_IF_PSH                                                    \
    do {                                                                             \
        int _ihl = ip->ihl * 4;                                                      \
        struct tcphdr *_th = (void *)ip + _ihl;                                     \
        if ((void *)(_th + 1) <= data_end && _th->psh && _th->ack && !_th->syn && !_th->rst) \
            count_psh_ack_filtered();                                                \
    } while (0);

/*=============================================================================================================
 *                                      XDP ACK Defense (Key 1)
 *============================================================================================================*/
#define DECL_ACK_MAPS(SZ) \
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_ack_pkt_counter SEC(".maps"); \
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, SZ); __type(key, __u32); __type(value, struct flood_stats); } ack_counter_fixed SEC(".maps"); \
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, SZ); __type(key, __u32); __type(value, struct flood_stats); } ack_counter_fixed_metrics SEC(".maps"); \
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, SZ); __type(key, __u32); __type(value, struct burst_state); } burst_ack_state SEC(".maps");

DECL_ACK_MAPS(MAP_SIZE_LARGE)

DEFINE_FLOOD_HANDLER(xdp_parse_ack, TCP_PROTO_CHECK, IPPROTO_TCP, struct tcphdr, TCP_HDR_CHECK,
    global_ack_pkt_counter, ack_counter_fixed, ack_counter_fixed_metrics, burst_ack_state,
    &global_fw_config.g_ack_config, valid, ack_fixed_check_duration, ack_fixed_threshold,
    burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
    ack_attack, EVENT_TCP_ACK_ATTACK_BURST_BLOCK, EVENT_TCP_ACK_ATTACK_FIXED_BLOCK,
    FIXED_IP_RING_BUF_ACK, 1, NO_PSH_FILTERED, COUNT_PKT_ON, 1)

/*=============================================================================================================
 *                                      XDP RST Defense (Key 2) — now catches RST+ACK too
 *============================================================================================================*/
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_rst_pkt_counter SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct flood_stats); } rst_counter_fixed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct flood_stats); } rst_counter_fixed_metrics SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct burst_state); } burst_rst_state SEC(".maps");

DEFINE_FLOOD_HANDLER(xdp_parse_rst, TCP_PROTO_CHECK, IPPROTO_TCP, struct tcphdr, TCP_HDR_CHECK,
    global_rst_pkt_counter, rst_counter_fixed, rst_counter_fixed_metrics, burst_rst_state,
    &global_fw_config.g_rst_config, valid, rst_fixed_check_duration, rst_fixed_threshold,
    burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
    rst_attack, EVENT_TCP_RST_ATTACK_BURST_BLOCK, EVENT_TCP_RST_ATTACK_FIXED_BLOCK,
    FIXED_IP_RING_BUF_RST, 1, NO_PSH_FILTERED, COUNT_PKT_ON, 1)

/*=============================================================================================================
 *                                      XDP ICMP Defense (Key 3)
 *============================================================================================================*/
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_icmp_pkt_counter SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } icmp_counter_fixed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } icmp_counter_fixed_metrics SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct burst_state); } burst_icmp_state SEC(".maps");

DEFINE_FLOOD_HANDLER(xdp_parse_icmp, ICMP_PROTO_CHECK, IPPROTO_ICMP, struct icmphdr, ICMP_HDR_CHECK,
    global_icmp_pkt_counter, icmp_counter_fixed, icmp_counter_fixed_metrics, burst_icmp_state,
    &global_fw_config.g_icmp_config, valid, icmp_fixed_check_duration, icmp_fixed_threshold,
    burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
    icmp_attack, EVENT_ICMP_ATTACK_BURST_BLOCK, EVENT_ICMP_ATTACK_FIXED_BLOCK,
    FIXED_IP_RING_BUF_ICMP, 0, NO_PSH_FILTERED, COUNT_PKT_ON, 1)

/*=============================================================================================================
 *                                      XDP UDP Defense (Key 4)
 *============================================================================================================*/
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_udp_pkt_counter SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct flood_stats); } udp_counter_fixed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct flood_stats); } udp_counter_fixed_metrics SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct burst_state); } burst_udp_state SEC(".maps");

DEFINE_FLOOD_HANDLER(xdp_parse_udp, UDP_PROTO_CHECK, IPPROTO_UDP, struct udphdr, UDP_HDR_CHECK,
    global_udp_pkt_counter, udp_counter_fixed, udp_counter_fixed_metrics, burst_udp_state,
    &global_fw_config.g_udp_config, valid, udp_fixed_check_duration, udp_fixed_threshold,
    burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
    udp_attack, EVENT_UDP_ATTACK_BURST_BLOCK, EVENT_UDP_ATTACK_FIXED_BLOCK,
    FIXED_IP_RING_BUF_UDP, 0, NO_PSH_FILTERED, COUNT_PKT_ON, 1)

/*=============================================================================================================
 *                                      XDP GRE Defense (Key 5)
 *============================================================================================================*/
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_gre_pkt_counter SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } gre_counter_fixed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } gre_counter_fixed_metrics SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct burst_state); } burst_gre_state SEC(".maps");

DEFINE_FLOOD_HANDLER(xdp_parse_gre, GRE_PROTO_CHECK, IPPROTO_GRE, void, NO_HDR_CHECK,
    global_gre_pkt_counter, gre_counter_fixed, gre_counter_fixed_metrics, burst_gre_state,
    &global_fw_config.g_gre_config, valid, gre_fixed_check_duration, gre_fixed_threshold,
    burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
    gre_attack, EVENT_GRE_ATTACK_BURST_BLOCK, EVENT_GRE_ATTACK_FIXED_BLOCK,
    FIXED_IP_RING_BUF_GRE, 0, NO_PSH_FILTERED, COUNT_PKT_ON, 1)

/*=============================================================================================================
 *  PSH+ACK classifier (Key 6)
 *  Samples payload length per source. After 32 packets, a source that almost
 *  always matches its first length is STOMP; one whose lengths differ is HANDSHAKE.
 *  That label is used only once the source is already over the STOMP fixed-window
 *  rate, so ordinary low-rate PSH+ACK is not treated as a handshake flood.
 *  Enforcement stays in xdp_parse_stomp (key 9) and xdp_parse_handshake (key 8).
 *============================================================================================================*/
/* Detection counters: incremented in the classifier (before routing). */
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_stomp_pkt_counter SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_handshake_pkt_counter SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_synack_pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, struct psh_len_profile);
} psh_ack_len_profile SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, struct flood_stats);
} psh_ack_rate SEC(".maps");

static __always_inline __u8 psh_len_observe(__u32 src_ip, __u16 payload_len)
{
    struct psh_len_profile *prof = bpf_map_lookup_elem(&psh_ack_len_profile, &src_ip);
    if (!prof) {
        struct psh_len_profile np = {0};
        np.first_len = payload_len;
        np.seen = 1;
        np.match_cnt = 1;
        bpf_map_update_elem(&psh_ack_len_profile, &src_ip, &np, BPF_ANY);
        return PSH_LEN_CLASS_UNKNOWN;
    }
    if (prof->klass != PSH_LEN_CLASS_UNKNOWN)
        return prof->klass;

    if (payload_len == prof->first_len)
        prof->match_cnt++;
    else
        prof->differ_cnt++;
    prof->seen++;
    if (prof->seen < PSH_LEN_WINDOW)
        return PSH_LEN_CLASS_UNKNOWN;

    if (prof->differ_cnt >= PSH_LEN_DIFFER_HANDSHAKE)
        prof->klass = PSH_LEN_CLASS_HANDSHAKE;
    else
        prof->klass = PSH_LEN_CLASS_STOMP;
    return prof->klass;
}

SEC("xdp")
int xdp_parse_psh_ack(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    struct iphdr *ip = parse_ipv4(data, data_end);
    if (!ip)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ihl = ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u16 tot = bpf_ntohs(ip->tot_len);
    __u32 tcp_hlen = tcp->doff * 4;
    if (tcp_hlen < sizeof(struct tcphdr))
        tcp_hlen = sizeof(struct tcphdr);
    __u32 hdrs = (__u32)ihl + tcp_hlen;
    __u16 payload_len = 0;
    if ((__u32)tot > hdrs)
        payload_len = (__u16)(tot - hdrs);

    /* Only real PSH+ACK belongs on the STOMP/HANDSHAKE path. */
    if (!(tcp->psh && tcp->ack && !tcp->syn && !tcp->rst)) {
        bpf_tail_call(ctx, &prog_array, 1); /* fall back to ACK handler */
        return XDP_PASS;
    }

    __u8 klass = psh_len_observe(src_ip, payload_len);

    /* Phase 0 N2: count labels before routing. UNKNOWN is not STOMP yet —
     * only count after the length profile decides (avoids STOMP ≫ PSH+ACK). */
    {
        __u32 ck = 0;
        if (klass == PSH_LEN_CLASS_HANDSHAKE) {
            __u64 *hc = bpf_map_lookup_elem(&global_handshake_pkt_counter, &ck);
            if (hc)
                __sync_fetch_and_add(hc, 1);
        } else if (klass == PSH_LEN_CLASS_STOMP) {
            __u64 *sc = bpf_map_lookup_elem(&global_stomp_pkt_counter, &ck);
            if (sc)
                __sync_fetch_and_add(sc, 1);
        }
    }

    /* Phase 1: label overlays on top of exclusive DET_CLASS_DATA. */
    if (klass == PSH_LEN_CLASS_HANDSHAKE || klass == PSH_LEN_CLASS_STOMP) {
        __u64 psz = (__u64)(ctx->data_end - ctx->data);
        if (klass == PSH_LEN_CLASS_HANDSHAKE)
            det_count(ip->daddr, DET_CLASS_HANDSHAKE, psz);
        else
            det_count(ip->daddr, DET_CLASS_STOMP, psz);
    }

    volatile struct global_attack_stats *atk = &global_fw_config.g_attack_stats;
    volatile struct stomp_config *sc = &global_fw_config.g_stomp_config;
    volatile struct handshake_config *hc = &global_fw_config.g_handshake_config;

    /* Per-source rate probe (used to arm handlers before host Attack flags). */
    struct flood_stats *rate = bpf_map_lookup_elem(&psh_ack_rate, &src_ip);
    __u8 over_rate = 0;
    if (rate) {
        __u64 td = now - rate->last_ts;
        if (sc->stomp_fixed_check_duration > 0 && td > sc->stomp_fixed_check_duration) {
            rate->count = 1;
            rate->last_ts = now;
        } else {
            rate->count += 1;
        }
        if (rate->count > sc->stomp_fixed_threshold)
            over_rate = 1;
    } else {
        struct flood_stats ns = {0};
        ns.count = 1;
        ns.last_ts = now;
        bpf_map_update_elem(&psh_ack_rate, &src_ip, &ns, BPF_ANY);
    }

    /*
     * STOMP = constant payload length; HANDSHAKE = variable length.
     * Always route by length-profile label when known — never force all
     * PSH+ACK into STOMP just because adaptive DATA raised stomp_attack.
     */
    __u8 under_attack = atk->stomp_attack || atk->handshake_attack;
    if (under_attack || over_rate) {
        if (klass == PSH_LEN_CLASS_HANDSHAKE) {
            if (hc->valid)
                bpf_tail_call(ctx, &prog_array, 8); /* handshake handler */
            bpf_tail_call(ctx, &prog_array, 9);
            return XDP_PASS;
        }
        if (klass == PSH_LEN_CLASS_STOMP) {
            bpf_tail_call(ctx, &prog_array, 9); /* stomp handler */
            return XDP_PASS;
        }
        /* UNKNOWN (still learning length profile): prefer HS if that flag
         * alone is set, otherwise STOMP rate-limit until klass decides. */
        if (atk->handshake_attack && !atk->stomp_attack && hc->valid)
            bpf_tail_call(ctx, &prog_array, 8);
        bpf_tail_call(ctx, &prog_array, 9);
        return XDP_PASS;
    }

    return XDP_PASS;
}

/*=============================================================================================================
 *                          XDP PSH-ACK / STOMP Defense (Key 9)
 *  Constant-length PSH+ACK, and any PSH+ACK still under the rate threshold.
 *============================================================================================================*/
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct flood_stats); } stomp_counter_fixed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct flood_stats); } stomp_counter_fixed_metrics SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct burst_state); } burst_stomp_state SEC(".maps");

DEFINE_FLOOD_HANDLER(xdp_parse_stomp, TCP_PROTO_CHECK, IPPROTO_TCP, struct tcphdr, TCP_HDR_CHECK,
    global_stomp_pkt_counter, stomp_counter_fixed, stomp_counter_fixed_metrics, burst_stomp_state,
    &global_fw_config.g_stomp_config, valid, stomp_fixed_check_duration, stomp_fixed_threshold,
    burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
    stomp_attack, EVENT_TCP_STOMP_ATTACK_BURST_BLOCK, EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK,
    FIXED_IP_RING_BUF_STOMP, 0, COUNT_PSH_FILTERED, COUNT_PKT_OFF, 1)


/*=============================================================================================================
 *                          XDP Handshake Defense (Key 8)
 *  Variable-length PSH+ACK (SYN+ACK is key 10).
 *============================================================================================================*/
 struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } handshake_counter_fixed SEC(".maps");
 struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } handshake_counter_fixed_metrics SEC(".maps");
 struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct burst_state); } burst_handshake_state SEC(".maps");
 
 
 DEFINE_FLOOD_HANDLER(xdp_parse_handshake, TCP_PROTO_CHECK, IPPROTO_TCP, struct tcphdr, TCP_HDR_CHECK,
     global_handshake_pkt_counter, handshake_counter_fixed, handshake_counter_fixed_metrics, burst_handshake_state,
     &global_fw_config.g_handshake_config, valid, handshake_fixed_check_duration, handshake_fixed_threshold,
     burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
     handshake_attack, EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK, EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK,
     FIXED_IP_RING_BUF_HANDSHAKE, 0, COUNT_PSH_FILTERED_IF_PSH, COUNT_PKT_OFF, 1)

/*=============================================================================================================
 *                          XDP SYN+ACK Defense (Key 10) — Phase 0 H7
 *  Own detection counter; reuses handshake config and handshake_attack for enforcement.
 *============================================================================================================*/
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } synack_counter_fixed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } synack_counter_fixed_metrics SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct burst_state); } burst_synack_state SEC(".maps");

DEFINE_FLOOD_HANDLER(xdp_parse_synack, TCP_PROTO_CHECK, IPPROTO_TCP, struct tcphdr, TCP_HDR_CHECK,
    global_synack_pkt_counter, synack_counter_fixed, synack_counter_fixed_metrics, burst_synack_state,
    &global_fw_config.g_handshake_config, valid, handshake_fixed_check_duration, handshake_fixed_threshold,
    burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
    handshake_attack, EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK, EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK,
    FIXED_IP_RING_BUF_HANDSHAKE, 0, NO_PSH_FILTERED, COUNT_PKT_ON, 1)
/*=============================================================================================================
 *                          NEW: XDP TCP SOCKET Defense (Key 7)
 *  Catches invalid/unusual TCP flag combos: NULL scan, XMAS, FIN-only, URG-only, etc.
 *============================================================================================================*/
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_socket_pkt_counter SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } socket_counter_fixed SEC(".maps");

SEC("xdp")
int xdp_parse_tcp_socket(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();
    __u64 packet_size = ctx->data_end - ctx->data;
    __u32 key = 0;
    struct traffic_stats_config *traffic_stats = bpf_map_lookup_elem(&global_income_pkt_traffic, &key);
    if (!traffic_stats) return XDP_PASS;
    struct iphdr *ip = parse_ipv4(data, data_end);
    if (!ip) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
    int ihl = ip->ihl * 4;
    if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end) return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void*)(tcp + 1) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 *pkt_cnt = bpf_map_lookup_elem(&global_socket_pkt_counter, &key);
    if (!pkt_cnt) return XDP_PASS;

    volatile struct socket_config *config = &global_fw_config.g_socket_config;
    if (config->valid == 0) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }

    __u8 flags = 0;
    if (tcp->fin) flags |= 0x01;
    if (tcp->syn) flags |= 0x02;
    if (tcp->rst) flags |= 0x04;
    if (tcp->psh) flags |= 0x08;
    if (tcp->ack) flags |= 0x10;
    if (tcp->urg) flags |= 0x20;

    __sync_fetch_and_add(pkt_cnt, 1);

    /* NULL / XMAS — drop immediately; still count toward fixed window below. */
    __u8 null_xmas = (flags == 0x00 || flags == 0x29 || flags == 0x39);

    /* FIN without ACK from non-established = suspicious. */
    __u8 odd_fin = ((flags & 0x01) && !(flags & 0x10) &&
                    !is_tcp_established(src_ip, tcp->source));

    __u32 thresh = odd_fin ? config->socket_fin_threshold
                           : config->socket_fixed_threshold;
    if (thresh == 0)
        thresh = config->socket_fixed_threshold;

    struct flood_stats *fs = bpf_map_lookup_elem(&socket_counter_fixed, &src_ip);
    if (fs) {
        __u64 td = now - fs->last_ts;
        if (config->socket_fixed_check_duration > 0 && td > config->socket_fixed_check_duration) {
            fs->count = 1; fs->last_ts = now;
        } else {
            fs->count += 1;
        }
    } else {
        struct flood_stats ns = {0}; ns.count = 1; ns.last_ts = now;
        bpf_map_update_elem(&socket_counter_fixed, &src_ip, &ns, BPF_ANY);
        fs = bpf_map_lookup_elem(&socket_counter_fixed, &src_ip);
    }

    if (fs && fs->count > thresh) {
        if (fs->count == thresh + 1) {
            struct fixed_ip_event fe = {0};
            fe.srcip = src_ip;
            fe.fixed_type = FIXED_IP_RING_BUF_SOCKET;
            fe.duration = (now - fs->last_ts);
            fe.pkt_count = fs->count; fe.over_fixed = 1;
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);
            return block_ip_with_event(src_ip, now, EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK,
                                       traffic_stats, packet_size);
        }
        {
            __u64 *bl = bpf_map_lookup_elem(&blocked_ips, &src_ip);
            if (bl) {
                traffic_stats->blocked_traffic += packet_size;
                return XDP_DROP;
            }
            return block_ip_with_event(src_ip, now, EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK,
                                       traffic_stats, packet_size);
        }
    }

    if (null_xmas) {
        traffic_stats->blocked_traffic += packet_size;
        return XDP_DROP;
    }
    return XDP_PASS;
}

/*=============================================================================================================
 *  TC egress: record outbound SYN for inbound SYN-ACK matching (H7)
 *============================================================================================================*/
SEC("tc")
int tc_egress_record_syn(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 proto = 0;
    void *l3 = eth_skip_vlan(eth, data_end, &proto);
    if (!l3 || proto != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *iph = l3;
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    if (iph->ihl < 5)
        return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;
    if (!(tcph->syn && !tcph->ack))
        return TC_ACT_OK;

    struct outbound_syn_key ok = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .sport = tcph->source,
        .dport = tcph->dest,
    };
    struct outbound_syn_val ov = {
        .seq = tcph->seq,
        .ts_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&outbound_syn, &ok, &ov, BPF_ANY);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";