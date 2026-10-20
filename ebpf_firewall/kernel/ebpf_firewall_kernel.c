// ebpf_firewall_kernel.c
// Optimized XDP anti-DDoS kernel with STOMP, SOCKET, and Handshake flood protection
// Map sizes tuned for 20GB+ RAM enterprise deployment (~2-3GB total map footprint)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

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
 * Key 8 -> xdp_parse_handshake    (HANDSHAKE enforcement)
 * Key 9 -> xdp_parse_stomp        (STOMP enforcement)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
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


/*-------------------------------------------- Static Functions ------------------------------------*/
#if 0
static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}
#endif

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

static __always_inline int block_ip_with_event(
    __u32 src_ip, __u64 now, __u16 reason,
    struct traffic_stats_config *traffic_stats, __u64 packet_size)
{
    volatile struct global_config *gcfg = &global_fw_config.g_config;
    __u64 block_exp = now + gcfg->black_ip_duration;
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
    if ((void*)(eth + 1) > data_end || eth->h_proto != __constant_htons(ETH_P_IP)) {
        traffic_stats->other += packet_size;
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)(iph + 1) > data_end) {
        traffic_stats->other += packet_size;
        return XDP_PASS;
    }

    __u8 have_tcp = 0;
    __u8 tcp_syn = 0, tcp_ack = 0, tcp_fin = 0, tcp_rst = 0, tcp_psh = 0, tcp_urg = 0;

    if (iph->protocol == IPPROTO_TCP) {
        traffic_stats->tcp += packet_size;
        int ip_hdr_len = iph->ihl * 4;
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void*)(tcph + 1) <= data_end) {
            have_tcp = 1;
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

    __u8 *whitelisted = bpf_map_lookup_elem(&allowed_ips, &src_ip);
    if (whitelisted)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();

    struct stats_config *pkt_stats = bpf_map_lookup_elem(&global_income_pkt_counter, &key);
    if (!pkt_stats) return XDP_PASS;

    volatile struct global_config *gcfg = &global_fw_config.g_config;
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
            struct event evt = {0};
            evt.time = now; evt.srcip = src_ip; evt.reason = EVENT_IP_FRAG_MIDDLE_BLOCK;
            bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
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
    
    /* TCP dispatch */
    if (have_tcp) {
        if (tcp_syn && !tcp_ack)
            bpf_tail_call(ctx, &prog_array, 0);       /* SYN flood */
        if (tcp_psh && tcp_ack && !tcp_syn && !tcp_rst)
            bpf_tail_call(ctx, &prog_array, 6);       /* PSH+ACK: STOMP or HANDSHAKE */
        if (tcp_syn && tcp_ack)
            bpf_tail_call(ctx, &prog_array, 8);       /* SYN+ACK handshake */
        if (tcp_ack && !tcp_syn && !tcp_fin && !tcp_rst && !tcp_psh)
            bpf_tail_call(ctx, &prog_array, 1);       /* Pure ACK flood */
        if (tcp_rst)
            bpf_tail_call(ctx, &prog_array, 2);       /* RST flood (incl RST+ACK) */
        bpf_tail_call(ctx, &prog_array, 7);           /* SOCKET (everything else) */
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
 * Map of IPs that recently passed the SYN challenge.
 * Key: src_ip, Value: expiration timestamp (ns).
 * Once an IP passes the challenge, it gets a grace period (e.g. 60s)
 * during which subsequent SYNs skip the challenge entirely.
 * This prevents the challenge from punishing legitimate clients that
 * open multiple connections during an attack.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_SIZE_LARGE);
    __type(key, __u32);
    __type(value, __u64);    /* grace expiration time in ns */
} syn_validated_ips SEC(".maps");

/* Grace period after passing SYN challenge: 120 seconds.
 * During this window, further SYNs from this IP skip the challenge. */
#define SYN_GRACE_PERIOD_NS  (120ULL * ONE_SECOND_NS)


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
    if ((void*)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    int ihl = ip->ihl * 4;
    if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end) return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void*)(tcp + 1) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;
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

    /* ---- FAST PATH 1: IP has existing established connections ----
     * If conntrack knows this IP (has at least one TCP session), it's not a spoofed source.
     * Let the SYN through immediately — the kernel will handle the handshake normally.
     * This protects existing clients opening additional connections during an attack.
     */
     

    if (is_tcp_established(src_ip, tcp->source)) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }


    /*
     * Count every SYN from sources not in the established fast-path toward global PPS.
     * This must run before any XDP_DROP (challenge, burst, fixed), otherwise the
     * userspace worker never sees flood volume and syn_attack stays off while the
     * dataplane is dropping or while attack mode flaps off under challenge load.
     */
    __sync_fetch_and_add(pkt_cnt, 1);


    volatile struct global_attack_stats *g_atk = &global_fw_config.g_attack_stats;
    if (g_atk->syn_attack == 0) {
        return XDP_PASS;
    }

    /* ======================================================================
     * ATTACK MODE — burst + SYN challenge + fixed window when syn_attack == 1
     * ====================================================================== */

    /* ---- FAST PATH 2: IP recently passed the SYN challenge ----
     * Grace period prevents re-challenging clients that just proved they're real.
     * This is crucial during attacks: without it, every new connection from a
     * legitimate client pays the challenge penalty, and LRU eviction of the
     * challenge state causes infinite retry loops.
     */
    __u64 *grace_exp = bpf_map_lookup_elem(&syn_validated_ips, &src_ip);
    if (grace_exp) {
        if (now < *grace_exp) {
            /* Still within grace period — skip challenge, just do fixed counter check */
            goto fixed_window_check;
        }
        /* Grace expired — remove and re-challenge */
        bpf_map_delete_elem(&syn_validated_ips, &src_ip);
    }

    /* ---- Burst detection ---- */
    struct burst_state *state = bpf_map_lookup_elem(&burst_syn_state, &src_ip);
    if (!state) {
        struct burst_state ns = {0};
        ns.last_pkt_time = now; ns.last_reset = now; ns.current_burst_count = 1;
        bpf_map_update_elem(&burst_syn_state, &src_ip, &ns, BPF_ANY);
    } else {
        if (state->burst_count >= config->burst_count_threshold) {
            block_ip_with_event(src_ip, now, EVENT_TCP_SYN_ATTACK_BURST_BLOCK, traffic_stats, packet_size);
            struct fixed_ip_event fe = {0};
            fe.srcip = src_ip; fe.fixed_type = FIXED_IP_RING_BUF_SYN;
            fe.duration = (now - state->last_reset); fe.pkt_count = state->current_burst_count; fe.over_fixed = 1;
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);
            return XDP_DROP;
        }
        if (now - state->last_reset >= ONE_SECOND_NS) {
            state->last_reset = now; state->current_burst_count = 1;
            state->burst_count = 0; state->last_pkt_time = now;
        } else {
            if (now - state->last_pkt_time > config->burst_gap_ns) {
                if (state->current_burst_count >= config->burst_pkt_threshold) state->burst_count++;
                state->current_burst_count = 1;
            } else { state->current_burst_count++; }
            state->last_pkt_time = now;
        }
    }

    /* ---- SYN Challenge ----
     * Only runs during attack mode. The challenge works as follows:
     *
     * Stage 0 (cstate == NULL): First SYN from this IP during attack.
     *   → DROP the SYN, record it. A real client will retransmit in ~1s.
     *   → An attacker using spoofed IPs won't retransmit from the same IP.
     *
     * Stage 1 (retransmit received): Same IP sent another SYN with same seq.
     *   → This is likely a real client retransmitting. Send a RST back
     *     (not a fake SYN-ACK with wrong checksum — that wastes another RTT).
     *   → The RST causes the client to immediately retry with a new SYN.
     *
     * Stage 2 (third SYN from same IP): Client is definitely real.
     *   → Delete challenge state, grant grace period, PASS the SYN.
     *
     * Total cost to legitimate client: ~1 extra RTT (the dropped first SYN).
     * Previous code cost: 2-3 RTTs (drop + fake SYN-ACK + wait for client RST + retry).
     */
    struct challenge_state *cstate = bpf_map_lookup_elem(&syn_challenge, &src_ip);

    if (cstate) {
        /* Check timeout — if too old and different seq, it's a new connection attempt */
        if (now - cstate->ts > config->challenge_timeout) {
            if (cstate->seq != tcp->seq) {
                bpf_map_delete_elem(&syn_challenge, &src_ip);
                cstate = NULL;
            }
        }
    }

    if (cstate == NULL) {
        /* Stage 0: First SYN — just drop it. Real clients will retransmit. */
        struct challenge_state ncs = {0};
        ncs.stage = 1;
        ncs.ts = now;
        ncs.seq = tcp->seq;
        bpf_map_update_elem(&syn_challenge, &src_ip, &ncs, BPF_ANY);
        traffic_stats->blocked_traffic += packet_size;
        return XDP_DROP;

    } else if (cstate->stage == 1) {
        /*
         * Stage 1: Client retransmitted SYN (same seq, or new seq after our drop).
         *
         * Option A (simple & effective): Just let it through now.
         * The client already proved it can retransmit from the same IP,
         * which spoofed attackers can't do. No need for the SYN-ACK trick.
         *
         * Grant grace period so future SYNs from this IP skip the challenge.
         */
        bpf_map_delete_elem(&syn_challenge, &src_ip);

        /* Grant grace period */
        __u64 grace = now + SYN_GRACE_PERIOD_NS;
        bpf_map_update_elem(&syn_validated_ips, &src_ip, &grace, BPF_ANY);

        /* Fall through to fixed window check, then PASS */
        goto fixed_window_check;

    } else if (cstate->stage == 2) {
        /* Legacy stage — clean up if leftover from old code */
        bpf_map_delete_elem(&syn_challenge, &src_ip);
    }


fixed_window_check: {
    /* ---- Fixed window rate limiting (per-IP) ---- */

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
    }

    if (fixed_stats && fixed_stats->count > config->syn_fixed_threshold) {
        block_ip_with_event(src_ip, now, EVENT_TCP_SYN_ATTACK_FIXED_BLOCK, traffic_stats, packet_size);
        struct fixed_ip_event fe = {0};
        fe.srcip = src_ip; fe.fixed_type = FIXED_IP_RING_BUF_SYN;
        fe.duration = (now - fixed_stats->last_ts); fe.pkt_count = fixed_stats->count; fe.over_fixed = 1;
        bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);
        return XDP_DROP;
    }

    return XDP_PASS;
}
}


/*=============================================================================================================
 *  Macro: generic flood handler body (ACK, RST, ICMP, UDP, GRE share identical logic)
 *  This avoids 500+ lines of copy-paste per handler. Each handler just declares maps + calls this.
 *============================================================================================================*/
#define DEFINE_FLOOD_HANDLER(FUNC_NAME, PROTO_CHECK, PROTO_TYPE, HDR_TYPE, HDR_SIZE_CHECK,    \
    GLOBAL_PKT_MAP, FIXED_MAP, FIXED_METRICS_MAP, BURST_MAP,                                  \
    CONFIG_PTR, CONFIG_VALID, CONFIG_FIXED_DUR, CONFIG_FIXED_THRESH,                           \
    CONFIG_BURST_GAP, CONFIG_BURST_PKT, CONFIG_BURST_CNT,                                     \
    ATTACK_FLAG, BURST_EVENT, FIXED_EVENT, RING_TYPE,                                          \
    USE_CONNTRACK, FILTERED_ON_DROP)                                                           \
SEC("xdp")                                                                                    \
int FUNC_NAME(struct xdp_md *ctx) {                                                           \
    void *data = (void *)(long)ctx->data;                                                     \
    void *data_end = (void *)(long)ctx->data_end;                                             \
    __u64 now = bpf_ktime_get_ns();                                                           \
    __u64 packet_size = ctx->data_end - ctx->data;                                            \
    __u32 key = 0;                                                                            \
    struct traffic_stats_config *traffic_stats = bpf_map_lookup_elem(&global_income_pkt_traffic, &key); \
    if (!traffic_stats) return XDP_PASS;                                                      \
    struct ethhdr *eth = data;                                                                \
    if ((void*)(eth + 1) > data_end) return XDP_PASS;                                        \
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;                         \
    struct iphdr *ip = data + sizeof(*eth);                                                   \
    if ((void*)(ip + 1) > data_end) return XDP_PASS;                                         \
    PROTO_CHECK                                                                               \
    HDR_SIZE_CHECK                                                                            \
    __u32 src_ip = ip->saddr;                                                                \
    key = 0;                                                                                  \
    volatile typeof(*CONFIG_PTR) *config = CONFIG_PTR;                                        \
    __u64 *pkt_cnt = bpf_map_lookup_elem(&GLOBAL_PKT_MAP, &key);                             \
    if (!pkt_cnt) return XDP_PASS;                                                            \
    if (config->CONFIG_VALID == 0) {                                                          \
        __sync_fetch_and_add(pkt_cnt, 1);                                                    \
        return XDP_PASS;                                                                      \
    }                                                                                         \
    if (USE_CONNTRACK) {                                                                      \
        int ihl2 = ip->ihl * 4;                                                              \
        struct tcphdr *tcp2 = (void *)ip + ihl2;                                              \
        if ((void*)(tcp2 + 1) <= data_end) {                                                  \
            if (is_tcp_established(src_ip, tcp2->source)) {                                   \
                __sync_fetch_and_add(pkt_cnt, 1);                                            \
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
        __sync_fetch_and_add(pkt_cnt, 1);                                                    \
        return XDP_PASS;                                                                      \
    }                                                                                         \
    struct burst_state *state = bpf_map_lookup_elem(&BURST_MAP, &src_ip);                     \
    if (!state) {                                                                             \
        struct burst_state ns = {0};                                                          \
        ns.last_pkt_time = now; ns.last_reset = now; ns.current_burst_count = 1;              \
        bpf_map_update_elem(&BURST_MAP, &src_ip, &ns, BPF_ANY);                              \
    } else {                                                                                  \
        if (state->burst_count >= config->CONFIG_BURST_CNT) {                                 \
            block_ip_with_event(src_ip, now, BURST_EVENT, traffic_stats, packet_size);        \
            struct fixed_ip_event fe = {0};                                                   \
            fe.srcip = src_ip; fe.fixed_type = RING_TYPE;                                     \
            fe.duration = (now - state->last_reset);                                          \
            fe.pkt_count = state->current_burst_count; fe.over_fixed = 1;                     \
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);               \
            FILTERED_ON_DROP                                                                      \
            return XDP_DROP;                                                                  \
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
        block_ip_with_event(src_ip, now, FIXED_EVENT, traffic_stats, packet_size);            \
        struct fixed_ip_event fe = {0};                                                       \
        fe.srcip = src_ip; fe.fixed_type = RING_TYPE;                                         \
        fe.duration = (now - fixed_stats->last_ts);                                           \
        fe.pkt_count = fixed_stats->count; fe.over_fixed = 1;                                 \
        bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fe, sizeof(fe), 0);                   \
        FILTERED_ON_DROP                                                                          \
        return XDP_DROP;                                                                      \
    }                                                                                         \
    __sync_fetch_and_add(pkt_cnt, 1);                                                        \
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
    FIXED_IP_RING_BUF_ACK, 1, NO_PSH_FILTERED)

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
    FIXED_IP_RING_BUF_RST, 1, NO_PSH_FILTERED)

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
    FIXED_IP_RING_BUF_ICMP, 0, NO_PSH_FILTERED)

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
    FIXED_IP_RING_BUF_UDP, 0, NO_PSH_FILTERED)

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
    FIXED_IP_RING_BUF_GRE, 0, NO_PSH_FILTERED)

/*=============================================================================================================
 *  PSH+ACK classifier (Key 6)
 *  Samples payload length per source. After 32 packets, a source that almost
 *  always matches its first length is STOMP; one whose lengths differ is HANDSHAKE.
 *  That label is used only once the source is already over the STOMP fixed-window
 *  rate, so ordinary low-rate PSH+ACK is not treated as a handshake flood.
 *  Enforcement stays in xdp_parse_stomp (key 9) and xdp_parse_handshake (key 8).
 *============================================================================================================*/
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

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
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

    __u8 klass = psh_len_observe(src_ip, payload_len);

    /* Userspace already chose the attack from the PSH+ACK rate. Every PSH+ACK
     * packet then takes that defense's original burst and fixed-window filter. */
    volatile struct global_attack_stats *atk = &global_fw_config.g_attack_stats;
    if (atk->handshake_attack) {
        bpf_tail_call(ctx, &prog_array, 8);
        return XDP_PASS;
    }
    if (atk->stomp_attack) {
        bpf_tail_call(ctx, &prog_array, 9);
        return XDP_PASS;
    }

    volatile struct stomp_config *sc = &global_fw_config.g_stomp_config;
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

    volatile struct handshake_config *hc = &global_fw_config.g_handshake_config;
    if (over_rate && klass == PSH_LEN_CLASS_HANDSHAKE && hc->valid) {
        bpf_tail_call(ctx, &prog_array, 8);
        return XDP_PASS;
    }
    bpf_tail_call(ctx, &prog_array, 9);
    return XDP_PASS;
}

/*=============================================================================================================
 *                          XDP PSH-ACK / STOMP Defense (Key 9)
 *  Constant-length PSH+ACK, and any PSH+ACK still under the rate threshold.
 *============================================================================================================*/
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_stomp_pkt_counter SEC(".maps");    
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct flood_stats); } stomp_counter_fixed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct flood_stats); } stomp_counter_fixed_metrics SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_LARGE); __type(key, __u32); __type(value, struct burst_state); } burst_stomp_state SEC(".maps");

DEFINE_FLOOD_HANDLER(xdp_parse_stomp, TCP_PROTO_CHECK, IPPROTO_TCP, struct tcphdr, TCP_HDR_CHECK,
    global_stomp_pkt_counter, stomp_counter_fixed, stomp_counter_fixed_metrics, burst_stomp_state,
    &global_fw_config.g_stomp_config, valid, stomp_fixed_check_duration, stomp_fixed_threshold,
    burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
    stomp_attack, EVENT_TCP_STOMP_ATTACK_BURST_BLOCK, EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK,
    FIXED_IP_RING_BUF_STOMP, 0, COUNT_PSH_FILTERED)


/*=============================================================================================================
 *                          XDP Handshake Defense (Key 8)
 *  SYN+ACK, and PSH+ACK whose payload length varies across the source.
 *============================================================================================================*/
 struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } global_handshake_pkt_counter SEC(".maps");
 struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } handshake_counter_fixed SEC(".maps");
 struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct flood_stats); } handshake_counter_fixed_metrics SEC(".maps");
 struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, MAP_SIZE_MEDIUM); __type(key, __u32); __type(value, struct burst_state); } burst_handshake_state SEC(".maps");
 
 
 DEFINE_FLOOD_HANDLER(xdp_parse_handshake, TCP_PROTO_CHECK, IPPROTO_TCP, struct tcphdr, TCP_HDR_CHECK,
     global_handshake_pkt_counter, handshake_counter_fixed, handshake_counter_fixed_metrics, burst_handshake_state,
     &global_fw_config.g_handshake_config, valid, handshake_fixed_check_duration, handshake_fixed_threshold,
     burst_gap_ns, burst_pkt_threshold, burst_count_threshold,
     handshake_attack, EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK, EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK,
     FIXED_IP_RING_BUF_HANDSHAKE, 0, COUNT_PSH_FILTERED_IF_PSH)
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
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;
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

    /* NULL scan / XMAS tree — always drop while SOCKET defense is on */
    if (flags == 0x00 || flags == 0x29) {
        traffic_stats->blocked_traffic += packet_size;
        return XDP_DROP;
    }

    /* FIN without ACK from non-established = suspicious.
     * Shares socket_counter_fixed with the generic window below. */
    if ((flags & 0x01) && !(flags & 0x10) && !is_tcp_established(src_ip, tcp->source)) {
        struct flood_stats *fs = bpf_map_lookup_elem(&socket_counter_fixed, &src_ip);
        if (fs) {
            __u64 td = now - fs->last_ts;
            if (config->socket_fixed_check_duration > 0 && td > config->socket_fixed_check_duration) {
                fs->count = 1; fs->last_ts = now;
            } else { fs->count += 1; }
            if (fs->count > config->socket_fin_threshold) {
                block_ip_with_event(src_ip, now, EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK, traffic_stats, packet_size);
                return XDP_DROP;
            }
        } else {
            struct flood_stats ns = {0}; ns.count = 1; ns.last_ts = now;
            bpf_map_update_elem(&socket_counter_fixed, &src_ip, &ns, BPF_ANY);
        }
    }

    /* Generic rate limit for every other unusual flag combination */
    struct flood_stats *fs = bpf_map_lookup_elem(&socket_counter_fixed, &src_ip);
    if (fs) {
        __u64 td = now - fs->last_ts;
        if (config->socket_fixed_check_duration > 0 && td > config->socket_fixed_check_duration) {
            fs->count = 1; fs->last_ts = now;
        } else { fs->count += 1; }
        if (fs->count > config->socket_fixed_threshold) {
            block_ip_with_event(src_ip, now, EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK, traffic_stats, packet_size);
            return XDP_DROP;
        }
    } else {
        struct flood_stats ns = {0}; ns.count = 1; ns.last_ts = now;
        bpf_map_update_elem(&socket_counter_fixed, &src_ip, &ns, BPF_ANY);
    }

    __sync_fetch_and_add(pkt_cnt, 1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";