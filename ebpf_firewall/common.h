#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

// Define time constants (in nanoseconds)

#define MAX_LINE_LEN                128
#define XDP_CORE_FILE               "EBPF_FIREWALL_XDP_KO"
#define CONFIG_FILE                 "EBPF_FIREWALL_XDP_CONFIG"
#define SQLITE_DB_NAME              "SQLITE_DB_NAME"
#define SQLITE_DB_PATH_DEFAULT      "/usr/local/share/dorian/sparta/firewall_control.db"
#define SOCK_PATH                   "/tmp/ebpf_fw.sock"
#define NGINX_UNIX_PATH             "/tmp/unix.sock"
#define FIFO_PATH                   "/tmp/firewall_to_api_parser.fifo"
#define API_PARSER_UNIX_DGRAM_PATH  "/tmp/firewall_to_api_parser.sock"

#define PUBKEY_PATH                 "PUBKEY_PATH"
#define LICENSE_PATH                "LICENSE_PATH"
#define LICENSE_CHECK_INTERVAL      60

#define LICENSE_FEATURE_L4          1
#define LICENSE_FEATURE_L7          2

#define ONE_SECOND_NS               1000000000ULL
#define BLOCK_DURATION_NS           (3600ULL * 1000000000ULL)  // 1 hour

#define SYN_THRESHOLD               200000                    // 200K SYN packets per second
#define SYN_BURST_PKT_THRESHOLD     20                        /* Each burst must have >=20 SYN packets */
#define SYN_BURST_COUNT_THRESHOLD   10                        /* 10 bursts per second triggers block */
#define SYN_FIXED_THRESHOLD         20000                     // Maximum SYN packets allowed in a 15-second window.
#define SYN_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define SYN_CHALLENGE_TIMEOUT_NS    (2ULL * ONE_SECOND_NS)    // Timeout for challenge state
#define SYN_BURST_GAP_NS            ONE_SECOND_NS / SYN_BURST_COUNT_THRESHOLD    /* 100 ms gap ends a burst */
#define SYN_PROTECTION_DURATION     0                         // Protection duration for SYN

#define ACK_THRESHOLD               200000                    // 200K ACK packets per second
#define ACK_BURST_COUNT_THRESHOLD   100                       /* 10 bursts per second triggers block */
#define ACK_BURST_PKT_THRESHOLD     200                       /* Each burst must have >=20 ACK packets */
#define ACK_FIXED_THRESHOLD         20000                     // Maximum ACK packets allowed in a 15-second window.
#define ACK_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define ACK_BURST_GAP_NS            ONE_SECOND_NS / ACK_BURST_PKT_THRESHOLD     
#define ACK_PROTECTION_DURATION     0                         // Protection duration for ACK

#define RST_THRESHOLD               200000                    // 200K RST packets per second
#define RST_BURST_COUNT_THRESHOLD   10                        /* 10 bursts per second triggers block */
#define RST_BURST_PKT_THRESHOLD     20                        /* Each burst must have >=20 RST packets */
#define RST_FIXED_THRESHOLD         20000                     // Maximum RST packets allowed in a 15-second window.
#define RST_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define RST_BURST_GAP_NS            ONE_SECOND_NS / RST_BURST_PKT_THRESHOLD 
#define RST_PROTECTION_DURATION     0                         // Protection duration for RST

#define ICMP_THRESHOLD               200000                    // 200K ICMP packets per second
#define ICMP_BURST_COUNT_THRESHOLD   10                        /* 10 bursts per second triggers block */
#define ICMP_BURST_PKT_THRESHOLD     20                        /* Each burst must have >=20 ICMP packets */
#define ICMP_FIXED_THRESHOLD         20000                     // Maximum ICMP packets allowed in a 15-second window.
#define ICMP_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define ICMP_BURST_GAP_NS            ONE_SECOND_NS / ICMP_BURST_PKT_THRESHOLD
#define ICMP_PROTECTION_DURATION     0                         // Protection duration for ICMP

#define UDP_THRESHOLD               200000                     // 200K ICMP packets per second
#define UDP_BURST_COUNT_THRESHOLD   10                         /* 10 bursts per second triggers block */
#define UDP_BURST_PKT_THRESHOLD     20                         /* Each burst must have >=20 UDP packets */
#define UDP_FIXED_THRESHOLD         20000                      // Maximum UDP packets allowed in a 15-second window.
#define UDP_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)    // 15 seconds for fixed duration check
#define UDP_BURST_GAP_NS            ONE_SECOND_NS / UDP_BURST_PKT_THRESHOLD
#define UDP_PROTECTION_DURATION     0                         // Protection duration for UDP

#define GRE_THRESHOLD               200000                     // 200K GRE packets per second
#define GRE_BURST_COUNT_THRESHOLD   10                         /* bursts per sec */
#define GRE_BURST_PKT_THRESHOLD     20                         /* Each burst must have >=20 GRE packets */
#define GRE_FIXED_THRESHOLD         20000                      // 15‑sec window
#define GRE_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)
#define GRE_BURST_GAP_NS            ONE_SECOND_NS / GRE_BURST_PKT_THRESHOLD
#define GRE_PROTECTION_DURATION     0                         // Protection duration for GRE

#define STOMP_THRESHOLD               200000                     // 200K STOMP packets per second
#define STOMP_BURST_COUNT_THRESHOLD   10                         /* bursts per sec */
#define STOMP_BURST_PKT_THRESHOLD     20                         /* Each burst must have >=20 STOMP packets */
#define STOMP_FIXED_THRESHOLD         20000                      // 15‑sec window
#define STOMP_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)
#define STOMP_BURST_GAP_NS            ONE_SECOND_NS / STOMP_BURST_PKT_THRESHOLD
#define STOMP_PROTECTION_DURATION     0                         // Protection duration for STOMP

#define HANDSHAKE_THRESHOLD               200000                     // 200K HandShake packets per second
#define HANDSHAKE_BURST_COUNT_THRESHOLD   10                         /* bursts per sec */
#define HANDSHAKE_BURST_PKT_THRESHOLD     20                         /* Each burst must have >=20 HandShake packets */
#define HANDSHAKE_FIXED_THRESHOLD         20000                      // 15‑sec window
#define HANDSHAKE_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)
#define HANDSHAKE_BURST_GAP_NS            ONE_SECOND_NS / HANDSHAKE_BURST_PKT_THRESHOLD
#define HANDSHAKE_PROTECTION_DURATION     0                         // Protection duration for HandShake

/* SOCKET is not a flood mode. NULL/XMAS are dropped immediately.
 * FIN-without-ACK and other unusual flags share one fixed window. */
#define SOCKET_FIN_THRESHOLD              100
#define SOCKET_FIXED_THRESHOLD            500
#define SOCKET_FIXED_CHECK_DURATION_NS    (15ULL * ONE_SECOND_NS)

/* ---- Event codes ---- */
#define EVENT_IP_BLOCK_END                         0

#define EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START  10
#define EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END    11
#define EVENT_TCP_SYN_ATTACK_BURST_BLOCK           12
#define EVENT_TCP_SYN_ATTACK_FIXED_BLOCK           13

#define EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START  20
#define EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END    21
#define EVENT_TCP_ACK_ATTACK_BURST_BLOCK           22
#define EVENT_TCP_ACK_ATTACK_FIXED_BLOCK           23

#define EVENT_TCP_RST_ATTACK_PROTECION_MODE_START  30
#define EVENT_TCP_RST_ATTACK_PROTECION_MODE_END    31
#define EVENT_TCP_RST_ATTACK_BURST_BLOCK           32
#define EVENT_TCP_RST_ATTACK_FIXED_BLOCK           33

#define EVENT_ICMP_ATTACK_PROTECION_MODE_START     40
#define EVENT_ICMP_ATTACK_PROTECION_MODE_END       41
#define EVENT_ICMP_ATTACK_BURST_BLOCK              42
#define EVENT_ICMP_ATTACK_FIXED_BLOCK              43

#define EVENT_UDP_ATTACK_PROTECION_MODE_START      50
#define EVENT_UDP_ATTACK_PROTECION_MODE_END        51
#define EVENT_UDP_ATTACK_BURST_BLOCK               52
#define EVENT_UDP_ATTACK_FIXED_BLOCK               53

#define EVENT_GRE_ATTACK_PROTECION_MODE_START      60
#define EVENT_GRE_ATTACK_PROTECION_MODE_END        61
#define EVENT_GRE_ATTACK_BURST_BLOCK               62
#define EVENT_GRE_ATTACK_FIXED_BLOCK               63

#define EVENT_IP_FRAG_MIDDLE_BLOCK                 70

#define EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_START  80
#define EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_END    81
#define EVENT_TCP_STOMP_ATTACK_BURST_BLOCK           82
#define EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK           83

#define EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_START  90
#define EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_END    91
#define EVENT_TCP_HANDSHAKE_ATTACK_BURST_BLOCK           92
#define EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK           93

#define EVENT_TCP_SOCKET_ATTACK_FIXED_BLOCK            100
#define EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_START   101
#define EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_END     102

#define EVENT_TCP_CONNECTION_LIMIT_REACHED            110

#define EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_START  120
#define EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_END    121

#define EVENT_TCP_FIN_ATTACK_PROTECION_MODE_START     140
#define EVENT_TCP_FIN_ATTACK_PROTECION_MODE_END       141

#define EVENT_IP_FRAG_ATTACK_PROTECION_MODE_START     150
#define EVENT_IP_FRAG_ATTACK_PROTECION_MODE_END       151

#define EVENT_OTHER_ATTACK_PROTECION_MODE_START       160
#define EVENT_OTHER_ATTACK_PROTECION_MODE_END         161

/* ---- Fixed IP ring buffer type codes ---- */
#define FIXED_IP_RING_BUF_SYN                      1
#define FIXED_IP_RING_BUF_ACK                      2
#define FIXED_IP_RING_BUF_RST                      3
#define FIXED_IP_RING_BUF_PSH                      4
#define FIXED_IP_RING_BUF_URG                      5
#define FIXED_IP_RING_BUF_FIN                      6
#define FIXED_IP_RING_BUF_SYN_ACK                  7
#define FIXED_IP_RING_BUF_RST_ACK                  8
#define FIXED_IP_RING_BUF_FIN_ACK                  9
#define FIXED_IP_RING_BUF_UDP                      10
#define FIXED_IP_RING_BUF_ICMP                     11
#define FIXED_IP_RING_BUF_GRE                      12
// Newly added 2026/4/1
#define FIXED_IP_RING_BUF_STOMP                    13     // constant-length PSH+ACK flood
#define FIXED_IP_RING_BUF_HANDSHAKE                14     // variable-length PSH+ACK, or SYN+ACK
#define FIXED_IP_RING_BUF_SOCKET                   15     // unusual TCP flags / concurrent cap

/* PSH+ACK payload-length profile. STOMP keeps one length; HANDSHAKE does not.
 * Classify after PSH_LEN_WINDOW packets: differ_cnt >= PSH_LEN_DIFFER_HANDSHAKE
 * means the lengths are spread out (HANDSHAKE). Fewer differs means STOMP.
 * The decision is applied only after the source crosses the PSH+ACK rate threshold. */
#define PSH_LEN_WINDOW                 32
#define PSH_LEN_DIFFER_HANDSHAKE       5
#define PSH_LEN_CLASS_UNKNOWN          0
#define PSH_LEN_CLASS_STOMP            1
#define PSH_LEN_CLASS_HANDSHAKE        2

struct psh_len_profile {
    __u16 first_len;
    __u16 seen;
    __u16 match_cnt;
    __u16 differ_cnt;
    __u8  klass;
    __u8  _pad[7];
};

/* ---- Structures ---- */

/* Service profile + validity knobs (redesign.config). Lives in .bss. */
struct service_profile {
    __u8 http3;                 /* UDP/TCP 443 + QUIC checks */
    __u8 dns;                   /* UDP/TCP 53 */
    __u8 gre_tunnels;           /* 0 = any GRE invalid under mode≥1 */
    __u8 quic_header_check;     /* long-header / Initial size */
    __u8 icmp_drop_fragments;
    __u8 synack_match_outbound; /* require TC egress SYN match */
    __u8 ipv6_enabled;
    __u8 _pad;
};

struct global_config {
    __u8 tcp_seg_check;
    __u8 enforce_drop_invalid; /* Phase 4: 1 = XDP drops out-of-state when mode≥1 */
    __u8 prefer_adaptive;      /* Phase 5: 1 = static absolute PPS gates do not start Attack */
    __u8 _pad_cfg;
    /* 1 = count every packet; N>1 = update detailed pkt/type counters ~1/N of the time with scale N (expected value preserved). */
    __u32 stats_detail_sample_divisor;
    __u64 black_ip_duration;     /* legacy single TTL (ns); used as initial if block_initial_ns==0 */
    __u64 block_initial_ns;      /* first offence TTL */
    __u64 block_max_ns;          /* cap after doubling */
    struct service_profile svc;
};

/* Proven-source offence counter for escalating block TTL. */
struct block_offense_val {
    __u32 count;
    __u32 _pad;
    __u64 last_block_ns;
};

struct event {
    __u64 time;
    __u16 reason;
    __u32 srcip;
    __u64 req_id;
};

struct fixed_ip_event {
    __u32 srcip;
    __u16 fixed_type;
    __u64 duration;
    __u64 pkt_count;
    __u8 over_fixed;
};

// Existing counters for flood detection.
struct flood_stats {
    __u8  detected;
    __u64 count;
    __u64 last_ts;
};

struct global_attack_stats {
    __u8 syn_attack;
    __u64 syn_protect_expire;
    __u8 ack_attack;
    __u64 ack_protect_expire;
    __u8 rst_attack;
    __u64 rst_protect_expire;
    __u8 icmp_attack;
    __u64 icmp_protect_expire;
    __u8 udp_attack;
    __u64 udp_protect_expire;
    __u8 gre_attack;
    __u64 gre_protect_expire;
    __u8 stomp_attack;
    __u64 stomp_protect_expire;
    __u8 handshake_attack;
    __u64 handshake_protect_expire;
    /* Adaptive exclusive classes (appended; classic flood loop does not drive these). */
    __u8 synack_attack;
    __u8 socket_attack;
    __u8 fin_attack;
    __u8 frag_attack;
    __u8 other_attack;
    __u8 _pad_atk[3];

    __u64 global_req_id;
    __u64 syn_req_id;
    __u64 ack_req_id;
    __u64 rst_req_id;
    __u64 icmp_req_id;
    __u64 udp_req_id;
    __u64 gre_req_id;
    __u64 stomp_req_id;
    __u64 handshake_req_id;
};

/* Optional adaptive/classic detail fields for angelos report_* messages. */
struct alert_extra {
    const char *class_name; /* SYN, UDP, ... */
    const char *state;      /* ATTACK, COOLDOWN, NORMAL */
    const char *mode;       /* OFF, DROP_INVALID, RATE_LIMIT, DST_CAP */
    const char *why;        /* threshold, force, cleared, classic, ... */
    const char *source;     /* adaptive | classic */
    const char *classes;    /* comma list for report_attack */
    __u64 rate;
    __u64 enter_pps;
    __u64 exit_pps;
    __u64 peak;
    __u8  has_metrics;
};

// Per-source state for SYN packet bursts.
struct burst_state {
    __u64 last_pkt_time;       /* Timestamp of the last SYN packet */
    __u32 current_burst_count; /* Count of SYN packets in current burst */
    __u32 burst_count;         /* Number of bursts (which met the threshold) in current 1s window */
    __u64 last_reset;          /* Start time of the current 1-second window */
};

struct syn_config {
    __u32 valid;
    __u32 syn_threshold;
    __u64 burst_gap_ns;
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u64 challenge_timeout;
    __u32 syn_fixed_threshold;
    __u64 syn_fixed_check_duration;
    __u32 syn_protect_duration;
};

struct ack_config {
    __u32 valid;
    __u32 ack_threshold;
    __u64 burst_gap_ns;
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 ack_fixed_threshold;
    __u64 ack_fixed_check_duration;
    __u32 ack_protect_duration;
};

struct rst_config {
    __u32 valid;
    __u32 rst_threshold;
    __u64 burst_gap_ns;
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 rst_fixed_threshold;
    __u64 rst_fixed_check_duration;
    __u32 rst_protect_duration;
};

struct icmp_config {
    __u32 valid;
    __u32 icmp_threshold;
    __u64 burst_gap_ns;
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 icmp_fixed_threshold;
    __u64 icmp_fixed_check_duration;
    __u32 icmp_protect_duration;
};

struct udp_config {
    __u32 valid;
    __u32 udp_threshold;
    __u64 burst_gap_ns;
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 udp_fixed_threshold;
    __u64 udp_fixed_check_duration;
    __u32 udp_protect_duration;
};

struct gre_config {
    __u32 valid;
    __u32 gre_threshold;
    __u64 burst_gap_ns;
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 gre_fixed_threshold;
    __u64 gre_fixed_check_duration;
    __u32 gre_protect_duration;
};  

struct stomp_config {
    __u32 valid;
    __u32 stomp_threshold;
    __u64 burst_gap_ns;
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 stomp_fixed_threshold;
    __u64 stomp_fixed_check_duration;
    __u32 stomp_protect_duration;
};

struct handshake_config {
    __u32 valid;
    __u32 handshake_threshold;
    __u64 burst_gap_ns;
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 handshake_fixed_threshold;
    __u64 handshake_fixed_check_duration;
    __u32 handshake_protect_duration;
};

struct socket_config {
    __u32 valid;
    __u32 socket_fin_threshold;
    __u32 socket_fixed_threshold;
    __u32 _pad;
    __u64 socket_fixed_check_duration;
};

struct geo_config {
    __u8 check;
    __u8 _pad_geo[3];
    /* Incremented when geo rules/maps change; invalidates geo_result_cache entries in XDP. */
    __u32 cache_generation;
};

/* LRU value for geo_result_cache (kernel + userspace layout). */
struct geo_cache_val {
    __u32 generation;
    __u8 allowed;   /* 1 = pass geo, 0 = drop */
    __u8 mode;      /* copy of geo_config.check when entry was stored (1=allow trie, 2=block trie) */
    __u16 _reserved;
};

struct tcp_connection_config {
    __u32 valid;
    __u8 check;
    __u32 limit_cnt;
};

struct global_firewall_config {
    struct global_attack_stats   g_attack_stats;
    struct global_config         g_config;
    struct syn_config            g_syn_config;
    struct ack_config            g_ack_config;
    struct rst_config            g_rst_config;
    struct icmp_config           g_icmp_config;
    struct udp_config            g_udp_config;
    struct gre_config            g_gre_config;
    struct stomp_config          g_stomp_config;
    struct handshake_config      g_handshake_config;
    struct socket_config         g_socket_config;
    struct geo_config            g_geo_config;
    struct tcp_connection_config g_tcp_connection_config;
};

// New structure and map for the SYN challenge state.
struct challenge_state {
    __u8 stage;       // 1: first SYN seen; 2: challenge sent (waiting for client response)
    __u64 ts;         // Timestamp when state was updated
    __u32 seq;        // Seq Number of syn
};

struct icmphdr
{
  __u8 type;                /* message type */
  __u8 code;                /* type sub-code */
  __u16 checksum;
  union
  {
    struct
    {
      __u16        id;
      __u16        sequence;
    } echo;                        /* echo datagram */
    __u32        gateway;        /* gateway address */
    struct
    {
      __u16        __unused;
      __u16        mtu;
    } frag;                        /* path mtu discovery */
  } un;
};

struct stats_config {
    __u64 syn;
    __u64 ack;
    __u64 rst;
    __u64 urg;
    __u64 psh;
    __u64 fin;
    __u64 syn_ack;
    __u64 fin_ack;
    __u64 rst_ack;
    __u64 psh_ack;
    __u64 icmp;
    __u64 udp;
    __u64 gre;
};

/* One traffic sample per second. 86400 slots keep 24 hours (~8 MB of RAM). */
#define TRAFFIC_STATS_SLOTS (24 * 60 * 60)

struct traffic_stats_config {
    __u64 timestamp;
    __u64 total_traffic;
    __u64 allowed_traffic;
    __u64 blocked_traffic;
    __u64 syn;
    __u64 ack;
    __u64 rst;
    __u64 tcp;
    __u64 udp;
    __u64 icmp;
    __u64 gre;
    __u64 other;
};

struct fixed_ip_pkt_stats {
    __u64 normal_syn;
    __u64 attack_syn;
    __u64 normal_ack;
    __u64 attack_ack;
    __u64 normal_rst;
    __u64 attack_rst;
    __u64 normal_urg;
    __u64 attack_urg;
    __u64 normal_psh;
    __u64 attack_psh;
    __u64 normal_fin;
    __u64 attack_fin;
    __u64 normal_syn_ack;
    __u64 attack_syn_ack;
    __u64 normal_fin_ack;
    __u64 attack_fin_ack;
    __u64 normal_rst_ack;
    __u64 attack_rst_ack;
    __u64 normal_icmp;
    __u64 attack_icmp;
    __u64 normal_udp;
    __u64 attack_udp;
    __u64 normal_gre;
    __u64 attack_gre;
    __u64 normal_stomp;
    __u64 attack_stomp;
    __u64 normal_socket;
    __u64 attack_socket;
    __u64 normal_handshake;
    __u64 attack_handshake;
};

/* Phase 1: per-{dst,class} detection classes (exclusive for NIC match).
 * STOMP/HANDSHAKE are label overlays counted in the classifier (not exclusive). */
enum det_class {
    DET_CLASS_SYN = 0,
    DET_CLASS_ACK,
    DET_CLASS_SYNACK,
    DET_CLASS_RST,
    DET_CLASS_ICMP,
    DET_CLASS_UDP,
    DET_CLASS_GRE,
    DET_CLASS_DATA,       /* PSH+ACK with payload → STOMP/HS path */
    DET_CLASS_SOCKET,     /* unusual / invalid flag combos */
    DET_CLASS_FIN,        /* FIN(+ACK) exclusive class */
    DET_CLASS_FRAG,       /* IP fragment (TCP/other) */
    DET_CLASS_OTHER,
    DET_CLASS_STOMP,      /* label only — from PSH+ACK classifier */
    DET_CLASS_HANDSHAKE,  /* label only — from PSH+ACK classifier */
    DET_CLASS_MAX
};

/* Exclusive classes sum to one count per IPv4 packet (for 1% NIC gate). */
#define DET_CLASS_EXCLUSIVE_MAX  DET_CLASS_STOMP

enum invalid_reason {
    INVALID_BAD_IHL = 0,
    INVALID_BAD_DOFF,
    INVALID_LAND,
    INVALID_TCP_FRAG,
    INVALID_FLAG_NULL,
    INVALID_FLAG_XMAS,
    INVALID_FLAG_SYN_FIN,
    INVALID_FLAG_SYN_RST,
    INVALID_FLAG_SYN_URG,
    INVALID_FLAG_FIN_ONLY,
    INVALID_SYN_PAYLOAD,   /* SYN with data (no TFO cookie check yet) */
    INVALID_BAD_TOTLEN,    /* tot_len vs frame (N4) */
    INVALID_REASON_MAX
};

/* IPv4 Phase 1 key; IPv6-mapped form comes with C5. */
struct det_key {
    __u32 dst;
    __u8  class;
    __u8  pad[3];
};

struct det_val {
    __u64 pkts;
    __u64 bytes;
};

struct invalid_key {
    __u32 dst;
    __u8  reason;
    __u8  pad[3];
};

/* Host-wide Phase 1 snapshot (userspace deltas per second). */
struct det_snapshot {
    __u64 class_pkts[DET_CLASS_MAX];
    __u64 class_bytes[DET_CLASS_MAX];
    __u64 invalid_pkts[INVALID_REASON_MAX];
    __u64 total_pkts;   /* sum of exclusive class pkts */
    __u64 total_bytes;
};

/* Phase 2: capacity ceilings derived from NIC/CPU (shadow only until Phase 3+). */
struct capacity_profile {
    __u32 link_mbps;          /* 0 if unknown */
    __u32 rx_queues;
    __u32 xdp_cores;
    __u64 line_pps;
    __u64 cpu_pps;
    __u64 host_ceiling_pps;
    __u64 host_ceiling_bps;
    __u64 cap_syn;
    __u64 cap_ack;
    __u64 cap_rst;
    __u64 cap_icmp;
    __u64 cap_udp;
    __u64 cap_gre;
    __u64 cap_data;
    __u8  http3;              /* raises UDP cap fraction */
    __u8  gre_tunnels;        /* 0 => GRE at floor only */
    __u8  _pad[2];
};

#define CAP_PER_CORE_PPS_DEFAULT     3000000ULL
#define CAP_CEILING_FRACTION_NUM     65ULL
#define CAP_CEILING_FRACTION_DEN     100ULL
#define CAP_LINK_FALLBACK_MBPS       10000U

/* Phase 3 shadow lifecycle (per dst, class). */
enum shadow_state {
    SHADOW_NORMAL = 0,
    SHADOW_ATTACK = 1,
    SHADOW_COOLDOWN = 2,
};

/* Mitigation mode written by C, read by XDP (Phase 4+). */
enum mitigation_mode {
    MODE_OFF = 0,
    MODE_DROP_INVALID = 1, /* Phase 4: drop packets failing validity */
    MODE_RATE_LIMIT = 2,   /* Phase 5: per-flow / per-source buckets */
    MODE_DST_CAP = 3       /* Phase 5: per-destination caps */
};

struct mode_val {
    __u8  mode;       /* enum mitigation_mode */
    __u8  state;      /* enum shadow_state */
    __u8  incident;   /* 1 = destination Incident (drop-invalid all classes) */
    __u8  _pad;
    __u64 expires_ns; /* watchdog: stale mode ignored by XDP */
};

/* Per-class limits pushed by C for mode 2 (src/flow) and mode 3 (dst). */
struct mode_limits {
    __u32 src_pps;    /* per-source packets per 1s window */
    __u32 dst_pps;    /* per-destination class packets per 1s window */
    __u32 flow_pps;   /* per-flow DATA packets per 1s window (mode 2+) */
    __u32 new_flow_pps; /* HANDSHAKE: new 4-tuples per source per 1s */
    __u32 socket_src_cap;     /* concurrent flows per source (Attack) */
    __u32 socket_prefix24_cap; /* concurrent flows per /24 (Attack) */
};

struct src_bucket_key {
    __u32 src;
    __u8  class;
    __u8  pad[3];
};

struct rate_win {
    __u64 count;
    __u64 last_ts;
};

/* Layer 4 established-flow tracking (Phase 5 follow-up / plan flows map). */
struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

struct flow_val {
    __u64 pkts;
    __u64 bytes;
    __u64 last_ts;
    __u64 first_ts;
    __u64 win_pkts;       /* packets in current 1s window */
    __u64 win_start;
    __u16 first_payload;  /* first DATA length (STOMP/HS label support) */
    __u16 differ_cnt;
    __u8  handshake_done; /* saw non-SYN after SYN path */
    __u8  pad2[3];
};

#define SHADOW_CONFIRM_WINDOWS       3
#define SHADOW_FLOW_PPS_K            6    /* flow limit ≈ max(50, mean * k / sources_est) */
#define SHADOW_EXIT_WINDOWS          45
#define SHADOW_COOLDOWN_SECONDS      90
/* When class rate is near-idle, leave Attack after this many quiet seconds
 * instead of waiting the full exit_windows (flap-safe fast clear). */
#define SHADOW_QUIET_CLEAR_WINDOWS   10
/* After entering Attack, wait this many still-elevated seconds before panel
 * attack_start / protection START (filters 1s L7 traffic spikes). */
#define SHADOW_ALERT_HOLD_WINDOWS    5
#define SHADOW_ESCALATE_WINDOWS      5    /* Attack windows before +1 mitigation mode */
#define SHADOW_SURGE_FACTOR          3
#define SHADOW_REARM_SECONDS         300

/* Why should_drop_invalid let a non-SYN TCP packet through (valid_pass_reasons). */
enum valid_pass_reason {
    PASS_REASON_SOCKET = 0,  /* established / request / timewait socket */
    PASS_REASON_MIRROR,      /* conntrack ESTABLISHED mirror */
    PASS_REASON_COOKIE,      /* valid SYN-cookie ACK, no socket yet */
    PASS_REASON_MAX
};
#define SHADOW_ESCALATE_CAP_WINDOWS  10   /* legacy alias: 2× escalate → mode 3 */
#define SHADOW_SRC_BUCKET_K          3    /* src limit ≈ max(floor, mean * k) */
#define SHADOW_BASELINE_K            6.0
#define SHADOW_BASELINE_M            3.0
#define SHADOW_T_EXIT_MEAN_MULT      1.5
#define SHADOW_T_EXIT_ENTER_FRAC     0.5
/* Half-life ~45 min at 1 Hz → alpha ≈ 1 - 2^(-1/2700) */
#define SHADOW_EWMA_ALPHA            0.0002567
#define SHADOW_GROWTH_CAP_PER_HOUR   2.0
#define SHADOW_LEARNING_SECONDS      (7ULL * 24ULL * 3600ULL)
#define SHADOW_DST_SLOTS             8192
#define SHADOW_WALK_BUDGET           4096
#define SHADOW_INVALID_FLOOR_PPS     1000ULL
#define SHADOW_INVALID_RATIO         0.05

/* Runtime-tunable shadow knobs (redesign.config); defaults match #defines above. */
struct shadow_runtime_cfg {
    __u32 confirm_windows;
    __u32 exit_windows;
    __u32 cooldown_seconds;
    __u32 quiet_clear_windows; /* Attack→Cooldown when rate≈idle for N seconds */
    __u32 alert_hold_windows;  /* defer panel START until sustained Attack */
    __u32 escalate_after_windows;
    __u32 surge_factor;   /* rate ≥ enter × factor → Attack + DST_CAP in one window */
    __u32 rearm_seconds;  /* re-entry within this long after Attack restores peak mode */
    __u32 src_bucket_k;
    __u32 flow_pps_k;
    __u32 invalid_floor_pps;
    __u32 learning_days;
    __u32 nic_drop_trigger_seconds;
    __u32 softirq_trigger_percent;
    __u32 softirq_trigger_seconds;
    /*
     * Detection proficiency 1..10 (5 = catalog / redesign defaults).
     * Higher = more sensitive (lower floors, tighter baseline, fewer confirms).
     */
    __u32 detection_level;
    __u8  cusum_enable;
    __u8  seasonal_enable; /* hour_of_week */
    __u8  _pad[2];
    double baseline_k;
    double baseline_m;
    double invalid_ratio;
    double t_exit_mean_mult;
    double t_exit_enter_frac;
    double cusum_drift;    /* allowance below mean before CUSUM grows */
    double cusum_h;        /* decision threshold in pps units */
};

struct shadow_cell {
    double mean;
    double var;
    double cusum_pos;     /* one-sided CUSUM accumulator */
    __u64 prev_pkts;
    __u64 prev_invalid;   /* host invalid_totals sum for L3 trigger */
    __u64 t_enter;
    __u64 t_exit;
    __u64 peak_pps;
    __u64 state_since;
    __u64 learning_samples;
    __u32 above_windows;
    __u32 below_windows;
    __u32 cooldown_left;
    __u32 escalate_hold;  /* windows at current mit_mode while in Attack */
    __u8  state;          /* enum shadow_state */
    __u8  mit_mode;       /* enum mitigation_mode; stepped +1/−1 */
    __u8  have_prev;
    __u8  learning_done;
    __u8  fast_entry;     /* last Attack entry skipped confirm (surge / re-arm) */
    __u8  peak_mode;      /* highest mit_mode reached in the last Attack */
    __u8  _pad_rearm[6];
    __u64 attack_end_sample; /* sample index when Attack last ended; 0 = never */
};

/* Outbound SYN recorded by TC egress for SYN-ACK matching (H7). */
struct outbound_syn_key {
    __u32 saddr; /* local (our) address = SYN source / SYN-ACK dest */
    __u32 daddr; /* peer = SYN dest / SYN-ACK source */
    __u16 sport;
    __u16 dport;
};

struct outbound_syn_val {
    __u32 seq;       /* network-order SYN seq */
    __u64 ts_ns;
};

struct shadow_dst_entry {
    __u32 dst;
    __u8  class;
    __u8  used;
    __u16 _pad;
    struct shadow_cell cell;
    __u64 last_seen;      /* monotonic sample index for eviction */
};

struct shadow_host_summary {
    __u8  state[DET_CLASS_EXCLUSIVE_MAX];
    __u8  mit_mode[DET_CLASS_EXCLUSIVE_MAX];
    __u64 rate[DET_CLASS_EXCLUSIVE_MAX];
    __u64 t_enter[DET_CLASS_EXCLUSIVE_MAX];
    __u64 t_exit[DET_CLASS_EXCLUSIVE_MAX];
    __u64 peak[DET_CLASS_EXCLUSIVE_MAX];
    __u64 mean_pps[DET_CLASS_EXCLUSIVE_MAX]; /* rounded EWMA mean for status */
    __u32 attacks_active;
    __u32 dst_tracked;
    __u64 samples;
    __u8  learning;       /* 1 while still in bootstrap */
};

// LPM trie key: prefixlen (# of bits), then IPv4 in network order
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

#endif