/*
 * Host-aware BPF map sizing, applied between bpf_object__open and load.
 *
 * Maps keyed by source IP or flow scale from their compiled-in defaults by a
 * profile factor. "auto" picks the largest profile whose estimated
 * preallocated map memory fits map_memory_budget_percent of RAM. Event ring
 * buffers scale with possible CPUs.
 *
 * firewall.config is parsed only after load, so these keys are read here:
 *   map_size_profile          = auto | small | medium | standard | large | xlarge
 *   map_memory_budget_percent = 8
 */
#include <ebpf_firewall_common.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_mapsize.h>
#include <ctype.h>

struct size_profile {
    const char *name;
    unsigned num;
    unsigned den;
};

static const struct size_profile profiles[] = {
    { "small",    1, 4 },
    { "medium",   1, 2 },
    { "standard", 1, 1 },   /* compiled-in MAP_SIZE_* */
    { "large",    2, 1 },
    { "xlarge",   4, 1 },
};
#define N_PROFILES ((int)(sizeof(profiles) / sizeof(profiles[0])))
#define PROFILE_STANDARD 2

#define DEFAULT_BUDGET_PERCENT  8
#define SCALED_MIN_ENTRIES      4096U
#define SCALED_MAX_ENTRIES      (16U * 1024U * 1024U)
#define EVENT_RING_PER_16_CPUS  (256U * 1024U)
#define EVENT_RING_MAX          (16U * 1024U * 1024U)
#define HTAB_ELEM_OVERHEAD      64ULL   /* matches kernel memlock per prealloc elem */

/* Capacity = how many sources / connections are tracked before LRU eviction
 * resets their counters (or, for blocked_ips, silently unblocks them). */
static const char *const scaled_maps[] = {
    "blocked_ips", "block_offense",
    "syn_counter_fixed", "burst_syn_state", "syn_challenge", "syn_validated_ips",
    "ack_counter_fixed", "ack_counter_fixed_metrics", "burst_ack_state",
    "rst_counter_fixed", "rst_counter_fixed_metrics", "burst_rst_state",
    "udp_counter_fixed", "udp_counter_fixed_metrics", "burst_udp_state",
    "icmp_counter_fixed", "icmp_counter_fixed_metrics", "burst_icmp_state",
    "gre_counter_fixed", "gre_counter_fixed_metrics", "burst_gre_state",
    "stomp_counter_fixed", "stomp_counter_fixed_metrics", "burst_stomp_state",
    "handshake_counter_fixed", "handshake_counter_fixed_metrics", "burst_handshake_state",
    "synack_counter_fixed", "synack_counter_fixed_metrics", "burst_synack_state",
    "socket_counter_fixed", "psh_ack_rate", "psh_ack_len_profile",
    "src_buckets", "src_new_flows", "src_conn_count", "prefix24_conn_count",
    "frag_event_last", "outbound_syn", "geo_result_cache",
    "flows", "tcp_established_map", "tcp_connection_map",
};
#define N_SCALED ((int)(sizeof(scaled_maps) / sizeof(scaled_maps[0])))

static int is_scaled(const char *name)
{
    for (int i = 0; i < N_SCALED; i++)
        if (strcmp(scaled_maps[i], name) == 0)
            return 1;
    return 0;
}

static __u32 scale_entries(__u32 def, const struct size_profile *p)
{
    __u64 n = (__u64)def * p->num / p->den;
    if (n < SCALED_MIN_ENTRIES)
        n = SCALED_MIN_ENTRIES;
    if (n > SCALED_MAX_ENTRIES)
        n = SCALED_MAX_ENTRIES;
    return (__u32)n;
}

static __u64 round8(__u64 v)
{
    return (v + 7) & ~7ULL;
}

static __u64 estimate_map_bytes(const struct bpf_map *m, __u32 entries, int ncpus)
{
    __u64 k = round8(bpf_map__key_size(m));
    __u64 v = round8(bpf_map__value_size(m));

    switch (bpf_map__type(m)) {
    case BPF_MAP_TYPE_HASH:
    case BPF_MAP_TYPE_LRU_HASH:
        if (bpf_map__map_flags(m) & BPF_F_NO_PREALLOC)
            return 0;
        return (k + v + HTAB_ELEM_OVERHEAD) * entries;
    case BPF_MAP_TYPE_PERCPU_HASH:
    case BPF_MAP_TYPE_LRU_PERCPU_HASH:
        return (k + HTAB_ELEM_OVERHEAD + 8 + v * (__u64)ncpus) * entries;
    case BPF_MAP_TYPE_ARRAY:
        return v * entries;
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        return v * (__u64)ncpus * entries;
    case BPF_MAP_TYPE_RINGBUF:
        return entries;
    case BPF_MAP_TYPE_LPM_TRIE:
        return 0;   /* BPF_F_NO_PREALLOC: grows with loaded prefixes */
    default:
        return (k + v) * entries;
    }
}

static __u32 event_ring_bytes(__u32 def, int ncpus)
{
    __u64 want = (__u64)EVENT_RING_PER_16_CPUS * (((__u64)ncpus + 15) / 16);
    __u64 sz = def;
    while (sz < want && sz < EVENT_RING_MAX)
        sz <<= 1;   /* ringbuf size must stay a power of two */
    return (__u32)sz;
}

static __u64 estimate_total(struct bpf_object *obj, const struct size_profile *p, int ncpus)
{
    struct bpf_map *m;
    __u64 total = 0;
    bpf_object__for_each_map(m, obj) {
        __u32 n = bpf_map__max_entries(m);
        if (is_scaled(bpf_map__name(m)))
            n = scale_entries(n, p);
        else if (strcmp(bpf_map__name(m), "ring_buf_events") == 0)
            n = event_ring_bytes(n, ncpus);
        total += estimate_map_bytes(m, n, ncpus);
    }
    return total;
}

static void trim(char *s)
{
    char *p = s;
    while (isspace((unsigned char)*p))
        p++;
    memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
}

static void read_sizing_keys(char *profile, size_t plen, int *budget_pct)
{
    const char *path = getenv(CONFIG_FILE);
    FILE *fp = path ? fopen(path, "r") : NULL;
    if (!fp)
        return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char key[128] = {0}, val[128] = {0};
        if (line[0] == '#' || sscanf(line, "%127[^=]= %127s", key, val) != 2)
            continue;
        trim(key);
        if (strcmp(key, "map_size_profile") == 0) {
            strncpy(profile, val, plen - 1);
            profile[plen - 1] = '\0';
        } else if (strcmp(key, "map_memory_budget_percent") == 0) {
            int v = atoi(val);
            if (v >= 1 && v <= 50)
                *budget_pct = v;
            else
                LOG_W("map_memory_budget_percent=%s out of range 1..50, using %d\n",
                      val, *budget_pct);
        }
    }
    fclose(fp);
}

int apply_host_map_sizing(struct bpf_object *obj)
{
    char want[32] = "auto";
    int budget_pct = DEFAULT_BUDGET_PERCENT;
    read_sizing_keys(want, sizeof(want), &budget_pct);

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1)
        ncpus = 1;
    long pages = sysconf(_SC_PHYS_PAGES);
    long psize = sysconf(_SC_PAGESIZE);
    __u64 ram = (pages > 0 && psize > 0) ? (__u64)pages * (__u64)psize : 0;
    __u64 budget = ram / 100 * (__u64)budget_pct;

    int chosen = -1;
    for (int i = 0; i < N_PROFILES; i++)
        if (strcmp(want, profiles[i].name) == 0)
            chosen = i;

    if (chosen < 0) {
        if (strcmp(want, "auto") != 0)
            LOG_W("Unknown map_size_profile '%s', using auto\n", want);
        if (ram == 0) {
            chosen = PROFILE_STANDARD;   /* unknown RAM: keep compiled-in sizes */
        } else {
            chosen = 0;
            for (int i = N_PROFILES - 1; i > 0; i--) {
                if (estimate_total(obj, &profiles[i], ncpus) <= budget) {
                    chosen = i;
                    break;
                }
            }
        }
    }

    const struct size_profile *p = &profiles[chosen];
    __u64 est = estimate_total(obj, p, ncpus);
    LOG_I("Map sizing: profile=%s (requested %s) ram=%.1fGB cpus=%d "
          "budget=%d%% (%.1fGB) estimated=%.1fGB\n",
          p->name, want, (double)ram / 1e9, ncpus, budget_pct,
          (double)budget / 1e9, (double)est / 1e9);
    if (ram && est > budget)
        LOG_W("Map sizing: estimated map memory exceeds the %d%% RAM budget\n", budget_pct);

    int missing = 0;
    for (int i = 0; i < N_SCALED; i++) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, scaled_maps[i]);
        if (!m) {
            missing++;
            continue;
        }
        __u32 old = bpf_map__max_entries(m);
        __u32 n = scale_entries(old, p);
        if (n != old && bpf_map__set_max_entries(m, n)) {
            LOG_E("Map sizing: %s %u -> %u failed\n", scaled_maps[i], old, n);
            return -1;
        }
    }
    if (missing)
        LOG_D("Map sizing: %d scaled map names not in this object\n", missing);

    struct bpf_map *rb = bpf_object__find_map_by_name(obj, "ring_buf_events");
    if (rb) {
        __u32 old = bpf_map__max_entries(rb);
        __u32 n = event_ring_bytes(old, ncpus);
        if (n != old && bpf_map__set_max_entries(rb, n)) {
            LOG_E("Map sizing: ring_buf_events %u -> %u failed\n", old, n);
            return -1;
        }
    }

    struct bpf_map *b = bpf_object__find_map_by_name(obj, "blocked_ips");
    struct bpf_map *f = bpf_object__find_map_by_name(obj, "flows");
    struct bpf_map *s = bpf_object__find_map_by_name(obj, "syn_counter_fixed");
    LOG_I("Map sizing: blocked_ips=%u flows=%u per-source(syn_counter_fixed)=%u "
          "ring_buf_events=%uKB\n",
          b ? bpf_map__max_entries(b) : 0, f ? bpf_map__max_entries(f) : 0,
          s ? bpf_map__max_entries(s) : 0, rb ? bpf_map__max_entries(rb) / 1024 : 0);
    return 0;
}
