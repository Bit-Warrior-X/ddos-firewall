/*
 * Phase 3–4 adaptive control loop.
 *
 * Learns EWMA baselines per host class and per {dst,class}, runs the
 * Normal → Attack → Cooldown hysteresis machine, and (Phase 4) publishes
 * MODE_DROP_INVALID into mitigation_mode for XDP. Static flood gates still
 * run in parallel; modes 2–3 are not enabled yet.
 */
#include <ebpf_firewall_common.h>
#include <ebpf_firewall_shadow.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_config.h>
#include <ebpf_firewall_core.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>

extern int exiting;
extern int n_cpus;
extern char ifname[];
extern struct capacity_profile global_capacity_profile;
extern struct global_firewall_config global_fw_config;

static inline size_t shadow_percpu_stride(__u32 value_size)
{
    return (size_t)(((unsigned)value_size + 7U) & ~7U);
}

static int shadow_percpu_nr_cpus(void)
{
    int n = libbpf_num_possible_cpus();
    return (n > 0) ? n : n_cpus;
}

struct shadow_host_summary global_shadow_summary = {0};

static pthread_t shadow_thr;
static int shadow_started = 0;
static volatile int shadow_stop = 0;

static struct shadow_cell host_cells[DET_CLASS_EXCLUSIVE_MAX];
/* 1 while any host class was in Attack at the previous sample. */
static int shadow_episode_open;
static struct shadow_dst_entry dst_table[SHADOW_DST_SLOTS];
static __u64 sample_index = 0;
static time_t learning_start = 0;
/* Panel alert gate: wait for sustained Attack before attack_start. */
static __u8  host_alert_pending[DET_CLASS_EXCLUSIVE_MAX];
static __u8  host_alert_sent[DET_CLASS_EXCLUSIVE_MAX];
static __u32 host_alert_hold[DET_CLASS_EXCLUSIVE_MAX];

/* Tunables (defaults = plan #defines; overridden by redesign.config keys). */
struct shadow_runtime_cfg shadow_cfg = {
    .confirm_windows = SHADOW_CONFIRM_WINDOWS,
    .exit_windows = SHADOW_EXIT_WINDOWS,
    .cooldown_seconds = SHADOW_COOLDOWN_SECONDS,
    .quiet_clear_windows = SHADOW_QUIET_CLEAR_WINDOWS,
    .alert_hold_windows = SHADOW_ALERT_HOLD_WINDOWS,
    .escalate_after_windows = SHADOW_ESCALATE_WINDOWS,
    .surge_factor = SHADOW_SURGE_FACTOR,
    .rearm_seconds = SHADOW_REARM_SECONDS,
    .src_bucket_k = SHADOW_SRC_BUCKET_K,
    .flow_pps_k = SHADOW_FLOW_PPS_K,
    .invalid_floor_pps = (__u32)SHADOW_INVALID_FLOOR_PPS,
    .learning_days = 7,
    .nic_drop_trigger_seconds = 3,
    .softirq_trigger_percent = 80,
    .softirq_trigger_seconds = 3,
    .detection_level = 5, /* proficiency: 1=deaf … 5=normal … 10=max */
    .cusum_enable = 1,
    .seasonal_enable = 1,
    .baseline_k = SHADOW_BASELINE_K,
    .baseline_m = SHADOW_BASELINE_M,
    .invalid_ratio = SHADOW_INVALID_RATIO,
    .t_exit_mean_mult = SHADOW_T_EXIT_MEAN_MULT,
    .t_exit_enter_frac = SHADOW_T_EXIT_ENTER_FRAC,
    .cusum_drift = 0.0,
    .cusum_h = 0.0, /* set from class floor at runtime if 0 */
};

/* Clamp proficiency to 1..10. */
static __u32 det_level(void)
{
    __u32 L = shadow_cfg.detection_level;
    if (L < 1)
        return 1;
    if (L > 10)
        return 10;
    return L;
}

static const char *det_level_name(__u32 L)
{
    static const char *names[11] = {
        "?", "minimal", "very_low", "low", "moderate_low", "normal",
        "moderate_high", "elevated", "high", "very_high", "max"
    };
    if (L < 1 || L > 10)
        return "?";
    return names[L];
}

/*
 * Floor scale vs level 5 (=1.0). Higher proficiency → lower floors.
 * Level 10 ≈ 0.0055 → ACK/DATA catalog 50k → ~275 pps.
 */
static double det_floor_scale(void)
{
    return pow(2.0, (5.0 - (double)det_level()) * 1.5);
}

/* Milder scale for baseline k/m (level 10 ≈ ×0.66). */
static double det_km_scale(void)
{
    return pow(2.0, (5.0 - (double)det_level()) * 0.15);
}

/* Confirm windows by proficiency (overrides catalog confirm at non-5). */
static __u32 det_confirm_windows(void)
{
    static const __u32 tbl[11] = { 0, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1 };
    return tbl[det_level()];
}

static __u64 host_invalid_prev = 0;
static __u8 host_invalid_have_prev = 0;

/* Seasonality: host-only hour-of-week means [class][hour]. */
static double host_hour_mean[DET_CLASS_EXCLUSIVE_MAX][168];
static __u32 host_hour_samples[DET_CLASS_EXCLUSIVE_MAX][168];

/* Layer-1 NIC / softirq watch. */
static __u64 prev_rx_missed = 0;
static __u64 prev_rx_nobuf = 0;
static int nic_have_prev = 0;
static int nic_breach_windows = 0;
static int softirq_breach_windows = 0;
static unsigned long long prev_softirq = 0;
static unsigned long long prev_cpu_total = 0;
static int softirq_have_prev = 0;

static const char *shadow_state_name(__u8 s)
{
    switch (s) {
    case SHADOW_NORMAL:   return "NORMAL";
    case SHADOW_ATTACK:   return "ATTACK";
    case SHADOW_COOLDOWN: return "COOLDOWN";
    default:              return "?";
    }
}

static const char *mit_mode_name(__u8 m)
{
    switch (m) {
    case MODE_OFF:           return "OFF";
    case MODE_DROP_INVALID:  return "DROP_INVALID";
    case MODE_RATE_LIMIT:    return "RATE_LIMIT";
    case MODE_DST_CAP:       return "DST_CAP";
    default:                 return "?";
    }
}

/* STOMP = constant PSH payload length; HANDSHAKE = variable length.
 * Updated each shadow sample from DET_CLASS_STOMP / DET_CLASS_HANDSHAKE labels. */
static int data_overlay_handshake; /* 1=HANDSHAKE primary, 0=STOMP primary */
static __u64 label_prev_stomp;
static __u64 label_prev_hs;
static int label_have_prev;

int shadow_data_overlay_is_handshake(void)
{
    return data_overlay_handshake;
}

static const char *det_class_name(__u8 c)
{
    switch (c) {
    case DET_CLASS_SYN:    return "SYN";
    case DET_CLASS_ACK:    return "ACK";
    case DET_CLASS_SYNACK: return "SYNACK";
    case DET_CLASS_RST:    return "RST";
    case DET_CLASS_ICMP:   return "ICMP";
    case DET_CLASS_UDP:    return "UDP";
    case DET_CLASS_GRE:    return "GRE";
    case DET_CLASS_DATA:
        return data_overlay_handshake ? "HANDSHAKE" : "STOMP";
    case DET_CLASS_SOCKET: return "SOCKET";
    case DET_CLASS_FIN:    return "FIN";
    case DET_CLASS_FRAG:   return "FRAG";
    case DET_CLASS_OTHER:  return "OTHER";
    default:               return "?";
    }
}

static int class_protection_event(__u8 class, int is_start)
{
    switch (class) {
    case DET_CLASS_SYN:
        return is_start ? EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START
                        : EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_ACK:
        return is_start ? EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START
                        : EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_RST:
        return is_start ? EVENT_TCP_RST_ATTACK_PROTECION_MODE_START
                        : EVENT_TCP_RST_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_ICMP:
        return is_start ? EVENT_ICMP_ATTACK_PROTECION_MODE_START
                        : EVENT_ICMP_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_UDP:
        return is_start ? EVENT_UDP_ATTACK_PROTECION_MODE_START
                        : EVENT_UDP_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_GRE:
        return is_start ? EVENT_GRE_ATTACK_PROTECION_MODE_START
                        : EVENT_GRE_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_DATA:
        /* Emit HANDSHAKE or STOMP protection based on length-profile labels. */
        if (data_overlay_handshake)
            return is_start ? EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_START
                            : EVENT_TCP_HANDSHAKE_ATTACK_PROTECION_MODE_END;
        return is_start ? EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_START
                        : EVENT_TCP_STOMP_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_SYNACK:
        return is_start ? EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_START
                        : EVENT_TCP_SYNACK_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_SOCKET:
        return is_start ? EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_START
                        : EVENT_TCP_SOCKET_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_FIN:
        return is_start ? EVENT_TCP_FIN_ATTACK_PROTECION_MODE_START
                        : EVENT_TCP_FIN_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_FRAG:
        return is_start ? EVENT_IP_FRAG_ATTACK_PROTECION_MODE_START
                        : EVENT_IP_FRAG_ATTACK_PROTECION_MODE_END;
    case DET_CLASS_OTHER:
        return is_start ? EVENT_OTHER_ATTACK_PROTECION_MODE_START
                        : EVENT_OTHER_ATTACK_PROTECION_MODE_END;
    default:
        return -1;
    }
}

static void shadow_set_class_attack_flag(__u8 class, int active)
{
    struct global_attack_stats *atk = &global_fw_config.g_attack_stats;
    __u8 v = active ? 1 : 0;

    switch (class) {
    case DET_CLASS_SYN:    atk->syn_attack = v; break;
    case DET_CLASS_ACK:    atk->ack_attack = v; break;
    case DET_CLASS_RST:    atk->rst_attack = v; break;
    case DET_CLASS_ICMP:   atk->icmp_attack = v; break;
    case DET_CLASS_UDP:    atk->udp_attack = v; break;
    case DET_CLASS_GRE:    atk->gre_attack = v; break;
    case DET_CLASS_DATA:
        /* Enable both handlers; kernel routes each source by length label. */
        atk->stomp_attack = v;
        atk->handshake_attack = v;
        break;
    case DET_CLASS_SYNACK: atk->synack_attack = v; break;
    case DET_CLASS_SOCKET: atk->socket_attack = v; break;
    case DET_CLASS_FIN:    atk->fin_attack = v; break;
    case DET_CLASS_FRAG:   atk->frag_attack = v; break;
    case DET_CLASS_OTHER:  atk->other_attack = v; break;
    default: break;
    }
}

static __u64 sum_det_val_percpu(const void *raw, size_t stride, int nr);

/* Refresh STOMP vs HANDSHAKE primary from label overlay counters. */
static void shadow_update_data_overlay(int det_class_fd, void *raw, size_t stride, int nr)
{
    __u32 ck;
    __u64 cur_stomp = 0, cur_hs = 0;

    ck = DET_CLASS_STOMP;
    if (bpf_map_lookup_elem(det_class_fd, &ck, raw) == 0)
        cur_stomp = sum_det_val_percpu(raw, stride, nr);
    ck = DET_CLASS_HANDSHAKE;
    if (bpf_map_lookup_elem(det_class_fd, &ck, raw) == 0)
        cur_hs = sum_det_val_percpu(raw, stride, nr);

    if (!label_have_prev) {
        label_prev_stomp = cur_stomp;
        label_prev_hs = cur_hs;
        label_have_prev = 1;
        /* Bootstrap primary from absolute label counts (first sample). */
        if (cur_hs > cur_stomp * 2 && cur_hs >= 64)
            data_overlay_handshake = 1;
        else if (cur_stomp > cur_hs * 2 && cur_stomp >= 64)
            data_overlay_handshake = 0;
        return;
    }

    __u64 rate_stomp = (cur_stomp >= label_prev_stomp) ?
                       (cur_stomp - label_prev_stomp) : cur_stomp;
    __u64 rate_hs = (cur_hs >= label_prev_hs) ?
                    (cur_hs - label_prev_hs) : cur_hs;
    label_prev_stomp = cur_stomp;
    label_prev_hs = cur_hs;

    /* Require a clear majority so mixed noise does not flip the alert type. */
    if (rate_hs > rate_stomp * 2 && rate_hs >= 64)
        data_overlay_handshake = 1;
    else if (rate_stomp > rate_hs * 2 && rate_stomp >= 64)
        data_overlay_handshake = 0;
}

/* Emit deferred panel START once Attack has stayed elevated long enough. */
static void shadow_fire_alert_start(__u8 class, const struct shadow_cell *cell,
                                   __u64 rate, const char *why)
{
    int ev;
    struct alert_extra ex = {0};

    if (global_fw_config.g_attack_stats.global_req_id == 0)
        global_fw_config.g_attack_stats.global_req_id = generate_attack_req_id();
    /* Open archive only when the episode is real enough to alert. */
    if (attack_log_open(global_fw_config.g_attack_stats.global_req_id,
                        det_class_name(class), "adaptive") > 0)
        LOG_I("ATTACK archive open req_id=%llu class=%s\n",
              (unsigned long long)global_fw_config.g_attack_stats.global_req_id,
              det_class_name(class));
    shadow_set_class_attack_flag(class, 1);
    ex.class_name = det_class_name(class);
    ex.state = shadow_state_name(SHADOW_ATTACK);
    ex.mode = mit_mode_name(cell->mit_mode);
    ex.why = why ? why : "threshold";
    ex.source = "adaptive";
    ex.rate = rate;
    ex.enter_pps = cell->t_enter;
    ex.exit_pps = cell->t_exit;
    ex.peak = cell->peak_pps;
    ex.has_metrics = 1;
    ev = class_protection_event(class, 1);
    if (ev >= 0)
        print_firewall_status_ex(NULL, ev, 0,
                                 global_fw_config.g_attack_stats.global_req_id, &ex);
    host_alert_sent[class] = 1;
    host_alert_pending[class] = 0;
    host_alert_hold[class] = 0;
    LOG_I("ALERT hold passed class=%s rate=%llu hold=%us (%s) — panel START\n",
          det_class_name(class), (unsigned long long)rate,
          cell->fast_entry ? 1U : shadow_cfg.alert_hold_windows, ex.why);
}

/* Host-only: report_protection START/END under prefer_adaptive (episode via flags). */
static void shadow_report_host_transition(__u8 class, __u8 prev, __u8 now_state,
                                         const struct shadow_cell *cell, __u64 rate,
                                         const char *why)
{
    int ev;
    struct alert_extra ex = {0};

    if (!global_fw_config.g_config.prefer_adaptive)
        return;
    if (prev == now_state)
        return;
    if (class >= DET_CLASS_EXCLUSIVE_MAX)
        return;

    ex.class_name = det_class_name(class);
    ex.state = shadow_state_name(now_state);
    ex.mode = mit_mode_name(cell->mit_mode);
    ex.why = why ? why : "threshold";
    ex.source = "adaptive";
    ex.rate = rate;
    ex.enter_pps = cell->t_enter;
    ex.exit_pps = cell->t_exit;
    ex.peak = cell->peak_pps;
    ex.has_metrics = 1;

    if (now_state == SHADOW_ATTACK &&
        (prev == SHADOW_NORMAL || prev == SHADOW_COOLDOWN)) {
        /* Defer panel START — brief L7 spikes must not open an episode. */
        host_alert_pending[class] = 1;
        host_alert_sent[class] = 0;
        host_alert_hold[class] = 0;
        return;
    }

    /* Episode / protection END when leaving Attack — only if START was sent. */
    if (prev == SHADOW_ATTACK &&
        (now_state == SHADOW_COOLDOWN || now_state == SHADOW_NORMAL)) {
        shadow_set_class_attack_flag(class, 0);
        if (host_alert_sent[class]) {
            ex.why = (now_state == SHADOW_COOLDOWN) ? "below_exit" : "cleared";
            ev = class_protection_event(class, 0);
            if (ev >= 0)
                print_firewall_status_ex(NULL, ev, 0,
                                         global_fw_config.g_attack_stats.global_req_id,
                                         &ex);
        } else if (host_alert_pending[class]) {
            LOG_I("ALERT suppressed class=%s (spike ended before hold=%us)\n",
                  det_class_name(class), shadow_cfg.alert_hold_windows);
        }
        host_alert_pending[class] = 0;
        host_alert_sent[class] = 0;
        host_alert_hold[class] = 0;
        return;
    }
}

/* Tick deferred panel alerts while host class remains in Attack. */
static void shadow_tick_alert_hold(__u8 class, struct shadow_cell *cell, __u64 rate)
{
    if (class >= DET_CLASS_EXCLUSIVE_MAX)
        return;
    if (!host_alert_pending[class] || host_alert_sent[class])
        return;
    if (cell->state != SHADOW_ATTACK)
        return;

    /* Require still-elevated rate; a dead spike resets the hold timer. */
    if (rate < cell->t_exit) {
        host_alert_hold[class] = 0;
        return;
    }
    host_alert_hold[class]++;
    /* Surge / re-arm entries are already proven; the per-source flood
     * handlers are armed with the alert, so do not hold them back. */
    __u32 need = cell->fast_entry ? 1 : shadow_cfg.alert_hold_windows;
    if (host_alert_hold[class] >= need)
        shadow_fire_alert_start(class, cell, rate,
                                cell->fast_entry ? "fast" : "sustained");
}

static __u64 class_floor_base(__u8 c)
{
    switch (c) {
    case DET_CLASS_SYN:    return 20000ULL;
    case DET_CLASS_ACK:    return 50000ULL;
    case DET_CLASS_RST:    return 10000ULL;
    case DET_CLASS_ICMP:   return 2000ULL;
    case DET_CLASS_UDP:    return global_capacity_profile.http3 ? 50000ULL : 20000ULL;
    case DET_CLASS_GRE:    return 1000ULL;
    case DET_CLASS_DATA:   return 50000ULL;
    case DET_CLASS_SYNACK: return 10000ULL;
    case DET_CLASS_SOCKET: return 1000ULL;
    case DET_CLASS_FIN:    return 5000ULL;
    case DET_CLASS_FRAG:   return 2000ULL;
    default:               return 1000ULL;
    }
}

static __u64 class_floor(__u8 c)
{
    __u64 base = class_floor_base(c);
    double scaled = (double)base * det_floor_scale();
    __u64 f = (__u64)(scaled + 0.5);
    __u64 min_f = 64;

    /* Keep SYN/ACK/DATA/UDP from collapsing to noise at max proficiency. */
    if (c == DET_CLASS_SYN || c == DET_CLASS_ACK ||
        c == DET_CLASS_DATA || c == DET_CLASS_UDP)
        min_f = 128;
    if (f < min_f)
        f = min_f;
    if (f < 1)
        f = 1;
    return f;
}

static __u64 class_cap(__u8 c)
{
    switch (c) {
    case DET_CLASS_SYN:    return global_capacity_profile.cap_syn    ? global_capacity_profile.cap_syn    : class_floor(c);
    case DET_CLASS_ACK:    return global_capacity_profile.cap_ack    ? global_capacity_profile.cap_ack    : class_floor(c);
    case DET_CLASS_RST:    return global_capacity_profile.cap_rst    ? global_capacity_profile.cap_rst    : class_floor(c);
    case DET_CLASS_ICMP:   return global_capacity_profile.cap_icmp   ? global_capacity_profile.cap_icmp   : class_floor(c);
    case DET_CLASS_UDP:    return global_capacity_profile.cap_udp    ? global_capacity_profile.cap_udp    : class_floor(c);
    case DET_CLASS_GRE:    return global_capacity_profile.cap_gre    ? global_capacity_profile.cap_gre    : class_floor(c);
    case DET_CLASS_DATA:   return global_capacity_profile.cap_data   ? global_capacity_profile.cap_data   : class_floor(c);
    case DET_CLASS_SYNACK: return global_capacity_profile.cap_ack    ? global_capacity_profile.cap_ack / 2 : class_floor(c);
    case DET_CLASS_SOCKET: return 5000ULL;
    default:               return class_floor(c) * 4;
    }
}

static unsigned dst_hash(__u32 dst, __u8 class)
{
    return (unsigned)((dst * 2654435761u) ^ ((unsigned)class * 0x9e3779b9u)) % SHADOW_DST_SLOTS;
}

static struct shadow_dst_entry *dst_lookup_or_insert(__u32 dst, __u8 class)
{
    unsigned h = dst_hash(dst, class);
    int free_slot = -1;
    int oldest = -1;
    __u64 oldest_seen = UINT64_MAX;

    for (unsigned i = 0; i < SHADOW_DST_SLOTS; i++) {
        unsigned idx = (h + i) % SHADOW_DST_SLOTS;
        struct shadow_dst_entry *e = &dst_table[idx];
        if (!e->used) {
            if (free_slot < 0)
                free_slot = (int)idx;
            break;
        }
        if (e->dst == dst && e->class == class)
            return e;
        if (e->last_seen < oldest_seen && e->cell.state == SHADOW_NORMAL) {
            oldest_seen = e->last_seen;
            oldest = (int)idx;
        }
    }

    int slot = free_slot >= 0 ? free_slot : oldest;
    if (slot < 0)
        return NULL;

    struct shadow_dst_entry *e = &dst_table[slot];
    memset(e, 0, sizeof(*e));
    e->used = 1;
    e->dst = dst;
    e->class = class;
    e->last_seen = sample_index;
    return e;
}

static int hour_of_week_now(void)
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    /* tm_wday 0=Sun … 6=Sat; plan uses hour_of_week 0..167. */
    int hod = tm.tm_wday * 24 + tm.tm_hour;
    if (hod < 0) hod = 0;
    if (hod > 167) hod = 167;
    return hod;
}

static void shadow_recompute_thresholds(struct shadow_cell *cell, __u8 class)
{
    double mean = cell->mean;
    /* Seasonality: blend with hour-of-week host mean when available. */
    if (shadow_cfg.seasonal_enable && class < DET_CLASS_EXCLUSIVE_MAX) {
        int h = hour_of_week_now();
        if (host_hour_samples[class][h] >= 8) {
            double hm = host_hour_mean[class][h];
            mean = 0.5 * cell->mean + 0.5 * hm;
        }
    }
    double sigma = sqrt(cell->var > 0.0 ? cell->var : 0.0);
    double km = det_km_scale();
    double k = shadow_cfg.baseline_k * km;
    double m = shadow_cfg.baseline_m * km;
    double t_sig = mean + k * sigma;
    double t_mean = m * mean;
    double t_enter = t_sig > t_mean ? t_sig : t_mean;
    if (t_enter < (double)class_floor(class))
        t_enter = (double)class_floor(class);

    __u64 cap = class_cap(class);
    if (t_enter > (double)cap)
        t_enter = (double)cap;

    /*
     * Learning bootstrap (plan: ~cap/4 upper bound).
     * On high-capacity NICs (e.g. 200G → DATA cap/4 ≈ 780k PPS) a fixed
     * cap/4 gate misses real mid-size floods. Use:
     *   enter = clamp(floor, warm_baseline_or_cold, cap/4)
     * cold = 4×floor until we have enough quiet samples.
     */
    if (!cell->learning_done) {
        double floor = (double)class_floor(class);
        double boot_cap = (double)cap / 4.0;
        double cold = floor * 4.0;
        double boot;

        if (boot_cap < floor)
            boot_cap = floor;
        if (cold < floor)
            cold = floor;
        if (cold > boot_cap)
            cold = boot_cap;

        if (cell->learning_samples >= 30 && mean > 0.0) {
            double warm = t_sig > t_mean ? t_sig : t_mean;
            if (warm < floor)
                warm = floor;
            if (warm > boot_cap)
                warm = boot_cap;
            boot = warm;
        } else {
            boot = cold;
        }
        t_enter = boot;
    }

    double t_exit = shadow_cfg.t_exit_mean_mult * mean;
    double half_enter = shadow_cfg.t_exit_enter_frac * t_enter;
    if (half_enter > t_exit)
        t_exit = half_enter;
    if (t_exit >= t_enter)
        t_exit = t_enter * 0.5;
    if (t_exit < 1.0)
        t_exit = 1.0;

    cell->t_enter = (__u64)(t_enter + 0.5);
    cell->t_exit = (__u64)(t_exit + 0.5);
}

static void shadow_update_ewma(struct shadow_cell *cell, __u64 rate, __u8 class)
{
    if (!cell->learning_done) {
        /* Gate from current mean first so outliers can be rejected. */
        shadow_recompute_thresholds(cell, class);

        int outlier = 0;
        if (cell->learning_samples >= 10 && cell->t_enter > 0 &&
            rate >= cell->t_enter) {
            outlier = 1;
        } else if (cell->learning_samples >= 10 && cell->mean > 0.0 &&
                   (double)rate > 4.0 * cell->mean &&
                   rate >= class_floor(class)) {
            outlier = 1;
        }

        if (!outlier) {
            cell->learning_samples++;
            /* Warm start: running average until we have a few samples. */
            if (cell->learning_samples == 1) {
                cell->mean = (double)rate;
                cell->var = 0.0;
            } else {
                double n = (double)cell->learning_samples;
                double delta = (double)rate - cell->mean;
                cell->mean += delta / n;
                cell->var += delta * ((double)rate - cell->mean);
            }
            shadow_recompute_thresholds(cell, class);
        }

        if (learning_start > 0) {
            time_t now = time(NULL);
            __u64 learn_s;
            if (shadow_cfg.learning_days == 0)
                learn_s = 60; /* quick warm-up: floor gates, no 7-day wait */
            else
                learn_s = (__u64)shadow_cfg.learning_days * 24ULL * 3600ULL;
            if ((__u64)(now - learning_start) >= learn_s) {
                cell->learning_done = 1;
                shadow_recompute_thresholds(cell, class);
            }
        }
        return;
    }

    /* Freeze learning outside Normal. */
    if (cell->state != SHADOW_NORMAL) {
        shadow_recompute_thresholds(cell, class);
        return;
    }

    double alpha = SHADOW_EWMA_ALPHA;
    double r = (double)rate;
    double prev_mean = cell->mean;
    cell->mean = prev_mean + alpha * (r - prev_mean);
    cell->var = (1.0 - alpha) * (cell->var + alpha * (r - prev_mean) * (r - prev_mean));

    /* Growth cap: mean may not rise more than 2x per hour ≈ 2^(1/3600) per second. */
    double max_mean = prev_mean * pow(SHADOW_GROWTH_CAP_PER_HOUR, 1.0 / 3600.0);
    if (cell->mean > max_mean && prev_mean > 0.0)
        cell->mean = max_mean;

    /* CUSUM: accumulate positive deviations; caller may force_enter on breach. */
    if (shadow_cfg.cusum_enable) {
        double drift = shadow_cfg.cusum_drift;
        if (drift <= 0.0)
            drift = cell->mean * 0.25; /* allow 25% above mean before climb */
        double x = r - cell->mean - drift;
        cell->cusum_pos = cell->cusum_pos + x;
        if (cell->cusum_pos < 0.0)
            cell->cusum_pos = 0.0;
    }

    /* Update hour-of-week host seasonal bins (host cells only — caller tags). */
    if (shadow_cfg.seasonal_enable && class < DET_CLASS_EXCLUSIVE_MAX) {
        int h = hour_of_week_now();
        __u32 n = host_hour_samples[class][h] + 1;
        if (n > 100000)
            n = 100000;
        double hm = host_hour_mean[class][h];
        host_hour_mean[class][h] = hm + ((double)rate - hm) / (double)n;
        host_hour_samples[class][h] = n;
    }

    shadow_recompute_thresholds(cell, class);
}

/* Returns 1 if CUSUM decision threshold exceeded.
 * Require rate already at/above t_enter so quiet classes (ICMP/RST trickle)
 * cannot force-enter during another flood and open an Attack with no IPs. */
static int shadow_cusum_trip(const struct shadow_cell *cell, __u8 class, __u64 rate)
{
    if (!shadow_cfg.cusum_enable)
        return 0;
    if (rate < cell->t_enter || cell->t_enter == 0)
        return 0;
    double h = shadow_cfg.cusum_h;
    if (h <= 0.0)
        h = (double)class_floor(class);
    return cell->cusum_pos >= h;
}

static __u64 read_sysfs_u64(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1)
        v = 0;
    fclose(f);
    return (__u64)v;
}

/* Layer-1: sustained NIC drop counters or softirq pressure → force host mode 3. */
static int shadow_layer1_pressure(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_missed_errors", ifname);
    __u64 missed = read_sysfs_u64(path);
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_no_buffer_count", ifname);
    __u64 nobuf = read_sysfs_u64(path);
    /* Some drivers use rx_fifo_errors instead of rx_no_buffer_count. */
    if (nobuf == 0) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_fifo_errors", ifname);
        nobuf = read_sysfs_u64(path);
    }

    int nic_hot = 0;
    if (nic_have_prev) {
        if (missed > prev_rx_missed || nobuf > prev_rx_nobuf)
            nic_breach_windows++;
        else
            nic_breach_windows = 0;
        if (nic_breach_windows >= (int)shadow_cfg.nic_drop_trigger_seconds)
            nic_hot = 1;
    } else {
        nic_have_prev = 1;
    }
    prev_rx_missed = missed;
    prev_rx_nobuf = nobuf;

    /* Softirq share from /proc/stat aggregate. */
    int soft_hot = 0;
    FILE *sf = fopen("/proc/stat", "r");
    if (sf) {
        char line[512];
        if (fgets(line, sizeof(line), sf)) {
            unsigned long long user, nice, sys, idle, iow, irq, sirq;
            if (sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu",
                       &user, &nice, &sys, &idle, &iow, &irq, &sirq) >= 7) {
                unsigned long long total = user + nice + sys + idle + iow + irq + sirq;
                if (softirq_have_prev && total > prev_cpu_total) {
                    unsigned long long dsoft = sirq - prev_softirq;
                    unsigned long long dtot = total - prev_cpu_total;
                    if (dtot > 0) {
                        unsigned pct = (unsigned)((dsoft * 100ULL) / dtot);
                        if (pct >= shadow_cfg.softirq_trigger_percent)
                            softirq_breach_windows++;
                        else
                            softirq_breach_windows = 0;
                        if (softirq_breach_windows >= (int)shadow_cfg.softirq_trigger_seconds)
                            soft_hot = 1;
                    }
                } else {
                    softirq_have_prev = 1;
                }
                prev_softirq = sirq;
                prev_cpu_total = total;
            }
        }
        fclose(sf);
    }

    return nic_hot || soft_hot;
}

/* force_enter: Layer-3 invalid trigger (or Incident) may enter Attack without rate gate. */
static void shadow_step_lifecycle(struct shadow_cell *cell, __u64 rate,
                                 __u8 class, __u32 dst, int is_host,
                                 int force_enter)
{
    __u8 prev = cell->state;
    __u8 prev_mode = cell->mit_mode;

    if (rate > cell->peak_pps)
        cell->peak_pps = rate;

    /*
     * Surge: far above the entry gate — no L7 burst looks like this.
     * Re-arm: this class was in Attack recently, or another class is in Attack
     * now (pulse waves / multi-vector). Both skip confirm and alert hold;
     * re-arm restores the mode the last Attack reached.
     */
    int surge = cell->t_enter > 0 && shadow_cfg.surge_factor > 0 &&
                rate >= cell->t_enter * (__u64)shadow_cfg.surge_factor;
    int recent = cell->attack_end_sample != 0 &&
                 sample_index - cell->attack_end_sample <= shadow_cfg.rearm_seconds;
    int hot = surge || ((recent || shadow_episode_open) && rate >= cell->t_enter);

    switch (cell->state) {
    case SHADOW_NORMAL:
        /* force_enter (CUSUM / L3) may count a window without rate≥enter,
         * but never skips confirm — one-second L7 bursts must not Attack. */
        if (force_enter || rate >= cell->t_enter) {
            cell->above_windows++;
            if (hot || cell->above_windows >= det_confirm_windows()) {
                cell->state = SHADOW_ATTACK;
                cell->state_since = sample_index;
                cell->above_windows = 0;
                cell->below_windows = 0;
                cell->escalate_hold = 0;
                cell->fast_entry = hot ? 1 : 0;
                cell->mit_mode = MODE_DROP_INVALID;
                if (surge)
                    cell->mit_mode = MODE_DST_CAP;
                else if (recent && cell->peak_mode > cell->mit_mode)
                    cell->mit_mode = cell->peak_mode;
                if (!recent)
                    cell->peak_mode = cell->mit_mode;
            }
        } else {
            cell->above_windows = 0;
        }
        break;

    case SHADOW_ATTACK:
        if (rate < cell->t_exit && !force_enter) {
            cell->below_windows++;
            cell->escalate_hold = 0;
            /*
             * Quiet clear: when the class is near-idle (rate ≪ exit), the
             * flood is gone — do not wait the full exit_windows (~45s).
             * Full exit_windows still applies for "soft" below-exit tails.
             */
            __u64 quiet_ceil = cell->t_exit / 8;
            if (quiet_ceil < 64)
                quiet_ceil = 64;
            int idle = (rate <= quiet_ceil);
            __u32 need = idle ? shadow_cfg.quiet_clear_windows
                              : shadow_cfg.exit_windows;
            if (need < 3)
                need = 3;
            if (cell->below_windows >= need) {
                cell->state = SHADOW_COOLDOWN;
                cell->state_since = sample_index;
                cell->attack_end_sample = sample_index;
                /* Idle end → short cooldown; soft tail keeps full cooldown. */
                cell->cooldown_left = idle
                    ? shadow_cfg.quiet_clear_windows
                    : shadow_cfg.cooldown_seconds;
                if (cell->cooldown_left < 3)
                    cell->cooldown_left = 3;
                cell->below_windows = 0;
            }
        } else {
            cell->below_windows = 0;
            if (surge && cell->mit_mode < MODE_DST_CAP) {
                cell->mit_mode = MODE_DST_CAP;
                cell->escalate_hold = 0;
                break;
            }
            /* Stepped escalate: +1 mode after N windows still above exit. */
            cell->escalate_hold++;
            if (cell->escalate_hold >= shadow_cfg.escalate_after_windows &&
                cell->mit_mode < MODE_DST_CAP) {
                cell->mit_mode++;
                cell->escalate_hold = 0;
            }
        }
        break;

    case SHADOW_COOLDOWN:
        if (force_enter || rate >= cell->t_enter) {
            cell->state = SHADOW_ATTACK;
            cell->state_since = sample_index;
            cell->cooldown_left = 0;
            cell->below_windows = 0;
            cell->escalate_hold = 0;
            cell->fast_entry = 1;
            if (surge)
                cell->mit_mode = MODE_DST_CAP;
            else if (cell->peak_mode > cell->mit_mode)
                cell->mit_mode = cell->peak_mode;
            if (cell->mit_mode < MODE_DROP_INVALID)
                cell->mit_mode = MODE_DROP_INVALID;
            break;
        }
        /* Still idle in cooldown → drain faster so NORMAL arrives promptly. */
        {
            __u64 quiet_ceil = cell->t_exit / 8;
            if (quiet_ceil < 64)
                quiet_ceil = 64;
            if (rate <= quiet_ceil && cell->cooldown_left > 1)
                cell->cooldown_left = 1;
        }
        if (cell->cooldown_left > 0)
            cell->cooldown_left--;
        /* Stepped de-escalate: −1 per cooldown second; never jump straight to OFF. */
        if (cell->mit_mode > MODE_DROP_INVALID)
            cell->mit_mode--;
        if (cell->cooldown_left == 0 && cell->mit_mode <= MODE_DROP_INVALID) {
            cell->state = SHADOW_NORMAL;
            cell->state_since = sample_index;
            cell->peak_pps = 0;
            cell->mit_mode = MODE_OFF;
            cell->escalate_hold = 0;
        }
        break;
    }

    if (cell->state == SHADOW_ATTACK && cell->mit_mode > cell->peak_mode)
        cell->peak_mode = cell->mit_mode;

    if (prev != cell->state || prev_mode != cell->mit_mode) {
        char ipbuf[INET_ADDRSTRLEN];
        const char *why = "rate";

        if (is_host)
            snprintf(ipbuf, sizeof(ipbuf), "HOST");
        else
            inet_ntop(AF_INET, &dst, ipbuf, sizeof(ipbuf));

        if (surge && cell->state == SHADOW_ATTACK && prev_mode != cell->mit_mode)
            why = "surge";
        else if (force_enter && prev == SHADOW_NORMAL && cell->state == SHADOW_ATTACK)
            why = "force";
        else if (prev == SHADOW_NORMAL && cell->state == SHADOW_ATTACK)
            why = cell->fast_entry ? "rearm" : "threshold";
        else if (prev == SHADOW_ATTACK && cell->state == SHADOW_COOLDOWN)
            why = "below_exit";
        else if (prev == SHADOW_COOLDOWN && cell->state == SHADOW_ATTACK)
            why = "reenter";
        else if (prev == SHADOW_COOLDOWN && cell->state == SHADOW_NORMAL)
            why = "cleared";
        else if (prev == cell->state && prev_mode != cell->mit_mode)
            why = (cell->mit_mode > prev_mode) ? "escalate" : "deescalate";

        /* DETECT lines are the primary operator view of the adaptive engine. */
        if (prev != cell->state) {
            LOG_N("DETECT %s %s %s→%s why=%s mode=%s→%s "
                  "rate=%llu enter=%llu exit=%llu mean=%.0f peak=%llu "
                  "above=%u below=%u cooldown=%u\n",
                  ipbuf, det_class_name(class),
                  shadow_state_name(prev), shadow_state_name(cell->state),
                  why,
                  mit_mode_name(prev_mode), mit_mode_name(cell->mit_mode),
                  (unsigned long long)rate,
                  (unsigned long long)cell->t_enter,
                  (unsigned long long)cell->t_exit,
                  cell->mean,
                  (unsigned long long)cell->peak_pps,
                  cell->above_windows, cell->below_windows,
                  cell->cooldown_left);
            if (is_host)
                shadow_report_host_transition(class, prev, cell->state, cell, rate, why);
        } else {
            LOG_N("DETECT %s %s mode %s→%s why=%s "
                  "rate=%llu enter=%llu exit=%llu peak=%llu\n",
                  ipbuf, det_class_name(class),
                  mit_mode_name(prev_mode), mit_mode_name(cell->mit_mode),
                  why,
                  (unsigned long long)rate,
                  (unsigned long long)cell->t_enter,
                  (unsigned long long)cell->t_exit,
                  (unsigned long long)cell->peak_pps);
        }
    }
    /* Sustained-Attack gate for panel / episode START (every sample). */
    if (is_host)
        shadow_tick_alert_hold(class, cell, rate);
}

static __u64 shadow_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * ONE_SECOND_NS + (__u64)ts.tv_nsec;
}

/* Publish mitigation mode for XDP (watchdog refresh every sample). */
static void publish_mode(int mode_fd, __u32 dst, __u8 class,
                         const struct shadow_cell *cell, __u8 incident,
                         __u8 force_cap)
{
    struct det_key k = { .dst = dst, .class = class };
    __u8 mode = cell->mit_mode;
    if (cell->state == SHADOW_NORMAL)
        mode = MODE_OFF;
    if (force_cap && mode < MODE_DST_CAP && cell->state != SHADOW_NORMAL)
        mode = MODE_DST_CAP;
    if (incident && mode < MODE_DROP_INVALID)
        mode = MODE_DROP_INVALID;
    if (mode == MODE_OFF) {
        bpf_map_delete_elem(mode_fd, &k);
        return;
    }
    struct mode_val v = {0};
    v.mode = mode;
    v.state = cell->state;
    v.incident = incident;
    v.expires_ns = shadow_mono_ns() + 5ULL * ONE_SECOND_NS;
    bpf_map_update_elem(mode_fd, &k, &v, BPF_ANY);
}

/* 1 while the previous sample saw host ceiling breach or Layer-1 NIC/softirq pressure. */
static int host_pressure_active;

static void publish_class_limits(int lim_fd, __u8 class, const struct shadow_cell *cell,
                                 int pressure)
{
    if (lim_fd < 0 || class >= DET_CLASS_MAX)
        return;
    __u32 key = class;
    struct mode_limits lim = {0};

    __u64 floor = 1000;
    __u64 cap = 100000;
    switch (class) {
    case DET_CLASS_SYN:    floor = 20000; cap = global_capacity_profile.cap_syn  ?: 48000; break;
    case DET_CLASS_ACK:    floor = 50000; cap = global_capacity_profile.cap_ack  ?: 121000; break;
    case DET_CLASS_RST:    floor = 10000; cap = global_capacity_profile.cap_rst  ?: 24000; break;
    case DET_CLASS_ICMP:   floor = 2000;  cap = global_capacity_profile.cap_icmp ?: 12000; break;
    case DET_CLASS_UDP:    floor = 20000; cap = global_capacity_profile.cap_udp  ?: 363000; break;
    case DET_CLASS_GRE:    floor = 1000;  cap = global_capacity_profile.cap_gre  ?: 1000; break;
    case DET_CLASS_DATA:   floor = 50000; cap = global_capacity_profile.cap_data ?: 242000; break;
    case DET_CLASS_SYNACK: floor = 10000; cap = global_capacity_profile.cap_ack / 2 ?: 60000; break;
    case DET_CLASS_SOCKET: floor = 100;   cap = 5000; break;
    case DET_CLASS_FIN:    floor = 5000;  cap = 50000; break;
    case DET_CLASS_FRAG:   floor = 2000;  cap = 20000; break;
    default: break;
    }

    __u64 from_mean = (__u64)(cell->mean * (double)shadow_cfg.src_bucket_k + 0.5);
    if (from_mean < floor / 10)
        from_mean = floor / 10;
    if (from_mean < 50)
        from_mean = 50;
    lim.src_pps = (__u32)(from_mean > 1000000 ? 1000000 : from_mean);
    /*
     * DST_CAP gate = this class's Attack-entry rate (≥ 3× learned mean), not a
     * share of theoretical NIC/CPU capacity: the capacity share is millions of
     * pps on large hosts, which the stack cannot absorb long before it is hit.
     * SYN keeps the capacity cap (cookies validate) unless the host is already
     * dropping at the NIC / softirq.
     */
    {
        __u64 dst = cell->t_enter ? cell->t_enter : floor;
        if (dst < floor)
            dst = floor;
        if (dst > cap)
            dst = cap;
        if (class == DET_CLASS_SYN && !pressure)
            dst = cap;
        lim.dst_pps = (__u32)(dst > 0xffffffffULL ? 0xffffffffU : dst);
    }
    /* Per-flow DATA: mean * FLOW_PPS_K, floored for small baselines. */
    {
        __u64 flow = (__u64)(cell->mean * (double)shadow_cfg.flow_pps_k / 10.0 + 0.5);
        if (flow < 50)
            flow = 50;
        if (flow > 100000)
            flow = 100000;
        lim.flow_pps = (__u32)flow;
    }
    /* HANDSHAKE new-flow + SOCKET concurrent caps (plan defaults). */
    {
        __u64 nf = (__u64)(cell->mean * (double)shadow_cfg.flow_pps_k / 20.0 + 0.5);
        if (nf < 20)
            nf = 20;
        if (nf > 100000)
            nf = 100000;
        lim.new_flow_pps = (__u32)nf;
    }
    lim.socket_src_cap = 1000;      /* source_concurrent_cap */
    lim.socket_prefix24_cap = 20000; /* prefix24_concurrent_cap */
    bpf_map_update_elem(lim_fd, &key, &lim, BPF_ANY);
}

static __u64 sum_det_val_percpu(const void *raw, size_t stride, int nr)
{
    __u64 pkts = 0;
    for (int cpu = 0; cpu < nr; cpu++) {
        const struct det_val *p =
            (const struct det_val *)((const char *)raw + cpu * stride);
        pkts += p->pkts;
    }
    return pkts;
}

static void *shadow_worker(void *arg)
{
    struct bpf_object *obj = arg;
    int det_class_fd = bpf_object__find_map_fd_by_name(obj, "det_class_totals");
    int det_map_fd = bpf_object__find_map_fd_by_name(obj, "det_counters");
    int mode_fd = bpf_object__find_map_fd_by_name(obj, "mitigation_mode");
    int lim_fd = bpf_object__find_map_fd_by_name(obj, "mode_limits");
    int invalid_fd = bpf_object__find_map_fd_by_name(obj, "invalid_totals");
    int pass_fd = bpf_object__find_map_fd_by_name(obj, "valid_pass_reasons");
    int bss_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    __u64 pass_prev[PASS_REASON_MAX] = {0};
    __u64 pass_rate[PASS_REASON_MAX] = {0};
    int pass_have_prev = 0;
    if (det_class_fd < 0 || det_map_fd < 0) {
        LOG_E("SHADOW: missing det maps\n");
        return NULL;
    }
    if (mode_fd < 0) {
        LOG_E("SHADOW: missing mitigation_mode map (Phase 4 disabled)\n");
        mode_fd = -1;
    }
    if (lim_fd < 0) {
        LOG_W("SHADOW: missing mode_limits map (Phase 5 limits disabled)\n");
        lim_fd = -1;
    }
    if (invalid_fd < 0)
        LOG_W("SHADOW: missing invalid_totals (L3 trigger disabled)\n");

    int nr = shadow_percpu_nr_cpus();
    size_t stride = shadow_percpu_stride(sizeof(struct det_val));
    void *raw = calloc((size_t)nr, stride);
    size_t inv_stride = shadow_percpu_stride(sizeof(__u64));
    void *inv_raw = calloc((size_t)nr, inv_stride);
    if (!raw)
        return NULL;

    /* learning_days=0 → 60s quick warm-up (not a 7-day wait). */
    __u64 learning_secs = shadow_cfg.learning_days == 0
                              ? 60ULL
                              : (__u64)shadow_cfg.learning_days * 24ULL * 3600ULL;

    learning_start = time(NULL);
    LOG_I("DETECT engine started: level=%u(%s) floor_x=%.3f km_x=%.3f "
          "confirm=%uw learning=%llus exit=%uw quiet=%uw alert_hold=%uw "
          "cooldown=%us escalate=%uw surge=x%u rearm=%us invalid_floor=%upps ratio=%.3f "
          "mode_map=%s cusum=%u seasonal=%u\n",
          det_level(), det_level_name(det_level()),
          det_floor_scale(), det_km_scale(),
          det_confirm_windows(),
          (unsigned long long)learning_secs,
          shadow_cfg.exit_windows, shadow_cfg.quiet_clear_windows,
          shadow_cfg.alert_hold_windows,
          shadow_cfg.cooldown_seconds,
          shadow_cfg.escalate_after_windows,
          shadow_cfg.surge_factor, shadow_cfg.rearm_seconds,
          shadow_cfg.invalid_floor_pps,
          shadow_cfg.invalid_ratio,
          mode_fd >= 0 ? "yes" : "no",
          shadow_cfg.cusum_enable, shadow_cfg.seasonal_enable);

    struct det_key walk_key = {0};
    int walk_has_key = 0;

    while (!exiting && !shadow_stop) {
        sample_index++;
        time_t now = time(NULL);
        int still_learning = 0;
        if ((__u64)(now - learning_start) < learning_secs)
            still_learning = 1;

        shadow_episode_open = 0;
        for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++)
            if (host_cells[c].state == SHADOW_ATTACK)
                shadow_episode_open = 1;

        if (pass_fd >= 0 && inv_raw) {
            for (__u32 r = 0; r < PASS_REASON_MAX; r++) {
                __u64 sum = 0;
                if (bpf_map_lookup_elem(pass_fd, &r, inv_raw) != 0)
                    continue;
                for (int cpu = 0; cpu < nr; cpu++)
                    sum += *(const __u64 *)((const char *)inv_raw + cpu * inv_stride);
                pass_rate[r] = (pass_have_prev && sum >= pass_prev[r]) ? sum - pass_prev[r] : 0;
                pass_prev[r] = sum;
            }
            pass_have_prev = 1;
        }

        /* Layer 3: host-wide invalid PPS + ratio vs total exclusive class rate. */
        __u64 invalid_rate = 0;
        __u64 total_rate = 0;
        int invalid_force = 0;
        if (invalid_fd >= 0 && inv_raw) {
            __u64 inv_sum = 0;
            for (__u32 r = 0; r < INVALID_REASON_MAX; r++) {
                if (bpf_map_lookup_elem(invalid_fd, &r, inv_raw) != 0)
                    continue;
                for (int cpu = 0; cpu < nr; cpu++) {
                    const __u64 *p = (const __u64 *)((const char *)inv_raw + cpu * inv_stride);
                    inv_sum += *p;
                }
            }
            if (host_invalid_have_prev)
                invalid_rate = (inv_sum >= host_invalid_prev) ?
                               (inv_sum - host_invalid_prev) : inv_sum;
            else
                host_invalid_have_prev = 1;
            host_invalid_prev = inv_sum;
        }

        /* STOMP vs HANDSHAKE label majority — before DATA transitions fire alerts. */
        shadow_update_data_overlay(det_class_fd, raw, stride, nr);

        /* --- Host-wide per exclusive class --- */
        __u32 attacks = 0;
        for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++) {
            if (bpf_map_lookup_elem(det_class_fd, &c, raw) != 0)
                continue;
            __u64 cur = sum_det_val_percpu(raw, stride, nr);
            struct shadow_cell *cell = &host_cells[c];
            __u64 rate = 0;
            if (cell->have_prev) {
                rate = (cur >= cell->prev_pkts) ? (cur - cell->prev_pkts) : cur;
                total_rate += rate;
                shadow_update_ewma(cell, rate, (__u8)c);
                int force = shadow_cusum_trip(cell, (__u8)c, rate);
                if (force)
                    cell->cusum_pos = 0.0; /* reset after trip */
                shadow_step_lifecycle(cell, rate, (__u8)c, 0, 1, force);
            } else {
                cell->have_prev = 1;
            }
            cell->prev_pkts = cur;
            if (!cell->learning_done)
                still_learning = 1;

            global_shadow_summary.state[c] = cell->state;
            global_shadow_summary.mit_mode[c] = cell->mit_mode;
            global_shadow_summary.rate[c] = rate;
            global_shadow_summary.t_enter[c] = cell->t_enter;
            global_shadow_summary.t_exit[c] = cell->t_exit;
            global_shadow_summary.peak[c] = cell->peak_pps;
            global_shadow_summary.mean_pps[c] = (__u64)(cell->mean + 0.5);
            if (cell->state == SHADOW_ATTACK || cell->state == SHADOW_COOLDOWN)
                attacks++;
            if (lim_fd >= 0)
                publish_class_limits(lim_fd, (__u8)c, cell, host_pressure_active);
            if (mode_fd >= 0)
                publish_mode(mode_fd, 0, (__u8)c, cell, 0, 0);
        }

        if (invalid_rate >= shadow_cfg.invalid_floor_pps && total_rate > 0) {
            double ratio = (double)invalid_rate / (double)total_rate;
            if (ratio >= shadow_cfg.invalid_ratio)
                invalid_force = 1;
        }
        if (invalid_force) {
            for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++) {
                struct shadow_cell *cell = &host_cells[c];
                __u64 rate = global_shadow_summary.rate[c];
                /* Only pull classes already at enter — no phantom ICMP/RST Attack. */
                if (rate < cell->t_enter || cell->t_enter == 0)
                    continue;
                if (cell->state == SHADOW_NORMAL || cell->state == SHADOW_COOLDOWN) {
                    shadow_step_lifecycle(cell, rate, (__u8)c, 0, 1, 1);
                    if (mode_fd >= 0)
                        publish_mode(mode_fd, 0, (__u8)c, cell, 0, 0);
                }
            }
            if ((sample_index % 10) == 0)
                LOG_W("DETECT L3-invalid active: invalid_pps=%llu total_pps=%llu "
                      "ratio=%.3f (floor=%u min_ratio=%.3f)\n",
                      (unsigned long long)invalid_rate,
                      (unsigned long long)total_rate,
                      total_rate ? (double)invalid_rate / (double)total_rate : 0.0,
                      shadow_cfg.invalid_floor_pps, shadow_cfg.invalid_ratio);
        }

        /* --- Per-{dst,class} walk (budgeted) --- */
        __u32 tracked = 0;
        for (unsigned i = 0; i < SHADOW_DST_SLOTS; i++)
            if (dst_table[i].used)
                tracked++;

        int walked = 0;
        while (walked < SHADOW_WALK_BUDGET) {
            struct det_key next = {0};
            int err;
            if (!walk_has_key)
                err = bpf_map_get_next_key(det_map_fd, NULL, &next);
            else
                err = bpf_map_get_next_key(det_map_fd, &walk_key, &next);
            if (err) {
                walk_has_key = 0;
                break;
            }
            walk_key = next;
            walk_has_key = 1;
            walked++;

            if (next.class >= DET_CLASS_EXCLUSIVE_MAX)
                continue; /* skip label overlays */

            if (bpf_map_lookup_elem(det_map_fd, &next, raw) != 0)
                continue;
            __u64 cur = sum_det_val_percpu(raw, stride, nr);

            struct shadow_dst_entry *e = dst_lookup_or_insert(next.dst, next.class);
            if (!e)
                continue;
            e->last_seen = sample_index;

            __u64 rate = 0;
            if (e->cell.have_prev) {
                rate = (cur >= e->cell.prev_pkts) ? (cur - e->cell.prev_pkts) : cur;
                shadow_update_ewma(&e->cell, rate, next.class);
                shadow_step_lifecycle(&e->cell, rate, next.class, next.dst, 0, 0);
            } else {
                e->cell.have_prev = 1;
            }
            e->cell.prev_pkts = cur;
        }

        /* Phase 4–5: publish per-dst modes + Incident. */
        if (mode_fd >= 0) {
            __u32 incident_dsts[256];
            __u32 n_inc = 0;
            for (unsigned i = 0; i < SHADOW_DST_SLOTS; i++) {
                if (!dst_table[i].used)
                    continue;
                publish_mode(mode_fd, dst_table[i].dst, dst_table[i].class,
                             &dst_table[i].cell, 0, 0);
                if (dst_table[i].cell.state == SHADOW_ATTACK ||
                    dst_table[i].cell.state == SHADOW_COOLDOWN) {
                    __u32 d = dst_table[i].dst;
                    __u32 seen = 0;
                    for (__u32 k = 0; k < n_inc; k++) {
                        if (incident_dsts[k] == d) {
                            seen = 1;
                            break;
                        }
                    }
                    if (!seen && n_inc < 256)
                        incident_dsts[n_inc++] = d;
                }
            }
            for (__u32 k = 0; k < n_inc; k++) {
                for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++) {
                    /* Incident: force at least drop-invalid on all classes for dst. */
                    struct shadow_cell tmp = host_cells[c];
                    if (tmp.mit_mode < MODE_DROP_INVALID)
                        tmp.mit_mode = MODE_DROP_INVALID;
                    if (tmp.state == SHADOW_NORMAL)
                        tmp.state = SHADOW_ATTACK;
                    publish_mode(mode_fd, incident_dsts[k], (__u8)c, &tmp, 1, 0);
                }
            }
        }

        tracked = 0;
        for (unsigned i = 0; i < SHADOW_DST_SLOTS; i++)
            if (dst_table[i].used)
                tracked++;

        global_shadow_summary.attacks_active = attacks;
        global_shadow_summary.dst_tracked = tracked;
        global_shadow_summary.samples = sample_index;
        global_shadow_summary.learning = still_learning ? 1 : 0;

        /* prefer_adaptive: shadow owns Attack flags so flood handlers stay in sync. */
        if (global_fw_config.g_config.prefer_adaptive && bss_fd >= 0) {
            struct global_attack_stats *atk = &global_fw_config.g_attack_stats;
            /* Episode / flood handlers: only after alert_hold passes.
             * Soft mitigation still follows cell.state via publish_mode. */
#define SHADOW_ATK(c) (host_cells[c].state == SHADOW_ATTACK && \
                       host_alert_sent[c])
            atk->syn_attack = SHADOW_ATK(DET_CLASS_SYN);
            atk->ack_attack = SHADOW_ATK(DET_CLASS_ACK);
            atk->rst_attack = SHADOW_ATK(DET_CLASS_RST);
            atk->icmp_attack = SHADOW_ATK(DET_CLASS_ICMP);
            atk->udp_attack = SHADOW_ATK(DET_CLASS_UDP);
            atk->gre_attack = SHADOW_ATK(DET_CLASS_GRE);
            {
                int data_on = SHADOW_ATK(DET_CLASS_DATA);
                atk->stomp_attack = data_on;
                atk->handshake_attack = data_on;
            }
            atk->synack_attack = SHADOW_ATK(DET_CLASS_SYNACK);
            atk->socket_attack = SHADOW_ATK(DET_CLASS_SOCKET);
            atk->fin_attack = SHADOW_ATK(DET_CLASS_FIN);
            atk->frag_attack = SHADOW_ATK(DET_CLASS_FRAG);
            atk->other_attack = SHADOW_ATK(DET_CLASS_OTHER);
#undef SHADOW_ATK
            __u32 bkey = 0;
            bpf_map_update_elem(bss_fd, &bkey, &global_fw_config, BPF_ANY);
        }

        /* Host aggregate vs capacity ceiling, or Layer-1 NIC/softirq pressure. */
        {
            __u64 host_pps = 0;
            for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++)
                host_pps += global_shadow_summary.rate[c];
            int ceil_breach = (global_capacity_profile.host_ceiling_pps > 0 &&
                               host_pps >= global_capacity_profile.host_ceiling_pps);
            int l1 = shadow_layer1_pressure();
            int was_pressure = host_pressure_active;
            host_pressure_active = (ceil_breach || l1);
            if (lim_fd >= 0 && host_pressure_active != was_pressure) {
                for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++)
                    publish_class_limits(lim_fd, (__u8)c, &host_cells[c],
                                         host_pressure_active);
            }
            if (ceil_breach || l1) {
                static time_t last_ceil_log;
                if (now != last_ceil_log) {
                    LOG_W("DETECT HOST-pressure: pps=%llu ceiling=%llu l1=%d "
                          "→ force DST_CAP all classes\n",
                          (unsigned long long)host_pps,
                          (unsigned long long)global_capacity_profile.host_ceiling_pps,
                          l1);
                    last_ceil_log = now;
                }
                if (mode_fd >= 0) {
                    for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++) {
                        struct shadow_cell tmp = host_cells[c];
                        tmp.state = SHADOW_ATTACK;
                        if (tmp.mit_mode < MODE_DST_CAP)
                            tmp.mit_mode = MODE_DST_CAP;
                        publish_mode(mode_fd, 0, (__u8)c, &tmp, 1, 1);
                    }
                }
            }
        }

        /* Periodic snapshot so operators can confirm detection is alive. */
        {
            unsigned interval = attacks ? 5u : 10u;
            if ((sample_index % interval) == 0) {
                __u64 host_pps = 0;
                for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++)
                    host_pps += global_shadow_summary.rate[c];

                LOG_I("DETECT snapshot sample=%llu level=%u(%s) learning=%u "
                      "attacks=%u dst_tracked=%u host_pps=%llu invalid_pps=%llu "
                      "adaptive=%u drop_invalid=%u "
                      "valid_pass_pps sock=%llu mirror=%llu cookie=%llu\n",
                      (unsigned long long)sample_index,
                      det_level(), det_level_name(det_level()),
                      still_learning ? 1u : 0u, attacks, tracked,
                      (unsigned long long)host_pps,
                      (unsigned long long)invalid_rate,
                      global_fw_config.g_config.prefer_adaptive,
                      global_fw_config.g_config.enforce_drop_invalid,
                      (unsigned long long)pass_rate[PASS_REASON_SOCKET],
                      (unsigned long long)pass_rate[PASS_REASON_MIRROR],
                      (unsigned long long)pass_rate[PASS_REASON_COOKIE]);

                for (__u32 c = 0; c < DET_CLASS_EXCLUSIVE_MAX; c++) {
                    struct shadow_cell *cell = &host_cells[c];
                    /* Quiet classes stay compact; active ones get full detail. */
                    if (cell->state == SHADOW_NORMAL &&
                        global_shadow_summary.rate[c] == 0 &&
                        !attacks)
                        continue;
                    LOG_I("DETECT %-7s %-8s mode=%-12s rate=%llu enter=%llu "
                          "exit=%llu mean=%llu peak=%llu%s\n",
                          det_class_name((__u8)c),
                          shadow_state_name(cell->state),
                          mit_mode_name(cell->mit_mode),
                          (unsigned long long)global_shadow_summary.rate[c],
                          (unsigned long long)cell->t_enter,
                          (unsigned long long)cell->t_exit,
                          (unsigned long long)(cell->mean + 0.5),
                          (unsigned long long)cell->peak_pps,
                          cell->learning_done ? "" : " [learning]");
                }

                /* Top per-dst attacks (up to 8) for visibility. */
                if (attacks) {
                    unsigned shown = 0;
                    for (unsigned i = 0; i < SHADOW_DST_SLOTS && shown < 8; i++) {
                        if (!dst_table[i].used)
                            continue;
                        if (dst_table[i].cell.state == SHADOW_NORMAL)
                            continue;
                        char ipbuf[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &dst_table[i].dst, ipbuf, sizeof(ipbuf));
                        LOG_I("DETECT dst=%s %-7s %-8s mode=%s peak=%llu\n",
                              ipbuf, det_class_name(dst_table[i].class),
                              shadow_state_name(dst_table[i].cell.state),
                              mit_mode_name(dst_table[i].cell.mit_mode),
                              (unsigned long long)dst_table[i].cell.peak_pps);
                        shown++;
                    }
                }
            }
        }

        sleep(1);
    }

    free(raw);
    free(inv_raw);
    LOG_I("SHADOW control loop stopped\n");
    return NULL;
}

int start_shadow_control_loop(struct bpf_object *obj)
{
    if (shadow_started)
        return 0;
    shadow_stop = 0;
    memset(host_cells, 0, sizeof(host_cells));
    memset(dst_table, 0, sizeof(dst_table));
    memset(&global_shadow_summary, 0, sizeof(global_shadow_summary));
    sample_index = 0;

    if (pthread_create(&shadow_thr, NULL, shadow_worker, obj) != 0) {
        LOG_E("SHADOW: pthread_create failed\n");
        return -1;
    }
    shadow_started = 1;
    return 0;
}

void stop_shadow_control_loop(void)
{
    if (!shadow_started)
        return;
    shadow_stop = 1;
    pthread_join(shadow_thr, NULL);
    shadow_started = 0;
}

int set_enforce_drop_invalid(struct bpf_object *obj, int enable)
{
    global_fw_config.g_config.enforce_drop_invalid = enable ? 1 : 0;
    if (!obj)
        return 0;
    int bss_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    if (bss_fd < 0)
        return -1;
    __u32 key = 0;
    if (bpf_map_update_elem(bss_fd, &key, &global_fw_config, BPF_ANY))
        return -1;
    LOG_I("Phase 4 enforce_drop_invalid = %d\n", enable ? 1 : 0);
    return 0;
}

int set_prefer_adaptive(struct bpf_object *obj, int enable)
{
    global_fw_config.g_config.prefer_adaptive = enable ? 1 : 0;
    if (!obj)
        return 0;
    int bss_fd = bpf_object__find_map_fd_by_name(obj, ".bss");
    if (bss_fd < 0)
        return -1;
    __u32 key = 0;
    if (bpf_map_update_elem(bss_fd, &key, &global_fw_config, BPF_ANY))
        return -1;
    LOG_I("Phase 5 prefer_adaptive = %d\n", enable ? 1 : 0);
    return 0;
}

int shadow_format_status(char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
        return -1;

    struct shadow_host_summary *s = &global_shadow_summary;
    /* Format: CLASS=state/mode/rate/enter  (rate vs enter threshold). */
    int n = snprintf(buf, buflen,
                     "OK! DETECT samples=%llu learning=%u attacks=%u dst_tracked=%u "
                     "enforce_drop_invalid=%u prefer_adaptive=%u "
                     "SYN=%s/%s/%llu/%llu ACK=%s/%s/%llu/%llu DATA=%s/%s/%llu/%llu "
                     "UDP=%s/%s/%llu/%llu RST=%s/%s/%llu/%llu ICMP=%s/%s/%llu/%llu "
                     "FIN=%s/%s/%llu/%llu FRAG=%s/%s/%llu/%llu "
                     "SYNACK=%s/%s/%llu/%llu SOCKET=%s/%s/%llu/%llu GRE=%s/%s/%llu/%llu\n",
                     (unsigned long long)s->samples, s->learning, s->attacks_active,
                     s->dst_tracked,
                     global_fw_config.g_config.enforce_drop_invalid,
                     global_fw_config.g_config.prefer_adaptive,
                     shadow_state_name(s->state[DET_CLASS_SYN]),
                     mit_mode_name(s->mit_mode[DET_CLASS_SYN]),
                     (unsigned long long)s->rate[DET_CLASS_SYN],
                     (unsigned long long)s->t_enter[DET_CLASS_SYN],
                     shadow_state_name(s->state[DET_CLASS_ACK]),
                     mit_mode_name(s->mit_mode[DET_CLASS_ACK]),
                     (unsigned long long)s->rate[DET_CLASS_ACK],
                     (unsigned long long)s->t_enter[DET_CLASS_ACK],
                     shadow_state_name(s->state[DET_CLASS_DATA]),
                     mit_mode_name(s->mit_mode[DET_CLASS_DATA]),
                     (unsigned long long)s->rate[DET_CLASS_DATA],
                     (unsigned long long)s->t_enter[DET_CLASS_DATA],
                     shadow_state_name(s->state[DET_CLASS_UDP]),
                     mit_mode_name(s->mit_mode[DET_CLASS_UDP]),
                     (unsigned long long)s->rate[DET_CLASS_UDP],
                     (unsigned long long)s->t_enter[DET_CLASS_UDP],
                     shadow_state_name(s->state[DET_CLASS_RST]),
                     mit_mode_name(s->mit_mode[DET_CLASS_RST]),
                     (unsigned long long)s->rate[DET_CLASS_RST],
                     (unsigned long long)s->t_enter[DET_CLASS_RST],
                     shadow_state_name(s->state[DET_CLASS_ICMP]),
                     mit_mode_name(s->mit_mode[DET_CLASS_ICMP]),
                     (unsigned long long)s->rate[DET_CLASS_ICMP],
                     (unsigned long long)s->t_enter[DET_CLASS_ICMP],
                     shadow_state_name(s->state[DET_CLASS_FIN]),
                     mit_mode_name(s->mit_mode[DET_CLASS_FIN]),
                     (unsigned long long)s->rate[DET_CLASS_FIN],
                     (unsigned long long)s->t_enter[DET_CLASS_FIN],
                     shadow_state_name(s->state[DET_CLASS_FRAG]),
                     mit_mode_name(s->mit_mode[DET_CLASS_FRAG]),
                     (unsigned long long)s->rate[DET_CLASS_FRAG],
                     (unsigned long long)s->t_enter[DET_CLASS_FRAG],
                     shadow_state_name(s->state[DET_CLASS_SYNACK]),
                     mit_mode_name(s->mit_mode[DET_CLASS_SYNACK]),
                     (unsigned long long)s->rate[DET_CLASS_SYNACK],
                     (unsigned long long)s->t_enter[DET_CLASS_SYNACK],
                     shadow_state_name(s->state[DET_CLASS_SOCKET]),
                     mit_mode_name(s->mit_mode[DET_CLASS_SOCKET]),
                     (unsigned long long)s->rate[DET_CLASS_SOCKET],
                     (unsigned long long)s->t_enter[DET_CLASS_SOCKET],
                     shadow_state_name(s->state[DET_CLASS_GRE]),
                     mit_mode_name(s->mit_mode[DET_CLASS_GRE]),
                     (unsigned long long)s->rate[DET_CLASS_GRE],
                     (unsigned long long)s->t_enter[DET_CLASS_GRE]);
    return n < 0 ? -1 : 0;
}
