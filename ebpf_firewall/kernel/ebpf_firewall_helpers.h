#ifndef __EBPF_FIREWALL_HELPERS_H
#define __EBPF_FIREWALL_HELPERS_H

#include "common.h"

/*-------------------------------------------- Helper Functions ------------------------------------*/

/**
 * Check if IP should be blocked based on expiration time
 * Returns: 1 if blocked, 0 if expired/not blocked
 */
static __always_inline int check_blocked_ip(__u32 src_ip, __u64 now, __u64 *expire_out) {
    __u64 *blocked_exp = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (!blocked_exp) {
        return 0; // Not blocked
    }
    
    if (now < *blocked_exp) {
        if (expire_out) *expire_out = *blocked_exp;
        return 1; // Still blocked
    }
    
    // Expired - remove from map
    struct event evt = {0};
    evt.time = now;
    evt.srcip = src_ip;
    evt.reason = EVENT_IP_BLOCK_END;
    bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
    bpf_map_delete_elem(&blocked_ips, &src_ip);
    return 0; // No longer blocked
}

/**
 * Block an IP address with expiration time
 */
static __always_inline void block_ip(__u32 src_ip, __u64 expire_time, __u16 reason) {
    __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (!blocked_time_p) {
        bpf_map_update_elem(&blocked_ips, &src_ip, &expire_time, BPF_ANY);
    } else {
        *blocked_time_p = expire_time;
    }
    
    struct event evt = {0};
    evt.time = bpf_ktime_get_ns();
    evt.srcip = src_ip;
    evt.reason = reason;
    bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
}

/**
 * Update fixed window counter and check threshold
 * Returns: 1 if threshold exceeded, 0 otherwise
 */
static __always_inline int update_fixed_counter(
    void *counter_map,
    void *metrics_map,
    __u32 src_ip,
    __u64 now,
    __u64 fixed_duration,
    __u32 fixed_threshold,
    __u16 fixed_type
) {
    // Update metrics map
    struct flood_stats *metrics_stats = bpf_map_lookup_elem(metrics_map, &src_ip);
    if (metrics_stats) {
        __u64 timediff = now - metrics_stats->last_ts;
        if (timediff > fixed_duration) {
            struct fixed_ip_event fixed_evt = {0};
            fixed_evt.srcip = src_ip;
            fixed_evt.fixed_type = fixed_type;
            fixed_evt.duration = timediff;
            fixed_evt.pkt_count = metrics_stats->count;
            fixed_evt.over_fixed = 0;
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);
            
            metrics_stats->count = 1;
            metrics_stats->last_ts = now;
        } else {
            metrics_stats->count += 1;
        }
    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(metrics_map, &src_ip, &new_stats, BPF_ANY);
    }
    
    // Check active counter
    struct flood_stats *fixed_stats = bpf_map_lookup_elem(counter_map, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > fixed_duration) {
            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
            if (fixed_stats->count > fixed_threshold) {
                return 1; // Threshold exceeded
            }
        }
    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(counter_map, &src_ip, &new_stats, BPF_ANY);
    }
    
    return 0; // Threshold not exceeded
}

/**
 * Check and update burst state
 * Returns: 1 if should block (burst threshold exceeded), 0 otherwise
 */
static __always_inline int check_burst_detection(
    void *burst_map,
    __u32 src_ip,
    __u64 now,
    __u64 burst_gap_ns,
    __u32 burst_pkt_threshold,
    __u32 burst_count_threshold
) {
    struct burst_state *state = bpf_map_lookup_elem(burst_map, &src_ip);
    
    if (!state) {
        // Initialize new state
        struct burst_state new_state = {0};
        new_state.last_pkt_time = now;
        new_state.current_burst_count = 1;
        new_state.burst_count = 0;
        new_state.last_reset = now;
        bpf_map_update_elem(burst_map, &src_ip, &new_state, BPF_ANY);
        return 0;
    }
    
    // Calculate total bursts (including current burst if threshold met)
    __u32 total_bursts = state->burst_count;
    if (state->current_burst_count >= burst_pkt_threshold) {
        total_bursts++;
    }
    
    // Check if burst threshold exceeded
    if (total_bursts >= burst_count_threshold) {
        return 1; // Should block
    }
    
    // Update state
    if (now - state->last_reset >= ONE_SECOND_NS) {
        // Reset for new second
        state->last_reset = now;
        state->current_burst_count = 1;
        state->burst_count = 0;
        state->last_pkt_time = now;
    } else {
        // Within same second
        if (now - state->last_pkt_time > burst_gap_ns) {
            // Gap too long - previous burst ends
            if (state->current_burst_count >= burst_pkt_threshold) {
                state->burst_count++;
            }
            state->current_burst_count = 1;
        } else {
            // No gap - accumulate in current burst
            state->current_burst_count++;
        }
        state->last_pkt_time = now;
    }
    
    return 0; // Don't block yet
}

/**
 * Common protocol handler logic - checks fixed window and blocks if needed
 * Returns: XDP_DROP if blocked, 0 if should continue
 */
static __always_inline int check_fixed_window_and_block(
    void *counter_map,
    void *metrics_map,
    __u32 src_ip,
    __u64 now,
    __u64 fixed_duration,
    __u32 fixed_threshold,
    __u16 fixed_type,
    __u16 block_reason,
    __u64 block_duration
) {
    struct flood_stats *fixed_stats = bpf_map_lookup_elem(counter_map, &src_ip);
    
    // Update metrics
    update_fixed_counter(counter_map, metrics_map, src_ip, now, fixed_duration, fixed_threshold, fixed_type);
    
    // Re-check after update
    fixed_stats = bpf_map_lookup_elem(counter_map, &src_ip);
    if (fixed_stats && fixed_stats->count > fixed_threshold) {
        __u64 block_exp = now + block_duration;
        block_ip(src_ip, block_exp, block_reason);
        
        struct fixed_ip_event fixed_evt = {0};
        fixed_evt.srcip = src_ip;
        fixed_evt.fixed_type = fixed_type;
        fixed_evt.duration = (now - fixed_stats->last_ts);
        fixed_evt.pkt_count = fixed_stats->count;
        fixed_evt.over_fixed = 1;
        bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);
        
        return XDP_DROP;
    }
    
    return 0; // Continue processing
}

#endif /* __EBPF_FIREWALL_HELPERS_H */


