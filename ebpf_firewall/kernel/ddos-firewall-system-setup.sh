#!/bin/bash
# ddos-firewall-system-setup.sh
# Production system hardening for XDP/eBPF anti-DDoS firewall
#
# Usage:
#   ./ddos-firewall-system-setup.sh [interface] [--skip-iptables] [--skip-nic] [--dry-run] \
#       [--spread-nic-processing] [--keep-irqbalance] [--irq-affinity-numa-local] [--high-pps-softnet]
#
# What this script already does (high-PPS oriented):
#   • Bond slaves: max RX/TX rings, GRO/LRO off (XDP-friendly), rxhash on, ntuple on (best-effort),
#     RX coalesce rx-usecs=0 / rx-frames=32, ethtool -X equal <queue-count> for RSS spread.
#   • --spread-nic-processing: stop irqbalance; pin each mlx5 MSI-X IRQ to CPUs (PCI BDF match,
#     mlx5_comp* order); optional RPS/XPS on slaves (NUMA-local CPU mask).
#   • Sysctl: large netdev_max_backlog, netdev_budget / budget_usecs, conntrack sizing, TCP/rmem, etc.
#
# 10M+ pps needs more than tuning: XDP program cost, PCIe, upstream scrubbing, and often hardware
# drops (rx_discards_phy) if host cannot drain. This script improves IRQ/RSS/softnet headroom only.
#
# For Mellanox mlx5 + bond under heavy PPS: use --spread-nic-processing (stops irqbalance,
# pins IRQs by PCI BDF, enables RPS/XPS). irqbalance often mis-handles 60+ MSI-X lines.
# IRQ affinity uses all online CPUs except those in /sys/.../cpu/isolated unless you pass
# --irq-affinity-numa-local (NUMA node of the NIC(s) only).
# --high-pps-softnet: raise net.core.netdev_budget* for more work per NAPI poll (trade: latency).
#
# Safe for: bond/team interfaces, VLAN sub-interfaces, single NICs
# Idempotent: can be run multiple times without side effects

set -euo pipefail

# =====================================================================
# Configuration
# =====================================================================
IFACE="${1:-bond0}"
SKIP_IPTABLES=0
SKIP_NIC=0
DRY_RUN=0
SPREAD_NIC=0
KEEP_IRQBALANCE=0
IRQ_AFFINITY_NUMA_LOCAL=0
HIGH_PPS_SOFTNET=0
SSH_PORT=22
SYSCTL_CONF="/etc/sysctl.d/99-ddos-firewall.conf"
MODPROBE_CONF="/etc/modprobe.d/nf_conntrack.conf"

# Parse flags (after positional arg)
shift || true
for arg in "$@"; do
    case "$arg" in
        --skip-iptables) SKIP_IPTABLES=1 ;;
        --skip-nic)      SKIP_NIC=1 ;;
        --dry-run)       DRY_RUN=1 ;;
        --spread-nic-processing) SPREAD_NIC=1 ;;
        --keep-irqbalance) KEEP_IRQBALANCE=1 ;;
        --irq-affinity-numa-local) IRQ_AFFINITY_NUMA_LOCAL=1 ;;
        --high-pps-softnet) HIGH_PPS_SOFTNET=1 ;;
        --ssh-port=*)    SSH_PORT="${arg#*=}" ;;
        *)               echo "Unknown option: $arg"; exit 1 ;;
    esac
done

# =====================================================================
# Helpers
# =====================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log_ok()   { echo -e "  ${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
log_err()  { echo -e "  ${RED}[ERR]${NC} $*"; }
log_skip() { echo -e "  [SKIP] $*"; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "  [DRY-RUN] $*"
        return 0
    fi
    "$@"
}

sysctl_set() {
    local key="$1" val="$2"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "  [DRY-RUN] sysctl -w $key=$val"
        return 0
    fi
    sysctl -w "$key=$val" >/dev/null 2>&1 && return 0
    return 1
}

# Expand kernel cpulist (e.g. 0-7,16-23) to space-separated CPU numbers
expand_cpulist() {
    local IFS=','
    local -a parts
    read -r -a parts <<< "$1"
    local p a b
    for p in "${parts[@]}"; do
        if [[ "$p" == *-* ]]; then
            a=${p%-*}; b=${p#*-}
            seq "$a" "$b" 2>/dev/null || true
        else
            [ -n "$p" ] && echo "$p"
        fi
    done
}

# PCI BDF for netdev (mlx5 IRQ lines use pci:0000:12:00.0, not iface name)
nic_pci_bdf() {
    local nic="$1"
    local dev
    dev=$(readlink -f "/sys/class/net/$nic/device" 2>/dev/null || true)
    [ -n "$dev" ] || return 1
    basename "$dev"
}

# IRQ numbers whose /proc/interrupts line mentions this PCI BDF
irqs_for_pci() {
    local pci="$1"
    [ -n "$pci" ] || return 0
    awk -v pci="$pci" '
        NR == 1 { next }
        $0 ~ pci {
            gsub(/:/, "", $1)
            if ($1 ~ /^[0-9]+$/) print $1
        }
    ' /proc/interrupts 2>/dev/null | sort -un
}

# Same IRQs as irqs_for_pci, but order mlx5_compN by N (then async, then other MSI-X lines).
# IRQ number order alone does not match queue index; spreading in comp order maps queues to CPUs predictably.
irqs_for_pci_sorted() {
    local pci="$1"
    [ -n "$pci" ] || return 0
    awk -v pci="$pci" '
        NR == 1 { next }
        $0 ~ pci {
            gsub(/:/, "", $1)
            if ($1 !~ /^[0-9]+$/) next
            irq = $1
            key = 2000000 + irq
            if (match($0, /mlx5_comp[0-9]+/)) {
                line = substr($0, RSTART, RLENGTH)
                sub(/^mlx5_comp/, "", line)
                key = line + 0
            } else if (match($0, /mlx5_async[0-9]+/)) {
                line = substr($0, RSTART, RLENGTH)
                sub(/^mlx5_async/, "", line)
                key = 1000000 + line + 0
            }
            print key, irq
        }
    ' /proc/interrupts 2>/dev/null | sort -n -k1,1 -k2,2n | awk '{ print $2 }' | awk '!seen[$0]++'
}

# Online CPUs minus kernel isolated list (isolcpus / tuned); preferred targets for IRQ affinity
cpus_online_exclude_isolated() {
    local -A iso=()
    local c online
    online=$(cat /sys/devices/system/cpu/online 2>/dev/null || true)
    [ -z "$online" ] && online="0-$(($(nproc) - 1))"
    for c in $(expand_cpulist "$(cat /sys/devices/system/cpu/isolated 2>/dev/null || true)"); do
        iso[$c]=1
    done
    for c in $(expand_cpulist "$online"); do
        [ -z "${iso[$c]:-}" ] && echo "$c"
    done | sort -un
}

# CPUs on the NUMA node local to the NIC; fallback all CPUs
cpus_for_nic_numa() {
    local nic="$1"
    local nn f
    nn=$(cat "/sys/class/net/$nic/device/numa_node" 2>/dev/null || echo -1)
    if [ "$nn" -ge 0 ] && [ -f "/sys/devices/system/node/node${nn}/cpulist" ]; then
        f=$(cat "/sys/devices/system/node/node${nn}/cpulist")
        expand_cpulist "$f"
    else
        seq 0 $(($(nproc) - 1))
    fi
}

# RX queue count from sysfs (matches what ethtool -X equal N expects for that netdev)
nic_rx_queue_count() {
    local nic="$1"
    echo $(ls -d "/sys/class/net/$nic/queues/rx-"* 2>/dev/null | wc -l)
}

# Build rps_cpus / xps_cpus mask: comma-separated 32-bit little-endian groups (CPUs 0-31 first)
cpus_to_mask() {
    local -a buckets=(0 0 0 0 0 0 0 0)
    local c w b max_w=0
    for c in "$@"; do
        w=$((c / 32))
        b=$((c % 32))
        buckets[w]=$(( ${buckets[w]} | (1 << b) ))
        [ "$w" -gt "$max_w" ] && max_w=$w
    done
    local i s=""
    for i in $(seq 0 "$max_w"); do
        [ -n "$s" ] && s+=","
        s+=$(printf '%x' "${buckets[i]}")
    done
    echo "$s"
}

# =====================================================================
# Pre-flight checks
# =====================================================================
echo "=== eBPF DDoS Firewall — System Hardening ==="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    log_err "Must run as root"
    exit 1
fi

# Validate interface exists
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    log_err "Interface '$IFACE' does not exist"
    echo "  Available interfaces:"
    ip -br link | awk '{print "    " $1}'
    exit 1
fi

# Detect interface type
IFACE_TYPE="physical"
if [ -d "/sys/class/net/$IFACE/bonding" ]; then
    IFACE_TYPE="bond"
    BOND_SLAVES=$(cat "/sys/class/net/$IFACE/bonding/slaves" 2>/dev/null || echo "")
    echo "Interface: $IFACE (bond, slaves: ${BOND_SLAVES:-none})"
elif [ -d "/sys/class/net/$IFACE/bridge" ]; then
    IFACE_TYPE="bridge"
    echo "Interface: $IFACE (bridge)"
elif ip link show "$IFACE" 2>/dev/null | grep -q "vlan"; then
    IFACE_TYPE="vlan"
    echo "Interface: $IFACE (vlan)"
else
    echo "Interface: $IFACE (physical)"
fi

# Slaves for bond/team-style configs (IRQ/RPS always target hardware netdevs)
PHYSICAL_NIC_LIST="$IFACE"
if [ "$IFACE_TYPE" = "bond" ] && [ -n "${BOND_SLAVES:-}" ]; then
    PHYSICAL_NIC_LIST="$BOND_SLAVES"
fi

echo "Mode: $([ $DRY_RUN -eq 1 ] && echo 'DRY RUN' || echo 'LIVE')"
echo ""


# =====================================================================
# 1. IPTABLES — Protect during XDP restart gap
# =====================================================================
echo "[1/6] Configuring iptables..."

if [ "$SKIP_IPTABLES" -eq 1 ]; then
    log_skip "iptables (--skip-iptables)"
else
    # Verify SSH connectivity won't break — check current SSH session
    # If we're connected via SSH, ensure the port is whitelisted
    SSH_CONN=$(ss -tnp 2>/dev/null | grep "sshd" | head -1 || true)
    if [ -n "$SSH_CONN" ]; then
        DETECTED_SSH_PORT=$(echo "$SSH_CONN" | awk '{print $4}' | rev | cut -d: -f1 | rev)
        if [ -n "$DETECTED_SSH_PORT" ] && [ "$DETECTED_SSH_PORT" != "$SSH_PORT" ]; then
            log_warn "Detected SSH on port $DETECTED_SSH_PORT but configured for $SSH_PORT"
            log_warn "Use --ssh-port=$DETECTED_SSH_PORT to match"
            SSH_PORT="$DETECTED_SSH_PORT"
        fi
    fi

    # Save current rules as backup
    IPTABLES_BACKUP="/tmp/iptables-backup-$(date +%s).rules"
    iptables-save > "$IPTABLES_BACKUP" 2>/dev/null || true
    log_ok "Backed up current iptables to $IPTABLES_BACKUP"

    # Build new rules
    run iptables -F INPUT
    run iptables -P INPUT ACCEPT
    run iptables -A INPUT -i lo -j ACCEPT

    # SSH — always allow (prevent lockout)
    run iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    log_ok "SSH port $SSH_PORT whitelisted"

    # Established + related only (NOT new)
    run iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ICMP ping
    run iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

    # Drop invalid packets
    run iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    # Drop all new TCP — this is the restart gap protection
    #run iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP
    #log_ok "NEW TCP connections blocked (restart gap protection)"

    # Default policy
    #run iptables -P INPUT DROP

    # Persist
    if command -v netfilter-persistent &>/dev/null; then
        run netfilter-persistent save
        log_ok "Rules saved via netfilter-persistent"
    elif [ -d /etc/iptables ]; then
        run iptables-save > /etc/iptables/rules.v4
        log_ok "Rules saved to /etc/iptables/rules.v4"
    fi
fi


# =====================================================================
# 2. NIC RING BUFFER + OFFLOAD TUNING
# =====================================================================
echo ""
echo "[2/6] Tuning NIC..."

TUNED_NIC_LIST="$PHYSICAL_NIC_LIST"
if [ "$SKIP_NIC" -eq 1 ]; then
    log_skip "NIC tuning (--skip-nic)"
elif ! command -v ethtool &>/dev/null; then
    log_warn "ethtool not found — install with: apt install ethtool"
else
    NIC_LIST="$PHYSICAL_NIC_LIST"
    [ "$IFACE_TYPE" = "bond" ] && [ -n "${BOND_SLAVES:-}" ] && log_ok "Tuning bond slaves: $BOND_SLAVES"

    for NIC in $NIC_LIST; do
        echo "  --- $NIC ---"

        # Ring buffers
        RING_INFO=$(ethtool -g "$NIC" 2>/dev/null || true)
        if [ -n "$RING_INFO" ]; then
            MAX_RX=$(echo "$RING_INFO" | awk '/Pre-set maximums/,/Current/{if(/RX:/) print $2}' | head -1)
            CUR_RX=$(echo "$RING_INFO" | awk '/Current hardware/,/^$/{if(/RX:/) print $2}' | head -1)
            MAX_TX=$(echo "$RING_INFO" | awk '/Pre-set maximums/,/Current/{if(/TX:/) print $2}' | head -1)
            CUR_TX=$(echo "$RING_INFO" | awk '/Current hardware/,/^$/{if(/TX:/) print $2}' | head -1)

            if [ -n "$MAX_RX" ] && [ "$MAX_RX" -gt 0 ] 2>/dev/null; then
                if [ "${CUR_RX:-0}" -lt "$MAX_RX" ]; then
                    run ethtool -G "$NIC" rx "$MAX_RX" 2>/dev/null || true
                    log_ok "RX ring: $CUR_RX -> $MAX_RX"
                else
                    log_ok "RX ring: already at max ($MAX_RX)"
                fi
            fi

            if [ -n "$MAX_TX" ] && [ "$MAX_TX" -gt 0 ] 2>/dev/null; then
                if [ "${CUR_TX:-0}" -lt "$MAX_TX" ]; then
                    run ethtool -G "$NIC" tx "$MAX_TX" 2>/dev/null || true
                    log_ok "TX ring: $CUR_TX -> $MAX_TX"
                else
                    log_ok "TX ring: already at max ($MAX_TX)"
                fi
            fi
        fi

        # Offload settings — disable features that break per-packet XDP processing
        # GRO aggregates packets before XDP → breaks rate counters
        run ethtool -K "$NIC" gro off 2>/dev/null || true
        # LRO same problem as GRO
        run ethtool -K "$NIC" lro off 2>/dev/null || true
        # TSO/GSO are TX-side — safe to leave on (XDP_TX benefits from them)
        # rx-vlan-offload: leave on unless causing issues

        # --- Interrupt coalescing (lower latency / faster RX refill; more IRQ load) ---
        # mlx5: rx-usecs 0 + small rx-frames reduces batching vs defaults like 8µs/128 frames.
        # Turn off adaptive RX if driver allows (can batch too aggressively for steady high PPS + XDP)
        run ethtool -C "$NIC" adaptive-rx off 2>/dev/null || true
        if run ethtool -C "$NIC" rx-usecs 0 rx-frames 32 2>/dev/null; then
            log_ok "RX coalesce: adaptive-rx off (best effort), rx-usecs=0 rx-frames=32"
        elif run ethtool -C "$NIC" rx-usecs 0 2>/dev/null; then
            log_ok "RX coalesce: rx-usecs=0 (rx-frames not set on this driver)"
        else
            log_warn "Could not set RX coalesce on $NIC (driver may use fixed or adaptive-only)"
        fi

        # --- n-tuple / flow director (hardware steering hooks; many mlx5 parts show [fixed] off) ---
        if run ethtool -K "$NIC" ntuple on 2>/dev/null; then
            log_ok "ntuple filters: on"
        else
            log_warn "ntuple not enabled on $NIC (often off [fixed] on mlx5 — use rxhash + -X below)"
        fi

        # Enable RX flow hashing for multi-queue distribution (RSS input side)
        run ethtool -K "$NIC" rxhash on 2>/dev/null || true

        log_ok "GRO/LRO off, rxhash on"

        # --- RSS indirection: spread flows evenly across all RX queues ---
        QUEUES=$(nic_rx_queue_count "$NIC")
        if [ "${QUEUES:-0}" -ge 2 ] 2>/dev/null; then
            if run ethtool -X "$NIC" equal "$QUEUES" 2>/dev/null; then
                log_ok "RSS indirection: equal $QUEUES queues (ethtool -X)"
            else
                log_warn "ethtool -X equal $QUEUES failed on $NIC (firmware/driver limit or needs ethtool -L first)"
            fi
        else
            log_warn "Unexpected RX queue count ($QUEUES) for $NIC — skip ethtool -X"
        fi

        log_ok "RX queues: $QUEUES"
    done
fi


# =====================================================================
# 3. IRQ AFFINITY (+ optional RPS/XPS)
# =====================================================================
echo ""
echo "[3/6] Configuring IRQ affinity..."

_IRQB_ACTIVE=0
if systemctl is-active --quiet irqbalance 2>/dev/null; then
    _IRQB_ACTIVE=1
fi

if [ "$_IRQB_ACTIVE" -eq 1 ] && [ "$KEEP_IRQBALANCE" -eq 1 ]; then
    log_ok "irqbalance is running (--keep-irqbalance: leaving IRQ affinity unchanged)"
elif [ "$_IRQB_ACTIVE" -eq 1 ] && [ "$SPREAD_NIC" -eq 0 ]; then
    log_warn "irqbalance is active — under high PPS, mlx5 MSI-X often piles onto a few CPUs"
    log_warn "Fix: run again with --spread-nic-processing (stops irqbalance, pins IRQs by PCI BDF)"
else
    if [ "$_IRQB_ACTIVE" -eq 1 ] && [ "$SPREAD_NIC" -eq 1 ]; then
        run systemctl stop irqbalance 2>/dev/null || true
        log_ok "Stopped irqbalance (stable manual IRQ spread)"
    fi

    IRQ_IFACES="$PHYSICAL_NIC_LIST"

    declare -a SPREAD_CPUS=()
    if [ "$SPREAD_NIC" -eq 1 ] && [ "$IRQ_AFFINITY_NUMA_LOCAL" -eq 0 ]; then
        mapfile -t SPREAD_CPUS < <(cpus_online_exclude_isolated)
        if [ "${#SPREAD_CPUS[@]}" -eq 0 ]; then
            log_warn "No online non-isolated CPUs for IRQ spread — falling back to NUMA-local pool"
        fi
    fi
    if [ "${#SPREAD_CPUS[@]}" -eq 0 ]; then
        mapfile -t SPREAD_CPUS < <(
            {
                for _nic in $IRQ_IFACES; do
                    cpus_for_nic_numa "$_nic"
                done
            } | sort -un
        )
    fi
    if [ "${#SPREAD_CPUS[@]}" -eq 0 ]; then
        mapfile -t SPREAD_CPUS < <(seq 0 $(($(nproc) - 1)))
    fi

    _irq_pool_note="NUMA-local pool"
    if [ "$SPREAD_NIC" -eq 1 ] && [ "$IRQ_AFFINITY_NUMA_LOCAL" -eq 0 ]; then
        _irq_pool_note="online CPUs excluding isolated"
    fi

    TOTAL_IRQS=0
    declare -A SEEN_IRQ=()
    _nic_idx=0
    for NIC in $IRQ_IFACES; do
        PCI=$(nic_pci_bdf "$NIC" || true)
        IRQ_LIST=$(irqs_for_pci_sorted "$PCI")
        if [ -z "$IRQ_LIST" ]; then
            IRQ_LIST=$(irqs_for_pci "$PCI")
        fi
        if [ -z "$IRQ_LIST" ]; then
            log_warn "No IRQ lines matched PCI ${PCI:-?} for $NIC — trying netdev name in /proc/interrupts"
            IRQ_LIST=$(awk -v n="$NIC" 'NR>1 && $0 ~ n {gsub(/:/,"",$1); print $1}' /proc/interrupts 2>/dev/null | sort -un)
        fi
        # Stagger starting CPU per port so two 100G slaves do not align all queues to the same phase
        _n="${#SPREAD_CPUS[@]}"
        [ "$_n" -gt 0 ] || _n=1
        _irq_slot=0
        _base=$(( (_nic_idx * 17) % _n ))
        for IRQ in $IRQ_LIST; do
            [ -z "$IRQ" ] && continue
            [ -n "${SEEN_IRQ[$IRQ]:-}" ] && continue
            SEEN_IRQ[$IRQ]=1
            _cpu=${SPREAD_CPUS[$(( (_base + _irq_slot) % _n ))]}
            _irq_slot=$((_irq_slot + 1))
            if [ -w "/proc/irq/$IRQ/smp_affinity_list" ]; then
                run sh -c "echo ${_cpu} > /proc/irq/$IRQ/smp_affinity_list" 2>/dev/null || true
            elif [ -w "/proc/irq/$IRQ/smp_affinity" ]; then
                # Legacy kernels: only safe for low CPU ids
                if [ "${_cpu}" -lt 32 ]; then
                    run sh -c "printf '%x\n' $((1 << _cpu)) > /proc/irq/$IRQ/smp_affinity" 2>/dev/null || true
                fi
            fi
            TOTAL_IRQS=$((TOTAL_IRQS + 1))
        done
        _nic_idx=$((_nic_idx + 1))
    done

    if [ "$TOTAL_IRQS" -gt 0 ]; then
        log_ok "Pinned $TOTAL_IRQS NIC IRQs across ${#SPREAD_CPUS[@]} CPUs (PCI BDF, mlx5_comp order, per-port CPU phase, $_irq_pool_note)"
    else
        log_warn "No NIC IRQs pinned — verify mlx5 and /proc/interrupts"
    fi
fi

# RPS / XPS: spreads softnet work after XDP_PASS (does not replace line-rate NIC drops)
if [ "$SKIP_NIC" -eq 0 ] && [ "$SPREAD_NIC" -eq 1 ] && [ -n "${TUNED_NIC_LIST:-}" ]; then
    echo ""
    echo "  RPS / XPS (same NUMA as each slave)..."
    sysctl_set net.core.rps_sock_flow_entries 131072 || true
    for NIC in $TUNED_NIC_LIST; do
        mapfile -t _ncpus < <(cpus_for_nic_numa "$NIC" | sort -un)
        [ "${#_ncpus[@]}" -eq 0 ] && continue
        _mask=$(cpus_to_mask "${_ncpus[@]}")
        [ -z "$_mask" ] && continue
        for _rx in /sys/class/net/"$NIC"/queues/rx-*/rps_cpus; do
            [ -f "$_rx" ] || continue
            run sh -c "echo '$_mask' > \"$_rx\"" 2>/dev/null || true
        done
        for _rx in /sys/class/net/"$NIC"/queues/rx-*/rps_flow_cnt; do
            [ -f "$_rx" ] || continue
            run sh -c "echo 4096 > \"$_rx\"" 2>/dev/null || true
        done
        for _tx in /sys/class/net/"$NIC"/queues/tx-*/xps_cpus; do
            [ -f "$_tx" ] || continue
            run sh -c "echo '$_mask' > \"$_tx\"" 2>/dev/null || true
        done
        log_ok "RPS/XPS for $NIC (mask=$_mask, ${#_ncpus[@]} CPUs in NUMA pool)"
    done
fi


# =====================================================================
# 4. CONNTRACK HASH TABLE
# =====================================================================
echo ""
echo "[4/6] Configuring conntrack..."

# Calculate optimal hashsize: nf_conntrack_max / 4
TARGET_MAX=2097152
TARGET_HASH=$((TARGET_MAX / 4))

run sh -c "echo 'options nf_conntrack hashsize=$TARGET_HASH' > $MODPROBE_CONF"
log_ok "Wrote $MODPROBE_CONF (hashsize=$TARGET_HASH)"

# Try live update
if [ -f /sys/module/nf_conntrack/parameters/hashsize ]; then
    CURRENT_HASH=$(cat /sys/module/nf_conntrack/parameters/hashsize)
    if [ "$CURRENT_HASH" -lt "$TARGET_HASH" ]; then
        run sh -c "echo $TARGET_HASH > /sys/module/nf_conntrack/parameters/hashsize" 2>/dev/null || true
        NEW_HASH=$(cat /sys/module/nf_conntrack/parameters/hashsize)
        log_ok "Conntrack hashsize: $CURRENT_HASH -> $NEW_HASH"
    else
        log_ok "Conntrack hashsize already >= $TARGET_HASH (current: $CURRENT_HASH)"
    fi
else
    log_warn "nf_conntrack module not loaded — hashsize will apply on next load/reboot"
fi


# =====================================================================
# 5. SYSCTL
# =====================================================================
echo ""
echo "[5/6] Applying sysctl..."

if [ ! -f "$SYSCTL_CONF" ]; then
    log_warn "$SYSCTL_CONF not found — creating with defaults"
    cat > "$SYSCTL_CONF" << 'SYSCTL_EOF'
# Auto-generated by ddos-firewall-system-setup.sh
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 15
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60
net.netfilter.nf_conntrack_icmp_timeout = 10
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 250000
net.core.netdev_budget = 1000
net.core.netdev_budget_usecs = 8000
net.core.rps_sock_flow_entries = 131072
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = 16777216
net.core.rmem_default = 4194304
net.core.wmem_max = 16777216
net.core.wmem_default = 4194304
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
vm.max_map_count = 1048576
SYSCTL_EOF
fi

# Apply line by line to catch individual failures instead of aborting entirely
APPLIED=0
FAILED=0
while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue

    KEY=$(echo "$line" | cut -d= -f1 | tr -d ' ')
    VAL=$(echo "$line" | cut -d= -f2- | tr -d ' ')

    if [ -z "$KEY" ] || [ -z "$VAL" ]; then
        continue
    fi

    if sysctl_set "$KEY" "$VAL"; then
        APPLIED=$((APPLIED + 1))
    else
        FAILED=$((FAILED + 1))
        log_warn "Failed to set $KEY=$VAL (module not loaded or param unavailable)"
    fi
done < "$SYSCTL_CONF"

log_ok "Applied $APPLIED sysctl parameters"
[ "$FAILED" -gt 0 ] && log_warn "$FAILED parameters failed (may need reboot or module load)"

# Ensure softnet/RPS globals even when 99-ddos-firewall.conf predates these keys
if [ "$HIGH_PPS_SOFTNET" -eq 1 ]; then
    echo ""
    echo "  High-PPS softnet (--high-pps-softnet): more NAPI work per poll (watch p99 latency)."
    sysctl_set net.core.netdev_budget 5000
    sysctl_set net.core.netdev_budget_usecs 20000
    sysctl_set net.core.netdev_max_backlog 500000
    log_ok "netdev_budget=5000 netdev_budget_usecs=20000 netdev_max_backlog=500000"
else
    sysctl_set net.core.netdev_budget 1000
    sysctl_set net.core.netdev_budget_usecs 8000
fi
sysctl_set net.core.rps_sock_flow_entries 131072

if [ "$HIGH_PPS_SOFTNET" -eq 1 ]; then
    # Persist overrides into sysctl.d so they survive partial reloads
    if [ -f "$SYSCTL_CONF" ] && ! grep -q 'net.core.netdev_budget = 5000' "$SYSCTL_CONF" 2>/dev/null; then
        {
            echo ""
            echo "# High-PPS softnet (ddos-firewall-system-setup.sh --high-pps-softnet)"
            echo "net.core.netdev_budget = 5000"
            echo "net.core.netdev_budget_usecs = 20000"
            echo "net.core.netdev_max_backlog = 500000"
        } >> "$SYSCTL_CONF"
        log_ok "Appended high-PPS netdev_* keys to $SYSCTL_CONF"
    fi
fi


# =====================================================================
# 6. RESOURCE LIMITS CHECK
# =====================================================================
echo ""
echo "[6/6] Checking resource limits..."

# Check MEMLOCK
MEMLOCK=$(ulimit -l 2>/dev/null || echo "0")
if [ "$MEMLOCK" = "unlimited" ]; then
    log_ok "MEMLOCK: unlimited"
else
    log_warn "MEMLOCK: $MEMLOCK KB — BPF maps may fail to allocate"
    log_warn "Add 'LimitMEMLOCK=infinity' to systemd service"
fi

# Check NOFILE
NOFILE=$(ulimit -n 2>/dev/null || echo "0")
if [ "$NOFILE" -ge 65536 ] 2>/dev/null; then
    log_ok "NOFILE: $NOFILE"
else
    log_warn "NOFILE: $NOFILE — consider increasing to 1048576"
fi

# Check available memory for BPF maps (~2.5GB needed)
MEM_AVAIL_KB=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo "0")
MEM_AVAIL_GB=$((MEM_AVAIL_KB / 1024 / 1024))
BPF_NEED_GB=3
if [ "$MEM_AVAIL_GB" -ge "$BPF_NEED_GB" ]; then
    log_ok "Available memory: ${MEM_AVAIL_GB}GB (need ~${BPF_NEED_GB}GB for BPF maps)"
else
    log_warn "Available memory: ${MEM_AVAIL_GB}GB — BPF maps need ~${BPF_NEED_GB}GB"
fi

# Check XDP support on the interface
XDP_SUPPORT=""
if command -v ethtool &>/dev/null; then
    # Check if the driver supports XDP
    DRIVER=$(ethtool -i "$IFACE" 2>/dev/null | awk '/driver:/{print $2}' || true)
    if [ -n "$DRIVER" ]; then
        case "$DRIVER" in
            i40e|ixgbe|ixgbevf|mlx5_core|mlx4_en|nfp|bnxt_en|qede|ena|ice|igb|igc|virtio_net|veth|bonding)
                XDP_SUPPORT="native"
                log_ok "Driver '$DRIVER' supports native XDP"
                ;;
            *)
                XDP_SUPPORT="skb"
                log_warn "Driver '$DRIVER' may only support SKB mode XDP (slower)"
                ;;
        esac
    fi
fi

# Verify kernel version
KVER=$(uname -r | cut -d. -f1-2)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
if [ "$KMAJOR" -gt 5 ] || ([ "$KMAJOR" -eq 5 ] && [ "$KMINOR" -ge 10 ]); then
    log_ok "Kernel $(uname -r) (>= 5.10, full XDP support)"
else
    log_warn "Kernel $(uname -r) — recommend >= 5.10 for full XDP features"
fi


# =====================================================================
# Summary
# =====================================================================
echo ""
echo "==========================================="
echo "  System hardening complete"
echo "==========================================="
echo ""
echo "  Interface:     $IFACE ($IFACE_TYPE)"
echo "  Kernel:        $(uname -r)"
[ -n "${DRIVER:-}" ] && echo "  NIC driver:    $DRIVER ($XDP_SUPPORT XDP)"
echo "  CPUs:          $(nproc)"
echo "  Memory:        ${MEM_AVAIL_GB}GB available"
echo ""

if [ -n "${IPTABLES_BACKUP:-}" ] && [ -f "${IPTABLES_BACKUP:-}" ]; then
    echo "  iptables backup: $IPTABLES_BACKUP"
    echo "  To restore:      iptables-restore < $IPTABLES_BACKUP"
    echo ""
fi

echo "  systemd service should have:"
echo "    LimitMEMLOCK=infinity"
echo "    LimitNOFILE=1048576"
echo "    Nice=-20"
echo ""
echo "  Beyond this script (10M+ pps goals):"
echo "    • Light native XDP on slaves; avoid trace_printk / locks on hot path."
echo "    • Upstream scrubbing / hardware ACLs — rx_discards_phy means NIC overload, not fixable by sysctl alone."
echo "    • PCIe gen/lanes, mlx5 firmware, kernel 6.x; consider --high-pps-softnet and measure latency."
echo ""