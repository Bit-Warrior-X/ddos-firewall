#!/bin/bash
# ddos-firewall-system-setup.sh
# Production system hardening for XDP/eBPF anti-DDoS firewall
#
# Usage:
#   ./ddos-firewall-system-setup.sh [interface] [--skip-iptables] [--skip-nic] [--dry-run]
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

if [ "$SKIP_NIC" -eq 1 ]; then
    log_skip "NIC tuning (--skip-nic)"
elif ! command -v ethtool &>/dev/null; then
    log_warn "ethtool not found — install with: apt install ethtool"
else
    # For bond interfaces, tune the slave NICs (the bond itself doesn't have ring buffers)
    if [ "$IFACE_TYPE" = "bond" ] && [ -n "$BOND_SLAVES" ]; then
        NIC_LIST="$BOND_SLAVES"
        log_ok "Tuning bond slaves: $BOND_SLAVES"
    else
        NIC_LIST="$IFACE"
    fi

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

        # Enable RX flow hashing for multi-queue distribution
        run ethtool -K "$NIC" rxhash on 2>/dev/null || true

        log_ok "GRO/LRO off, rxhash on"

        # Show current queue count
        QUEUES=$(ls -d /sys/class/net/"$NIC"/queues/rx-* 2>/dev/null | wc -l)
        log_ok "RX queues: $QUEUES"
    done
fi


# =====================================================================
# 3. IRQ AFFINITY
# =====================================================================
echo ""
echo "[3/6] Configuring IRQ affinity..."

if systemctl is-active --quiet irqbalance 2>/dev/null; then
    log_ok "irqbalance is running (handles affinity automatically)"
    log_ok "For maximum XDP performance, consider stopping irqbalance"
    log_ok "and pinning IRQs manually to specific cores"
else
    NCPUS=$(nproc)

    # For bond, distribute IRQs from all slave NICs
    if [ "$IFACE_TYPE" = "bond" ] && [ -n "$BOND_SLAVES" ]; then
        IRQ_IFACES="$BOND_SLAVES"
    else
        IRQ_IFACES="$IFACE"
    fi

    TOTAL_IRQS=0
    CPU_IDX=0
    for NIC in $IRQ_IFACES; do
        IRQ_LIST=$(grep "$NIC" /proc/interrupts 2>/dev/null | awk '{print $1}' | tr -d ':' || true)
        for IRQ in $IRQ_LIST; do
            CPU_MASK=$(printf "%x" $((1 << CPU_IDX)))
            run sh -c "echo $CPU_MASK > /proc/irq/$IRQ/smp_affinity" 2>/dev/null || true
            CPU_IDX=$(( (CPU_IDX + 1) % NCPUS ))
            TOTAL_IRQS=$((TOTAL_IRQS + 1))
        done
    done

    if [ "$TOTAL_IRQS" -gt 0 ]; then
        log_ok "Distributed $TOTAL_IRQS IRQs across $NCPUS CPUs"
    else
        log_warn "No IRQs found for $IFACE — may be using MSI-X naming"
        log_warn "Check: grep -i '$IFACE\|msi' /proc/interrupts"
    fi
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