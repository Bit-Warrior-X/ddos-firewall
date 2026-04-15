#!/usr/bin/env bash
# Real-time essentials-only view for high PPS / heavy traffic (parsed ethtool & kernel).
#
# Usage:
#   ./nic-heavy-traffic-monitor.sh [interface] [interval_sec]
# Examples:
#   ./nic-heavy-traffic-monitor.sh bond0 1
#   ./nic-heavy-traffic-monitor.sh eth0 2
#
# Requires: ethtool, ip (iproute2). Optional: sysctl.

set -eu

IFACE="${1:-bond0}"
INTERVAL="${2:-2}"

if ! command -v ethtool >/dev/null 2>&1; then
	echo "ethtool is required (apt install ethtool / iproute2)." >&2
	exit 1
fi

if [ ! -d "/sys/class/net/$IFACE" ]; then
	echo "Interface '$IFACE' does not exist." >&2
	exit 1
fi

IFACES=("$IFACE")
if [ -d "/sys/class/net/$IFACE/bonding" ]; then
	read -r SLAVES_STR <"/sys/class/net/$IFACE/bonding/slaves" || true
	if [ -n "${SLAVES_STR:-}" ]; then
		read -r -a SLAVE_ARR <<<"$SLAVES_STR"
		for s in "${SLAVE_ARR[@]}"; do
			IFACES+=("$s")
		done
	fi
fi

sysctl_get() {
	local k="$1"
	if command -v sysctl >/dev/null 2>&1; then
		sysctl -n "$k" 2>/dev/null || echo "n/a"
	else
		echo "n/a"
	fi
}

# RX/TX ring current vs max (two lines from ethtool -g)
parse_ring_summary() {
	local dev="$1"
	ethtool -g "$dev" 2>/dev/null | awk '
	/^Pre-set maximums:/ { m=1; c=0; next }
	/^Current hardware settings:/ { m=0; c=1; next }
	m && $1 ~ /^RX:/ { sub(/^[ \t]+/,"",$2); rxm=$2 }
	m && $1 ~ /^TX:/ { sub(/^[ \t]+/,"",$2); txm=$2 }
	c && $1 ~ /^RX:/ { sub(/^[ \t]+/,"",$2); rxc=$2 }
	c && $1 ~ /^TX:/ { sub(/^[ \t]+/,"",$2); txc=$2 }
	END {
		if (rxc != "" || rxm != "")
			printf "  rings  RX %s / %s   TX %s / %s\n", rxc, rxm, txc, txm
	}'
}

# RSS / queue counts: current vs max for Combined (and RX/TX if non-zero)
parse_channel_summary() {
	local dev="$1"
	ethtool -l "$dev" 2>/dev/null | awk '
	/^Pre-set maximums:/ { m=1; c=0; next }
	/^Current hardware settings:/ { m=0; c=1; next }
	m && $1 ~ /^Combined:/ { sub(/^[ \t]+/,"",$2); cm=$2 }
	m && $1 ~ /^RX:/ && $2+0>0 { sub(/^[ \t]+/,"",$2); rxm=$2 }
	m && $1 ~ /^TX:/ && $2+0>0 { sub(/^[ \t]+/,"",$2); txm=$2 }
	c && $1 ~ /^Combined:/ { sub(/^[ \t]+/,"",$2); cc=$2 }
	c && $1 ~ /^RX:/ && $2+0>0 { sub(/^[ \t]+/,"",$2); rxc=$2 }
	c && $1 ~ /^TX:/ && $2+0>0 { sub(/^[ \t]+/,"",$2); txc=$2 }
	END {
		if (cc != "" || cm != "") {
			printf "  queues Combined %s / %s", cc, cm
			if (rxc != "" || txc != "")
				printf "   RX %s/%s TX %s/%s", rxc, rxm, txc, txm
			printf "\n"
		}
	}'
}

# Interrupt moderation: first line of each queue block often empty on mlx5 — keep short list
parse_coalesce_essentials() {
	local dev="$1"
	ethtool -c "$dev" 2>/dev/null | awk '
	BEGIN { pr=0 }
	tolower($0) ~ /^adaptive-rx:|^adaptive-tx:/ { print "  " $0; next }
	$0 ~ /^rx-usecs:|^tx-usecs:|^rx-frames:|^tx-frames:/ && $0 !~ /: 0$/ { print "  " $0; pr=1 }
	END { if (!pr) print "  (defaults / not reported)" }' | head -12
}

# Top-level offload lines only (no nested tx-tcp-* noise)
parse_offload_essentials() {
	local dev="$1"
	ethtool -k "$dev" 2>/dev/null | awk '
	/^[a-z].*: (on|off)/ && $0 !~ /^[[:space:]]/ {
		if ($0 ~ /rx-checksumming|tx-checksumming|tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|large-receive-offload|receive-hashing|ntuple-filters/)
			print "  " $0
	}' | head -10
}

# /proc/net/dev: rx/tx bytes, packets, errs, drop
parse_proc_dev_line() {
	local dev="$1"
	awk -v d="$dev:" '
	$1 == d {
		printf "  rx  bytes=%s pkts=%s errs=%s drop=%s\n", $2, $3, $4, $5
		printf "  tx  bytes=%s pkts=%s errs=%s drop=%s\n", $10, $11, $12, $13
	}' /proc/net/dev 2>/dev/null || true
}

# Driver counters: non-zero, high-signal only (no per-queue rx0_/tx1_ spam; no mpwqe path stats)
parse_driver_stats_nonzero() {
	local dev="$1"
	ethtool -S "$dev" 2>/dev/null | awk -F: '
	NF < 2 { next }
	{
		key=$1; gsub(/^[ \t]+/,"",key)
		val=$2; gsub(/^[ \t]+/,"",val)
		if (val !~ /^[0-9]+$/) next
		if (val+0 == 0) next
		if (key ~ /^(rx|tx)[0-9]+_/) next
		l=tolower(key)
		if (l ~ /drop|discard|err|error|miss|xdp|fifo|timeout|out_of|overrun|aborted|failed|steer/)
			printf "  %-55s %s\n", key, val
	}' | head -20
}

# Same but show up to 8 lines even if zero for "total" visibility (optional fallback)
parse_driver_stats_totals() {
	local dev="$1"
	ethtool -S "$dev" 2>/dev/null | awk -F: '
	NF < 2 { next }
	{
		key=$1; gsub(/^[ \t]+/,"",key)
		val=$2; gsub(/^[ \t]+/,"",val)
		if (val !~ /^[0-9]+$/) next
		l=tolower(key)
		if (l ~ /^total_/) print "  " key ": " val
	}' | head -6
}

parse_link_essentials() {
	local dev="$1"
	ethtool "$dev" 2>/dev/null | awk -F: '
	/^[[:space:]]*Speed/ { sub(/^[[:space:]]+/,""); print "  " $0 }
	/^[[:space:]]*Duplex/ { sub(/^[[:space:]]+/,""); print "  " $0 }
	/^[[:space:]]*Link detected/ { sub(/^[[:space:]]+/,""); print "  " $0 }'
}

parse_driver_info() {
	local dev="$1"
	ethtool -i "$dev" 2>/dev/null | awk '
	/^driver:/ { sub(/^driver:[ \t]*/, ""); print "  driver     " $0 }
	/^firmware-version:/ { sub(/^firmware-version:[ \t]*/, ""); print "  firmware   " $0 }
	/^bus-info:/ { sub(/^bus-info:[ \t]*/, ""); print "  bus        " $0 }'
}

while true; do
	clear 2>/dev/null || printf '\033[H\033[2J'
	echo "=== NIC monitor (essentials) ===  $(date -Iseconds)  every ${INTERVAL}s"
	echo "iface: $IFACE"
	echo ""
	echo "[kernel]"
	printf "  %-32s %s\n" "netdev_max_backlog" "$(sysctl_get net.core.netdev_max_backlog)"
	printf "  %-32s %s\n" "netdev_budget" "$(sysctl_get net.core.netdev_budget)"
	printf "  %-32s %s\n" "netdev_budget_usecs" "$(sysctl_get net.core.netdev_budget_usecs)"
	if [ -r /proc/net/softnet_stat ]; then
		dropped_sum=$(awk '{d+=$2} END{print d+0}' /proc/net/softnet_stat)
		squeeze_sum=$(awk '{s+=$3} END{print s+0}' /proc/net/softnet_stat)
		printf "  %-32s %s\n" "softnet dropped (Σ CPUs)" "$dropped_sum"
		printf "  %-32s %s\n" "softnet time_squeeze (Σ CPUs)" "$squeeze_sum"
	fi
	echo ""

	for dev in "${IFACES[@]}"; do
		[ -d "/sys/class/net/$dev" ] || continue
		echo "── $dev ──"
		ip -br link show "$dev" 2>/dev/null | awk '{printf "  state %s  %s\n", $2, $3}'

		if ! ethtool "$dev" &>/dev/null; then
			parse_proc_dev_line "$dev"
			echo ""
			continue
		fi

		parse_link_essentials "$dev"
		parse_driver_info "$dev"

		if ethtool -g "$dev" &>/dev/null; then
			parse_ring_summary "$dev"
		fi
		if ethtool -l "$dev" &>/dev/null; then
			parse_channel_summary "$dev"
		fi

		echo "  coalesce (non-zero / adaptive)"
		parse_coalesce_essentials "$dev"

		echo "  offloads"
		parse_offload_essentials "$dev"

		echo "  counters (/proc/net/dev)"
		parse_proc_dev_line "$dev"

		echo "  driver stats (non-zero: drop/err/xdp/…)"
		stats_out=$(parse_driver_stats_nonzero "$dev")
		if [ -n "$stats_out" ]; then
			echo "$stats_out"
		else
			tot=$(parse_driver_stats_totals "$dev")
			if [ -n "$tot" ]; then
				echo "$tot"
			else
				echo "  (none non-zero or N/A)"
			fi
		fi
		echo ""
	done

	echo "Ctrl+C to exit"
	sleep "$INTERVAL"
done
