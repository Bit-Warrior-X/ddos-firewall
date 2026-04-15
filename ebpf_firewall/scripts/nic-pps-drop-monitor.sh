#!/usr/bin/env bash
# One line per sample (bond slaves summed, or single iface if not bond):
#
#   <ISO8601 timestamp>  phy_arrival_pps=…  phy_drop_pps=…  window_s=…
#
# phy_arrival_pps — estimate of packets/s that reached the physical NIC (mlx5 driver view), per slave:
#   max(Δ sysfs rx_packets, Δ ethtool rx_packets)   # delivered into driver & counted as RX (e.g. XDP_PASS)
# + Δ rx_discards_phy                               # dropped at PHY / ASIC ingress
# + Δ rx_xdp_drop                                   # delivered to XDP then dropped (not in rx_packets on many setups)
#   Summed over bond slaves. These three deltas are mutually exclusive per packet; sum ≈ total load on the port.
#
# phy_drop_pps — only PHY-layer discards (rx_discards_phy), summed over slaves.
#
# Also prints: arrival_pkts (total packet Δ in this window, all slaves), avg_rx_bytes_per_pkt (ΣΔrx_bytes/ΣΔdrv_rx_pkts).
#   avg applies only to netdev rx_bytes/rx_packets path; XDP-dropped packets often have no rx_bytes increment.
#
# Rates use wall-clock seconds between snapshots. Optional: NIC_MON_VERBOSE=1 adds drv/xdp/rss/k_rx breakdown.
#
# Usage:
#   ./nic-pps-drop-monitor.sh [interface] [interval_sec]

set -eu

IFACE="${1:-bond0}"
INTERVAL="${2:-1}"

if [ ! -d "/sys/class/net/$IFACE" ]; then
	echo "Interface '$IFACE' does not exist." >&2
	exit 1
fi

if ! [[ "$INTERVAL" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
	echo "interval must be a number" >&2
	exit 1
fi
if ! awk -v x="$INTERVAL" 'BEGIN{exit (x > 0 ? 0 : 1)}'; then
	echo "interval must be positive" >&2
	exit 1
fi

SLAVES=("$IFACE")
if [ -d "/sys/class/net/$IFACE/bonding" ]; then
	read -r SLAVES_STR <"/sys/class/net/$IFACE/bonding/slaves" 2>/dev/null || true
	if [ -n "${SLAVES_STR:-}" ]; then
		read -r -a _sl <<<"$SLAVES_STR"
		SLAVES=("${_sl[@]}")
	fi
fi

VERBOSE="${NIC_MON_VERBOSE:-0}"

read_u64() {
	local f="$1"
	if [ -r "$f" ]; then
		tr -d ' \t\r\n' <"$f" || echo 0
	else
		echo 0
	fi
}

ethtool_stat_u64() {
	local dev="$1" want="$2"
	command -v ethtool >/dev/null 2>&1 || {
		echo 0
		return
	}
	ethtool -S "$dev" 2>/dev/null | awk -F: -v want="$want" '
	NF < 2 { next }
	{
		k = $1
		gsub(/^[ \t]+/, "", k)
		gsub(/[ \t]+$/, "", k)
		v = $2
		gsub(/^[ \t]+/, "", v)
		if (k == want && v ~ /^[0-9]+$/) {
			printf "%.0f\n", v + 0
			exit
		}
	}
	END { print 0 }'
}

xdp_drop_total_ethtool() {
	local dev="$1"
	command -v ethtool >/dev/null 2>&1 || {
		echo 0
		return
	}
	ethtool -S "$dev" 2>/dev/null | awk -F: '
	NF < 2 { next }
	{
		k = $1
		gsub(/^[ \t]+/, "", k)
		gsub(/[ \t]+$/, "", k)
		v = $2
		gsub(/^[ \t]+/, "", v)
		if (v !~ /^[0-9]+$/) next
		if (k == "rx_xdp_drop") { agg = v + 0; has_agg = 1 }
		else if (k ~ /^rx[0-9]+_xdp_drop$/) perq += v + 0
	}
	END {
		if (has_agg) printf "%.0f\n", agg
		else printf "%.0f\n", perq
	}'
}

collect_metrics() {
	local d
	for d in "${SLAVES[@]}"; do
		[ -d "/sys/class/net/$d" ] || continue
		printf '%s\trx_packets_sysfs\t%s\n' "$d" "$(read_u64 "/sys/class/net/$d/statistics/rx_packets")"
		printf '%s\trx_bytes\t%s\n' "$d" "$(read_u64 "/sys/class/net/$d/statistics/rx_bytes")"
		printf '%s\trx_packets_ethtool\t%s\n' "$d" "$(ethtool_stat_u64 "$d" "rx_packets")"
		printf '%s\trx_dropped\t%s\n' "$d" "$(read_u64 "/sys/class/net/$d/statistics/rx_dropped")"
		printf '%s\trx_discards_phy\t%s\n' "$d" "$(ethtool_stat_u64 "$d" "rx_discards_phy")"
		printf '%s\trx_steer_missed_packets\t%s\n' "$d" "$(ethtool_stat_u64 "$d" "rx_steer_missed_packets")"
		printf '%s\trx_xdp_drop_sum\t%s\n' "$d" "$(xdp_drop_total_ethtool "$d")"
	done
}

join_snaps() {
	local p=$1 c=$2
	awk -F'\t' '
	FNR == NR { key = $1 SUBSEP $2; prev[key] = $3; next }
	{
		key = $1 SUBSEP $2
		if (key in prev) print $1 "\t" $2 "\t" prev[key] "\t" $3
	}' "$p" "$c"
}

summarize_interval() {
	local ts=$1
	local dt=$2
	awk -v ts="$ts" -v iv="$dt" -v verbose="$VERBOSE" -F'\t' '
	function delta(o, n) {
		o += 0; n += 0
		if (n >= o) return n - o
		return 0
	}
	function max2(a, b) { return (a > b ? a : b) }
	$2 == "rx_bytes" {
		rxb[$1] += delta($3, $4)
	}
	$2 == "rx_packets_sysfs" {
		dsys[$1] += delta($3, $4)
	}
	$2 == "rx_packets_ethtool" {
		detf[$1] += delta($3, $4)
	}
	$2 == "rx_dropped" {
		k_rx_drop += delta($3, $4)
	}
	$2 == "rx_discards_phy" {
		phy_disc[$1] += delta($3, $4)
	}
	$2 == "rx_steer_missed_packets" {
		steer_miss += delta($3, $4)
	}
	$2 == "rx_xdp_drop_sum" {
		xdp_disc[$1] += delta($3, $4)
	}
	END {
		delete seen
		for (d in dsys) seen[d] = 1
		for (d in detf) seen[d] = 1
		for (d in phy_disc) seen[d] = 1
		for (d in xdp_disc) seen[d] = 1
		for (d in rxb) seen[d] = 1
		phy_arrival = 0
		phy_drop_tot = 0
		drv_sum = 0
		xdp_sum = 0
		for (d in seen) {
			drv = 0
			if (d in dsys) drv = dsys[d]
			if (d in detf) drv = max2(drv, detf[d])
			pd = (d in phy_disc ? phy_disc[d] : 0)
			xd = (d in xdp_disc ? xdp_disc[d] : 0)
			phy_arrival += drv + pd + xd
			phy_drop_tot += pd
			drv_sum += drv
			xdp_sum += xd
		}
		if (iv < 1) iv = 1
		parr = phy_arrival / iv
		pdr = phy_drop_tot / iv
		sum_rxb = 0
		for (d in rxb) sum_rxb += rxb[d]
		printf "%s  phy_arrival_pps=%.2f  phy_drop_pps=%.2f  window_s=%.0f  arrival_pkts=%.0f",
			ts, parr, pdr, iv, phy_arrival + 0
		if (drv_sum > 0)
			printf "  avg_rx_bytes_per_pkt=%.0f", sum_rxb / drv_sum
		else
			printf "  avg_rx_bytes_per_pkt=n/a"
		if (verbose + 0 == 1) {
			printf "  drv_rx_pps=%.2f  xdp_drop_pps=%.2f  rss_steer_miss_pps=%.2f  k_rx_drop_pps=%.2f",
				drv_sum / iv, xdp_sum / iv, steer_miss / iv, k_rx_drop / iv
		}
		printf "\n"
	}'
}

echo "nic-pps-drop-monitor  iface=$IFACE  sleep=${INTERVAL}s  slaves=[${SLAVES[*]}]  (Ctrl+C to exit)"
echo "phy_arrival_pps = drv_rx + phy_discards + xdp_drops (per slave, then summed). arrival_pkts = that sum over the window (not divided by time)."
echo "avg_rx_bytes_per_pkt = sum(Δrx_bytes)/sum(Δdrv_rx_pkts) over slaves (netdev stats only)."
[ "$VERBOSE" = 1 ] && echo "NIC_MON_VERBOSE=1: prints drv_rx / xdp_drop / rss_miss / k_rx_drop rates on each line."
echo ""

prev=$(mktemp)
cur=$(mktemp)
trap 'rm -f "$prev" "$cur"' EXIT

last_t=$(date +%s)
collect_metrics >"$prev"
sleep "$INTERVAL"
collect_metrics >"$cur"

while true; do
	now=$(date +%s)
	dt=$((now - last_t))
	[ "$dt" -lt 1 ] && dt=1
	last_t=$now
	ts=$(date -Iseconds)

	join_snaps "$prev" "$cur" | summarize_interval "$ts" "$dt"

	cp "$cur" "$prev"
	sleep "$INTERVAL"
	collect_metrics >"$cur"
done
