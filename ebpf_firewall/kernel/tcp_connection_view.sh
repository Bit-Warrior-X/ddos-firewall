#!/bin/bash
# tcp-stats-per-ip.sh

INTERVAL="${1:-2}"

echo "Monitoring TCP connection states per IP (refresh: ${INTERVAL}s)"
echo "Press Ctrl+C to stop"
echo ""

while true; do
    clear
    echo "=== $(date) ==="
    echo ""

    ss -tan state all | awk '
    NR>1 {
        split($5, a, ":");
        ip=a[1];
        state=$1;
        key=ip "|" state;
        count[key]++;
    }
    END {
        printf "%-20s %-12s %s\n", "IP", "STATE", "COUNT";
        print "--------------------------------------------------";

        for (k in count) {
            split(k, b, "|");
            printf "%-20s %-12s %d\n", b[1], b[2], count[k];
        }
    }' | sort -k3 -nr | head -30

    sleep "$INTERVAL"
done