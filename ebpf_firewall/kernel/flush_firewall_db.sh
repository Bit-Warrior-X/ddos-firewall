#!/bin/bash
# flush_firewall_db.sh — Flush eBPF firewall SQLite database
#
# Usage:
#   ./flush_firewall_db.sh              # flush both tables (interactive)
#   ./flush_firewall_db.sh --blocked    # flush only blocked_ips
#   ./flush_firewall_db.sh --whitelist  # flush only white_ips
#   ./flush_firewall_db.sh --all        # flush both, no confirmation
#   ./flush_firewall_db.sh --status     # show counts only

set -euo pipefail

DB="/usr/local/share/dorian/sparta/firewall_control.db"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

if [ ! -f "$DB" ]; then
    echo -e "${RED}Database not found: $DB${NC}"
    exit 1
fi

# Get current counts
BLOCKED_COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM blocked_ips;" 2>/dev/null || echo "0")
WHITE_COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM white_ips;" 2>/dev/null || echo "0")

MODE="${1:---interactive}"

case "$MODE" in
    --status)
        echo "=== Firewall Database Status ==="
        echo "  Database: $DB"
        echo "  Size:     $(du -h "$DB" | cut -f1)"
        echo ""
        echo "  blocked_ips: $BLOCKED_COUNT entries"
        echo "  white_ips:   $WHITE_COUNT entries"
        echo ""
        if [ "$BLOCKED_COUNT" -gt 0 ]; then
            echo "  Top 10 blocked IPs (most recent):"
            sqlite3 -column "$DB" \
                "SELECT ip, type, duration, reason, created FROM blocked_ips ORDER BY id DESC LIMIT 10;"
        fi
        echo ""
        if [ "$WHITE_COUNT" -gt 0 ]; then
            echo "  Whitelisted IPs:"
            sqlite3 -column "$DB" \
                "SELECT ip, reason, created FROM white_ips ORDER BY id DESC LIMIT 10;"
        fi
        exit 0
        ;;

    --blocked)
        echo -e "${YELLOW}Flushing blocked_ips table ($BLOCKED_COUNT entries)...${NC}"
        sqlite3 "$DB" "DELETE FROM blocked_ips;"
        sqlite3 "$DB" "DELETE FROM sqlite_sequence WHERE name='blocked_ips';"
        echo -e "${GREEN}Done. blocked_ips flushed.${NC}"

        # Also clear the BPF map if the firewall is running
        if pgrep -f ebpf_firewall >/dev/null 2>&1; then
            echo "Firewall is running — clearing BPF blocked_ips map via CLI..."
            /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_BLOCK_IP_ALL 2>/dev/null || true
        fi
        ;;

    --whitelist)
        echo -e "${YELLOW}Flushing white_ips table ($WHITE_COUNT entries)...${NC}"
        sqlite3 "$DB" "DELETE FROM white_ips;"
        sqlite3 "$DB" "DELETE FROM sqlite_sequence WHERE name='white_ips';"
        echo -e "${GREEN}Done. white_ips flushed.${NC}"

        if pgrep -f ebpf_firewall >/dev/null 2>&1; then
            echo "Firewall is running — clearing BPF allowed_ips map via CLI..."
            /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_ALLOW_IP_ALL 2>/dev/null || true
        fi
        ;;

    --all)
        echo -e "${YELLOW}Flushing ALL tables...${NC}"
        echo "  blocked_ips: $BLOCKED_COUNT entries"
        echo "  white_ips:   $WHITE_COUNT entries"

        sqlite3 "$DB" <<EOF
DELETE FROM blocked_ips;
DELETE FROM white_ips;
DELETE FROM sqlite_sequence WHERE name='blocked_ips';
DELETE FROM sqlite_sequence WHERE name='white_ips';
VACUUM;
EOF
        echo -e "${GREEN}Done. All tables flushed and database compacted.${NC}"

        if pgrep -f ebpf_firewall >/dev/null 2>&1; then
            echo "Firewall is running — clearing BPF maps via CLI..."
            /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_BLOCK_IP_ALL 2>/dev/null || true
            /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_ALLOW_IP_ALL 2>/dev/null || true
        fi
        ;;

    --interactive|*)
        echo "=== eBPF Firewall — Database Flush ==="
        echo ""
        echo "  Database: $DB ($(du -h "$DB" | cut -f1))"
        echo "  blocked_ips: $BLOCKED_COUNT entries"
        echo "  white_ips:   $WHITE_COUNT entries"
        echo ""
        echo "Options:"
        echo "  1) Flush blocked_ips only"
        echo "  2) Flush white_ips only"
        echo "  3) Flush both tables"
        echo "  4) Flush both + VACUUM (compact database file)"
        echo "  5) Cancel"
        echo ""
        read -rp "Choice [1-5]: " CHOICE

        case "$CHOICE" in
            1)
                sqlite3 "$DB" "DELETE FROM blocked_ips; DELETE FROM sqlite_sequence WHERE name='blocked_ips';"
                echo -e "${GREEN}blocked_ips flushed ($BLOCKED_COUNT entries removed)${NC}"
                if pgrep -f ebpf_firewall >/dev/null 2>&1; then
                    /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_BLOCK_IP_ALL 2>/dev/null || true
                    echo "BPF blocked_ips map cleared"
                fi
                ;;
            2)
                sqlite3 "$DB" "DELETE FROM white_ips; DELETE FROM sqlite_sequence WHERE name='white_ips';"
                echo -e "${GREEN}white_ips flushed ($WHITE_COUNT entries removed)${NC}"
                if pgrep -f ebpf_firewall >/dev/null 2>&1; then
                    /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_ALLOW_IP_ALL 2>/dev/null || true
                    echo "BPF allowed_ips map cleared"
                fi
                ;;
            3)
                sqlite3 "$DB" "DELETE FROM blocked_ips; DELETE FROM white_ips; DELETE FROM sqlite_sequence;"
                echo -e "${GREEN}Both tables flushed${NC}"
                if pgrep -f ebpf_firewall >/dev/null 2>&1; then
                    /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_BLOCK_IP_ALL 2>/dev/null || true
                    /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_ALLOW_IP_ALL 2>/dev/null || true
                    echo "BPF maps cleared"
                fi
                ;;
            4)
                sqlite3 "$DB" "DELETE FROM blocked_ips; DELETE FROM white_ips; DELETE FROM sqlite_sequence; VACUUM;"
                NEW_SIZE=$(du -h "$DB" | cut -f1)
                echo -e "${GREEN}Both tables flushed + VACUUM (size: $NEW_SIZE)${NC}"
                if pgrep -f ebpf_firewall >/dev/null 2>&1; then
                    /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_BLOCK_IP_ALL 2>/dev/null || true
                    /usr/local/share/dorian/sparta/bin/ebpf_firewall_cli CLEAR_ALLOW_IP_ALL 2>/dev/null || true
                    echo "BPF maps cleared"
                fi
                ;;
            *)
                echo "Cancelled."
                exit 0
                ;;
        esac
        ;;
esac

# Verify
echo ""
echo "Current state:"
echo "  blocked_ips: $(sqlite3 "$DB" "SELECT COUNT(*) FROM blocked_ips;") entries"
echo "  white_ips:   $(sqlite3 "$DB" "SELECT COUNT(*) FROM white_ips;") entries"
echo "  DB size:     $(du -h "$DB" | cut -f1)"