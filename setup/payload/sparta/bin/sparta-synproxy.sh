#!/bin/bash
# Under SYN mitigation XDP answers SYNs with cookies (XDP_TX). Linux accepts a
# cookie ACK only if that listener itself overflowed in the last ~2 minutes,
# which never happens while XDP absorbs the flood, so it RSTs the ACK and the
# client's first connection fails. SYNPROXY validates the cookie of such ACKs
# (conntrack INVALID, nf_conntrack_tcp_loose=0) and completes the handshake to
# the local listener. Normal handshakes are tracked as NEW and never reach it.
#
# usage: sparta-synproxy.sh add|del
# Ports: SPARTA_SYNPROXY_PORTS (comma list, max 15), default the L7 listeners.
set -u
CHAIN=SPARTA_SYNPROXY
PORTS=${SPARTA_SYNPROXY_PORTS:-80,443,2052,8080}
IPT="iptables -w 5"

del_rules() {
    while $IPT -D INPUT -j "$CHAIN" 2>/dev/null; do :; done
    while $IPT -S INPUT 2>/dev/null | grep -q -- "-j $CHAIN"; do
        rule=$($IPT -S INPUT | grep -m1 -- "-j $CHAIN" | sed 's/^-A /-D /')
        $IPT $rule || break
    done
    $IPT -F "$CHAIN" 2>/dev/null
    $IPT -X "$CHAIN" 2>/dev/null
    return 0
}

add_rules() {
    del_rules
    $IPT -N "$CHAIN" || return 1
    $IPT -A "$CHAIN" -p tcp -m conntrack --ctstate INVALID,UNTRACKED \
        -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 || return 1
    $IPT -I INPUT ! -i lo -p tcp -m multiport --dports "$PORTS" -j "$CHAIN" || return 1
    sysctl -qw net.netfilter.nf_conntrack_tcp_loose=0 2>/dev/null
    return 0
}

case "${1:-}" in
    add) add_rules ;;
    del) del_rules ;;
    *) echo "usage: $0 add|del" >&2; exit 2 ;;
esac
