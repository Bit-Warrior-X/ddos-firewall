# core/backend_whitelist.py
"""Ensure critical IPs are on the L4 whitelist before / while Sparta runs.

Sources:
  - Panel backend IPs (PANEL_BACKEND_IPS; the panel host is behind Cloudflare,
    so DNS of API_BASE_URL does not return the real backend address)
  - L7 upstream (origin) IPs from Redis
  - GeoDB download hosts (GEODB_DOWNLOAD_HOSTS, resolved via DNS)
  - Optional static L4_INFRA_WHITELIST_IPS
"""
import socket
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import config
from core.database import DatabaseManager
from core.firewall import execute_cli_command
from core.redis_client import RedisClient

BACKEND_WHITELIST_REASON = "L7 upstream backend"
PANEL_WHITELIST_REASON = "panel backend"
GEODB_WHITELIST_REASON = "geodb download"
INFRA_WHITELIST_REASON = "infra whitelist"


def _is_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def ip_from_ip_port(ip_port: str) -> Optional[str]:
    """Extract IPv4 host from `ip`, `ip:port`, or `http(s)://ip:port` forms."""
    raw = (ip_port or "").strip()
    if not raw:
        return None

    if "://" in raw:
        host = urlparse(raw).hostname
        if host and _is_ipv4(host):
            return host
        return None

    # Strip brackets for rare [ipv4]:port misuse; IPv6 not supported by L4 map.
    if raw.startswith("["):
        end = raw.find("]")
        if end > 1:
            host = raw[1:end]
            return host if _is_ipv4(host) else None
        return None

    host = raw.rsplit(":", 1)[0].strip() if raw.count(":") == 1 else raw
    # IPv6 has multiple colons — skip (Sparta allowed_ips is IPv4-only).
    if raw.count(":") > 1:
        return None
    return host if _is_ipv4(host) else None


def resolve_host_ipv4s(host: str) -> List[str]:
    """Resolve a hostname (or pass through an IPv4 literal) to IPv4 addresses."""
    host = (host or "").strip().rstrip(".")
    if not host:
        return []
    if _is_ipv4(host):
        return [host]
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        print(f"[BACKEND_WL] DNS resolve failed for {host}: {exc}", flush=True)
        return []
    found: Set[str] = set()
    for info in infos:
        addr = info[4][0] if info and info[4] else None
        if addr and _is_ipv4(addr):
            found.add(addr)
    result = list(found)
    result.sort()
    return result


def _config_tuple(name: str) -> List[str]:
    value = getattr(config, name, None)
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def collect_backend_ips() -> List[str]:
    """Unique IPv4 backend/origin addresses from Redis upstreamservers keys."""
    found: Set[str] = set()
    for entry in RedisClient.get_all_upstreamservers():
        if not isinstance(entry, dict):
            continue
        ip = ip_from_ip_port(str(entry.get("ip_port") or ""))
        if ip:
            found.add(ip)
    result = list(found)
    result.sort()
    return result


def collect_whitelist_targets() -> List[Tuple[str, str]]:
    """(ip, reason) pairs that must stay L4-whitelisted; first reason wins."""
    by_ip: Dict[str, str] = {}

    def _add(ip: str, reason: str) -> None:
        ip = (ip or "").strip()
        if _is_ipv4(ip) and ip not in by_ip:
            by_ip[ip] = reason

    # Panel backend first: static config, independent of Redis and DNS.
    for item in _config_tuple("PANEL_BACKEND_IPS"):
        for ip in resolve_host_ipv4s(item):
            _add(ip, PANEL_WHITELIST_REASON)

    try:
        for ip in collect_backend_ips():
            _add(ip, BACKEND_WHITELIST_REASON)
    except Exception as exc:
        print(f"[BACKEND_WL] Failed to collect upstream IPs: {exc}", flush=True)

    for host in _config_tuple("GEODB_DOWNLOAD_HOSTS"):
        for ip in resolve_host_ipv4s(host):
            _add(ip, GEODB_WHITELIST_REASON)

    for ip in _config_tuple("L4_INFRA_WHITELIST_IPS"):
        _add(ip, INFRA_WHITELIST_REASON)

    ips = list(by_ip.keys())
    ips.sort()
    return [(ip, by_ip[ip]) for ip in ips]


def _apply_live_sparta(ips: Iterable[str]) -> None:
    """Best-effort live map update when Sparta is already running."""
    for ip in ips:
        allow = execute_cli_command(["sparta_cli", "ADD_ALLOW_IP", ip])
        if allow.get("status") == "success":
            print(f"[BACKEND_WL] ADD_ALLOW_IP {ip} -> ok", flush=True)
        else:
            # Sparta not up yet is expected; SQLite load covers cold start.
            msg = (allow.get("message") or "")[:120]
            print(f"[BACKEND_WL] ADD_ALLOW_IP {ip} skipped/failed: {msg}", flush=True)

        clear = execute_cli_command(["sparta_cli", "CLEAR_BLOCK_IP", ip])
        if clear.get("status") == "success":
            print(f"[BACKEND_WL] CLEAR_BLOCK_IP {ip} -> ok", flush=True)


def ensure_backend_ips_whitelisted(apply_live: bool = True) -> List[str]:
    """
    Merge panel backend, L7 origin, and geodb download IPs into SQLite
    white_ips (and clear matching local blocks).

    Call this *before* starting/restarting Sparta so load_config populates
    allowed_ips ahead of XDP attach. When Sparta is already running, also
    push ADD_ALLOW_IP / CLEAR_BLOCK_IP.
    """
    targets = collect_whitelist_targets()
    if not targets:
        print("[BACKEND_WL] No whitelist target IPs found", flush=True)
        return []

    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    entries = [
        {"ip": ip, "reason": reason, "created": created}
        for ip, reason in targets
    ]
    ips = [ip for ip, _ in targets]

    for ip, reason in targets:
        print(f"[BACKEND_WL] whitelist {ip} ({reason})", flush=True)

    try:
        DatabaseManager.init_database()
        ok, msg = DatabaseManager.merge_whitelist(entries)
        if ok:
            print(f"[BACKEND_WL] {msg}", flush=True)
        else:
            print(f"[BACKEND_WL] merge_whitelist failed: {msg}", flush=True)

        removed = DatabaseManager.remove_blocked_ips(ips)
        if removed:
            print(
                f"[BACKEND_WL] Removed {removed} IP(s) from blocked_ips",
                flush=True,
            )
    except Exception as exc:
        print(f"[BACKEND_WL] SQLite update failed: {exc}", flush=True)

    if apply_live:
        try:
            _apply_live_sparta(ips)
        except Exception as exc:
            print(f"[BACKEND_WL] Live Sparta update failed: {exc}", flush=True)

    return ips
