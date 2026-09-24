# core/backend_whitelist.py
"""Ensure L7 upstream (backend/origin) IPs are on the L4 whitelist before Sparta runs."""
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

from core.database import DatabaseManager
from core.firewall import execute_cli_command
from core.redis_client import RedisClient

BACKEND_WHITELIST_REASON = "L7 upstream backend"


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


def collect_backend_ips() -> List[str]:
    """Unique IPv4 backend/origin addresses from Redis upstreamservers keys."""
    ips: Set[str] = set()
    for entry in RedisClient.get_all_upstreamservers():
        if not isinstance(entry, dict):
            continue
        ip = ip_from_ip_port(str(entry.get("ip_port") or ""))
        if ip:
            ips.add(ip)
    return sorted(ips)


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
    Merge Redis upstream backend IPs into SQLite white_ips (and clear local blocks).

    Call this *before* starting/restarting Sparta so load_config populates
    allowed_ips ahead of XDP attach. When Sparta is already running, also
    push ADD_ALLOW_IP / CLEAR_BLOCK_IP.
    """
    try:
        ips = collect_backend_ips()
    except Exception as exc:
        print(f"[BACKEND_WL] Failed to collect upstream IPs: {exc}", flush=True)
        return []

    if not ips:
        print("[BACKEND_WL] No upstream backend IPs found in Redis", flush=True)
        return []

    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    entries = [
        {"ip": ip, "reason": BACKEND_WHITELIST_REASON, "created": created}
        for ip in ips
    ]

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
                f"[BACKEND_WL] Removed {removed} backend IP(s) from blocked_ips",
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
