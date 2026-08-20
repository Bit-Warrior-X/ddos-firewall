# core/listening_ports.py
"""Server-scoped nginx listening ports (edge-wide).

Redis key: listeningports
  JSON array of { id, serverId, port, protocol, description, status }

Nginx conf: server_default_ports.conf (listen directives only for ENABLE entries).
Site-selected ports remain under listening:{site_id}.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import config
from core.redis_client import RedisClient


def normalize_protocol(protocol: Any) -> str:
    p = str(protocol or "HTTP").strip().upper()
    if p in ("HTTPS", "SSL", "TLS"):
        return "HTTPS"
    return "HTTP"


def is_enabled(status: Any) -> bool:
    return str(status or "ENABLE").strip().upper() in (
        "ENABLE", "ENABLED", "1", "TRUE", "ON", "YES"
    )


def normalize_api_ports(listeningports_in: list) -> Tuple[List[Dict], List[Dict]]:
    """Return (redis_entries, enabled_conf_ports).

    redis_entries keeps full metadata for all valid rows.
    enabled_conf_ports is [{port, protocol}, ...] for ENABLE rows only (deduped).
    """
    redis_entries: List[Dict] = []
    enabled_ports: List[Dict] = []
    seen = set()

    for entry in listeningports_in or []:
        if not isinstance(entry, dict):
            continue
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        if port < 1 or port > 65535:
            continue

        protocol = normalize_protocol(entry.get("protocol"))
        status = str(entry.get("status") or "ENABLE").strip().upper()
        if status in ("ENABLED", "1", "TRUE", "ON", "YES"):
            status = "ENABLE"
        elif status in ("DISABLED", "0", "FALSE", "OFF", "NO"):
            status = "DISABLE"

        item = {
            "port": port,
            "protocol": protocol,
            "status": status,
        }
        if entry.get("id") is not None:
            try:
                item["id"] = int(entry.get("id"))
            except (TypeError, ValueError):
                item["id"] = entry.get("id")
        if entry.get("serverId") is not None or entry.get("server_id") is not None:
            try:
                item["serverId"] = int(
                    entry.get("serverId")
                    if entry.get("serverId") is not None
                    else entry.get("server_id")
                )
            except (TypeError, ValueError):
                pass
        desc = entry.get("description")
        if desc is not None:
            item["description"] = str(desc)

        redis_entries.append(item)

        if status == "ENABLE":
            key = (port, protocol)
            if key not in seen:
                seen.add(key)
                enabled_ports.append({"port": port, "protocol": protocol})

    enabled_ports.sort(key=lambda x: (x["port"], x["protocol"]))
    return redis_entries, enabled_ports


def listen_line(port: int, protocol: str) -> str:
    if protocol == "HTTPS":
        return f"listen {port} ssl reuseport;"
    return f"listen {port} reuseport;"


def build_default_ports_conf(ports: List[Dict]) -> str:
    lines = [
        listen_line(int(entry["port"]), normalize_protocol(entry.get("protocol")))
        for entry in sorted(ports, key=lambda x: (int(x["port"]), normalize_protocol(x.get("protocol"))))
    ]
    return "\n".join(lines) + ("\n" if lines else "")


def parse_default_ports_conf(content: str) -> List[Dict]:
    ports = []
    seen = set()
    for line in (content or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(
            r"listen\s+(\d+)(?:\s+(?:ssl|http2|reuseport|deferred|fastopen=\d+|default_server))*\s*;",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        port = int(match.group(1))
        protocol = "HTTPS" if re.search(r"\bssl\b", line, re.IGNORECASE) else "HTTP"
        key = (port, protocol)
        if key in seen:
            continue
        seen.add(key)
        ports.append({"port": port, "protocol": protocol})
    return sorted(ports, key=lambda x: (x["port"], x["protocol"]))


def read_default_ports_conf() -> Tuple[str, Optional[str]]:
    path = Path(config.L7_DEFAULT_PORTS_CONF)
    try:
        if not path.is_file():
            return "", None
        return path.read_text(encoding="utf-8"), None
    except Exception as exc:
        return "", str(exc)


def write_default_ports_conf(content: str) -> Tuple[bool, Optional[str]]:
    path = Path(config.L7_DEFAULT_PORTS_CONF)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return True, None
    except Exception as exc:
        return False, str(exc)


def restart_l7_service() -> Tuple[bool, Optional[str]]:
    try:
        result = subprocess.run(
            ["systemctl", "restart", config.L7_SERVICE],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False, "Service restart timed out"
    except Exception as exc:
        return False, str(exc)

    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        return False, err or f"systemctl restart failed (exit {result.returncode})"
    return True, None


def apply_enabled_ports(enabled_ports: List[Dict], restart: bool = True) -> Tuple[bool, Dict]:
    """Write server_default_ports.conf from enabled ports; restart athens if changed.

    Returns (ok, details_dict).
    """
    if not enabled_ports:
        return False, {"message": "No valid enabled listening ports provided."}

    new_conf = build_default_ports_conf(enabled_ports)
    current_conf, read_err = read_default_ports_conf()
    if read_err:
        return False, {
            "message": "Failed to read current listening ports configuration.",
            "details": read_err,
        }

    current_ports = parse_default_ports_conf(current_conf)
    changed = current_ports != enabled_ports

    if not changed:
        return True, {
            "changed": False,
            "message": "Listening ports unchanged; no restart required.",
            "listeningportsCount": len(enabled_ports),
        }

    ok, write_err = write_default_ports_conf(new_conf)
    if not ok:
        return False, {
            "message": "Failed to write listening ports configuration.",
            "details": write_err or "Unknown error",
        }

    if not restart:
        return True, {
            "changed": True,
            "restarted": False,
            "message": "Listening ports configuration updated (restart skipped).",
            "listeningportsCount": len(enabled_ports),
        }

    restarted, restart_err = restart_l7_service()
    if not restarted:
        return False, {
            "message": "Listening ports configuration updated but service restart failed.",
            "details": restart_err or "Unknown error",
            "changed": True,
            "listeningportsCount": len(enabled_ports),
        }

    return True, {
        "changed": True,
        "restarted": True,
        "message": "Listening ports updated and athens service restarted.",
        "listeningportsCount": len(enabled_ports),
    }


def sync_from_redis_on_startup() -> None:
    """On Angelos start: ensure Redis has edge ports and apply them to nginx conf.

    - If Redis has listeningports → apply ENABLE entries to server_default_ports.conf
    - If Redis empty but conf has listens → seed Redis from conf (migration)
    """
    print("[INIT] Syncing edge listening ports from Redis", flush=True)
    try:
        stored = RedisClient.get_edge_listeningports()
    except Exception as exc:
        print(f"[INIT] Failed to read listeningports from Redis: {exc}", flush=True)
        return

    if stored:
        _, enabled = normalize_api_ports(stored)
        if not enabled:
            print("[INIT] listeningports in Redis has no ENABLE entries; skipping apply", flush=True)
            return
        ok, details = apply_enabled_ports(enabled, restart=True)
        print(f"[INIT] apply listeningports ok={ok} details={details}", flush=True)
        return

    # Migration: seed Redis from existing nginx conf so ports survive redeploys.
    current_conf, read_err = read_default_ports_conf()
    if read_err:
        print(f"[INIT] Could not read default ports conf: {read_err}", flush=True)
        return
    conf_ports = parse_default_ports_conf(current_conf)
    if not conf_ports:
        print("[INIT] No listeningports in Redis and conf is empty; keeping bootstrap default", flush=True)
        return

    seed = [
        {
            "port": p["port"],
            "protocol": p["protocol"],
            "status": "ENABLE",
            "description": "seeded from server_default_ports.conf",
        }
        for p in conf_ports
    ]
    ok, err = RedisClient.store_edge_listeningports(seed)
    if ok:
        print(f"[INIT] Seeded Redis listeningports with {len(seed)} port(s) from conf", flush=True)
    else:
        print(f"[INIT] Failed to seed Redis listeningports: {err}", flush=True)
