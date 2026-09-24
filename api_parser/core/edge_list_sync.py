# core/edge_list_sync.py
"""
Periodic edge → backend sync for L4 + L7 configure state.

Every EDGE_LIST_SYNC_INTERVAL seconds, snapshot:
  - L4: firewall.config + SQLite white_ips / blocked_ips
  - L7: Redis (site waf/cache/listening/upstream/compress/ssl/domain,
        edge listeningports, temporaryblacklist, legacy ACL globals)
and POST to the panel.
"""
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import config
from core.api_client import APIClient
from core.database import DatabaseManager
from core.redis_client import RedisClient
from utils.auth import get_token

SYNC_INTERVAL_SEC = getattr(config, "EDGE_LIST_SYNC_INTERVAL", 60)
INCLUDE_SSL_PEMS = bool(getattr(config, "EDGE_CONFIG_REPORT_INCLUDE_SSL_PEMS", False))


def _normalize_whitelist_rows(rows: List[Dict]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in rows or []:
        ip = (row.get("ip") or "").strip()
        if not ip:
            continue
        out.append(
            {
                "ip": ip,
                "reason": row.get("reason") or "",
                "created": row.get("created") or row.get("timestamp") or "",
            }
        )
    return out


def _normalize_blocklist_rows(rows: List[Dict]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in rows or []:
        ip = (row.get("ip") or "").strip()
        if not ip:
            continue
        duration = row.get("duration")
        try:
            duration = int(duration) if duration is not None and duration != "" else -1
        except (TypeError, ValueError):
            duration = -1
        out.append(
            {
                "ip": ip,
                "type": row.get("type") or "L4",
                "duration": duration,
                "reason": row.get("reason") or "",
                "created": row.get("created") or row.get("timestamp") or "",
            }
        )
    return out


def _read_firewall_config() -> Tuple[bool, Any]:
    """Parse Sparta firewall.config key=value file."""
    path = config.FIREWALL_CONFIG_PATH
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return False, f"Config file not found at {path}"
    except OSError as exc:
        return False, f"Failed to read config file: {exc}"

    parsed: Dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        parsed[key.strip()] = value.strip()
    return True, parsed


def _read_optional_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def build_edge_configure_payload(token: str) -> Dict[str, Any]:
    """Full L4 + L7 configure snapshot for the backend report API."""
    whitelist = _normalize_whitelist_rows(DatabaseManager.get_whitelist())
    blocklist = _normalize_blocklist_rows(DatabaseManager.get_blocklist())

    fw_ok, fw_cfg = _read_firewall_config()
    firewall_config = fw_cfg if fw_ok and isinstance(fw_cfg, dict) else {}
    firewall_config_error = None if fw_ok else str(fw_cfg)

    try:
        l7 = RedisClient.dump_l7_configure(include_ssl_pems=INCLUDE_SSL_PEMS)
    except Exception as exc:
        l7 = {
            "edge": {},
            "sites": {},
            "meta": {"site_count": 0, "temporaryblacklist_count": 0, "error": str(exc)},
        }

    ports_conf = _read_optional_file(getattr(config, "L7_DEFAULT_PORTS_CONF", None))

    l7_meta = dict(l7.get("meta") or {})
    sites = l7.get("sites") or {}

    return {
        "token": token,
        "command": "report_edge_configure",
        "reported_at": int(time.time()),
        "l4": {
            "firewall_config": firewall_config,
            "firewall_config_error": firewall_config_error,
            "whitelist": whitelist,
            "blocklist": blocklist,
        },
        "l7": {
            "edge": l7.get("edge") or {},
            "sites": sites,
            "files": {
                "server_default_ports_conf": ports_conf,
            },
        },
        # Keep flat counts for simple backend logging / older parsers.
        "whitelist": whitelist,
        "blocklist": blocklist,
        "whitelist_count": len(whitelist),
        "blocklist_count": len(blocklist),
        "site_count": int(l7_meta.get("site_count") or len(sites)),
        "temporaryblacklist_count": int(l7_meta.get("temporaryblacklist_count") or 0),
        "include_ssl_pems": INCLUDE_SSL_PEMS,
    }


# Back-compat alias used by earlier revision.
def build_edge_list_payload(token: str) -> Dict[str, Any]:
    return build_edge_configure_payload(token)


def report_edge_lists_once() -> bool:
    """Collect edge L4+L7 configure and POST to backend. Returns True on success."""
    token = get_token()
    if not token:
        print("[EDGE_LIST_SYNC] No API token; skipping report", flush=True)
        return False

    try:
        payload = build_edge_configure_payload(token)
    except Exception as exc:
        print(f"[EDGE_LIST_SYNC] Failed to build payload: {exc}", flush=True)
        return False

    ok = APIClient.report_edge_configure(payload)
    if ok:
        print(
            f"[EDGE_LIST_SYNC] Reported configure "
            f"whitelist={payload['whitelist_count']} "
            f"blocklist={payload['blocklist_count']} "
            f"sites={payload['site_count']} "
            f"temp_bl={payload['temporaryblacklist_count']}",
            flush=True,
        )
    else:
        print("[EDGE_LIST_SYNC] Backend report failed", flush=True)
    return ok


def _run_sync_loop() -> None:
    pid = os.getpid()
    thread_name = threading.current_thread().name
    print(
        f"[EDGE_LIST_SYNC] pid={pid} thread={thread_name} "
        f"starting full L4+L7 configure sync (interval={SYNC_INTERVAL_SEC}s)",
        flush=True,
    )

    # Small delay so startup L4 pull / Redis settle before first push.
    time.sleep(min(5, SYNC_INTERVAL_SEC))

    while True:
        try:
            report_edge_lists_once()
        except Exception as exc:
            print(f"[EDGE_LIST_SYNC] Unexpected error: {exc}", flush=True)
        time.sleep(SYNC_INTERVAL_SEC)


def start_edge_list_sync() -> threading.Thread:
    """Start the periodic edge→backend configure reporter in a daemon thread."""
    thread = threading.Thread(
        target=_run_sync_loop,
        daemon=True,
        name="edge_list_sync",
    )
    thread.start()
    return thread
