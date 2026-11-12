# core/initializer.py
"""Initialization logic for API parser."""
import config as app_config
from utils.auth import get_token
from core.api_client import APIClient
from core.backend_whitelist import ensure_backend_ips_whitelisted
from core.database import DatabaseManager
from core.firewall import firewall_control, health_check


def _read_firewall_config():
    """
    Read simple key=value firewall config file and return dict.

    This mirrors the logic in L4 routes but is kept local here to
    avoid importing the routes module from the initializer.
    """
    config_path = app_config.FIREWALL_CONFIG_PATH
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return False, f"Config file not found at {config_path}"
    except OSError as exc:
        return False, f"Failed to read config file: {exc}"

    parsed = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        # Values carry inline comments ("native # native | generic"); passing
        # them on made sparta append the comment again on every start.
        parsed[key.strip()] = value.split("#", 1)[0].strip()

    return True, parsed


def panel_list(data):
    """Panel list payload as a list of dicts, or None when it is unusable.

    An error object such as {"status": "error"} must not be taken as an empty
    list, or the sync would wipe the panel-owned rows."""
    if isinstance(data, dict):
        if data.get("IP") or data.get("ip"):
            data = [data]
        elif isinstance(data.get("data"), list):
            data = data["data"]
        else:
            return None
    if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
        return None
    return data


def sync_l4_lists_and_start_firewall():
    """
    At API parser startup (L4-licensed only):
      - Call backend /api/get_blocklist_ips and /api/get_whitelist_ips first.
      - Only if we get success response(s): init DB, clear tables, then store
        the response data. On API failure we do not clear or overwrite the DB.
      - Regardless of API success/failure, start the L4 firewall via CLI.
    """
    print("[INIT] Starting L4 list sync and firewall startup", flush=True)

    token = None
    try:
        token = get_token()
    except Exception as exc:
        print(f"[INIT] Failed to load token for L4 sync: {exc}", flush=True)

    blocklist_ok = False
    blocklist_data = None
    whitelist_ok = False
    whitelist_data = None

    if token:
        try:
            blocklist_ok, blocklist_data = APIClient.fetch_blocklist(token)
            if not blocklist_ok:
                print(f"[INIT] fetch_blocklist failed: {blocklist_data}", flush=True)
        except Exception as exc:
            print(f"[INIT] Exception during blocklist fetch: {exc}", flush=True)

        try:
            whitelist_ok, whitelist_data = APIClient.fetch_whitelist(token)
            if not whitelist_ok:
                print(f"[INIT] fetch_whitelist failed: {whitelist_data}", flush=True)
        except Exception as exc:
            print(f"[INIT] Exception during whitelist fetch: {exc}", flush=True)
    else:
        print("[INIT] Skipping L4 list fetch because token is unavailable", flush=True)

    try:
        DatabaseManager.init_database()
    except Exception as exc:
        print(f"[INIT] Failed to init firewall DB: {exc}", flush=True)

    # Replace the lists only when both fetches succeeded and look valid, in one
    # transaction; otherwise keep what sparta already has.
    blocklist = panel_list(blocklist_data) if blocklist_ok else None
    whitelist = panel_list(whitelist_data) if whitelist_ok else None
    if blocklist is not None and whitelist is not None:
        db_ok, msg = DatabaseManager.replace_lists(blocklist, whitelist)
        print(f"[INIT] {'Synced L4 lists: ' if db_ok else 'L4 list sync failed: '}{msg}", flush=True)
    else:
        print("[INIT] Keeping existing L4 lists (panel lists unavailable or invalid)", flush=True)

    # Always whitelist L7 upstream backends before XDP attach / restart.
    # Must run after the whitelist replace (which wipes white_ips) and before Sparta start.
    try:
        ensure_backend_ips_whitelisted(apply_live=True)
    except Exception as exc:
        print(f"[INIT] Backend whitelist inject failed: {exc}", flush=True)

    # Start L4 only if it is down. A full RESTART_FW wipes Sparta's in-memory
    # TRAFFIC_STATS ring and stalls panel L4 charts until the ring fills again.
    ok, fw_cfg = _read_firewall_config()
    if not ok:
        print(f"[INIT] Skipping firewall start: {fw_cfg}", flush=True)
        return

    interface = fw_cfg.get("dev")
    attach_mode = fw_cfg.get("attach_mode", "native")

    if not interface:
        print("[INIT] Skipping firewall start: 'dev' not set in firewall.config", flush=True)
        return

    try:
        health = health_check()
        if health.get("status") == "success":
            print(
                "[INIT] L4 firewall already healthy; skipping RESTART_FW "
                "(preserves TRAFFIC_STATS history)",
                flush=True,
            )
            return

        result = firewall_control("restart", interface, attach_mode)
        status = result.get("status")
        message = result.get("message", "")
        print(f"[INIT] L4 firewall start via CLI -> {status}: {message}", flush=True)
    except Exception as exc:
        print(f"[INIT] Failed to start L4 firewall via CLI: {exc}", flush=True)
