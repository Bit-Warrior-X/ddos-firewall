# core/initializer.py
"""Initialization logic for API parser."""
from utils.auth import get_token
from core.api_client import APIClient
from core.database import DatabaseManager
from core.firewall import firewall_control


def _read_firewall_config():
    """
    Read simple key=value firewall config file and return dict.

    This mirrors the logic in L4 routes but is kept local here to
    avoid importing the routes module from the initializer.
    """
    config_path = "/usr/local/share/ebpf_firewall/firewall.config"
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
        parsed[key.strip()] = value.strip()

    return True, parsed


def sync_l4_lists_and_start_firewall():
    """
    At API parser startup:
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

    # Only when we got at least one success: init DB, clear, and update with response
    if blocklist_ok and whitelist_ok:
        try:
            DatabaseManager.init_database()
            DatabaseManager.clear_all_tables()
            print("[INIT] Initialized and cleared firewall SQLite tables", flush=True)
        except Exception as exc:
            print(f"[INIT] Failed to init/clear firewall DB: {exc}", flush=True)
        else:
            if blocklist_ok and blocklist_data is not None:
                data = [blocklist_data] if isinstance(blocklist_data, dict) else blocklist_data
                if isinstance(data, list):
                    db_ok, msg = DatabaseManager.store_blocklist(data)
                    if db_ok:
                        print(f"[INIT] {msg}", flush=True)
                    else:
                        print(f"[INIT] store_blocklist failed: {msg}", flush=True)
                else:
                    print(f"[INIT] Unexpected blocklist payload type: {type(blocklist_data)}", flush=True)
            if whitelist_ok and whitelist_data is not None:
                data = [whitelist_data] if isinstance(whitelist_data, dict) else whitelist_data
                if isinstance(data, list):
                    db_ok, msg = DatabaseManager.store_whitelist(data)
                    if db_ok:
                        print(f"[INIT] {msg}", flush=True)
                    else:
                        print(f"[INIT] store_whitelist failed: {msg}", flush=True)
                else:
                    print(f"[INIT] Unexpected whitelist payload type: {type(whitelist_data)}", flush=True)

    # Start L4 firewall via CLI, regardless of API sync success
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
        result = firewall_control("restart", interface, attach_mode)
        status = result.get("status")
        message = result.get("message", "")
        print(f"[INIT] L4 firewall start via CLI -> {status}: {message}", flush=True)
    except Exception as exc:
        print(f"[INIT] Failed to start L4 firewall via CLI: {exc}", flush=True)
