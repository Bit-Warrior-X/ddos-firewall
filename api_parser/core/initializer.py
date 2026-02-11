# core/initializer.py
"""Initialization logic for API parser."""
import os
import sys
import signal
import subprocess
import shlex
import base64
import socket
import tempfile
import requests
from utils.auth import get_token
from core.api_client import APIClient
from core.database import DatabaseManager
from core.firewall import firewall_control
import config

def _get_primary_ip() -> str:
    """Return primary non-loopback IPv4 used for outbound traffic."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

def _atomic_write(path: str, data: bytes, mode: int = 0o600):
    """Atomic write with secure permissions."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass

def _fail_and_stop(reason: str, exit_code: int = 1, sig: int = signal.SIGINT) -> None:
    """Log reason, ask Gunicorn master to stop, then exit."""
    print(f"[INIT] {reason}", flush=True)
    try:
        ppid = os.getppid()
        if ppid != 1:
            os.kill(ppid, sig)
    except Exception as e:
        print(f"[INIT] Could not signal Gunicorn master: {e}", flush=True)
    
    try:
        sys.exit(exit_code)
    finally:
        os._exit(exit_code)

def handle_initialize_file():
    """
    Start-up initializer:
      - Ensure INIT_FILE exists (default '0').
      - If INIT_FILE == '0': call backend /API/deploy_done with ip,machine,token.
        On success: save license + decoded pubkey, set INIT_FILE to '1'.
        On failure: stop the service and exit.
      - If INIT_FILE == '1': skip.
    """
    try:
        dirpath = os.path.dirname(config.INIT_FILE)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)

        if not os.path.exists(config.INIT_FILE):
            with open(config.INIT_FILE, "w", encoding="utf-8") as f:
                f.write("0")
            print(f"[INIT] Created {config.INIT_FILE} with value 0", flush=True)

        with open(config.INIT_FILE, "r", encoding="utf-8", errors="replace") as f:
            flag = (f.read() or "").strip()

        if flag != "0":
            print(f"[INIT] initialize={flag}; nothing to do", flush=True)
            return

        if not os.path.exists(config.MACHINE_FILE):
            _fail_and_stop(f"Missing executable at {config.MACHINE_FILE}; exiting")

        if not os.access(config.MACHINE_FILE, os.X_OK):
            _fail_and_stop(f"Not executable: {config.MACHINE_FILE}; exiting")

        try:
            cmd = shlex.split(config.MACHINE_FILE)
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=8,
                check=True,
            )
            out_bytes = proc.stdout or b""
        except subprocess.TimeoutExpired:
            _fail_and_stop(f"{config.MACHINE_FILE} timed out")
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or b"").decode("utf-8", "ignore")
            _fail_and_stop(f"{config.MACHINE_FILE} failed (rc={e.returncode}): {stderr}")
        except Exception as e:
            _fail_and_stop(f"Error running {config.MACHINE_FILE}: {e}")

        try:
            machine_id = out_bytes.decode("utf-8").strip()
        except UnicodeDecodeError:
            machine_id = out_bytes.decode("utf-8", errors="ignore").strip()

        machine_id = "".join(ch for ch in machine_id if ch.isalnum() or ch in "-_")
        if not machine_id:
            _fail_and_stop("Empty/invalid machine_id from executable; exiting")

        ip_addr = _get_primary_ip()
        token = get_token()
        payload = {"ip": ip_addr, "machine": machine_id, "token": token}
        
        print(f"[INIT] Calling backend: {config.BACKEND_DEPLOY_URL} with {payload}", flush=True)
        success, result = APIClient.deploy_done(payload)
        if not success:
            _fail_and_stop(f"Backend request failed: {result}")
        
        resp = result
        status = str(resp.get("status", "")).lower()
        license_text = resp.get("license")
        pub_key_b64 = resp.get("pub_key")
        
        if status != "success" or not license_text or not pub_key_b64:
            _fail_and_stop(f"Backend failure or missing fields: {resp}")

        try:
            _atomic_write(config.LICENSE_PATH, license_text.encode("utf-8"), mode=0o600)
            _atomic_write(config.PUBKEY_PATH, base64.b64decode(pub_key_b64), mode=0o600)
            print(f"[INIT] Saved license -> {config.LICENSE_PATH}, pubkey -> {config.PUBKEY_PATH}", flush=True)
        except Exception as e:
            _fail_and_stop(f"Failed writing license/pubkey: {e}")

        try:
            with open(config.INIT_FILE, "w", encoding="utf-8") as f:
                f.write("1\n")
            print(f"[INIT] Updated {config.INIT_FILE} to 1 (deploy_done success)", flush=True)
        except Exception as e:
            _fail_and_stop(f"Failed to write {config.INIT_FILE}: {e}")

        print(f"[INIT] Calling backend: {config.BACKEND_DEPLOY_COMPLETE_URL} with {payload}", flush=True)
        success, result = APIClient.deploy_complete(payload)
        if not success:
            _fail_and_stop(f"Backend request failed: {result}")

    except SystemExit:
        raise
    except Exception as e:
        _fail_and_stop(f"Unexpected error: {e}")


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

