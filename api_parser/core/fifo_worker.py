# core/fifo_worker.py
"""FIFO reader worker for processing firewall commands."""
import os
import threading
import time
import json
import socket
from queue import Queue, Full
from typing import Dict, List, Tuple
from core.api_client import APIClient
from core.redis_client import RedisClient
import config
from utils.auth import get_token
import maxminddb

def parse_fifo_message(raw_data: str) -> List[Dict[str, str]]:
    """Parses raw FIFO data into command dictionaries."""
    commands = []
    current_command = {}
    
    for line in raw_data.split('\n'):
        line = line.strip()
        if not line:
            continue
            
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            
            if key == 'command':
                if current_command:
                    commands.append(current_command)
                current_command = {'command': value}
            else:
                current_command[key] = value
    
    if current_command:
        commands.append(current_command)
    
    return commands

_geoip_reader = None
_cmd_queue = Queue(maxsize=20000)
_critical_queue = Queue(maxsize=1000)
_dgram_drop_count = 0
_critical_drop_count = 0
_CRITICAL_COMMANDS = {"report_license", "report_protection", "report_attack"}
_CRITICAL_ATTEMPTS = 5


def _command_worker() -> None:
    """Worker that handles high-volume commands off the receive path."""
    while True:
        cmd = _cmd_queue.get()
        try:
            process_command(cmd)
        finally:
            _cmd_queue.task_done()


def _critical_worker() -> None:
    """One worker so attack and protection reports are not queued behind block-IP posts."""
    while True:
        cmd = _critical_queue.get()
        try:
            process_command(cmd, reliable=True)
        finally:
            _critical_queue.task_done()

def _lookup_geo(ip: str) -> Tuple[str, str]:
    global _geoip_reader

    if not ip:
        return "-", "-"

    if _geoip_reader is None:
        try:
            db_path = config.GEOIP_MMDB_PATH
            _geoip_reader = maxminddb.open_database(db_path)
            print(f"[API_PARSER] MaxMind DB reader initialized with DB: {db_path}")
        except Exception as e:
            print(f"[API_PARSER] MaxMind DB init failed: {e}")
            _geoip_reader = False
            return "-", "-"

    if _geoip_reader is False:
        return "-", "-"

    try:
        record = _geoip_reader.get(ip)
        country = record.get("country", {}).get("iso_code", "-")
        city = record.get("city", {}).get("names", {}).get("en", "-")
        return country, city
    except Exception as e:
        print(f"[API_PARSER] Geo lookup failed for ip={ip}: {e}")
        return "-", "-"


def _log_field(value) -> str:
    """Cython's fast %s join segfaults on None. Always hand it a real str."""
    if value is None:
        return ""
    return str(value)


def _deliver_report(payload: Dict[str, str], reliable: bool) -> None:
    """POST a report. Critical reports are retried when the panel is briefly unavailable."""
    attempts = _CRITICAL_ATTEMPTS if reliable else 1
    delay = 0.5
    command = _log_field(payload.get("command"))
    data = _log_field(payload.get("data") or payload.get("attack_type"))
    req_id = _log_field(payload.get("req_id"))
    for attempt in range(1, attempts + 1):
        ok, retriable = APIClient.post_report_xdp(payload)
        if ok:
            if reliable:
                print(
                    "[API_PARSER] report_xdp delivered command="
                    + command
                    + " data="
                    + data
                    + " req_id="
                    + req_id
                    + " attempt="
                    + str(attempt),
                    flush=True,
                )
            return
        if not reliable or not retriable or attempt == attempts:
            print(
                "[API_PARSER] report_xdp gave up command="
                + command
                + " data="
                + data
                + " req_id="
                + req_id
                + " attempt="
                + str(attempt),
                flush=True,
            )
            return
        time.sleep(delay)
        delay = min(delay * 2, 8)


_OPTIONAL_ALERT_FIELDS = (
    "class",
    "state",
    "mode",
    "rate",
    "enter",
    "exit",
    "peak",
    "why",
    "source",
    "classes",
)


def _copy_optional_alert_fields(cmd: Dict[str, str], payload: Dict[str, str]) -> None:
    """Pass through adaptive/classic detail fields when present on the wire."""
    for key in _OPTIONAL_ALERT_FIELDS:
        val = cmd.get(key)
        if val is not None and str(val) != "":
            payload[key] = str(val)


def process_command(cmd: Dict[str, str], reliable: bool = False) -> None:
    """Processes a single command dictionary."""
    print(f"[API_PARSER] Processing command: {cmd}")
    token = get_token()
    if not token:
        print(f"[API_PARSER] No API token configured; skipping command: {cmd}")
        return
    try:
        if cmd['command'] == 'report_license':
            payload = {
                'req_id': str(cmd.get('req_id', '')),
                'time': str(cmd.get('time', 'unknown')),
                'command': 'report_license',
                'data': str(cmd.get('data', 'unknown')),
                'token': token
            }
            _deliver_report(payload, reliable)
        elif cmd['command'] == 'report_protection':
            payload = {
                'time': str(cmd.get('time', 'unknown')),
                'command': 'report_protection',
                'data': str(cmd.get('data', 'unknown')),
                'req_id': str(cmd.get('req_id', '')),
                'token': token
            }
            _copy_optional_alert_fields(cmd, payload)
            _deliver_report(payload, reliable)
        elif cmd['command'] == 'report_attack':
            payload = {
                'time': str(cmd.get('time', 'unknown')),
                'command': 'report_attack',
                'data': str(cmd.get('data', 'unknown')),
                'req_id': str(cmd.get('req_id', '')),
                'token': token
            }
            _copy_optional_alert_fields(cmd, payload)
            _deliver_report(payload, reliable)
        elif cmd['command'] == 'report_block_ip':
            payload = {
                'time': str(cmd.get('time', 'unknown')),
                'command': 'report_block_ip',
                'ip': str(cmd.get('ip', 'unknown')),
                'ttl': str(cmd.get('ttl', 'unknown')),
                'attack_type': str(cmd.get('attack_type', 'unknown')),
                'req_id': str(cmd.get('req_id', '')),
                'token': token
            }
            _copy_optional_alert_fields(cmd, payload)
            _deliver_report(payload, reliable)

            # Also add this IP to temporaryblacklist in Redis (for L7 WAF), and publish.
            ip = (cmd.get('ip') or '').strip()
            ttl_raw = cmd.get('ttl') or ''
            try:
                ttl = int(ttl_raw)
            except (TypeError, ValueError):
                ttl = config.DEFAULT_BLOCK_DURATION

            if ip and ttl > 0:
                try:
                    blocked_at = int(time.time())
                    country, city = _lookup_geo(ip)
                    entry = {
                        "ip": ip,
                        # Use a regex that matches any URI for this IP
                        "url": ".*",
                        "country": country,
                        "city": city,
                        "blocked_at": str(blocked_at),
                        "ttl": ttl,
                        # Mark that this came from L4 DDoS logic
                        "trigger_rule": "l4ddos",
                        "req_id": str(cmd.get("req_id", "")),
                    }
                    json_str = json.dumps(entry, ensure_ascii=False, separators=(",", ":")).replace("\\/", "/")

                    rcli = RedisClient.get_client()
                    key = f"temporaryblacklist:{ip}:{blocked_at}"
                    rcli.set(key, json_str)
                    rcli.expire(key, ttl)
                    # Notify L7-side monitor & backend
                    rcli.publish("temporaryblacklist:added", json_str)
                    print(f"[API_PARSER] Added L4 temp blacklist entry key={key} ttl={ttl}")
                except Exception as e:
                    print(f"[API_PARSER] Failed to add L4 temp blacklist entry for ip={ip}: {e}")
        else:
            print(f"[API_PARSER] Unknown command: {cmd['command']}")
    except Exception as e:
        print(f"[API_PARSER] Error processing command {cmd}: {str(e)}")

def fifo_reader_thread():
    """AF_UNIX datagram listener for firewall commands."""
    global _dgram_drop_count, _critical_drop_count

    if os.path.exists(config.UNIX_DGRAM_PATH):
        os.unlink(config.UNIX_DGRAM_PATH)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError as e:
        print(f"[API_PARSER] Failed to set SO_RCVBUF: {e}")
    sock.bind(config.UNIX_DGRAM_PATH)
    os.chmod(config.UNIX_DGRAM_PATH, 0o666)
    print(f"[API_PARSER] AF_UNIX DGRAM listening at {config.UNIX_DGRAM_PATH}")

    threading.Thread(target=_critical_worker, daemon=True).start()
    worker_count = 4
    for _ in range(worker_count):
        threading.Thread(target=_command_worker, daemon=True).start()

    while True:
        try:
            raw_bytes = sock.recv(65535)
            if not raw_bytes:
                continue
            raw = raw_bytes.decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            for cmd in parse_fifo_message(raw):
                critical = cmd.get("command") in _CRITICAL_COMMANDS
                queue = _critical_queue if critical else _cmd_queue
                try:
                    queue.put_nowait(cmd)
                except Full:
                    if critical:
                        _critical_drop_count += 1
                        print(
                            "[API_PARSER] Critical command queue full, dropping command="
                            + _log_field(cmd.get("command"))
                            + " data="
                            + _log_field(cmd.get("data"))
                            + " req_id="
                            + _log_field(cmd.get("req_id"))
                            + " dropped="
                            + str(_critical_drop_count),
                            flush=True,
                        )
                    else:
                        _dgram_drop_count += 1
                        if (_dgram_drop_count % 100) == 1:
                            print(f"[API_PARSER] Command queue full, dropping commands (dropped={_dgram_drop_count})")
        except Exception as e:
            print(f"[API_PARSER] AF_UNIX DGRAM error: {e}; retrying in 1s")
            time.sleep(1)

def start_fifo_listener():
    """Start the FIFO reader thread."""
    thread = threading.Thread(target=fifo_reader_thread, daemon=True)
    thread.start()
    return thread

