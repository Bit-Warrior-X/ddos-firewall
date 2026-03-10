# core/fifo_worker.py
"""FIFO reader worker for processing firewall commands."""
import os
import threading
import time
import json
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

def _lookup_geo(ip: str) -> Tuple[str, str]:
    global _geoip_reader

    if not ip:
        return "-", "-"

    if _geoip_reader is None:
        try:
            db_path = "/usr/local/openresty/nginx/lua/geoip2/dbip-full-2026-02.mmdb"
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


def process_command(cmd: Dict[str, str]) -> None:
    """Processes a single command dictionary."""
    print(f"[API_PARSER] Processing command: {cmd}")
    token = get_token()
    if not token:
        print(f"[API_PARSER] No API token configured; skipping command: {cmd}")
        return
    try:
        if cmd['command'] == 'report_license':
            payload = {
                'command': 'report_license',
                'data': str(cmd.get('data', 'unknown')),
                'token': token
            }
            APIClient.send_report_xdp(payload)
        elif cmd['command'] == 'report_protection':
            payload = {
                'command': 'report_protection',
                'data': str(cmd.get('data', 'unknown')),
                'token': token
            }
            APIClient.send_report_xdp(payload)
        elif cmd['command'] == 'report_attack':
            payload = {
                'command': 'report_attack',
                'data': str(cmd.get('data', 'unknown')),
                'token': token
            }
            APIClient.send_report_xdp(payload)
        elif cmd['command'] == 'report_block_ip':
            payload = {
                'command': 'report_block_ip',
                'ip': str(cmd.get('ip', 'unknown')),
                'ttl': str(cmd.get('ttl', 'unknown')),
                'attack_type': str(cmd.get('attack_type', 'unknown')),
                'token': token
            }
            APIClient.send_report_xdp(payload)

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
    """FIFO reader thread function."""
    if not os.path.exists(config.FIFO_PATH):
        os.mkfifo(config.FIFO_PATH)
    print(f"... listening at {config.FIFO_PATH}")
    while True:
        try:
            with open(config.FIFO_PATH, 'r') as fifo:
                print(f"[API_PARSER] FIFO opened")
                buf = []
                for line in fifo:
                    print(f"[API_PARSER] FIFO line: {line}")
                    line = line.rstrip('\n')
                    if line == "":  # delimiter between commands
                        raw = "\n".join(buf).strip()
                        print(f"[API_PARSER] FIFO raw: {raw}")
                        if raw:
                            print(f"[API_PARSER] FIFO raw: {raw}")
                            for cmd in parse_fifo_message(raw):
                                process_command(cmd)
                        buf = []
                    else:
                        buf.append(line)
        except Exception as e:
            print(f"[API_PARSER] FIFO error: {e}; retrying in 1s")
            time.sleep(1)

def start_fifo_listener():
    """Start the FIFO reader thread."""
    thread = threading.Thread(target=fifo_reader_thread, daemon=True)
    thread.start()
    return thread

