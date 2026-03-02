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
    """
    Lookup (country, city) for an IP using MaxMind GeoIP2 city DB.

    If geo DB or library is unavailable, returns ("-", "-") and logs once.
    """
    global _geoip_reader
    if not ip:
        return "-", "-"

    if _geoip_reader is None:
        try:
            import geoip2.database  # type: ignore
            db_path = "/usr/local/openresty/nginx/lua/geoip2/dbip-full-2026-02.mmdb"
            _geoip_reader = geoip2.database.Reader(db_path)
            print(f"[API_PARSER] GeoIP2 reader initialized with DB: {db_path}")
        except Exception as e:
            print(f"[API_PARSER] GeoIP2 init failed, geo will be '-': {e}")
            _geoip_reader = False  # sentinel to avoid repeated attempts
            return "-", "-"

    if _geoip_reader is False:
        return "-", "-"

    try:
        resp = _geoip_reader.city(ip)

        # Country (prefer English name)
        country = (
            resp.country.names.get("en")
            if resp.country and resp.country.names
            else None
        ) or resp.country.iso_code or "-"

        # City (prefer English name)
        city = (
            resp.city.names.get("en")
            if resp.city and resp.city.names
            else None
        ) or "-"
        
        return country or "-", city or "-"
    except Exception as e:
        print(f"[API_PARSER] GeoIP2 lookup failed for ip={ip}: {e}")
        return "-", "-"


def process_command(cmd: Dict[str, str]) -> None:
    """Processes a single command dictionary."""
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
                buf = []
                for line in fifo:
                    line = line.rstrip('\n')
                    if line == "":  # delimiter between commands
                        raw = "\n".join(buf).strip()
                        if raw:
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

