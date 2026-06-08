# routes/l7_routes.py
"""L7 firewall API routes (Redis-backed rule sync; nginx files are not edited via this API)."""
import base64
import binascii
import json
import subprocess
from flask import Blueprint, request, jsonify

from core.redis_client import RedisClient
from utils.auth import token_required, extract_token
from utils.validators import validate_url

l7_bp = Blueprint('l7', __name__, url_prefix='/API/L7')

@l7_bp.route('/firewall_main', methods=['POST'])
@token_required
def firewall_main_l7():
    """Control L7 firewall service."""
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request must be application/json"}), 400
    
    data = request.json
    status = data.get('status')
    
    if not status:
        return jsonify({"status": "error", "message": "Missing 'status' parameters"}), 400
    
    action = str(status).strip().lower()
    allowed_actions = {'start', 'stop', 'restart'}
    
    if action not in allowed_actions:
        return jsonify({"status": "error", "message": "Invalid action. Valid actions: start, stop, restart"}), 400
    
    cmd = ['systemctl', action, 'l7_firewall']
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30
        )
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Command timed out'}), 504
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Unexpected error: {str(e)}'}), 400
    
    return jsonify({
        "status": "success",
        "action": action,
        "message": "success",
    }), 200


def _build_whitelist_rule_string(ips: str, url: str, method: str) -> str:
    """Build ACL rule string from backend rule fields (IP, URI path, RequestMethod)."""
    ips = (ips or "").strip()
    url = (url or "").strip()
    method = (method or "").strip()
    parts = []
    if ips:
        parts.append(f'["IP","-","is in","{ips}"]')
    if url:
        parts.append(f'["URI Path","-","regex","{url}"]')
    if method:
        parts.append(f'["RequestMethod","-","is in","{method}"]')
    return " \nAND \n".join(parts) if parts else ""


def _behavior_to_action(behavior: str) -> int:
    """Map behavior string to action code.

    Mapping:
      Allow       -> 1
      Drop        -> 2
      Deny        -> 3
      Drop+Block  -> 4
    """
    b = (behavior or "").strip().lower()
    mapping = {
        "allow": 1,
        "drop": 2,
        "deny": 3,
        "drop+block": 4,
    }
    return mapping.get(b, 3)


def _build_geo_rule_string(url: str, country: str) -> str:
    """Build ACL rule string for Geo-based rules (URI path + Geo country list)."""
    url = (url or "").strip()
    country = (country or "").strip()
    parts = []
    if url:
        parts.append(f'["URI Path","-","regex","{url}"]')
    if country:
        parts.append(f'["Geo","-","is in","{country}"]')
    return " \nAND \n".join(parts) if parts else ""


def _block_mode_to_header_op(block_mode: str) -> str:
    """Map block_mode to header comparison operator for ACL."""
    bm = (block_mode or "").strip().lower()
    if bm == "if not match":
        return "is not in"
    # default and 'If match'
    return "is in"


def _build_antiheader_rule_string(url: str, header: str, value: str, block_mode: str) -> str:
    """Build ACL rule string for anti-header rules (URI path + header value)."""
    url = (url or "").strip()
    header = (header or "").strip()
    value = (value or "").strip()
    op = _block_mode_to_header_op(block_mode)
    parts = []
    if url:
        parts.append(f'["URI Path","-","regex","{url}"]')
    if header and value:
        parts.append(f'["Header","{header}","{op}","{value}"]')
    return " \nAND \n".join(parts) if parts else ""


def _build_intervalfreq_rule_string(url: str, req_count: int, time_sec: int) -> str:
    """Build ACL rule string for interval frequency limit rules."""
    url = (url or "").strip()
    try:
        req_count = int(req_count)
    except (TypeError, ValueError):
        req_count = 0
    try:
        time_sec = int(time_sec)
    except (TypeError, ValueError):
        time_sec = 0
    parts = []
    if url:
        parts.append(f'["URI Path","-","regex","{url}"]')
    if req_count > 0 and time_sec > 0:
        freq_str = f"{req_count}times/{time_sec}s"
        parts.append(f'["Request Frequency","-",">=","{freq_str}"]')
    return " \nAND \n".join(parts) if parts else ""


def _build_secondfreq_rule_string(url: str, req_count: int, burst: int) -> str:
    """Build ACL rule string for second frequency (burst) limit rules."""
    url = (url or "").strip()
    try:
        req_count = int(req_count)
    except (TypeError, ValueError):
        req_count = 0
    try:
        burst = int(burst)
    except (TypeError, ValueError):
        burst = 0
    parts = []
    if url:
        parts.append(f'["URI Path","-","regex","{url}"]')
    if burst > 0 and req_count > 0:
        freq_str = f"{burst}/{req_count}"
        parts.append(f'["Burst Frequency","-","-","{freq_str}"]')
    return " \nAND \n".join(parts) if parts else ""


def _build_responsefreq_rule_string(url: str, response_code: str, response_count: int, time_sec: int) -> str:
    """Build ACL rule string for response frequency rules (URI path + response code + count/time)."""
    url = (url or "").strip()
    response_code = (response_code or "").strip()
    try:
        response_count = int(response_count)
    except (TypeError, ValueError):
        response_count = 0
    try:
        time_sec = int(time_sec)
    except (TypeError, ValueError):
        time_sec = 0
    parts = []
    if url:
        parts.append(f'["URI Path","-","regex","{url}"]')
    if response_count > 0 and time_sec > 0:
        freq_str = f"{response_count}times/{time_sec}s"
        code_val = response_code if response_code else "-"
        parts.append(f'["Response Frequency","{code_val}",">=","{freq_str}"]')
    return " \nAND \n".join(parts) if parts else ""


def _match_to_useragent_op(match: str) -> str:
    """Map match type to UserAgent operator."""
    m = str(match or "").strip().lower()
    if m == "regex":
        return "regex"
    if m == "equals":
        return "equals"
    if m == "contains":
        return "contains"
    # default
    return "equals"


def _build_useragent_rule_string(url: str, user_agent: str, match: str) -> str:
    """Build ACL rule string for user-agent rules."""
    url = (url or "").strip()
    ua = (user_agent or "").strip()
    op = _match_to_useragent_op(match)
    parts = []
    if url:
        parts.append(f'["URI Path","-","regex","{url}"]')
    if ua:
        parts.append(f'["UserAgent","-","{op}","{ua}"]')
    return " \nAND \n".join(parts) if parts else ""


@l7_bp.route('/l7_update_whitelist', methods=['POST'])
def l7_update_whitelist():
    """Receive whitelist from backend and store in Redis under key 'whitelist'.

    Expected JSON: { serverId, serverIp, rules: [ { id, serverId, ips, url, method, description }, ... ] }
    Transforms into Redis value: { id, rules: [ { action: 1, priority, rule: "..." }, ... ] }
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    rules_in = data.get("rules")
    if rules_in is None:
        rules_in = []
    elif not isinstance(rules_in, list):
        return jsonify({"status": "error", "message": "Invalid 'rules' (must be array)."}), 400

    redis_rules = []
    for idx, r in enumerate(rules_in):
        if not isinstance(r, dict):
            continue
        rule_id = r.get("id")
        if rule_id is None:
            rule_id = idx + 1
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            rule_id = idx + 1
        ips = r.get("ips", "") or ""
        url = r.get("url", "") or ""
        method = r.get("method", "") or ""
        rule_str = _build_whitelist_rule_string(ips, url, method)
        redis_rules.append({
            "action": 1,
            "priority": rule_id,
            "rule": rule_str
        })

    whitelist_payload = {
        "id": 1,
        "rules": redis_rules
    }
    ok, err = RedisClient.store_whitelist(whitelist_payload)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write whitelist to Redis.",
            "details": err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Whitelist updated in Redis.",
        "serverId": server_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/l7_update_upstreamservers', methods=['POST'])
def l7_update_upstreamservers():
    """Receive upstream servers from backend and store in Redis under key 'upstreamservers'.

    Expected JSON: { serverId, upstreams: [ { id, serverId, ip_port, description }, ... ] }
    Redis value: [ {"ip_port": "host:port", "description": "weight=4 max_fails=3 fail_timeout=30s"}, ... ]
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    upstreams_in = data.get("upstreams")
    if upstreams_in is None:
        upstreams_in = []
    if not isinstance(upstreams_in, list):
        return jsonify({"status": "error", "message": "Invalid 'upstreams' (must be array)."}), 400

    redis_upstreams = []
    for u in upstreams_in:
        if not isinstance(u, dict):
            continue
        ip_port = (u.get("ip_port") or "").strip()
        if not ip_port:
            continue
        description = (u.get("description") or "").strip()
        redis_upstreams.append({
            "ip_port": ip_port,
            "description": description or "weight=1 max_fails=3 fail_timeout=30s"
        })

    ok, err = RedisClient.store_upstreamservers(redis_upstreams)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write upstream servers to Redis.",
            "details": err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Upstream servers updated in Redis.",
        "serverId": server_id,
        "upstreamsCount": len(redis_upstreams)
    }), 200


@l7_bp.route('/l7_update_temporaryblacklist', methods=['POST'])
def l7_update_temporaryblacklist():
    """
    Receive temporary blacklist from backend and store in Redis as per-key entries.

    Expected JSON:
    {
      "serverId": 123,
      "temporaryblacklist": [
        {
          "ip": "192.168.1.1",
          "url": "/api/foo",
          "country": "United States",
          "city": "New York",
          "blocked_at": "1729876543",
          "ttl": 180,
          "trigger_rule": "intervalfreqlimit"
        },
        ...
      ]
    }

    Behavior:
      - Delete all existing temporaryblacklist:* keys in Redis.
      - Store each entry as key temporaryblacklist:<ip>:<blocked_at> with JSON value.
      - TTL for each key is computed as blocked_at + ttl - now_epoch().
      - These writes do NOT notify backend again (no publish on temporaryblacklist:added).
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    items = data.get("temporaryblacklist") or []
    if not isinstance(items, list):
        return jsonify({"status": "error", "message": "Invalid 'temporaryblacklist' (must be array)."}), 400

    # Load existing temporaryblacklist entries before clearing, so we can detect removed L4 entries.
    try:
        rcli = RedisClient.get_client()
        # Snapshot of existing keys: key -> parsed JSON
        old_entries = {}
        cursor = "0"
        pattern = f"{RedisClient.TEMPORARYBLACKLIST_PREFIX}*"
        while True:
            cursor, keys = rcli.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                for k in keys:
                    try:
                        raw = rcli.get(k)
                        if raw:
                            obj = json.loads(raw)
                            if isinstance(obj, dict):
                                old_entries[k] = obj
                    except Exception:
                        continue
            if cursor == 0 or cursor == "0":
                break
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to read old temporary blacklist from Redis: {e}"}), 500

    # Build a fast lookup for new entries by IP+blocked_at, so we know which old keys disappeared.
    new_index = set()
    for e in items:
        if not isinstance(e, dict):
            continue
        ip = (e.get("ip") or "").strip()
        blocked_at = str(e.get("blocked_at") or "").strip()
        if ip and blocked_at:
            new_index.add((ip, blocked_at))

    # For any old entry that was L4 (trigger_rule == "l4ddos") and is not in new_index,
    # call sparta_cli CLEAR_BLOCK_IP <ip> to clear the L4 block.
    for key, obj in old_entries.items():
        try:
            trig = str(obj.get("trigger_rule", "")).strip().lower()
            ip = str(obj.get("ip", "")).strip()
            blocked_at = str(obj.get("blocked_at", "")).strip()
            if trig == "l4ddos" and ip and blocked_at and (ip, blocked_at) not in new_index:
                command_args = ["sparta_cli", "CLEAR_BLOCK_IP", ip]
                # Reuse the helper from l4_routes to execute CLI
                from routes.l4_routes import execute_cli_command  # local import to avoid cycles at module load
                res = execute_cli_command(command_args)
                print(f"[L7] CLEAR_BLOCK_IP ip={ip} result={res.get('status')} msg={res.get('message')}")
        except Exception as e:
            print(f"[L7] Error while clearing L4 block for key={key}: {e}")

    # Clear existing temporaryblacklist:* keys, then store new set.
    try:
        RedisClient.clear_temporaryblacklist()
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to clear temporary blacklist in Redis: {e}"}), 500

    ok, err = RedisClient.store_temporaryblacklist(items)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write temporary blacklist to Redis.",
            "details": err or "Unknown error"
        }), 500

    # Count only entries that were non-expired and had valid ip/ttl
    return jsonify({
        "status": "success",
        "message": "Temporary blacklist updated in Redis.",
        "serverId": server_id,
        "itemsCount": len(items)
    }), 200


@l7_bp.route('/l7_update_blacklist', methods=['POST'])
def l7_update_blacklist():
    """Receive blacklist from backend and store in Redis under key 'blacklist'.

    Expected JSON: { serverId, serverIp, rules: [ { id, serverId, ips, url, method, behavior, description }, ... ] }
    Transforms into Redis value: { id, rules: [ { action, priority, rule: "..." }, ... ] }
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    rules_in = data.get("rules")
    if rules_in is None:
        rules_in = []
    elif not isinstance(rules_in, list):
        return jsonify({"status": "error", "message": "Invalid 'rules' (must be array)."}), 400
    
    redis_rules = []
    for idx, r in enumerate(rules_in):
        if not isinstance(r, dict):
            continue
        rule_id = r.get("id")
        if rule_id is None:
            rule_id = idx + 1
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            rule_id = idx + 1

        ips = r.get("ips", "") or ""
        url = r.get("url", "") or ""
        method = r.get("method", "") or ""
        behavior = r.get("behavior", "") or ""

        action = _behavior_to_action(behavior)
        rule_str = _build_whitelist_rule_string(ips, url, method)

        redis_rules.append({
            "action": action,
            "priority": rule_id,
            "rule": rule_str
        })

    blacklist_payload = {
        "id": 2,
        "rules": redis_rules
    }
    ok, err = RedisClient.store_blacklist(blacklist_payload)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write blacklist to Redis.",
            "details": err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Blacklist updated in Redis.",
        "serverId": server_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/l7_update_geo', methods=['POST'])
def l7_update_geo():
    """Receive Geo rules from backend and store in Redis under key 'geo'.

    Expected JSON:
      {
        "serverId": 123,
        "serverIp": "x.x.x.x",
        "rules": [
          { "id": 1, "serverId": 123, "country": "Asia, Africa", "url": "/path",
            "behavior": "Deny", "operation": "BLACK", "status": "ENABLE" },
          ...
        ]
      }

    We ignore 'status' and 'operation' and map 'behavior' to action:
      allow -> 1, Drop -> 2, Deny -> 3, Drop+Block -> 4
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    rules_in = data.get("rules")
    if rules_in is None:
        rules_in = []
    elif not isinstance(rules_in, list):
        return jsonify({"status": "error", "message": "Invalid 'rules' (must be array)."}), 400

    redis_rules = []
    for idx, r in enumerate(rules_in):
        if not isinstance(r, dict):
            continue

        rule_id = r.get("id")
        if rule_id is None:
            rule_id = idx + 1
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            rule_id = idx + 1

        url = r.get("url", "") or ""
        country = r.get("country", "") or ""
        behavior = r.get("behavior", "") or ""

        action = _behavior_to_action(behavior)
        rule_str = _build_geo_rule_string(url, country)

        redis_rules.append({
            "action": action,
            "priority": rule_id,
            "rule": rule_str
        })

    geo_payload = {
        "id": 3,
        "rules": redis_rules
    }
    ok, err = RedisClient.store_geo(geo_payload)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write geo rules to Redis.",
            "details": err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Geo rules updated in Redis.",
        "serverId": server_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/l7_update_antiheader', methods=['POST'])
def l7_update_antiheader():
    """Receive anti-header rules from backend and store in Redis under key 'antiheader'.

    Expected JSON:
      {
        "serverId": 123,
        "serverIp": "x.x.x.x",
        "rules": [
          {
            "id": 1,
            "serverId": 123,
            "url": "/path",
            "header": "X-XX-Protection",
            "value": "curl",
            "blockMode": "If match",
            "behavior": "Deny",
            "status": "ENABLE"
          },
          ...
        ]
      }

    We ignore 'status'. block_mode is mapped:
      "If match"     -> "is in"
      "If not match" -> "is not in"
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    rules_in = data.get("rules")
    if rules_in is None:
        rules_in = []
    elif not isinstance(rules_in, list):
        return jsonify({"status": "error", "message": "Invalid 'rules' (must be array)."}), 400
    redis_rules = []
    for idx, r in enumerate(rules_in):
        if not isinstance(r, dict):
            continue

        rule_id = r.get("id")
        if rule_id is None:
            rule_id = idx + 1
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            rule_id = idx + 1

        url = r.get("url", "") or ""
        header = r.get("header", "") or ""
        value = r.get("value", "") or ""
        block_mode = r.get("blockMode", "") or ""
        behavior = r.get("behavior", "") or ""

        action = _behavior_to_action(behavior)
        rule_str = _build_antiheader_rule_string(url, header, value, block_mode)

        redis_rules.append({
            "action": action,
            "priority": rule_id,
            "rule": rule_str
        })

    anti_payload = {
        "id": 4,
        "rules": redis_rules
    }
    ok, err = RedisClient.store_antiheader(anti_payload)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write antiheader rules to Redis.",
            "details": err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Antiheader rules updated in Redis.",
        "serverId": server_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/l7_update_useragent', methods=['POST'])
def l7_update_useragent():
    """Receive user-agent rules from backend and store in Redis under key 'useragent'.

    Expected JSON:
      {
        "serverId": 123,
        "serverIp": "x.x.x.x",
        "rules": [
          {
            "id": 1,
            "serverId": 123,
            "url": "/path",
            "user_agent": "curl/7.0",
            "match": "Regex" | "Equals" | "Contains",
            "behavior": "Deny",
            "status": "ENABLE"
          },
          ...
        ]
      }

    We ignore 'status'. match is mapped:
      Regex   -> "regex"
      Equals  -> "equals"
      Contains-> "contains"
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    rules_in = data.get("rules")
    if rules_in is None:
        rules_in = []
    elif not isinstance(rules_in, list):
        return jsonify({"status": "error", "message": "Invalid 'rules' (must be array)."}), 400

    redis_rules = []
    for idx, r in enumerate(rules_in):
        if not isinstance(r, dict):
            continue

        rule_id = r.get("id")
        if rule_id is None:
            rule_id = idx + 1
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            rule_id = idx + 1

        url = r.get("url", "") or ""
        ua = r.get("user_agent", "") or ""
        match = r.get("match", "") or ""
        behavior = r.get("behavior", "") or ""

        action = _behavior_to_action(behavior)
        rule_str = _build_useragent_rule_string(url, ua, match)

        redis_rules.append({
            "action": action,
            "priority": rule_id,
            "rule": rule_str
        })

    payload = {
        "id": 8,
        "rules": redis_rules
    }
    ok, err = RedisClient.store_useragent(payload)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write useragent rules to Redis.",
            "details": err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Useragent rules updated in Redis.",
        "serverId": server_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/l7_update_intervalfreqlimit', methods=['POST'])
def l7_update_intervalfreqlimit():
    """Receive interval frequency limit rules and store in Redis under key 'intervalfreqlimit'.

    Expected JSON:
      {
        "serverId": 123,
        "serverIp": "x.x.x.x",
        "rules": [
          {
            "id": 1,
            "serverId": 123,
            "url": "/path",
            "time": 100,
            "request_count": 5,
            "behavior": "Deny",
            "status": "ENABLE"
          },
          ...
        ]
      }

    We ignore 'status'. Rule format:
      ["URI Path","-","regex","/path"]
      AND
      ["Request Frequency","-",">=","5times/100s"]
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    rules_in = data.get("rules")
    if rules_in is None:
        rules_in = []
    elif not isinstance(rules_in, list):
        return jsonify({"status": "error", "message": "Invalid 'rules' (must be array)."}), 400

    redis_rules = []
    for idx, r in enumerate(rules_in):
        if not isinstance(r, dict):
            continue

        rule_id = r.get("id")
        if rule_id is None:
            rule_id = idx + 1
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            rule_id = idx + 1

        url = r.get("url", "") or ""
        time_sec = r.get("time", 0)
        req_count = r.get("request_count", 0)
        behavior = r.get("behavior", "") or ""

        action = _behavior_to_action(behavior)
        rule_str = _build_intervalfreq_rule_string(url, req_count, time_sec)

        redis_rules.append({
            "action": action,
            "priority": rule_id,
            "rule": rule_str
        })

    payload = {
        "id": 5,
        "rules": redis_rules
    }
    ok, err = RedisClient.store_intervalfreqlimit(payload)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write interval frequency limit rules to Redis.",
            "details": err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Interval frequency limit rules updated in Redis.",
        "serverId": server_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/l7_update_secondfreqlimit', methods=['POST'])
def l7_update_secondfreqlimit():
    """Receive second frequency (burst) limit rules and store in Redis under key 'secondfreqlimit'.

    Expected JSON:
      {
        "serverId": 123,
        "serverIp": "x.x.x.x",
        "rules": [
          {
            "id": 1,
            "serverId": 123,
            "url": "/path",
            "request_count": 10,
            "burst": 5,
            "behavior": "Deny",
            "status": "ENABLE"
          },
          ...
        ]
      }

    We ignore 'status'. Rule format:
      ["URI Path","-","regex","/path"]
      AND
      ["Burst Frequency","-","-","5/10"]
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    rules_in = data.get("rules")
    if rules_in is None:
        rules_in = []
    elif not isinstance(rules_in, list):
        return jsonify({"status": "error", "message": "Invalid 'rules' (must be array)."}), 400

    redis_rules = []
    for idx, r in enumerate(rules_in):
        if not isinstance(r, dict):
            continue

        rule_id = r.get("id")
        if rule_id is None:
            rule_id = idx + 1
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            rule_id = idx + 1

        url = r.get("url", "") or ""
        req_count = r.get("request_count", 0)
        burst = r.get("burst", 0)
        behavior = r.get("behavior", "") or ""

        action = _behavior_to_action(behavior)
        rule_str = _build_secondfreq_rule_string(url, req_count, burst)

        redis_rules.append({
            "action": action,
            "priority": rule_id,
            "rule": rule_str
        })

    payload = {
        "id": 6,
        "rules": redis_rules
    }
    ok, err = RedisClient.store_secondfreqlimit(payload)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write second frequency limit rules to Redis.",
            "details": err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Second frequency limit rules updated in Redis.",
        "serverId": server_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/l7_update_responsefreq', methods=['POST'])
def l7_update_responsefreq():
    """Receive response frequency rules and store in Redis under key 'responsefreq'.

    Expected JSON:
      {
        "serverId": 123,
        "serverIp": "x.x.x.x",
        "rules": [
          {
            "id": 1,
            "serverId": 123,
            "url": "/path",
            "response_code": "not 404",
            "time": 100,
            "response_count": 5,
            "behavior": "Deny",
            "status": "ENABLE"
          },
          ...
        ]
      }

    We ignore 'status'. Rule format:
      ["URI Path","-","regex","/path"]
      AND
      ["Response Frequency","<response_code>",">=","<response_count>times/<time>s"]
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = data.get("serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'serverId'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'serverId' (must be integer)."}), 400

    rules_in = data.get("rules")
    if rules_in is None:
        rules_in = []
    elif not isinstance(rules_in, list):
        return jsonify({"status": "error", "message": "Invalid 'rules' (must be array)."}), 400

    redis_rules = []
    for idx, r in enumerate(rules_in):
        if not isinstance(r, dict):
            continue

        rule_id = r.get("id")
        if rule_id is None:
            rule_id = idx + 1
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            rule_id = idx + 1

        url = r.get("url", "") or ""
        response_code = r.get("response_code", "") or ""
        time_sec = r.get("time", 0)
        response_count = r.get("response_count", 0)
        behavior = r.get("behavior", "") or ""

        action = _behavior_to_action(behavior)
        rule_str = _build_responsefreq_rule_string(url, response_code, response_count, time_sec)

        redis_rules.append({
            "action": action,
            "priority": rule_id,
            "rule": rule_str
        })

    payload = {
        "id": 7,
        "rules": redis_rules
    }
    ok, err = RedisClient.store_responsefreq(payload)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write response frequency rules to Redis.",
            "details": err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Response frequency rules updated in Redis.",
        "serverId": server_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/acl_rule_management', methods=['POST'])
@token_required
def acl_rule_management():
    """Store ACL rules in Redis."""
    payload = request.get_json(silent=True) or {}
    items = payload.get("data")
    if not isinstance(items, list) or not items:
        return jsonify({"status": "error", "message": "Body must contain non-empty 'data' array."}), 400
    
    def decode_b64_text(field_name: str, s: str):
        if not isinstance(s, str):
            return None, f"'{field_name}' must be a base64-encoded string."
        try:
            raw = base64.b64decode(s.strip(), validate=True)
        except (binascii.Error, ValueError) as e:
            return None, f"'{field_name}' is not valid base64: {e}"
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None, f"'{field_name}' decoded bytes are not valid UTF-8 text."
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        return text, None

    seen_ids = set()
    prepared = []
    
    for idx, it in enumerate(items, start=1):
        if not isinstance(it, dict):
            return jsonify({"status": "error", "message": f"Entry #{idx} must be an object."}), 400

        try:
            acl_id = int(it.get("id", None))
            if acl_id <= 0:
                raise ValueError()
        except Exception:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid 'id' (must be positive integer)."}), 400
        if acl_id in seen_ids:
            return jsonify({"status": "error", "message": f"Duplicate id '{acl_id}'."}), 400
        seen_ids.add(acl_id)
        
        rules_b64 = it.get("rules", "")
        rules_text, err = decode_b64_text("rules", rules_b64)
        if err:
            return jsonify({"status": "error", "message": f"Entry #{idx}: {err}"}), 400

        rules_obj = None
        try:
            parsed = json.loads(rules_text)
            if isinstance(parsed, list):
                rules_obj = parsed
            elif isinstance(parsed, dict):
                rules_obj = [parsed]
            else:
                rules_obj = None
        except Exception:
            rules_obj = None
        
        if rules_obj is None:
            rules_obj = [
                {
                    "action": it.get("default_action", 1) or 1,
                    "priority": it.get("default_priority", 100) or 100,
                    "rule": rules_text
                }
            ]
            
        sanitized_rules = []
        for r in rules_obj:
            if isinstance(r, dict):
                rule_field = r.get("rule")
                if rule_field is None:
                    rule_str = json.dumps(r, ensure_ascii=False, indent=2).replace('\\/', '/')
                    action_val = int(r.get("action", 1)) if r.get("action") is not None else 1
                    priority_val = int(r.get("priority", 100)) if r.get("priority") is not None else 100
                else:
                    if isinstance(rule_field, (dict, list)):
                        rule_str = json.dumps(rule_field, ensure_ascii=False, indent=2).replace('\\/', '/')
                    else:
                        rule_str = str(rule_field)
                    action_val = int(r.get("action", 1)) if r.get("action") is not None else 1
                    priority_val = int(r.get("priority", 100)) if r.get("priority") is not None else 100
                sanitized_rules.append({
                    "action": action_val,
                    "priority": priority_val,
                    "rule": rule_str
                })
            else:
                sanitized_rules.append({
                    "action": 1,
                    "priority": 100,
                    "rule": str(r)
                })

        redis_obj = {
            "id": acl_id,
            "rules": sanitized_rules
        }
        prepared.append(redis_obj)

    ok, err = RedisClient.store_acl_rules(prepared)
    if not ok:
        return jsonify({"status": "error", "message": err}), 500

    return jsonify({
        "status": "success",
        "message": f"Wrote {len(prepared)} acl_rule(s) to Redis and published updates.",
        "ids": [r['id'] for r in prepared]
    }), 200

@l7_bp.route("/acl_rule_management", methods=["GET"])
def acl_rule_management_get():
    """Get ACL rules from Redis."""
    try:
        rcli = RedisClient.get_client()
        ids = rcli.smembers("acl_rule_ids") or set()
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to read acl_rule_ids from Redis: {e}"}), 500
    
    results = []
    try:
        for sid in sorted(ids, key=lambda x: int(x) if str(x).isdigit() else x):
            key = f"acl_rule:{sid}"
            try:
                val = rcli.get(key)
            except Exception as e:
                continue

            if not val:
                continue

            try:
                obj = json.loads(val)
            except Exception as e:
                rules_array = [{"action": 1, "priority": 100, "rule": val}]
            else:
                rules_array = obj.get("rules")
                if not isinstance(rules_array, list):
                    rules_array = [{"action": obj.get("action", 1),
                                    "priority": obj.get("priority", 100),
                                    "rule": obj.get("rule", "")}] if isinstance(obj, dict) else [{"action":1,"priority":100,"rule":str(obj)}]

            try:
                rules_json = json.dumps(rules_array, ensure_ascii=False, indent=2).replace('\\/', '/')
                rules_b64 = base64.b64encode(rules_json.encode("utf-8")).decode("ascii")
            except Exception as e:
                continue

            results.append({
                "id": int(sid) if str(sid).isdigit() else sid,
                "rules": rules_b64
            })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Unexpected error: {e}"}), 500

    return jsonify({
        "data": results,
        "token": extract_token(request)
    }), 200

@l7_bp.route('/acl_rule_apply', methods=['POST'])
@token_required
def acl_rule_apply():
    """Store ACL apply rules in Redis."""
    payload = request.get_json(silent=True) or {}
    data_str = payload.get("data")
    if not data_str:
        return jsonify({"status": "error", "message": "Missing 'data' field."}), 400

    items = None
    if isinstance(data_str, (list, tuple)):
        items = list(data_str)
    elif isinstance(data_str, str):
        try:
            parsed = json.loads(data_str)
            if isinstance(parsed, (list, tuple)):
                items = list(parsed)
            else:
                return jsonify({"status": "error", "message": "'data' JSON must be an array."}), 400
        except json.JSONDecodeError:
            return jsonify({"status": "error", "message": "Invalid JSON string in 'data' field."}), 400
    elif isinstance(data_str, (bytes, bytearray)):
        try:
            parsed = json.loads(data_str.decode("utf-8"))
            if isinstance(parsed, (list, tuple)):
                items = list(parsed)
            else:
                return jsonify({"status": "error", "message": "'data' JSON must be an array."}), 400
        except Exception:
            return jsonify({"status": "error", "message": "Invalid JSON bytes in 'data' field."}), 400
    else:
        return jsonify({"status": "error", "message": "Unsupported 'data' field type."}), 400

    if not items:
        return jsonify({"status": "error", "message": "Body must contain non-empty 'data' array."}), 400

    normalized = []
    seen_ids = set()

    for idx, it in enumerate(items, start=1):
        if not isinstance(it, dict):
            return jsonify({"status": "error", "message": f"Entry #{idx} must be an object."}), 400

        try:
            acl_id = int(it.get("id", None))
            if acl_id <= 0:
                raise ValueError()
        except Exception:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid 'id' (must be positive integer)."}), 400
        if acl_id in seen_ids:
            return jsonify({"status": "error", "message": f"Duplicate id in payload: {acl_id}"}), 400
        seen_ids.add(acl_id)

        status = str(it.get("status", "")).strip().lower()
        if status not in {"enabled", "disabled"}:
            return jsonify({"status": "error", "message": f"Entry #{idx}: 'status' must be 'enabled' or 'disabled'."}), 400
        
        cond = str(it.get("checking_cond", "")).strip().lower()
        if cond not in {"allow", "block"}:
            return jsonify({"status": "error", "message": f"Entry #{idx}: 'checking_cond' must be 'allow' or 'block'."}), 400

        code = str(it.get("apply_code", "")).strip().lower()
        if code not in {"allow", "block", "return_code", "redirect"}:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid 'apply_code'."}), 400

        content = it.get("apply_content", None)

        if code in {"allow", "block"}:
            if content not in (None, "", [], {}):
                return jsonify({"status": "error", "message": f"Entry #{idx}: 'apply_content' must be empty for '{code}'."}), 400
            action = {"kind": code}
        elif code == "return_code":
            try:
                rc = int(content)
                if not (100 <= rc <= 599):
                    raise ValueError()
            except Exception:
                return jsonify({"status": "error", "message": f"Entry #{idx}: 'apply_content' must be a valid HTTP status code (100..599)."}), 400
            action = {"kind": "return_code", "code": rc}
        else:  # redirect
            url = str(content or "").strip()
            if url and not validate_url(url):
                return jsonify({"status": "error", "message": f"Entry #{idx}: 'apply_content' must be a valid http(s) URL for 'redirect'."}), 400
            action = {"kind": "redirect", "url": url}

        normalized.append({
            "id": acl_id,
            "status": status,
            "cond": cond,
            "action": action
        })

    if not RedisClient.store_acl_apply_rules(normalized):
        return jsonify({"status": "error", "message": "Failed to write to Redis"}), 500

    return jsonify({
        "status": "success",
        "message": "acl_apply_rules stored in Redis and update published.",
        "count": len(normalized)
    }), 200

@l7_bp.route("/acl_rule_apply", methods=["GET"])
def acl_rule_apply_get():
    """Get ACL apply rules from Redis."""
    try:
        stored = RedisClient.get_acl_apply_rules()
        rules = []
        for r in stored:
            act = r.get("action", {})
            kind = act.get("kind")
            if kind == "allow":
                apply_code = "allow"
                apply_content = ""
            elif kind == "block":
                apply_code = "block"
                apply_content = ""
            elif kind == "return_code":
                apply_code = "return_code"
                apply_content = act.get("code", 451)
            elif kind == "redirect":
                apply_code = "redirect"
                apply_content = act.get("url", "")
            else:
                apply_code = "block"
                apply_content = ""
            rules.append({
                "id": r.get("id"),
                "status": r.get("status"),
                "checking_cond": r.get("cond", ""),
                "apply_code": apply_code,
                "apply_content": apply_content
            })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to read from Redis: {e}"}), 500

    return jsonify({
        "data": rules,
        "token": extract_token(request)
    }), 200
