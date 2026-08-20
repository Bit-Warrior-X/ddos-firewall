# routes/l7_routes.py
"""L7 firewall API routes (Redis-backed rule sync and nginx listening-port updates)."""
import base64
import binascii
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
from flask import Blueprint, request, jsonify

import config
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
      Deny/Block  -> 3
      Drop+Block  -> 4
    """
    b = (behavior or "").strip().lower()
    mapping = {
        "allow": 1,
        "drop": 2,
        "deny": 3,
        "block": 3,
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
    if m == "prefix":
        return "prefix"
    # default
    return "equals"


def _pick_field(obj: dict, *keys, default=None):
    """Return the first present key from obj (supports camelCase / snake_case aliases)."""
    for key in keys:
        if key in obj and obj[key] is not None:
            return obj[key]
    return default


def _json_object_or_error():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return None, (jsonify({"status": "error", "message": "Body must be JSON object."}), 400)
    return data, None


def _require_int_id(data, *keys):
    raw = _pick_field(data, *keys)
    label = keys[0]
    if raw is None:
        return None, (jsonify({"status": "error", "message": f"Missing '{label}'."}), 400)
    try:
        return int(raw), None
    except (TypeError, ValueError):
        return None, (jsonify({"status": "error", "message": f"Invalid '{label}' (must be integer)."}), 400)


def _require_list_field(data, *keys):
    raw = _pick_field(data, *keys, default=None)
    label = keys[0]
    if raw is None:
        return [], None
    if not isinstance(raw, list):
        return None, (jsonify({"status": "error", "message": f"Invalid '{label}' (must be array)."}), 400)
    return raw, None


def _is_rule_enabled(entry: dict) -> bool:
    """Treat missing status as enabled; skip explicit DISABLE."""
    status = str(entry.get("status") or "ENABLE").strip().upper()
    return status in ("ENABLE", "ENABLED", "1", "TRUE", "ON", "YES")


def _rule_id_or_index(entry: dict, idx: int) -> int:
    rule_id = entry.get("id")
    if rule_id is None:
        return idx + 1
    try:
        return int(rule_id)
    except (TypeError, ValueError):
        return idx + 1


def _build_anticc_rule_string(url: str, method: str, threshold, window) -> str:
    """Build ACL rule string for anti-CC rules (URI + method + request frequency)."""
    url = (url or "").strip()
    method = (method or "").strip()
    try:
        threshold = int(threshold)
    except (TypeError, ValueError):
        threshold = 0
    try:
        window = int(window)
    except (TypeError, ValueError):
        window = 0
    parts = []
    if url:
        parts.append(f'["URI Path","-","regex","{url}"]')
    if method and method != "*":
        parts.append(f'["RequestMethod","-","is in","{method}"]')
    if threshold > 0 and window > 0:
        freq_str = f"{threshold}times/{window}s"
        parts.append(f'["Request Frequency","-",">=","{freq_str}"]')
    return " \nAND \n".join(parts) if parts else ""


def _transform_site_whitelist(rules_in) -> list:
    redis_rules = []
    for idx, r in enumerate(rules_in or []):
        if not isinstance(r, dict) or not _is_rule_enabled(r):
            continue
        rule_id = _rule_id_or_index(r, idx)
        ips = _pick_field(r, "ips", default="") or ""
        url = _pick_field(r, "url", default="") or ""
        method = _pick_field(r, "method", default="") or ""
        redis_rules.append({
            "action": 1,
            "priority": rule_id,
            "rule": _build_whitelist_rule_string(ips, url, method),
        })
    return redis_rules


def _transform_site_blacklist(rules_in) -> list:
    redis_rules = []
    for idx, r in enumerate(rules_in or []):
        if not isinstance(r, dict) or not _is_rule_enabled(r):
            continue
        rule_id = _rule_id_or_index(r, idx)
        ips = _pick_field(r, "ips", default="") or ""
        url = _pick_field(r, "url", default="") or ""
        method = _pick_field(r, "method", default="") or ""
        behavior = _pick_field(r, "behavior", default="") or ""
        redis_rules.append({
            "action": _behavior_to_action(behavior),
            "priority": rule_id,
            "rule": _build_whitelist_rule_string(ips, url, method),
        })
    return redis_rules


def _transform_site_geo(rules_in) -> list:
    redis_rules = []
    for idx, r in enumerate(rules_in or []):
        if not isinstance(r, dict) or not _is_rule_enabled(r):
            continue
        rule_id = _rule_id_or_index(r, idx)
        url = _pick_field(r, "url", default="") or ""
        country = _pick_field(r, "country", default="") or ""
        behavior = _pick_field(r, "behavior", default="") or ""
        redis_rules.append({
            "action": _behavior_to_action(behavior),
            "priority": rule_id,
            "rule": _build_geo_rule_string(url, country),
        })
    return redis_rules


def _transform_site_anticc(rules_in) -> list:
    redis_rules = []
    for idx, r in enumerate(rules_in or []):
        if not isinstance(r, dict) or not _is_rule_enabled(r):
            continue
        rule_id = _rule_id_or_index(r, idx)
        url = _pick_field(r, "url", default="") or ""
        method = _pick_field(r, "method", default="") or ""
        threshold = _pick_field(r, "threshold", default=0)
        window = _pick_field(r, "window", default=0)
        behavior = _pick_field(r, "behavior", "action", default="") or ""
        redis_rules.append({
            "action": _behavior_to_action(behavior),
            "priority": rule_id,
            "rule": _build_anticc_rule_string(url, method, threshold, window),
        })
    return redis_rules


def _transform_site_antiheader(rules_in) -> list:
    redis_rules = []
    for idx, r in enumerate(rules_in or []):
        if not isinstance(r, dict) or not _is_rule_enabled(r):
            continue
        rule_id = _rule_id_or_index(r, idx)
        url = _pick_field(r, "url", default="") or ""
        header = _pick_field(r, "header", default="") or ""
        value = _pick_field(r, "value", default="") or ""
        block_mode = _pick_field(r, "blockMode", "block_mode", default="") or ""
        behavior = _pick_field(r, "behavior", default="") or ""
        redis_rules.append({
            "action": _behavior_to_action(behavior),
            "priority": rule_id,
            "rule": _build_antiheader_rule_string(url, header, value, block_mode),
        })
    return redis_rules


def _transform_site_intervalfreq(rules_in) -> list:
    redis_rules = []
    for idx, r in enumerate(rules_in or []):
        if not isinstance(r, dict) or not _is_rule_enabled(r):
            continue
        rule_id = _rule_id_or_index(r, idx)
        url = _pick_field(r, "url", default="") or ""
        time_sec = _pick_field(r, "time", default=0)
        req_count = _pick_field(r, "requestCount", "request_count", default=0)
        behavior = _pick_field(r, "behavior", default="") or ""
        redis_rules.append({
            "action": _behavior_to_action(behavior),
            "priority": rule_id,
            "rule": _build_intervalfreq_rule_string(url, req_count, time_sec),
        })
    return redis_rules


def _transform_site_secondfreq(rules_in) -> list:
    redis_rules = []
    for idx, r in enumerate(rules_in or []):
        if not isinstance(r, dict) or not _is_rule_enabled(r):
            continue
        rule_id = _rule_id_or_index(r, idx)
        url = _pick_field(r, "url", default="") or ""
        req_count = _pick_field(r, "requestCount", "request_count", default=0)
        burst = _pick_field(r, "burst", default=0)
        behavior = _pick_field(r, "behavior", default="") or ""
        redis_rules.append({
            "action": _behavior_to_action(behavior),
            "priority": rule_id,
            "rule": _build_secondfreq_rule_string(url, req_count, burst),
        })
    return redis_rules


def _transform_site_responsefreq(rules_in) -> list:
    redis_rules = []
    for idx, r in enumerate(rules_in or []):
        if not isinstance(r, dict) or not _is_rule_enabled(r):
            continue
        rule_id = _rule_id_or_index(r, idx)
        url = _pick_field(r, "url", default="") or ""
        response_code = _pick_field(r, "responseCode", "response_code", default="") or ""
        time_sec = _pick_field(r, "time", default=0)
        response_count = _pick_field(r, "responseCount", "response_count", default=0)
        behavior = _pick_field(r, "behavior", default="") or ""
        redis_rules.append({
            "action": _behavior_to_action(behavior),
            "priority": rule_id,
            "rule": _build_responsefreq_rule_string(url, response_code, response_count, time_sec),
        })
    return redis_rules


def _transform_site_useragent(rules_in) -> list:
    redis_rules = []
    for idx, r in enumerate(rules_in or []):
        if not isinstance(r, dict) or not _is_rule_enabled(r):
            continue
        rule_id = _rule_id_or_index(r, idx)
        url = _pick_field(r, "url", default="") or ""
        ua = _pick_field(r, "userAgent", "user_agent", default="") or ""
        match = _pick_field(r, "match", default="") or ""
        behavior = _pick_field(r, "behavior", default="") or ""
        redis_rules.append({
            "action": _behavior_to_action(behavior),
            "priority": rule_id,
            "rule": _build_useragent_rule_string(url, ua, match),
        })
    return redis_rules


def _transform_site_cache_rules(rules_in) -> list:
    redis_rules = []
    for entry in rules_in or []:
        if not isinstance(entry, dict) or not _is_rule_enabled(entry):
            continue

        rule_name = (entry.get("rule_name") or "").strip()
        if not rule_name:
            continue

        rule_type = str(entry.get("rule_type") or "file").strip().lower()
        if rule_type not in ("url", "file"):
            continue

        try:
            caching_time = int(entry.get("caching_time", 0))
        except (TypeError, ValueError):
            continue
        if caching_time <= 0:
            continue

        url = (entry.get("url") or "").strip()
        file_types = (entry.get("file_types") or "").strip()

        if rule_type == "url" and not url:
            continue
        if rule_type == "file" and not file_types:
            continue

        try:
            priority = int(entry.get("priority", 1000))
        except (TypeError, ValueError):
            priority = 1000

        redis_rules.append({
            "rule_name": rule_name,
            "rule_type": rule_type,
            "caching_time": caching_time,
            "url": url,
            "file_types": file_types,
            "priority": priority,
            "cache_slice": _parse_cache_slice_mb(entry.get("cache_slice", 0)),
            "without_parameter": _normalize_without_parameter(entry.get("without_parameter")),
            "cache_mode": _normalize_cache_mode(entry.get("cache_mode")),
        })
    return redis_rules


def _transform_site_listening_ports(ports_in, force_protocol: str = None) -> list:
    enabled_ports = []
    for entry in ports_in or []:
        if not isinstance(entry, dict) or not _is_rule_enabled(entry):
            continue
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        if port < 1 or port > 65535:
            continue
        protocol = force_protocol or _normalize_listening_protocol(entry.get("protocol"))
        description = (entry.get("description") or "").strip()
        port_entry = {
            "port": port,
            "protocol": protocol,
            "description": description,
        }
        if not any(p["port"] == port and p["protocol"] == protocol for p in enabled_ports):
            enabled_ports.append(port_entry)
    return enabled_ports


def _transform_site_listening_split(http_ports_in, https_ports_in) -> dict:
    """Normalize site HTTP/HTTPS port selections for listening:{site_id}."""
    return {
        "http_ports": _transform_site_listening_ports(http_ports_in, force_protocol="HTTP"),
        "https_ports": _transform_site_listening_ports(https_ports_in, force_protocol="HTTPS"),
    }


def _parse_site_listening_payload(data) -> tuple:
    """Parse http_ports/https_ports or legacy combined site_listening_port.

    Returns (payload_dict, error_response_or_None).
    """
    http_raw = _pick_field(data, "http_ports", "httpPorts")
    https_raw = _pick_field(data, "https_ports", "httpsPorts")
    if http_raw is not None or https_raw is not None:
        if http_raw is None:
            http_raw = []
        if https_raw is None:
            https_raw = []
        if not isinstance(http_raw, list):
            return None, (jsonify({"status": "error", "message": "Invalid 'http_ports' (must be array)."}), 400)
        if not isinstance(https_raw, list):
            return None, (jsonify({"status": "error", "message": "Invalid 'https_ports' (must be array)."}), 400)
        return _transform_site_listening_split(http_raw, https_raw), None

    combined = _pick_field(data, "site_listening_port", "site_listening_ports", "listeningports")
    if combined is None:
        combined = []
    if not isinstance(combined, list):
        return None, (jsonify({"status": "error", "message": "Invalid site listening ports (must be array)."}), 400)
    transformed = _transform_site_listening_ports(combined)
    return {
        "http_ports": [p for p in transformed if p["protocol"] == "HTTP"],
        "https_ports": [p for p in transformed if p["protocol"] == "HTTPS"],
    }, None


def _transform_site_upstreams(upstreams_in) -> list:
    redis_upstreams = []
    for u in upstreams_in or []:
        if not isinstance(u, dict):
            continue
        ip_port = (u.get("ip_port") or "").strip()
        if not ip_port:
            continue
        description = (u.get("description") or "").strip()
        redis_upstreams.append({
            "ip_port": ip_port,
            "description": description or "weight=1 max_fails=3 fail_timeout=30s",
        })
    return redis_upstreams


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
    """Receive whitelist from backend and store under waf:{siteId}:whitelist.

    Expected JSON: { serverId, siteId, serverIp, rules: [ { id, ips, url, method, description }, ... ] }
    """
    data, err = _json_object_or_error()
    if err:
        return err

    server_id, err = _require_int_id(data, "serverId", "server_id")
    if err:
        return err
    site_id, err = _require_int_id(data, "siteId", "site_id")
    if err:
        return err
    rules_in, err = _require_list_field(data, "rules")
    if err:
        return err

    redis_rules = _transform_site_whitelist(rules_in)
    ok, store_err = RedisClient.store_site_waf_rules(site_id, "whitelist", {
        "id": 1,
        "rules": redis_rules,
    })
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write whitelist to Redis.",
            "details": store_err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Whitelist updated in Redis.",
        "serverId": server_id,
        "siteId": site_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/l7_update_upstreamservers', methods=['POST'])
def l7_update_upstreamservers():
    """Receive upstream servers and store under upstreamservers:{siteId}.

    Expected JSON: { serverId, siteId, upstreams: [ { id, ip_port, description }, ... ] }
    """
    data, err = _json_object_or_error()
    if err:
        return err

    server_id, err = _require_int_id(data, "serverId", "server_id")
    if err:
        return err
    site_id, err = _require_int_id(data, "siteId", "site_id")
    if err:
        return err
    upstreams_in, err = _require_list_field(data, "upstreams", "upstream_servers")
    if err:
        return err

    redis_upstreams = _transform_site_upstreams(upstreams_in)
    ok, store_err = RedisClient.store_site_upstreamservers(site_id, redis_upstreams)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write upstream servers to Redis.",
            "details": store_err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Upstream servers updated in Redis.",
        "serverId": server_id,
        "siteId": site_id,
        "upstreamsCount": len(redis_upstreams)
    }), 200


def _normalize_cache_mode(mode: str) -> str:
    m = str(mode or "origin").strip().lower()
    if m == "force":
        return "force"
    return "origin"


def _normalize_without_parameter(value) -> str:
    v = str(value or "no").strip().lower()
    if v in ("yes", "true", "1"):
        return "yes"
    return "no"


def _parse_cache_slice_mb(value) -> float:
    """Parse cache_slice in megabytes (float), e.g. 1.06 = 1.06 MB."""
    if value is None or value == "":
        return 0.0
    try:
        cache_slice = float(value)
    except (TypeError, ValueError):
        return 0.0
    if cache_slice < 0:
        return 0.0
    return cache_slice


_CLEAR_CACHE_MATCH_TYPE_BY_ID = {
    1: "prefix_match",
    2: "exact_match",
    3: "advanced_match",
}
_CLEAR_CACHE_MATCH_TYPES = frozenset(_CLEAR_CACHE_MATCH_TYPE_BY_ID.values())
_CLEAR_CACHE_SCHEMES = ("http://", "https://")


def _normalize_clear_cache_match_type(match_type) -> tuple:
    """Resolve public match_type (1/2/3) to internal name. Returns (ok, public_value, internal_name_or_error)."""
    if match_type is None:
        return False, match_type, "match_type is required."

    if isinstance(match_type, bool):
        return False, match_type, "match_type must be 1 (prefix), 2 (exact), or 3 (advanced)."

    if isinstance(match_type, (int, float)):
        mt_id = int(match_type)
        if mt_id in _CLEAR_CACHE_MATCH_TYPE_BY_ID:
            return True, mt_id, _CLEAR_CACHE_MATCH_TYPE_BY_ID[mt_id]
        return False, match_type, "match_type must be 1 (prefix), 2 (exact), or 3 (advanced)."

    mt_raw = str(match_type).strip()
    if mt_raw.isdigit():
        mt_id = int(mt_raw)
        if mt_id in _CLEAR_CACHE_MATCH_TYPE_BY_ID:
            return True, mt_id, _CLEAR_CACHE_MATCH_TYPE_BY_ID[mt_id]
        return False, match_type, "match_type must be 1 (prefix), 2 (exact), or 3 (advanced)."

    mt = mt_raw.lower()
    if mt in _CLEAR_CACHE_MATCH_TYPES:
        for mt_id, mt_name in _CLEAR_CACHE_MATCH_TYPE_BY_ID.items():
            if mt_name == mt:
                return True, mt_id, mt
        return False, match_type, "match_type must be 1 (prefix), 2 (exact), or 3 (advanced)."

    return False, match_type, "match_type must be 1 (prefix), 2 (exact), or 3 (advanced)."


def _host_for_cache_key(parsed) -> str:
    host = parsed.hostname or ""
    if parsed.port and parsed.port not in (80, 443):
        return f"{host}:{parsed.port}"
    return host


def _validate_clear_cache_request(match_type_name: str, match_content: str) -> tuple:
    """Validate l7_clear_url_cache fields. Returns (ok, message_or_normalized_content)."""
    mt = match_type_name
    mc = str(match_content or "").strip()

    if not mc:
        return False, "match_content is required."

    if mt == "advanced_match":
        return True, mc

    lower_mc = mc.lower()
    if not lower_mc.startswith(_CLEAR_CACHE_SCHEMES):
        return False, "match_content must start with http:// or https://."

    if mt == "prefix_match" and not mc.endswith("/"):
        return False, "prefix_match match_content must end with / (e.g. https://www.cdnray.com/)."

    return True, mc


def _build_purge_pattern(match_type: str, match_content: str) -> str:
    """Convert a public URL match into an Athens/Redis cache-key glob pattern."""
    mt = match_type.strip().lower()
    mc = match_content.strip()

    if mt == "advanced_match":
        return mc

    parsed = urlparse(mc)
    host = _host_for_cache_key(parsed)
    path = parsed.path or "/"
    uri = path
    if parsed.query:
        uri += "?" + parsed.query

    base = f"{host}{uri}"
    if mt == "prefix_match":
        return f"{base}*"
    # exact_match: append * so slice cache keys (host/pathbytes=...) are included.
    return f"{base}*"


def _call_athens_cache_purge(purge_pattern: str) -> tuple:
    """Call Athens purge endpoint. Returns (ok, payload, http_status)."""
    purge_path = "/purge/" + quote(purge_pattern, safe="*/[]")
    purge_url = f"{config.L7_CACHE_PURGE_BASE}{purge_path}"

    try:
        resp = requests.get(purge_url, timeout=30)
    except requests.RequestException as exc:
        return False, {
            "status": "error",
            "message": "Failed to call Athens cache purge endpoint.",
            "details": str(exc),
            "purgePattern": purge_pattern,
            "purgeUrl": purge_url,
        }, 502

    purge_body = resp.text
    purge_json = None
    try:
        purge_json = resp.json()
    except ValueError:
        pass

    purge_response = purge_json if purge_json is not None else purge_body
    payload = {
        "purgePattern": purge_pattern,
        "purgeUrl": purge_url,
        "purgeStatusCode": resp.status_code,
        "purgeResponse": purge_response,
    }

    if resp.status_code >= 400:
        payload["status"] = "error"
        payload["message"] = "Athens cache purge request failed."
        return False, payload, 502

    return True, payload, 200


@l7_bp.route('/l7_clear_cache', methods=['POST'])
def l7_clear_cache():
    """Purge cached content for a site via Athens ngx_cache_purge on port 9000.

    Expected JSON:
      {
        "serverId": 1035,
        "siteId": 55
      }

    Looks up domain:{host} -> siteId and purges each host prefix. Does not
    purge other sites on this edge.
    """
    data, err = _json_object_or_error()
    if err:
        return err

    server_id, err = _require_int_id(data, "serverId", "server_id")
    if err:
        return err
    site_id, err = _require_int_id(data, "siteId", "site_id")
    if err:
        return err

    domains = RedisClient.get_domains_for_site(site_id)
    extra_domain = str(_pick_field(data, "domain", default="") or "").strip()
    if extra_domain and extra_domain not in domains:
        domains.append(extra_domain)
    if not domains:
        return jsonify({
            "status": "error",
            "message": "No domain mapping found for siteId; cannot purge site cache.",
            "serverId": server_id,
            "siteId": site_id,
        }), 400

    purge_results = []
    for domain in domains:
        ok, result, http_status = _call_athens_cache_purge(f"{domain}*")
        purge_results.append({
            "domain": domain,
            **result,
        })
        if not ok:
            result["serverId"] = server_id
            result["siteId"] = site_id
            result["domains"] = domains
            result["purgeResults"] = purge_results
            return jsonify(result), http_status

    return jsonify({
        "status": "success",
        "message": "Site cache entries purged.",
        "serverId": server_id,
        "siteId": site_id,
        "domains": domains,
        "purgeResults": purge_results,
    }), 200


@l7_bp.route('/l7_clear_url_cache', methods=['POST'])
def l7_clear_url_cache():
    """Purge cached content via Athens ngx_cache_purge on port 9000.

    Expected JSON:
      {
        "serverId": 1035,
        "siteId": 55,
        "match_type": 1,
        "match_content": "https://www.cdnray.com/"
      }

    match_type:
      - 1 (prefix): URL must start with http(s):// and end with /
      - 2 (exact): URL must start with http(s)://
      - 3 (advanced): any purge pattern string (glob or PCRE-style regex)
    """
    data, err = _json_object_or_error()
    if err:
        return err

    server_id, err = _require_int_id(data, "serverId", "server_id")
    if err:
        return err
    site_id, err = _require_int_id(data, "siteId", "site_id")
    if err:
        return err

    match_type_raw = data.get("match_type")
    match_content = data.get("match_content")
    ok, match_type, match_type_name = _normalize_clear_cache_match_type(match_type_raw)
    if not ok:
        return jsonify({"status": "error", "message": match_type_name}), 400

    ok, result = _validate_clear_cache_request(match_type_name, match_content)
    if not ok:
        return jsonify({"status": "error", "message": result}), 400

    match_content = result
    purge_pattern = _build_purge_pattern(match_type_name, match_content)

    ok, result, http_status = _call_athens_cache_purge(purge_pattern)
    if not ok:
        result["serverId"] = server_id
        result["siteId"] = site_id
        result["match_type"] = match_type
        result["match_content"] = match_content
        return jsonify(result), http_status

    return jsonify({
        "status": "success",
        "message": "Cache purge completed.",
        "serverId": server_id,
        "siteId": site_id,
        "match_type": match_type,
        "match_content": match_content,
        **result,
    }), 200


@l7_bp.route('/l7_update_cacherules', methods=['POST'])
def l7_update_cacherules():
    """Receive cache rules from backend and store under cache:{siteId}.

    Expected JSON:
      {
        "serverId": 1035,
        "siteId": 55,
        "cacherules": [ ... ]
      }

    Only entries with status ENABLE are stored. Lower priority value wins when
    multiple rules match (same convention as ACL rules).
    """
    data, err = _json_object_or_error()
    if err:
        return err

    server_id, err = _require_int_id(data, "serverId", "server_id")
    if err:
        return err
    site_id, err = _require_int_id(data, "siteId", "site_id")
    if err:
        return err
    rules_in, err = _require_list_field(data, "cacherules", "cache_rules")
    if err:
        return err

    redis_rules = _transform_site_cache_rules(rules_in)
    ok, store_err = RedisClient.store_site_cache(site_id, redis_rules)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write cache rules to Redis.",
            "details": store_err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Cache rules updated in Redis.",
        "serverId": server_id,
        "siteId": site_id,
        "cacherulesCount": len(redis_rules)
    }), 200


def _normalize_listening_protocol(protocol: str) -> str:
    p = str(protocol or "HTTP").strip().upper()
    if p in ("HTTPS", "SSL", "TLS"):
        return "HTTPS"
    return "HTTP"


def _listen_line(port: int, protocol: str) -> str:
    if protocol == "HTTPS":
        return f"listen {port} ssl reuseport;"
    return f"listen {port} reuseport;"


def _build_default_ports_conf(ports: list) -> str:
    lines = [
        _listen_line(entry["port"], entry["protocol"])
        for entry in sorted(ports, key=lambda x: (x["port"], x["protocol"]))
    ]
    return "\n".join(lines) + ("\n" if lines else "")


def _parse_default_ports_conf(content: str) -> list:
    ports = []
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
        ports.append({"port": port, "protocol": protocol})
    return sorted(ports, key=lambda x: (x["port"], x["protocol"]))


def _read_default_ports_conf() -> tuple:
    path = Path(config.L7_DEFAULT_PORTS_CONF)
    try:
        if not path.is_file():
            return "", None
        return path.read_text(encoding="utf-8"), None
    except Exception as exc:
        return "", str(exc)


def _write_default_ports_conf(content: str) -> tuple:
    path = Path(config.L7_DEFAULT_PORTS_CONF)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return True, None
    except Exception as exc:
        return False, str(exc)


def _restart_l7_service() -> tuple:
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


@l7_bp.route('/l7_update_listeningports', methods=['POST'])
def l7_update_listeningports():
    """Server-scoped: replace nginx listen ports for this edge.

    Expected JSON:
      {
        "serverId": 1033,
        "listeningports": [
          {
            "id": 21,
            "serverId": 1033,
            "port": 80,
            "protocol": "HTTP",
            "description": "Public HTTP",
            "status": "ENABLE"
          }
        ]
      }

    Persists the full list under Redis key 'listeningports', writes ENABLE
    entries to server_default_ports.conf, and restarts athens when listen
    directives change. Does not take site_id (see l7_update_site_listeningports).
    """
    from core.listening_ports import apply_enabled_ports, normalize_api_ports

    data, err = _json_object_or_error()
    if err:
        return err

    server_id, err = _require_int_id(data, "serverId", "server_id")
    if err:
        return err
    listeningports_in, err = _require_list_field(data, "listeningports")
    if err:
        return err

    redis_entries, enabled_ports = normalize_api_ports(listeningports_in)
    if not enabled_ports:
        return jsonify({
            "status": "error",
            "message": "No valid enabled listening ports provided."
        }), 400

    ok, store_err = RedisClient.store_edge_listeningports(redis_entries)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write listeningports to Redis.",
            "details": store_err or "Unknown error"
        }), 500

    ok, details = apply_enabled_ports(enabled_ports, restart=True)
    if not ok:
        return jsonify({
            "status": "error",
            "serverId": server_id,
            **details,
        }), 500

    return jsonify({
        "status": "success",
        "serverId": server_id,
        "redisCount": len(redis_entries),
        **details,
    }), 200


@l7_bp.route('/l7_update_site_listeningports', methods=['POST'])
def l7_update_site_listeningports():
    """Site-scoped: replace HTTP/HTTPS ports selected for one site.

    Expected JSON:
      {
        "server_id": 1033,
        "site_id": 55,
        "http_ports": [ { id, port, protocol, description, status }, ... ],
        "https_ports": [ { id, port, protocol, description, status }, ... ]
      }

    Stored under listening:{site_id} as { http_ports, https_ports }.
    """
    data, err = _json_object_or_error()
    if err:
        return err

    server_id, err = _require_int_id(data, "server_id", "serverId")
    if err:
        return err
    site_id, err = _require_int_id(data, "site_id", "siteId")
    if err:
        return err

    http_raw = _pick_field(data, "http_ports", "httpPorts")
    https_raw = _pick_field(data, "https_ports", "httpsPorts")
    if http_raw is None and https_raw is None:
        return jsonify({
            "status": "error",
            "message": "Missing 'http_ports' and 'https_ports'."
        }), 400
    if http_raw is None:
        http_raw = []
    if https_raw is None:
        https_raw = []
    if not isinstance(http_raw, list):
        return jsonify({"status": "error", "message": "Invalid 'http_ports' (must be array)."}), 400
    if not isinstance(https_raw, list):
        return jsonify({"status": "error", "message": "Invalid 'https_ports' (must be array)."}), 400

    payload = _transform_site_listening_split(http_raw, https_raw)
    ok, store_err = RedisClient.store_site_listening(site_id, payload)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write site listening ports to Redis.",
            "details": store_err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Site listening ports applied.",
        "server_id": server_id,
        "site_id": site_id,
        "httpPortsCount": len(payload["http_ports"]),
        "httpsPortsCount": len(payload["https_ports"]),
    }), 200


# Category -> MIME types for gzip_types. text/html is always compressed by nginx
# when gzip is on, so it is omitted from the gzip_types line to avoid a warning.
# application/json; charset=utf-8 cannot be expressed in gzip_types ('; ends the
# directive); application/json covers those responses.
_COMPRESS_MIME_TYPES = {
    "css": (
        "text/css",
        "application/css",
    ),
    "html": (
        "text/html",
        "application/xhtml+xml",
        "application/xml",
    ),
    "js": (
        "application/javascript",
        "application/ecmascript",
        "text/javascript",
    ),
    "audio": (
        "audio/wav",
        "audio/midi",
        "audio/vnd.wave",
        "audio/wave",
        "audio/3gpp",
    ),
    "font": (
        "application/x-font-ttf",
        "application/x-font-otf",
        "font/otf",
        "font/woff",
        "font/woff2",
    ),
    "applications": (
        "application/pdf",
        "application/java-archive",
        "application/octet-stream",
        "application/x-msdownload",
        "application/vnd.debian.binary-package",
        "application/mac-binhex40",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/postscript",
        "application/rtf",
        "application/vnd.ms-fontobject",
        "application/x-rpm",
        "text/plain",
        "application/json",
    ),
}
_COMPRESS_KEYS = ("css", "html", "js", "audio", "font", "applications")


def _normalize_compress_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "enable", "enabled")
    return False


def _normalize_compress_flags(compress_in) -> dict:
    flags = {key: False for key in _COMPRESS_KEYS}
    if not isinstance(compress_in, dict):
        return flags
    for key in _COMPRESS_KEYS:
        if key in compress_in:
            flags[key] = _normalize_compress_bool(compress_in.get(key))
    return flags


def _compress_marker_line(flags: dict) -> str:
    parts = [f"{key}={1 if flags.get(key) else 0}" for key in _COMPRESS_KEYS]
    return "# compress: " + " ".join(parts)


def _build_gzip_types(flags: dict) -> list:
    types = []
    seen = set()
    for key in _COMPRESS_KEYS:
        if not flags.get(key):
            continue
        for mime in _COMPRESS_MIME_TYPES[key]:
            # nginx always compresses text/html when gzip is on; listing it
            # explicitly only triggers a duplicate-type warning.
            if mime == "text/html":
                continue
            if mime in seen:
                continue
            seen.add(mime)
            types.append(mime)
    return types


def _build_gzip_conf(flags: dict) -> str:
    any_enabled = any(flags.get(key) for key in _COMPRESS_KEYS)
    lines = [
        "# Managed by angelos l7_update_compress. Do not edit by hand.",
        _compress_marker_line(flags),
    ]
    if not any_enabled:
        lines.append("gzip off;")
        return "\n".join(lines) + "\n"

    gzip_types = _build_gzip_types(flags)
    lines.extend([
        "gzip on;",
        "gzip_vary on;",
        "gzip_proxied any;",
        "gzip_comp_level 4;",
        "gzip_min_length 256;",
    ])
    if gzip_types:
        lines.append("gzip_types " + " ".join(gzip_types) + ";")
    lines.append('gzip_disable "msie6";')
    return "\n".join(lines) + "\n"


def _parse_compress_flags(content: str) -> dict:
    flags = {key: False for key in _COMPRESS_KEYS}
    for line in (content or "").splitlines():
        line = line.strip()
        if not line.startswith("# compress:"):
            continue
        body = line[len("# compress:"):].strip()
        for token in body.split():
            if "=" not in token:
                continue
            key, _, raw = token.partition("=")
            key = key.strip().lower()
            if key in flags:
                flags[key] = raw.strip() in ("1", "true", "yes", "on")
        return flags

    # Fallback for legacy inline gzip config without a marker comment.
    lowered = (content or "").lower()
    if re.search(r"^\s*gzip\s+off\s*;", content or "", re.IGNORECASE | re.MULTILINE):
        return flags
    if not re.search(r"^\s*gzip\s+on\s*;", content or "", re.IGNORECASE | re.MULTILINE):
        return flags

    types_match = re.search(r"gzip_types\s+([^;]+);", content or "", re.IGNORECASE)
    type_set = set()
    if types_match:
        type_set = {t.strip().lower() for t in types_match.group(1).split() if t.strip()}

    for key, mimes in _COMPRESS_MIME_TYPES.items():
        if key == "html":
            # gzip on implies text/html compression in nginx.
            flags["html"] = True
            continue
        flags[key] = any(mime.lower() in type_set for mime in mimes if mime != "text/html")
    return flags


def _read_gzip_conf() -> tuple:
    path = Path(config.L7_GZIP_CONF)
    try:
        if not path.is_file():
            return "", None
        return path.read_text(encoding="utf-8"), None
    except Exception as exc:
        return "", str(exc)


def _write_gzip_conf(content: str) -> tuple:
    path = Path(config.L7_GZIP_CONF)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return True, None
    except Exception as exc:
        return False, str(exc)


@l7_bp.route('/l7_update_compress', methods=['POST'])
def l7_update_compress():
    """Receive compression category flags and store under compress:{siteId}.

    Expected JSON:
      {
        "serverId": 42,
        "siteId": 55,
        "compress": {
          "css": true,
          "html": true,
          "js": true,
          "audio": false,
          "font": false,
          "applications": false
        }
      }
    """
    data, err = _json_object_or_error()
    if err:
        return err

    server_id, err = _require_int_id(data, "serverId", "server_id")
    if err:
        return err
    site_id, err = _require_int_id(data, "siteId", "site_id")
    if err:
        return err

    compress_in = _pick_field(data, "compress", "compress_settings")
    if compress_in is None:
        return jsonify({"status": "error", "message": "Missing 'compress'."}), 400
    if not isinstance(compress_in, dict):
        return jsonify({"status": "error", "message": "Invalid 'compress' (must be object)."}), 400

    flags = _normalize_compress_flags(compress_in)
    ok, store_err = RedisClient.store_site_compress(site_id, flags)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write compress settings to Redis.",
            "details": store_err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Compression settings updated in Redis.",
        "serverId": server_id,
        "siteId": site_id,
        "compress": flags
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
          "blocked_at": "2026-08-11T09:15:00Z",
          "ttl": 180,
          "trigger_rule": "intervalfreqlimit",
          "site_id": 55
        },
        ...
      ]
    }

    Behavior:
      - Delete all existing temporaryblacklist:* keys in Redis.
      - Store each entry as key temporaryblacklist:<ip>:<blocked_at>[:<site_id>]
        with JSON value including site_id so the block applies to that site.
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

    # Build a fast lookup for new entries by IP+blocked_at+site_id.
    new_index = set()
    for e in items:
        if not isinstance(e, dict):
            continue
        ip = (e.get("ip") or "").strip()
        blocked_at = RedisClient.parse_blocked_at(e.get("blocked_at"))
        site_id = RedisClient.parse_optional_site_id(
            e.get("site_id") if e.get("site_id") is not None else e.get("siteId")
        )
        if ip and blocked_at > 0:
            new_index.add((ip, str(blocked_at), site_id))

    # For any old entry that was L4 (trigger_rule == "l4ddos") and is not in new_index,
    # call sparta_cli CLEAR_BLOCK_IP <ip> to clear the L4 block.
    for key, obj in old_entries.items():
        try:
            trig = str(obj.get("trigger_rule", "")).strip().lower()
            ip = str(obj.get("ip", "")).strip()
            blocked_at = str(RedisClient.parse_blocked_at(obj.get("blocked_at")))
            site_id = RedisClient.parse_optional_site_id(
                obj.get("site_id") if obj.get("site_id") is not None else obj.get("siteId")
            )
            if trig == "l4ddos" and ip and blocked_at != "0" and (ip, blocked_at, site_id) not in new_index:
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


# WAF type id used in Redis payload { id, rules } — matches legacy global keys.
_SITE_WAF_TYPE_IDS = {
    "whitelist": 1,
    "blacklist": 2,
    "geo": 3,
    "antiheader": 4,
    "intervalfreqlimit": 5,
    "secondfreqlimit": 6,
    "responsefreq": 7,
    "useragent": 8,
    "anticc": 9,
}


def _update_site_waf_rules(rule_type: str, transform_fn, success_message: str):
    """Shared handler for site-scoped WAF rule updates."""
    data, err = _json_object_or_error()
    if err:
        return err

    server_id, err = _require_int_id(data, "serverId", "server_id")
    if err:
        return err
    site_id, err = _require_int_id(data, "siteId", "site_id")
    if err:
        return err
    rules_in, err = _require_list_field(data, "rules")
    if err:
        return err

    redis_rules = transform_fn(rules_in)
    ok, store_err = RedisClient.store_site_waf_rules(site_id, rule_type, {
        "id": _SITE_WAF_TYPE_IDS.get(rule_type, 0),
        "rules": redis_rules,
    })
    if not ok:
        return jsonify({
            "status": "error",
            "message": f"Failed to write waf:{site_id}:{rule_type} to Redis.",
            "details": store_err or "Unknown error"
        }), 500

    return jsonify({
        "status": "success",
        "message": success_message,
        "serverId": server_id,
        "siteId": site_id,
        "rulesCount": len(redis_rules)
    }), 200


@l7_bp.route('/l7_update_blacklist', methods=['POST'])
def l7_update_blacklist():
    """Receive blacklist from backend and store under waf:{siteId}:blacklist."""
    return _update_site_waf_rules(
        "blacklist",
        _transform_site_blacklist,
        "Blacklist updated in Redis.",
    )


@l7_bp.route('/l7_update_geo', methods=['POST'])
@l7_bp.route('/l7_update_geolocation', methods=['POST'])
def l7_update_geo():
    """Receive Geo rules from backend and store under waf:{siteId}:geo."""
    return _update_site_waf_rules(
        "geo",
        _transform_site_geo,
        "Geo rules updated in Redis.",
    )


@l7_bp.route('/l7_update_antiheader', methods=['POST'])
def l7_update_antiheader():
    """Receive anti-header rules and store under waf:{siteId}:antiheader."""
    return _update_site_waf_rules(
        "antiheader",
        _transform_site_antiheader,
        "Antiheader rules updated in Redis.",
    )


@l7_bp.route('/l7_update_useragent', methods=['POST'])
def l7_update_useragent():
    """Receive user-agent rules and store under waf:{siteId}:useragent."""
    return _update_site_waf_rules(
        "useragent",
        _transform_site_useragent,
        "Useragent rules updated in Redis.",
    )


@l7_bp.route('/l7_update_intervalfreqlimit', methods=['POST'])
def l7_update_intervalfreqlimit():
    """Receive interval frequency limit rules and store under waf:{siteId}:intervalfreqlimit."""
    return _update_site_waf_rules(
        "intervalfreqlimit",
        _transform_site_intervalfreq,
        "Interval frequency limit rules updated in Redis.",
    )


@l7_bp.route('/l7_update_secondfreqlimit', methods=['POST'])
def l7_update_secondfreqlimit():
    """Receive second frequency limit rules and store under waf:{siteId}:secondfreqlimit."""
    return _update_site_waf_rules(
        "secondfreqlimit",
        _transform_site_secondfreq,
        "Second frequency limit rules updated in Redis.",
    )


@l7_bp.route('/l7_update_responsefreq', methods=['POST'])
def l7_update_responsefreq():
    """Receive response frequency rules and store under waf:{siteId}:responsefreq."""
    return _update_site_waf_rules(
        "responsefreq",
        _transform_site_responsefreq,
        "Response frequency rules updated in Redis.",
    )


@l7_bp.route('/l7_update_site', methods=['POST'])
def l7_update_site():
    """Receive full per-site L7 configuration from Dorian and store in Redis.

    Expected JSON (L7SiteConfig):
      {
        "server_id": 1033,
        "site_id": 55,
        "domain": "www.example.com",
        "ssl": { ssl_type, ssl_cert, ssl_cert_key },  # ssl_type=none => HTTP-only
        "waf_rules": {
          "waf_rule_id": 42,
          "waf_whitelist": [...],
          "waf_blacklist": [...],
          "waf_geolocation": [...],
          "waf_anticc": [...],
          "waf_antiheader": [...],
          "waf_intervalfreqlimit": [...],
          "waf_secondfreqlimit": [...],
          "waf_responsefreq": [...],
          "waf_useragent": [...]
        },
        "compress_settings": { css, html, js, audio, font, applications },
        "cache_rules": [...],
        "http_ports": [...],
        "https_ports": [...],
        "upstream_servers": [...]
      }

    Redis keys written:
      domain:{domain}              -> site_id
      site:{site_id}:domain        -> domain
      ssl:{site_id}                -> { ssl_type, ssl_cert, ssl_cert_key, domain }
      waf:{site_id}:whitelist|blacklist|geo|anticc|antiheader|
           intervalfreqlimit|secondfreqlimit|responsefreq|useragent
      cache:{site_id}
      listening:{site_id}
      upstreamservers:{site_id}
      compress:{site_id}
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = _pick_field(data, "server_id", "serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'server_id'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'server_id' (must be integer)."}), 400

    site_id = _pick_field(data, "site_id", "siteId")
    if site_id is None:
        return jsonify({"status": "error", "message": "Missing 'site_id'."}), 400
    try:
        site_id = int(site_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'site_id' (must be integer)."}), 400

    domain = str(_pick_field(data, "domain", default="") or "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing 'domain'."}), 400

    ssl_in = data.get("ssl")
    if ssl_in is not None and not isinstance(ssl_in, dict):
        return jsonify({"status": "error", "message": "Invalid 'ssl' (must be object)."}), 400

    waf_rules = data.get("waf_rules")
    if waf_rules is None:
        waf_rules = {}
    if not isinstance(waf_rules, dict):
        return jsonify({"status": "error", "message": "Invalid 'waf_rules' (must be object)."}), 400

    cache_rules_in = data.get("cache_rules")
    if cache_rules_in is None:
        cache_rules_in = []
    if not isinstance(cache_rules_in, list):
        return jsonify({"status": "error", "message": "Invalid 'cache_rules' (must be array)."}), 400

    redis_listening, listen_err = _parse_site_listening_payload(data)
    if listen_err:
        return listen_err

    upstreams_in = data.get("upstream_servers")
    if upstreams_in is None:
        upstreams_in = []
    if not isinstance(upstreams_in, list):
        return jsonify({"status": "error", "message": "Invalid 'upstream_servers' (must be array)."}), 400

    compress_in = data.get("compress_settings")
    if compress_in is None:
        compress_in = {}
    if compress_in is not None and not isinstance(compress_in, dict):
        return jsonify({"status": "error", "message": "Invalid 'compress_settings' (must be object)."}), 400

    # --- Transform ---
    waf_payloads = {
        "whitelist": _transform_site_whitelist(waf_rules.get("waf_whitelist")),
        "blacklist": _transform_site_blacklist(waf_rules.get("waf_blacklist")),
        "geo": _transform_site_geo(waf_rules.get("waf_geolocation")),
        "anticc": _transform_site_anticc(waf_rules.get("waf_anticc")),
        "antiheader": _transform_site_antiheader(waf_rules.get("waf_antiheader")),
        "intervalfreqlimit": _transform_site_intervalfreq(waf_rules.get("waf_intervalfreqlimit")),
        "secondfreqlimit": _transform_site_secondfreq(waf_rules.get("waf_secondfreqlimit")),
        "responsefreq": _transform_site_responsefreq(waf_rules.get("waf_responsefreq")),
        "useragent": _transform_site_useragent(waf_rules.get("waf_useragent")),
    }
    redis_cache = _transform_site_cache_rules(cache_rules_in)
    redis_upstreams = _transform_site_upstreams(upstreams_in)
    redis_compress = _normalize_compress_flags(compress_in)

    # --- Store ---
    ok, err = RedisClient.store_site_domain(site_id, domain)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write domain mapping to Redis.",
            "details": err or "Unknown error",
        }), 500

    ssl_stored = False
    ssl_http_only = False
    if isinstance(ssl_in, dict):
        ssl_type = str(
            _pick_field(ssl_in, "ssl_type", "sslType", default="") or ""
        ).strip().lower()
        has_cert = bool(
            (ssl_in.get("ssl_cert") or ssl_in.get("sslCert"))
            and (ssl_in.get("ssl_cert_key") or ssl_in.get("sslCertKey") or ssl_in.get("ssl_key"))
        )
        if ssl_type == "none":
            # HTTP-only site: visitor↔edge must not use HTTPS for this hostname.
            ok, err = RedisClient.store_site_ssl(site_id, domain, {
                "ssl_type": "none",
                "ssl_cert": "",
                "ssl_cert_key": "",
            })
            if not ok:
                return jsonify({
                    "status": "error",
                    "message": "Failed to clear SSL certificate in Redis.",
                    "details": err or "Unknown error",
                }), 500
            ssl_http_only = True
            # Drop any HTTPS port selections for this site.
            redis_listening = {
                "http_ports": list(redis_listening.get("http_ports") or []),
                "https_ports": [],
            }
        elif has_cert:
            ok, err = RedisClient.store_site_ssl(site_id, domain, ssl_in)
            if not ok:
                return jsonify({
                    "status": "error",
                    "message": "Failed to write SSL certificate to Redis.",
                    "details": err or "Unknown error",
                }), 500
            ssl_stored = True

    waf_counts = {}
    for rule_type, rules in waf_payloads.items():
        payload = {
            "id": _SITE_WAF_TYPE_IDS.get(rule_type, 0),
            "rules": rules,
        }
        ok, err = RedisClient.store_site_waf_rules(site_id, rule_type, payload)
        if not ok:
            return jsonify({
                "status": "error",
                "message": f"Failed to write waf:{site_id}:{rule_type} to Redis.",
                "details": err or "Unknown error",
            }), 500
        waf_counts[rule_type] = len(rules)

    ok, err = RedisClient.store_site_cache(site_id, redis_cache)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write cache rules to Redis.",
            "details": err or "Unknown error",
        }), 500

    ok, err = RedisClient.store_site_listening(site_id, redis_listening)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write listening ports to Redis.",
            "details": err or "Unknown error",
        }), 500

    ok, err = RedisClient.store_site_upstreamservers(site_id, redis_upstreams)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write upstream servers to Redis.",
            "details": err or "Unknown error",
        }), 500

    ok, err = RedisClient.store_site_compress(site_id, redis_compress)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to write compress settings to Redis.",
            "details": err or "Unknown error",
        }), 500

    return jsonify({
        "status": "success",
        "message": "Site configuration applied.",
        "server_id": server_id,
        "site_id": site_id,
        "domain": domain,
        "sslStored": ssl_stored,
        "sslHttpOnly": ssl_http_only,
        "wafRulesCount": waf_counts,
        "cacheRulesCount": len(redis_cache),
        "httpPortsCount": len(redis_listening.get("http_ports", [])),
        "httpsPortsCount": len(redis_listening.get("https_ports", [])),
        "upstreamsCount": len(redis_upstreams),
    }), 200


@l7_bp.route('/l7_delete_site', methods=['POST'])
def l7_delete_site():
    """Remove a site's domain mapping and related L7 Redis configuration.

    Expected JSON (L7SiteDelete):
      {
        "server_id": 1033,
        "site_id": 55,
        "domain": "www.example.com"
      }

    Deletes:
      domain:{domain}
      site:{site_id}:domain
      ssl:{site_id}
      waf:{site_id}:* (whitelist, blacklist, geo, anticc, antiheader, ...)
      cache:{site_id}
      listening:{site_id}
      upstreamservers:{site_id}
      compress:{site_id}
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = _pick_field(data, "server_id", "serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'server_id'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'server_id' (must be integer)."}), 400

    site_id = _pick_field(data, "site_id", "siteId")
    if site_id is None:
        return jsonify({"status": "error", "message": "Missing 'site_id'."}), 400
    try:
        site_id = int(site_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'site_id' (must be integer)."}), 400

    domain = str(_pick_field(data, "domain", default="") or "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing 'domain'."}), 400

    ok, result = RedisClient.delete_site_config(site_id, domain)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to delete site configuration from Redis.",
            "details": result or "Unknown error",
        }), 500

    return jsonify({
        "status": "success",
        "message": "Site removed from edge.",
        "server_id": server_id,
        "site_id": site_id,
        "domain": domain,
        "deletedKeys": result,
    }), 200


@l7_bp.route('/l7_update_domain', methods=['POST'])
def l7_update_domain():
    """Rename a site domain on this edge (L7SiteDomainUpdate).

    Expected JSON:
      {
        "server_id": 1033,
        "site_id": 55,
        "old_domain": "old.example.com",
        "new_domain": "www.example.com"
      }

    Redis:
      SET domain:{new_domain} -> site_id
      DEL domain:{old_domain} (and any other domain:* mapping to this site_id)

    Called by Dorian before l7_update_site pushes full config for the new hostname.
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Body must be JSON object."}), 400

    server_id = _pick_field(data, "server_id", "serverId")
    if server_id is None:
        return jsonify({"status": "error", "message": "Missing 'server_id'."}), 400
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'server_id' (must be integer)."}), 400

    site_id = _pick_field(data, "site_id", "siteId")
    if site_id is None:
        return jsonify({"status": "error", "message": "Missing 'site_id'."}), 400
    try:
        site_id = int(site_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid 'site_id' (must be integer)."}), 400

    old_domain = str(_pick_field(data, "old_domain", "oldDomain", default="") or "").strip()
    if not old_domain:
        return jsonify({"status": "error", "message": "Missing 'old_domain'."}), 400

    new_domain = str(_pick_field(data, "new_domain", "newDomain", default="") or "").strip()
    if not new_domain:
        return jsonify({"status": "error", "message": "Missing 'new_domain'."}), 400

    ok, result = RedisClient.rename_site_domain(site_id, old_domain, new_domain)
    if not ok:
        return jsonify({
            "status": "error",
            "message": "Failed to rename site domain in Redis.",
            "details": result or "Unknown error",
        }), 500

    return jsonify({
        "status": "success",
        "message": "Site domain renamed on edge.",
        "server_id": server_id,
        "site_id": site_id,
        "old_domain": old_domain,
        "new_domain": new_domain,
        "newKey": result.get("newKey") if isinstance(result, dict) else None,
        "removedKeys": result.get("removedKeys") if isinstance(result, dict) else [],
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
