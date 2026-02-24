# routes/l7_routes.py
"""L7 firewall API routes."""
import os
import base64
import binascii
import json
import subprocess
import ipaddress
from flask import Blueprint, request, jsonify
from urllib.parse import urlparse
import config
from utils.nginx_utils import (
    normalize_methods, replace_or_append, remove_backup,
    write_atomic, backup_path, file_to_base64
)
from core.nginx_ops import nginx_test, nginx_reload
from core.nginx_parser import (
    get_report_settings,
    parse_backend_list,
    parse_acl_system_config,
    parse_acl_switch,
    parse_set_ports,
)
from core.nginx import NginxConfigManager
from core.redis_client import RedisClient
from utils.auth import token_required, extract_token, get_token
from utils.validators import validate_url

l7_bp = Blueprint('l7', __name__, url_prefix='/API/L7')

_ACL_DEFAULT_STUB = """# Managed by /API/L7/acl_system_config
# DO NOT EDIT MANUALLY — CHANGES WILL BE OVERWRITTEN

# GeoIP database locations (keep/edit these paths as needed)
acl_geo_database_path /usr/local/openresty/nginx/lua/geoip2/city.mmdb;
acl_isp_database_path  /usr/local/openresty/nginx/lua/geoip2/isp.mmdb;

"""

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

@l7_bp.route('/allow_request_method', methods=['POST'])
@token_required
def allow_request_method():
    """Configure allowed HTTP request methods."""
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip().lower()
    method_field = data.get("method")
    block_duration = data.get("block_duration")
    
    if status not in {"on", "off"}:
        return jsonify({"status": "error", "message": "Invalid 'status'. Use 'on' or 'off'."}), 400
    
    methods_str, err = normalize_methods(method_field)
    if err:
        return jsonify({"status": "error", "message": err}), 400
    
    try:
        with open(config.CONFIG_HTTP_REPORT_IP_PATH, "r") as f:
            original = f.read()
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to read config: {e}"}), 400
    
    updated = replace_or_append(original, "report_module_check", f"{status};")
    updated = replace_or_append(updated, "report_available_methods", f"{methods_str};")
    updated = replace_or_append(updated, "report_block_duration", f"{block_duration};")
    
    success, msg = NginxConfigManager.update_config(config.CONFIG_HTTP_REPORT_IP_PATH, updated)
    if not success:
        return jsonify({"status": "error", "message": msg}), 400
    
    return jsonify({
        "status": "success",
        "message": "nginx configuration successfully updated for allow http request method and applied."
    }), 200

@l7_bp.route('/allow_request_method', methods=['GET'])
def allow_request_method_get():
    """Get current allowed request method settings."""
    try:
        status, methods, duration = get_report_settings(config.CONFIG_HTTP_REPORT_IP_PATH)
        token = extract_token(request)
        if token != get_token():
            return jsonify({"status": "error", "message": "Invalid token"}), 403
        
        method_str = ", ".join(methods) if methods else ""
        
        resp = {
            "status": status,
            "method": method_str,
            "block_duration": duration,
            "token": token
        }
        return jsonify(resp), 200
    except FileNotFoundError:
        return jsonify({"status": "error",
                        "message": f"Config not found: {config.CONFIG_HTTP_REPORT_IP_PATH}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@l7_bp.route('/backend_list', methods=['POST'])
@token_required
def update_backend_list():
    """Update backend server list."""
    payload = request.get_json(silent=True) or {}
    items = payload.get("data", payload if isinstance(payload, list) else None)
    if not isinstance(items, list) or not items:
        return jsonify({"status": "error", "message": "Body must contain non-empty 'data' array."}), 400

    servers = []
    seen = set()
    idx = 0
    
    for item in items:
        idx += 1
        if not isinstance(item, dict):
            return jsonify({"status": "error", "message": f"Entry #{idx} must be an object."}), 400

        name = str(item.get("name", "")).strip()
        ip_raw = str(item.get("ip", "")).strip()
        port = item.get("port")
        weight = item.get("weight", 1)

        try:
            ipaddress.ip_address(ip_raw)
        except Exception:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid IP '{ip_raw}'."}), 400

        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError()
        except Exception:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid port '{port}'."}), 400

        try:
            weight = int(weight)
            if weight <= 0:
                raise ValueError()
        except Exception:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid weight '{weight}' (must be positive integer)."}), 400

        key = (ip_raw, port)
        if key in seen:
            return jsonify({"status": "error", "message": f"Duplicate server '{ip_raw}:{port}' detected."}), 400
        seen.add(key)

        comment = f" # {name}" if name else ""
        servers.append(f"    server {ip_raw}:{port} weight={weight};{comment}")

    header = (
        "# THIS FILE IS MANAGED BY /API/L7/backend_list\n"
        "# DO NOT EDIT MANUALLY — CHANGES WILL BE OVERWRITTEN\n"
    )
    body = "upstream backend {\n" + "\n".join(servers) + "\n}\n"
    new_content = header + body

    success, msg = NginxConfigManager.update_config(config.CONFIG_BACKEND_LIST_PATH, new_content)
    if not success:
        return jsonify({"status": "error", "message": msg}), 400
    
    return jsonify({
        "status": "success",
        "message": "nginx configuration successfully updated for backend list and applied"
    }), 200

@l7_bp.route('/backend_list', methods=['GET'])
def backend_list_get():
    """Get current backend list."""
    try:
        data = parse_backend_list(config.CONFIG_BACKEND_LIST_PATH)
        return jsonify({
            "data": data,
            "token": extract_token(request)
        }), 200
    except FileNotFoundError:
        return jsonify({
            "status": "error",
            "message": f"Config not found: {config.CONFIG_BACKEND_LIST_PATH}"
        }), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@l7_bp.route('/acl_system_config', methods=['POST'])
@token_required
def acl_system_config():
    """Update ACL system configuration."""
    data = request.get_json(silent=True) or {}

    def pos_int(field):
        val = data.get(field, None)
        try:
            v = int(val)
            if v <= 0:
                raise ValueError()
            return v, None
        except Exception:
            return None, f"Invalid '{field}' (must be a positive integer)."

    rule_mb, err = pos_int("acl_rule_shm_size")
    if err: return jsonify({"status": "error", "message": err}), 400
    req_mb, err = pos_int("acl_req_shm_size")
    if err: return jsonify({"status": "error", "message": err}), 400
    rsp_mb, err = pos_int("acl_rsp_shm_size")
    if err: return jsonify({"status": "error", "message": err}), 400
    period_s, err = pos_int("acl_optimize_period")
    if err: return jsonify({"status": "error", "message": err}), 400

    try:
        if os.path.exists(config.CONFIG_HTTP_LUA_ACL_PATH):
            with open(config.CONFIG_HTTP_LUA_ACL_PATH, "r") as f:
                original = f.read()
        else:
            original = _ACL_DEFAULT_STUB
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to read config: {e}"}), 400

    updated = replace_or_append(original, "acl_rule_shm_size", f"{rule_mb}m;")
    updated = replace_or_append(updated, "acl_req_shm_size", f"{req_mb}m;")
    updated = replace_or_append(updated, "acl_rsp_shm_size", f"{rsp_mb}m;")
    updated = replace_or_append(updated, "acl_optimize_period", f"{period_s}s;")

    success, msg = NginxConfigManager.update_config(config.CONFIG_HTTP_LUA_ACL_PATH, updated)
    if not success:
        return jsonify({"status": "error", "message": msg}), 400
    
    return jsonify({
        "status": "success",
        "message": "ACL system config updated, nginx test passed, and reload signaled."
    }), 200

@l7_bp.route("/acl_system_config", methods=["GET"])
def acl_system_config_get():
    """Get ACL system configuration."""
    try:
        data = parse_acl_system_config(config.CONFIG_HTTP_LUA_ACL_PATH)
        data["token"] = extract_token(request)
        return jsonify(data), 200
    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": f"Config not found: {e}"}), 500
    except PermissionError as e:
        return jsonify({"status": "error", "message": f"Permission denied: {e}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@l7_bp.route('/ngx_base_config', methods=['POST'])
@token_required
def ngx_base_config():
    """Update base nginx configuration files."""
    payload = request.get_json(silent=True) or {}

    required = ["header", "http", "proxy"]
    missing = [k for k in required if k not in payload]
    if missing:
        return jsonify({"status": "error",
                        "message": f"Missing required field(s): {', '.join(missing)}"}), 400

    def decode_b64(name, s):
        if not isinstance(s, str):
            return None, f"Field '{name}' must be a base64-encoded string."
        try:
            raw = base64.b64decode(s.strip(), validate=True)
        except (binascii.Error, ValueError) as e:
            return None, f"Field '{name}' is not valid base64: {e}"
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None, f"Field '{name}' decoded bytes are not valid UTF-8 text."
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if not text.endswith("\n"):
            text += "\n"
        return text, None

    header_text, err = decode_b64("header", payload["header"])
    if err: return jsonify({"status": "error", "message": err}), 400
    http_text, err = decode_b64("http", payload["http"])
    if err: return jsonify({"status": "error", "message": err}), 400
    proxy_text, err = decode_b64("proxy", payload["proxy"])
    if err: return jsonify({"status": "error", "message": err}), 400

    targets = [
        (config.CONFIG_HEADER_CONF_PATH, header_text),
        (config.CONFIG_HTTP_BASE_HEADER_CONF_PATH, http_text),
        (config.CONFIG_LOCATION_PROXY_SETTING_CONF_PATH, proxy_text),
    ]

    success, msg = NginxConfigManager.update_multiple_configs(targets)
    if not success:
        return jsonify({"status": "error", "message": msg}), 400
    
    return jsonify({
        "status": "success",
        "message": "Base configs updated, nginx test passed, and reload signaled."
    }), 200

@l7_bp.route("/ngx_base_config", methods=["GET"])
def ngx_base_config_get():
    """Get base nginx configuration files."""
    try:
        payload = {
            "header": file_to_base64(config.CONFIG_HEADER_CONF_PATH),
            "http": file_to_base64(config.CONFIG_HTTP_BASE_HEADER_CONF_PATH),
            "proxy": file_to_base64(config.CONFIG_LOCATION_PROXY_SETTING_CONF_PATH),
            "token": extract_token(request),
        }
        return jsonify(payload), 200
    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": f"Config not found: {e}"}), 500
    except PermissionError as e:
        return jsonify({"status": "error", "message": f"Permission denied: {e}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@l7_bp.route('/set_acl', methods=['POST'])
@token_required
def set_acl():
    """Set ACL on/off."""
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip().lower()

    if status not in {"on", "off"}:
        return jsonify({
            "status": "error",
            "message": "Invalid 'status'. Use 'on' or 'off'."
        }), 400

    new_content = f"acl {status};\n"
    success, msg = NginxConfigManager.update_config(config.CONFIG_SERVER_ACL_PATH, new_content)
    if not success:
        return jsonify({"status": "error", "message": msg}), 400
    
    return jsonify({
        "status": "success",
        "message": f"ACL successfully set to '{status}' and nginx reloaded."
    }), 200

@l7_bp.route("/set_acl", methods=["GET"])
def set_acl_get():
    """Get ACL status."""
    try:
        status = parse_acl_switch(config.CONFIG_SERVER_ACL_PATH)
        return jsonify({
            "status": status,
            "token": extract_token(request)
        }), 200
    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": f"Config not found: {e}"}), 500
    except PermissionError as e:
        return jsonify({"status": "error", "message": f"Permission denied: {e}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


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
          "country": "US",
          "province": "CA",
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

    # Clear existing temporaryblacklist:* keys first
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
        
    try:
        rcli = RedisClient.get_client()
        orig_members = rcli.smembers("acl_rule_ids") or set()
        orig_ids = set()
        for m in orig_members:
            try:
                orig_ids.add(int(m) if isinstance(m, (int, str)) else int(m.decode()))
            except Exception:
                pass
        
        prepared_ids = {r['id'] for r in prepared}
        pipe = rcli.pipeline()
        for rule in prepared:
            key = f"acl_rule:{rule['id']}"
            value = json.dumps(rule, ensure_ascii=False, indent=2).replace('\\/', '/')
            pipe.set(key, value)
            pipe.sadd("acl_rule_ids", rule['id'])
            pipe.publish("acl:updates", f"acl_rule:{rule['id']}")
        pipe.execute()
        
        to_remove = sorted(list(orig_ids - prepared_ids))
        if to_remove:
            del_pipe = rcli.pipeline()
            for rid in to_remove:
                del_key = f"acl_rule:{rid}"
                del_pipe.delete(del_key)
                del_pipe.srem("acl_rule_ids", rid)
                del_pipe.publish("acl:updates", f"acl_rule_deleted:{rid}")
            del_pipe.execute()
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to write to Redis: {e}"}), 500

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

@l7_bp.route('/set_ports', methods=['POST'])
@token_required
def set_ports():
    """Set server ports."""
    payload = request.get_json(silent=True) or {}
    
    data_str = payload.get("set_ports")
    if not data_str:
        return jsonify({"status": "error", "message": f"data field is nothing"}), 403
    
    try:
        ports = [int(p.strip()) for p in data_str.split(',')]
    except ValueError:
        return jsonify({"status": "error", "message": "invalid port values"}), 403
    
    invalid_ports = [p for p in ports if p < 1 or p > 65535]
    if invalid_ports:
        return jsonify({"status": "error", "message": f"invalid ports: {invalid_ports}"}), 403
    
    new_content = "".join(f"listen {p};\n" for p in ports)
    
    success, msg = NginxConfigManager.update_config(config.CONFIG_SERVER_DEFAULT_PORTS_PATH, new_content)
    if not success:
        return jsonify({"status": "error", "message": msg}), 400

    return jsonify({
        "status": "success",
        "message": "Server ports are successfully updated."
    }), 200

@l7_bp.route("/set_ports", methods=["GET"])
def set_ports_get():
    """Get server ports."""
    try:
        ports = parse_set_ports(config.CONFIG_SERVER_DEFAULT_PORTS_PATH)
        return jsonify({
            "set_ports": ports,
            "token": extract_token(request)
        }), 200
    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": f"Config not found: {e}"}), 500
    except PermissionError as e:
        return jsonify({"status": "error", "message": f"Permission denied: {e}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

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
