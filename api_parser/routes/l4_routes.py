# routes/l4_routes.py
"""L4 firewall API routes."""
import csv
import os
import tempfile
from flask import Blueprint, request, jsonify, current_app
from core.firewall import firewall_control, set_protection, execute_cli_command
from core.database import DatabaseManager
from core.api_client import APIClient
from utils.auth import token_required
import config

l4_bp = Blueprint('l4', __name__, url_prefix='/API/L4')

_GEO_NAME_TO_ISO_CACHE = {}

def _normalize_status(value):
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, (int, float)):
        return "on" if value else "off"
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"on", "true", "1", "yes"}:
            return "on"
        if lowered in {"off", "false", "0", "no"}:
            return "off"
    raise ValueError(f"Invalid status value: {value}")

def _normalize_bool_int(value):
    return 1 if _normalize_status(value) == "on" else 0

def _update_firewall_config(updates):
    try:
        with open(config.FIREWALL_CONFIG_PATH, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return False, f"Config file not found at {config.FIREWALL_CONFIG_PATH}"
    except OSError as exc:
        return False, f"Failed to read config file: {exc}"

    found = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue

        key = stripped.split("=", 1)[0].strip()
        if key in updates and updates[key] is not None:
            new_lines.append(f"{key} = {updates[key]}\n")
            found.add(key)
        else:
            new_lines.append(line)

    missing = [key for key, value in updates.items() if value is not None and key not in found]
    if missing:
        new_lines.append("\n")
        for key in missing:
            new_lines.append(f"{key} = {updates[key]}\n")

    try:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
            tmp.writelines(new_lines)
            temp_path = tmp.name
        os.replace(temp_path, config.FIREWALL_CONFIG_PATH)
    except OSError as exc:
        return False, f"Failed to write config file: {exc}"

    return True, "Config updated"

def _resolve_geo_path(path_value):
    if not path_value:
        return None
    if os.path.isabs(path_value):
        return path_value
    return os.path.join(str(config.BASE_EBPF_FIREWALL_DIR), path_value)

def _load_geo_name_map(location_path):
    cached = _GEO_NAME_TO_ISO_CACHE.get(location_path)
    if cached is not None:
        return cached

    mapping = {}
    try:
        with open(location_path, "r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                name = (row.get("country_name") or "").strip().lower()
                iso = (row.get("country_iso_code") or "").strip().upper()
                if name and iso and name not in mapping:
                    mapping[name] = iso
    except (OSError, csv.Error):
        _GEO_NAME_TO_ISO_CACHE[location_path] = {}
        return {}

    _GEO_NAME_TO_ISO_CACHE[location_path] = mapping
    return mapping

def _normalize_geo(geo_value, location_path):
    if isinstance(geo_value, str):
        items = [item.strip() for item in geo_value.split(",") if item.strip()]
    elif isinstance(geo_value, list):
        items = [str(item).strip() for item in geo_value if str(item).strip()]
    else:
        raise ValueError("geo_value must be a list or string")

    if not items:
        return "", []

    resolved_path = _resolve_geo_path(location_path)
    name_map = _load_geo_name_map(resolved_path) if resolved_path else {}

    converted = []
    unknown = []
    for item in items:
        if len(item) == 2 and item.isalpha():
            converted.append(item.upper())
            continue
        iso = name_map.get(item.lower())
        if iso:
            converted.append(iso)
        else:
            unknown.append(item)

    return ",".join(converted), unknown

def _read_firewall_config():
    try:
        with open(config.FIREWALL_CONFIG_PATH, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return False, f"Config file not found at {config.FIREWALL_CONFIG_PATH}"
    except OSError as exc:
        return False, f"Failed to read config file: {exc}"

    config = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        config[key.strip()] = value.strip()

    return True, config

def _list_interfaces():
    try:
        interfaces = [name for name in os.listdir("/sys/class/net") if name]
    except OSError:
        return []
    return [name for name in interfaces if name != "lo"]

def _attach_modes_for_interface(interface):
    modes = ["skb", "native"]
    if os.path.exists(f"/sys/class/net/{interface}/xdp"):
        modes.extend(["drv", "hw"])
    return modes

@l4_bp.route('/firewall_main', methods=['POST'])
@token_required
def firewall_main():
    """Control L4 firewall."""
    data = request.json
    
    if 'status' not in data:
        return jsonify({"status": "error", "message": "Missing 'status' parameter"}), 400
    
    action = data['status'].lower()
    interface = data.get('interface')
    if not interface:
        return jsonify({"status": "error", "message": "Interface parameter is required"}), 400
    
    attach_mode = data.get('attach_mode', 'native')
    
    # Initialize database and fetch lists for start/restart
    if action in ['start', 'restart']:
        DatabaseManager.init_database()  # Ensure tables exist first
        DatabaseManager.clear_all_tables()  # Then clear them
        
        token = data['token']
        
        # Fetch and store blocklist
        success, result = APIClient.fetch_blocklist(token)
        if not success:
            return jsonify({
                "status": "error",
                "message": f"Firewall {action} failed during blocklist processing",
                "details": str(result)
            }), 500
        
        success, msg = DatabaseManager.store_blocklist(result)
        if not success:
            return jsonify({
                "status": "error",
                "message": f"Firewall {action} failed during blocklist storage",
                "details": msg
            }), 500
        
        # Fetch and store whitelist
        success, result = APIClient.fetch_whitelist(token)
        if not success:
            return jsonify({
                "status": "error",
                "message": f"Firewall {action} failed during whitelist processing",
                "details": str(result)
            }), 500
        
        success, msg = DatabaseManager.store_whitelist(result)
        if not success:
            return jsonify({
                "status": "error",
                "message": f"Firewall {action} failed during whitelist storage",
                "details": msg
            }), 500
    
    # Execute firewall command
    result = firewall_control(action, interface, attach_mode)
    
    if result['status'] == 'error':
        return jsonify({
            "status": "error",
            "action": action,
            "message": result['message']
        }), 400
    
    response = {
        "status": "success",
        "action": action,
        "message": result['message'],
        "interface": interface,
        "attach_mode": attach_mode
    }
    
    if action in ['start', 'restart']:
        blockcount, whitecount = DatabaseManager.get_counts()
        response['blocklist_loaded'] = True
        response['blocklist_count'] = blockcount
        response['whitelist_loaded'] = True
        response['whitelist_count'] = whitecount
    
    return jsonify(response)

@l4_bp.route('/tcp_syn', methods=['POST'])
@token_required
def tcp_syn():
    """TCP SYN protection."""
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter', 
                      'fixed_threshold', 'fixed_duration', 'challenge_timeout', 'protection_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    try:
        challenge_timeout = int(data['challenge_timeout']) if data.get('challenge_timeout') is not None else 3
        
        result = set_protection(
            'TCP_SYN',
            data['status'],
            int(data['threshold']),
            int(data['burst_pkt']),
            int(data['burst_counter']),
            int(data['fixed_threshold']),
            int(data['fixed_duration']),
            int(data['protection_duration']),
            challenge_timeout
        )
    except (ValueError, TypeError) as e:
        return jsonify({"status": "error", "message": f"Invalid parameter type: {str(e)}"}), 400
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/tcp_ack', methods=['POST'])
@token_required
def tcp_ack():
    """TCP ACK protection."""
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    try:
        result = set_protection(
            'TCP_ACK',
            data['status'],
            int(data['threshold']),
            int(data['burst_pkt']),
            int(data['burst_counter']),
            int(data['fixed_threshold']),
            int(data['fixed_duration']),
            int(data['protection_duration'])
        )
    except (ValueError, TypeError) as e:
        return jsonify({"status": "error", "message": f"Invalid parameter type: {str(e)}"}), 400
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/tcp_rst', methods=['POST'])
@token_required
def tcp_rst():
    """TCP RST protection."""
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    try:
        result = set_protection(
            'TCP_RST',
            data['status'],
            int(data['threshold']),
            int(data['burst_pkt']),
            int(data['burst_counter']),
            int(data['fixed_threshold']),
            int(data['fixed_duration']),
            int(data['protection_duration'])
        )
    except (ValueError, TypeError) as e:
        return jsonify({"status": "error", "message": f"Invalid parameter type: {str(e)}"}), 400
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/icmp', methods=['POST'])
@token_required
def icmp():
    """ICMP protection."""
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    try:
        result = set_protection(
            'ICMP',
            data['status'],
            int(data['threshold']),
            int(data['burst_pkt']),
            int(data['burst_counter']),
            int(data['fixed_threshold']),
            int(data['fixed_duration']),
            int(data['protection_duration'])
        )
    except (ValueError, TypeError) as e:
        return jsonify({"status": "error", "message": f"Invalid parameter type: {str(e)}"}), 400
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/udp', methods=['POST'])
@token_required
def udp():
    """UDP protection."""
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    try:
        result = set_protection(
            'UDP',
            data['status'],
            int(data['threshold']),
            int(data['burst_pkt']),
            int(data['burst_counter']),
            int(data['fixed_threshold']),
            int(data['fixed_duration']),
            int(data['protection_duration'])
        )
    except (ValueError, TypeError) as e:
        return jsonify({"status": "error", "message": f"Invalid parameter type: {str(e)}"}), 400
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/gre', methods=['POST'])
@token_required
def gre():
    """GRE protection."""
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    try:
        result = set_protection(
            'GRE',
            data['status'],
            int(data['threshold']),
            int(data['burst_pkt']),
            int(data['burst_counter']),
            int(data['fixed_threshold']),
            int(data['fixed_duration']),
            int(data['protection_duration'])
        )
    except (ValueError, TypeError) as e:
        return jsonify({"status": "error", "message": f"Invalid parameter type: {str(e)}"}), 400
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/tcp_seg', methods=['POST'])
@token_required
def tcp_seg():
    """TCP segment check."""
    data = request.json
    if 'status' not in data:
        return jsonify({"status": "error", "message": "Missing 'status' parameter"}), 400
    
    command_args = ['l4_firewall_cli', 'SET_TCP_SEG', data['status']]
    result = execute_cli_command(command_args)
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/tcp_geo', methods=['POST'])
@token_required
def tcp_geo():
    """Geo location filtering."""
    data = request.json
    if 'status' not in data:
        return jsonify({"status": "error", "message": "Missing 'status' parameter"}), 400
    
    command_args = ['l4_firewall_cli', 'SET_GEO', data['status']]
    
    if 'geo' in data:
        config_ok, current_config = _read_firewall_config()
        if not config_ok:
            return jsonify({"status": "error", "message": current_config}), 500
        geo_value, unknown_geo = _normalize_geo(
            data['geo'],
            current_config.get("geo_db_location_path")
        )
        if unknown_geo:
            return jsonify({
                "status": "error",
                "message": f"Unknown country names: {', '.join(unknown_geo)}"
            }), 400
        command_args.extend([geo_value])
    
    result = execute_cli_command(command_args)
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/tcp_con_limit', methods=['POST'])
@token_required
def tcp_connection_limit():
    """TCP connection limit."""
    data = request.json
    if 'status' not in data:
        return jsonify({"status": "error", "message": "Missing 'status' parameter"}), 400
    
    command_args = ['l4_firewall_cli', 'SET_CONN_LIMIT', data['status']]
    
    if 'limit_cnt' in data:
        command_args.extend([str(data['limit_cnt'])])
    
    result = execute_cli_command(command_args)
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/add_block_ip', methods=['POST'])
@token_required
def add_block_ip():
    """Add IP to blocklist."""
    data = request.json
    if 'ip' not in data:
        return jsonify({"status": "error", "message": "Missing 'ip' parameter"}), 400
    
    command_args = ['l4_firewall_cli', 'ADD_BLOCK_IP', data['ip'], '-1']
    
    if 'duration' in data:
        command_args.extend([str(data['duration'])])
    
    result = execute_cli_command(command_args)
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/remove_block_ip', methods=['POST'])
@token_required
def remove_block_ip():
    """Remove IP from blocklist."""
    data = request.json
    if 'ip' not in data:
        return jsonify({"status": "error", "message": "Missing 'ip' parameter"}), 400
    
    command_args = ['l4_firewall_cli', 'CLEAR_BLOCK_IP', data['ip']]
    result = execute_cli_command(command_args)
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/remove_block_ip_all', methods=['POST'])
@token_required
def remove_block_ip_all():
    """Remove all IPs from blocklist."""
    command_args = ['l4_firewall_cli', 'CLEAR_BLOCK_IP_ALL']
    result = execute_cli_command(command_args)
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/add_white_ip', methods=['POST'])
@token_required
def add_white_ip():
    """Add IP to whitelist."""
    data = request.json
    if 'ip' not in data:
        return jsonify({"status": "error", "message": "Missing 'ip' parameter"}), 400
    
    command_args = ['l4_firewall_cli', 'ADD_ALLOW_IP', data['ip']]
    result = execute_cli_command(command_args)
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/remove_white_ip', methods=['POST'])
@token_required
def remove_white_ip():
    """Remove IP from whitelist."""
    data = request.json
    if 'ip' not in data:
        return jsonify({"status": "error", "message": "Missing 'ip' parameter"}), 400
    
    command_args = ['l4_firewall_cli', 'CLEAR_ALLOW_IP', data['ip']]
    result = execute_cli_command(command_args)
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/remove_white_ip_all', methods=['POST'])
@token_required
def remove_white_ip_all():
    """Remove all IPs from whitelist."""
    command_args = ['l4_firewall_cli', 'CLEAR_ALLOW_IP_ALL']
    result = execute_cli_command(command_args)
    
    if result['status'] == 'error':
        return jsonify({"status": "error", "message": result['message']}), 400
    
    return jsonify({"status": "success", "message": result['message']})

@l4_bp.route('/get_blocklist', methods=['POST'])
@token_required
def get_blocklist():
    """Get blocklist with optional filters."""
    data = request.get_json(force=True) or {}
    
    filter_type = data.get("filter_type", "x")
    filter_ip = data.get("filter_ip", "x")
    filter_date = data.get("filter_date", "x")
    
    try:
        rows = DatabaseManager.get_blocklist(filter_type, filter_ip, filter_date)
        return jsonify({"status": "success", "data": rows})
    except Exception as ex:
        return jsonify({"status": "error", "message": f"DB error: {ex}"}), 500

@l4_bp.route('/options', methods=['POST'])
@token_required
def l4_options():
    interfaces = _list_interfaces()
    attach_modes = {
        iface: _attach_modes_for_interface(iface)
        for iface in interfaces
    }
    return jsonify({
        "interfaces": interfaces,
        "attachModesByInterface": attach_modes
    })

@l4_bp.route('/l4_firewall_data', methods=['POST'])
@token_required
def l4_firewall_data():
    data = request.get_json(force=True) or {}
    current_app.logger.info("l4_firewall_data payload: %s", data)

    required_fields = [
        "dev", "attachMode", "blackIpDuration",
        "synValid", "synThreshold", "synBurstPkt", "synBurstCountPerSec",
        "synFixedThreshold", "synFixedCheckDuration", "challengeTimeout", "synProtectionDuration",
        "ackValid", "ackThreshold", "ackBurstPkt", "ackBurstCountPerSec",
        "ackFixedThreshold", "ackFixedCheckDuration", "ackProtectionDuration",
        "rstValid", "rstThreshold", "rstBurstPkt", "rstBurstCountPerSec",
        "rstFixedThreshold", "rstFixedCheckDuration", "rstProtectionDuration",
        "icmpValid", "icmpThreshold", "icmpBurstPkt", "icmpBurstCountPerSec",
        "icmpFixedThreshold", "icmpFixedCheckDuration", "icmpProtectionDuration",
        "udpValid", "udpThreshold", "udpBurstPkt", "udpBurstCountPerSec",
        "udpFixedThreshold", "udpFixedCheckDuration", "udpProtectionDuration",
        "greValid", "greThreshold", "greBurstPkt", "greBurstCountPerSec",
        "greFixedThreshold", "greFixedCheckDuration", "greProtectionDuration",
        "tcpSegCheck", "geoCheck", "geoDbIpv4Path", "geoDbLocationPath",
        "geoAllowCountries", "geoCountriesBlockMode", "tcpConnectionLimitCheck", "tcpConnectionLimitCnt",
    ]

    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({
            "status": "error",
            "message": f"Missing required fields: {', '.join(missing_fields)}"
        }), 400

    try:
        geo_value, unknown_geo = _normalize_geo(
            data["geoAllowCountries"],
            data["geoDbLocationPath"]
        )
        if unknown_geo:
            return jsonify({
                "status": "error",
                "message": f"Unknown country names: {', '.join(unknown_geo)}"
            }), 400

        updates = {
            "dev": data["dev"],
            "attach_mode": data["attachMode"],
            "black_ip_duration": int(data["blackIpDuration"]),
            "syn_valid": _normalize_bool_int(data["synValid"]),
            "syn_threshold": int(data["synThreshold"]),
            "syn_burst_pkt": int(data["synBurstPkt"]),
            "syn_burst_count_per_sec": int(data["synBurstCountPerSec"]),
            "syn_fixed_threshold": int(data["synFixedThreshold"]),
            "syn_fixed_check_duration": int(data["synFixedCheckDuration"]),
            "challenge_timeout": int(data["challengeTimeout"]),
            "syn_protection_duration": int(data["synProtectionDuration"]),
            "ack_valid": _normalize_bool_int(data["ackValid"]),
            "ack_threshold": int(data["ackThreshold"]),
            "ack_burst_pkt": int(data["ackBurstPkt"]),
            "ack_burst_count_per_sec": int(data["ackBurstCountPerSec"]),
            "ack_fixed_threshold": int(data["ackFixedThreshold"]),
            "ack_fixed_check_duration": int(data["ackFixedCheckDuration"]),
            "ack_protection_duration": int(data["ackProtectionDuration"]),
            "rst_valid": _normalize_bool_int(data["rstValid"]),
            "rst_threshold": int(data["rstThreshold"]),
            "rst_burst_pkt": int(data["rstBurstPkt"]),
            "rst_burst_count_per_sec": int(data["rstBurstCountPerSec"]),
            "rst_fixed_threshold": int(data["rstFixedThreshold"]),
            "rst_fixed_check_duration": int(data["rstFixedCheckDuration"]),
            "rst_protection_duration": int(data["rstProtectionDuration"]),
            "icmp_valid": _normalize_bool_int(data["icmpValid"]),
            "icmp_threshold": int(data["icmpThreshold"]),
            "icmp_burst_pkt": int(data["icmpBurstPkt"]),
            "icmp_burst_count_per_sec": int(data["icmpBurstCountPerSec"]),
            "icmp_fixed_threshold": int(data["icmpFixedThreshold"]),
            "icmp_fixed_check_duration": int(data["icmpFixedCheckDuration"]),
            "icmp_protection_duration": int(data["icmpProtectionDuration"]),
            "udp_valid": _normalize_bool_int(data["udpValid"]),
            "udp_threshold": int(data["udpThreshold"]),
            "udp_burst_pkt": int(data["udpBurstPkt"]),
            "udp_burst_count_per_sec": int(data["udpBurstCountPerSec"]),
            "udp_fixed_threshold": int(data["udpFixedThreshold"]),
            "udp_fixed_check_duration": int(data["udpFixedCheckDuration"]),
            "udp_protection_duration": int(data["udpProtectionDuration"]),
            "gre_valid": _normalize_bool_int(data["greValid"]),
            "gre_threshold": int(data["greThreshold"]),
            "gre_burst_pkt": int(data["greBurstPkt"]),
            "gre_burst_count_per_sec": int(data["greBurstCountPerSec"]),
            "gre_fixed_threshold": int(data["greFixedThreshold"]),
            "gre_fixed_check_duration": int(data["greFixedCheckDuration"]),
            "gre_protection_duration": int(data["greProtectionDuration"]),
            "tcp_seg_check": _normalize_bool_int(data["tcpSegCheck"]),
            "geo_check": _normalize_bool_int(data["geoCheck"]),
            "geo_countries_block_mode": _normalize_bool_int(data["geoCountriesBlockMode"]),
            "geo_db_ipv4_path": data["geoDbIpv4Path"],
            "geo_db_location_path": data["geoDbLocationPath"],
            "geo_countries": geo_value,
            "tcp_connection_limit_check": _normalize_bool_int(data["tcpConnectionLimitCheck"]),
            "tcp_connection_limit_cnt": int(data["tcpConnectionLimitCnt"]),
        }
    except (ValueError, TypeError) as exc:
        return jsonify({"status": "error", "message": f"Invalid parameter type: {exc}"}), 400

    config_ok, current_config = _read_firewall_config()
    if not config_ok:
        return jsonify({"status": "error", "message": current_config}), 500

    changed_updates = {}
    for key, value in updates.items():
        new_value = str(value)
        if current_config.get(key) != new_value:
            changed_updates[key] = value

    if changed_updates:
        config_ok, config_msg = _update_firewall_config(changed_updates)
        if not config_ok:
            return jsonify({"status": "error", "message": config_msg}), 500

    results = {}

    syn_changed = any(key.startswith("syn_") or key == "challenge_timeout" for key in changed_updates)
    ack_changed = any(key.startswith("ack_") for key in changed_updates)
    rst_changed = any(key.startswith("rst_") for key in changed_updates)
    icmp_changed = any(key.startswith("icmp_") for key in changed_updates)
    udp_changed = any(key.startswith("udp_") for key in changed_updates)
    gre_changed = any(key.startswith("gre_") for key in changed_updates)
    tcp_seg_changed = "tcp_seg_check" in changed_updates
    geo_runtime_changed = any(
        key in changed_updates for key in {"geo_check", "geo_countries", "geo_countries_block_mode"}
    )
    conn_limit_changed = any(
        key in changed_updates for key in {"tcp_connection_limit_check", "tcp_connection_limit_cnt"}
    )
    restart_required = any(key in changed_updates for key in {"dev", "attach_mode"})

    if syn_changed:
        results["tcp_syn"] = set_protection(
            "TCP_SYN",
            _normalize_status(data["synValid"]),
            int(data["synThreshold"]),
            int(data["synBurstPkt"]),
            int(data["synBurstCountPerSec"]),
            int(data["synFixedThreshold"]),
            int(data["synFixedCheckDuration"]),
            int(data["synProtectionDuration"]),
            int(data["challengeTimeout"]),
        )
    if ack_changed:
        results["tcp_ack"] = set_protection(
            "TCP_ACK",
            _normalize_status(data["ackValid"]),
            int(data["ackThreshold"]),
            int(data["ackBurstPkt"]),
            int(data["ackBurstCountPerSec"]),
            int(data["ackFixedThreshold"]),
            int(data["ackFixedCheckDuration"]),
            int(data["ackProtectionDuration"]),
        )
    if rst_changed:
        results["tcp_rst"] = set_protection(
            "TCP_RST",
            _normalize_status(data["rstValid"]),
            int(data["rstThreshold"]),
            int(data["rstBurstPkt"]),
            int(data["rstBurstCountPerSec"]),
            int(data["rstFixedThreshold"]),
            int(data["rstFixedCheckDuration"]),
            int(data["rstProtectionDuration"]),
        )
    if icmp_changed:
        results["icmp"] = set_protection(
            "ICMP",
            _normalize_status(data["icmpValid"]),
            int(data["icmpThreshold"]),
            int(data["icmpBurstPkt"]),
            int(data["icmpBurstCountPerSec"]),
            int(data["icmpFixedThreshold"]),
            int(data["icmpFixedCheckDuration"]),
            int(data["icmpProtectionDuration"]),
        )
    if udp_changed:
        results["udp"] = set_protection(
            "UDP",
            _normalize_status(data["udpValid"]),
            int(data["udpThreshold"]),
            int(data["udpBurstPkt"]),
            int(data["udpBurstCountPerSec"]),
            int(data["udpFixedThreshold"]),
            int(data["udpFixedCheckDuration"]),
            int(data["udpProtectionDuration"]),
        )
    if gre_changed:
        results["gre"] = set_protection(
            "GRE",
            _normalize_status(data["greValid"]),
            int(data["greThreshold"]),
            int(data["greBurstPkt"]),
            int(data["greBurstCountPerSec"]),
            int(data["greFixedThreshold"]),
            int(data["greFixedCheckDuration"]),
            int(data["greProtectionDuration"]),
        )

    if tcp_seg_changed:
        results["tcp_seg"] = execute_cli_command(
            ["l4_firewall_cli", "SET_TCP_SEG", _normalize_status(data["tcpSegCheck"])]
        )
    if geo_runtime_changed:
        if _normalize_status(data["geoCheck"]) == "on":     # geo check is on
            if _normalize_status(data["geoCountriesBlockMode"]) == "on": # geo countries block mode is on
                results["tcp_geo"] = execute_cli_command(
                    ["l4_firewall_cli", "SET_GEO", "block", geo_value]
                )
            else: # geo countries block mode is off
                results["tcp_geo"] = execute_cli_command(
                    ["l4_firewall_cli", "SET_GEO", "allow", geo_value]
                )
        else: # geo check is off
            results["tcp_geo"] = execute_cli_command(
                ["l4_firewall_cli", "SET_GEO", "off", ""]
            )
    if conn_limit_changed:
        results["tcp_connection_limit"] = execute_cli_command(
            ["l4_firewall_cli", "SET_CONN_LIMIT", _normalize_status(data["tcpConnectionLimitCheck"]),
             str(int(data["tcpConnectionLimitCnt"]))],
        )
    if restart_required:
        results["firewall_restart"] = firewall_control(
            "restart",
            data["dev"],
            data["attachMode"]
        )

    failures = {key: val for key, val in results.items() if val.get("status") == "error"}
    if failures:
        return jsonify({
            "status": "error",
            "message": "Config updated, but one or more commands failed",
            "config_updated": bool(changed_updates),
            "failures": failures
        }), 400

    return jsonify({
        "status": "success",
        "message": "L4 firewall config applied",
        "config_updated": bool(changed_updates),
        "changes": list(changed_updates.keys()),
        "details": results
    })

