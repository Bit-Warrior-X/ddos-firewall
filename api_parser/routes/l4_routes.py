# routes/l4_routes.py
"""L4 firewall API routes."""
from flask import Blueprint, request, jsonify
from core.firewall import firewall_control, set_protection, execute_cli_command
from core.database import DatabaseManager
from core.api_client import APIClient
from utils.auth import token_required

l4_bp = Blueprint('l4', __name__, url_prefix='/API/L4')

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
        command_args.extend([data['geo']])
    
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

