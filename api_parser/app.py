from flask import Flask, request, jsonify
from functools import wraps
import subprocess

app = Flask(__name__)

# Configuration
VALID_TOKENS = {"l13dbUeIow4YgWNRrA2v1aOuujIbDA2p"}  # Set your valid tokens here
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5000

# Helper decorator for token authentication
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.json.get('token')
        if token not in VALID_TOKENS:
            return jsonify({"status": "error", "message": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated_function

def parse_cli_output(output):
    """Parse the CLI output into status and message"""
    lines = output.strip().split('\n')
    if not lines:
        return {'status': 'error', 'message': 'Empty response from command'}
    
    if lines[0] == 'ok' and len(lines) > 1 and lines[1] == 'success':
        return {'status': 'success', 'message': 'Operation completed successfully'}
    elif lines[0] == 'failed' and len(lines) > 1:
        return {'status': 'error', 'message': '\n'.join(lines[1:])}
    else:
        return {'status': 'error', 'message': 'Unexpected response format'}

def execute_cli_command(command_args):
    try:
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            check=False
        )
        
        output = result.stdout.strip()
        return parse_cli_output(output)
    except subprocess.TimeoutExpired:
        return {'status': 'error', 'message': 'Command timed out'}
    except Exception as e:
        return {'status': 'error', 'message': f'Unexpected error: {str(e)}'}

# Firewall Main Control
@app.route('/API/L4/firewall_main', methods=['POST'])
@token_required
def firewall_main():
    data = request.json
    
    if 'status' not in data:
        return jsonify({"status": "error", "message": "Missing 'status' parameter"}), 400
    
    action = data['status'].lower()
    actions = {
        'start': 'START_FW',
        'stop': 'STOP_FW',
        'restart': 'RESTART_FW',
        'reload': 'RELOAD_FW'
    }
    
    if action not in actions:
        return jsonify({"status": "error", "message": "Invalid action. Valid actions: start, stop, restart, reload"}), 400
    
    interface = data.get('interface')
    if not interface:
        return jsonify({"status": "error", "message": "Interface parameter is required"}), 400
    
    attach_mode = data.get('attach_mode', 'native')
    command_args = ['l4_firewall_cli', actions[action], interface, attach_mode]
    
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({
            "status": "error",
            "action": action,
            "command": ' '.join(command_args),
            "message": parsed['message'],
            "output": parsed.get('output', '')
        }), 400
    
    return jsonify({
        "status": "success",
        "action": action,
        "command": ' '.join(command_args),
        "message": parsed['message'],
        "interface": interface,
        "attach_mode": attach_mode
    })

# TCP SYN Protection
@app.route('/API/L4/tcp_syn', methods=['POST'])
@token_required
def tcp_syn():
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter', 
                      'fixed_threshold', 'fixed_duration', 'challenge_timeout']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    command_args = [
        'l4_firewall_cli', 'TCP_SYN',  data['status'], str(data['threshold']), str(data['burst_pkt']), str(data['burst_counter']), str(data['fixed_threshold']),
        str(data['fixed_duration']), str(data['challenge_timeout'])
    ]
    
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# TCP ACK Protection
@app.route('/API/L4/tcp_ack', methods=['POST'])
@token_required
def tcp_ack():
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    command_args = [
        'l4_firewall_cli', 'TCP_ACK',
        data['status'], str(data['threshold']), str(data['burst_pkt']), str(data['burst_counter']), str(data['fixed_threshold']), str(data['fixed_duration'])
    ]
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# TCP RST Protection
@app.route('/API/L4/tcp_rst', methods=['POST'])
@token_required
def tcp_rst():
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    command_args = [
        'l4_firewall_cli', 'TCP_RST',
        data['status'], str(data['threshold']), str(data['burst_pkt']), str(data['burst_counter']), str(data['fixed_threshold']), str(data['fixed_duration'])
    ]
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# ICMP Protection
@app.route('/API/L4/icmp', methods=['POST'])
@token_required
def icmp():
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    command_args = [
        'l4_firewall_cli', 'ICMP',
        data['status'],
        str(data['threshold']),
        str(data['burst_pkt']),
        str(data['burst_counter']),
        str(data['fixed_threshold']),
        str(data['fixed_duration'])
    ]
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# UDP Protection
@app.route('/API/L4/udp', methods=['POST'])
@token_required
def udp():
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    command_args = [
        'l4_firewall_cli', 'UDP',
        data['status'],
        str(data['threshold']),
        str(data['burst_pkt']),
        str(data['burst_counter']),
        str(data['fixed_threshold']),
        str(data['fixed_duration'])
    ]
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})


# GRE Protection
@app.route('/API/L4/gre', methods=['POST'])
@token_required
def gre():
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter',
                      'fixed_threshold', 'fixed_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    command_args = [
        'l4_firewall_cli', 'GRE',
        data['status'],
        str(data['threshold']),
        str(data['burst_pkt']),
        str(data['burst_counter']),
        str(data['fixed_threshold']),
        str(data['fixed_duration'])
    ]
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# TCP Segment Check
@app.route('/API/L4/tcp_seg', methods=['POST'])
@token_required
def tcp_seg():
    data = request.json
    if 'status' not in data:
        return jsonify({"status": "error", "message": "Missing 'status' parameter"}), 400
    
    print (data)
    command_args = ['l4_firewall_cli', 'SET_TCP_SEG', data['status']]
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# Geo Location Filtering
@app.route('/API/L4/tcp_geo', methods=['POST'])
@token_required
def tcp_geo():
    data = request.json
    if 'status' not in data:
        return jsonify({"status": "error", "message": "Missing 'status' parameter"}), 400
    
    print (data)
    command_args = ['l4_firewall_cli', 'SET_GEO', data['status']]
    
    if 'geo' in data:
        command_args.extend([data['geo']])
    
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# TCP Connection Limit
@app.route('/API/L4/tcp_con_limit', methods=['POST'])
@token_required
def tcp_connection_limit():
    data = request.json
    if 'status' not in data:
        return jsonify({"status": "error", "message": "Missing 'status' parameter"}), 400
    
    print (data)
    
    command_args = ['l4_firewall_cli', 'SET_CONN_LIMIT', data['status']]
    
    if 'limit_cnt' in data:
        command_args.extend([str(data['limit_cnt'])])
    
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# IP Blocking Management
@app.route('/API/L4/add_block_ip', methods=['POST'])
@token_required
def add_block_ip():
    data = request.json
    if 'ip' not in data:
        return jsonify({"status": "error", "message": "Missing 'ip' parameter"}), 400
    
    print (data)
    
    command_args = ['l4_firewall_cli', 'BLOCK_IP', '--ip', data['ip']]
    
    if 'duration' in data:
        command_args.extend(['--duration', str(data['duration'])])
    
    print (command_args)
    
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

@app.route('/API/L4/remove_block_ip', methods=['POST'])
@token_required
def remove_block_ip():
    data = request.json
    if 'ip' not in data:
        return jsonify({"status": "error", "message": "Missing 'ip' parameter"}), 400
    
    print (data)
    command_args = ['l4_firewall_cli', 'UNBLOCK_IP', '--ip', data['ip']]
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

@app.route('/API/L4/remove_block_ip_all', methods=['POST'])
@token_required
def remove_block_ip_all():
    command_args = ['l4_firewall_cli', 'CLEAR_BLOCKED_IPS']
    
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# IP Whitelisting Management
@app.route('/API/L4/add_white_ip', methods=['POST'])
@token_required
def add_white_ip():
    data = request.json
    if 'ip' not in data:
        return jsonify({"status": "error", "message": "Missing 'ip' parameter"}), 400
    
    command_args = ['l4_firewall_cli', 'WHITELIST_IP', '--ip', data['ip']]
    
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

@app.route('/API/L4/remove_white_ip', methods=['POST'])
@token_required
def remove_white_ip():
    data = request.json
    if 'ip' not in data:
        return jsonify({"status": "error", "message": "Missing 'ip' parameter"}), 400
    
    command_args = ['l4_firewall_cli', 'UNWHITELIST_IP', '--ip', data['ip']]
    
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

if __name__ == '__main__':
    app.run(host=SERVER_IP, port=SERVER_PORT, debug=True)