import requests
from flask import Flask, request, jsonify
from functools import wraps
import subprocess
import sqlite3

app = Flask(__name__)

# Configuration
VALID_TOKENS = {"l13dbUeIow4YgWNRrA2v1aOuujIbDA2p"}  # Set your valid tokens here
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5000
BLOCKLIST_API_URL = "https://login.dnscrxyz.com/api/l4/get_blocklist_ips"
WHITELIST_API_URL = "https://login.dnscrxyz.com/api/l4/get_whitelist_ips"
FIRWALL_DB_NAME = "/usr/local/share/ebpf_firewall/firewall_control.db"


def create_table():
    """Create SQLite database and table for blocklist if they don't exist"""
    conn = sqlite3.connect(FIRWALL_DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        type TEXT NOT NULL,
        duration INTEGER,
        reason TEXT,
        created TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS white_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        reason TEXT,
        created TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()
    
def fetch_and_store_blocklist(token):
    """Fetch blocklist from API and store in database"""
    headers = {'Content-Type': 'application/json'}
    data = {'token': token}
    conn = None
    
    try:
        # Make API request
        response = requests.post(BLOCKLIST_API_URL, headers=headers, json=data)
        response.raise_for_status()
        blocklist_data = response.json()
        
        # Connect to database
        conn = sqlite3.connect(FIRWALL_DB_NAME)
        cursor = conn.cursor()
        
        # Create table if not exists (added this for robustness)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT,
            type TEXT,
            duration INTEGER,
            reason TEXT,
            created TEXT,
            UNIQUE(ip, reason)
        )
        ''')
        
        # Clear existing entries
        cursor.execute('DELETE FROM blocked_ips')
        
        # Insert new entries
        for entry in blocklist_data:
            cursor.execute('''
            INSERT OR IGNORE INTO blocked_ips (ip, type, duration, reason, created)
            VALUES (?, ?, ?, ?, ?)
            ''', (
                entry.get('IP'),
                entry.get('TYPE'),
                entry.get('Duration', -1),  # Default to -1 (Permanent) if not specified
                entry.get('Reason', ''),
                entry.get('Created', '')
            ))
        
        conn.commit()
        return True, f"Successfully stored {len(blocklist_data)} blocked IPs"
    
    except requests.exceptions.RequestException as e:
        return False, f"API request failed: {str(e)}"
    except sqlite3.Error as e:
        return False, f"Database error: {str(e)}"
    except Exception as e:
        return False, f"Error processing blocklist: {str(e)}"
    finally:
        if conn is not None:
            conn.close()

def fetch_and_store_whitelist(token):
    """Fetch whitelist from API and store in database"""
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
    data = {'token': token}
    conn = None  # Initialize conn as None
    
    try:
        response = requests.post(WHITELIST_API_URL, headers=headers, json=data)
        response.raise_for_status()
        whitelist_data = response.json()
        
        conn = sqlite3.connect(FIRWALL_DB_NAME)
        cursor = conn.cursor()
        
        # Clear existing entries (optional - you might want to keep history)
        cursor.execute('DELETE FROM white_ips')
        
        for entry in whitelist_data:
            cursor.execute('''
            INSERT INTO white_ips (ip, reason, created)
            VALUES (?, ?, ?)
            ''', (
                entry.get('IP', ''),
                entry.get('Reason', ''),
                entry.get('Created', '')
            ))
        
        conn.commit()
        return True, f"Successfully stored {len(whitelist_data)} white IPs"
    except Exception as e:
        return False, f"Error processing whitelist: {str(e)}"
    finally:
        if conn is not None:  # Only close if connection was established
            conn.close()
                
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
    
    if lines[0] == 'ok' and len(lines) > 1:
        return {'status': 'success', 'message': '\n'.join(lines[1:])}
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
    
    # Initialize database and fetch blocklist for start/restart actions
    if action in ['start', 'restart']:
        create_table()
        user_token = data['token']
        success, message = fetch_and_store_blocklist(user_token)
        if not success:
            return jsonify({
                "status": "error",
                "message": f"Firewall {action} failed during blocklist processing",
                "details": message
            }), 500
        success, message = fetch_and_store_whitelist(user_token)
        if not success:
            return jsonify({
                "status": "error",
                "message": f"Firewall {action} failed during whitelist processing",
                "details": message
            }), 500
            
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({
            "status": "error",
            "action": action,
            "command": ' '.join(command_args),
            "message": parsed['message'],
            "output": parsed.get('output', '')
        }), 400
    
    response = {
        "status": "success",
        "action": action,
        "command": ' '.join(command_args),
        "message": parsed['message'],
        "interface": interface,
        "attach_mode": attach_mode
    }
        
    # Add blocklist/Whitelist info if this was a start/restart
    if action in ['start', 'restart']:
        conn = sqlite3.connect(FIRWALL_DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM blocked_ips')
        blockcount = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM white_ips')
        whitecount = cursor.fetchone()[0]
        conn.close()
        response['blocklist_loaded'] = True
        response['blocklist_count'] = blockcount
        response['whitelist_loaded'] = True
        response['whitelist_count'] = whitecount
        
    return jsonify(response)

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
    command_args = ['l4_firewall_cli', 'ADD_BLOCK_IP', data['ip']]
    
    if 'duration' in data:
        command_args.extend([str(data['duration'])])
    
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
    command_args = ['l4_firewall_cli', 'CLEAR_BLOCK_IP', data['ip']]
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
    print (data)
    command_args = ['l4_firewall_cli', 'ADD_ALLOW_IP', data['ip']]
    print (command_args)
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
    print (data)
    command_args = ['l4_firewall_cli', 'CLEAR_ALLOW_IP', data['ip']]
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

# get config
@app.route('/API/get_config', methods=['POST'])
@token_required
def get_config():
    config_path = '/usr/local/share/ebpf_firewall/firewall.config'
    
    try:
        # Read the config file
        with open(config_path, 'r') as f:
            config_content = f.read()
        
        return jsonify({
            "status": "success",
            "config": config_content
        })
    
    except FileNotFoundError:
        return jsonify({
            "status": "error",
            "message": f"Config file not found at {config_path}"
        }), 404
    
    except PermissionError:
        return jsonify({
            "status": "error",
            "message": f"Permission denied when accessing {config_path}"
        }), 403
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to read config file: {str(e)}"
        }), 500
        
@app.route('/API/health_check', methods=['POST'])
@token_required
def health_check():
    command_args = ['l4_firewall_cli', 'HEALTH_CHECK']
    print(command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']})
    
    return jsonify({"status": "success", "message": parsed['message']})
if __name__ == '__main__':
    app.run(host=SERVER_IP, port=SERVER_PORT, debug=True)
    
    
