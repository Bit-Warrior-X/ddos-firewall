import os
import requests
import subprocess
import sqlite3
import threading
import time
import base64
import shutil
import ipaddress
import binascii
import urllib.request
import urllib.error
import sys
import socket
import tempfile
import shlex
import signal
import time
import json
import redis

from flask import Flask, request, jsonify
from functools import wraps
from collections import defaultdict
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse

from l7_nginx_config import (
    CONFIG_HTTP_REPORT_IP_PATH,
    CONFIG_BACKEND_LIST_PATH,
    CONFIG_HTTP_LUA_ACL_PATH,
    CONFIG_HEADER_CONF_PATH,
    CONFIG_HTTP_BASE_HEADER_CONF_PATH,
    CONFIG_LOCATION_PROXY_SETTING_CONF_PATH,
    CONFIG_SERVER_ACL_PATH,
    CONFIG_SERVER_LUA_ACL_SET_PATH,
    CONFIG_LOCATION_LUA_ACL_CHECK_PATH,
    CONFIG_SERVER_DEFAULT_PORTS_PATH,
    normalize_methods, replace_or_append, remove_backup,
    write_atomic, backup_path, 
    nginx_test, nginx_reload,
    
    get_report_settings,
    parse_backend_list,
    file_to_base64,
    parse_acl_system_config,
    parse_acl_switch,
    parse_set_ports,
    parse_acl_rule_management,
    parse_acl_rule_apply
)


app = Flask(__name__)

# Configuration
FIFO_PATH = "/tmp/firewall_to_api_parser.fifo"
FIREWALL_DB_NAME = "/usr/local/share/ebpf_firewall/firewall_control.db"
INIT_FILE = "/usr/local/share/ebpf_firewall/initialize"
MACHINE_FILE = "/usr/local/share/ebpf_firewall/machine_id"
LICENSE_PATH = "/usr/local/share/ebpf_firewall/license.lic"
PUBKEY_PATH = "/usr/local/share/ebpf_firewall/server_public_key.pem"
TOKEN_FILE = "/usr/local/share/ebpf_firewall/token"

#VALID_TOKENS = {"l13dbUeIow4YgWNRrA2v1aOuujIbDA2p"}  # Set your valid tokens here
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5000
#BLOCKLIST_API_URL = "https://login.dnscrxyz.com/api/l4/get_blocklist_ips"
BLOCKLIST_API_URL = "https://fw.dnscrxyz.com/api/e36i5n8t9rgnhov8fe9b1f70oklt/blacklist"
#WHITELIST_API_URL = "https://login.dnscrxyz.com/api/l4/get_whitelist_ips"
WHITELIST_API_URL = "https://fw.dnscrxyz.com/api/e36i5n8t9rgnhov8fe9b1f70oklt/whitelist"
#REPORT_LOG_API_URL = "https://login.dnscrxyz.com/api/l4/report_log"
REPORT_LOG_API_URL = "https://fw.dnscrxyz.com/api/e36i5n8t9rgnhov8fe9b1f70oklt/report"
#CHECK_BLOCKLIST_API_URL = "https://login.dnscrxyz.com/api/l4/check_blocklist"
CHECK_BLOCKLIST_API_URL = "https://fw.dnscrxyz.com/api/e36i5n8t9rgnhov8fe9b1f70oklt/check_blacklist"

#BACKEND_DEPLOY_URL = "http://fw.dnscrxyz.com/api/deploy_done"
BACKEND_DEPLOY_URL = "https://fw.dnscrxyz.com/api/e36i5n8t9rgnhov8fe9b1f70oklt/deploy_done"
BACKEND_DEPLOY_COMPLETE_URL = "https://fw.dnscrxyz.com/api/e36i5n8t9rgnhov8fe9b1f70oklt/deploy_complete"

REDIS_SOCK = "/tmp/redis.sock"            # path to unix socket (no "unix:" prefix here)
REDIS_DB = 0
RULE_IDS_KEY = "acl_rule_ids"

def get_redis_client():
    # redis-py v3/v4 accepts unix_socket_path
    return redis.Redis(unix_socket_path=REDIS_SOCK, db=REDIS_DB, decode_responses=True)

user_token = {"l13dbUeIow4YgWNRrA2v1aOuujIbDA2p"}

def create_table():
    """Create SQLite database and table for blocklist if they don't exist"""
    conn = sqlite3.connect(FIREWALL_DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        type TEXT NOT NULL,
        duration INTEGER,
        reason TEXT,
        created DATETIME DEFAULT CURRENT_TIMESTAMP,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS white_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        reason TEXT,
        created DATETIME DEFAULT CURRENT_TIMESTAMP,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

def clear_all_tables():
    """Remove all rows from blocked_ips and white_ips tables."""
    conn = None
    try:
        conn = sqlite3.connect(FIREWALL_DB_NAME)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN ('blocked_ips', 'white_ips')
        """)
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        if not existing_tables:
            print("Warning: No firewall tables found in the database")
            return
        
        # Delete all records from existing tables
        if 'blocked_ips' in existing_tables:
            cursor.execute("DELETE FROM blocked_ips")
            print("Cleared blocked_ips table")
        else:
            print("Warning: blocked_ips table not found")
            
        if 'white_ips' in existing_tables:
            cursor.execute("DELETE FROM white_ips")
            print("Cleared white_ips table")
        else:
            print("Warning: white_ips table not found")
        
        # Reset AUTOINCREMENT counters if tables exist
        if 'blocked_ips' in existing_tables or 'white_ips' in existing_tables:
            cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('blocked_ips', 'white_ips')")
        
        conn.commit()
        print("Database cleared successfully")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        if conn:
            conn.rollback()
            
    except Exception as e:
        print(f"Unexpected error: {e}")
        if conn:
            conn.rollback()
            
    finally:
        if conn:
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
        conn = sqlite3.connect(FIREWALL_DB_NAME)
        cursor = conn.cursor()
        
        # Create table if not exists (added this for robustness)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            type TEXT NOT NULL,
            duration INTEGER,
            reason TEXT,
            created DATETIME,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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
        
        conn = sqlite3.connect(FIREWALL_DB_NAME)
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

def _pick_token() -> str:
    """Read API token from TOKEN_FILE."""
    try:
        with open(TOKEN_FILE, "r") as f:
            token = f.read().strip()
            if token:
                return token
    except Exception as e:
        print(f"[INIT] Failed to read token file {TOKEN_FILE}: {e}")
    return ""
                
# Helper decorator for token authentication
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.json.get('token')
        #if token not in VALID_TOKENS:
        if token != _pick_token():
            return jsonify({"status": "error", "message": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated_function

def parse_cli_output(output):
    """Parse CLI output where the first line is the status ('ok'/'failed')
    and everything from the second line to the end is the message."""
    lines = output.strip().splitlines()  # handles \n, \r\n, \r
    if not lines:
        return {'status': 'error', 'message': 'Empty response from command'}

    first = lines[0].strip().split(':', 1)[0].lower()  # tolerate "ok:" / "failed:"
    if first == 'ok':
        status = 'success'
    elif first == 'failed':
        status = 'error'
    else:
        return {'status': 'error', 'message': 'Unexpected response format'}

    message = '\n'.join(lines[1:]) if len(lines) > 1 else ''
    return {'status': status, 'message': message}

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
    print (data)
    if action not in actions:
        return jsonify({"status": "error", "message": "Invalid action. Valid actions: start, stop, restart, reload"}), 400
    
    interface = data.get('interface')
    if not interface:
        return jsonify({"status": "error", "message": "Interface parameter is required"}), 400
    
    attach_mode = data.get('attach_mode', 'native')
    command_args = ['l4_firewall_cli', actions[action], interface, attach_mode]
    print (command_args)
    # Initialize database and fetch blocklist for start/restart actions
    if action in ['start', 'restart']:
        clear_all_tables()
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
        conn = sqlite3.connect(FIREWALL_DB_NAME)
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

# Firewall Main Control
@app.route('/API/L7/firewall_main', methods=['POST'])
@token_required
def firewall_main_l7():
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request must be application/json"}), 400
    
    data = request.json
    status = data.get('status')
    
    if not status:
        return jsonif({"status": "error", "message": "Missing 'status' parameters"}), 400
    
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
            check=False
        )
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Command timed out'}), 504
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Unexpected error: {str(e)}'}), 400
    
    print (cmd)
    
    print (result.returncode)
    
    #if result.returncode != 0:
    #    return jsonify({"status": "error", "action": action, "message": "command failed"}), 500
    
    return jsonify({
        "status": "success",
        "action": action,
        "message": "success",
    }), 200

# TCP SYN Protection
@app.route('/API/L4/tcp_syn', methods=['POST'])
@token_required
def tcp_syn():
    data = request.json
    required_fields = ['status', 'threshold', 'burst_pkt', 'burst_counter', 
                      'fixed_threshold', 'fixed_duration', 'challenge_timeout', 'protection_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    command_args = [
        'l4_firewall_cli', 'TCP_SYN',  data['status'], str(data['threshold']), str(data['burst_pkt']), str(data['burst_counter']), str(data['fixed_threshold']),
        str(data['fixed_duration']), str(data['challenge_timeout']), str(data['protection_duration'])
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
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    command_args = [
        'l4_firewall_cli', 'TCP_ACK',
        data['status'], str(data['threshold']), str(data['burst_pkt']), str(data['burst_counter']), str(data['fixed_threshold']), str(data['fixed_duration']), str(data['protection_duration'])
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
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"Missing '{field}' parameter"}), 400
    
    command_args = [
        'l4_firewall_cli', 'TCP_RST',
        data['status'], str(data['threshold']), str(data['burst_pkt']), str(data['burst_counter']), str(data['fixed_threshold']), str(data['fixed_duration']), str(data['protection_duration'])
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
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
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
        str(data['fixed_duration']), 
        str(data['protection_duration'])
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
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
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
        str(data['fixed_duration']),
        str(data['protection_duration'])
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
                      'fixed_threshold', 'fixed_duration', 'protection_duration']
    
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
        str(data['fixed_duration']),
        str(data['protection_duration'])
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
    command_args = ['l4_firewall_cli', 'ADD_BLOCK_IP', data['ip'], '-1']
    
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
    command_args = ['l4_firewall_cli', 'CLEAR_BLOCK_IP_ALL']
     
    parsed = execute_cli_command(command_args)
    print (parsed)
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

@app.route('/API/L4/remove_white_ip_all', methods=['POST'])
@token_required
def remove_white_ip_all():
    data = request.json
    print (data)
    command_args = ['l4_firewall_cli', 'CLEAR_ALLOW_IP_ALL']
    print (command_args)
    parsed = execute_cli_command(command_args)
    if parsed['status'] == 'error':
        return jsonify({"status": "error", "message": parsed['message']}), 400
    
    return jsonify({"status": "success", "message": parsed['message']})

@app.route('/API/L7/allow_request_method', methods=['POST'])
@token_required
def allow_request_method():
    data = request.get_json(silent=True) or {}
    print (data)
    status = str(data.get("status", "")).strip().lower()
    method_field = data.get("method")
    block_duration = data.get("block_duration")
    
    if status not in {"on", "off"}:
        return jsonify({"status": "error", "message": "Invalid 'status'. Use 'on' or 'off'."}), 400
    
    methods_str, err = normalize_methods(method_field)
    if err:
        return jsonify({"status": "error", "message": err}), 400
    
    try:
        with open(CONFIG_HTTP_REPORT_IP_PATH, "r") as f:
            original = f.read()
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to read config: {e}"}), 400
    
    updated = replace_or_append(original, "report_module_check", f"{status};")
    updated = replace_or_append(updated, "report_available_methods", f"{methods_str};")
    updated = replace_or_append(updated, "report_block_duration", f"{block_duration};")
    
    backup = backup_path(CONFIG_HTTP_REPORT_IP_PATH)
    try:
        shutil.copy2(CONFIG_HTTP_REPORT_IP_PATH, backup)
        write_atomic(CONFIG_HTTP_REPORT_IP_PATH, updated)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to write new config: {e}"}), 400
    
    ok_test, test_msg = nginx_test()
    if not ok_test:
        # Roll back on test failure
        shutil.copy2(backup, CONFIG_HTTP_REPORT_IP_PATH)
        remove_backup(backup)
        return jsonify({
            "status": "error",
            "message": test_msg  # already trimmed (e.g., invalid method "AAA" in "report_available_methods")
        }), 400
        
    # Reload nginx AFTER successful test
    ok_reload, reload_msg = nginx_reload()
    if not ok_reload:
        # (Optional) You could roll back file here; behavior depends on your preference.
        # The running nginx keeps old config if reload fails, so leaving the file changed is usually OK.
        remove_backup(backup)
        return jsonify({
            "status": "error",
            "message": reload_msg  # trimmed message for reload failure
        }), 400

    remove_backup(backup)
    
    # All good
    return jsonify({
        "status": "success",
        "message": "nginx configuration successfully updated for allow http request method and applied."
    }), 200

def _extract_token(req) -> str:
    """Get token from Authorization: Bearer <token> or ?token=... (fallback)."""
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip()
    return req.args.get("token", "")  # GET fallback

@app.route('/API/L7/allow_request_method', methods=['GET'])
#@token_required
def allow_request_method_get():
    """
    GET /API/L7/allow_request_method  -> returns current settings:
      {
        "status": "on"|"off",
        "method": "GET, POST",
        "block_duration": 300,
        "token": "<received token>"
      }
    """
    try:
        status, methods, duration = get_report_settings(CONFIG_HTTP_REPORT_IP_PATH)
        token = _extract_token(request)
        if token != _pick_token():
            return jsonify({"status": "error", "message": "Invalid token"}), 403
        
        # Format methods exactly like you asked: "GET, POST"
        method_str = ", ".join(methods) if methods else ""

        resp = {
            "status": status,
            "method": method_str,
            "block_duration": duration,   # default as requested
            "token": token           # echo back the received token
        }
        return jsonify(resp), 200

    except FileNotFoundError:
        return jsonify({"status": "error",
                        "message": f"Config not found: {CONFIG_HTTP_REPORT_IP_PATH}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
     
@app.route('/API/L7/backend_list', methods=['POST'])
@token_required
def update_backend_list():
    """
    Accepts JSON like:
    {
      "data": [
        {"name": "backend1", "ip": "10.10.10.10", "port": 8080, "weight": 2},
        {"name": "backend2", "ip": "11.11.11.11", "port": 80,   "weight": 2}
      ]
    }
    """
    payload = request.get_json(silent=True) or {}
    print (payload)
    # Accept either {"data":[...]} or a raw list as the body, to be flexible.
    items = payload.get("data", payload if isinstance(payload, list) else None)
    if not isinstance(items, list) or not items:
        return jsonify({"status": "error", "message": "Body must contain non-empty 'data' array."}), 400

    # Validate and normalize entries
    servers = []
    seen = set()
    idx = 0
    
    for item in items:
        idx += 1
        if not isinstance(item, dict):
            return jsonify({"status": "error", "message": f"Entry #{idx} must be an object."}), 400

        name   = str(item.get("name", "")).strip()
        ip_raw = str(item.get("ip", "")).strip()
        port   = item.get("port")
        weight = item.get("weight", 1)

        # ip
        try:
            ipaddress.ip_address(ip_raw)
        except Exception:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid IP '{ip_raw}'."}), 400

        # port
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError()
        except Exception:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid port '{port}'."}), 400

        # weight
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

        # Comment the name if present for convenience
        comment = f" # {name}" if name else ""
        servers.append(f"    server {ip_raw}:{port} weight={weight};{comment}")

    # Render the file content
    header = (
        "# THIS FILE IS MANAGED BY /API/L7/backend_list\n"
        "# DO NOT EDIT MANUALLY — CHANGES WILL BE OVERWRITTEN\n"
    )
    body = "upstream backend {\n" + "\n".join(servers) + "\n}\n"
    new_content = header + body

    # Backup, write, test, (rollback on failure), reload
    backup = backup_path(CONFIG_BACKEND_LIST_PATH)
    try:
        shutil.copy2(CONFIG_BACKEND_LIST_PATH, backup)
    except Exception:
        # If the file doesn't exist yet, that's fine; continue without failing
        pass

    try:
        write_atomic(CONFIG_BACKEND_LIST_PATH, new_content)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to write config: {e}"}), 400

    ok_test, test_msg = nginx_test()
    if not ok_test:
        # Roll back if test fails
        try:
            if os.path.exists(backup):
                shutil.copy2(backup, CONFIG_BACKEND_LIST_PATH)
        except Exception:
            # Even if rollback fails, surface primary error
            pass
        remove_backup(backup)
        return jsonify({"status": "error", "message": test_msg}), 400

    ok_reload, reload_msg = nginx_reload()
    if not ok_reload:
        # Optionally keep file (nginx keeps old running config if reload failed)
        remove_backup(backup)
        return jsonify({"status": "error", "message": reload_msg}), 400
    remove_backup(backup)
    
    
    return jsonify({
        "status": "success",
        "message": "nginx configuration successfully updated for backend list and applied"
    }), 200

@app.route('/API/L7/backend_list', methods=['GET'])
def backend_list_get():
    try:
        data = parse_backend_list(CONFIG_BACKEND_LIST_PATH)
        return jsonify({
            "data": data,
            "token": _extract_token(request)
        }), 200
    except FileNotFoundError:
        return jsonify({
            "status": "error",
            "message": f"Config not found: {CONFIG_BACKEND_LIST_PATH}"
        }), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
        
_ACL_DEFAULT_STUB = """# Managed by /API/L7/acl_system_config
# DO NOT EDIT MANUALLY — CHANGES WILL BE OVERWRITTEN

# GeoIP database locations (keep/edit these paths as needed)
acl_geo_database_path /usr/local/openresty/nginx/lua/geoip2/city.mmdb;
acl_isp_database_path  /usr/local/openresty/nginx/lua/geoip2/isp.mmdb;

"""
@app.route('/API/L7/acl_system_config', methods=['POST'])
@token_required
def acl_system_config():
    """
    Accepts JSON like:
    {
      "acl_rule_shm_size": 10,   # megabytes
      "acl_req_shm_size": 200,   # megabytes
      "acl_rsp_shm_size": 200,   # megabytes
      "acl_optimize_period": 10  # seconds
    }
    """
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
    req_mb, err  = pos_int("acl_req_shm_size")
    if err: return jsonify({"status": "error", "message": err}), 400
    rsp_mb, err  = pos_int("acl_rsp_shm_size")
    if err: return jsonify({"status": "error", "message": err}), 400
    period_s, err = pos_int("acl_optimize_period")
    if err: return jsonify({"status": "error", "message": err}), 400

    # Load existing config (or seed with defaults if missing)
    try:
        if os.path.exists(CONFIG_HTTP_LUA_ACL_PATH):
            with open(CONFIG_HTTP_LUA_ACL_PATH, "r") as f:
                original = f.read()
        else:
            original = _ACL_DEFAULT_STUB
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to read config: {e}"}), 400

    # Update/insert the four directives (add units and semicolons)
    updated = replace_or_append(original, "acl_rule_shm_size",     f"{rule_mb}m;")
    updated = replace_or_append(updated,  "acl_req_shm_size",      f"{req_mb}m;")
    updated = replace_or_append(updated,  "acl_rsp_shm_size",      f"{rsp_mb}m;")
    updated = replace_or_append(updated,  "acl_optimize_period",   f"{period_s}s;")

    # Backup -> write -> test -> reload (rollback on test failure)
    backup = backup_path(CONFIG_HTTP_LUA_ACL_PATH)
    try:
        if os.path.exists(CONFIG_HTTP_LUA_ACL_PATH):
            shutil.copy2(CONFIG_HTTP_LUA_ACL_PATH, backup)
    except Exception as e:
        # Not fatal if backup fails, but safer to surface it
        return jsonify({"status": "error", "message": f"Failed to create backup: {e}"}), 400

    try:
        write_atomic(CONFIG_HTTP_LUA_ACL_PATH, updated)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to write new config: {e}"}), 400

    ok_test, test_msg = nginx_test()
    if not ok_test:
        # Roll back on test failure
        try:
            if os.path.exists(backup):
                shutil.copy2(backup, CONFIG_HTTP_LUA_ACL_PATH)
        except Exception:
            pass
        remove_backup(backup)
        return jsonify({"status": "error", "message": test_msg}), 400

    ok_reload, reload_msg = nginx_reload()
    if not ok_reload:
        # nginx keeps old running config if reload failed
        remove_backup(backup)
        return jsonify({"status": "error", "message": reload_msg}), 400
    
    remove_backup(backup)
    return jsonify({
        "status": "success",
        "message": "ACL system config updated, nginx test passed, and reload signaled."
    }), 200
   

@app.route("/API/L7/acl_system_config", methods=["GET"])
def acl_system_config_get():
    try:
        data = parse_acl_system_config(CONFIG_HTTP_LUA_ACL_PATH)
        data["token"] = _extract_token(request)
        return jsonify(data), 200
    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": f"Config not found: {e}"}), 500
    except PermissionError as e:
        return jsonify({"status": "error", "message": f"Permission denied: {e}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
    
@app.route('/API/L7/ngx_base_config', methods=['POST'])
@token_required
def ngx_base_config():
    """
    Accepts JSON like:
    {
      "header": "<base64 string>",   # -> header.conf
      "http":   "<base64 string>",   # -> http_base_header.conf
      "proxy":  "<base64 string>"    # -> location_proxy_setting.conf
    }
    """
    payload = request.get_json(silent=True) or {}

    # Validate presence
    required = ["header", "http", "proxy"]
    missing = [k for k in required if k not in payload]
    if missing:
        return jsonify({"status": "error",
                        "message": f"Missing required field(s): {', '.join(missing)}"}), 400

    def decode_b64(name, s):
        if not isinstance(s, str):
            return None, f"Field '{name}' must be a base64-encoded string."
        try:
            # strip to tolerate accidental whitespace/newlines in transport
            raw = base64.b64decode(s.strip(), validate=True)
        except (binascii.Error, ValueError) as e:
            return None, f"Field '{name}' is not valid base64: {e}"
        try:
            # nginx configs are text; enforce utf-8
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None, f"Field '{name}' decoded bytes are not valid UTF-8 text."
        # Normalize newlines and ensure trailing newline (typical for conf files)
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if not text.endswith("\n"):
            text += "\n"
        return text, None

    header_text, err = decode_b64("header", payload["header"])
    if err: return jsonify({"status": "error", "message": err}), 400
    http_text, err   = decode_b64("http",   payload["http"])
    if err: return jsonify({"status": "error", "message": err}), 400
    proxy_text, err  = decode_b64("proxy",  payload["proxy"])
    if err: return jsonify({"status": "error", "message": err}), 400

    print (header_text)
    print (http_text)
    print (proxy_text)
    
    # Prepare transactional write across three files
    targets = [
        (CONFIG_HEADER_CONF_PATH,                 header_text),
        (CONFIG_HTTP_BASE_HEADER_CONF_PATH,       http_text),
        (CONFIG_LOCATION_PROXY_SETTING_CONF_PATH, proxy_text),
    ]

    backups = []   # list of (path, backup_path, existed_before)
    written  = []  # list of paths successfully written

    # Backup any existing files first
    for path, _ in targets:
        existed = os.path.exists(path)
        bkp = None
        if existed:
            try:
                bkp = backup_path(path)
                shutil.copy2(path, bkp)
            except Exception as e:
                return jsonify({"status": "error",
                                "message": f"Failed to create backup for {path}: {e}"}), 400
        backups.append((path, bkp, existed))

    # Write all three atomically (per file)
    try:
        for path, content in targets:
            write_atomic(path, content)
            written.append(path)
    except Exception as e:
        # If any write fails, attempt rollback of what we wrote
        for path, bkp, existed in backups:
            try:
                if existed and bkp and os.path.exists(bkp):
                    shutil.copy2(bkp, path)
                elif not existed and path in written and os.path.exists(path):
                    os.unlink(path)
            except Exception:
                pass
        return jsonify({"status": "error", "message": f"Failed to write config: {e}"}), 400

    # nginx -t, rollback on failure
    ok_test, test_msg = nginx_test()
    if not ok_test:
        for path, bkp, existed in backups:
            try:
                if existed and bkp and os.path.exists(bkp):
                    shutil.copy2(bkp, path)
                elif not existed and os.path.exists(path):
                    os.unlink(path)
            except Exception:
                pass
            remove_backup(bkp)
        
        return jsonify({"status": "error", "message": test_msg}), 400

    # Reload nginx
    ok_reload, reload_msg = nginx_reload()
    if not ok_reload:
        # Leaving files as-is is usually OK; running nginx keeps old live config if reload fails
        for path, bkp, existed in backups:
            try:
                if existed and bkp and os.path.exists(bkp):
                    remove_backup(bkp)
            except Exception:
                pass
                
        return jsonify({"status": "error", "message": reload_msg}), 400

    for path, bkp, existed in backups:
        try:
            if existed and bkp and os.path.exists(bkp):
                remove_backup(bkp)
        except Exception:
            pass
    return jsonify({
        "status": "success",
        "message": "Base configs updated, nginx test passed, and reload signaled."
    }), 200


@app.route("/API/L7/ngx_base_config", methods=["GET"])
def ngx_base_config_get():
    try:
        payload = {
            "header": file_to_base64(CONFIG_HEADER_CONF_PATH),
            "http": file_to_base64(CONFIG_HTTP_BASE_HEADER_CONF_PATH),
            "proxy": file_to_base64(CONFIG_LOCATION_PROXY_SETTING_CONF_PATH),
            "token": _extract_token(request),
        }
        return jsonify(payload), 200

    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": f"Config not found: {e}"}), 500
    except PermissionError as e:
        return jsonify({"status": "error", "message": f"Permission denied: {e}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
@app.route('/API/L7/set_acl', methods=['POST'])
@token_required
def set_acl():
    """
    Accepts JSON like:
    {
      "status": "on",   # or "off"
      "token": "...."
    }
    Writes server_acl.conf as: acl on; / acl off;
    """
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip().lower()

    if status not in {"on", "off"}:
        return jsonify({
            "status": "error",
            "message": "Invalid 'status'. Use 'on' or 'off'."
        }), 400

    new_content = f"acl {status};\n"

    # Backup old config
    backup = None
    try:
        if os.path.exists(CONFIG_SERVER_ACL_PATH):
            backup = backup_path(CONFIG_SERVER_ACL_PATH)
            shutil.copy2(CONFIG_SERVER_ACL_PATH, backup)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to backup: {e}"}), 400

    # Write new config atomically
    try:
        write_atomic(CONFIG_SERVER_ACL_PATH, new_content)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to write config: {e}"}), 400

    # Test nginx
    ok_test, test_msg = nginx_test()
    if not ok_test:
        # Rollback
        try:
            if backup and os.path.exists(backup):
                shutil.copy2(backup, CONFIG_SERVER_ACL_PATH)
                remove_backup(backup)
        except Exception:
            pass
        return jsonify({"status": "error", "message": test_msg}), 400

    # Reload nginx
    ok_reload, reload_msg = nginx_reload()
    if not ok_reload:
        remove_backup(backup)
        return jsonify({"status": "error", "message": reload_msg}), 400
    remove_backup(backup)
    return jsonify({
        "status": "success",
        "message": f"ACL successfully set to '{status}' and nginx reloaded."
    }), 200
    

@app.route("/API/L7/set_acl", methods=["GET"])
def set_acl_get():
    try:
        status = parse_acl_switch(CONFIG_SERVER_ACL_PATH)
        return jsonify({
            "status": status,          # "on" or "off"
            "token": _extract_token(request)
        }), 200
    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": f"Config not found: {e}"}), 500
    except PermissionError as e:
        return jsonify({"status": "error", "message": f"Permission denied: {e}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

ACL_RULE_URL_BASE = "http://127.0.0.1"  # or "http://localhost" if you prefer
@app.route('/API/L7/acl_rule_management', methods=['POST'])
@token_required
def acl_rule_management():
    """
    Accept JSON:
    {
      "data": [
        {"id": 18, "rules": "<base64 text>"},
        {"id": 21, "rules": "<base64 text>"}
      ],
      "token": "..."
    }

    For each entry we store a Redis key `acl_rule:<id>` with JSON like:
    {
      "id": 1,
      "rules": [ { "action": 1, "priority": 12, "rule": "..." }, ... ]
    }

    We also SADD id to `acl_rule_ids` and PUBLISH "acl_rule:<id>" on channel `acl:updates`.
    """
    
    
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
        # Normalize newlines
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        return text, None

    # Validate each entry and prepare redis objects
    seen_ids = set()
    prepared = []  # list of tuples (id, redis_value_dict)
    
    
    for idx, it in enumerate(items, start=1):
        if not isinstance(it, dict):
            return jsonify({"status": "error", "message": f"Entry #{idx} must be an object."}), 400

        # validate id
        try:
            acl_id = int(it.get("id", None))
            if acl_id <= 0:
                raise ValueError()
        except Exception:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid 'id' (must be positive integer)."}), 400
        if acl_id in seen_ids:
            return jsonify({"status": "error", "message": f"Duplicate id '{acl_id}'."}), 400
        seen_ids.add(acl_id)
        
        # decode base64 rules payload
        rules_b64 = it.get("rules", "")
        rules_text, err = decode_b64_text("rules", rules_b64)
        if err:
            return jsonify({"status": "error", "message": f"Entry #{idx}: {err}"}), 400
        

        # Attempt to parse decoded text as JSON array of rule objects (best-effort)
        rules_obj = None
        try:
            parsed = json.loads(rules_text)
            # Accept either a list of rule objects, or a single object (wrap into list)
            if isinstance(parsed, list):
                rules_obj = parsed
            elif isinstance(parsed, dict):
                rules_obj = [parsed]
            else:
                # not a dict/list -> fallback to treat decoded text as raw rule string
                rules_obj = None
        except Exception:
            # not JSON -> fallback below
            rules_obj = None
        
        if rules_obj is None:
            # decoded text might be a Lua/other string representing the RHS; store it as the "rule" string
            # Create a single-entry rule object. You can customize default action/priority if desired.
            rules_obj = [
                {
                    "action": it.get("default_action", 1) or 1,
                    "priority": it.get("default_priority", 100) or 100,
                    "rule": rules_text
                }
            ]
            
        # Sanity: ensure every rule in rules_obj has 'rule' property as a string.
        sanitized_rules = []
        for r_i, r in enumerate(rules_obj, start=1):
            if isinstance(r, dict):
                rule_field = r.get("rule")
                # If rule field is not a string but is a list/dict, convert it to compact JSON string
                if rule_field is None:
                    # If user didn't include a 'rule' subfield, maybe they provided a single expression object;
                    # convert whole object to JSON string.
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
                # unexpected non-dict element -> convert to string
                sanitized_rules.append({
                    "action": 1,
                    "priority": 100,
                    "rule": str(r)
                })

        # Build final redis object
        redis_obj = {
            "id": acl_id,
            "rules": sanitized_rules
        }

        prepared.append((acl_id, redis_obj))
        
    # All entries validated & prepared. Now write to Redis in a pipeline.
    try:
        rcli = get_redis_client()
        
        try:
            orig_members = rcli.smembers(RULE_IDS_KEY)
            orig_ids = set()
            for m in orig_members:
                if isinstance (m, bytes):
                    try:
                        orig_ids.add(int(m.decode()))
                    except Exception:
                        try:
                            orig_ids.add(int(m.decode('utf-8')))
                        except Exception:
                            pass
                else:
                    try:
                        orig_ids.add(int(m))
                    except Exception:
                        pass
        except Exception:
            return jsonify({"status": "error", "message": f"Failed to read existing acl_rule_ids from Redis: {e}"}), 500
        
        prepared_ids = {acl_id for (acl_id, _obj) in prepared}
    
        pipe = rcli.pipeline()    
        for acl_id, obj in prepared:
            key = f"acl_rule:{acl_id}"
            # store pretty-printed JSON for readability (you may use compact JSON by using separators)
            value = json.dumps(obj, ensure_ascii=False, indent=2).replace('\\/', '/')
            pipe.set(key, value)
            # add id to acl_rule_ids set
            pipe.sadd(RULE_IDS_KEY, acl_id)
            # publish notification so subscriber updates mlcache and applies rule
            pipe.publish("acl:updates", f"acl_rule:{acl_id}")
        # execute all pipeline commands atomically as a batch (not a single Redis transaction)
        pipe.execute()
        
        to_remove = sorted(list(orig_ids - prepared_ids))
        #removed_ids = []
        
        if to_remove:
            del_pipe = rcli.pipeline()
            for rid in to_remove:
                del_key = f"acl_rule:{rid}"
                del_pipe.delete(del_key)
                del_pipe.srem(RULE_IDS_KEY, rid)
                # Optional: notify subscribers about deletion. Adjust payload if needed.
                del_pipe.publish("acl:updates", f"acl_rule_deleted:{rid}")
            res = del_pipe.execute()
            # res contains results for delete, srem, publish for each id; we only want the ids we attempted
            # Build removed_ids from the to_remove list. Optionally validate res to check success.
            # removed_ids = to_remove
            
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to write to Redis: {e}"}), 500

    return jsonify({
        "status": "success",
        "message": f"Wrote {len(prepared)} acl_rule(s) to Redis and published updates.",
        "ids": [acl_id for (acl_id, _obj) in prepared]
    }), 200
    
@app.route("/API/L7/acl_rule_management", methods=["GET"])
def acl_rule_management_get():
    """
    Return JSON:
    {
      "data": [
        { "id": 1, "rules": "<base64 of rules array JSON>" },
        ...
      ],
      "token": "<token>"
    }
    """
    rcli = get_redis_client()

    try:
        # Get the set of IDs (as strings)
        ids = rcli.smembers("acl_rule_ids") or set()
    except Exception as e:
        # Redis access error
        return jsonify({"status": "error", "message": f"Failed to read acl_rule_ids from Redis: {e}"}), 500
    
    results = []
    # iterate sorted ids for stable output (optional)
    try:
        for sid in sorted(ids, key=lambda x: int(x) if str(x).isdigit() else x):
            key = f"acl_rule:{sid}"
            try:
                val = rcli.get(key)
            except Exception as e:
                # skip this id but log
                print("Failed to GET %s: %s", key, e)
                continue

            if not val:
                # key missing or empty — skip
                print("%s missing or empty", key)
                continue

            # val is expected to be a JSON string like {"id":1,"rules":[...]}
            try:
                obj = json.loads(val)
            except Exception as e:
                # stored value isn't JSON — attempt best-effort handling:
                print("Invalid JSON in %s: %s", key, e)
                # Fallback: treat entire stored value as a single rule string.
                rules_array = [{"action": 1, "priority": 100, "rule": val}]
            else:
                # Prefer obj["rules"] if present and is a list
                rules_array = obj.get("rules")
                if not isinstance(rules_array, list):
                    # If it's missing or not a list, convert to a single-entry list
                    rules_array = [{"action": obj.get("action", 1),
                                    "priority": obj.get("priority", 100),
                                    "rule": obj.get("rule", "")}] if isinstance(obj, dict) else [{"action":1,"priority":100,"rule":str(obj)}]

            # Serialize the rules array to JSON (compact) then base64-encode
            try:
                rules_json = json.dumps(rules_array, ensure_ascii=False, indent=2).replace('\\/', '/')
                rules_b64 = base64.b64encode(rules_json.encode("utf-8")).decode("ascii")
            except Exception as e:
                print("Failed to encode rules for %s: %s", key, e)
                continue

            results.append({
                "id": int(sid) if str(sid).isdigit() else sid,
                "rules": rules_b64
            })

    except Exception as e:
        return jsonify({"status": "error", "message": f"Unexpected error: {e}"}), 500

    return jsonify({
        "data": results,
        "token": _extract_token(request)
    }), 200
    
@app.route('/API/L7/set_ports', methods=['POST'])
@token_required
def set_ports():
    """
    Body:
    {
        "set_ports" : 80,8080,1107
    }
    
    Writes /usr/local/openresty/nginx/conf/server_default_ports.conf
    
    """
    payload = request.get_json(silent=True) or {}
    print(payload)
    
    data_str = payload.get("set_ports")
    if not data_str:
        return jsonify({"status": "error", "message": f"data field is nothing"}), 403
    
    # split data_str to comma and store it to CONFIG_SERVER_DEFAULT_PORTS_PATH
    try:
        ports = [int(p.strip()) for p in data_str.split(',')]
    except ValueError:
        return jsonify({"status": "error", "message": "invalid port values"}), 403
    
    invalid_ports = [p for p in ports if p < 1 or p > 65535]
    if invalid_ports:
        return jsonify({"status": "error", "message": f"invalid ports: {invalid_ports}"}), 403
    
    
    new_content = "".join(f"listen {p};\n" for p in ports)
    
    # Backup -> write -> test -> reload (with rollback on failure)
    backup = None
    try:
        if os.path.exists(CONFIG_SERVER_DEFAULT_PORTS_PATH):
            backup = backup_path(CONFIG_SERVER_DEFAULT_PORTS_PATH)
            shutil.copy2(CONFIG_SERVER_DEFAULT_PORTS_PATH, backup)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to create backup: {e}"}), 400

    try:
        write_atomic(CONFIG_SERVER_DEFAULT_PORTS_PATH, new_content)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to write config: {e}"}), 400

    ok_test, test_msg = nginx_test()
    if not ok_test:
        try:
            if backup and os.path.exists(backup):
                shutil.copy2(backup, CONFIG_SERVER_DEFAULT_PORTS_PATH)
                remove_backup(backup)
        except Exception:
            pass
        return jsonify({"status": "error", "message": test_msg}), 400

    ok_reload, reload_msg = nginx_reload()
    if not ok_reload:
        return jsonify({"status": "error", "message": reload_msg}), 400
    
    remove_backup(backup)

    return jsonify({
        "status": "success",
        "message": "Server ports are successfully updated."
    }), 200


@app.route("/API/L7/set_ports", methods=["GET"])
def set_ports_get():
    try:
        ports = parse_set_ports(CONFIG_SERVER_DEFAULT_PORTS_PATH)
        return jsonify({
            "set_ports": ports,          # "on" or "off"
            "token": _extract_token(request)
        }), 200
    except FileNotFoundError as e:
        return jsonify({"status": "error", "message": f"Config not found: {e}"}), 500
    except PermissionError as e:
        return jsonify({"status": "error", "message": f"Permission denied: {e}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
@app.route('/API/L7/acl_rule_apply', methods=['POST'])
@token_required
def acl_rule_apply():
    """
    POST body:
    {
      "data": [
        {"id":12,"checking_cond":"allow","apply_code":"allow","apply_content":null, "status":"enabled"},
        ...
      ],
      "token": "..."
    }

    Stores canonical apply rules in Redis under `acl_apply_rules` and publishes an update.
    """
    payload = request.get_json(silent=True) or {}
    print(payload)
        
    data_str = payload.get("data")
    if not data_str:
        return jsonify({"status": "error", "message": "Missing 'data' field."}), 400

    items = None

    # Case 1: already parsed list/tuple
    if isinstance(data_str, (list, tuple)):
        items = list(data_str)

    # Case 2: a JSON string
    elif isinstance(data_str, str):
        try:
            parsed = json.loads(data_str)
        except json.JSONDecodeError:
            return jsonify({"status": "error", "message": "Invalid JSON string in 'data' field."}), 400
        if isinstance(parsed, (list, tuple)):
            items = list(parsed)
        else:
            return jsonify({"status": "error", "message": "'data' JSON must be an array."}), 400

    # Case 3: raw bytes/bytearray (e.g., some clients)
    elif isinstance(data_str, (bytes, bytearray)):
        try:
            parsed = json.loads(data_str.decode("utf-8"))
        except Exception:
            return jsonify({"status": "error", "message": "Invalid JSON bytes in 'data' field."}), 400
        if isinstance(parsed, (list, tuple)):
            items = list(parsed)
        else:
            return jsonify({"status": "error", "message": "'data' JSON must be an array."}), 400

    else:
        return jsonify({"status": "error", "message": "Unsupported 'data' field type."}), 400

    # final validation
    if not items:
        return jsonify({"status": "error", "message": "Body must contain non-empty 'data' array."}), 400

    # items is now a list you can safely use
    print(items)
    
    # helper validators
    def valid_url(u: str) -> bool:
        try:
            p = urlparse(u)
            return p.scheme in ("http", "https") and bool(p.netloc)
        except Exception:
            return False

    normalized = []
    seen_ids = set()

    for idx, it in enumerate(items, start=1):
        if not isinstance(it, dict):
            return jsonify({"status": "error", "message": f"Entry #{idx} must be an object."}), 400

        # id
        try:
            acl_id = int(it.get("id", None))
            if acl_id <= 0:
                raise ValueError()
        except Exception:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid 'id' (must be positive integer)."}), 400
        if acl_id in seen_ids:
            return jsonify({"status": "error", "message": f"Duplicate id in payload: {acl_id}"}), 400
        seen_ids.add(acl_id)

        # status
        status = str(it.get("status", "")).strip().lower()
        if status not in {"enabled", "disabled"}:
            return jsonify({"status": "error", "message": f"Entry #{idx}: 'status' must be 'enabled' or 'disabled'."}), 400
        
        # checking_cond
        cond = str(it.get("checking_cond", "")).strip().lower()
        if cond not in {"allow", "block"}:
            return jsonify({"status": "error", "message": f"Entry #{idx}: 'checking_cond' must be 'allow' or 'block'."}), 400

        # apply_code + apply_content
        code = str(it.get("apply_code", "")).strip().lower()
        if code not in {"allow", "block", "return_code", "redirect"}:
            return jsonify({"status": "error", "message": f"Entry #{idx}: invalid 'apply_code'."}), 400

        content = it.get("apply_content", None)

        if code in {"allow", "block"}:
            # allow/block should have empty content (tolerate None or "")
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
            if url and not valid_url(url):
                return jsonify({"status": "error", "message": f"Entry #{idx}: 'apply_content' must be a valid http(s) URL for 'redirect'."}), 400
            action = {"kind": "redirect", "url": url}

        normalized.append({
            "id": acl_id,
            "status": status,
            "cond": cond,
            "action": action
        })

    # write to redis: compact JSON (no pretty indent)
    try:
        rcli = get_redis_client()
        json_val = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False, indent=2).replace('\\/', '/')
        # set key and publish a notification so workers can update mlcache
        pipe = rcli.pipeline()
        pipe.set("acl_apply_rules", json_val)
        pipe.publish("acl:updates", "acl_apply_rules")
        pipe.execute()
    except Exception as e:
        print("Failed to write acl_apply_rules to Redis")
        return jsonify({"status": "error", "message": f"Failed to write to Redis: {e}"}), 500

    return jsonify({
        "status": "success",
        "message": "acl_apply_rules stored in Redis and update published.",
        "count": len(normalized)
    }), 200
  
  
@app.route("/API/L7/acl_rule_apply", methods=["GET"])
def acl_rule_apply_get():
    """
    Returns the current ACL apply rules stored in Redis, converted to the API format.
    Response format:
    {
        "data": [...],
        "token": "..."
    }
    """
    try:
        rcli = get_redis_client()
        val = rcli.get("acl_apply_rules")
        if not val:
            rules = []
        else:
            stored = json.loads(val)
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
                    # unknown action → treat as block
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
        print("Failed to read acl_apply_rules from Redis")
        return jsonify({"status": "error", "message": f"Failed to read from Redis: {e}"}), 500

    return jsonify({
        "data": rules,
        "token": _extract_token(request)
    }), 200
    
def encode_base64(data):
    """
    Encodes the given data (string or bytes) to Base64.
    
    Args:
        data: Input data to be encoded (string or bytes)
        
    Returns:
        Base64 encoded string
    """
    if isinstance(data, str):
        # Convert string to bytes using UTF-8 encoding
        data_bytes = data.encode('utf-8')
    else:
        # Assume it's already bytes
        data_bytes = data
    
    # Encode to Base64 bytes, then decode to string
    encoded_bytes = base64.b64encode(data_bytes)
    encoded_str = encoded_bytes.decode('utf-8')
    
    return encoded_str
    
# get config
@app.route('/API/get_config', methods=['POST'])
@token_required
def get_config():
    config_path = '/usr/local/share/ebpf_firewall/firewall.config'
    
    try:
        # Read the config file
        with open(config_path, 'r') as f:
            config_content = f.read()
            
        encoded_bytes = encode_base64(config_content)
        return jsonify({
            "status": "success",
            "config": encoded_bytes
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
    
    l4_status = "failure"
    l4_reason = "unknown error"
    if isinstance(parsed, dict) and parsed.get('status') == 'error':
        l4_status = "failure"
        # try to extract error message
        if isinstance(parsed, dict):
            l4_reason = parsed.get('message', 'l4 check failed')
        else:
            l4_reason = str(parsed)
    else:
        l4_status = "success"
        # prefer a human message if provided
        l4_reason = parsed.get('message', 'l4 healthy')
    
    l7_status = "failure"
    l7_reason = ""
    
    systemctl_path = shutil.which("systemctl")
    if not systemctl_path:
        l7_status = "failure"
        l7_reason = "systemctl not found on this host"
    else:
        try:
            # Use `systemctl status` for diagnostics but keep this call short.
            # `--no-pager` avoids blocking on a pager.
            proc = subprocess.run(
                [systemctl_path, "status", "l7_firewall", "--no-pager"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                text=True
            )

            # systemctl status returns 0 for active (running); non-zero otherwise.
            stdout = (proc.stdout or "").strip()
            stderr = (proc.stderr or "").strip()

            if proc.returncode == 0:
                l7_status = "success"
                # Prefer short human message
                # Try to extract the "Active: ..." line for clarity
                active_line = None
                for line in stdout.splitlines():
                    if "Active:" in line:
                        active_line = line.strip()
                        break
                l7_reason = active_line or "l7_firewall is active (systemctl returned OK)"
            else:
                l7_status = "failure"
                # Try to extract reason from stdout/stderr
                active_line = None
                for line in stdout.splitlines():
                    if "Active:" in line:
                        active_line = line.strip()
                        break

                if active_line:
                    l7_reason = active_line
                elif stderr:
                    l7_reason = stderr
                elif stdout:
                    l7_reason = stdout.splitlines()[0][:200]  # shorten
                else:
                    l7_reason = f"systemctl exit code {proc.returncode}"
        except subprocess.TimeoutExpired:
            l7_status = "failure"
            l7_reason = "systemctl status timed out"
        except Exception as e:
            l7_status = "failure"
            l7_reason = f"error executing systemctl: {e}"

    # Build response
    resp = {
        "l4": l4_status,
        "l4_reason": l4_reason,
        "l7": l7_status,
        "l7_reason": l7_reason
    }

    return jsonify(resp), 200


def _is_x(val) -> bool:
    return val is None or str(val).strip().lower() == "x"

def _norm_dt(s: str) -> str:
    """
    Accepts 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM:SS', or ISO-8601.
    Returns 'YYYY-MM-DD HH:MM:SS' (SQLite CURRENT_TIMESTAMP format).
    """
    s = str(s).strip()
    # Try ISO-8601 first (handles 'Z' and timezone offsets)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    # Try full datetime
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    # Try date-only
    try:
        return datetime.strptime(s, "%Y-%m-%d").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        raise ValueError("Invalid date/time format for filter_date")
    
@app.route('/API/L4/get_blocklist', methods=['POST'])
@token_required
def get_blocklist():
    data = request.get_json(force=True) or {}

    filter_type = data.get("filter_type", "x")
    filter_ip   = data.get("filter_ip", "x")
    filter_date = data.get("filter_date", "x")

    sql = """
        SELECT id, ip, type, duration, reason, created, timestamp
        FROM blocked_ips
        WHERE 1=1
    """
    params = []

    if not _is_x(filter_type):
        sql += " AND type = ?"
        params.append(str(filter_type).strip())

    if not _is_x(filter_ip):
        sql += " AND ip = ?"
        params.append(str(filter_ip).strip())

    if not _is_x(filter_date):
        try:
            dt_str = _norm_dt(filter_date)
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400
        # created > given time
        sql += " AND created > ?"
        params.append(dt_str)

    sql += " ORDER BY created DESC"

    try:
        with sqlite3.connect(FIREWALL_DB_NAME, timeout=5) as con:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(sql, params)
            rows = [dict(r) for r in cur.fetchall()]
    except Exception as ex:
        return jsonify({"status": "error", "message": f"DB error: {ex}"}), 500

    return jsonify({"status": "success", "data": rows})


def send_http_request(url: str, payload: Optional[Dict[str, Any]] = None) -> requests.Response:
    """Sends HTTP POST request with JSON payload."""
    headers = {'Content-Type': 'application/json'}
    
    # Ensure payload is a dictionary and create a safe copy
    request_payload = dict(payload) if payload is not None else {}
    
    # Add token (ensure it's a string, not a set)
    if isinstance(user_token, set):
        request_payload['token'] = next(iter(user_token))  # Get first element if it's a set
    else:
        request_payload['token'] = str(user_token)
    
    try:
        response = requests.post(
            url,
            headers=headers,
            json=request_payload,
            timeout=5
        )
        response.raise_for_status()
        print(f"[HTTP] Success: {response.status_code} - {response.text}")
        return response
    except requests.exceptions.RequestException as e:
        print(f"[HTTP] Error: {e}")
        raise

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

def process_command(cmd: Dict[str, str]) -> None:
    """Processes a single command dictionary."""
    try:
        if cmd['command'] == 'report_log':
            payload = {
                'type': str(cmd.get('type', 'unknown')),
                'data': str(cmd.get('data', ''))
            }
            send_http_request(REPORT_LOG_API_URL, payload)
        elif cmd['command'] == 'check_blocklist':
            # For check_blocklist, we just need to send the token
            payload = {
                'status': str(cmd.get('status', 'unknown'))
            }
            send_http_request(CHECK_BLOCKLIST_API_URL, payload)
        else:
            print(f"[API_PARSER] Unknown command: {cmd['command']}")
    except Exception as e:
        print(f"[API_PARSER] Error processing command {cmd}: {str(e)}")
                
def fifo_reader_thread():
    if not os.path.exists(FIFO_PATH):
        os.mkfifo(FIFO_PATH)
    print(f"... listening at {FIFO_PATH}")
    while True:
        try:
            with open(FIFO_PATH, 'r') as fifo:
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


def _get_primary_ip() -> str:
    """Return primary non-loopback IPv4 used for outbound traffic."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable; just used to pick the local iface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback
        return socket.gethostbyname(socket.gethostname())


def _atomic_write(path: str, data: bytes, mode: int = 0o600):
    """Atomic write with secure permissions."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass
        
# ... your other imports and constants:
# INIT_FILE, MACHINE_FILE, BACKEND_DEPLOY_URL, LICENSE_PATH, PUBKEY_PATH
# _atomic_write, _get_primary_ip, _pick_token

def _fail_and_stop(reason: str, exit_code: int = 1, sig: int = signal.SIGINT) -> None:
    """
    Log reason, ask Gunicorn master to stop (signal parent PID),
    then exit this process. Works whether we're in main thread or not.
    """
    print(f"[INIT] {reason}", flush=True)
    try:
        ppid = os.getppid()
        # If ppid == 1 we're not under Gunicorn (or already orphaned); skip signaling.
        if ppid != 1:
            os.kill(ppid, sig)  # SIGINT matches KillSignal in your unit file
    except Exception as e:
        print(f"[INIT] Could not signal Gunicorn master: {e}", flush=True)

    # Try graceful, then hard-exit as a fallback (covers worker thread cases)
    try:
        sys.exit(exit_code)
    finally:
        os._exit(exit_code)

def handle_initialize_file():
    """
    Start-up initializer:
      - Ensure INIT_FILE exists (default '1').
      - If INIT_FILE == '0': call backend /API/deploy_done with ip,machine,token.
        On success: save license + decoded pubkey, set INIT_FILE to '1'.
        On failure: stop the service (signal Gunicorn master) and exit.
      - If INIT_FILE == '1': skip.
    """
    try:
        # Safely create parent dir if it exists in the path
        dirpath = os.path.dirname(INIT_FILE)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)

        # Ensure flag file exists with default '0'
        if not os.path.exists(INIT_FILE):
            with open(INIT_FILE, "w", encoding="utf-8") as f:
                f.write("0")
            print(f"[INIT] Created {INIT_FILE} with value 1", flush=True)

        # Read flag (tolerant)
        with open(INIT_FILE, "r", encoding="utf-8", errors="replace") as f:
            flag = (f.read() or "").strip()

        if flag != "0":
            print(f"[INIT] initialize={flag}; nothing to do", flush=True)
            return

        # We only proceed when flag == '0'
        if not os.path.exists(MACHINE_FILE):
            _fail_and_stop(f"Missing executable at {MACHINE_FILE}; exiting")

        if not os.access(MACHINE_FILE, os.X_OK):
            _fail_and_stop(f"Not executable: {MACHINE_FILE}; exiting")

        # Execute MACHINE_FILE and capture stdout
        try:
            cmd = shlex.split(MACHINE_FILE)
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=8,
                check=True,
            )
            out_bytes = proc.stdout or b""
        except subprocess.TimeoutExpired:
            _fail_and_stop(f"{MACHINE_FILE} timed out")
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or b"").decode("utf-8", "ignore")
            _fail_and_stop(f"{MACHINE_FILE} failed (rc={e.returncode}): {stderr}")
        except Exception as e:
            _fail_and_stop(f"Error running {MACHINE_FILE}: {e}")

        # Decode + sanitize machine id
        try:
            machine_id = out_bytes.decode("utf-8").strip()
        except UnicodeDecodeError:
            machine_id = out_bytes.decode("utf-8", errors="ignore").strip()

        # Keep only safe chars
        machine_id = "".join(ch for ch in machine_id if ch.isalnum() or ch in "-_")
        if not machine_id:
            _fail_and_stop("Empty/invalid machine_id from executable; exiting")

        ip_addr = _get_primary_ip()
        token = _pick_token()
        payload = {"ip": ip_addr, "machine": machine_id, "token": token}
        headers = {'Content-Type': 'application/json'}
        
        print(f"[INIT] Calling backend: {BACKEND_DEPLOY_URL} with {payload}", flush=True)
        try:
            r = requests.post(BACKEND_DEPLOY_URL, headers=headers, json=payload, timeout=10)
            r.raise_for_status()
            resp = r.json()
        except Exception as e:
            _fail_and_stop(f"Backend request failed: {e}")
        
        status = str(resp.get("status", "")).lower()
        license_text = resp.get("license")
        pub_key_b64 = resp.get("pub_key")
        
        if status != "success" or not license_text or not pub_key_b64:
            _fail_and_stop(f"Backend failure or missing fields: {resp}")

        try:
            print (license_text)
            print (pub_key_b64)
            _atomic_write(LICENSE_PATH, license_text.encode("utf-8"), mode=0o600)
            _atomic_write(PUBKEY_PATH, base64.b64decode(pub_key_b64), mode=0o600)
            print(f"[INIT] Saved license -> {LICENSE_PATH}, pubkey -> {PUBKEY_PATH}", flush=True)
        except Exception as e:
            _fail_and_stop(f"Failed writing license/pubkey: {e}")

        # Success: flip INIT_FILE to '1' so we skip next boot
        try:
            with open(INIT_FILE, "w", encoding="utf-8") as f:
                f.write("1\n")
            print(f"[INIT] Updated {INIT_FILE} to 1 (deploy_done success)", flush=True)
        except Exception as e:
            _fail_and_stop(f"Failed to write {INIT_FILE}: {e}")

        print(f"[INIT] Calling backend: {BACKEND_DEPLOY_COMPLETE_URL} with {payload}", flush=True)
        try:
            r = requests.post(BACKEND_DEPLOY_COMPLETE_URL, headers=headers, json=payload, timeout=10)
            r.raise_for_status()
            resp = r.json()
        except Exception as e:
            _fail_and_stop(f"Backend request failed: {e}")
            
    except SystemExit:
        raise
    except Exception as e:
        _fail_and_stop(f"Unexpected error: {e}")


        
if __name__ == '__main__':
    handle_initialize_file()
    should_start = os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug
    if should_start:
        fifo_thread = start_fifo_listener()
    app.run(host=SERVER_IP, port=SERVER_PORT, debug=False, use_reloader=False)
    
    print("\n[API_PARSER] Shutting down...")
    if os.path.exists(FIFO_PATH):
        os.unlink(FIFO_PATH)  # Clean up FIFO on exit

