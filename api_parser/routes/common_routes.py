# routes/common_routes.py
"""Common API routes (health check, config)."""
import os
import base64
import subprocess
import shutil
from flask import Blueprint, request, jsonify
from core.firewall import health_check as fw_health_check
from utils.auth import token_required, extract_token
import config

common_bp = Blueprint('common', __name__, url_prefix='/API')

def encode_base64(data):
    """Encodes the given data (string or bytes) to Base64."""
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
    encoded_bytes = base64.b64encode(data_bytes)
    return encoded_bytes.decode('utf-8')

@common_bp.route('/get_config', methods=['POST'])
@token_required
def get_config():
    """Get firewall config file as base64."""
    config_path = config.FIREWALL_CONFIG_PATH
    
    try:
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

@common_bp.route('/health_check', methods=['POST'])
@token_required
def health_check():
    """Health check for L4 and L7 firewalls."""
    parsed = fw_health_check()
    
    l4_status = "failure"
    l4_reason = "unknown error"
    if isinstance(parsed, dict) and parsed.get('status') == 'error':
        l4_status = "failure"
        if isinstance(parsed, dict):
            l4_reason = parsed.get('message', 'l4 check failed')
        else:
            l4_reason = str(parsed)
    else:
        l4_status = "success"
        l4_reason = parsed.get('message', 'l4 healthy')
    
    l7_status = "failure"
    l7_reason = ""
    
    systemctl_path = shutil.which("systemctl")
    if not systemctl_path:
        l7_status = "failure"
        l7_reason = "systemctl not found on this host"
    else:
        try:
            proc = subprocess.run(
                [systemctl_path, "status", "l7_firewall", "--no-pager"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                text=True
            )

            stdout = (proc.stdout or "").strip()
            stderr = (proc.stderr or "").strip()

            if proc.returncode == 0:
                l7_status = "success"
                active_line = None
                for line in stdout.splitlines():
                    if "Active:" in line:
                        active_line = line.strip()
                        break
                l7_reason = active_line or "l7_firewall is active (systemctl returned OK)"
            else:
                l7_status = "failure"
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
                    l7_reason = stdout.splitlines()[0][:200]
                else:
                    l7_reason = f"systemctl exit code {proc.returncode}"
        except subprocess.TimeoutExpired:
            l7_status = "failure"
            l7_reason = "systemctl status timed out"
        except Exception as e:
            l7_status = "failure"
            l7_reason = f"error executing systemctl: {e}"

    resp = {
        "l4": l4_status,
        "l4_reason": l4_reason,
        "l7": l7_status,
        "l7_reason": l7_reason
    }

    return jsonify(resp), 200

