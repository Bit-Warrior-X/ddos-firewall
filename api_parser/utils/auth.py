# utils/auth.py
"""Authentication utilities."""
from functools import wraps
from flask import request, jsonify
import config

def get_token() -> str:
    """Read API token from TOKEN_FILE."""
    try:
        with open(config.TOKEN_FILE, "r") as f:
            token = f.read().strip()
            if token:
                return token
    except Exception as e:
        print(f"[AUTH] Failed to read token file {config.TOKEN_FILE}: {e}")
    return ""

def token_required(f):
    """Decorator for token authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({"status": "error", "message": "Request must be JSON"}), 400
        
        token = request.json.get('token')
        if not token or token != get_token():
            return jsonify({"status": "error", "message": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated_function

def extract_token(req) -> str:
    """Get token from Authorization header or query param."""
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip()
    return req.args.get("token", "")

