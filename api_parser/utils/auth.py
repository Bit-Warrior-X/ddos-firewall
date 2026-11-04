# utils/auth.py
"""Authentication utilities."""
import hmac
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

def token_matches(token) -> bool:
    """Constant-time comparison against the agent token (empty never matches)."""
    expected = get_token()
    if not expected or not isinstance(token, str) or not token:
        return False
    return hmac.compare_digest(token.encode(), expected.encode())

def token_required(f):
    """Decorator for token authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"status": "error", "message": "Request must be a JSON object"}), 400
        
        if not token_matches(data.get('token')):
            return jsonify({"status": "error", "message": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated_function

def extract_token(req) -> str:
    """Get token from Authorization header or query param."""
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip()
    return req.args.get("token", "")
