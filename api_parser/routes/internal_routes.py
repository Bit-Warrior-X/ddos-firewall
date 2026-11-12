# routes/internal_routes.py
"""Localhost-only helpers for Athens ↔ angelos (no panel token)."""
from flask import Blueprint, jsonify, request

from core.l7_escalate import escalate_ips

internal_bp = Blueprint("internal", __name__, url_prefix="/internal")


@internal_bp.route("/l7_escalate", methods=["POST"])
def l7_escalate():
    """Drain L7 guard flush batches into Sparta or nftables.

    Body JSON: { "ips": ["1.2.3.4", ...], "ttl": 600, "reason": "l7-guard" }
    Only reachable from peers already allowed by app_factory (localhost / panel).
    """
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request must be application/json"}), 400

    data = request.get_json(silent=True) or {}
    ips = data.get("ips") or data.get("ip") or []
    if isinstance(ips, str):
        ips = [ips]
    if not isinstance(ips, list):
        return jsonify({"status": "error", "message": "ips must be a list"}), 400

    result = escalate_ips(ips, data.get("ttl") or 0, str(data.get("reason") or "l7-guard"))
    code = 200 if result.get("status") == "success" else 503
    if result.get("message") == "no valid IPv4 addresses":
        code = 400
    if result.get("message") == "L7 escalate not allowed for current license":
        code = 403
    return jsonify(result), code
