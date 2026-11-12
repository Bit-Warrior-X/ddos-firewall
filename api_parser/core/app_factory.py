# core/app_factory.py
"""Flask application factory - creates and configures the Flask app."""
import os
from flask import Flask, jsonify, request
from routes.l4_routes import l4_bp
from routes.l7_routes import l7_bp
from routes.common_routes import common_bp
from routes.internal_routes import internal_bp
from core.fifo_worker import start_fifo_listener
from core.initializer import sync_l4_lists_and_start_firewall
from core.listening_ports import sync_from_redis_on_startup
from core.temporary_blacklist_monitor import start_temporary_blacklist_monitor
from core.license_monitor import start_license_monitor
from core.edge_list_sync import start_edge_list_sync
from core.cache_hit_sync import start_cache_hit_sync
from core.l7_attack_sync import start_l7_attack_sync
from core.metrics_sync import start_metrics_sync
from core.l7_escalate import sync_escalate_backend
from core import license_check as license_check_mod
from core.license_check import get_license_info
import config

def _allowed_peers() -> frozenset:
    return frozenset(
        tuple(getattr(config, "API_ALLOWED_IPS", ("127.0.0.1", "::1")))
        + tuple(getattr(config, "PANEL_BACKEND_IPS", ()))
    )


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    allowed = _allowed_peers()

    # Port 5000 is reachable from the internet and most routes have no token:
    # only the panel backend and localhost may call the API.
    @app.before_request
    def _restrict_peers():
        if request.remote_addr not in allowed:
            return jsonify({"status": "error", "message": "Forbidden"}), 403
        return None

    app.register_blueprint(l4_bp)
    app.register_blueprint(l7_bp)
    app.register_blueprint(common_bp)
    app.register_blueprint(internal_bp)

    return app

def initialize_app(start_workers: bool = None):
    """Initialize the application (start FIFO listener, start temp blacklist monitor).

    Important: When running with the Flask reloader (python app.py with debug=True),
    there are TWO Python processes:
      - the reloader/parent
      - the actual worker (child) where WERKZEUG_RUN_MAIN == "true"

    We only want to start long-running background threads in the REAL worker
    process, otherwise each reload would duplicate them.
    """
    should_start = start_workers if start_workers is not None else (
        os.environ.get("WERKZEUG_RUN_MAIN") == "true" or
        "gunicorn" in os.environ.get("SERVER_SOFTWARE", "").lower())

    if not should_start:
        print("[INIT] Skipping background workers in reloader/parent process")
        return

    # License first so L4/L7 startup and escalate backend follow the type.
    info = None
    try:
        info = get_license_info()
        license_check_mod.license_info = info
        print(
            f"[INIT] License status={info.status} type={info.license_type!r} "
            f"l4={info.allows_l4} l7={info.allows_l7}",
            flush=True,
        )
    except Exception as exc:
        print(f"[INIT] License check failed at boot: {exc}", flush=True)

    start_fifo_listener()

    allows_l4 = bool(info and info.allows_l4)
    allows_l7 = bool(info and info.allows_l7)

    if allows_l4:
        sync_l4_lists_and_start_firewall()
    else:
        print("[INIT] Skipping L4 list sync / firewall start (not licensed)", flush=True)

    if allows_l7:
        sync_from_redis_on_startup()
        start_temporary_blacklist_monitor()
        start_cache_hit_sync()
        start_l7_attack_sync()
    else:
        print("[INIT] Skipping L7 Redis ports / cache-hit / l7-attack sync (not licensed)", flush=True)

    try:
        backend = sync_escalate_backend()
        print(f"[INIT] L7 escalate backend={backend}", flush=True)
    except Exception as exc:
        print(f"[INIT] L7 escalate backend sync failed: {exc}", flush=True)

    start_license_monitor()
    start_edge_list_sync()
    start_metrics_sync()

def cleanup_on_exit():
    """Cleanup resources on application exit."""
    if os.path.exists(config.UNIX_DGRAM_PATH):
        try:
            os.unlink(config.UNIX_DGRAM_PATH)
        except Exception:
            pass
