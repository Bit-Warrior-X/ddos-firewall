# core/app_factory.py
"""Flask application factory - creates and configures the Flask app."""
import os
from flask import Flask
from routes.l4_routes import l4_bp
from routes.l7_routes import l7_bp
from routes.common_routes import common_bp
from core.fifo_worker import start_fifo_listener
from core.initializer import sync_l4_lists_and_start_firewall
from core.listening_ports import sync_from_redis_on_startup
from core.temporary_blacklist_monitor import start_temporary_blacklist_monitor
from core.license_monitor import start_license_monitor
import config

def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Register blueprints
    app.register_blueprint(l4_bp)
    app.register_blueprint(l7_bp)
    app.register_blueprint(common_bp)
    
    return app

def initialize_app():
    """Initialize the application (start FIFO listener, start temp blacklist monitor).

    Important: When running with the Flask reloader (python app.py with debug=True),
    there are TWO Python processes:
      - the reloader/parent
      - the actual worker (child) where WERKZEUG_RUN_MAIN == "true"

    We only want to start long-running background threads (FIFO listener,
    L4 sync + firewall start, temporary blacklist monitor) in the REAL worker
    process, otherwise each reload would duplicate them.
    """
    # Only start background workers in the real Flask worker process
    should_start = os.environ.get("WERKZEUG_RUN_MAIN") == "true" or \
        "gunicorn" in os.environ.get("SERVER_SOFTWARE", "").lower()

    if not should_start:
        print("[INIT] Skipping FIFO listener and temp blacklist monitor in reloader/parent process")
        return

    start_fifo_listener()
    # On real worker start, sync L4 lists from backend and start firewall
    sync_l4_lists_and_start_firewall()
    # Apply edge-wide nginx listen ports from Redis (listeningports)
    sync_from_redis_on_startup()
    # Monitor Redis temporaryblacklist:* and notify backend when a new item is added
    start_temporary_blacklist_monitor()
    # Validate license every LICENSE_CHECK_INTERVAL seconds
    start_license_monitor()

def cleanup_on_exit():
    """Cleanup resources on application exit."""
    if os.path.exists(config.UNIX_DGRAM_PATH):
        try:
            os.unlink(config.UNIX_DGRAM_PATH)
        except Exception:
            pass

