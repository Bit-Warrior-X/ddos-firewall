# core/app_factory.py
"""Flask application factory - creates and configures the Flask app."""
import os
from flask import Flask
from routes.l4_routes import l4_bp
from routes.l7_routes import l7_bp
from routes.common_routes import common_bp
from core.fifo_worker import start_fifo_listener
from core.initializer import handle_initialize_file, sync_l4_lists_and_start_firewall
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
    """Initialize the application (handle init file, start FIFO listener)."""
    handle_initialize_file()
    #should_start = os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    #if should_start:
    start_fifo_listener()
        # On real worker start, sync L4 lists from backend and start firewall
    sync_l4_lists_and_start_firewall()

def cleanup_on_exit():
    """Cleanup resources on application exit."""
    if os.path.exists(config.FIFO_PATH):
        try:
            os.unlink(config.FIFO_PATH)
        except Exception:
            pass

