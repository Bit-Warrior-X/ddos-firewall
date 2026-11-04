# app.py
"""Main Flask application entry point - minimal wrapper for compiled app factory."""
import logging
from core.app_factory import create_app, initialize_app, cleanup_on_exit
import config

# Create the Flask app (logic is in compiled .so file)
app = create_app()
if not app.logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app.logger.setLevel(logging.INFO)
        
if __name__ == '__main__':
    # No debugger (remote code execution on error pages) and no reloader (it
    # restarts the agent - wiping and re-syncing L4 lists - whenever a module
    # file changes on disk).
    initialize_app(start_workers=True)
    app.run(host=config.SERVER_IP, port=config.SERVER_PORT, debug=False,
            use_reloader=False, threaded=True)
    print("\n[API_PARSER] Shutting down...")
    cleanup_on_exit()
