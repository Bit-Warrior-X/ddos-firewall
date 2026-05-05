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
    initialize_app()
    app.run(host=config.SERVER_IP, port=config.SERVER_PORT, debug=True, use_reloader=True)
    print("\n[API_PARSER] Shutting down...")
    cleanup_on_exit()
