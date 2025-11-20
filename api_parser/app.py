# app.py
"""Main Flask application entry point - minimal wrapper for compiled app factory."""
from core.app_factory import create_app, initialize_app, cleanup_on_exit
import config

# Create the Flask app (logic is in compiled .so file)
app = create_app()
        
if __name__ == '__main__':
    initialize_app()
    app.run(host=config.SERVER_IP, port=config.SERVER_PORT, debug=False, use_reloader=False)
    print("\n[API_PARSER] Shutting down...")
    cleanup_on_exit()
