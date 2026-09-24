# config.example.py — template when config.py is absent (e.g. CI).
# Copy to config.py locally or replace payload/config.py after deploy.
"""Configuration constants for the API parser."""
from pathlib import Path

# Base paths (Sparta L4 install layout)
BASE_EBPF_FIREWALL_DIR = Path("/usr/local/share/dorian/sparta")
BASE_LICENSE_DIR = Path("/usr/local/share/dorian/license")

# File paths
FIFO_PATH = "/tmp/firewall_to_api_parser.fifo"
UNIX_DGRAM_PATH = "/tmp/firewall_to_api_parser.sock"
FIREWALL_CONFIG_PATH = str(BASE_EBPF_FIREWALL_DIR / "firewall.config")
FIREWALL_DB_NAME = str(BASE_EBPF_FIREWALL_DIR / "firewall_control.db")
TOKEN_FILE = str(BASE_LICENSE_DIR / "token")
LICENSE_FILE = str(BASE_LICENSE_DIR / "license.lic")
PUBKEY_FILE = str(BASE_LICENSE_DIR / "server_public_key.pem")
LICENSE_CHECK_INTERVAL = 10
SPARTA_SERVICE = "sparta.service"
L7_SERVICE = "l7_firewall"
L7_NGINX_CONF_DIR = Path("/usr/local/share/dorian/athens/nginx/conf")
L7_DEFAULT_PORTS_CONF = str(L7_NGINX_CONF_DIR / "server_default_ports.conf")
L7_GZIP_CONF = str(L7_NGINX_CONF_DIR / "http_gzip.conf")

# Server configuration
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5000

# API URLs (override in production config.py)
API_BASE_URL = "http://127.0.0.1:8080/api".rstrip("/")

# L4-related APIs
REPORT_XDP_API_URL = f"{API_BASE_URL}/report_xdp"

# Block/white list sync APIs used by both startup and firewall_main route.
BLOCKLIST_API_URL = f"{API_BASE_URL}/get_blocklist_ips"
WHITELIST_API_URL = f"{API_BASE_URL}/get_whitelist_ips"
CHECK_BLOCKLIST_API_URL = f"{API_BASE_URL}/check_blacklist"

TEMPORARY_BLACKLIST_NOTIFY_URL = f"{API_BASE_URL}/temporary_blacklist_added"

# Edge → backend periodic sync of L4+L7 configure (SQLite, firewall.config, Redis)
EDGE_CONFIG_REPORT_URL = f"{API_BASE_URL}/report_edge_configure"
EDGE_L4_LISTS_REPORT_URL = EDGE_CONFIG_REPORT_URL
EDGE_LIST_SYNC_INTERVAL = 60
EDGE_CONFIG_REPORT_INCLUDE_SSL_PEMS = False

# Redis configuration
REDIS_SOCK = "/tmp/redis.sock"
REDIS_DB = 0
RULE_IDS_KEY = "acl_rule_ids"

# Defaults
DEFAULT_BLOCK_DURATION = 3600
DEFAULT_ACL_RULE_ACTION = 1
DEFAULT_ACL_RULE_PRIORITY = 100

GEOIP_MMDB_PATH = "/usr/local/openresty/nginx/lua/geoip2/dbip-full-2026-02.mmdb"
