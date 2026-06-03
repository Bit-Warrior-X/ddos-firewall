# config.example.py — template when config.py is absent (e.g. CI).
# Copy to config.py locally or replace payload/config.py after deploy.
"""Configuration constants for the API parser."""
from pathlib import Path

# Base paths
BASE_EBPF_FIREWALL_DIR = Path("/usr/local/share/dorian/ebpf_firewall")
BASE_LICENSE_DIR = Path("/usr/local/share/dorian/license")

# File paths
FIFO_PATH = "/tmp/firewall_to_api_parser.fifo"
UNIX_DGRAM_PATH = "/tmp/firewall_to_api_parser.sock"
FIREWALL_DB_NAME = str(BASE_EBPF_FIREWALL_DIR / "firewall_control.db")
TOKEN_FILE = str(BASE_LICENSE_DIR / "token")

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

# Redis configuration
REDIS_SOCK = "/tmp/redis.sock"
REDIS_DB = 0
RULE_IDS_KEY = "acl_rule_ids"

# Defaults
DEFAULT_BLOCK_DURATION = 3600
DEFAULT_ACL_RULE_ACTION = 1
DEFAULT_ACL_RULE_PRIORITY = 100

GEOIP_MMDB_PATH = "/usr/local/openresty/nginx/lua/geoip2/dbip-full-2026-02.mmdb"
