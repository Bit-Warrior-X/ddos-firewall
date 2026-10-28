# config.py
"""Configuration constants for the API parser."""
import os
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
L7_SERVICE = "athens.service"
L7_NGINX_CONF_DIR = Path("/usr/local/share/dorian/athens/nginx/conf")
L7_DEFAULT_PORTS_CONF = str(L7_NGINX_CONF_DIR / "server_default_ports.conf")
L7_GZIP_CONF = str(L7_NGINX_CONF_DIR / "http_gzip.conf")
L7_CACHE_PURGE_BASE = os.environ.get("L7_CACHE_PURGE_BASE", "http://127.0.0.1:9000").rstrip("/")

# Server configuration
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5000

# API URLs (base with no trailing slash to avoid double slashes)
#API_BASE_URL = "https://fw.dnscrxyz.com/api/e36i5n8t9rgnhov8fe9b1f70oklt"
#API_BASE_URL = "http://93.95.116.174:8080/api".rstrip("/")
API_BASE_URL = "https://panel.dorian.center/api".rstrip("/")

# Prefer IPv4 to panel (no working default IPv6 route on many edges)
FORCE_IPV4 = True

# L4-related APIs
REPORT_XDP_API_URL = f"{API_BASE_URL}/report_xdp"

# Block/white list sync APIs used by both startup and firewall_main route.
# Backend endpoints: /api/get_blocklist_ips and /api/get_whitelist_ips
BLOCKLIST_API_URL = f"{API_BASE_URL}/get_blocklist_ips"
WHITELIST_API_URL = f"{API_BASE_URL}/get_whitelist_ips"
CHECK_BLOCKLIST_API_URL = f"{API_BASE_URL}/check_blacklist"

# Temporary blacklist: notify backend when a new item is added to Redis (api_parser monitors Redis)
TEMPORARY_BLACKLIST_NOTIFY_URL = f"{API_BASE_URL}/temporary_blacklist_added"

# Edge → backend periodic sync of L4+L7 configure (SQLite, firewall.config, Redis)
EDGE_CONFIG_REPORT_URL = f"{API_BASE_URL}/report_edge_configure"
# Back-compat alias
EDGE_L4_LISTS_REPORT_URL = EDGE_CONFIG_REPORT_URL
EDGE_LIST_SYNC_INTERVAL = 60
# Include full SSL PEM material in reports (large); default redacts to presence/length only
EDGE_CONFIG_REPORT_INCLUDE_SSL_PEMS = False

# Redis configuration
REDIS_SOCK = "/tmp/redis.sock"
REDIS_DB = 0
RULE_IDS_KEY = "acl_rule_ids"

# Defaults
DEFAULT_BLOCK_DURATION = 3600
DEFAULT_ACL_RULE_ACTION = 1
DEFAULT_ACL_RULE_PRIORITY = 100

# GeoIP City/Country DB for L4->L7 temp blacklist enrichment (override if your .mmdb lives elsewhere)
GEOIP_MMDB_PATH = "/usr/local/openresty/nginx/lua/geoip2/dbip-full-2026-02.mmdb"

# Always L4-whitelisted before Sparta starts (see core/backend_whitelist.py).
# Real panel backend address: panel.dorian.center is behind Cloudflare, so its
# DNS does not return the IP that calls this agent on :5000.
PANEL_BACKEND_IPS = ("192.142.44.202",)
# Resolved via DNS at whitelist time.
GEODB_DOWNLOAD_HOSTS = (
    "download.maxmind.com",
    "download.db-ip.com",
)
L4_INFRA_WHITELIST_IPS = ()

