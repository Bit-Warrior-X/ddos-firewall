# config.py
"""Configuration constants for the API parser."""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path("/usr/local/share/ebpf_firewall")
API_PARSER_DIR = Path("/usr/local/share/api_parser")

# File paths
FIFO_PATH = "/tmp/firewall_to_api_parser.fifo"
FIREWALL_DB_NAME = str(BASE_DIR / "firewall_control.db")
INIT_FILE = str(BASE_DIR / "initialize")
MACHINE_FILE = str(BASE_DIR / "machine_id")
LICENSE_PATH = str(BASE_DIR / "license.lic")
PUBKEY_PATH = str(BASE_DIR / "server_public_key.pem")
TOKEN_FILE = str(BASE_DIR / "token")

# Server configuration
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5000

# API URLs (base with no trailing slash to avoid double slashes)
#API_BASE_URL = "https://fw.dnscrxyz.com/api/e36i5n8t9rgnhov8fe9b1f70oklt"
API_BASE_URL = "http://192.168.147.3:8080/api".rstrip("/")

# L4-related APIs
REPORT_XDP_API_URL = f"{API_BASE_URL}/report_xdp"

# Block/white list sync APIs used by both startup and firewall_main route.
# Backend endpoints: /api/get_blocklist_ips and /api/get_whitelist_ips
BLOCKLIST_API_URL = f"{API_BASE_URL}/get_blocklist_ips"
WHITELIST_API_URL = f"{API_BASE_URL}/get_whitelist_ips"
CHECK_BLOCKLIST_API_URL = f"{API_BASE_URL}/check_blacklist"

# Deployment / licensing APIs
BACKEND_DEPLOY_URL = f"{API_BASE_URL}/deploy_done"
BACKEND_DEPLOY_COMPLETE_URL = f"{API_BASE_URL}/deploy_complete"

# Redis configuration
REDIS_SOCK = "/tmp/redis.sock"
REDIS_DB = 0
RULE_IDS_KEY = "acl_rule_ids"

# HTTP Methods
ALLOWED_HTTP_METHODS = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "MKCOL", "COPY", 
    "MOVE", "OPTIONS", "PROPFIND", "PROPPATCH", "LOCK", 
    "UNLOCK", "PATCH", "TRACE", "CONNECT"
}

# Defaults
DEFAULT_BLOCK_DURATION = 300
DEFAULT_ACL_RULE_ACTION = 1
DEFAULT_ACL_RULE_PRIORITY = 100

# Nginx configuration paths
NGINX_CONF_DIR = "/usr/local/openresty/nginx/conf"
CONFIG_HTTP_REPORT_IP_PATH = f"{NGINX_CONF_DIR}/http_report_ip.conf"
CONFIG_BACKEND_LIST_PATH = f"{NGINX_CONF_DIR}/backend_list.conf"
CONFIG_HTTP_LUA_ACL_PATH = f"{NGINX_CONF_DIR}/http_lua_acl.conf"
CONFIG_HEADER_CONF_PATH = f"{NGINX_CONF_DIR}/header.conf"
CONFIG_HTTP_BASE_HEADER_CONF_PATH = f"{NGINX_CONF_DIR}/http_base_header.conf"
CONFIG_LOCATION_PROXY_SETTING_CONF_PATH = f"{NGINX_CONF_DIR}/location_proxy_setting.conf"
CONFIG_SERVER_ACL_PATH = f"{NGINX_CONF_DIR}/server_acl.conf"
CONFIG_SERVER_LUA_ACL_SET_PATH = f"{NGINX_CONF_DIR}/server_lua_acl_set.conf"
CONFIG_LOCATION_LUA_ACL_CHECK_PATH = f"{NGINX_CONF_DIR}/location_lua_acl_check.conf"
CONFIG_SERVER_DEFAULT_PORTS_PATH = f"{NGINX_CONF_DIR}/server_default_ports.conf"

