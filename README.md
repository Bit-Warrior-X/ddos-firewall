# DDoS Firewall

A high-performance, multi-layered DDoS protection system combining eBPF/XDP-based L4 firewall with OpenResty-based L7 protection, managed through a comprehensive REST API.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Usage Examples](#usage-examples)
- [Service Management](#service-management)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Overview

DDoS Firewall is a comprehensive network security solution that provides protection against Distributed Denial of Service (DDoS) attacks at both Layer 4 (L4) and Layer 7 (L7) of the OSI model.

### Key Components

1. **L4 Firewall (eBPF/XDP)**: Kernel-level packet filtering using eBPF programs attached to XDP hooks
2. **L7 Firewall (OpenResty)**: Application-layer protection with Nginx/OpenResty and Lua-based ACL rules
3. **API Parser**: RESTful API service for managing firewall rules and configurations
4. **Database**: SQLite-based storage for blocklists, whitelists, and firewall state

### How It Works

- **L4 Protection**: eBPF programs intercept packets at the XDP layer (before they reach the kernel network stack), providing ultra-low latency protection against flood attacks
- **L7 Protection**: OpenResty with custom Lua modules handles HTTP/HTTPS traffic, providing application-aware filtering and rate limiting
- **Centralized Management**: REST API allows remote configuration and monitoring of both L4 and L7 components

## Features

### L4 Firewall Features

- **Multi-Vector Attack Protection**:
  - TCP SYN flood protection
  - TCP ACK flood protection
  - TCP RST flood protection
  - ICMP flood protection
  - UDP flood protection
  - GRE flood protection

- **Intelligent Detection**:
  - Rate limiting with configurable thresholds
  - Burst detection (packets per burst, burst frequency)
  - Fixed window threshold monitoring
  - Challenge-response mechanism for SYN floods

- **Automatic IP Blocking**:
  - Temporary blocking of malicious IPs
  - Configurable block duration
  - Manual IP management (add/remove)

- **Performance**:
  - Kernel-level processing (XDP)
  - Minimal CPU overhead
  - High packet processing rates

### L7 Firewall Features

- **HTTP/HTTPS Protection**:
  - Request method filtering
  - Backend server management
  - ACL (Access Control List) system
  - Port-based routing

- **Advanced ACL System**:
  - Rule-based access control
  - Priority-based rule matching
  - Dynamic rule application
  - IP-based allow/deny lists

- **Nginx Integration**:
  - Dynamic configuration management
  - Hot reload without downtime
  - Custom OpenResty modules support

### API Features

- **RESTful API**: Complete HTTP API for all operations
- **Token-based Authentication**: Secure API access
- **Real-time Configuration**: Dynamic rule updates
- **Health Monitoring**: Service status and health checks
- **Database Management**: Blocklist/whitelist storage and querying

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    REST API (Flask/Gunicorn)                 │
│              /usr/local/share/api_parser/                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Routes: L4, L7, Common                              │   │
│  │  Core: Database, Firewall, Nginx, API Client          │   │
│  │  Utils: Auth, Validators, Nginx Utils                │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
┌───────▼────────┐            ┌─────────▼──────────┐
│  L4 Firewall   │            │   L7 Firewall      │
│  (eBPF/XDP)    │            │  (OpenResty)       │
│                │            │                    │
│  ┌──────────┐  │            │  ┌──────────────┐ │
│  │ XDP Hook │  │            │  │  Nginx       │ │
│  │ eBPF     │  │            │  │  Lua Modules │ │
│  │ Programs │  │            │  │  ACL Rules   │ │
│  └──────────┘  │            │  └──────────────┘ │
│                │            │                    │
│  CLI:          │            │  Config Files:    │
│  l4_firewall_  │            │  /usr/local/      │
│  cli           │            │  openresty/nginx/ │
└────────────────┘            └───────────────────┘
        │                               │
        └───────────────┬───────────────┘
                        │
                ┌───────▼───────┐
                │   SQLite DB   │
                │  Blocklist/   │
                │  Whitelist    │
                └──────────────┘
```

### Directory Structure

```
ddos-firewall/
├── api_parser/              # API service (modular Python)
│   ├── app.py              # Entry point
│   ├── config.py           # Configuration
│   ├── core/               # Core modules (compiled to .so)
│   │   ├── database.py
│   │   ├── firewall.py
│   │   ├── nginx.py
│   │   └── ...
│   ├── routes/             # API routes (compiled to .so)
│   │   ├── l4_routes.py
│   │   ├── l7_routes.py
│   │   └── common_routes.py
│   └── utils/              # Utilities (compiled to .so)
│       ├── auth.py
│       └── validators.py
├── ebpf_firewall/          # L4 eBPF firewall
│   ├── firewall.c         # eBPF program
│   ├── firewall_user.c    # Userspace loader
│   └── Makefile
├── openresty-modules/      # OpenResty custom modules
│   ├── ngx_acl/
│   ├── ngx_http_report_ip/
│   └── ngx_lic/
├── setup/                  # Installation package
│   ├── pack.sh            # Package builder
│   ├── installer_stub.sh   # Installation script
│   └── payload/           # Files to package
└── lib/                    # Shared libraries
```

## Requirements

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, or similar)
- **Kernel**: 5.10+ (for XDP support)
- **Architecture**: x86_64

### Software Dependencies

- **Python**: 3.8+ (3.10 recommended)
- **GCC/Clang**: For compiling eBPF programs
- **LLVM**: 10+ for eBPF compilation
- **OpenResty**: 1.25.3.1+ (for L7 protection)
- **SQLite**: 3.x
- **Redis**: Optional (for advanced features)

### Build Dependencies

```bash
apt-get update
apt-get install -y \
    python3 python3-venv python3-dev \
    gcc clang llvm libelf-dev libbpf-dev \
    xdp-tools libnetfilter-conntrack-dev \
    build-essential curl wget
```

## Installation

### Quick Installation

1. **Build the installer package**:
   ```bash
   cd ddos-firewall/setup
   ./pack.sh
   ```
   This creates `setup.sh` - a self-extracting installer.

2. **Transfer to target system** (if building on different machine):
   ```bash
   scp setup.sh user@target-server:/tmp/
   ```

3. **Run installation on target system**:
   ```bash
   sudo chmod +x /tmp/setup.sh
   sudo /tmp/setup.sh
   ```

### Installation Process

The installer performs the following steps:

1. **Extract payload** → Files extracted to temporary directory
2. **Copy binaries** → L4/L7 firewall binaries copied to `/usr/local/bin/`
3. **Install API parser** → Python modules installed to `/usr/local/share/api_parser/`
4. **Create Python venv** → Virtual environment created
5. **Install dependencies** → Packages from `requirements.txt` installed
6. **Compile .so files** → Python modules compiled to `.so` files (code protection)
7. **Install systemd services** → Services installed and enabled
8. **Start services** → Services started automatically

### Post-Installation

After installation, verify services are running:

```bash
# Check API parser service
sudo systemctl status api_parser

# Check L4 firewall (if running)
sudo systemctl status l4_firewall

# View API parser logs
sudo journalctl -u api_parser -f

# Verify .so files were compiled
find /usr/local/share/api_parser -name "*.so"
```

## Configuration

### API Parser Configuration

Edit `/usr/local/share/api_parser/config.py`:

```python
# Server configuration
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5000

# API URLs (backend endpoints)
API_BASE_URL = "https://your-backend.com/api/endpoint"

# Database path
FIREWALL_DB_NAME = "/usr/local/share/dorian/sparta/firewall_control.db"
```

### L4 Firewall Configuration

Edit `/usr/local/share/dorian/sparta/firewall.config`:

```ini
#------------------GLOBAL-------------------
dev = eth0                    # Network interface
attach_mode = native         # XDP mode: skb, native, drv, hw
black_ip_duration = 3600     # Block duration (seconds)

#------------------SYN-----------------------
syn_threshold = 200000       # Packets per second
syn_burst_pkt = 20           # Packets per burst
syn_burst_count_per_sec = 10 # Burst frequency
syn_fixed_threshold = 2000   # Fixed window threshold
syn_fixed_check_duration = 15 # Window duration (seconds)
syn_challenge_timeout = 3    # Challenge timeout (seconds)

# Similar configs for ACK, RST, ICMP, UDP, GRE...
```

### L7 Firewall Configuration

L7 firewall uses OpenResty configuration files in `/usr/local/openresty/nginx/conf/`:

- `http_lua_acl.conf` - ACL system configuration
- `backend_list.conf` - Backend server definitions
- `server_acl.conf` - Server-level ACL rules

Configuration is managed through the API (see API Documentation).

## API Documentation

### Authentication

All API endpoints require token authentication via the `token` parameter in the request body:

```json
{
  "token": "your_authentication_token"
}
```

### Base URL

```
http://your-server:5000/API
```

### L4 Firewall Endpoints

#### Firewall Control

**POST** `/API/L4/firewall_main`

Start, stop, or restart the L4 firewall.

**Request:**
```json
{
  "token": "your_token",
  "status": "start|stop|restart",
  "interface": "eth0",
  "attach_mode": "native"
}
```

**Response:**
```json
{
  "status": "success",
  "action": "start",
  "message": "Firewall started successfully",
  "interface": "eth0",
  "attach_mode": "native",
  "blocklist_loaded": true,
  "blocklist_count": 150,
  "whitelist_loaded": true,
  "whitelist_count": 10
}
```

#### Protection Configuration

**POST** `/API/L4/tcp_syn`

Configure TCP SYN flood protection.

**Request:**
```json
{
  "token": "your_token",
  "status": "enable|disable",
  "threshold": 200000,
  "burst_pkt": 20,
  "burst_counter": 10,
  "fixed_threshold": 2000,
  "fixed_duration": 15,
  "challenge_timeout": 3,
  "protection_duration": 60
}
```

Similar endpoints:
- `/API/L4/tcp_ack` - TCP ACK protection
- `/API/L4/tcp_rst` - TCP RST protection
- `/API/L4/icmp` - ICMP protection
- `/API/L4/udp` - UDP protection
- `/API/L4/gre` - GRE protection

#### IP Management

**POST** `/API/L4/add_block_ip`

Add IP to blocklist.

**Request:**
```json
{
  "token": "your_token",
  "ip": "192.168.1.100",
  "duration": 3600
}
```

**POST** `/API/L4/remove_block_ip`

Remove IP from blocklist.

**Request:**
```json
{
  "token": "your_token",
  "ip": "192.168.1.100"
}
```

**POST** `/API/L4/remove_block_ip_all`

Remove all IPs from blocklist.

**POST** `/API/L4/add_white_ip`

Add IP to whitelist.

**POST** `/API/L4/remove_white_ip`

Remove IP from whitelist.

**POST** `/API/L4/get_blocklist`

Query blocklist with filters.

**Request:**
```json
{
  "token": "your_token",
  "filter_type": "SYN|ACK|RST|ICMP|UDP|GRE|x",
  "filter_ip": "192.168.1.100|x",
  "filter_date": "2025-11-20|x"
}
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "ip": "192.168.1.100",
      "type": "SYN",
      "duration": 3600,
      "reason": "Flood attack detected",
      "created": "2025-11-20 10:30:00",
      "timestamp": "2025-11-20 10:30:00"
    }
  ]
}
```

#### Advanced Features

**POST** `/API/L4/tcp_seg`

Enable/disable TCP segment checking.

**POST** `/API/L4/tcp_geo`

Configure geo-location filtering.

**POST** `/API/L4/tcp_con_limit`

Set TCP connection limit.

### L7 Firewall Endpoints

#### Firewall Control

**POST** `/API/L7/firewall_main`

Start, stop, or restart L7 firewall (OpenResty).

**Request:**
```json
{
  "token": "your_token",
  "status": "start|stop|restart"
}
```

#### Request Method Filtering

**POST** `/API/L7/allow_request_method`

Configure allowed HTTP methods.

**Request:**
```json
{
  "token": "your_token",
  "methods": ["GET", "POST", "PUT", "DELETE"]
}
```

**GET** `/API/L7/allow_request_method`

Get current allowed methods.

#### Backend Management

**POST** `/API/L7/backend_list`

Configure backend servers.

**Request:**
```json
{
  "token": "your_token",
  "backends": [
    {
      "name": "backend1",
      "ip": "192.168.1.10",
      "port": 8080,
      "weight": 100
    }
  ]
}
```

**GET** `/API/L7/backend_list`

Get current backend configuration.

#### ACL System

**POST** `/API/L7/acl_system_config`

Configure ACL system settings.

**POST** `/API/L7/set_acl`

Set ACL rules.

**POST** `/API/L7/acl_rule_management`

Manage ACL rules (add, update, delete).

**POST** `/API/L7/acl_rule_apply`

Apply ACL rules to Nginx configuration.

#### Port Configuration

**POST** `/API/L7/set_ports`

Configure listening ports.

**Request:**
```json
{
  "token": "your_token",
  "ports": [80, 443, 8080]
}
```

### Common Endpoints

**POST** `/API/common/health_check`

Health check endpoint.

**Request:**
```json
{
  "token": "your_token"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "API parser is running",
  "timestamp": "2025-11-20T10:30:00"
}
```

**POST** `/API/common/get_config`

Get current configuration.

## Usage Examples

### Starting the Firewall

```bash
# Start L4 firewall
curl -X POST http://localhost:5000/API/L4/firewall_main \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_token",
    "status": "start",
    "interface": "eth0",
    "attach_mode": "native"
  }'

# Start L7 firewall
curl -X POST http://localhost:5000/API/L7/firewall_main \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_token",
    "status": "start"
  }'
```

### Configuring TCP SYN Protection

```bash
curl -X POST http://localhost:5000/API/L4/tcp_syn \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_token",
    "status": "enable",
    "threshold": 200000,
    "burst_pkt": 20,
    "burst_counter": 10,
    "fixed_threshold": 2000,
    "fixed_duration": 15,
    "challenge_timeout": 3,
    "protection_duration": 60
  }'
```

### Adding IP to Blocklist

```bash
curl -X POST http://localhost:5000/API/L4/add_block_ip \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_token",
    "ip": "192.168.1.100",
    "duration": 3600
  }'
```

### Querying Blocklist

```bash
curl -X POST http://localhost:5000/API/L4/get_blocklist \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_token",
    "filter_type": "SYN",
    "filter_ip": "x",
    "filter_date": "2025-11-20"
  }'
```

### Python Client Example

```python
import requests

API_BASE = "http://localhost:5000/API"
TOKEN = "your_token"

# Start firewall
response = requests.post(
    f"{API_BASE}/L4/firewall_main",
    json={
        "token": TOKEN,
        "status": "start",
        "interface": "eth0",
        "attach_mode": "native"
    }
)
print(response.json())

# Configure SYN protection
response = requests.post(
    f"{API_BASE}/L4/tcp_syn",
    json={
        "token": TOKEN,
        "status": "enable",
        "threshold": 200000,
        "burst_pkt": 20,
        "burst_counter": 10,
        "fixed_threshold": 2000,
        "fixed_duration": 15,
        "challenge_timeout": 3,
        "protection_duration": 60
    }
)
print(response.json())
```

## Service Management

### Systemd Services

The installation creates the following systemd services:

- **`api_parser.service`**: REST API service
- **`l4_firewall.service`**: L4 eBPF firewall (optional)

### Managing Services

```bash
# Start API parser
sudo systemctl start api_parser

# Stop API parser
sudo systemctl stop api_parser

# Restart API parser
sudo systemctl restart api_parser

# Enable auto-start on boot
sudo systemctl enable api_parser

# Check status
sudo systemctl status api_parser

# View logs
sudo journalctl -u api_parser -f

# View last 100 lines
sudo journalctl -u api_parser -n 100
```

### Manual CLI Commands (L4 Firewall)

```bash
# Restart firewall
sudo l4_firewall_cli RESTART_FW

# Reload configuration
sudo l4_firewall_cli RELOAD_FW

# Clear statistics
sudo l4_firewall_cli CLEAR_FW

# View statistics
sudo l4_firewall_cli STATS_FW

# List blocked IPs
sudo l4_firewall_cli LIST_IP

# Clear specific IP
sudo l4_firewall_cli CLEAR_IP 192.168.1.100

# Clear all IPs
sudo l4_firewall_cli CLEAR_IP_ALL

# Add IP to blocklist
sudo l4_firewall_cli ADD_IP 192.168.1.100 3600
```

## Troubleshooting

### API Parser Issues

**Service won't start:**
```bash
# Check service status
sudo systemctl status api_parser

# Check logs
sudo journalctl -u api_parser -n 50

# Verify Python venv
ls -la /usr/local/share/api_parser/venv

# Check permissions
ls -la /usr/local/share/api_parser
```

**Missing .so files:**
```bash
# Verify .so files exist
find /usr/local/share/api_parser -name "*.so"

# Rebuild .so files (if needed)
cd /usr/local/share/api_parser
source venv/bin/activate
python setup.py build_ext --inplace
```

**Database errors:**
```bash
# Check database file
ls -la /usr/local/share/dorian/sparta/firewall_control.db

# Verify database permissions
sudo chown root:root /usr/local/share/dorian/sparta/firewall_control.db
sudo chmod 644 /usr/local/share/dorian/sparta/firewall_control.db
```

### L4 Firewall Issues

**XDP program won't attach:**
```bash
# Check kernel version (requires 5.10+)
uname -r

# Check XDP support
ip link show eth0 | grep xdp

# Try different attach mode
# Edit firewall.config: attach_mode = skb (fallback)
```

**Interface not found:**
```bash
# List available interfaces
ip link show

# Update firewall.config with correct interface name
```

**Permission denied:**
```bash
# Ensure running as root
sudo l4_firewall_cli STATS_FW

# Check binary permissions
ls -la /usr/local/bin/l4_firewall_cli
```

### L7 Firewall Issues

**OpenResty not starting:**
```bash
# Check OpenResty status
sudo systemctl status openresty

# Test Nginx configuration
sudo /usr/local/openresty/nginx/sbin/nginx -t

# Check error logs
sudo tail -f /usr/local/openresty/nginx/logs/error.log
```

**ACL rules not applying:**
```bash
# Verify configuration files
ls -la /usr/local/openresty/nginx/conf/

# Check Lua module loading
sudo tail -f /usr/local/openresty/nginx/logs/error.log | grep lua
```

### Network Issues

**Can't connect to API:**
```bash
# Check if service is listening
sudo netstat -tlnp | grep 5000

# Check firewall rules
sudo iptables -L -n

# Test local connection
curl http://localhost:5000/API/common/health_check \
  -H "Content-Type: application/json" \
  -d '{"token": "your_token"}'
```

**SSL certificate errors:**
- The API client disables SSL verification by default (for expired certificates)
- To re-enable, edit `core/api_client.py` and remove `verify=False` parameters

## Development

### Project Structure

The API parser uses a modular architecture with Cython compilation:

- **Source files**: Python modules in `core/`, `routes/`, `utils/`
- **Compiled files**: `.so` files generated during installation
- **Entry point**: `app.py` (minimal wrapper)

### Building from Source

```bash
# Clone repository
git clone <repository-url>
cd ddos-firewall

# Set up development environment
cd api_parser
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Build .so files
python setup.py build_ext --inplace

# Run in development mode
python app.py
```

### Code Organization

- **`core/`**: Business logic (database, firewall, nginx operations)
- **`routes/`**: Flask route handlers (L4, L7, common endpoints)
- **`utils/`**: Utility functions (authentication, validation)
- **`config.py`**: Centralized configuration

### Testing

```bash
# Test API endpoints
curl -X POST http://localhost:5000/API/common/health_check \
  -H "Content-Type: application/json" \
  -d '{"token": "test_token"}'

# Test L4 firewall
curl -X POST http://localhost:5000/API/L4/firewall_main \
  -H "Content-Type: application/json" \
  -d '{"token": "test_token", "status": "start", "interface": "eth0"}'
```

### Debugging

```bash
# Enable debug logging
# Edit config.py: Set appropriate log levels

# View real-time logs
sudo journalctl -u api_parser -f

# Check Python errors
sudo journalctl -u api_parser | grep -i error
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Make your changes**: Follow existing code style
4. **Test thoroughly**: Ensure all tests pass
5. **Submit a pull request**: Include description of changes

### Code Style

- Follow PEP 8 for Python code
- Use type hints where appropriate
- Add docstrings to functions and classes
- Keep functions focused and modular

### Reporting Issues

When reporting issues, please include:

- OS and kernel version
- Python version
- Error messages and logs
- Steps to reproduce
- Expected vs actual behavior

## License

This project is licensed under the GPL License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- **Issues**: Open an issue on GitHub
- **Documentation**: Check the `setup/` folder for detailed setup guides
- **Logs**: Check systemd journal logs for error details

## Acknowledgments

- eBPF/XDP technology for high-performance packet processing
- OpenResty for L7 protection capabilities
- Flask/Gunicorn for the REST API framework

---

**Note**: This firewall system operates at kernel level and requires root privileges. Use with caution and ensure proper security practices.
