# Setup Folder - Installation Package Builder

This folder contains scripts and payload files for creating a self-extracting installer for the DDoS Firewall system.

## Structure

```
setup/
├── installer_stub.sh          # Main installation script (embedded in setup.sh)
├── pack.sh                     # Script to create the installer package
├── deploy.sh                   # Remote deployment script
├── payload/                    # Files to be packaged
│   ├── api_parser/            # Modular API parser (with .so compilation)
│   ├── l4/                    # L4 firewall binaries
│   ├── l7/                    # L7 firewall files
│   └── lib/                   # Shared libraries
└── setup.sh                   # Generated self-extracting installer
```

## Quick Start

### 1. Build the Installer

```bash
cd ddos-firewall/setup
./pack.sh
```

This creates `setup.sh` - a self-extracting installer.

### 2. Optional: Pre-build .so Files

If you want to pre-compile Python modules (requires matching architecture):

```bash
BUILD_SO=1 ./pack.sh
```

**Note:** By default, .so files are built during installation on the target system to ensure architecture compatibility.

### 3. Run Installation

On the target system:

```bash
sudo ./setup.sh
```

## API Parser Structure

The `payload/api_parser/` now uses a **modular structure**:

```
api_parser/
├── app.py                    # Minimal wrapper (14 lines)
├── config.py                 # Configuration
├── setup.py                  # Cython build config
├── build.sh                  # Build script
├── requirements.txt          # Dependencies (includes Cython)
├── api_parser.service        # Systemd service (uses Gunicorn)
├── core/                     # Core modules
│   ├── app_factory.py
│   ├── database.py
│   ├── firewall.py
│   └── ...
├── routes/                   # Route handlers
│   ├── l4_routes.py
│   ├── l7_routes.py
│   └── common_routes.py
└── utils/                    # Utilities
    ├── auth.py
    ├── nginx_utils.py
    └── validators.py
```

## Installation Process

1. **Extract payload** → Files extracted to temporary directory
2. **Copy files** → Files copied to installation directories
3. **Create Python venv** → Virtual environment created
4. **Install dependencies** → Packages from requirements.txt installed
5. **Build .so files** → Python modules compiled to .so files
6. **Install services** → Systemd service files installed
7. **Start services** → Services started automatically

## Key Features

### Modular API Parser
- ✅ Separated into `core/`, `routes/`, `utils/` modules
- ✅ Compiled to .so files for code protection
- ✅ Automatic build during installation
- ✅ Production-ready with Gunicorn

### Service Configuration
- ✅ Uses Gunicorn (2 workers, 4 threads each)
- ✅ Proper timeouts and graceful shutdown
- ✅ Automatic FIFO pipe creation
- ✅ Systemd integration

### Build System
- ✅ Automatic .so compilation during installation
- ✅ Optional pre-build for matching architectures
- ✅ Fallback to source if compilation fails

## Files Modified

1. **`payload/api_parser/`** - Updated to modular structure
2. **`payload/api_parser/api_parser.service`** - Uses Gunicorn
3. **`installer_stub.sh`** - Added .so build step
4. **`pack.sh`** - Added optional pre-build support

## Testing

After installation, verify:

```bash
# Check service status
sudo systemctl status api_parser

# Check logs
sudo journalctl -u api_parser -f

# Verify .so files
find /usr/local/share/api_parser -name "*.so"

# Test API
curl -X POST http://localhost:5000/API/health_check \
  -H "Content-Type: application/json" \
  -d '{"token": "your_token"}'
```

## Troubleshooting

### Build Fails During Installation
- Check Python version (requires 3.8+)
- Verify Cython is installed: `pip list | grep Cython`
- Check logs: `journalctl -u api_parser`
- Service will fallback to Python source files

### Service Won't Start
- Check service file: `cat /etc/systemd/system/api_parser.service`
- Check permissions: `ls -la /usr/local/share/api_parser`
- Check Python venv: `ls -la /usr/local/share/api_parser/venv`
- View logs: `journalctl -u api_parser -n 50`

### Missing .so Files
- .so files are built during installation
- If missing, check build logs in journalctl
- Service will use Python source files as fallback

## Documentation

- `SETUP_UPDATE_SUMMARY.md` - Detailed changes made
- `PAYLOAD_API_PARSER_REVIEW.md` - Review of old vs new structure

