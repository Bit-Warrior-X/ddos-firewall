# Setup Folder Update Summary

## Changes Made

The setup folder has been updated to support the modular api_parser structure with compiled .so files.

### 1. Updated `setup/payload/api_parser/` Structure

**Before:**
- Monolithic `app.py` (2,399 lines)
- Single `l7_nginx_config.py` file
- No modular structure

**After:**
```
setup/payload/api_parser/
├── app.py                    # Minimal wrapper (14 lines)
├── config.py                 # Configuration module
├── setup.py                  # Cython build configuration
├── build.sh                  # Build script
├── requirements.txt          # Includes Cython
├── api_parser.service        # Updated to use Gunicorn
├── core/                     # Core modules
│   ├── __init__.py
│   ├── app_factory.py
│   ├── database.py
│   ├── firewall.py
│   ├── api_client.py
│   ├── nginx_ops.py
│   ├── nginx_parser.py
│   └── ...
├── routes/                   # Route handlers
│   ├── __init__.py
│   ├── l4_routes.py
│   ├── l7_routes.py
│   └── common_routes.py
└── utils/                    # Utilities
    ├── __init__.py
    ├── auth.py
    ├── nginx_utils.py
    └── validators.py
```

### 2. Updated `api_parser.service`

**Changes:**
- ✅ Now uses Gunicorn instead of Flask dev server
- ✅ Configured with 2 workers, 4 threads per worker
- ✅ Proper production settings (timeout, graceful shutdown)
- ✅ Creates FIFO pipe if missing
- ✅ Type changed to `notify` for better service management

**Before:**
```ini
ExecStart= /usr/local/share/api_parser/venv/bin/python app.py
```

**After:**
```ini
ExecStart=/usr/local/share/api_parser/venv/bin/python -m gunicorn \
          -w 2 -k gthread --threads 4 \
          -b 0.0.0.0:5000 \
          --timeout 60 --graceful-timeout 15 \
          app:app
```

### 3. Updated `installer_stub.sh`

**Added build step in `prepare_api_parser_venv()`:**
- After installing Python dependencies, automatically builds .so files
- Uses `build.sh` if available, otherwise falls back to `setup.py`
- Continues installation even if build fails (with warning)

**New code:**
```bash
# Build .so files if setup.py exists (modular structure with Cython)
if [[ -f "${INSTALL_API_PARSER_DIR}/setup.py" ]]; then
    print_status "Building compiled modules (.so files)..."
    cd "${INSTALL_API_PARSER_DIR}"
    if [[ -f "${INSTALL_API_PARSER_DIR}/build.sh" ]]; then
        chmod +x "${INSTALL_API_PARSER_DIR}/build.sh"
        "${INSTALL_API_PARSER_DIR}/build.sh" || print_warning "Build script failed, continuing anyway"
    else
        "${VENV_DIR}/bin/python" setup.py build_ext --inplace || print_warning "setup.py build failed, continuing anyway"
    fi
    print_status "Module compilation complete"
fi
```

### 4. Updated `pack.sh`

**Changes:**
- Added optional pre-build step for .so files
- Can be enabled with `BUILD_SO=1 ./pack.sh`
- Cleans up build artifacts before packaging
- Better documentation

**Note:** By default, .so files are built during installation (on target system) to ensure architecture compatibility. Pre-building is optional.

### 5. Updated `requirements.txt`

**Added build dependencies:**
```txt
Cython>=3.0.0
setuptools>=68.0.0
wheel>=0.41.0
```

## Installation Flow

1. **Extract payload** → `installer_stub.sh` extracts files
2. **Copy api_parser** → Files copied to `/usr/local/share/api_parser/`
3. **Create venv** → Python virtual environment created
4. **Install dependencies** → From `requirements.txt` (includes Cython)
5. **Build .so files** → Automatically compiles modules during installation
6. **Install service** → Systemd service file installed
7. **Start service** → Gunicorn starts with compiled modules

## Benefits

1. ✅ **Modular Structure**: Easier to maintain and test
2. ✅ **Code Protection**: Compiled .so files protect source code
3. ✅ **Production Ready**: Uses Gunicorn instead of dev server
4. ✅ **Automatic Build**: .so files built during installation
5. ✅ **Better Error Handling**: Fixed integer conversion bugs
6. ✅ **Scalable**: Multiple workers and threads for better performance

## Testing

To test the updated setup:

1. **Build the installer:**
   ```bash
   cd ddos-firewall/setup
   ./pack.sh
   ```

2. **Run installation:**
   ```bash
   sudo ./setup.sh
   ```

3. **Check service:**
   ```bash
   sudo systemctl status api_parser
   sudo journalctl -u api_parser -f
   ```

4. **Verify .so files:**
   ```bash
   find /usr/local/share/api_parser -name "*.so"
   ```

## Notes

- `.so` files are built **during installation** by default (ensures correct architecture)
- Pre-building with `BUILD_SO=1` is optional (requires matching architecture)
- The service automatically creates the FIFO pipe if missing
- All Python source files are included for fallback if compilation fails

