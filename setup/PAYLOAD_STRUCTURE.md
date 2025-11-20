# Payload Structure - .so Files Only

## Overview

The `setup/payload/api_parser/` folder now contains **only compiled .so files** and essential Python files, not the source code.

## Structure

```
payload/api_parser/
├── app.py                    # Entry point (imports from .so files)
├── config.py                 # Configuration (not compiled, regular Python)
├── requirements.txt          # Runtime dependencies (Cython filtered out during install)
├── api_parser.service        # Systemd service file
├── core/                     # Compiled modules
│   ├── __init__.py          # Package marker
│   ├── *.so                 # Compiled .so files (no .py source)
│   └── ...
├── routes/                   # Compiled route handlers
│   ├── __init__.py          # Package marker
│   ├── *.so                 # Compiled .so files (no .py source)
│   └── ...
└── utils/                    # Compiled utilities
    ├── __init__.py          # Package marker
    ├── *.so                 # Compiled .so files (no .py source)
    └── ...
```

## Files Included

### Python Source Files (Required)
- ✅ `app.py` - Entry point, imports from .so files
- ✅ `config.py` - Configuration constants (not compiled)
- ✅ `__init__.py` - Package markers for Python imports

### Compiled Files
- ✅ `*.so` - All compiled modules from core/, routes/, utils/

### Excluded Files
- ❌ `*.py` source files (except app.py, config.py, __init__.py)
- ❌ `setup.py` - Not needed at runtime
- ❌ `build.sh` - Not needed at runtime
- ❌ `venv/` - Created during installation
- ❌ `__pycache__/` - Generated at runtime
- ❌ `*.c` - Cython generated C files
- ❌ `build/` - Build artifacts

## Build Process

### During Packaging (`pack.sh`)

1. **Build .so files** in `api_parser/` directory
2. **Copy only necessary files** to `payload/api_parser/`:
   - app.py
   - config.py
   - requirements.txt
   - api_parser.service
   - All .so files
   - All __init__.py files

### During Installation (`installer_stub.sh`)

1. **Extract payload** → Files copied to `/usr/local/share/api_parser/`
2. **Create Python venv** → Virtual environment created
3. **Install dependencies** → From requirements.txt (Cython filtered out)
4. **Verify .so files** → Check that .so files are present
5. **Install service** → Systemd service installed
6. **Start service** → Service starts with pre-built .so files

## Benefits

1. ✅ **Code Protection** - Source code not exposed
2. ✅ **Faster Installation** - No compilation needed
3. ✅ **Smaller Payload** - Only compiled binaries
4. ✅ **Architecture Specific** - Built for target architecture during packaging

## Requirements

### Build Time (pack.sh)
- Python 3.8+
- Cython
- setuptools, wheel
- All Python source files

### Runtime (installer)
- Python 3.8+
- Flask, Gunicorn, requests, redis
- **No Cython needed** (filtered out during install)

## Verification

After packaging, verify payload:

```bash
# Check .so files
find setup/payload/api_parser -name "*.so" | wc -l

# Check Python files (should be minimal)
find setup/payload/api_parser -name "*.py" | grep -v __init__

# Should show only:
# - app.py
# - config.py
# - __init__.py files
```

## Notes

- `.so` files are **architecture-specific** - must be built on matching architecture
- `__init__.py` files are needed for Python to recognize directories as packages
- `config.py` is kept as source since it's just configuration constants
- `app.py` is kept as source since it's the entry point

