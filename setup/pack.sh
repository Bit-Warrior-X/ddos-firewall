#!/bin/bash
# pack.sh - Package the payload and create self-extracting installer

set -e

PAYLOAD_API_DIR="payload/angelos"
PAYLOAD_L4_DIR="payload/sparta"

# Make sure installer_stub.sh is executable
chmod +x installer_stub.sh

# Clean up old build artifacts
rm -rf /usr/local/openresty/nginx/logs/*
rm -rf /usr/local/openresty/nginx/sbin/nginx.old
rm -rf payload/l7/openresty.tar.gz

# Save current directory (setup/)
SETUP_DIR="$(pwd)"

# Build api_parser .so files before packaging
echo "Building api_parser .so files..."
# Use realpath to normalize the path (resolve ..)
if command -v realpath >/dev/null 2>&1; then
    API_PARSER_DIR="$(realpath "${SETUP_DIR}/../api_parser")"
else
    # Fallback: use cd to resolve path
    API_PARSER_DIR="$(cd "${SETUP_DIR}/../api_parser" && pwd)"
fi
if [[ -d "${API_PARSER_DIR}" ]]; then
    cd "${API_PARSER_DIR}"
    
    # Clean previous builds
    rm -rf build/ dist/ *.egg-info
    find . -name "*.so" -delete
    find . -name "*.c" -delete
    
    # Check if venv exists, if not create it
    if [[ ! -d "venv" ]]; then
        echo "Creating Python venv for build..."
        python3 -m venv venv
    fi
    
    # Check if Cython is working, if not recreate venv
    if ! venv/bin/python -c "import Cython; from Cython.Build import cythonize" 2>/dev/null; then
        echo "Cython installation appears broken, recreating venv..."
        rm -rf venv
        python3 -m venv venv
    fi
    
    # Install build dependencies
    echo "Installing build dependencies..."
    venv/bin/pip install --upgrade pip setuptools wheel >/dev/null 2>&1
    echo "Installing Cython (this may take a moment)..."
    venv/bin/pip install --force-reinstall --no-cache-dir Cython || {
        echo "Warning: Cython install with --no-cache-dir failed, trying normal install..."
        venv/bin/pip install --force-reinstall Cython
    }
    
    # Verify Cython installation works
    echo "Verifying Cython installation..."
    if ! venv/bin/python -c "import Cython; from Cython.Build import cythonize; print('Cython OK')" 2>/dev/null; then
        echo "Error: Cython installation is corrupted or incomplete!"
        echo "Trying to fix by reinstalling..."
        venv/bin/pip uninstall -y Cython
        venv/bin/pip install Cython
        # Final check
        if ! venv/bin/python -c "import Cython; from Cython.Build import cythonize" 2>/dev/null; then
            echo "Error: Cython installation failed. Please install Cython manually:"
            echo "  cd ${API_PARSER_DIR} && python3 -m venv venv && venv/bin/pip install Cython"
            exit 1
        fi
    fi
    
    # Build .so files
    echo "Compiling Python modules to .so files..."
    venv/bin/python setup.py build_ext --inplace
    
    if [[ $? -ne 0 ]]; then
        echo "Error: Build failed! Cannot package without .so files."
        exit 1
    fi
    
    # Verify .so files were created
    SO_COUNT=$(find . -name "*.so" -type f | wc -l)
    if [[ $SO_COUNT -eq 0 ]]; then
        echo "Error: No .so files found after build!"
        exit 1
    fi
    
    echo "Build complete! Found $SO_COUNT .so files"
    
    # Return to setup directory
    cd "${SETUP_DIR}"
else
    echo "Error: api_parser directory not found at ${API_PARSER_DIR}!"
    echo "Make sure you're running pack.sh from the setup/ directory"
    exit 1
fi

# Clean payload/angelos and copy only necessary files
echo "Preparing ${PAYLOAD_API_DIR} with .so files only..."
rm -rf "${PAYLOAD_API_DIR}"
mkdir -p "${PAYLOAD_API_DIR}"

# Ensure we're back in setup directory
cd "${SETUP_DIR}"

# Copy essential files (using absolute path)
if [[ -f "${API_PARSER_DIR}/app.py" ]]; then
    cp "${API_PARSER_DIR}/app.py" "${PAYLOAD_API_DIR}/"
else
    echo "Error: ${API_PARSER_DIR}/app.py not found!"
    exit 1
fi

if [[ -f "${API_PARSER_DIR}/config.py" ]]; then
    cp "${API_PARSER_DIR}/config.py" "${PAYLOAD_API_DIR}/"
else
    echo "Error: ${API_PARSER_DIR}/config.py not found!"
    exit 1
fi

if [[ -f "${API_PARSER_DIR}/requirements.txt" ]]; then
    cp "${API_PARSER_DIR}/requirements.txt" "${PAYLOAD_API_DIR}/"
fi

if [[ -f "${API_PARSER_DIR}/api_parser.service" ]]; then
    cp "${API_PARSER_DIR}/api_parser.service" "${PAYLOAD_API_DIR}/angelos.service"
fi

# Copy .so files and __init__.py files (needed for package imports)
# Exclude venv, __pycache__, build directories
echo "Copying .so files..."
find "${API_PARSER_DIR}" -name "*.so" -type f -not -path "*/venv/*" -not -path "*/__pycache__/*" -not -path "*/build/*" | while read -r file; do
    # Strip the ../api_parser/ prefix and copy to payload/angelos/
    rel_path="${file#${API_PARSER_DIR}/}"
    mkdir -p "${PAYLOAD_API_DIR}/$(dirname "$rel_path")"
    cp "$file" "${PAYLOAD_API_DIR}/$rel_path"
done

# Copy __init__.py files (needed for Python package structure)
# Exclude venv, __pycache__, build directories
echo "Copying __init__.py files..."
find "${API_PARSER_DIR}" -name "__init__.py" -type f -not -path "*/venv/*" -not -path "*/__pycache__/*" -not -path "*/build/*" | while read -r file; do
    # Strip the ../api_parser/ prefix and copy to payload/angelos/
    rel_path="${file#${API_PARSER_DIR}/}"
    mkdir -p "${PAYLOAD_API_DIR}/$(dirname "$rel_path")"
    cp "$file" "${PAYLOAD_API_DIR}/$rel_path"
done

# Clean up: Remove any venv, __pycache__, build directories that might have been copied
echo "Cleaning up build artifacts from payload..."
find "${PAYLOAD_API_DIR}" -type d \( -name "venv" -o -name "__pycache__" -o -name "build" -o -name "dist" -o -name "*.egg-info" \) -exec rm -rf {} + 2>/dev/null || true
find "${PAYLOAD_API_DIR}" -name "*.c" -type f -delete 2>/dev/null || true

# Rename payload/l4 to payload/sparta for package naming
if [[ -d "payload/l4" ]]; then
    rm -rf "${PAYLOAD_L4_DIR}"
    cp -a "payload/l4" "${PAYLOAD_L4_DIR}"
    rm -rf "payload/l4"
fi

# Normalize L4 service names in payload/sparta/service
if [[ -f "${PAYLOAD_L4_DIR}/service/ebpf_firewall.service" ]]; then
    cp -f "${PAYLOAD_L4_DIR}/service/ebpf_firewall.service" "${PAYLOAD_L4_DIR}/service/sparta.service"
elif [[ -f "${PAYLOAD_L4_DIR}/service/ebpf-firewall.service" ]]; then
    cp -f "${PAYLOAD_L4_DIR}/service/ebpf-firewall.service" "${PAYLOAD_L4_DIR}/service/sparta.service"
fi

if [[ -f "${PAYLOAD_L4_DIR}/service/ebpf_firewall_prometheus.service" ]]; then
    cp -f "${PAYLOAD_L4_DIR}/service/ebpf_firewall_prometheus.service" "${PAYLOAD_L4_DIR}/service/sparta-prometheus.service"
elif [[ -f "${PAYLOAD_L4_DIR}/service/ebpf-firewall-prometheus.service" ]]; then
    cp -f "${PAYLOAD_L4_DIR}/service/ebpf-firewall-prometheus.service" "${PAYLOAD_L4_DIR}/service/sparta-prometheus.service"
fi

# Verify payload structure
echo ""
echo "Payload structure:"
echo "  angelos Python files: $(find "${PAYLOAD_API_DIR}" -name "*.py" -type f | wc -l)"
echo "  angelos .so files: $(find "${PAYLOAD_API_DIR}" -name "*.so" -type f | wc -l)"
echo "  angelos venv dirs: $(find "${PAYLOAD_API_DIR}" -type d -name "venv" 2>/dev/null | wc -l) (should be 0)"
echo "  sparta files: $(find "${PAYLOAD_L4_DIR}" -type f 2>/dev/null | wc -l)"
echo ""

# Package OpenResty
echo "Packaging OpenResty..."
tar -zcf payload/l7/openresty.tar.gz -C /usr/local openresty

# Create self-extracting setup.sh
echo "Creating self-extracting installer..."
{
  cat installer_stub.sh
  tar -czf - -C payload . | base64 -w 0
  echo
} > setup.sh

# Make setup.sh executable
chmod +x setup.sh

echo "Packaging complete! Created setup.sh"
echo ""
echo "Payload contains:"
echo "  - Compiled .so files (no Python source)"
echo "  - app.py (entry point)"
echo "  - config.py (configuration)"
echo "  - __init__.py files (package structure)"
