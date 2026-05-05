#!/bin/bash
# build.sh - Build script for compiling to .so files
# and staging runtime artifacts into setup/payload/angelos

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PAYLOAD_DIR="${PROJECT_ROOT}/setup/payload/angelos"
INSTALL_DIR="/usr/local/share/dorian/angelos"
VENV_DIR="${INSTALL_DIR}/venv"
SYSTEMD_SERVICE_DIR="/etc/systemd/system"

cd "${SCRIPT_DIR}"

echo "Building api_parser with Cython..."

# Clean previous builds
rm -rf build/ dist/ *.egg-info
find . -name "*.so" -delete
find . -name "*.c" -delete

# Install build dependencies (user-local to avoid root permission issues)
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  python3 -m pip install --upgrade setuptools wheel Cython
else
  python3 -m pip install --user --upgrade setuptools wheel Cython
fi

# Build
python3 setup.py build_ext --inplace

echo "Build complete! Compiled .so files are in:"
find . -name "*.so" -type f

# Stage payload files
echo ""
echo "Staging files into ${PAYLOAD_DIR} ..."
rm -rf "${PAYLOAD_DIR}"
mkdir -p "${PAYLOAD_DIR}"

# Essential runtime files
cp "${SCRIPT_DIR}/app.py" "${PAYLOAD_DIR}/"
if [[ -f "${SCRIPT_DIR}/config.py" ]]; then
  cp "${SCRIPT_DIR}/config.py" "${PAYLOAD_DIR}/"
elif [[ -f "${SCRIPT_DIR}/config.example.py" ]]; then
  echo "Note: config.py not found; staging config.example.py as config.py (set real config on deploy)."
  cp "${SCRIPT_DIR}/config.example.py" "${PAYLOAD_DIR}/config.py"
else
  echo "error: missing ${SCRIPT_DIR}/config.py and config.example.py" >&2
  exit 1
fi

if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
    cp "${SCRIPT_DIR}/requirements.txt" "${PAYLOAD_DIR}/"
fi

if [[ -f "${SCRIPT_DIR}/api_parser.service" ]]; then
    cp "${SCRIPT_DIR}/api_parser.service" "${PAYLOAD_DIR}/angelos.service"
fi

# Copy compiled extensions
find "${SCRIPT_DIR}" -name "*.so" -type f \
    -not -path "*/venv/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/build/*" \
    -not -path "*/dist/*" | while read -r file; do
    rel_path="${file#${SCRIPT_DIR}/}"
    mkdir -p "${PAYLOAD_DIR}/$(dirname "${rel_path}")"
    cp "${file}" "${PAYLOAD_DIR}/${rel_path}"
done

# Copy package markers
find "${SCRIPT_DIR}" -name "__init__.py" -type f \
    -not -path "*/venv/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/build/*" \
    -not -path "*/dist/*" | while read -r file; do
    rel_path="${file#${SCRIPT_DIR}/}"
    mkdir -p "${PAYLOAD_DIR}/$(dirname "${rel_path}")"
    cp "${file}" "${PAYLOAD_DIR}/${rel_path}"
done

echo "Payload staging complete:"
echo "  Python files: $(find "${PAYLOAD_DIR}" -name "*.py" -type f | wc -l)"
echo "  .so files: $(find "${PAYLOAD_DIR}" -name "*.so" -type f | wc -l)"
echo "  Target: ${PAYLOAD_DIR}"

if [[ "${DDOS_FW_CI_PAYLOAD_ONLY:-}" == "1" ]]; then
  echo "DDOS_FW_CI_PAYLOAD_ONLY=1: skipping local install, venv, and systemd."
  exit 0
fi

# Install to runtime directory as well
echo ""
echo "Installing files into ${INSTALL_DIR} ..."
rm -rf "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
cp -a "${PAYLOAD_DIR}/." "${INSTALL_DIR}/"
# Do not keep service file in dorian runtime folder
rm -f "${INSTALL_DIR}/angelos.service"

echo "Install complete:"
echo "  Python files: $(find "${INSTALL_DIR}" -name "*.py" -type f | wc -l)"
echo "  .so files: $(find "${INSTALL_DIR}" -name "*.so" -type f | wc -l)"
echo "  Target: ${INSTALL_DIR}"

# Ensure runtime venv exists and is up to date
echo ""
echo "Preparing runtime venv at ${VENV_DIR} ..."
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${VENV_DIR}"
fi
"${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel
if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
    "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
fi
echo "  Runtime venv ready"

# Install systemd service
if [[ -f "${SCRIPT_DIR}/api_parser.service" ]]; then
    echo ""
    echo "Installing systemd service: angelos.service"
    cp "${SCRIPT_DIR}/api_parser.service" "${SYSTEMD_SERVICE_DIR}/angelos.service"
    systemctl daemon-reload
    systemctl enable angelos.service >/dev/null 2>&1 || true
    echo "  Service installed to ${SYSTEMD_SERVICE_DIR}/angelos.service"
fi

# Optional: Remove .c files after build
# find . -name "*.c" -delete

