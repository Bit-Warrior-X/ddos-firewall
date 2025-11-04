#!/bin/bash

# Setup script for myapp / ebpf_firewall bundle
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
LIB_DIR="/usr/local/lib"
L4_APP_NAME="ebpf_firewall"

INSTALL_L4_DIR="/usr/local/share/ebpf_firewall"
INSTALL_API_PARSER_DIR="/usr/local/share/api_parser"

L4_SERVICE_NAME="ebpf_firewall.service"
L7_SERVICE_NAME="l7_firewall.service"
L4_PROM_SERVICE_NAME="ebpf_firewall_prometheus.service"
API_PARSER_SERVICE_NAME="api_parser.service"
REDIS_SERVER_SERVICE_NAME="redis-server.service"


# Function to print colored output
print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Extract embedded files (supports base64-encoded payload or raw tar.gz payload)
extract_files() {
    print_status "Extracting embedded files..."

    # Find the line number where the payload starts
    PAYLOAD_START_LINE=$(grep -n "^__PAYLOAD_START__$" "$0" | cut -d: -f1 || true)

    if [[ -z "$PAYLOAD_START_LINE" ]]; then
        print_error "Could not find payload start marker (__PAYLOAD_START__)"
        exit 1
    fi

    TMPDIR="$(mktemp -d /tmp/installer.XXXXXX)"
    # ensure we clean up if script exits unexpectedly; but don't delete until end of script
    trap 'rm -rf "${TMPDIR}"' EXIT

    # Try decode-as-base64 then tar; if that fails, try raw tar (some packers append raw tar)
    tail -n +"$((PAYLOAD_START_LINE + 1))" "$0" > "${TMPDIR}/payload.bin"

    set +e
    ( base64 -d "${TMPDIR}/payload.bin" 2>/dev/null | tar -xz -C "${TMPDIR}" ) >/dev/null 2>&1
    RC=$?
    set -e

    if [[ $RC -ne 0 ]]; then
        # try raw tar.gz
        if tar -tzf "${TMPDIR}/payload.bin" >/dev/null 2>&1; then
            tar -xzf "${TMPDIR}/payload.bin" -C "${TMPDIR}"
        else
            print_error "Failed to extract payload (not base64 or tar.gz)."
            exit 1
        fi
    fi

    print_status "Payload extracted to ${TMPDIR}"
    # Return path to extracted payload via global variable
    EXTRACTED_DIR="${TMPDIR}"
}

# Set permissions (as you requested)
set_permissions() {
    print_status "Setting permissions..."

    # Only change if files exist
    [[ -d "${EXTRACTED_DIR}/lib" ]] && chmod 777 "${EXTRACTED_DIR}/lib/"* || true
    [[ -d "${EXTRACTED_DIR}/l4/helper" ]] && chmod 777 "${EXTRACTED_DIR}/l4/helper/"* || true
    [[ -f "${EXTRACTED_DIR}/l4/bin/ebpf_firewall_cli" ]] && chmod 777 "${EXTRACTED_DIR}/l4/bin/ebpf_firewall_cli"
    [[ -f "${EXTRACTED_DIR}/l4/bin/ebpf_firewall_prom" ]] && chmod 777 "${EXTRACTED_DIR}/l4/bin/ebpf_firewall_prom"
    [[ -f "${EXTRACTED_DIR}/l4/bin/ebpf_firewall_userspace" ]] && chmod 777 "${EXTRACTED_DIR}/l4/bin/ebpf_firewall_userspace"
    [[ -f "${EXTRACTED_DIR}/machine_id" ]] && chmod 777 "${EXTRACTED_DIR}/machine_id"
    [[ -f "${EXTRACTED_DIR}/uninstall.sh" ]] && chmod 777 "${EXTRACTED_DIR}/uninstall.sh"

    # Reasonable perms for other files (if present)
    [[ -f "${EXTRACTED_DIR}/l4/firewall.config" ]] && chmod 644 "${EXTRACTED_DIR}/l4/firewall.config"
    [[ -f "${EXTRACTED_DIR}/l4/ebpf_firewall_kernel.o" ]] && chmod 644 "${EXTRACTED_DIR}/l4/ebpf_firewall_kernel.o"
    [[ -f "${EXTRACTED_DIR}/l4/firewall_control.db" ]] && chmod 644 "${EXTRACTED_DIR}/l4/firewall_control.db"
    [[ -d "${EXTRACTED_DIR}/l4/geodb" ]] && chmod -R 644 "${EXTRACTED_DIR}/l4/geodb" || true
}

# Create installation directory
create_directories() {
    print_status "Creating directories..."
    mkdir -p "$LIB_DIR"
    mkdir -p "$INSTALL_L4_DIR"
    mkdir -p "$INSTALL_API_PARSER_DIR"
    mkdir -p "/usr/lib/x86_64-linux-gnu"
    mkdir -p "/etc/ld.so.conf.d"
}

# Install files
install_files() {
    print_status "Installing application files..."

    echo "Installing Redis server..."
    apt install redis-server -y

    # Install L4 user binaries and data
    if [[ -d "${EXTRACTED_DIR}/l4" ]]; then
        print_status "Installing L4 ebpf_firewall..."
        cp -f "${EXTRACTED_DIR}/l4/bin/ebpf_firewall_cli" "${INSTALL_L4_DIR}/" 2>/dev/null || true
        cp -f "${EXTRACTED_DIR}/l4/bin/ebpf_firewall_prom" "${INSTALL_L4_DIR}/" 2>/dev/null || true
        cp -f "${EXTRACTED_DIR}/l4/bin/ebpf_firewall_userspace" "${INSTALL_L4_DIR}/" 2>/dev/null || true
        cp -f "${EXTRACTED_DIR}/machine_id" "${INSTALL_L4_DIR}/" 2>/dev/null || true
        cp -f "${EXTRACTED_DIR}/uninstall.sh" "/tmp/" 2>/dev/null || true

        cp -f "${EXTRACTED_DIR}/l4/ebpf_firewall_kernel.o" "${INSTALL_L4_DIR}/" 2>/dev/null || true
        cp -f "${EXTRACTED_DIR}/l4/firewall.config" "${INSTALL_L4_DIR}/" 2>/dev/null || true
        cp -f "${EXTRACTED_DIR}/l4/firewall_control.db" "${INSTALL_L4_DIR}/" 2>/dev/null || true
        cp -f "${EXTRACTED_DIR}/initialize" "${INSTALL_L4_DIR}/" 2>/dev/null || true

        if [[ -d "${EXTRACTED_DIR}/l4/geodb" ]]; then
            cp -a "${EXTRACTED_DIR}/l4/geodb" "${INSTALL_L4_DIR}/" 2>/dev/null || true
        fi
    else
        print_warning "l4 directory not present in payload; skipping L4 install"
    fi

    # Create symlink for CLI in /usr/sbin
    if [[ -f "${INSTALL_L4_DIR}/ebpf_firewall_cli" ]]; then
        ln -sf "${INSTALL_L4_DIR}/ebpf_firewall_cli" /usr/sbin/l4_firewall_cli
        print_status "Created symlink: /usr/sbin/l4_firewall_cli -> ${INSTALL_L4_DIR}/ebpf_firewall_cli"
    else
        print_warning "ebpf_firewall_cli not found in ${INSTALL_L4_DIR}, skipping symlink"
    fi
    
    # Install API parser: move extracted api_parser content into the install dir.
    if [[ -d "${EXTRACTED_DIR}/api_parser" ]]; then
        print_status "Installing API parser (copying files)..."
        # copy entire directory tree
        cp -a "${EXTRACTED_DIR}/api_parser/." "${INSTALL_API_PARSER_DIR}/"
    else
        # maybe payload provided api_parser.tar.gz instead of a directory
        if [[ -f "${EXTRACTED_DIR}/api_parser.tar.gz" ]]; then
            print_status "Found api_parser.tar.gz in payload; extracting to ${INSTALL_API_PARSER_DIR}"
            mkdir -p "${INSTALL_API_PARSER_DIR}"
            tar -xzf "${EXTRACTED_DIR}/api_parser.tar.gz" -C "${INSTALL_API_PARSER_DIR}"
        else
            print_warning "api_parser not found in payload"
        fi
    fi

    # Install OpenResty (L7)
    if [[ -f "${EXTRACTED_DIR}/l7/openresty.tar.gz" ]]; then
        print_status "Installing OpenResty..."
        mkdir -p /usr/local/openresty
        tar -xzf "${EXTRACTED_DIR}/l7/openresty.tar.gz" -C /usr/local/openresty --strip-components=1
        print_status "OpenResty extracted to /usr/local/openresty"
    else
        print_warning "l7/openresty.tar.gz not found in payload; skipping OpenResty install"
    fi
    
    # Create symlink for CLI in /usr/sbin
    if [[ -f "/usr/local/openresty/nginx/sbin/nginx" ]]; then
        ln -sf "/usr/local/openresty/nginx/sbin/nginx" /usr/sbin/nginx
        print_status "Created symlink: /usr/sbin/nginx -> /usr/local/openresty/nginx/sbin/nginx"
    else
        print_warning "nginx not found in /usr/local/openresty/nginx/sbin/, skipping symlink"
    fi

    # Install libraries into LIB_DIR
    print_status "Installing libraries..."
    if [[ -d "${EXTRACTED_DIR}/lib" ]]; then
        for f in "${EXTRACTED_DIR}/lib/"*; do
            [[ -f "$f" ]] || continue
            cp -f "$f" "${LIB_DIR}/"
            # if user requested 777 for libs, keep it (your earlier scripts used 777)
            chmod 777 "${LIB_DIR}/$(basename "$f")" || true
        done
    else
        print_warning "lib directory not present in payload; skipping libs copy"
    fi

    # Specific installs (libbpf, libmicrohttpd) - keep behaviour but be safe
    if [[ -f "${EXTRACTED_DIR}/lib/libbpf.so.1.6.0" ]]; then
        cp -f "${EXTRACTED_DIR}/lib/libbpf.so.1.6.0" "${LIB_DIR}/"
        (cd "${LIB_DIR}" && ln -sf "libbpf.so.1.6.0" "libbpf.so.1") || true
    fi

    if [[ -f "${EXTRACTED_DIR}/lib/libmicrohttpd.so.12.60.0" ]]; then
        cp -f "${EXTRACTED_DIR}/lib/libmicrohttpd.so.12.60.0" "/usr/lib/x86_64-linux-gnu/"
        (cd "/usr/lib/x86_64-linux-gnu" && ln -sf "libmicrohttpd.so.12.60.0" "libmicrohttpd.so.12") || true
    fi

    # Install firewall_lib.conf to ld.so.conf.d if provided
    if [[ -f "${EXTRACTED_DIR}/lib/firewall_lib.conf" ]]; then
        cp -f "${EXTRACTED_DIR}/lib/firewall_lib.conf" "/etc/ld.so.conf.d/"
        chmod 644 "/etc/ld.so.conf.d/firewall_lib.conf"
    fi

    # Install redis-server config
    if [[ -f "${EXTRACTED_DIR}/lib/redis-socket.conf" ]]; then
        cp -f "${EXTRACTED_DIR}/lib/redis-socket.conf" "/etc/redis/"
        chmod 644 "/etc/redis/redis-socket.conf"
    fi

    # Update library cache
    print_status "Updating library cache..."
    if command -v ldconfig >/dev/null 2>&1; then
        ldconfig || true
    fi
}

install_python_venv_pkg() {
  print_status "Attempting to install python3-venv (need ensurepip)..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y python3-venv python3-pip || return 1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3-virtualenv python3-pip || dnf install -y python3-venv python3-pip || return 1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3-virtualenv python3-pip || return 1
  elif command -v zypper >/dev/null 2>&1; then
    zypper install -y python3-virtualenv python3-pip || return 1
  else
    print_warning "No supported package manager found; please install python3-venv manually."
    return 1
  fi
}

# Setup API parser venv and pip packages
prepare_api_parser_venv() {
    print_status "Preparing api_parser Python environment..."

    VENV_DIR="${INSTALL_API_PARSER_DIR}/venv"
    PIP_BIN=""

    if [[ -d "${VENV_DIR}" && -x "${VENV_DIR}/bin/python" ]]; then
        PIP_BIN="${VENV_DIR}/bin/pip"
        print_status "Using existing virtualenv at ${VENV_DIR}"
    else
      if command -v python3 >/dev/null 2>&1; then
        print_status "Creating virtualenv at ${VENV_DIR}"
        if ! python3 -m venv "${VENV_DIR}" 2>/dev/null; then
          print_warning "python3 venv creation failed (likely missing ensurepip)."
          if install_python_venv_pkg; then
            print_status "Retrying virtualenv creation..."
            python3 -m venv "${VENV_DIR}"
          else
            print_error "Could not install python3-venv automatically. Install it and rerun."
            return 0
          fi
        fi
        PIP_BIN="${VENV_DIR}/bin/pip"
      else
        print_warning "python3 not found: cannot create venv; skipping Python setup"
        return 0
      fi
    fi

    # Upgrade pip/wheel/setuptools and install required packages
    if [[ -n "${PIP_BIN}" && -x "${PIP_BIN}" ]]; then
        print_status "Upgrading pip/setuptools/wheel in venv"
        "${PIP_BIN}" install --upgrade pip setuptools wheel || print_warning "pip upgrade failed"

        # If there is a requirements.txt in the api_parser, prefer that; otherwise install minimal deps
        if [[ -f "${INSTALL_API_PARSER_DIR}/requirements.txt" ]]; then
            print_status "Installing packages from requirements.txt"
            "${PIP_BIN}" install -r "${INSTALL_API_PARSER_DIR}/requirements.txt" || print_warning "pip install -r requirements.txt failed"
        else
            print_status "Installing minimal packages: requests flask gunicorn"
            "${PIP_BIN}" install requests flask gunicorn || print_warning "pip install minimal packages failed"
        fi
    else
        print_warning "No pip available in venv; skipping Python package installation"
    fi
}

# Install systemd service files and enable services
install_service() {
    print_status "Installing systemd services..."

    # Copy service files
    # L4 services (if present in payload under l4/service/)
    if [[ -f "${EXTRACTED_DIR}/l4/service/${L4_SERVICE_NAME}" ]]; then
        cp -f "${EXTRACTED_DIR}/l4/service/${L4_SERVICE_NAME}" "/etc/systemd/system/${L4_SERVICE_NAME}"
        chmod 644 "/etc/systemd/system/${L4_SERVICE_NAME}"
    else
        print_warning "${L4_SERVICE_NAME} not found in payload (l4/service/)"
    fi

    if [[ -f "${EXTRACTED_DIR}/l7/${L7_SERVICE_NAME}" ]]; then
        cp -f "${EXTRACTED_DIR}/l7/${L7_SERVICE_NAME}" "/etc/systemd/system/${L7_SERVICE_NAME}"
        chmod 644 "/etc/systemd/system/${L7_SERVICE_NAME}"
    else
        print_warning "${L7_SERVICE_NAME} not found in payload (l7/)"
    fi

    if [[ -f "${EXTRACTED_DIR}/l4/service/${L4_PROM_SERVICE_NAME}" ]]; then
        cp -f "${EXTRACTED_DIR}/l4/service/${L4_PROM_SERVICE_NAME}" "/etc/systemd/system/${L4_PROM_SERVICE_NAME}"
        chmod 644 "/etc/systemd/system/${L4_PROM_SERVICE_NAME}"
    else
        print_warning "${L4_PROM_SERVICE_NAME} not found in payload (l4/service/)"
    fi

    # api_parser service (may be at EXTRACTED_DIR/api_parser/${API_PARSER_SERVICE_NAME})
    if [[ -f "${EXTRACTED_DIR}/api_parser/${API_PARSER_SERVICE_NAME}" ]]; then
        cp -f "${EXTRACTED_DIR}/api_parser/${API_PARSER_SERVICE_NAME}" "/etc/systemd/system/${API_PARSER_SERVICE_NAME}"
        chmod 644 "/etc/systemd/system/${API_PARSER_SERVICE_NAME}"
    elif [[ -f "${EXTRACTED_DIR}/${API_PARSER_SERVICE_NAME}" ]]; then
        cp -f "${EXTRACTED_DIR}/${API_PARSER_SERVICE_NAME}" "/etc/systemd/system/${API_PARSER_SERVICE_NAME}"
        chmod 644 "/etc/systemd/system/${API_PARSER_SERVICE_NAME}"
    else
        print_warning "${API_PARSER_SERVICE_NAME} not found in payload"
    fi

    # redis-server service (may be at EXTRACTED_DIR/lib/${REDIS_SERVER_SERVICE_NAME})
    if [[ -f "${EXTRACTED_DIR}/lib/${REDIS_SERVER_SERVICE_NAME}" ]]; then
        cp -f "${EXTRACTED_DIR}/lib/${REDIS_SERVER_SERVICE_NAME}" "/etc/systemd/system/${REDIS_SERVER_SERVICE_NAME}"
        chmod 644 "/etc/systemd/system/${REDIS_SERVER_SERVICE_NAME}"
    elif [[ -f "${EXTRACTED_DIR}/${REDIS_SERVER_SERVICE_NAME}" ]]; then
        cp -f "${EXTRACTED_DIR}/${REDIS_SERVER_SERVICE_NAME}" "/etc/systemd/system/${REDIS_SERVER_SERVICE_NAME}"
        chmod 644 "/etc/systemd/system/${REDIS_SERVER_SERVICE_NAME}"
    else
        print_warning "${REDIS_SERVER_SERVICE_NAME} not found in payload"
    fi


    # Reload systemd and enable/start services (only those we copied)
    print_status "Reloading systemd daemon..."
    systemctl daemon-reload || true

    if [[ -f "/etc/systemd/system/${L4_SERVICE_NAME}" ]]; then
        systemctl enable "${L4_SERVICE_NAME}" || print_warning "Failed to enable/start ${L4_SERVICE_NAME}"
    fi

    if [[ -f "/etc/systemd/system/${L7_SERVICE_NAME}" ]]; then
        systemctl enable "${L7_SERVICE_NAME}" || print_warning "Failed to enable/start ${L7_SERVICE_NAME}"
    fi

    if [[ -f "/etc/systemd/system/${L4_PROM_SERVICE_NAME}" ]]; then
        systemctl enable "${L4_PROM_SERVICE_NAME}" || print_warning "Failed to enable/start ${L4_PROM_SERVICE_NAME}"
    fi

    if [[ -f "/etc/systemd/system/${REDIS_SERVER_SERVICE_NAME}" ]]; then
        systemctl enable "${REDIS_SERVER_SERVICE_NAME}" || print_warning "Failed to enable/start ${REDIS_SERVER_SERVICE_NAME}"
        systemctl restart "${REDIS_SERVER_SERVICE_NAME}"
    fi

    
    print_status "Service installation steps complete."
}

# Cleanup: remove only extracted payload directory (do not remove system dirs)
cleanup() {
    print_status "Cleaning up temporary extracted files..."
    # EXTRACTED_DIR is under /tmp (created by mktemp) — remove it
    if [[ -n "${EXTRACTED_DIR:-}" && -d "${EXTRACTED_DIR}" ]]; then
        rm -rf "${EXTRACTED_DIR}"
        print_status "Removed temp dir ${EXTRACTED_DIR}"
    fi
}

# Main installation function
main() {
    print_status "Starting ${L4_APP_NAME} installation..."

    check_root
    extract_files
    set_permissions
    create_directories
    install_files

    # Prepare api_parser python venv and packages (newly added)
    prepare_api_parser_venv

    install_service

    cleanup

    print_status "Installation completed successfully!"
    echo ""
    print_status "Installation summary:"
    echo "  - L4 application installed to: $INSTALL_L4_DIR"
    echo "  - API parser installed to: $INSTALL_API_PARSER_DIR"
    echo "  - Libraries installed to: $LIB_DIR"
    echo "  - Systemd services installed (if present): $L4_SERVICE_NAME, $L7_SERVICE_NAME, $L4_PROM_SERVICE_NAME, $API_PARSER_SERVICE_NAME"
    echo ""
    print_status "To inspect api_parser logs: sudo journalctl -u ${API_PARSER_SERVICE_NAME} -f"
    print_status "To inspect L4 logs: sudo journalctl -u ${L4_SERVICE_NAME} -f"
    print_status "To inspect L7 logs: sudo journalctl -u ${L7_SERVICE_NAME} -f"
}

# Run main function
main "$@"

exit 0

# This marker indicates the start of the payload
__PAYLOAD_START__
