#!/bin/bash
# uninstall.sh — Uninstaller for ebpf_firewall + api_parser bundle

set -euo pipefail

# ===== Config (match your installer) =====
INSTALL_L4_DIR="/usr/local/share/ebpf_firewall"
INSTALL_API_PARSER_DIR="/usr/local/share/api_parser"
LIB_DIR="/usr/local/lib"
USR_LIB64="/usr/lib/x86_64-linux-gnu"

L4_SERVICE_NAME="ebpf_firewall.service"
L4_PROM_SERVICE_NAME="ebpf_firewall_prometheus.service"
API_PARSER_SERVICE_NAME="api_parser.service"

CLI_SYMLINK="/usr/sbin/l4_firewall_cli"
LD_CONF_FILE="/etc/ld.so.conf.d/firewall_lib.conf"

# Known lib files deployed by installer (best-effort cleanup)
LIBBPF_VER="libbpf.so.1.6.0"
LIBBPF_LINK="libbpf.so.1"
LIBMHTTPD_VER="libmicrohttpd.so.12.60.0"
LIBMHTTPD_LINK="libmicrohttpd.so.12"

# OpenResty (remove only with flag)
OPENRESTY_DIR="/usr/local/openresty"

# ===== Colors =====
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ===== Flags / Args =====
DRY_RUN=0
ASSUME_YES=0
PURGE_LIBS=0
PURGE_OPENRESTY=0
KEEP_DATA=0

usage() {
  cat <<EOF
Usage: sudo $0 [options]

Options:
  --yes               Non-interactive, assume "yes" to prompts
  --dry-run           Show what would be removed, but don't change anything
  --purge-libs        Also remove libraries installed by the bundle:
                        - ${LIB_DIR}/${LIBBPF_VER} (+ ${LIBBPF_LINK} if it points to it)
                        - ${USR_LIB64}/${LIBMHTTPD_VER} (+ ${LIBMHTTPD_LINK} if it points to it)
                        - ${LD_CONF_FILE} and run ldconfig
  --purge-openresty   Also remove ${OPENRESTY_DIR} (if installed by you)
  --keep-data         Keep ${INSTALL_L4_DIR} and ${INSTALL_API_PARSER_DIR} (do not delete data/configs)
  -h, --help          Show this help

Defaults:
  - Removes systemd services and disables them
  - Removes ${CLI_SYMLINK}
  - Removes ${INSTALL_L4_DIR} and ${INSTALL_API_PARSER_DIR} (unless --keep-data)
  - Keeps libs and OpenResty unless purge flags are provided
EOF
}

for arg in "$@"; do
  case "$arg" in
    --yes) ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --purge-libs) PURGE_LIBS=1 ;;
    --purge-openresty) PURGE_OPENRESTY=1 ;;
    --keep-data) KEEP_DATA=1 ;;
    -h|--help) usage; exit 0 ;;
    *) error "Unknown argument: $arg"; usage; exit 1 ;;
  esac
done

require_root() {
  if [[ $EUID -ne 0 ]]; then
    error "Run as root: sudo $0"
    exit 1
  fi
}

confirm() {
  local prompt="$1"
  if [[ $ASSUME_YES -eq 1 ]]; then
    return 0
  fi
  read -r -p "$prompt [y/N]: " ans
  [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

do_run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "DRY-RUN: $*"
  else
    eval "$@"
  fi
}

stop_disable_service() {
  local svc="$1"
  #if systemctl list-unit-files | grep -q "^${svc}"; then
    info "Stopping ${svc} (if running)..."
    do_run "systemctl stop '${svc}' || true"
    info "Disabling ${svc}..."
    do_run "systemctl disable '${svc}' || true"
    info "Removing service file /etc/systemd/system/${svc} (if exists)..."
    if [[ -f "/etc/systemd/system/${svc}" ]]; then
      do_run "rm -f '/etc/systemd/system/${svc}'"
    fi
    do_run "systemctl daemon-reload"
  #else
  #  warn "Service ${svc} not registered — skipping"
  fi
}

remove_path() {
  local p="$1"
  if [[ -e "$p" || -L "$p" ]]; then
    info "Removing: $p"
    do_run "rm -rf '$p'"
  else
    warn "Not found: $p"
  fi
}

# ===== Uninstall Steps =====

require_root
info "Preparing to uninstall ebpf_firewall + api_parser"

if ! confirm "Proceed with uninstall?"; then
  info "Aborted."
  exit 0
fi

# 1) Stop/disable services and remove unit files
stop_disable_service "${API_PARSER_SERVICE_NAME}"
stop_disable_service "${L4_PROM_SERVICE_NAME}"
stop_disable_service "${L4_SERVICE_NAME}"

info "Reloading systemd daemon..."
do_run "systemctl daemon-reload || true"

# 2) Remove symlink/CLI
if [[ -L "${CLI_SYMLINK}" || -f "${CLI_SYMLINK}" ]]; then
  info "Removing CLI symlink ${CLI_SYMLINK}"
  do_run "rm -f '${CLI_SYMLINK}'"
else
  warn "CLI symlink not found: ${CLI_SYMLINK}"
fi

# 3) Remove installed directories (unless --keep-data)
if [[ $KEEP_DATA -eq 1 ]]; then
  warn "Keeping data/configs as requested (--keep-data). Skipping removal of:"
  echo "  - ${INSTALL_L4_DIR}"
  echo "  - ${INSTALL_API_PARSER_DIR}"
else
  remove_path "${INSTALL_L4_DIR}"
  remove_path "${INSTALL_API_PARSER_DIR}"
fi

# 4) (Optional) Purge libraries installed by the bundle
if [[ $PURGE_LIBS -eq 1 ]]; then
  info "Purging installed libraries and ld.so config"

  # libbpf in /usr/local/lib
  if [[ -f "${LIB_DIR}/${LIBBPF_VER}" ]]; then
    info "Removing ${LIB_DIR}/${LIBBPF_VER}"
    do_run "rm -f '${LIB_DIR}/${LIBBPF_VER}'"
  else
    warn "Not found: ${LIB_DIR}/${LIBBPF_VER}"
  fi

  # If symlink points to our version, remove it
  if [[ -L "${LIB_DIR}/${LIBBPF_LINK}" ]]; then
    TARGET="$(readlink -f "${LIB_DIR}/${LIBBPF_LINK}" || true)"
    if [[ "${TARGET}" == "${LIB_DIR}/${LIBBPF_VER}" ]]; then
      info "Removing ${LIB_DIR}/${LIBBPF_LINK} (points to ${LIBBPF_VER})"
      do_run "rm -f '${LIB_DIR}/${LIBBPF_LINK}'"
    else
      warn "${LIB_DIR}/${LIBBPF_LINK} points to ${TARGET}; leaving it"
    fi
  fi

  # libmicrohttpd in /usr/lib/x86_64-linux-gnu
  if [[ -f "${USR_LIB64}/${LIBMHTTPD_VER}" ]]; then
    info "Removing ${USR_LIB64}/${LIBMHTTPD_VER}"
    do_run "rm -f '${USR_LIB64}/${LIBMHTTPD_VER}'"
  else
    warn "Not found: ${USR_LIB64}/${LIBMHTTPD_VER}"
  fi

  if [[ -L "${USR_LIB64}/${LIBMHTTPD_LINK}" ]]; then
    TARGET="$(readlink -f "${USR_LIB64}/${LIBMHTTPD_LINK}" || true)"
    if [[ "${TARGET}" == "${USR_LIB64}/${LIBMHTTPD_VER}" ]]; then
      info "Removing ${USR_LIB64}/${LIBMHTTPD_LINK} (points to ${LIBMHTTPD_VER})"
      do_run "rm -f '${USR_LIB64}/${LIBMHTTPD_LINK}'"
    else
      warn "${USR_LIB64}/${LIBMHTTPD_LINK} points to ${TARGET}; leaving it"
    fi
  fi

  # ld.so conf file
  if [[ -f "${LD_CONF_FILE}" ]]; then
    info "Removing ${LD_CONF_FILE}"
    do_run "rm -f '${LD_CONF_FILE}'"
  fi

  info "Running ldconfig to refresh library cache"
  do_run "ldconfig || true"
else
  warn "Keeping installed libraries (use --purge-libs to remove)"
fi

# 5) (Optional) Purge OpenResty directory
if [[ $PURGE_OPENRESTY -eq 1 ]]; then
  if [[ -d "${OPENRESTY_DIR}" ]]; then
    info "Removing OpenResty directory: ${OPENRESTY_DIR}"
    do_run "rm -rf '${OPENRESTY_DIR}'"
  else
    warn "OpenResty not found at ${OPENRESTY_DIR}"
  fi
else
  warn "Keeping OpenResty (use --purge-openresty to remove)"
fi

do_run "rm -rf /tmp/uninstall.sh"

info "Uninstall steps complete."

if [[ $DRY_RUN -eq 1 ]]; then
  info "Dry-run mode: no changes were made."
else
  info "If you see unit not found errors in journal, ignore them."
  info "To verify removal:"
  echo "  systemctl status ${L4_SERVICE_NAME} ${L4_PROM_SERVICE_NAME} ${API_PARSER_SERVICE_NAME} || true"
  echo "  ls -la ${INSTALL_L4_DIR} ${INSTALL_API_PARSER_DIR} || true"
fi

exit 0
