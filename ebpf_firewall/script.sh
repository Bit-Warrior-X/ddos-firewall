#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PAYLOAD_L4_DIR="${ROOT_DIR}/setup/payload/l4"
KERNEL_RELEASE="$(uname -r)"
LIBBPF_KERNEL_INCLUDE="/usr/src/linux-headers-${KERNEL_RELEASE}/tools/bpf/resolve_btfids/libbpf/include"

systemctl stop ebpf_firewall.service >/dev/null 2>&1 || true

cd "${SCRIPT_DIR}"

missing_deps=()
if [[ ! -f "/usr/include/bpf/bpf_helpers.h" && ! -f "${LIBBPF_KERNEL_INCLUDE}/bpf/bpf_helpers.h" ]]; then
  missing_deps+=("libbpf-dev (bpf_helpers.h)")
fi
if [[ ! -f "/usr/include/bpf/libbpf.h" && ! -f "${LIBBPF_KERNEL_INCLUDE}/bpf/libbpf.h" ]]; then
  missing_deps+=("libbpf-dev (libbpf.h)")
fi
if [[ ! -f "/usr/include/libnetfilter_conntrack/libnetfilter_conntrack.h" ]]; then
  missing_deps+=("libnetfilter-conntrack-dev")
fi
if [[ ! -f "/usr/include/sqlite3.h" ]]; then
  missing_deps+=("libsqlite3-dev")
fi
if [[ ! -f "/usr/include/bpf/libbpf.h" && ! -f "${LIBBPF_KERNEL_INCLUDE}/bpf/libbpf.h" ]]; then
  missing_deps+=("libbpf-dev")
fi
if [[ ! -f "/usr/include/xdp/libxdp.h" ]]; then
  missing_deps+=("libxdp-dev")
fi
if [[ ! -f "/usr/include/microhttpd.h" ]]; then
  missing_deps+=("libmicrohttpd-dev")
fi
missing_optional=()
if [[ ! -f "/usr/include/prom.h" || ! -f "/usr/include/promhttp.h" ]]; then
  missing_optional+=("prometheus exporter headers (prom.h/promhttp.h)")
fi

if (( ${#missing_deps[@]} )); then
  echo "Missing build dependencies:"
  printf '  - %s\n' "${missing_deps[@]}"
  echo "Install them and re-run this script."
  exit 1
fi

if (( ${#missing_optional[@]} )); then
  echo "Optional dependencies missing:"
  printf '  - %s\n' "${missing_optional[@]}"
  echo "Prometheus exporter will be skipped."
fi

make clean
make test_mode
if sudo -n true >/dev/null 2>&1; then
  make install
else
  echo "Skipping install: sudo is unavailable or not configured."
fi

mkdir -p "${PAYLOAD_L4_DIR}/bin" "${PAYLOAD_L4_DIR}/geodb"

cp -f "${SCRIPT_DIR}/build/ebpf_firewall_cli" "${PAYLOAD_L4_DIR}/bin/"
if [[ -f "${SCRIPT_DIR}/build/ebpf_firewall_prom" ]]; then
  cp -f "${SCRIPT_DIR}/build/ebpf_firewall_prom" "${PAYLOAD_L4_DIR}/bin/"
else
  echo "Prometheus exporter binary not built; skipping copy."
fi
cp -f "${SCRIPT_DIR}/build/ebpf_firewall_userspace" "${PAYLOAD_L4_DIR}/bin/"
cp -f "${SCRIPT_DIR}/build/firewall.config" "${PAYLOAD_L4_DIR}/"
cp -f "${SCRIPT_DIR}/build/ebpf_firewall_kernel.o" "${PAYLOAD_L4_DIR}/"
cp -af "${SCRIPT_DIR}/geodb/." "${PAYLOAD_L4_DIR}/geodb/"
