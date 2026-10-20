#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PAYLOAD_SPARTA_DIR="${ROOT_DIR}/setup/payload/sparta"
KERNEL_RELEASE="$(uname -r)"
LIBBPF_KERNEL_INCLUDE="/usr/src/linux-headers-${KERNEL_RELEASE}/tools/bpf/resolve_btfids/libbpf/include"

SPARTA_SERVICE="sparta.service"
SPARTA_PROM_SERVICE="sparta-prometheus.service"

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
#if [[ ! -f "/usr/include/xdp/libxdp.h" ]]; then
#  missing_deps+=("libxdp-dev")
#fi
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

stage_sparta_payload() {
  mkdir -p "${PAYLOAD_SPARTA_DIR}/bin" "${PAYLOAD_SPARTA_DIR}/geodb" "${PAYLOAD_SPARTA_DIR}/service"

  cp -f "${SCRIPT_DIR}/build/sparta_cli" "${PAYLOAD_SPARTA_DIR}/bin/"
  if [[ -f "${SCRIPT_DIR}/build/sparta_prom" ]]; then
    cp -f "${SCRIPT_DIR}/build/sparta_prom" "${PAYLOAD_SPARTA_DIR}/bin/"
  else
    echo "Prometheus exporter binary not built; skipping copy."
  fi
  cp -f "${SCRIPT_DIR}/build/sparta_user" "${PAYLOAD_SPARTA_DIR}/bin/"
  install -m 755 "${SCRIPT_DIR}/scripts/set-firewall-dev.sh" "${PAYLOAD_SPARTA_DIR}/bin/set-firewall-dev.sh"
  cp -f "${SCRIPT_DIR}/build/firewall.config" "${PAYLOAD_SPARTA_DIR}/"
  cp -f "${SCRIPT_DIR}/build/sparta_kernel.o" "${PAYLOAD_SPARTA_DIR}/"
  cp -f "${SCRIPT_DIR}/service/ebpf-firewall.service" "${PAYLOAD_SPARTA_DIR}/service/${SPARTA_SERVICE}"
  cp -f "${SCRIPT_DIR}/service/ebpf-firewall-prometheus.service" "${PAYLOAD_SPARTA_DIR}/service/${SPARTA_PROM_SERVICE}"
  cp -af "${SCRIPT_DIR}/geodb/." "${PAYLOAD_SPARTA_DIR}/geodb/"
}

if [[ "${DDOS_FW_CI_PAYLOAD_ONLY:-}" == "1" ]]; then
  stage_sparta_payload
  echo "DDOS_FW_CI_PAYLOAD_ONLY=1: skipping install and systemd."
  exit 0
fi

systemctl stop "${SPARTA_SERVICE}" >/dev/null 2>&1 || true

if sudo -n true >/dev/null 2>&1; then
  make install
else
  echo "Skipping install: sudo is unavailable or not configured."
fi

stage_sparta_payload

cp -f "${SCRIPT_DIR}/service/ebpf-firewall.service" "/etc/systemd/system/${SPARTA_SERVICE}"
cp -f "${SCRIPT_DIR}/service/ebpf-firewall-prometheus.service" "/etc/systemd/system/${SPARTA_PROM_SERVICE}"

systemctl daemon-reload
systemctl enable "${SPARTA_SERVICE}"
systemctl enable "${SPARTA_PROM_SERVICE}"
#systemctl start "${SPARTA_PROM_SERVICE}"
#systemctl start "${SPARTA_SERVICE}"
