#!/usr/bin/env bash
# Set firewall.config `dev` to this edge's main NIC.
# Main NIC: lowest-metric default route. A bond slave is recorded as its master.
set -euo pipefail

CONFIG="${1:-/usr/local/share/dorian/sparta/firewall.config}"

valid_name() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]
}

bond_master_of() {
  local dev="$1"
  if [[ -L "/sys/class/net/${dev}/master" ]]; then
    basename "$(readlink -f "/sys/class/net/${dev}/master")"
  fi
}

default_route_dev() {
  [[ -r /proc/net/route ]] || return 1
  awk '$2 == "00000000" && $1 != "lo" { print $7, $1 }' /proc/net/route \
    | sort -n \
    | awk 'NR == 1 { print $2 }'
}

main_nic() {
  local dev master n
  dev="$(default_route_dev || true)"
  if [[ -n "${dev}" ]]; then
    master="$(bond_master_of "${dev}" || true)"
    if [[ -n "${master}" ]]; then
      dev="${master}"
    fi
  fi
  if [[ -n "${dev}" ]] && valid_name "${dev}" && [[ -d "/sys/class/net/${dev}" ]]; then
    printf '%s\n' "${dev}"
    return 0
  fi

  shopt -s nullglob
  for n in /sys/class/net/*; do
    n="$(basename "${n}")"
    [[ "${n}" == "lo" || "${n}" == "bonding_masters" ]] && continue
    [[ "${n}" == docker* || "${n}" == veth* || "${n}" == br-* || "${n}" == virbr* ]] && continue
    if [[ -d "/sys/class/net/${n}/bonding" ]]; then
      printf '%s\n' "${n}"
      return 0
    fi
  done
  for n in /sys/class/net/*; do
    n="$(basename "${n}")"
    [[ "${n}" == "lo" || "${n}" == "bonding_masters" ]] && continue
    [[ "${n}" == docker* || "${n}" == veth* || "${n}" == br-* || "${n}" == virbr* ]] && continue
    [[ -L "/sys/class/net/${n}/master" ]] && continue
    if [[ -e "/sys/class/net/${n}/device" ]]; then
      printf '%s\n' "${n}"
      return 0
    fi
  done
  return 1
}

nic="$(main_nic)" || {
  echo "set-firewall-dev: no main NIC found" >&2
  exit 1
}

if [[ ! -f "${CONFIG}" ]]; then
  echo "set-firewall-dev: config not found: ${CONFIG}" >&2
  exit 1
fi

if grep -qE '^[[:space:]]*dev[[:space:]]*=' "${CONFIG}"; then
  sed -i -E "s/^([[:space:]]*dev[[:space:]]*=[[:space:]]*).*/\\1${nic}/" "${CONFIG}"
else
  sed -i "1a dev = ${nic}" "${CONFIG}"
fi

echo "set-firewall-dev: ${CONFIG} dev = ${nic}"
