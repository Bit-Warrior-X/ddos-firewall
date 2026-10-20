#!/usr/bin/env bash
# Install angelos, sparta, and athens from a payload tarball built by setup/pack.sh.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DORIAN_DIR="/usr/local/share/dorian"
DIST_DIR="${ROOT_DIR}/setup/dist"

usage() {
  cat <<EOF
Usage: $(basename "$0") [payload.tar.gz]

Installs angelos, sparta, and athens from a pack.sh tarball.
With no argument, uses the newest tarball in setup/dist/.

Existing firewall.config, firewall database, angelos config.py, Athens
certificates, and /usr/local/share/dorian/license are kept. dev in
firewall.config is set to this machine's main NIC.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

ARCHIVE="${1:-}"
if [[ -z "${ARCHIVE}" ]]; then
  shopt -s nullglob
  candidates=( "${DIST_DIR}"/dorian-ddos-firewall-*-payload.tar.gz )
  shopt -u nullglob
  if (( ${#candidates[@]} == 0 )); then
    echo "error: no payload tarball in ${DIST_DIR}" >&2
    usage >&2
    exit 1
  fi
  ARCHIVE="$(ls -1t "${candidates[@]}" | head -1)"
fi

if [[ ! -f "${ARCHIVE}" ]]; then
  echo "error: payload not found: ${ARCHIVE}" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
STASH="$(mktemp -d)"
cleanup() {
  rm -rf "${STAGE}" "${STASH}"
}
trap cleanup EXIT

echo "Extracting ${ARCHIVE}"
tar xzf "${ARCHIVE}" -C "${STAGE}"
for part in angelos sparta athens; do
  if [[ ! -d "${STAGE}/${part}" ]]; then
    echo "error: archive is missing ${part}/" >&2
    exit 1
  fi
done

mkdir -p "${STASH}"
if [[ -f "${DORIAN_DIR}/sparta/firewall.config" ]]; then
  cp -a "${DORIAN_DIR}/sparta/firewall.config" "${STASH}/firewall.config"
fi
if [[ -f "${DORIAN_DIR}/sparta/firewall_control.db" ]]; then
  cp -a "${DORIAN_DIR}/sparta/firewall_control.db" "${STASH}/firewall_control.db"
fi
if [[ -f "${DORIAN_DIR}/angelos/config.py" ]]; then
  cp -a "${DORIAN_DIR}/angelos/config.py" "${STASH}/config.py"
fi
if [[ -d "${DORIAN_DIR}/athens/nginx/cert" ]]; then
  cp -a "${DORIAN_DIR}/athens/nginx/cert" "${STASH}/cert"
fi

echo "Stopping services"
systemctl stop angelos.service athens.service sparta.service >/dev/null 2>&1 || true

mkdir -p "${DORIAN_DIR}"
# /access_logs must keep 7 days across upgrades; move (not copy) since it can be large.
ACCESS_LOG_DIR="${DORIAN_DIR}/athens/nginx/logs/access"
ACCESS_LOG_KEEP="${DORIAN_DIR}/.athens-access-logs"
if [[ -d "${ACCESS_LOG_DIR}" ]]; then
  rm -rf "${ACCESS_LOG_KEEP}"
  mv "${ACCESS_LOG_DIR}" "${ACCESS_LOG_KEEP}"
fi
rm -rf "${DORIAN_DIR}/angelos" "${DORIAN_DIR}/sparta" "${DORIAN_DIR}/athens"
cp -a "${STAGE}/angelos" "${DORIAN_DIR}/angelos"
cp -a "${STAGE}/sparta" "${DORIAN_DIR}/sparta"
cp -a "${STAGE}/athens" "${DORIAN_DIR}/athens"
mkdir -p "${DORIAN_DIR}/athens/nginx/logs"
if [[ -d "${ACCESS_LOG_KEEP}" ]]; then
  rm -rf "${ACCESS_LOG_DIR}"
  mv "${ACCESS_LOG_KEEP}" "${ACCESS_LOG_DIR}"
else
  mkdir -p "${ACCESS_LOG_DIR}"
fi

if [[ -f "${STASH}/firewall.config" ]]; then
  cp -a "${STASH}/firewall.config" "${DORIAN_DIR}/sparta/firewall.config"
fi
if [[ -f "${STASH}/firewall_control.db" ]]; then
  cp -a "${STASH}/firewall_control.db" "${DORIAN_DIR}/sparta/firewall_control.db"
fi
if [[ -f "${STASH}/config.py" ]]; then
  cp -a "${STASH}/config.py" "${DORIAN_DIR}/angelos/config.py"
fi
if [[ -d "${STASH}/cert" ]]; then
  mkdir -p "${DORIAN_DIR}/athens/nginx"
  rm -rf "${DORIAN_DIR}/athens/nginx/cert"
  cp -a "${STASH}/cert" "${DORIAN_DIR}/athens/nginx/cert"
fi

if [[ -x "${DORIAN_DIR}/sparta/bin/set-firewall-dev.sh" ]]; then
  "${DORIAN_DIR}/sparta/bin/set-firewall-dev.sh" "${DORIAN_DIR}/sparta/firewall.config"
fi

if [[ -x "${DORIAN_DIR}/athens/ensure-fallback-certs.sh" ]]; then
  ATHENS_CERT_DIR="${DORIAN_DIR}/athens/nginx/cert" \
    bash "${DORIAN_DIR}/athens/ensure-fallback-certs.sh"
fi

# Angelos Cython modules are ABI-specific (e.g. cpython-310). Do not use bare
# `python3` from PATH — conda / pyenv often put a newer interpreter first.
echo "Angelos venv"
ANGELOS_PY_ABI=""
if [[ -f "${STAGE}/BUILD_INFO" ]]; then
  ANGELOS_PY_ABI="$(awk -F= '/^python_abi=/{print $2; exit}' "${STAGE}/BUILD_INFO" | tr -d ' \n\r\t')"
fi
if [[ -z "${ANGELOS_PY_ABI}" ]]; then
  ANGELOS_PY_ABI="$(find "${DORIAN_DIR}/angelos" -name '*.cpython-*-x86_64-linux-gnu.so' -printf '%f\n' 2>/dev/null \
    | sed -n 's/.*\.cpython-\([0-9]\)\([0-9][0-9]*\)-.*/\1.\2/p' | head -1)"
fi
if [[ -z "${ANGELOS_PY_ABI}" ]]; then
  echo "error: cannot detect angelos Python ABI from BUILD_INFO or .so files" >&2
  exit 1
fi
ANGELOS_PY=""
for candidate in "/usr/bin/python${ANGELOS_PY_ABI}" "/bin/python${ANGELOS_PY_ABI}"; do
  if [[ -x "${candidate}" ]]; then
    ANGELOS_PY="${candidate}"
    break
  fi
done
if [[ -z "${ANGELOS_PY}" ]]; then
  echo "error: angelos requires Python ${ANGELOS_PY_ABI} (Cython .so ABI), but python${ANGELOS_PY_ABI} was not found under /usr/bin" >&2
  echo "       install it (e.g. apt install python${ANGELOS_PY_ABI} python${ANGELOS_PY_ABI}-venv) and re-run" >&2
  exit 1
fi
echo "  using ${ANGELOS_PY} (ABI ${ANGELOS_PY_ABI})"
rm -rf "${DORIAN_DIR}/angelos/venv"
"${ANGELOS_PY}" -m venv "${DORIAN_DIR}/angelos/venv"
"${DORIAN_DIR}/angelos/venv/bin/pip" install --upgrade pip setuptools wheel
if [[ -f "${DORIAN_DIR}/angelos/requirements.txt" ]]; then
  "${DORIAN_DIR}/angelos/venv/bin/pip" install -r "${DORIAN_DIR}/angelos/requirements.txt"
fi

install -d /etc/systemd/system
cp -f "${DORIAN_DIR}/angelos/angelos.service" /etc/systemd/system/angelos.service
cp -f "${DORIAN_DIR}/athens/athens.service" /etc/systemd/system/athens.service
cp -f "${DORIAN_DIR}/sparta/service/sparta.service" /etc/systemd/system/sparta.service
rm -f "${DORIAN_DIR}/angelos/angelos.service"

if [[ -f "${STAGE}/redis-socket.conf" ]] && command -v redis-server >/dev/null 2>&1; then
  install -d /etc/redis /var/log/redis /var/lib/redis
  if [[ ! -f /etc/redis/redis-socket.conf ]]; then
    cp -f "${STAGE}/redis-socket.conf" /etc/redis/redis-socket.conf
  fi
  if [[ ! -S /tmp/redis.sock ]]; then
    redis-server /etc/redis/redis-socket.conf
  fi
fi

systemctl daemon-reload
systemctl enable angelos.service athens.service sparta.service
systemctl restart sparta.service athens.service angelos.service

echo "Installed from ${ARCHIVE}"
systemctl is-active sparta.service athens.service angelos.service
