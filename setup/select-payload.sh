#!/usr/bin/env bash
# Pick the newest dorian-ddos-firewall payload tarball for this host's OS.
# Usage: ./select-payload.sh [uploads_dir]
set -euo pipefail

UPLOADS_DIR="${1:-/opt/dorian/uploads}"

if [[ ! -d "${UPLOADS_DIR}" ]]; then
  echo "error: uploads dir not found: ${UPLOADS_DIR}" >&2
  exit 1
fi

# Map host os-release to CI os_slug (must match build-payload.yml matrix).
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
fi

case "${ID:-}-${VERSION_ID:-}" in
  ubuntu-22.04) OS_SLUG="ubuntu-22.04" ;;
  ubuntu-24.04) OS_SLUG="ubuntu-24.04" ;;
  debian-12)    OS_SLUG="ubuntu-22.04" ;; # glibc-compatible with 22.04 builder
  *)
    echo "warning: unknown OS ${ID:-}-${VERSION_ID:-}; trying ubuntu-22.04 slug" >&2
    OS_SLUG="ubuntu-22.04"
    ;;
esac

shopt -s nullglob
candidates=( "${UPLOADS_DIR}"/dorian-ddos-firewall-*-"${OS_SLUG}"-payload.tar.gz )
if (( ${#candidates[@]} == 0 )); then
  echo "error: no tarball matching *-${OS_SLUG}-payload.tar.gz in ${UPLOADS_DIR}" >&2
  ls -1 "${UPLOADS_DIR}"/dorian-ddos-firewall-*-payload.tar.gz 2>/dev/null || true
  exit 1
fi

# Newest by mtime
best="$(ls -1t "${candidates[@]}" | head -1)"
echo "${best}"
