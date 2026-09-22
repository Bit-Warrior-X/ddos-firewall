#!/usr/bin/env bash
# Ensure nginx ssl_certificate / ssl_certificate_key paths exist.
# Real site certs are loaded at handshake via ssl_certificate_by_lua (Redis);
# these PEMs are only a config-load / no-SNI fallback.
set -euo pipefail

CERT_DIR="${ATHENS_CERT_DIR:-/usr/local/share/dorian/athens/nginx/cert}"
CERT="${CERT_DIR}/fullchain.pem"
KEY="${CERT_DIR}/privkey.pem"

mkdir -p "${CERT_DIR}"

if [[ -f "${CERT}" && -f "${KEY}" ]]; then
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: openssl required to create Athens fallback TLS certs at ${CERT_DIR}" >&2
  exit 1
fi

echo "creating Athens fallback self-signed TLS cert in ${CERT_DIR}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "${tmp}/privkey.pem" \
  -out "${tmp}/fullchain.pem" \
  -days 3650 -nodes \
  -subj "/CN=athens-fallback.local" \
  >/dev/null 2>&1

install -m 644 "${tmp}/fullchain.pem" "${CERT}"
install -m 600 "${tmp}/privkey.pem" "${KEY}"
