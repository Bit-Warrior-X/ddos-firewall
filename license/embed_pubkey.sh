#!/usr/bin/env bash
# Regenerate license/embedded_pubkey.h from license/server_public_key.pem.
# Run this after rotating the license signing key. The private key is never read.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUB="${ROOT}/server_public_key.pem"
OUT="${ROOT}/embedded_pubkey.h"

if [[ ! -f "${PUB}" ]]; then
  echo "error: missing ${PUB}" >&2
  exit 1
fi
if grep -q "PRIVATE KEY" "${PUB}"; then
  echo "error: ${PUB} contains a private key; refusing to embed it" >&2
  exit 1
fi

python3 - "${PUB}" "${OUT}" <<'PY'
import sys
from pathlib import Path

pem = Path(sys.argv[1]).read_bytes()
if b"PRIVATE" in pem:
    raise SystemExit("refusing to embed a private key")

mask = bytes([
    0x6D, 0xC3, 0x19, 0xA7, 0x52, 0x0E, 0xB4, 0x88,
    0x3F, 0xD1, 0x67, 0x15, 0x9A, 0xE2, 0x4C, 0x70,
])
xored = bytes(b ^ mask[i % len(mask)] for i, b in enumerate(pem))

def c_array(data, name):
    lines = [f"static const unsigned char {name}[] = {{"]
    row = []
    for b in data:
        row.append(f"0x{b:02x}")
        if len(row) == 12:
            lines.append("    " + ", ".join(row) + ",")
            row = []
    if row:
        lines.append("    " + ", ".join(row) + ",")
    lines.append("};")
    return "\n".join(lines)

Path(sys.argv[2]).write_text(f'''#ifndef DORIAN_EMBEDDED_PUBKEY_H
#define DORIAN_EMBEDDED_PUBKEY_H

/*
 * Vendor license public key, baked into sparta, athens, and angelos.
 * Verification must use this key. A customer-supplied PEM or PUBKEY_PATH
 * is not consulted.
 *
 * Regenerate with license/embed_pubkey.sh after rotating license/server_public_key.pem.
 * Never put the private key in this header.
 */

#include <stddef.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

{c_array(mask, "dorian_pubkey_mask")}

{c_array(xored, "dorian_pubkey_obf")}

static EVP_PKEY *dorian_load_embedded_pubkey(void)
{{
    unsigned char pem[sizeof(dorian_pubkey_obf) + 1];
    size_t i;
    const size_t mlen = sizeof(dorian_pubkey_mask);
    EVP_PKEY *pk;
    BIO *bio;

    for (i = 0; i < sizeof(dorian_pubkey_obf); i++)
        pem[i] = (unsigned char)(dorian_pubkey_obf[i] ^ dorian_pubkey_mask[i % mlen]);
    pem[sizeof(dorian_pubkey_obf)] = 0;

    bio = BIO_new_mem_buf(pem, (int)sizeof(dorian_pubkey_obf));
    if (!bio) {{
        memset(pem, 0, sizeof(pem));
        return NULL;
    }}
    pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    memset(pem, 0, sizeof(pem));
    return pk;
}}

#endif
''')
print(f"wrote {sys.argv[2]} ({len(pem)} pem bytes)")
PY
