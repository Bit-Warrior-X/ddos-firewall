#!/usr/bin/env bash
# Install libxdp + modern libbpf for building sparta.
# Ubuntu 24.04+: libxdp-dev from apt (includes new enough libbpf).
# Ubuntu 22.04: build xdp-tools (libxdp) + standalone libbpf >= 1.0.
set -euo pipefail

XDP_TOOLS_REF="${XDP_TOOLS_REF:-v1.2.2}"
LIBBPF_REF="${LIBBPF_REF:-v1.4.7}"
PREFIX="${LIBXDP_PREFIX:-/usr/local}"

libbpf_has_symbol() {
  local sym="$1"
  shift
  local f
  for f in "$@"; do
    [[ -e "${f}" ]] || continue
    if nm -g --defined-only "${f}" 2>/dev/null | grep -qw "${sym}"; then
      return 0
    fi
    if nm -D "${f}" 2>/dev/null | grep -qw "${sym}"; then
      return 0
    fi
  done
  return 1
}

if apt-cache show libxdp-dev >/dev/null 2>&1; then
  sudo apt-get install -y libxdp-dev
  echo "Installed libxdp-dev from apt ($(dpkg -s libxdp-dev | awk -F': ' '/^Version:/{print $2}'))"
  exit 0
fi

echo "libxdp-dev not in apt; building xdp-tools ${XDP_TOOLS_REF} + libbpf ${LIBBPF_REF} → ${PREFIX}"

sudo apt-get install -y \
  linux-libc-dev gcc-multilib \
  git clang llvm libelf-dev libpcap-dev zlib1g-dev m4 libcap-dev \
  "linux-headers-$(uname -r)"

# clang -target bpf needs <asm/types.h> on the default include path.
sudo ln -sf /usr/include/"$(uname -m)-linux-gnu"/asm /usr/include/asm

work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; }
trap cleanup EXIT

# --- libxdp (xdp-tools) ---
git -c advice.detachedHead=false clone --depth 1 --branch "${XDP_TOOLS_REF}" \
  https://github.com/xdp-project/xdp-tools.git "${work}/xdp-tools"

cd "${work}/xdp-tools"
git -c advice.detachedHead=false submodule update --init --depth 1 lib/libbpf

export FORCE_SUBDIR_LIBBPF=1
./configure
make -j"$(nproc)" libxdp
sudo make libxdp_install PREFIX="${PREFIX}"

# --- libbpf for sparta (bpf_xdp_attach, bpf_object__next_map; bundled 0.7 is too old) ---
git -c advice.detachedHead=false clone --depth 1 --branch "${LIBBPF_REF}" \
  https://github.com/libbpf/libbpf.git "${work}/libbpf"

cd "${work}/libbpf/src"
make -j"$(nproc)"
sudo make install PREFIX="${PREFIX}" LIBDIR="${PREFIX}/lib" INCLUDEDIR="${PREFIX}/include" \
  UAPIDIR="${PREFIX}/include" RUNDIR="${PREFIX}/include"
sudo ldconfig

shopt -s nullglob
libbpf_files=( "${PREFIX}/lib/libbpf.so"* "${PREFIX}/lib/libbpf.a" )
if ! libbpf_has_symbol bpf_xdp_attach "${libbpf_files[@]}"; then
  echo "error: installed libbpf missing bpf_xdp_attach" >&2
  ls -la "${PREFIX}/lib/libbpf"* 2>/dev/null || true
  nm -g --defined-only "${PREFIX}/lib/libbpf.a" 2>/dev/null | grep bpf_xdp | head -20 || true
  exit 1
fi
if ! libbpf_has_symbol bpf_object__next_map "${libbpf_files[@]}"; then
  echo "error: installed libbpf missing bpf_object__next_map" >&2
  exit 1
fi

echo "libbpf provides bpf_xdp_attach and bpf_object__next_map"
echo "Installed libxdp (${XDP_TOOLS_REF}) + libbpf (${LIBBPF_REF}) into ${PREFIX}"
