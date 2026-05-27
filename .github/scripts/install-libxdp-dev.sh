#!/usr/bin/env bash
# Install libxdp headers/libs for building sparta.
# Ubuntu 24.04+: libxdp-dev from apt.
# Ubuntu 22.04: build xdp-tools from source (no libxdp packages in apt).
set -euo pipefail

XDP_TOOLS_REF="${XDP_TOOLS_REF:-v1.2.2}"
PREFIX="${LIBXDP_PREFIX:-/usr/local}"

if apt-cache show libxdp-dev >/dev/null 2>&1; then
  sudo apt-get install -y libxdp-dev
  echo "Installed libxdp-dev from apt ($(dpkg -s libxdp-dev | awk -F': ' '/^Version:/{print $2}'))"
  exit 0
fi

echo "libxdp-dev not in apt; building xdp-tools ${XDP_TOOLS_REF} → ${PREFIX}"

sudo apt-get install -y \
  linux-libc-dev gcc-multilib \
  git clang llvm libelf-dev libpcap-dev zlib1g-dev m4 libcap-dev \
  "linux-headers-$(uname -r)"

# clang -target bpf needs <asm/types.h> on the default include path.
sudo ln -sf /usr/include/"$(uname -m)-linux-gnu"/asm /usr/include/asm

work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; }
trap cleanup EXIT

git -c advice.detachedHead=false clone --depth 1 --branch "${XDP_TOOLS_REF}" \
  https://github.com/xdp-project/xdp-tools.git "${work}/xdp-tools"

cd "${work}/xdp-tools"
git -c advice.detachedHead=false submodule update --init --depth 1 lib/libbpf

# Jammy system libbpf (0.5) is too old for xdp-tools — use bundled submodule.
export FORCE_SUBDIR_LIBBPF=1
./configure
make -j"$(nproc)"
sudo make install PREFIX="${PREFIX}"

# Install bundled libbpf for sparta (needs bpf_xdp_attach, bpf_object__next_map, etc.).
sudo make -C lib/libbpf/src install PREFIX="${PREFIX}" || {
  echo "libbpf install target failed; copying build artifacts"
  sudo install -d "${PREFIX}/lib" "${PREFIX}/include/bpf"
  sudo cp -f lib/libbpf/src/libbpf.a "${PREFIX}/lib/"
  sudo cp -f lib/libbpf/src/*.h "${PREFIX}/include/bpf/" 2>/dev/null || true
  sudo cp -rf lib/libbpf/src/root/usr/include/bpf "${PREFIX}/include/"
}
sudo ldconfig

if nm -D "${PREFIX}/lib/libbpf.so" 2>/dev/null | grep -q bpf_xdp_attach; then
  echo "libbpf.so provides bpf_xdp_attach"
elif nm "${PREFIX}/lib/libbpf.a" 2>/dev/null | grep -q bpf_xdp_attach; then
  echo "libbpf.a provides bpf_xdp_attach"
else
  echo "error: ${PREFIX}/lib/libbpf missing bpf_xdp_attach" >&2
  ls -la "${PREFIX}/lib/libbpf"* 2>/dev/null || true
  exit 1
fi

echo "Installed libxdp + libbpf from source into ${PREFIX}"
