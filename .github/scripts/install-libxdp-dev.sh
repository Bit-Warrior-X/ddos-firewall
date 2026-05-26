#!/usr/bin/env bash
# Install libxdp headers/libs for building sparta.
# Ubuntu 24.04+: libxdp-dev from apt.
# Ubuntu 22.04: no xdp-tools/libxdp packages in apt — build from source into /usr/local.
set -euo pipefail

XDP_TOOLS_REF="${XDP_TOOLS_REF:-v1.2.2}"
PREFIX="${LIBXDP_PREFIX:-/usr/local}"

if apt-cache show libxdp-dev >/dev/null 2>&1; then
  sudo apt-get install -y libxdp-dev
  echo "Installed libxdp-dev from apt ($(dpkg -s libxdp-dev | awk -F': ' '/^Version:/{print $2}'))"
  exit 0
fi

echo "libxdp-dev not in apt; building libxdp from xdp-tools ${XDP_TOOLS_REF} → ${PREFIX}"

sudo apt-get install -y libelf-dev zlib1g-dev m4 libcap-dev

work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; }
trap cleanup EXIT

git clone --depth 1 --branch "${XDP_TOOLS_REF}" \
  https://github.com/xdp-project/xdp-tools.git "${work}/xdp-tools"

cd "${work}/xdp-tools"
# Jammy libbpf is often too old; use the bundled submodule when configure asks for it.
git submodule update --init --depth 1 lib/libbpf
./configure --prefix="${PREFIX}" --libdir="${PREFIX}/lib"
make -j"$(nproc)"
sudo make install
sudo ldconfig

if ! pkg-config --exists libxdp 2>/dev/null; then
  echo "warning: pkg-config libxdp not found after install (headers under ${PREFIX}/include)" >&2
fi

echo "Installed libxdp from source into ${PREFIX}"
