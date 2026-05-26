#!/usr/bin/env bash
# Install libxdp headers/libs for building sparta.
# Ubuntu 24.04+: libxdp-dev from apt.
# Ubuntu 22.04: no xdp packages in apt — build xdp-tools libxdp into /usr/local.
set -euo pipefail

XDP_TOOLS_REF="${XDP_TOOLS_REF:-v1.2.2}"
PREFIX="${LIBXDP_PREFIX:-/usr/local}"

if apt-cache show libxdp-dev >/dev/null 2>&1; then
  sudo apt-get install -y libxdp-dev
  echo "Installed libxdp-dev from apt ($(dpkg -s libxdp-dev | awk -F': ' '/^Version:/{print $2}'))"
  exit 0
fi

echo "libxdp-dev not in apt; building libxdp from xdp-tools ${XDP_TOOLS_REF} → ${PREFIX}"

# linux-libc-dev: asm/types.h for clang BPF object build (xsk_def_xdp_prog*.o).
# libpcap-dev: required by xdp-tools configure when using bundled libbpf.
sudo apt-get install -y \
  libelf-dev zlib1g-dev m4 libcap-dev \
  linux-libc-dev libc6-dev \
  libpcap-dev \
  "linux-headers-$(uname -r)"

work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; }
trap cleanup EXIT

git -c advice.detachedHead=false clone --depth 1 --branch "${XDP_TOOLS_REF}" \
  https://github.com/xdp-project/xdp-tools.git "${work}/xdp-tools"

cd "${work}/xdp-tools"
git -c advice.detachedHead=false submodule update --init --depth 1 lib/libbpf

# Jammy system libbpf (0.5) lacks APIs xdp-tools needs — use bundled submodule.
export FORCE_SUBDIR_LIBBPF=1

# Do NOT set KERNEL_HEADERS: it makes clang pull azure kernel uapi headers that lack
# asm/types.h. xdp-tools ships headers/; only userspace arch includes are needed.
mlarch="$(uname -m)-linux-gnu"
if [[ -d "/usr/include/${mlarch}" ]]; then
  export ARCH_INCLUDES="-I/usr/include/${mlarch}"
fi

./configure
if ! grep -q 'ARCH_INCLUDES.*x86_64-linux-gnu\|ARCH_INCLUDES.*aarch64-linux-gnu' config.mk 2>/dev/null; then
  echo "warning: ARCH_INCLUDES may be empty in config.mk; BPF build can fail" >&2
  grep '^ARCH_INCLUDES' config.mk || true
fi
make -j"$(nproc)" libxdp
sudo make libxdp_install PREFIX="${PREFIX}"
sudo ldconfig

if ! pkg-config --exists libxdp 2>/dev/null; then
  echo "note: pkg-config libxdp may be missing; headers/libs are under ${PREFIX}" >&2
fi

echo "Installed libxdp from source into ${PREFIX}"
