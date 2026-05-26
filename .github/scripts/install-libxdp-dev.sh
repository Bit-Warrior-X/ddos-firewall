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

sudo apt-get install -y \
  libelf-dev zlib1g-dev m4 libcap-dev \
  linux-libc-dev libc6-dev \
  libpcap-dev \
  "linux-headers-$(uname -r)"

# clang -target bpf does not search /usr/include; use one unified include root
# (same idea as: -O2 -g -target bpf -Wall -Wextra -I$HOME/linux-headers-6.8/include).
prepare_bpf_include_root() {
  local kver_short kdir mlarch hdr_inc
  kver_short="$(uname -r | cut -d. -f1-2)"
  kdir="/usr/src/linux-headers-$(uname -r)"
  mlarch="$(uname -m)-linux-gnu"
  hdr_inc="${HOME}/linux-headers-${kver_short}/include"

  rm -rf "${HOME}/linux-headers-${kver_short}"
  mkdir -p "${hdr_inc}"

  if [[ ! -d "/usr/include/${mlarch}/asm" ]]; then
    echo "error: missing /usr/include/${mlarch}/asm (linux-libc-dev?)" >&2
    exit 1
  fi
  ln -sfn "/usr/include/${mlarch}/asm" "${hdr_inc}/asm"

  if [[ -d "${kdir}/include/uapi/linux" ]]; then
    ln -sfn "${kdir}/include/uapi/linux" "${hdr_inc}/linux"
  elif [[ -d "/usr/include/${mlarch}/linux" ]]; then
    ln -sfn "/usr/include/${mlarch}/linux" "${hdr_inc}/linux"
  else
    ln -sfn /usr/include/linux "${hdr_inc}/linux"
  fi

  if [[ -d "${kdir}/include/uapi/asm-generic" ]]; then
    ln -sfn "${kdir}/include/uapi/asm-generic" "${hdr_inc}/asm-generic"
  fi

  if [[ ! -e "${hdr_inc}/asm/types.h" ]]; then
    echo "error: ${hdr_inc}/asm/types.h not found after setup" >&2
    ls -la "${hdr_inc}" "${hdr_inc}/asm" 2>/dev/null || true
    exit 1
  fi

  echo "${hdr_inc}"
}

work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; }
trap cleanup EXIT

git -c advice.detachedHead=false clone --depth 1 --branch "${XDP_TOOLS_REF}" \
  https://github.com/xdp-project/xdp-tools.git "${work}/xdp-tools"

cd "${work}/xdp-tools"
git -c advice.detachedHead=false submodule update --init --depth 1 lib/libbpf

export FORCE_SUBDIR_LIBBPF=1
./configure

HDR_INC="$(prepare_bpf_include_root)"
echo "Unified BPF headers: ${HDR_INC}"

# Prove clang bpf can resolve linux/types.h → asm/types.h before full build.
clang -target bpf -O2 -g -Wall -Wextra -I"${HDR_INC}" -c -x c - -o /dev/null <<'EOF'
#include <linux/types.h>
EOF
echo "clang -target bpf header smoke test OK"

# config.mk BPF_CFLAGS is ignored by lib/libxdp for arch includes; patch Makefile.
sed -i "s|^BPF_CFLAGS += -I\$(HEADER_DIR)|BPF_CFLAGS += -I${HDR_INC} -I\$(HEADER_DIR)|" lib/libxdp/Makefile

make -j"$(nproc)" libxdp
sudo make libxdp_install PREFIX="${PREFIX}"
sudo ldconfig

if ! pkg-config --exists libxdp 2>/dev/null; then
  echo "note: pkg-config libxdp may be missing; headers/libs are under ${PREFIX}" >&2
fi

echo "Installed libxdp from source into ${PREFIX}"
