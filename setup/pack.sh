#!/usr/bin/env bash
# Recompile angelos, sparta, and athens, then pack them into one tarball.
# The archive is not installed. Run setup/install.sh to deploy it.
# --skip-<component> reuses setup/payload/<component> instead of rebuilding it.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENRESTY_VER="${OPENRESTY_VER:-1.27.1.2}"
DIST_DIR="${ROOT_DIR}/setup/dist"
DEPS_DIR="${ROOT_DIR}/openresty-modules/.ci-deps"

usage() {
  cat <<EOF
Usage: $(basename "$0") [-o output.tar.gz] [--skip-angelos] [--skip-sparta] [--skip-athens]

Recompiles angelos, sparta, and athens and writes one payload tarball.
A skipped component is not rebuilt; the existing setup/payload directory is packed.
Default output: setup/dist/dorian-ddos-firewall-<version>-<os>-payload.tar.gz
EOF
}

OUTPUT=""
SKIP_ANGELOS=0
SKIP_SPARTA=0
SKIP_ATHENS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)
      OUTPUT="${2:-}"
      shift 2
      ;;
    --skip-angelos)
      SKIP_ANGELOS=1
      shift
      ;;
    --skip-sparta)
      SKIP_SPARTA=1
      shift
      ;;
    --skip-athens)
      SKIP_ATHENS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_cmd() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      echo "error: missing command: ${cmd}" >&2
      exit 1
    fi
  done
}

os_slug() {
  local id="" version=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-}"
    version="${VERSION_ID:-}"
  fi
  case "${id}-${version}" in
    ubuntu-22.04|ubuntu-24.04) echo "${id}-${version}" ;;
    debian-12) echo "ubuntu-22.04" ;;
    *) echo "${id:-linux}-${version:-unknown}" ;;
  esac
}

ensure_uthash() {
  if [[ -f /usr/local/src/uthash/include/uthash.h || -f /usr/local/src/uthash/src/uthash.h ]]; then
    LIB_UTHASH_DIR="/usr/local/src/uthash"
    return 0
  fi
  local dest="${DEPS_DIR}/uthash"
  if [[ ! -f "${dest}/src/uthash.h" && ! -f "${dest}/include/uthash.h" ]]; then
    rm -rf "${dest}"
    git clone --depth 1 https://github.com/troydhanson/uthash.git "${dest}"
  fi
  if [[ ! -f "${dest}/include/uthash.h" ]]; then
    mkdir -p "${dest}/include"
    cp "${dest}/src/"*.h "${dest}/include/"
  fi
  LIB_UTHASH_DIR="${dest}"
}

ensure_cjson() {
  local dest="${ROOT_DIR}/openresty-modules/ngx_acl/inc/cjson"
  if [[ -f "${dest}/cJSON.h" ]]; then
    return 0
  fi
  rm -rf "${dest}"
  git clone --depth 1 --branch v1.7.15 https://github.com/DaveGamble/cJSON.git "${dest}"
}

ensure_libmaxminddb() {
  if [[ -e /usr/local/src/libmaxminddb/lib/libmaxminddb.so || -e /usr/local/lib/libmaxminddb.so ]]; then
    if [[ -d /usr/local/src/libmaxminddb ]]; then
      LIB_MAXMINDDB_DIR="/usr/local/src/libmaxminddb"
    else
      LIB_MAXMINDDB_DIR="/usr/local"
    fi
    return 0
  fi
  local prefix="${DEPS_DIR}/libmaxminddb"
  if [[ ! -e "${prefix}/lib/libmaxminddb.so" && ! -e "${prefix}/lib/libmaxminddb.so.0" ]]; then
    cmake -S "${ROOT_DIR}/openresty-modules/libmaxminddb" -B "${DEPS_DIR}/libmaxminddb-build" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="${prefix}" \
      -DBUILD_SHARED_LIBS=ON \
      -DBUILD_TESTING=OFF
    cmake --build "${DEPS_DIR}/libmaxminddb-build" -j"$(nproc)"
    cmake --install "${DEPS_DIR}/libmaxminddb-build"
  fi
  LIB_MAXMINDDB_DIR="${prefix}"
}

ensure_openresty_source() {
  local src="${ROOT_DIR}/openresty-modules/openresty-${OPENRESTY_VER}"
  if [[ -x "${src}/configure" ]]; then
    return 0
  fi
  local tarball="/tmp/openresty-${OPENRESTY_VER}.tar.gz"
  curl -fsSL "https://openresty.org/download/openresty-${OPENRESTY_VER}.tar.gz" -o "${tarball}"
  tar xzf "${tarball}" -C "${ROOT_DIR}/openresty-modules"
}

build_angelos() {
  local venv="${ROOT_DIR}/.pack-venv-angelos"
  local py="/usr/bin/python3"
  local want="" have=""
  if [[ ! -x "${py}" ]]; then
    echo "error: ${py} is required so angelos matches this OS Python" >&2
    exit 1
  fi
  want="$("${py}" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  if [[ -x "${venv}/bin/python" && -f "${venv}/bin/activate" ]]; then
    have="$("${venv}/bin/python" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  fi
  if [[ "${have}" != "${want}" ]]; then
    rm -rf "${venv}"
    "${py}" -m venv "${venv}"
  fi
  # shellcheck disable=SC1091
  source "${venv}/bin/activate"
  export DDOS_FW_CI_PAYLOAD_ONLY=1
  bash "${ROOT_DIR}/api_parser/build.sh"
  deactivate
}

build_sparta() {
  export DDOS_FW_CI_PAYLOAD_ONLY=1
  export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
  export LDFLAGS="-L/usr/local/lib${LDFLAGS:+ ${LDFLAGS}}"
  bash "${ROOT_DIR}/ebpf_firewall/script.sh"
}

build_athens() {
  ensure_uthash
  ensure_cjson
  ensure_libmaxminddb
  ensure_openresty_source

  export DDOS_FW_CI_PAYLOAD_ONLY=1
  export LIB_UTHASH="${LIB_UTHASH_DIR}"
  export LIB_MAXMINDDB="${LIB_MAXMINDDB_DIR}"
  if [[ -f /usr/local/lib/libredis_nginx_adapter.a ]]; then
    export LIB_REDIS_ADAPTER="/usr/local"
  else
    export LIB_REDIS_ADAPTER="${DEPS_DIR}/redis-adapter"
  fi
  bash "${ROOT_DIR}/openresty-modules/script.sh"
}

pack_tarball() {
  local version os name
  version="$(tr -d ' \n\r\t' < "${ROOT_DIR}/VERSION")"
  os="$(os_slug)"
  mkdir -p "${DIST_DIR}"
  if [[ -z "${OUTPUT}" ]]; then
    OUTPUT="${DIST_DIR}/dorian-ddos-firewall-${version}-${os}-payload.tar.gz"
  fi

  echo "${version}" > "${ROOT_DIR}/setup/payload/VERSION"
  # Cython .so ABI (e.g. 3.10). install.sh must create the venv with this exact Python.
  local py_abi=""
  # Tag is cpython-310 / cpython-313 → 3.10 / 3.13
  py_abi="$(find "${ROOT_DIR}/setup/payload/angelos" -name '*.cpython-*-x86_64-linux-gnu.so' -printf '%f\n' 2>/dev/null \
    | sed -n 's/.*\.cpython-\([0-9]\)\([0-9][0-9]*\)-.*/\1.\2/p' | head -1)"
  if [[ -z "${py_abi}" && -x /usr/bin/python3 ]]; then
    py_abi="$(/usr/bin/python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  fi
  {
    echo "version=${version}"
    echo "os_slug=${os}"
    echo "glibc=$(ldd --version | awk 'NR==1 {print $NF}')"
    [[ -n "${py_abi}" ]] && echo "python_abi=${py_abi}"
    if command -v git >/dev/null 2>&1 && git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      echo "sha=$(git -C "${ROOT_DIR}" rev-parse HEAD)"
    fi
    date -u --iso-8601=seconds
  } > "${ROOT_DIR}/setup/payload/BUILD_INFO"
  cp -f "${ROOT_DIR}/redis-socket.conf" "${ROOT_DIR}/setup/payload/redis-socket.conf"

  tar czf "${OUTPUT}" -C "${ROOT_DIR}/setup/payload" \
    angelos sparta athens VERSION BUILD_INFO redis-socket.conf
  echo "Packed ${OUTPUT} ($(du -h "${OUTPUT}" | awk '{print $1}'))"
}

run_part() {
  local name="$1"
  local skip="$2"
  local build="$3"
  if [[ "${skip}" -eq 1 ]]; then
    if [[ ! -d "${ROOT_DIR}/setup/payload/${name}" ]]; then
      echo "error: --skip-${name} set but setup/payload/${name} does not exist" >&2
      exit 1
    fi
    echo "== ${name} (skipped, using existing payload) =="
    return 0
  fi
  echo "== ${name} =="
  "${build}"
}

cmds=(tar)
if [[ "${SKIP_ANGELOS}" -eq 0 ]]; then
  cmds+=(python3)
fi
if [[ "${SKIP_SPARTA}" -eq 0 ]]; then
  cmds+=(gcc clang make pkg-config)
fi
if [[ "${SKIP_ATHENS}" -eq 0 ]]; then
  cmds+=(gcc make curl pkg-config cmake git)
fi
require_cmd "${cmds[@]}"
cd "${ROOT_DIR}"

run_part angelos "${SKIP_ANGELOS}" build_angelos
run_part sparta "${SKIP_SPARTA}" build_sparta
run_part athens "${SKIP_ATHENS}" build_athens
echo "== pack =="
pack_tarball
