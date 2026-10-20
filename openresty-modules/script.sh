#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENRESTY_SRC_DIR="${OPENRESTY_SRC_DIR:-${SCRIPT_DIR}/openresty-1.27.1.2}"
DEFAULT_ATHENS_PREFIX="/usr/local/share/dorian/athens"
# Paths are baked in at ./configure time — always use the runtime prefix for payloads.
if [[ "${DDOS_FW_CI_PAYLOAD_ONLY:-}" == "1" ]]; then
  INSTALL_PREFIX="${DEFAULT_ATHENS_PREFIX}"
elif [[ -n "${ATHENS_PREFIX:-}" ]]; then
  INSTALL_PREFIX="${ATHENS_PREFIX}"
else
  INSTALL_PREFIX="${DEFAULT_ATHENS_PREFIX}"
fi
NGINX_DIR="${INSTALL_PREFIX}/nginx"
CONF_DIR="${NGINX_DIR}/conf"
LUA_RESTY_DIR="${NGINX_DIR}/lua/resty"
SERVICE_SRC="${SCRIPT_DIR}/service/athens.service"
SERVICE_DST="/etc/systemd/system/athens.service"
PAYLOAD_ATHENS_DIR="${SCRIPT_DIR}/../setup/payload/athens"

export LIB_MAXMINDDB="${LIB_MAXMINDDB:-/usr/local/src/libmaxminddb}"
export LIB_UTHASH="${LIB_UTHASH:-/usr/local/src/uthash}"
export LIB_REDIS_ADAPTER="${LIB_REDIS_ADAPTER:-/usr/local}"

NGINX_BUNDLE_DIR="${OPENRESTY_SRC_DIR}/bundle/nginx-1.27.1"
NGINX_BUILD_DIR="${NGINX_BUNDLE_DIR}"

# Skip ./configure + make + make install; only refresh conf/lua/payload.
# Usage: ./script.sh --skip-recompile   OR   SKIP_RECOMPILE=1 ./script.sh
SKIP_RECOMPILE="${SKIP_RECOMPILE:-0}"

usage() {
  cat <<'EOF'
Usage: script.sh [options]

Options:
  --skip-recompile, -s   Skip OpenResty configure/make/install; only copy
                         config + lua into the existing prefix and refresh
                         setup/payload/athens.
  -h, --help             Show this help.

Environment:
  SKIP_RECOMPILE=1       Same as --skip-recompile
  ATHENS_PREFIX=...      Install/runtime prefix (default: /usr/local/share/dorian/athens)
  OPENRESTY_SRC_DIR=...  OpenResty source tree (ignored when skipping recompile)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-recompile|-s)
      SKIP_RECOMPILE=1
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

resolve_nginx_build_dir() {
  local candidates=(
    "${OPENRESTY_SRC_DIR}/build/nginx-1.27.1"
    "${NGINX_BUNDLE_DIR}"
  )

  for dir in "${candidates[@]}"; do
    if [[ -f "${dir}/objs/ngx_auto_headers.h" ]]; then
      NGINX_BUILD_DIR="${dir}"
      echo "using nginx build dir: ${NGINX_BUILD_DIR}"
      return 0
    fi
  done

  echo "error: ngx_auto_headers.h not found under build/ or bundle/; run openresty ./configure first" >&2
  exit 1
}

apply_nginx_patches() {
  if [[ ! -d "${NGINX_BUNDLE_DIR}" ]]; then
    echo "error: nginx bundle not found at ${NGINX_BUNDLE_DIR}" >&2
    exit 1
  fi

  if [[ -f "${SCRIPT_DIR}/ngx_purge/ngx_http_file_cache-1.27.1.patch" ]]; then
    patch -p1 -d "${NGINX_BUNDLE_DIR}" -N --forward \
      < "${SCRIPT_DIR}/ngx_purge/ngx_http_file_cache-1.27.1.patch" || true
    patch -p1 -d "${NGINX_BUNDLE_DIR}" -N --forward \
      < "${SCRIPT_DIR}/ngx_purge/ngx_http_upstream-1.27.1.patch" || true
  fi

  if [[ -f "${SCRIPT_DIR}/ngx_slice/ngx_http_slice_filter_module.patch" ]]; then
    patch -p1 -d "${NGINX_BUNDLE_DIR}" -N --forward \
      < "${SCRIPT_DIR}/ngx_slice/ngx_http_slice_filter_module.patch" || true
  fi

  # gzip_types hash is hardcoded to 64 bytes; OpenXML MIME names exceed that (~46 char effective max).
  if [[ -f "${SCRIPT_DIR}/ngx_gzip/ngx_http_test_types_hash_bucket-1.27.1.patch" ]]; then
    patch -p1 -d "${NGINX_BUNDLE_DIR}" -N --forward \
      < "${SCRIPT_DIR}/ngx_gzip/ngx_http_test_types_hash_bucket-1.27.1.patch" || true
  fi

  # ngx_req_status needs ngx_http_top_write_filter to count bytes sent per domain.
  local req_status_patch=""
  if [[ -f "${SCRIPT_DIR}/ngx_req_status/write_filter-openresty-1.27.1.patch" ]]; then
    req_status_patch="${SCRIPT_DIR}/ngx_req_status/write_filter-openresty-1.27.1.patch"
  elif [[ -f "${SCRIPT_DIR}/ngx_req_status/write_filter-openresty-1.21.4.2.patch" ]]; then
    req_status_patch="${SCRIPT_DIR}/ngx_req_status/write_filter-openresty-1.21.4.2.patch"
  fi
  if [[ -n "${req_status_patch}" ]]; then
    patch -p1 -d "${NGINX_BUNDLE_DIR}" -N --forward < "${req_status_patch}" || true
    if ! grep -q 'ngx_http_top_write_filter' \
         "${NGINX_BUNDLE_DIR}/src/http/ngx_http.c" \
      || ! grep -q 'ngx_http_top_write_filter' \
         "${NGINX_BUNDLE_DIR}/src/http/ngx_http_write_filter_module.c"; then
      echo "error: ngx_req_status write_filter patch did not apply (${req_status_patch})" >&2
      exit 1
    fi
  fi
}

build_redis_nginx_adapter() {
  resolve_nginx_build_dir

  if [[ -f "${LIB_REDIS_ADAPTER}/lib/libredis_nginx_adapter.a" ]]; then
    echo "redis_nginx_adapter already installed at ${LIB_REDIS_ADAPTER}"
    return 0
  fi

  local adapter_src="${SCRIPT_DIR}/.ci-deps/redis_nginx_adapter"
  if [[ ! -d "${adapter_src}/.git" ]]; then
    rm -rf "${adapter_src}"
    git clone --depth 1 https://github.com/wandenberg/redis_nginx_adapter.git "${adapter_src}"
  fi

  mkdir -p "${LIB_REDIS_ADAPTER}/lib" "${LIB_REDIS_ADAPTER}/include"

  make -C "${adapter_src}" clean >/dev/null 2>&1 || true
  (
    cd "${adapter_src}"
    ./configure \
      --prefix="${LIB_REDIS_ADAPTER}" \
      --with-nginx-dir="${NGINX_BUILD_DIR}"
    make -j"$(nproc)"
    make install
  )

  if [[ ! -f "${LIB_REDIS_ADAPTER}/lib/libredis_nginx_adapter.a" ]]; then
    echo "error: redis_nginx_adapter build failed" >&2
    exit 1
  fi
}

# ngx_purge links nginx against libhiredis.so.*; ship it in the payload so
# runtime hosts do not need distro package libhiredis0.14.
bundle_hiredis_libs() {
  local dest_lib="${1:?dest lib dir}"
  mkdir -p "${dest_lib}"

  local candidates=(
    /usr/lib/x86_64-linux-gnu/libhiredis.so.0.14
    /lib/x86_64-linux-gnu/libhiredis.so.0.14
    /usr/lib/x86_64-linux-gnu/libhiredis.so.1.1.0
    /lib/x86_64-linux-gnu/libhiredis.so.1.1.0
  )
  local src=""
  local c
  for c in "${candidates[@]}"; do
    if [[ -f "${c}" ]]; then
      src="${c}"
      break
    fi
  done
  if [[ -z "${src}" ]]; then
    src="$(ldconfig -p 2>/dev/null | awk '/libhiredis\\.so/{print $NF; exit}')" || true
  fi
  if [[ -z "${src}" || ! -f "${src}" ]]; then
    echo "error: libhiredis shared library not found (install libhiredis0.14 / libhiredis-dev)" >&2
    exit 1
  fi

  local real
  real="$(readlink -f "${src}")"
  local base
  base="$(basename "${real}")"
  cp -a "${real}" "${dest_lib}/${base}"

  # Preserve SONAME symlink expected by the nginx NEEDED entry.
  local soname
  soname="$(objdump -p "${real}" 2>/dev/null | awk '/SONAME/{print $2; exit}')" || true
  if [[ -n "${soname}" && "${soname}" != "${base}" ]]; then
    ln -sfn "${base}" "${dest_lib}/${soname}"
  fi
  ln -sfn "${base}" "${dest_lib}/libhiredis.so"
  echo "bundled hiredis: ${real} -> ${dest_lib}/"
}

# resty.maxminddb uses ffi.load("libmaxminddb"); ship it under athens/lib.
bundle_maxminddb_libs() {
  local dest_lib="${1:?dest lib dir}"
  mkdir -p "${dest_lib}"

  local candidates=(
    "${LIB_MAXMINDDB}/lib/libmaxminddb.so.0.0.7"
    "${LIB_MAXMINDDB}/lib/libmaxminddb.so.0"
    "${LIB_MAXMINDDB}/lib/libmaxminddb.so"
    "${SCRIPT_DIR}/libmaxminddb/lib/libmaxminddb.so.0.0.7"
    "${SCRIPT_DIR}/libmaxminddb/lib/libmaxminddb.so.0"
    "${SCRIPT_DIR}/libmaxminddb/src/.libs/libmaxminddb.so.0.0.7"
    /usr/local/lib/libmaxminddb.so.0.0.7
    /usr/local/lib/libmaxminddb.so.0
    /usr/lib/x86_64-linux-gnu/libmaxminddb.so.0.0.7
    /lib/x86_64-linux-gnu/libmaxminddb.so.0.0.7
  )
  local src=""
  local c
  for c in "${candidates[@]}"; do
    if [[ -f "${c}" ]]; then
      src="${c}"
      break
    fi
  done
  if [[ -z "${src}" ]]; then
    src="$(ldconfig -p 2>/dev/null | awk '/libmaxminddb\\.so/{print $NF; exit}')" || true
  fi
  if [[ -z "${src}" || ! -f "${src}" ]]; then
    echo "error: libmaxminddb shared library not found (build/install libmaxminddb)" >&2
    exit 1
  fi

  local real
  real="$(readlink -f "${src}")"
  local base
  base="$(basename "${real}")"
  cp -a "${real}" "${dest_lib}/${base}"

  local soname
  soname="$(objdump -p "${real}" 2>/dev/null | awk '/SONAME/{print $2; exit}')" || true
  if [[ -n "${soname}" && "${soname}" != "${base}" ]]; then
    ln -sfn "${base}" "${dest_lib}/${soname}"
  fi
  ln -sfn "${base}" "${dest_lib}/libmaxminddb.so"
  # Common SONAME used by ffi.load / ldconfig.
  if [[ "${base}" != "libmaxminddb.so.0" && "${soname:-}" != "libmaxminddb.so.0" ]]; then
    ln -sfn "${base}" "${dest_lib}/libmaxminddb.so.0"
  fi
  echo "bundled libmaxminddb: ${real} -> ${dest_lib}/"
}

# lua-resty-mlcache (acl_manager); depends on OpenResty lrucache + lock.
install_lua_resty_mlcache() {
  local dest_resty="${1:?dest resty dir}"
  local src="${SCRIPT_DIR}/third_party/lua-resty-mlcache/lib/resty"
  if [[ ! -f "${src}/mlcache.lua" ]]; then
    echo "error: vendored lua-resty-mlcache missing at ${src}/mlcache.lua" >&2
    exit 1
  fi
  mkdir -p "${dest_resty}/mlcache"
  cp -a "${src}/mlcache.lua" "${dest_resty}/mlcache.lua"
  cp -a "${src}/mlcache/." "${dest_resty}/mlcache/"
  echo "installed resty.mlcache -> ${dest_resty}/"
}

STAGING_DIR=""
INSTALL_ROOT=""

if [[ "${SKIP_RECOMPILE}" == "1" ]]; then
  echo "skipping OpenResty recompile (--skip-recompile)"
  if [[ ! -x "${NGINX_DIR}/sbin/nginx" ]]; then
    echo "error: no existing nginx binary at ${NGINX_DIR}/sbin/nginx; cannot --skip-recompile" >&2
    exit 1
  fi
  INSTALL_ROOT="${INSTALL_PREFIX}"
else
  apply_nginx_patches

  OPENRESTY_LD_OPT="-L${LIB_REDIS_ADAPTER}/lib -Wl,-rpath,${INSTALL_PREFIX}/lib -Wl,-rpath,${INSTALL_PREFIX}/luajit/lib"
  OPENRESTY_CC_OPT="-I${LIB_REDIS_ADAPTER}/include"
  if [[ "${DDOS_FW_CI_PAYLOAD_ONLY:-}" == "1" ]]; then
    OPENRESTY_LD_OPT="${OPENRESTY_LD_OPT} -Wl,-rpath,${LIB_REDIS_ADAPTER}/lib"
  fi

  cd "${OPENRESTY_SRC_DIR}"

  ./configure \
      --prefix="${INSTALL_PREFIX}" \
      --conf-path="${INSTALL_PREFIX}/nginx/conf/athens.conf" \
      --pid-path="${INSTALL_PREFIX}/nginx/logs/athens.pid" \
      --error-log-path="${INSTALL_PREFIX}/nginx/logs/athens_error.log" \
      --http-log-path="${INSTALL_PREFIX}/nginx/logs/athens_access.log" \
      --lock-path="${INSTALL_PREFIX}/nginx/logs/athens.lock" \
      --add-module=../ngx_acl \
      --add-module=../ngx_lic/ \
      --add-module=../ngx_slice/ \
      --add-module=../ngx_purge/ \
      --add-module=../ngx_req_status/ \
      --with-pcre-jit \
      --with-ipv6 \
      --with-http_ssl_module \
      --with-http_v2_module \
      --with-http_realip_module \
      --with-http_addition_module \
      --with-http_sub_module \
      --with-http_dav_module \
      --with-http_flv_module \
      --with-http_mp4_module \
      --with-http_gunzip_module \
      --with-http_gzip_static_module \
      --with-http_auth_request_module \
      --with-http_random_index_module \
      --with-http_secure_link_module \
      --with-http_slice_module \
      --with-http_stub_status_module \
      --with-stream \
      --with-stream_ssl_module \
      --with-stream_realip_module \
      --with-stream_ssl_preread_module \
      --with-threads \
      --with-file-aio \
      --with-ld-opt="${OPENRESTY_LD_OPT}" \
      --with-cc-opt="${OPENRESTY_CC_OPT}"

  build_redis_nginx_adapter

  make -j"$(nproc)"

  # CI: configure uses runtime prefix but install into a writable staging tree (no sudo).
  if [[ "${DDOS_FW_CI_PAYLOAD_ONLY:-}" == "1" ]]; then
    STAGING_DIR="$(mktemp -d)"
    make install DESTDIR="${STAGING_DIR}"
    INSTALL_ROOT="${STAGING_DIR}${INSTALL_PREFIX}"
  else
    make install
    INSTALL_ROOT="${INSTALL_PREFIX}"
  fi
fi

mkdir -p "${INSTALL_ROOT}/nginx/conf" "${INSTALL_ROOT}/nginx/lua/resty" "${INSTALL_ROOT}/nginx/cache/athens" "${INSTALL_ROOT}/lib"

bundle_hiredis_libs "${INSTALL_ROOT}/lib"
bundle_maxminddb_libs "${INSTALL_ROOT}/lib"

# Fallback PEMs required by ssl_certificate at nginx -t (real certs via Lua/SNI).
ensure_script="${SCRIPT_DIR}/service/ensure-fallback-certs.sh"
install -m 755 "${ensure_script}" "${INSTALL_ROOT}/ensure-fallback-certs.sh"
ATHENS_CERT_DIR="${INSTALL_ROOT}/nginx/cert" bash "${INSTALL_ROOT}/ensure-fallback-certs.sh"

cp "${SCRIPT_DIR}"/config/*.conf "${INSTALL_ROOT}/nginx/conf/"
cp -r "${SCRIPT_DIR}/config/lua/resty/." "${INSTALL_ROOT}/nginx/lua/resty/"
install_lua_resty_mlcache "${INSTALL_ROOT}/nginx/lua/resty"
# Also publish into OpenResty lualib path for installs where $prefix is the athens root.
mkdir -p "${INSTALL_ROOT}/lualib/resty"
install_lua_resty_mlcache "${INSTALL_ROOT}/lualib/resty"

if [[ "${DDOS_FW_CI_PAYLOAD_ONLY:-}" != "1" ]] && [[ -f "${SERVICE_SRC}" ]]; then
    cp "${SERVICE_SRC}" "${SERVICE_DST}"
    systemctl daemon-reload
fi

rm -rf "${PAYLOAD_ATHENS_DIR}"
mkdir -p "${PAYLOAD_ATHENS_DIR}"
cp -a "${INSTALL_ROOT}/." "${PAYLOAD_ATHENS_DIR}/"
cp "${SERVICE_SRC}" "${PAYLOAD_ATHENS_DIR}/athens.service"
cp "${SCRIPT_DIR}/athens-luajit.conf" "${PAYLOAD_ATHENS_DIR}/athens-luajit.conf"
# Keep ensure script executable in payload root (copied via INSTALL_ROOT above).
chmod 755 "${PAYLOAD_ATHENS_DIR}/ensure-fallback-certs.sh" 2>/dev/null || true

rm -rf "${PAYLOAD_ATHENS_DIR}/bin"
rm -rf "${PAYLOAD_ATHENS_DIR}/pod"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/client_body_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/fastcgi_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/proxy_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/scgi_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/uwsgi_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/logs"
mkdir -p "${PAYLOAD_ATHENS_DIR}/nginx/logs/access"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/sbin/nginx.old"
rm -rf "${PAYLOAD_ATHENS_DIR}/site"
rm -rf "${PAYLOAD_ATHENS_DIR}/COPYRIGHT"
rm -rf "${PAYLOAD_ATHENS_DIR}/resty.index"
rm -rf "${PAYLOAD_ATHENS_DIR}/LICENSE"

if [[ "${SKIP_RECOMPILE}" == "1" ]]; then
  echo "Athens config/lua refresh completed (OpenResty recompile skipped)."
else
  echo "Athens OpenResty build and install completed."
fi
echo "  prefix: ${INSTALL_PREFIX}"
if [[ -n "${STAGING_DIR}" ]]; then
  echo "  staged: ${INSTALL_ROOT}"
fi
echo "  nginx:  ${NGINX_DIR}/sbin/nginx"
