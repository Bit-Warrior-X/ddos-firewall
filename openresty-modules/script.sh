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
}

build_redis_nginx_adapter() {
  if [[ ! -f "${NGINX_BUNDLE_DIR}/objs/ngx_auto_headers.h" ]]; then
    echo "error: nginx objs not found; run openresty ./configure first" >&2
    exit 1
  fi

  if [[ -f "${LIB_REDIS_ADAPTER}/lib/libredis_nginx_adapter.a" ]]; then
    echo "redis_nginx_adapter already installed at ${LIB_REDIS_ADAPTER}"
    return 0
  fi

  local adapter_src="${SCRIPT_DIR}/.ci-deps/redis_nginx_adapter"
  if [[ ! -d "${adapter_src}/.git" ]]; then
    rm -rf "${adapter_src}"
    git clone --depth 1 https://github.com/wandenberg/redis_nginx_adapter.git "${adapter_src}"
  fi

  make -C "${adapter_src}" clean >/dev/null 2>&1 || true
  (
    cd "${adapter_src}"
    ./configure \
      --prefix="${LIB_REDIS_ADAPTER}" \
      --with-nginx-dir="${NGINX_BUNDLE_DIR}"
    make -j"$(nproc)"
    make install
  )

  if [[ ! -f "${LIB_REDIS_ADAPTER}/lib/libredis_nginx_adapter.a" ]]; then
    echo "error: redis_nginx_adapter build failed" >&2
    exit 1
  fi
}

apply_nginx_patches

OPENRESTY_LD_OPT="-L${LIB_REDIS_ADAPTER}/lib"
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
STAGING_DIR=""
if [[ "${DDOS_FW_CI_PAYLOAD_ONLY:-}" == "1" ]]; then
  STAGING_DIR="$(mktemp -d)"
  make install DESTDIR="${STAGING_DIR}"
  INSTALL_ROOT="${STAGING_DIR}${INSTALL_PREFIX}"
else
  make install
  INSTALL_ROOT="${INSTALL_PREFIX}"
fi

mkdir -p "${INSTALL_ROOT}/nginx/conf" "${INSTALL_ROOT}/nginx/lua/resty" "${INSTALL_ROOT}/nginx/cache/athens"

cp "${SCRIPT_DIR}"/config/*.conf "${INSTALL_ROOT}/nginx/conf/"
cp -r "${SCRIPT_DIR}/config/lua/resty/." "${INSTALL_ROOT}/nginx/lua/resty/"

if [[ "${DDOS_FW_CI_PAYLOAD_ONLY:-}" != "1" ]] && [[ -f "${SERVICE_SRC}" ]]; then
    cp "${SERVICE_SRC}" "${SERVICE_DST}"
    systemctl daemon-reload
fi

rm -rf "${PAYLOAD_ATHENS_DIR}"
mkdir -p "${PAYLOAD_ATHENS_DIR}"
cp -a "${INSTALL_ROOT}/." "${PAYLOAD_ATHENS_DIR}/"
cp "${SERVICE_SRC}" "${PAYLOAD_ATHENS_DIR}/athens.service"
cp "${SCRIPT_DIR}/athens-luajit.conf" "${PAYLOAD_ATHENS_DIR}/athens-luajit.conf"

rm -rf "${PAYLOAD_ATHENS_DIR}/bin"
rm -rf "${PAYLOAD_ATHENS_DIR}/pod"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/client_body_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/fastcgi_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/proxy_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/scgi_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/uwsgi_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/logs"
mkdir -p "${PAYLOAD_ATHENS_DIR}/nginx/logs"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/sbin/nginx.old"
rm -rf "${PAYLOAD_ATHENS_DIR}/site"
rm -rf "${PAYLOAD_ATHENS_DIR}/COPYRIGHT"
rm -rf "${PAYLOAD_ATHENS_DIR}/resty.index"
rm -rf "${PAYLOAD_ATHENS_DIR}/LICENSE"

echo "Athens OpenResty build and install completed."
echo "  prefix: ${INSTALL_PREFIX}"
if [[ -n "${STAGING_DIR}" ]]; then
  echo "  staged: ${INSTALL_ROOT}"
fi
echo "  nginx:  ${NGINX_DIR}/sbin/nginx"
