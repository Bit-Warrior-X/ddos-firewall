#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENRESTY_SRC_DIR="${OPENRESTY_SRC_DIR:-${SCRIPT_DIR}/openresty-1.27.1.2}"
DEFAULT_ATHENS_PREFIX="/usr/local/share/dorian/athens"
INSTALL_PREFIX="${ATHENS_PREFIX:-${DEFAULT_ATHENS_PREFIX}}"
NGINX_DIR="${INSTALL_PREFIX}/nginx"
CONF_DIR="${NGINX_DIR}/conf"
LUA_RESTY_DIR="${NGINX_DIR}/lua/resty"
SERVICE_SRC="${SCRIPT_DIR}/service/athens.service"
SERVICE_DST="/etc/systemd/system/athens.service"
PAYLOAD_ATHENS_DIR="${SCRIPT_DIR}/../setup/payload/athens"

export LIB_MAXMINDDB="${LIB_MAXMINDDB:-/usr/local/src/libmaxminddb}"
export LIB_UTHASH="${LIB_UTHASH:-/usr/local/src/uthash}"

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
    --with-file-aio

make -j$(nproc)
make install

mkdir -p "${CONF_DIR}" "${LUA_RESTY_DIR}"

cp "${SCRIPT_DIR}"/config/*.conf "${CONF_DIR}/"
cp -r "${SCRIPT_DIR}/config/lua/resty/." "${LUA_RESTY_DIR}/"

if [[ "${DDOS_FW_CI_PAYLOAD_ONLY:-}" != "1" ]] && [[ -f "${SERVICE_SRC}" ]]; then
    cp "${SERVICE_SRC}" "${SERVICE_DST}"
    systemctl daemon-reload
fi

rm -rf "${PAYLOAD_ATHENS_DIR}"
mkdir -p "${PAYLOAD_ATHENS_DIR}"
cp -a "${INSTALL_PREFIX}/." "${PAYLOAD_ATHENS_DIR}/"
cp "${SERVICE_SRC}" "${PAYLOAD_ATHENS_DIR}/athens.service"

rm -rf "${PAYLOAD_ATHENS_DIR}/bin"
rm -rf "${PAYLOAD_ATHENS_DIR}/pod"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/client_body_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/fastcgi_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/proxy_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/scgi_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/uwsgi_temp"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/logs/"
rm -rf "${PAYLOAD_ATHENS_DIR}/nginx/sbin/nginx.old"
rm -rf "${PAYLOAD_ATHENS_DIR}/site"
rm -rf "${PAYLOAD_ATHENS_DIR}/COPYRIGHT"
rm -rf "${PAYLOAD_ATHENS_DIR}/resty.index"
rm -rf "${PAYLOAD_ATHENS_DIR}/LICENSE"

echo "Athens OpenResty build and install completed."
