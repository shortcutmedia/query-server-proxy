#!/bin/bash
#
# taken from https://www.airpair.com/nginx/extending-nginx-tutorial

if [ ! -n "${NGINX_VERSION:+x}" ]; then
    echo "You must set NGINX_VERSION env var"
    exit 1
fi

printf "Configuring nginx v$NGINX_VERSION build for development...\n"


if [ ! -d "vendor/nginx-$NGINX_VERSION" ]; then
    echo "vendor/nginx-$NGINX_VERSION not found. You must bootstrap first..."
    exit 1
fi

pushd "vendor/nginx-$NGINX_VERSION"
CFLAGS="-g -O0 -Wall -std=c99" ./configure \
    --with-debug                           \
    --prefix=$(pwd)/../../build/nginx      \
    --conf-path=conf/nginx.conf            \
    --error-log-path=logs/error.log        \
    --http-log-path=logs/access.log        \
    --add-module=../../ngx_http_scm_query_server_proxy_module
popd
