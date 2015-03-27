#!/bin/bash
#
# taken from https://www.airpair.com/nginx/extending-nginx-tutorial

if [ ! -n "${NGINX_VERSION:+x}" ]; then
    echo "You must set NGINX_VERSION env var"
    exit 1
fi

if [ ! -n "${NGINX_ENV:+x}" ]; then
    echo "You must set NGINX_ENV env var"
    exit 1
fi

printf "Configuring nginx v$NGINX_VERSION build for $NGINX_ENV...\n"

if [ ! -d "vendor/nginx-$NGINX_VERSION" ]; then
    echo "vendor/nginx-$NGINX_VERSION not found. You must bootstrap first..."
    exit 1
fi

if [ "$NGINX_ENV" == "development" ]; then
  CFLAGS="-g -O0 -Wall -std=c99"
elif [ "$NGINX_ENV" == "production" ]; then
  CFLAGS="-O -Wall -std=c99"
else
  echo "Unknown NGINX_ENV: $NGINX_ENV..."
  exit 1
fi

pushd "vendor/nginx-$NGINX_VERSION"
CFLAGS="$CFLAGS" ./configure \
    --with-debug                                         \
    --prefix=$(pwd)/../../build/nginx-query-server-proxy \
    --sbin-path=bin/nginx-query-server-proxy             \
    --pid-path=logs/nginx-query-server-proxy.pid         \
    --conf-path=conf/nginx-query-server-proxy.conf       \
    --error-log-path=logs/error.log                      \
    --http-log-path=logs/access.log                      \
    --add-module=../../ngx_http_scm_query_server_proxy_module
popd
