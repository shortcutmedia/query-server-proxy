#!/bin/bash
#
# taken from https://www.airpair.com/nginx/extending-nginx-tutorial

printf "Configuring nginx build for development...\n"

pushd "vendor"
pushd "nginx-1.4.7"
CFLAGS="-g -O0 -Wall -std=c99" ./configure \
    --with-debug                           \
    --prefix=$(pwd)/../../build/nginx      \
    --conf-path=conf/nginx.conf            \
    --error-log-path=logs/error.log        \
    --http-log-path=logs/access.log        \
    --add-module=../../ngx_http_scm_query_server_proxy_module
popd
popd
