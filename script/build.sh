#!/bin/bash
#
# taken from https://www.airpair.com/nginx/extending-nginx-tutorial

if [ ! -n "${NGINX_VERSION:+x}" ]; then
    echo "You must set NGINX_VERSION env var"
    exit 1
fi

printf "Building nginx v$NGINX_VERSION...\n"


if [ ! -d "vendor/nginx-$NGINX_VERSION" ]; then
    echo "vendor/nginx-$NGINX_VERSION not found. You must bootstrap first..."
    exit 1
fi

pushd "vendor/nginx-$NGINX_VERSION"
make
make install
popd
