#!/bin/bash
#
# taken from https://www.airpair.com/nginx/extending-nginx-tutorial

set -o errexit

DIR=$(pwd)
BUILDDIR=$DIR/build
NGINX_DIR=nginx

setup_local_directories () {
    if [ ! -d $BUILDDIR ]; then
        printf "Setting up directories...\n"
        mkdir $BUILDDIR > /dev/null 2>&1
        mkdir $BUILDDIR/$NGINX_DIR > /dev/null 2>&1
    fi
}

download_nginx () {
    if [ ! -d "vendor/nginx-$NGINX_VERSION" ]; then
        printf "Downloading nginx v$NGINX_VERSION...\n"

        if [ ! -d "vendor" ]; then
            mkdir vendor > /dev/null 2>&1
        fi
        pushd vendor > /dev/null 2>&1

        curl -s -L -O "http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
        tar xzf "nginx-$NGINX_VERSION.tar.gz"

        popd > /dev/null 2>&1
    fi
}


if [ ! -n "${NGINX_VERSION:+x}" ]; then
    echo "You must set NGINX_VERSION env var"
    exit 1
fi

setup_local_directories
download_nginx
