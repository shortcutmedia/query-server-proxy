#!/bin/bash
#
# taken from https://www.airpair.com/nginx/extending-nginx-tutorial

set -o nounset
set -o errexit

DIR=$(pwd)
BUILDDIR=$DIR/build
NGINX_DIR=nginx
NGINX_VERSION=1.4.7

clean () {
    rm -rf build vendor
}

setup_local_directories () {
    if [ ! -d $BUILDDIR ]; then
        printf "Setting up directories...\n"
        mkdir $BUILDDIR > /dev/null 2>&1
        mkdir $BUILDDIR/$NGINX_DIR > /dev/null 2>&1
    fi
}

download_nginx () {
    if [ ! -d "vendor/nginx-$NGINX_VERSION" ]; then
        printf "Downloading nginx...\n"

        if [ ! -d "vendor" ]; then
            mkdir vendor > /dev/null 2>&1
        fi
        pushd vendor > /dev/null 2>&1

        curl -s -L -O "http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
        tar xzf "nginx-$NGINX_VERSION.tar.gz"

        popd > /dev/null 2>&1
        #ln -sf $(pwd)/nginx.conf $(pwd)/build/nginx/conf/nginx.conf
    fi
}

if [[ "$#" -eq 1 ]]; then
    if [[ "$1" == "clean" ]]; then
        clean
    else
        echo "Invalid option"
    fi
else
    setup_local_directories
    download_nginx
fi
