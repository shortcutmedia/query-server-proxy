#!/bin/bash
#
# taken from https://www.airpair.com/nginx/extending-nginx-tutorial

printf "Building nginx...\n"

pushd "vendor"
pushd "nginx-1.4.7"
make
make install
popd
popd
