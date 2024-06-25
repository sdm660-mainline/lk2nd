#!/bin/sh
PROJECT=$1

if [[ -z ${PROJECT} ]]; then PROJECT=lk2nd-msm8974; fi

BD=build-${PROJECT}
rm -rf ${BD}

#make -j8 TOOLCHAIN_PREFIX=armv7a-unknown-linux-gnueabihf- DEBUG=2 ${PROJECT}
bear -- make -j8 TOOLCHAIN_PREFIX=armv7a-unknown-linux-gnueabihf- DEBUG=2 ${PROJECT}

ls -la --color ${BD}/*.img
