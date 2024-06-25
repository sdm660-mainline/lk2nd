#!/bin/sh
PROJECT=$1

if [[ -z ${PROJECT} ]]; then PROJECT=lk2nd-sdm660; fi

BD=build-${PROJECT}
#TP=armv7a-unknown-linux-gnueabihf-
TP=arm-none-eabi-

rm -rf ${BD}

#make -j8 TOOLCHAIN_PREFIX=${TP} DEBUG=2 ${PROJECT}
bear -- make -j8 TOOLCHAIN_PREFIX=${TP} DEBUG=2 ${PROJECT}

ls -la --color ${BD}/*.img
