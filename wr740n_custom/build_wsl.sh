#!/bin/bash
set -e
export STAGING_DIR=/home/lpl2/wr740n_build/openwrt-sdk-18.06.9-ar71xx-tiny_gcc-7.3.0_musl.Linux-x86_64/staging_dir
export PATH="$STAGING_DIR/toolchain-mips_24kc_gcc-7.3.0_musl/bin:$PATH"

cd /mnt/c/Users/Mohamed/Desktop/tplink/wr740n_custom/src
make clean
make CC=mips-openwrt-linux-musl-gcc
mips-openwrt-linux-musl-strip rmeterd rmeter_cgi
ls -lh rmeterd rmeter_cgi
file rmeterd rmeter_cgi

echo "=== Checking ImageBuilder repositories and packages ==="
cd /home/lpl2/wr740n_build/openwrt-imagebuilder-18.06.9-ar71xx-tiny.Linux-x86_64
grep -v '^#' repositories.conf || true
make info | grep -A 5 "tl-wr740n-v4:"
