#!/bin/bash
IB=/home/lpl2/wr740n_build/openwrt-imagebuilder-18.06.9-ar71xx-tiny.Linux-x86_64
R=$IB/build_dir/target-mips_24kc_musl/root-ar71xx

echo "=== /usr/lib/iptables ==="
ls -1 "$R/usr/lib/iptables/"

echo "=== /lib/modules/4.9.243 ==="
ls -1 "$R/lib/modules/4.9.243/"

echo "=== mac80211.sh ==="
tail -n 35 "$R/lib/wifi/mac80211.sh"

echo "=== kmod-sched packages in dl ==="
zcat "$IB/dl/openwrt_core" | grep -A 8 -E "Package: (kmod-sched|iptables-mod|kmod-ipt)"

