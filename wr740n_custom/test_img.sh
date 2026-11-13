#!/bin/bash
set -e
cd /home/lpl2/wr740n_build/openwrt-imagebuilder-18.06.9-ar71xx-tiny.Linux-x86_64

# Test if downloads.openwrt.org responds; if not switch to archive.openwrt.org
if ! curl -fsSL --max-time 10 http://downloads.openwrt.org/releases/18.06.9/targets/ar71xx/tiny/packages/Packages.gz -o /dev/null; then
  echo "Switching repositories.conf to archive.openwrt.org..."
  sed -i 's|http://downloads.openwrt.org|https://archive.openwrt.org|g' repositories.conf
fi

# Dry-run package fetch & inspect sizes and modules
PKGS="-ip6tables -kmod-ip6tables -kmod-nf-conntrack6 -odhcp6c -odhcpd-ipv6only -luci -ppp -ppp-mod-pppoe uhttpd iwinfo libustream-mbedtls libmbedtls tc kmod-sched-core iptables-mod-ipopt kmod-ipt-ipopt"
# Wait: user may want ppp-mod-pppoe for WAN PPPoE! So KEEP ppp and ppp-mod-pppoe!
PKGS="-ip6tables -kmod-ip6tables -kmod-nf-conntrack6 -odhcp6c -odhcpd-ipv6only -luci uhttpd iwinfo libustream-mbedtls libmbedtls tc kmod-sched-core iptables-mod-ipopt kmod-ipt-ipopt"

echo "=== Running test make image ==="
mkdir -p staging_dir/host tmp
touch staging_dir/host/.prereq-build
make image PROFILE=tl-wr740n-v4 PACKAGES="$PKGS"
echo "=== Output images ==="
ls -lh bin/targets/ar71xx/tiny/
echo "=== Checking installed xt_*.ko and xt_*.so in build_dir ==="
find build_dir/target-mips_24kc_musl/root-ar71xx -name "*mac*" -o -name "*dscp*" -o -name "*DSCP*" -o -name "*mark*" -o -name "*MARK*" -o -name "*htb*" 2>/dev/null | sort
echo "=== Checking uhttpd gzip support ==="
strings build_dir/target-mips_24kc_musl/root-ar71xx/usr/sbin/uhttpd | grep -i -E "gzip|encoding|\.gz" || true
