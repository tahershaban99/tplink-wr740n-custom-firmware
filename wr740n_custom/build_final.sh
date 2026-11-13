#!/bin/bash
set -e

PROJ=/mnt/c/Users/Mohamed/Desktop/tplink/wr740n_custom
OUT=/mnt/c/Users/Mohamed/Desktop/tplink/output
IB=/home/lpl2/wr740n_build/openwrt-imagebuilder-18.06.9-ar71xx-tiny.Linux-x86_64
STAGE=/tmp/rmeter_rootfs

echo "=== 1. Running Host Unit Tests ==="
gcc -O2 -Wall -Wextra -std=gnu99 -I"$PROJ/src" \
  "$PROJ/tests/test_unit.c" "$PROJ/src/meter.c" "$PROJ/src/json_util.c" \
  -lpthread -o /tmp/test_unit
/tmp/test_unit

gcc -O2 -Wall -Wextra -std=gnu99 -I"$PROJ/src" \
  "$PROJ/tests/test_telegram.c" "$PROJ/src/meter.c" "$PROJ/src/json_util.c" \
  -lpthread -o /tmp/test_telegram
/tmp/test_telegram

gcc -O2 -Wall -Wextra -std=gnu99 -I"$PROJ/src" \
  -Wl,--wrap=system -Wl,--wrap=popen -Wl,--wrap=pclose -Wl,--wrap=fopen \
  "$PROJ/tests/test_meter_fw.c" "$PROJ/src/firewall.c" "$PROJ/src/meter.c" "$PROJ/src/json_util.c" \
  -lpthread -o /tmp/test_meter_fw
/tmp/test_meter_fw

echo "=== 2. Checking Web UI index.html ==="
python3 - <<'PY'
import html.parser, re
p = "/mnt/c/Users/Mohamed/Desktop/tplink/wr740n_custom/files/www/index.html"
data = open(p, encoding="utf-8").read()
assert "<script>" in data and "</script>" in data
assert "action=ota_upload" in data and "api('net_save'" in data
js = data.split("<script>")[1].split("</script>")[0]
print(f"index.html size: {len(data)} bytes, JS lines: {len(js.splitlines())}")
PY
if command -v node >/dev/null 2>&1; then
  node -e "const fs=require('fs'),vm=require('vm');const h=fs.readFileSync('$PROJ/files/www/index.html','utf8');const js=h.split('<script>')[1].split('</script>')[0];new vm.Script(js);console.log('[PASS] Node JS syntax check');"
fi

echo "=== 3. Cross-Compiling MIPS Binaries (rmeterd & rmeter_cgi) ==="
export STAGING_DIR=/home/lpl2/wr740n_build/openwrt-sdk-18.06.9-ar71xx-tiny_gcc-7.3.0_musl.Linux-x86_64/staging_dir
export PATH="$STAGING_DIR/toolchain-mips_24kc_gcc-7.3.0_musl/bin:$PATH"
cd "$PROJ/src"
make clean
make CC=mips-openwrt-linux-musl-gcc
mips-openwrt-linux-musl-strip rmeterd rmeter_cgi
ls -lh rmeterd rmeter_cgi

echo "=== 4. Staging Clean Linux RootFS Overlay ==="
rm -rf "$STAGE"
mkdir -p "$STAGE/etc/init.d" "$STAGE/etc/uci-defaults" "$STAGE/etc/config" "$STAGE/etc/rmeter" "$STAGE/usr/sbin" "$STAGE/www/cgi-bin"
cp "$PROJ/files/etc/init.d/rmeterd" "$STAGE/etc/init.d/rmeterd"
cp "$PROJ/files/etc/uci-defaults/99-rmeter-setup" "$STAGE/etc/uci-defaults/99-rmeter-setup"
cp "$PROJ/files/etc/config/uhttpd" "$STAGE/etc/config/uhttpd"
cp "$PROJ/files/etc/rmeter/tg_ca.pem" "$STAGE/etc/rmeter/tg_ca.pem"
cp "$PROJ/files/www/index.html" "$STAGE/www/index.html"
cp "$PROJ/src/rmeterd" "$STAGE/usr/sbin/rmeterd"
cp "$PROJ/src/rmeter_cgi" "$STAGE/www/cgi-bin/api"

sed -i 's/\r$//' "$STAGE/etc/init.d/rmeterd" "$STAGE/etc/uci-defaults/99-rmeter-setup" "$STAGE/etc/config/uhttpd" "$STAGE/etc/rmeter/tg_ca.pem" "$STAGE/www/index.html"
chmod 0755 "$STAGE/etc/init.d/rmeterd" "$STAGE/etc/uci-defaults/99-rmeter-setup" "$STAGE/usr/sbin/rmeterd" "$STAGE/www/cgi-bin/api"
chmod 0644 "$STAGE/etc/config/uhttpd" "$STAGE/etc/rmeter/tg_ca.pem" "$STAGE/www/index.html"
ls -laR "$STAGE"

echo "=== 5. Building Custom OpenWrt 18.06.9 Image ==="
cd "$IB"
mkdir -p staging_dir/host tmp
touch staging_dir/host/.prereq-build
PKGS="-ip6tables -kmod-ip6tables -kmod-nf-conntrack6 -odhcp6c -odhcpd-ipv6only -luci -opkg uhttpd iwinfo libustream-mbedtls libmbedtls tc kmod-sched-core iptables-mod-ipopt kmod-ipt-ipopt"
make image PROFILE=tl-wr740n-v4 PACKAGES="$PKGS" FILES="$STAGE"

echo "=== 6. Exporting Final Images & Checksums ==="
mkdir -p "$OUT"
BIN_DIR="$IB/bin/targets/ar71xx/tiny"
SYS_BIN="$BIN_DIR/openwrt-18.06.9-ar71xx-tiny-tl-wr740n-v4-squashfs-sysupgrade.bin"
FAC_BIN="$BIN_DIR/openwrt-18.06.9-ar71xx-tiny-tl-wr740n-v4-squashfs-factory.bin"
MAN_FILE="$BIN_DIR/openwrt-18.06.9-ar71xx-tiny-device-tl-wr740n-v4.manifest"

cp "$SYS_BIN" "$OUT/routermeter-wr740n-v4-sysupgrade.bin"
cp "$FAC_BIN" "$OUT/routermeter-wr740n-v4-factory.bin"
cp "$MAN_FILE" "$OUT/routermeter-wr740n-v4.manifest"
(cd "$OUT" && sha256sum routermeter-wr740n-v4-sysupgrade.bin routermeter-wr740n-v4-factory.bin > sha256sums.txt)

SYS_BYTES=$(stat -c%s "$OUT/routermeter-wr740n-v4-sysupgrade.bin")
FAC_BYTES=$(stat -c%s "$OUT/routermeter-wr740n-v4-factory.bin")
MAX_FW=3932160
FREE_JFFS=$((MAX_FW - SYS_BYTES))
echo "sysupgrade.bin: $SYS_BYTES bytes (free JFFS2 overlay ~ $FREE_JFFS bytes)"
echo "factory.bin:    $FAC_BYTES bytes"
cat "$OUT/sha256sums.txt"
if [ "$FREE_JFFS" -lt 196608 ]; then
  echo "WARNING: Free JFFS2 overlay < 192 KB!"
  exit 1
fi
echo "BUILD COMPLETE AND VERIFIED!"
