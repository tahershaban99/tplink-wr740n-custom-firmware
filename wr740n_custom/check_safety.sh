#!/bin/bash
IB=/home/lpl2/wr740n_build/openwrt-imagebuilder-18.06.9-ar71xx-tiny.Linux-x86_64
R=$IB/build_dir/target-mips_24kc_musl/root-ar71xx

echo "=== 1. Largest files in rootfs ==="
find "$R" -type f -printf "%s %p\n" | sort -rn | head -n 35

echo "=== 2. Package compressed .ipk sizes in dl/ ==="
ls -lhS "$IB/dl/"*.ipk | head -n 25

echo "=== 3. Last 32 bytes (0xdeadc0de) & First 96 bytes of sysupgrade.bin ==="
python3 - <<'PY'
d = open("/mnt/c/Users/Mohamed/Desktop/tplink/output/routermeter-wr740n-v4-sysupgrade.bin", "rb").read()
import struct
print("Total len:", len(d), hex(len(d)))
print("First 80 bytes hex:", d[:80].hex())
print("hw_id @ 0x40:", hex(struct.unpack(">I", d[0x40:0x44])[0]), "hw_rev @ 0x44:", hex(struct.unpack(">I", d[0x44:0x48])[0]))
print("Last 32 bytes hex:", d[-32:].hex())
PY

echo "=== 4. platform_check_image for wr740n in root-ar71xx ==="
ls -la "$R/lib/upgrade/" 2>/dev/null || true
grep -rn "wr740n\|0740" "$IB/target/linux/ar71xx/" 2>/dev/null | head -n 20 || true

