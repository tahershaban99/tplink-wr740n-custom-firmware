#!/bin/bash
set -e
IB=/home/lpl2/wr740n_build/openwrt-imagebuilder-18.06.9-ar71xx-tiny.Linux-x86_64
R=$IB/build_dir/target-mips_24kc_musl/root-ar71xx

echo "=== iptables binary & libs ==="
ls -la "$R/usr/sbin/" | grep -E "ipt|xtab" || true
strings "$R/usr/sbin/xtables-multi" 2>/dev/null | grep -E "mac-source|set-mark" || strings "$R/usr/lib/libxtables.so"* 2>/dev/null | grep -E "mac-source|set-mark" || true
echo "=== Why nf_conntrack_ipv6? ==="
grep -l "kmod-nf-conntrack6" "$R/usr/lib/opkg/info/"*.control 2>/dev/null || true

echo "=== Checking Telegram Root CA (api.telegram.org) ==="
openssl s_client -showcerts -connect api.telegram.org:443 </dev/null 2>/dev/null | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/{print}' | head -n 5 || true
# Better: extract GoDaddy Class 2 + G2 + DigiCert + GTS + ISRG Root CAs from /etc/ssl/certs/
OUT=/mnt/c/Users/Mohamed/Desktop/tplink/wr740n_custom/files/etc/rmeter/tg_ca.pem
mkdir -p "$(dirname "$OUT")"
> "$OUT"
for pat in "Go_Daddy_Root_Certificate_Authority_-_G2" "Go_Daddy_Class_2" "DigiCert_Global_Root_G2" "DigiCert_Global_Root_CA" "ISRG_Root_X1" "GlobalSign_Root_CA" "USERTrust_RSA"; do
  f=$(ls /etc/ssl/certs/*${pat}*.pem 2>/dev/null | head -n 1 || true)
  if [ -n "$f" ] && [ -f "$f" ]; then
    echo "Adding $f"
    cat "$f" >> "$OUT"
  fi
done
ls -lh "$OUT"
openssl x509 -in "$OUT" -noout -subject 2>/dev/null || true

