#!/bin/bash
set -e
OUT=/mnt/c/Users/Mohamed/Desktop/tplink/wr740n_custom/files/etc/rmeter/tg_ca.pem
> "$OUT"
for pat in "Go_Daddy_Root_Certificate_Authority_-_G2" "DigiCert_Global_Root_G2" "DigiCert_Global_Root_CA" "ISRG_Root_X1" "GlobalSign_Root_CA_-_R3" "USERTrust_RSA" "USERTrust_ECC" "GTS_Root_R1" "GTS_Root_R4"; do
  f=$(ls /etc/ssl/certs/*${pat}*.pem 2>/dev/null | head -n 1 || true)
  if [ -n "$f" ] && [ -f "$f" ]; then
    echo "Adding $f"
    cat "$f" >> "$OUT"
  fi
done
ls -lh "$OUT"
echo "=== Testing TLS verify against api.telegram.org ==="
openssl s_client -connect api.telegram.org:443 -CAfile "$OUT" </dev/null 2>/dev/null | grep "Verify return code"
echo "=== Testing TLS verify against github.com ==="
openssl s_client -connect github.com:443 -CAfile "$OUT" </dev/null 2>/dev/null | grep "Verify return code"
