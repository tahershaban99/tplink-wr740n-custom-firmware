# TP-Link TL-WR740N v4 Custom OpenWrt 18.06.9 Firmware (`RouterMeter`)

Custom lightweight, IPv6-free OpenWrt **18.06.9** (`ar71xx/tiny`) firmware and C/CGI management stack tailored for the **TP-Link TL-WR740N v4** (`4 MB` Flash / `32 MB` RAM, `AR9331`).

## Features

- **Per-Device Bandwidth & Quota Metering (`rmeterd`):** Live upload/download rate tracking, cumulative quota caps with auto-block at 100%, static DHCP IP binding, and per-device upload/download speed limits (`tc` / `iptables`).
- **VIP Gaming / DSCP Priority:** Low-latency EF DSCP prioritization toggle per device.
- **Telegram Bot Integration:** Notifications, threshold alerts, and interactive bot controls over HTTPS (`libustream-mbedtls` + `/etc/rmeter/tg_ca.pem`).
- **Auto-Reboot Scheduler & OTA Sysupgrade UI:** Built-in web dashboard (`uhttpd` + `/cgi-bin/api`) with firmware upload & verification.
- **IPv6-Free & Optimized Wireless (`ath9k`):** Strips IPv6 packages to preserve `~327 KB` free JFFS2 overlay, configures `country='JP'` (unlocks Channels 12–13 at full `18 dBm` TX power), `HT40` with `noscan='1'`, and `legacy_rates='0'`.

## Repository Structure

- `wr740n_custom/src/` — C daemon (`rmeterd`) and CGI API (`rmeter_cgi`)
- `wr740n_custom/files/` — OpenWrt rootfs overlay (`/www/index.html`, `/etc/init.d/rmeterd`, `/etc/uci-defaults/99-rmeter-setup`, `/etc/config/uhttpd`, `/etc/rmeter/tg_ca.pem`)
- `wr740n_custom/tests/` — Host unit tests (`test_unit.c`)
- `wr740n_custom/build_final.sh` — End-to-end test, cross-compile, and OpenWrt ImageBuilder script
- `output/` — Pre-built firmware images (`routermeter-wr740n-v4-sysupgrade.bin`, `routermeter-wr740n-v4-factory.bin`), package manifest, and `sha256sums.txt`

## Pre-Built Checksums (`output/sha256sums.txt`)

- `routermeter-wr740n-v4-sysupgrade.bin`: `c3d0c7933dc4a6ee1fd56424681bfd2c264823b8da0fe47accec311b4def2158` (`3,604,484` bytes)
- `routermeter-wr740n-v4-factory.bin`: `953d075661462dd680b7e1ac7b157c1ae6a87ceb41385f8aecf16e5a4c54e0c3` (`3,932,160` bytes)

## Building (Ubuntu / WSL)

Requires OpenWrt 18.06.9 `ar71xx-tiny` SDK and ImageBuilder configured in `wr740n_custom/build_final.sh`:

```bash
bash wr740n_custom/build_final.sh
```

