#include "meter.h"
#include "firewall.h"
#include "json_util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

rmeter_device_t g_devices[RMETER_MAX_DEVICES];
int g_device_count = 0;
rmeter_config_t g_config;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

uint32_t g_total_up_bps = 0;
uint32_t g_total_down_bps = 0;
char g_wan_if[32] = "eth1";
char g_lan_if[32] = "br-lan";
int32_t g_reboot_countdown = -1;
bool g_fw_dirty = true;
bool g_tc_dirty = true;
bool g_flash_dirty = false;

static uint64_t s_prev_wan_rx = 0;
static uint64_t s_prev_wan_tx = 0;
static uint64_t s_prev_wan_ns = 0;
static uint64_t s_prev_ipt_ns = 0;
static uint64_t s_last_saved_raw_bytes = 0;
static bool s_wan_init = false;

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint32_t calc_clamped_bps(uint64_t delta_bytes, double dt_sec) {
    if (delta_bytes == 0 || dt_sec < 0.05) return 0;
    double bps = ((double)delta_bytes * 8.0) / dt_sec;
    if (bps >= 1000000000.0) return 1000000000U;
    return (uint32_t)bps;
}

static uint32_t smooth_bps(uint32_t prev, uint32_t inst) {
    if (inst == 0) return prev / 2U;
    uint64_t v = ((uint64_t)prev + (uint64_t)inst * 3ULL) / 4ULL;
    return (v > 1000000000ULL) ? 1000000000U : (uint32_t)v;
}
static char s_wifi_ssid[64] = "RouterMeter";
static char s_wifi_chan[16] = "auto";
static bool s_wifi_disabled = false;
static int s_wifi_txpower_dbm = 0;
static int s_wifi_signal_dbm = 0;
static time_t s_last_wifi_meta = 0;

static void norm_mac(const char *in, char *out, size_t sz) {
    if (!in || !out || sz < 18) return;
    size_t i = 0;
    for (; i < 17 && in[i]; i++) {
        out[i] = (char)toupper((unsigned char)in[i]);
    }
    out[i] = '\0';
}

uint64_t meter_scaled_bytes(uint64_t raw) {
    if (g_config.scale_mode == 0 && g_config.scale_pct != 100 && g_config.scale_pct > 0) {
        return (raw * (uint64_t)g_config.scale_pct) / 100ULL;
    }
    return raw;
}

uint64_t meter_total_used_bytes(void) {
    uint64_t sum = 0;
    for (int i = 0; i < g_device_count; i++) {
        sum += g_devices[i].up_bytes + g_devices[i].down_bytes;
    }
    return meter_scaled_bytes(sum);
}

int meter_find_by_mac(const char *mac) {
    char m[18];
    norm_mac(mac, m, sizeof(m));
    for (int i = 0; i < g_device_count; i++) {
        if (strcasecmp(g_devices[i].mac, m) == 0) return i;
    }
    return -1;
}

int meter_find_by_ip(const char *ip) {
    if (!ip || !ip[0]) return -1;
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].ip, ip) == 0) return i;
    }
    return -1;
}

int meter_find_by_mac_or_ip(const char *id) {
    int idx = meter_find_by_mac(id);
    if (idx >= 0) return idx;
    return meter_find_by_ip(id);
}

static int ensure_device(const char *mac, const char *ip, const char *hostname) {
    char m[18];
    norm_mac(mac, m, sizeof(m));
    if (strlen(m) != 17 || strcmp(m, "00:00:00:00:00:00") == 0) return -1;
    /* Reject multicast/broadcast MACs (LSB of first octet == 1) */
    unsigned int b0 = 0;
    if (sscanf(m, "%2x", &b0) == 1 && (b0 & 1U)) return -1;

    int idx = meter_find_by_mac(m);
    if (idx < 0) {
        if (g_device_count >= RMETER_MAX_DEVICES) return -1;
        idx = g_device_count++;
        memset(&g_devices[idx], 0, sizeof(rmeter_device_t));
        snprintf(g_devices[idx].mac, sizeof(g_devices[idx].mac), "%s", m);
        g_flash_dirty = true;
    }

    if (ip && ip[0] && strcmp(g_devices[idx].ip, ip) != 0) {
        snprintf(g_devices[idx].ip, sizeof(g_devices[idx].ip), "%s", ip);
        g_fw_dirty = true;
        g_tc_dirty = true;
    }
    if (hostname && hostname[0] && strcmp(hostname, "*") != 0 && g_devices[idx].name[0] == '\0') {
        snprintf(g_devices[idx].name, sizeof(g_devices[idx].name), "%s", hostname);
    }
    return idx;
}

static void init_default_config(void) {
    memset(&g_config, 0, sizeof(g_config));
    g_config.main_quota_bytes = 0;
    snprintf(g_config.start_date, sizeof(g_config.start_date), "2026-01-01");
    snprintf(g_config.end_date, sizeof(g_config.end_date), "2026-01-31");
    g_config.period_days = 30;
    g_config.gb_standard = 1024;
    g_config.scale_pct = 100;
    g_config.scale_mode = 0;
    g_config.auto_reboot_enabled = false;
    g_config.auto_reboot_hour = 4;
    g_config.auto_reboot_min = 0;
    g_config.auto_reboot_tz = 2; /* Egypt UTC+2 */
    g_config.tg_enabled = false;
    g_config.tg_interactive = true;
    snprintf(g_config.tg_thresholds, sizeof(g_config.tg_thresholds), "50,75,90,95,100");
    snprintf(g_config.fw_version, sizeof(g_config.fw_version), "1.1.3-wr740nv4");
    g_config.observer_mode_enabled = false;
    g_config.ota_auto_check_enabled = true;
}

void meter_load_all(void) {
    init_default_config();
    FILE *fp = fopen(RMETER_CFG_FLASH, "r");
    if (fp) {
        char line[384];
        while (fgets(line, sizeof(line), fp)) {
            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            const char *k = line;
            const char *v = eq + 1;
            if (strcmp(k, "main_quota_bytes") == 0) g_config.main_quota_bytes = strtoull(v, NULL, 10);
            else if (strcmp(k, "wan_down_kbps") == 0) g_config.wan_down_kbps = (uint32_t)strtoul(v, NULL, 10);
            else if (strcmp(k, "wan_up_kbps") == 0) g_config.wan_up_kbps = (uint32_t)strtoul(v, NULL, 10);
            else if (strcmp(k, "start_date") == 0) snprintf(g_config.start_date, sizeof(g_config.start_date), "%s", v);
            else if (strcmp(k, "end_date") == 0) snprintf(g_config.end_date, sizeof(g_config.end_date), "%s", v);
            else if (strcmp(k, "period_days") == 0) g_config.period_days = (uint16_t)atoi(v);
            else if (strcmp(k, "gb_standard") == 0) g_config.gb_standard = (uint16_t)atoi(v);
            else if (strcmp(k, "scale_pct") == 0) g_config.scale_pct = (uint16_t)atoi(v);
            else if (strcmp(k, "scale_mode") == 0) g_config.scale_mode = (uint8_t)atoi(v);
            else if (strcmp(k, "auto_reboot_enabled") == 0) g_config.auto_reboot_enabled = (atoi(v) != 0);
            else if (strcmp(k, "auto_reboot_hour") == 0) g_config.auto_reboot_hour = (uint8_t)atoi(v);
            else if (strcmp(k, "auto_reboot_min") == 0) g_config.auto_reboot_min = (uint8_t)atoi(v);
            else if (strcmp(k, "auto_reboot_tz") == 0) g_config.auto_reboot_tz = (int8_t)atoi(v);
            else if (strcmp(k, "tg_enabled") == 0) g_config.tg_enabled = (atoi(v) != 0);
            else if (strcmp(k, "tg_interactive") == 0) g_config.tg_interactive = (atoi(v) != 0);
            else if (strcmp(k, "tg_token") == 0) snprintf(g_config.tg_token, sizeof(g_config.tg_token), "%s", v);
            else if (strcmp(k, "tg_admin_ids") == 0) snprintf(g_config.tg_admin_ids, sizeof(g_config.tg_admin_ids), "%s", v);
            else if (strcmp(k, "tg_thresholds") == 0) snprintf(g_config.tg_thresholds, sizeof(g_config.tg_thresholds), "%s", v);
            else if (strcmp(k, "main_alert_flags") == 0) g_config.main_alert_flags = (uint16_t)atoi(v);
            else if (strcmp(k, "tg_last_update_id") == 0) g_config.tg_last_update_id = strtoll(v, NULL, 10);
            else if (strcmp(k, "ota_version_url") == 0) snprintf(g_config.ota_version_url, sizeof(g_config.ota_version_url), "%s", v);
            else if (strcmp(k, "observer_mode_enabled") == 0) g_config.observer_mode_enabled = (atoi(v) != 0);
            else if (strcmp(k, "ota_auto_check_enabled") == 0) g_config.ota_auto_check_enabled = (atoi(v) != 0);
        }
        fclose(fp);
    }

    fp = fopen(RMETER_TG_ALERTS_FLASH, "r");
    if (fp) {
        char line[768];
        while (fgets(line, sizeof(line), fp)) {
            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            int idx = atoi(line);
            if (idx < 0 || idx >= RMETER_MAX_THRESHOLDS) continue;
            const char *src = eq + 1;
            char *dst = g_config.tg_alert_msgs[idx];
            size_t j = 0;
            for (size_t i = 0; src[i] && j + 1 < sizeof(g_config.tg_alert_msgs[idx]); i++) {
                if (src[i] == '\\' && src[i + 1] == 'n') {
                    dst[j++] = '\n';
                    i++;
                } else if (src[i] == '\\' && src[i + 1] == '\\') {
                    dst[j++] = '\\';
                    i++;
                } else {
                    dst[j++] = src[i];
                }
            }
            dst[j] = '\0';
        }
        fclose(fp);
    }

    g_device_count = 0;
    fp = fopen(RMETER_STATE_FLASH, "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp) && g_device_count < RMETER_MAX_DEVICES) {
            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            if (!line[0] || line[0] == '#') continue;

            rmeter_device_t d;
            memset(&d, 0, sizeof(d));
            char *p = line;
            char *fields[14] = {0};
            int nf = 0;
            while (nf < 14) {
                fields[nf++] = p;
                char *sep = strchr(p, '|');
                if (!sep) break;
                *sep = '\0';
                p = sep + 1;
            }
            if (nf < 8) continue;
            norm_mac(fields[0], d.mac, sizeof(d.mac));
            snprintf(d.bound_ip, sizeof(d.bound_ip), "%s", fields[1]);
            if (d.bound_ip[0]) snprintf(d.ip, sizeof(d.ip), "%s", d.bound_ip);
            snprintf(d.name, sizeof(d.name), "%s", fields[2]);
            d.up_bytes = strtoull(fields[3], NULL, 10);
            d.down_bytes = strtoull(fields[4], NULL, 10);
            d.quota_bytes = strtoull(fields[5], NULL, 10);
            d.cap_up_kbps = (uint32_t)strtoul(fields[6], NULL, 10);
            d.cap_down_kbps = (uint32_t)strtoul(fields[7], NULL, 10);
            if (nf > 8) d.blocked = (atoi(fields[8]) != 0);
            if (nf > 9) d.auto_blocked = (atoi(fields[9]) != 0);
            if (nf > 10) d.gaming_mode = (atoi(fields[10]) != 0);
            if (nf > 11) d.alert_flags = (uint16_t)atoi(fields[11]);
            if (nf > 12) snprintf(d.tg_chat_id, sizeof(d.tg_chat_id), "%s", fields[12]);
            if (nf > 13) d.speed_unlocked = (atoi(fields[13]) != 0);
            g_devices[g_device_count++] = d;
        }
        fclose(fp);
    }
    s_last_saved_raw_bytes = 0;
    for (int i = 0; i < g_device_count; i++) {
        s_last_saved_raw_bytes += g_devices[i].up_bytes + g_devices[i].down_bytes;
    }
}

static bool commit_tmp_file(FILE *fp, const char *tmp_path, const char *dst_path) {
    if (!fp) return false;
    bool ok = (fflush(fp) == 0 && !ferror(fp));
    if (fclose(fp) != 0) ok = false;
    if (ok && rename(tmp_path, dst_path) != 0) ok = false;
    if (!ok) remove(tmp_path);
    return ok;
}

void meter_save_all(void) {
    mkdir("/etc/rmeter", 0755);

    rmeter_config_t *snap_cfg = malloc(sizeof(rmeter_config_t));
    rmeter_device_t *snap_devs = malloc(sizeof(rmeter_device_t) * RMETER_MAX_DEVICES);
    if (!snap_cfg || !snap_devs) {
        free(snap_cfg);
        free(snap_devs);
        return;
    }

    pthread_mutex_lock(&g_lock);
    *snap_cfg = g_config;
    int snap_cnt = g_device_count;
    if (snap_cnt < 0) snap_cnt = 0;
    if (snap_cnt > RMETER_MAX_DEVICES) snap_cnt = RMETER_MAX_DEVICES;
    uint64_t snap_raw = 0;
    if (snap_cnt > 0) {
        memcpy(snap_devs, g_devices, sizeof(rmeter_device_t) * (size_t)snap_cnt);
        for (int i = 0; i < snap_cnt; i++) {
            snap_raw += snap_devs[i].up_bytes + snap_devs[i].down_bytes;
        }
    }
    s_last_saved_raw_bytes = snap_raw;
    g_flash_dirty = false;
    pthread_mutex_unlock(&g_lock);

    bool write_err = false;
    char tmp_cfg[128];
    snprintf(tmp_cfg, sizeof(tmp_cfg), "%s.tmp", RMETER_CFG_FLASH);
    FILE *fp = fopen(tmp_cfg, "w");
    if (fp) {
        fprintf(fp, "main_quota_bytes=%llu\n", (unsigned long long)snap_cfg->main_quota_bytes);
        fprintf(fp, "wan_down_kbps=%u\n", (unsigned)snap_cfg->wan_down_kbps);
        fprintf(fp, "wan_up_kbps=%u\n", (unsigned)snap_cfg->wan_up_kbps);
        fprintf(fp, "start_date=%s\n", snap_cfg->start_date);
        fprintf(fp, "end_date=%s\n", snap_cfg->end_date);
        fprintf(fp, "period_days=%u\n", (unsigned)snap_cfg->period_days);
        fprintf(fp, "gb_standard=%u\n", (unsigned)snap_cfg->gb_standard);
        fprintf(fp, "scale_pct=%u\n", (unsigned)snap_cfg->scale_pct);
        fprintf(fp, "scale_mode=%u\n", (unsigned)snap_cfg->scale_mode);
        fprintf(fp, "auto_reboot_enabled=%d\n", snap_cfg->auto_reboot_enabled ? 1 : 0);
        fprintf(fp, "auto_reboot_hour=%u\n", (unsigned)snap_cfg->auto_reboot_hour);
        fprintf(fp, "auto_reboot_min=%u\n", (unsigned)snap_cfg->auto_reboot_min);
        fprintf(fp, "auto_reboot_tz=%d\n", (int)snap_cfg->auto_reboot_tz);
        fprintf(fp, "tg_enabled=%d\n", snap_cfg->tg_enabled ? 1 : 0);
        fprintf(fp, "tg_interactive=%d\n", snap_cfg->tg_interactive ? 1 : 0);
        fprintf(fp, "tg_token=%s\n", snap_cfg->tg_token);
        fprintf(fp, "tg_admin_ids=%s\n", snap_cfg->tg_admin_ids);
        fprintf(fp, "tg_thresholds=%s\n", snap_cfg->tg_thresholds);
        fprintf(fp, "main_alert_flags=%u\n", (unsigned)snap_cfg->main_alert_flags);
        fprintf(fp, "tg_last_update_id=%lld\n", (long long)snap_cfg->tg_last_update_id);
        fprintf(fp, "ota_version_url=%s\n", snap_cfg->ota_version_url);
        fprintf(fp, "observer_mode_enabled=%d\n", snap_cfg->observer_mode_enabled ? 1 : 0);
        fprintf(fp, "ota_auto_check_enabled=%d\n", snap_cfg->ota_auto_check_enabled ? 1 : 0);
        if (!commit_tmp_file(fp, tmp_cfg, RMETER_CFG_FLASH)) write_err = true;
    }

    char tmp_alerts[128];
    snprintf(tmp_alerts, sizeof(tmp_alerts), "%s.tmp", RMETER_TG_ALERTS_FLASH);
    fp = fopen(tmp_alerts, "w");
    if (fp) {
        for (int i = 0; i < RMETER_MAX_THRESHOLDS; i++) {
            if (!snap_cfg->tg_alert_msgs[i][0]) continue;
            fprintf(fp, "%d=", i);
            for (size_t k = 0; snap_cfg->tg_alert_msgs[i][k]; k++) {
                char c = snap_cfg->tg_alert_msgs[i][k];
                if (c == '\n') fputs("\\n", fp);
                else if (c == '\r') continue;
                else if (c == '\\') fputs("\\\\", fp);
                else fputc(c, fp);
            }
            fputc('\n', fp);
        }
        if (!commit_tmp_file(fp, tmp_alerts, RMETER_TG_ALERTS_FLASH)) write_err = true;
    }

    char tmp_db[128];
    snprintf(tmp_db, sizeof(tmp_db), "%s.tmp", RMETER_STATE_FLASH);
    fp = fopen(tmp_db, "w");
    if (fp) {
        for (int i = 0; i < snap_cnt; i++) {
            rmeter_device_t *d = &snap_devs[i];
            fprintf(fp, "%s|%s|%s|%llu|%llu|%llu|%u|%u|%d|%d|%d|%u|%s|%d\n",
                    d->mac, d->bound_ip, d->name,
                    (unsigned long long)d->up_bytes,
                    (unsigned long long)d->down_bytes,
                    (unsigned long long)d->quota_bytes,
                    (unsigned)d->cap_up_kbps,
                    (unsigned)d->cap_down_kbps,
                    d->blocked ? 1 : 0,
                    d->auto_blocked ? 1 : 0,
                    d->gaming_mode ? 1 : 0,
                    (unsigned)d->alert_flags,
                    d->tg_chat_id,
                    d->speed_unlocked ? 1 : 0);
        }
        if (!commit_tmp_file(fp, tmp_db, RMETER_STATE_FLASH)) write_err = true;
    }

    if (write_err) {
        pthread_mutex_lock(&g_lock);
        g_flash_dirty = true;
        pthread_mutex_unlock(&g_lock);
    }

    free(snap_cfg);
    free(snap_devs);
}

void meter_init(void) {
    mkdir("/tmp/rmeter", 0755);
    mkdir("/etc/rmeter", 0755);
    meter_load_all();
    fw_detect_wan_if(g_wan_if, sizeof(g_wan_if));
    fw_init();
    fw_ensure_device_rules(g_devices, g_device_count);
    fw_sync_blocks_and_vip(g_devices, g_device_count);
    fw_apply_tc(g_devices, g_device_count, g_lan_if, g_wan_if, g_config.wan_down_kbps, g_config.wan_up_kbps);
}

static bool read_sys_u64(const char *path, uint64_t *out) {
    FILE *fp = fopen(path, "r");
    if (!fp) return false;
    unsigned long long val = 0;
    bool ok = (fscanf(fp, "%llu", &val) == 1);
    fclose(fp);
    if (ok && out) *out = val;
    return ok;
}

static bool s_iw_ok = false;
static bool s_wifi_seen[RMETER_MAX_DEVICES];

static void discover_clients(time_t now) {
    s_iw_ok = false;
    memset(s_wifi_seen, 0, sizeof(s_wifi_seen));

    /* 1. /tmp/dhcp.leases: expiry mac ip name clientid (metadata/IP only, not live presence) */
    FILE *fp = fopen("/tmp/dhcp.leases", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            long long exp = 0;
            char mac[32] = {0}, ip[32] = {0}, name[64] = {0};
            if (sscanf(line, "%lld %31s %31s %63s", &exp, mac, ip, name) >= 3) {
                ensure_device(mac, ip, name);
            }
        }
        fclose(fp);
    }

    /* 2. /proc/net/arp: ip hw_type flags mac mask dev */
    fp = fopen("/proc/net/arp", "r");
    if (fp) {
        char line[256];
        if (!fgets(line, sizeof(line), fp)) { fclose(fp); fp = NULL; } /* skip header */
        while (fp && fgets(line, sizeof(line), fp)) {
            char ip[32] = {0}, hw[16] = {0}, flags[16] = {0}, mac[32] = {0}, mask[16] = {0}, dev[32] = {0};
            if (sscanf(line, "%31s %15s %15s %31s %15s %31s", ip, hw, flags, mac, mask, dev) == 6) {
                if (strcmp(dev, g_lan_if) == 0 && strcmp(flags, "0x0") != 0) {
                    int idx = ensure_device(mac, ip, NULL);
                    if (idx >= 0) {
                        if (!g_devices[idx].is_wifi) {
                            if (!g_devices[idx].online || g_devices[idx].connected_at == 0) g_devices[idx].connected_at = now;
                            g_devices[idx].last_seen = now;
                        }
                    }
                }
            }
        }
        fclose(fp);
    }

    /* 3. iwinfo assoclist for active Wi-Fi clients */
    FILE *iw = popen("iwinfo wlan0 assoclist 2>/dev/null", "r");
    if (iw) {
        s_iw_ok = true;
        char line[256];
        while (fgets(line, sizeof(line), iw)) {
            char mac[32] = {0};
            if (sscanf(line, "%17s", mac) == 1 && strlen(mac) == 17 && mac[2] == ':') {
                int idx = ensure_device(mac, NULL, NULL);
                if (idx >= 0) {
                    g_devices[idx].is_wifi = true;
                    s_wifi_seen[idx] = true;
                    if (!g_devices[idx].online || g_devices[idx].connected_at == 0) g_devices[idx].connected_at = now;
                    g_devices[idx].last_seen = now;
                }
            }
        }
        pclose(iw);
    }

    if (now - s_last_wifi_meta >= 15) {
        s_last_wifi_meta = now;
        FILE *iwi = popen("iwinfo wlan0 info 2>/dev/null", "r");
        if (iwi) {
            char line[256];
            bool saw_any = false;
            while (fgets(line, sizeof(line), iwi)) {
                saw_any = true;
                char *q = strstr(line, "ESSID: \"");
                if (q) {
                    q += 8;
                    char *eq = strchr(q, '"');
                    if (eq) {
                        size_t len = (size_t)(eq - q);
                        if (len >= sizeof(s_wifi_ssid)) len = sizeof(s_wifi_ssid) - 1;
                        memcpy(s_wifi_ssid, q, len);
                        s_wifi_ssid[len] = '\0';
                    }
                }
                char *ch = strstr(line, "Channel: ");
                if (ch) {
                    int cnum = 0;
                    if (sscanf(ch + 9, "%d", &cnum) == 1 && cnum > 0) {
                        snprintf(s_wifi_chan, sizeof(s_wifi_chan), "%d", cnum);
                    }
                }
                char *tp = strstr(line, "Tx-Power:");
                if (tp) {
                    int txp = 0;
                    if (sscanf(tp + 9, "%d", &txp) == 1) s_wifi_txpower_dbm = txp;
                }
                char *sg = strstr(line, "Signal:");
                if (sg) {
                    int sig = 0;
                    if (sscanf(sg + 7, "%d", &sig) == 1) s_wifi_signal_dbm = sig;
                }
            }
            s_wifi_disabled = !saw_any;
            pclose(iwi);
        }
    }
}

void meter_tick(double dt_sec) {
    if (dt_sec <= 0.05) dt_sec = 1.0;
    time_t now = time(NULL);

    pthread_mutex_lock(&g_lock);

    discover_clients(now);
    fw_ensure_device_rules(g_devices, g_device_count);

    /* Snapshot previous per-device bytes */
    uint64_t prev_up[RMETER_MAX_DEVICES];
    uint64_t prev_down[RMETER_MAX_DEVICES];
    for (int i = 0; i < g_device_count; i++) {
        prev_up[i] = g_devices[i].up_bytes;
        prev_down[i] = g_devices[i].down_bytes;
    }

    fw_read_counters(g_devices, g_device_count);
    uint64_t ipt_now_ns = monotonic_ns();
    double ipt_dt = (s_prev_ipt_ns > 0 && ipt_now_ns > s_prev_ipt_ns)
                        ? ((double)(ipt_now_ns - s_prev_ipt_ns) / 1e9)
                        : dt_sec;
    if (ipt_dt < 0.05) ipt_dt = 0.05;
    s_prev_ipt_ns = ipt_now_ns;

    uint64_t total_raw_bytes = 0;
    for (int i = 0; i < g_device_count; i++) {
        uint64_t du = (g_devices[i].up_bytes >= prev_up[i]) ? (g_devices[i].up_bytes - prev_up[i]) : 0;
        uint64_t dd = (g_devices[i].down_bytes >= prev_down[i]) ? (g_devices[i].down_bytes - prev_down[i]) : 0;
        total_raw_bytes += g_devices[i].up_bytes + g_devices[i].down_bytes;

        uint32_t inst_up = calc_clamped_bps(du, ipt_dt);
        uint32_t inst_dn = calc_clamped_bps(dd, ipt_dt);

        g_devices[i].cur_up_bps = smooth_bps(g_devices[i].cur_up_bps, inst_up);
        g_devices[i].cur_down_bps = smooth_bps(g_devices[i].cur_down_bps, inst_dn);

        if ((du > 0 || dd > 0) && !(g_devices[i].is_wifi && s_iw_ok && !s_wifi_seen[i])) {
            if (!g_devices[i].online || g_devices[i].connected_at == 0) g_devices[i].connected_at = now;
            g_devices[i].last_seen = now;
        }
        if (g_devices[i].is_wifi && s_iw_ok) {
            g_devices[i].online = s_wifi_seen[i];
        } else {
            g_devices[i].online = (g_devices[i].last_seen > 0 && (now - g_devices[i].last_seen) <= 10);
        }
        if (!g_devices[i].online) {
            g_devices[i].connected_at = 0;
            g_devices[i].cur_up_bps = 0;
            g_devices[i].cur_down_bps = 0;
        }

        /* Enforce per-device quota auto-block */
        if (g_devices[i].quota_bytes > 0) {
            uint64_t used = meter_scaled_bytes(g_devices[i].up_bytes + g_devices[i].down_bytes);
            if (used >= g_devices[i].quota_bytes && !g_devices[i].blocked) {
                g_devices[i].blocked = true;
                g_devices[i].auto_blocked = true;
                g_fw_dirty = true;
                g_flash_dirty = true;
            } else if (used < g_devices[i].quota_bytes && g_devices[i].auto_blocked) {
                g_devices[i].blocked = false;
                g_devices[i].auto_blocked = false;
                g_fw_dirty = true;
                g_flash_dirty = true;
            }
        }
    }

    /* Mark flash dirty periodically as traffic accumulates so sudden power loss loses <= 10 min */
    if (total_raw_bytes < s_last_saved_raw_bytes) {
        s_last_saved_raw_bytes = total_raw_bytes;
    } else if (total_raw_bytes - s_last_saved_raw_bytes >= 1048576ULL) {
        s_last_saved_raw_bytes = total_raw_bytes;
        g_flash_dirty = true;
    }

    /* Total WAN speed measured with exact monotonic timestamp directly at sysfs read */
    char p_rx[96], p_tx[96];
    snprintf(p_rx, sizeof(p_rx), "/sys/class/net/%s/statistics/rx_bytes", g_wan_if);
    snprintf(p_tx, sizeof(p_tx), "/sys/class/net/%s/statistics/tx_bytes", g_wan_if);
    uint64_t rx = 0, tx = 0;
    if (read_sys_u64(p_rx, &rx) && read_sys_u64(p_tx, &tx)) {
        uint64_t wan_now_ns = monotonic_ns();
        if (s_wan_init && rx >= s_prev_wan_rx && tx >= s_prev_wan_tx && s_prev_wan_ns > 0 && wan_now_ns > s_prev_wan_ns) {
            double wan_dt = (double)(wan_now_ns - s_prev_wan_ns) / 1e9;
            if (wan_dt < 0.05) wan_dt = 0.05;
            uint32_t inst_dn = calc_clamped_bps(rx - s_prev_wan_rx, wan_dt);
            uint32_t inst_up = calc_clamped_bps(tx - s_prev_wan_tx, wan_dt);
            g_total_down_bps = smooth_bps(g_total_down_bps, inst_dn);
            g_total_up_bps   = smooth_bps(g_total_up_bps, inst_up);
        }
        s_prev_wan_rx = rx;
        s_prev_wan_tx = tx;
        s_prev_wan_ns = wan_now_ns;
        s_wan_init = true;
    }

    static time_t s_last_hook_check = 0;
    if (now - s_last_hook_check >= 15) {
        s_last_hook_check = now;
        if (fw_check_hooks()) {
            g_fw_dirty = true;
            g_tc_dirty = true;
        }
    }

    if (g_fw_dirty) {
        fw_sync_blocks_and_vip(g_devices, g_device_count);
        g_fw_dirty = false;
    }
    if (g_tc_dirty) {
        fw_apply_tc(g_devices, g_device_count, g_lan_if, g_wan_if, g_config.wan_down_kbps, g_config.wan_up_kbps);
        g_tc_dirty = false;
    }

    pthread_mutex_unlock(&g_lock);
}

static void read_sys_stats(unsigned long *uptime_s, unsigned long *ram_total_kb, unsigned long *ram_free_kb,
                           double *cpu_load, unsigned long *flash_total_kb, unsigned long *flash_free_kb) {
    *uptime_s = 0;
    *ram_total_kb = 0;
    *ram_free_kb = 0;
    *cpu_load = 0.0;
    *flash_total_kb = 0;
    *flash_free_kb = 0;

    FILE *fp = fopen("/proc/uptime", "r");
    if (fp) {
        double up = 0;
        if (fscanf(fp, "%lf", &up) == 1) *uptime_s = (unsigned long)up;
        fclose(fp);
    }
    fp = fopen("/proc/loadavg", "r");
    if (fp) {
        double l1 = 0.0;
        if (fscanf(fp, "%lf", &l1) == 1 && l1 >= 0.0) *cpu_load = l1;
        fclose(fp);
    }
    fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[128];
        unsigned long mfree = 0, mbuf = 0, mcache = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "MemTotal:", 9) == 0) sscanf(line + 9, "%lu", ram_total_kb);
            else if (strncmp(line, "MemFree:", 8) == 0) sscanf(line + 8, "%lu", &mfree);
            else if (strncmp(line, "Buffers:", 8) == 0) sscanf(line + 8, "%lu", &mbuf);
            else if (strncmp(line, "Cached:", 7) == 0) sscanf(line + 7, "%lu", &mcache);
        }
        *ram_free_kb = mfree + mbuf + mcache;
        fclose(fp);
    }
    struct statvfs vfs;
    if (statvfs("/overlay", &vfs) == 0 || statvfs("/", &vfs) == 0) {
        *flash_total_kb = (unsigned long)(((uint64_t)vfs.f_blocks * vfs.f_frsize) / 1024ULL);
        *flash_free_kb = (unsigned long)(((uint64_t)vfs.f_bavail * vfs.f_frsize) / 1024ULL);
    }
}

void meter_write_ram_json(void) {
    unsigned long uptime_s = 0, ram_tot = 0, ram_free = 0, flash_tot = 0, flash_free = 0;
    double cpu_load = 0.0;
    read_sys_stats(&uptime_s, &ram_tot, &ram_free, &cpu_load, &flash_tot, &flash_free);
    time_t now = time(NULL);

    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s.tmp", RMETER_STATE_RAM);

    pthread_mutex_lock(&g_lock);
    FILE *fp = fopen(tmp, "w");
    if (fp) {
        uint64_t total_used = meter_total_used_bytes();
        char esc_tok[192], esc_ids[320], esc_thr[96], esc_ota[384], esc_ssid[128];
        json_escape(g_config.tg_token, esc_tok, sizeof(esc_tok));
        json_escape(g_config.tg_admin_ids, esc_ids, sizeof(esc_ids));
        json_escape(g_config.tg_thresholds, esc_thr, sizeof(esc_thr));
        json_escape(g_config.ota_version_url, esc_ota, sizeof(esc_ota));
        json_escape(s_wifi_ssid, esc_ssid, sizeof(esc_ssid));

        int wifi_clients = 0;
        for (int i = 0; i < g_device_count; i++) {
            if (g_devices[i].online && g_devices[i].is_wifi) wifi_clients++;
        }

        char rtime_str[72] = "غير متزامن";
        bool time_synced = false;
        time_t local_t = now + (time_t)g_config.auto_reboot_tz * 3600;
        struct tm tm_val;
        if (gmtime_r(&local_t, &tm_val) && tm_val.tm_year + 1900 >= 2024) {
            time_synced = true;
            snprintf(rtime_str, sizeof(rtime_str), "%04d-%02d-%02d %02d:%02d:%02d",
                     tm_val.tm_year + 1900, tm_val.tm_mon + 1, tm_val.tm_mday,
                     tm_val.tm_hour, tm_val.tm_min, tm_val.tm_sec);
        }

        fprintf(fp, "{\n");
        fprintf(fp, "  \"fw_version\": \"%s\",\n", g_config.fw_version);
        fprintf(fp, "  \"wan_if\": \"%s\",\n", g_wan_if);
        fprintf(fp, "  \"uptime_s\": %lu,\n", uptime_s);
        fprintf(fp, "  \"ram_total_kb\": %lu,\n", ram_tot);
        fprintf(fp, "  \"ram_free_kb\": %lu,\n", ram_free);
        fprintf(fp, "  \"cpu_load\": %.2f,\n", cpu_load);
        fprintf(fp, "  \"flash_total_kb\": %lu,\n", flash_tot);
        fprintf(fp, "  \"flash_free_kb\": %lu,\n", flash_free);
        fprintf(fp, "  \"observer_mode\": %s,\n", g_config.observer_mode_enabled ? "true" : "false");
        fprintf(fp, "  \"ota_auto_check\": %s,\n", g_config.ota_auto_check_enabled ? "true" : "false");
        fprintf(fp, "  \"time_synced\": %s,\n", time_synced ? "true" : "false");
        fprintf(fp, "  \"router_time\": \"%s\",\n", rtime_str);
        fprintf(fp, "  \"wifi_ssid\": \"%s\",\n", esc_ssid);
        fprintf(fp, "  \"wifi_channel\": \"%s\",\n", s_wifi_chan);
        fprintf(fp, "  \"wifi_disabled\": %s,\n", s_wifi_disabled ? "true" : "false");
        fprintf(fp, "  \"wifi_txpower_dbm\": %d,\n", s_wifi_txpower_dbm);
        fprintf(fp, "  \"wifi_signal_dbm\": %d,\n", s_wifi_signal_dbm);
        fprintf(fp, "  \"wifi_clients\": %d,\n", wifi_clients);
        fprintf(fp, "  \"total_up_bps\": %u,\n", (unsigned)g_total_up_bps);
        fprintf(fp, "  \"total_down_bps\": %u,\n", (unsigned)g_total_down_bps);
        fprintf(fp, "  \"total_used_bytes\": %llu,\n", (unsigned long long)total_used);
        fprintf(fp, "  \"main_quota_bytes\": %llu,\n", (unsigned long long)g_config.main_quota_bytes);
        fprintf(fp, "  \"start_date\": \"%s\",\n", g_config.start_date);
        fprintf(fp, "  \"end_date\": \"%s\",\n", g_config.end_date);
        fprintf(fp, "  \"period_days\": %u,\n", (unsigned)g_config.period_days);
        fprintf(fp, "  \"gb_standard\": %u,\n", (unsigned)g_config.gb_standard);
        fprintf(fp, "  \"scale_pct\": %u,\n", (unsigned)g_config.scale_pct);
        fprintf(fp, "  \"scale_mode\": %u,\n", (unsigned)g_config.scale_mode);
        fprintf(fp, "  \"wan_down_kbps\": %u,\n", (unsigned)g_config.wan_down_kbps);
        fprintf(fp, "  \"wan_up_kbps\": %u,\n", (unsigned)g_config.wan_up_kbps);
        fprintf(fp, "  \"auto_reboot_enabled\": %s,\n", g_config.auto_reboot_enabled ? "true" : "false");
        fprintf(fp, "  \"auto_reboot_hour\": %u,\n", (unsigned)g_config.auto_reboot_hour);
        fprintf(fp, "  \"auto_reboot_min\": %u,\n", (unsigned)g_config.auto_reboot_min);
        fprintf(fp, "  \"auto_reboot_tz\": %d,\n", (int)g_config.auto_reboot_tz);
        fprintf(fp, "  \"reboot_countdown_s\": %d,\n", (int)g_reboot_countdown);
        fprintf(fp, "  \"tg_enabled\": %s,\n", g_config.tg_enabled ? "true" : "false");
        fprintf(fp, "  \"tg_interactive\": %s,\n", g_config.tg_interactive ? "true" : "false");
        fprintf(fp, "  \"tg_has_token\": %s,\n", g_config.tg_token[0] ? "true" : "false");
        fprintf(fp, "  \"tg_token\": \"%s\",\n", esc_tok);
        fprintf(fp, "  \"tg_admin_ids\": \"%s\",\n", esc_ids);
        fprintf(fp, "  \"tg_thresholds\": \"%s\",\n", esc_thr);
        fprintf(fp, "  \"ota_version_url\": \"%s\",\n", esc_ota);
        fprintf(fp, "  \"tg_alert_msgs\": [");
        for (int a = 0; a < RMETER_MAX_THRESHOLDS; a++) {
            char esc_msg[512];
            json_escape(g_config.tg_alert_msgs[a], esc_msg, sizeof(esc_msg));
            fprintf(fp, "\"%s\"%s", esc_msg, (a + 1 < RMETER_MAX_THRESHOLDS) ? "," : "");
        }
        fprintf(fp, "],\n");
        fprintf(fp, "  \"devices\": [\n");

        for (int i = 0; i < g_device_count; i++) {
            rmeter_device_t *d = &g_devices[i];
            char esc_name[128], esc_chat[64];
            json_escape(d->name, esc_name, sizeof(esc_name));
            json_escape(d->tg_chat_id, esc_chat, sizeof(esc_chat));
            uint64_t su = meter_scaled_bytes(d->up_bytes);
            uint64_t sd = meter_scaled_bytes(d->down_bytes);
            long long conn_s = (d->online && d->connected_at > 0 && now >= d->connected_at) ? (long long)(now - d->connected_at) : 0;

            fprintf(fp,
                    "    {\"mac\":\"%s\",\"ip\":\"%s\",\"bound_ip\":\"%s\",\"name\":\"%s\","
                    "\"up_bytes\":%llu,\"down_bytes\":%llu,\"quota_bytes\":%llu,"
                    "\"cap_up_kbps\":%u,\"cap_down_kbps\":%u,"
                    "\"cur_up_bps\":%u,\"cur_down_bps\":%u,"
                    "\"online\":%s,\"blocked\":%s,\"auto_blocked\":%s,\"gaming_mode\":%s,\"speed_unlocked\":%s,\"is_wifi\":%s,"
                    "\"connected_s\":%lld,\"tg_chat_id\":\"%s\",\"last_seen\":%lld}%s\n",
                    d->mac, d->ip, d->bound_ip, esc_name,
                    (unsigned long long)su, (unsigned long long)sd, (unsigned long long)d->quota_bytes,
                    (unsigned)d->cap_up_kbps, (unsigned)d->cap_down_kbps,
                    (unsigned)d->cur_up_bps, (unsigned)d->cur_down_bps,
                    d->online ? "true" : "false",
                    d->blocked ? "true" : "false",
                    d->auto_blocked ? "true" : "false",
                    d->gaming_mode ? "true" : "false",
                    d->speed_unlocked ? "true" : "false",
                    d->is_wifi ? "true" : "false",
                    conn_s, esc_chat, (long long)d->last_seen,
                    (i + 1 < g_device_count) ? "," : "");
        }
        fprintf(fp, "  ]\n}\n");
        fclose(fp);
        rename(tmp, RMETER_STATE_RAM);
    }
    pthread_mutex_unlock(&g_lock);
}

bool meter_set_device_blocked(const char *mac, bool blocked, bool is_auto) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    g_devices[idx].blocked = blocked;
    g_devices[idx].auto_blocked = blocked ? is_auto : false;
    g_fw_dirty = true;
    g_tc_dirty = true;
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_set_device_gaming(const char *mac, bool gaming) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    g_devices[idx].gaming_mode = gaming;
    g_fw_dirty = true;
    g_tc_dirty = true;
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_set_device_quota(const char *mac, uint64_t quota_bytes) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    g_devices[idx].quota_bytes = quota_bytes;
    g_devices[idx].alert_flags = 0;
    if (quota_bytes == 0 || meter_scaled_bytes(g_devices[idx].up_bytes + g_devices[idx].down_bytes) < quota_bytes) {
        if (g_devices[idx].auto_blocked) {
            g_devices[idx].blocked = false;
            g_devices[idx].auto_blocked = false;
            g_fw_dirty = true;
        }
    }
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_add_device_quota(const char *mac, int64_t add_bytes) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    int64_t q = (int64_t)g_devices[idx].quota_bytes + add_bytes;
    if (q < 0) q = 0;
    g_devices[idx].quota_bytes = (uint64_t)q;
    g_devices[idx].alert_flags = 0;
    uint64_t used = meter_scaled_bytes(g_devices[idx].up_bytes + g_devices[idx].down_bytes);
    if (g_devices[idx].quota_bytes == 0 || used < g_devices[idx].quota_bytes) {
        if (g_devices[idx].auto_blocked || add_bytes > 0) {
            g_devices[idx].blocked = false;
            g_devices[idx].auto_blocked = false;
            g_fw_dirty = true;
        }
    }
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_set_device_speed_cap(const char *mac, uint32_t up_kbps, uint32_t down_kbps) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    if (g_devices[idx].cap_up_kbps != up_kbps || g_devices[idx].cap_down_kbps != down_kbps) {
        g_devices[idx].cap_up_kbps = up_kbps;
        g_devices[idx].cap_down_kbps = down_kbps;
        g_devices[idx].speed_unlocked = false;
        g_tc_dirty = true;
        g_flash_dirty = true;
    }
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_set_device_speed_unlocked(const char *mac, bool unlocked) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    g_devices[idx].speed_unlocked = unlocked;
    g_tc_dirty = true;
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_set_device_name(const char *mac, const char *name) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    snprintf(g_devices[idx].name, sizeof(g_devices[idx].name), "%s", name ? name : "");
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_set_device_binding(const char *mac, const char *bound_ip) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    snprintf(g_devices[idx].bound_ip, sizeof(g_devices[idx].bound_ip), "%s", bound_ip ? bound_ip : "");
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_set_device_telegram(const char *mac, const char *chat_id) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    snprintf(g_devices[idx].tg_chat_id, sizeof(g_devices[idx].tg_chat_id), "%s", chat_id ? chat_id : "");
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_reset_device_usage(const char *mac) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    g_devices[idx].up_bytes = 0;
    g_devices[idx].down_bytes = 0;
    g_devices[idx].alert_flags = 0;
    if (g_devices[idx].auto_blocked) {
        g_devices[idx].blocked = false;
        g_devices[idx].auto_blocked = false;
        g_fw_dirty = true;
    }
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool meter_delete_device(const char *mac) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac_or_ip(mac);
    if (idx < 0) { pthread_mutex_unlock(&g_lock); return false; }
    for (int i = idx; i + 1 < g_device_count; i++) {
        g_devices[i] = g_devices[i + 1];
    }
    g_device_count--;
    g_fw_dirty = true;
    g_tc_dirty = true;
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

void meter_reset_all_usage(void) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_device_count; i++) {
        g_devices[i].up_bytes = 0;
        g_devices[i].down_bytes = 0;
        g_devices[i].alert_flags = 0;
        if (g_devices[i].auto_blocked) {
            g_devices[i].blocked = false;
            g_devices[i].auto_blocked = false;
            g_fw_dirty = true;
        }
    }
    g_config.main_alert_flags = 0;
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
}

void meter_set_tg_alert_msg(int slot, const char *msg) {
    if (slot < 0 || slot >= RMETER_MAX_THRESHOLDS) return;
    pthread_mutex_lock(&g_lock);
    snprintf(g_config.tg_alert_msgs[slot], sizeof(g_config.tg_alert_msgs[slot]), "%s", msg ? msg : "");
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
}

void meter_fmt_bytes_short(uint64_t b, char *out, size_t sz) {
    double std = (g_config.gb_standard == 1000) ? 1000.0 : 1024.0;
    double mb = (double)b / (std * std);
    double gb = mb / std;
    if (gb >= 1.0) snprintf(out, sz, "%.2f GB", gb);
    else snprintf(out, sz, "%.1f MB", mb);
}

void meter_format_alert_template(const char *tmpl, const char *name, const char *ip,
                                 unsigned pct, const char *used_str,
                                 const char *quota_str, const char *rem_str,
                                 char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    if (!tmpl || !tmpl[0]) {
        out[0] = '\0';
        return;
    }
    char pct_buf[16];
    snprintf(pct_buf, sizeof(pct_buf), "%u%%", pct);

    size_t pos = 0;
    const char *p = tmpl;
    while (*p && pos + 1 < out_sz) {
        const char *rep = NULL;
        size_t adv = 0;
        if (strncmp(p, "{name}", 6) == 0) { rep = name ? name : ""; adv = 6; }
        else if (strncmp(p, "{ip}", 4) == 0) { rep = ip ? ip : ""; adv = 4; }
        else if (strncmp(p, "{pct}", 5) == 0) { rep = pct_buf; adv = 5; }
        else if (strncmp(p, "{used}", 6) == 0) { rep = used_str ? used_str : "0"; adv = 6; }
        else if (strncmp(p, "{quota}", 7) == 0) { rep = quota_str ? quota_str : "0"; adv = 7; }
        else if (strncmp(p, "{rem}", 5) == 0) { rep = rem_str ? rem_str : "0"; adv = 5; }

        if (rep) {
            size_t rlen = strlen(rep);
            size_t avail = out_sz - 1 - pos;
            if (rlen > avail) rlen = avail;
            memcpy(out + pos, rep, rlen);
            pos += rlen;
            p += adv;
        } else {
            out[pos++] = *p++;
        }
    }
    out[pos] = '\0';
}
