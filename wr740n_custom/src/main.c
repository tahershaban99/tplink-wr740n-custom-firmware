#include "rmeter.h"
#include "meter.h"
#include "firewall.h"
#include "telegram.h"
#include "json_util.h"
#include "fazakkir.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define CTRL_SOCK_PATH "/tmp/rmeter/ctrl.sock"

static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static unsigned long get_uptime_s(void) {
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp) return 0;
    double up = 0;
    if (fscanf(fp, "%lf", &up) != 1) up = 0;
    fclose(fp);
    return (unsigned long)up;
}

static void sync_static_lease_uci(const char *mac, const char *ip, const char *name) {
    if (!mac || !mac[0]) return;
    char cmd[320];
    /* Remove any old rmeter host entry for this MAC */
    char clean_id[32];
    int j = 0;
    for (int i = 0; mac[i] && j < 20; i++) {
        if (mac[i] != ':') clean_id[j++] = mac[i];
    }
    clean_id[j] = '\0';

    snprintf(cmd, sizeof(cmd), "uci -q delete dhcp.rm_%s 2>/dev/null || true", clean_id);
    system(cmd);
    if (ip && ip[0]) {
        snprintf(cmd, sizeof(cmd),
                 "uci set dhcp.rm_%s=host && "
                 "uci set dhcp.rm_%s.mac='%s' && "
                 "uci set dhcp.rm_%s.ip='%s' && "
                 "uci set dhcp.rm_%s.name='%s' && "
                 "uci commit dhcp && /etc/init.d/dnsmasq reload 2>/dev/null",
                 clean_id, clean_id, mac, clean_id, ip, clean_id,
                 (name && name[0]) ? name : "device");
        system(cmd);
    } else {
        system("uci commit dhcp 2>/dev/null");
    }
}

static void process_ctrl_json(const char *req, char *resp, size_t resp_sz) {
    char action[48] = {0};
    if (!json_get_str(req, "action", action, sizeof(action))) {
        snprintf(resp, resp_sz, "{\"ok\":false,\"error\":\"missing action\"}");
        return;
    }

    if (strcmp(action, "ping") == 0) {
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "device_save") == 0) {
        char mac[32] = {0}, name[64] = {0}, bound_ip[16] = {0}, chat[32] = {0};
        json_get_str(req, "mac", mac, sizeof(mac));
        if (!mac[0]) { snprintf(resp, resp_sz, "{\"ok\":false,\"error\":\"missing mac\"}"); return; }

        if (json_get_str(req, "name", name, sizeof(name))) meter_set_device_name(mac, name);
        uint64_t q = 0;
        if (json_get_u64(req, "quota_bytes", &q)) meter_set_device_quota(mac, q);
        uint64_t cu = 0, cd = 0;
        bool has_cu = json_get_u64(req, "cap_up_kbps", &cu);
        bool has_cd = json_get_u64(req, "cap_down_kbps", &cd);
        if (has_cu || has_cd) {
            pthread_mutex_lock(&g_lock);
            int idx = meter_find_by_mac_or_ip(mac);
            uint32_t u = has_cu ? (uint32_t)cu : (idx >= 0 ? g_devices[idx].cap_up_kbps : 0);
            uint32_t d = has_cd ? (uint32_t)cd : (idx >= 0 ? g_devices[idx].cap_down_kbps : 0);
            pthread_mutex_unlock(&g_lock);
            meter_set_device_speed_cap(mac, u, d);
        }
        bool b = false;
        if (json_get_bool(req, "blocked", &b)) meter_set_device_blocked(mac, b, false);
        bool g = false;
        if (json_get_bool(req, "gaming_mode", &g)) meter_set_device_gaming(mac, g);
        bool su = false;
        if (json_get_bool(req, "speed_unlocked", &su)) meter_set_device_speed_unlocked(mac, su);
        if (json_get_str(req, "tg_chat_id", chat, sizeof(chat))) meter_set_device_telegram(mac, chat);
        if (json_get_str(req, "bound_ip", bound_ip, sizeof(bound_ip))) {
            char cur_name[48] = {0};
            if (name[0]) {
                snprintf(cur_name, sizeof(cur_name), "%s", name);
            } else {
                pthread_mutex_lock(&g_lock);
                int idx = meter_find_by_mac_or_ip(mac);
                if (idx >= 0) snprintf(cur_name, sizeof(cur_name), "%s", g_devices[idx].name);
                pthread_mutex_unlock(&g_lock);
            }
            meter_set_device_binding(mac, bound_ip);
            sync_static_lease_uci(mac, bound_ip, cur_name);
        }
        meter_save_all();
        meter_write_ram_json();
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "device_block") == 0) {
        char mac[32] = {0};
        bool blk = false;
        json_get_str(req, "mac", mac, sizeof(mac));
        json_get_bool(req, "blocked", &blk);
        bool ok = meter_set_device_blocked(mac, blk, false);
        if (ok) { meter_save_all(); meter_write_ram_json(); }
        snprintf(resp, resp_sz, "{\"ok\":%s}", ok ? "true" : "false");
    } else if (strcmp(action, "device_gaming") == 0) {
        char mac[32] = {0};
        bool vip = false;
        json_get_str(req, "mac", mac, sizeof(mac));
        json_get_bool(req, "gaming_mode", &vip);
        bool ok = meter_set_device_gaming(mac, vip);
        if (ok) { meter_save_all(); meter_write_ram_json(); }
        snprintf(resp, resp_sz, "{\"ok\":%s}", ok ? "true" : "false");
    } else if (strcmp(action, "device_speed_unlock") == 0) {
        char mac[32] = {0};
        bool unl = false;
        json_get_str(req, "mac", mac, sizeof(mac));
        json_get_bool(req, "speed_unlocked", &unl);
        bool ok = meter_set_device_speed_unlocked(mac, unl);
        if (ok) { meter_save_all(); meter_write_ram_json(); }
        snprintf(resp, resp_sz, "{\"ok\":%s}", ok ? "true" : "false");
    } else if (strcmp(action, "device_add_quota") == 0) {
        char mac[32] = {0};
        int64_t add_b = 0;
        json_get_str(req, "mac", mac, sizeof(mac));
        json_get_i64(req, "add_bytes", &add_b);
        bool ok = meter_add_device_quota(mac, add_b);
        if (ok) { meter_save_all(); meter_write_ram_json(); }
        snprintf(resp, resp_sz, "{\"ok\":%s}", ok ? "true" : "false");
    } else if (strcmp(action, "device_reset") == 0) {
        char mac[32] = {0};
        json_get_str(req, "mac", mac, sizeof(mac));
        bool ok = meter_reset_device_usage(mac);
        if (ok) { meter_save_all(); meter_write_ram_json(); }
        snprintf(resp, resp_sz, "{\"ok\":%s}", ok ? "true" : "false");
    } else if (strcmp(action, "device_delete") == 0) {
        char mac[32] = {0};
        json_get_str(req, "mac", mac, sizeof(mac));
        bool ok = meter_delete_device(mac);
        if (ok) { meter_save_all(); meter_write_ram_json(); }
        snprintf(resp, resp_sz, "{\"ok\":%s}", ok ? "true" : "false");
    } else if (strcmp(action, "main_quota") == 0) {
        uint64_t mq = 0, pd = 30, wdl = 0, wul = 0;
        char sd[16] = {0}, ed[16] = {0};
        pthread_mutex_lock(&g_lock);
        if (json_get_u64(req, "main_quota_bytes", &mq)) {
            g_config.main_quota_bytes = mq;
            g_config.main_alert_flags = 0;
        }
        if (json_get_str(req, "start_date", sd, sizeof(sd))) snprintf(g_config.start_date, sizeof(g_config.start_date), "%s", sd);
        if (json_get_str(req, "end_date", ed, sizeof(ed))) snprintf(g_config.end_date, sizeof(g_config.end_date), "%s", ed);
        if (json_get_u64(req, "period_days", &pd)) g_config.period_days = (uint16_t)pd;
        if (json_get_u64(req, "wan_down_kbps", &wdl)) {
            g_config.wan_down_kbps = (uint32_t)wdl;
            g_tc_dirty = true;
        }
        if (json_get_u64(req, "wan_up_kbps", &wul)) {
            g_config.wan_up_kbps = (uint32_t)wul;
            g_tc_dirty = true;
        }
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "meter_scale") == 0) {
        uint64_t gbs = 1024, pct = 100, mode = 0;
        pthread_mutex_lock(&g_lock);
        if (json_get_u64(req, "gb_standard", &gbs) && (gbs == 1000 || gbs == 1024)) g_config.gb_standard = (uint16_t)gbs;
        if (json_get_u64(req, "scale_pct", &pct) && pct >= 50 && pct <= 200) g_config.scale_pct = (uint16_t)pct;
        if (json_get_u64(req, "scale_mode", &mode)) g_config.scale_mode = (uint8_t)mode;
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "meter_reset_all") == 0) {
        meter_reset_all_usage();
        meter_save_all();
        meter_write_ram_json();
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "auto_reboot") == 0) {
        bool en = false;
        uint64_t hr = 4, mn = 0;
        int64_t tz = 2;
        pthread_mutex_lock(&g_lock);
        if (json_get_bool(req, "enabled", &en)) g_config.auto_reboot_enabled = en;
        if (json_get_u64(req, "hour", &hr) && hr < 24) g_config.auto_reboot_hour = (uint8_t)hr;
        if (json_get_u64(req, "min", &mn) && mn < 60) g_config.auto_reboot_min = (uint8_t)mn;
        if (json_get_i64(req, "tz", &tz) && tz >= -12 && tz <= 14) g_config.auto_reboot_tz = (int8_t)tz;
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "reboot_now") == 0) {
        int64_t cd = 3;
        json_get_i64(req, "countdown_s", &cd);
        if (cd < -1) cd = -1;
        if (cd > 86400) cd = 86400;
        meter_save_all();
        g_reboot_countdown = (int32_t)cd;
        meter_write_ram_json();
        snprintf(resp, resp_sz, "{\"ok\":true,\"countdown_s\":%d}", (int)g_reboot_countdown);
    } else if (strcmp(action, "telegram_save") == 0) {
        bool en = false, inter = true, test = false;
        char tok[96] = {0}, ids[160] = {0}, thr[48] = {0};
        pthread_mutex_lock(&g_lock);
        if (json_get_bool(req, "enabled", &en)) g_config.tg_enabled = en;
        if (json_get_bool(req, "interactive", &inter)) g_config.tg_interactive = inter;
        if (json_get_str(req, "token", tok, sizeof(tok)) && tok[0]) snprintf(g_config.tg_token, sizeof(g_config.tg_token), "%s", tok);
        if (json_get_str(req, "admin_ids", ids, sizeof(ids))) snprintf(g_config.tg_admin_ids, sizeof(g_config.tg_admin_ids), "%s", ids);
        if (json_get_str(req, "thresholds", thr, sizeof(thr)) && thr[0]) {
            snprintf(g_config.tg_thresholds, sizeof(g_config.tg_thresholds), "%s", thr);
            g_config.main_alert_flags = 0;
        }
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        json_get_bool(req, "test", &test);
        if (test) {
            char err[128] = {0};
            bool ok = telegram_send_test(err, sizeof(err));
            snprintf(resp, resp_sz, "{\"ok\":%s,\"msg\":\"%s\"}",
                     ok ? "true" : "false", ok ? "Test message sent!" : err);
        } else {
            snprintf(resp, resp_sz, "{\"ok\":true}");
        }
    } else if (strcmp(action, "ota_save") == 0) {
        char url[192] = {0};
        bool auto_chk = true;
        bool has_auto = json_get_bool(req, "ota_auto_check", &auto_chk);
        bool has_url = json_get_str(req, "ota_version_url", url, sizeof(url));
        if (has_url || has_auto) {
            pthread_mutex_lock(&g_lock);
            if (has_url) snprintf(g_config.ota_version_url, sizeof(g_config.ota_version_url), "%s", url);
            if (has_auto) g_config.ota_auto_check_enabled = auto_chk;
            pthread_mutex_unlock(&g_lock);
            meter_save_all();
            meter_write_ram_json();
        }
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "sys_opts_save") == 0) {
        bool obs = false, ota_auto = true;
        pthread_mutex_lock(&g_lock);
        if (json_get_bool(req, "observer_mode", &obs)) g_config.observer_mode_enabled = obs;
        if (json_get_bool(req, "ota_auto_check", &ota_auto)) g_config.ota_auto_check_enabled = ota_auto;
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "tg_alerts_save") == 0) {
        for (int i = 0; i < RMETER_MAX_THRESHOLDS; i++) {
            char key[8];
            char val[256] = {0};
            snprintf(key, sizeof(key), "m%d", i);
            if (json_get_str(req, key, val, sizeof(val))) {
                meter_set_tg_alert_msg(i, val);
            }
        }
        meter_save_all();
        meter_write_ram_json();
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "flush_save") == 0) {
        meter_save_all();
        meter_write_ram_json();
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "fazakkir_reload") == 0) {
        fazakkir_reload();
        snprintf(resp, resp_sz, "{\"ok\":true}");
    } else if (strcmp(action, "fazakkir_refresh") == 0) {
        char err[128] = {0};
        bool ok = fazakkir_refresh_prayers(err, sizeof(err));
        char es[256];
        json_escape(err, es, sizeof(es));
        snprintf(resp, resp_sz, "{\"ok\":%s,\"msg\":\"%s\"}",
                 ok ? "true" : "false", ok ? "تم تحديث مواقيت الصلاة" : es);
    } else if (strcmp(action, "fazakkir_autolocate") == 0) {
        char city[48] = {0}, country[48] = {0}, err[128] = {0};
        bool ok = fazakkir_autolocate(city, sizeof(city), country, sizeof(country), err, sizeof(err));
        if (ok) {
            char dummy[128];
            fazakkir_refresh_prayers(dummy, sizeof(dummy));
        }
        char ec[96], eco[96], eerr[256];
        json_escape(city, ec, sizeof(ec));
        json_escape(country, eco, sizeof(eco));
        json_escape(err, eerr, sizeof(eerr));
        snprintf(resp, resp_sz, "{\"ok\":%s,\"city\":\"%s\",\"country\":\"%s\",\"msg\":\"%s\"}",
                 ok ? "true" : "false", ec, eco, ok ? "تم تحديد الموقع وتحديث المواقيت" : eerr);
    } else if (strcmp(action, "fazakkir_fetch_zikr") == 0) {
        char txt[384] = {0}, err[128] = {0};
        bool ok = fazakkir_fetch_zikr(true, txt, sizeof(txt), err, sizeof(err));
        char et[768], eerr[256];
        json_escape(txt, et, sizeof(et));
        json_escape(err, eerr, sizeof(eerr));
        snprintf(resp, resp_sz, "{\"ok\":%s,\"text\":\"%s\",\"msg\":\"%s\"}",
                 ok ? "true" : "false", et, ok ? "تم جلب الذكر وإضافته للبطاقات" : eerr);
    } else if (strcmp(action, "fazakkir_test") == 0) {
        uint64_t kind = 0;
        json_get_u64(req, "kind", &kind);
        char err[128] = {0};
        bool ok = fazakkir_send_test((int)kind, err, sizeof(err));
        char eerr[256];
        json_escape(err, eerr, sizeof(eerr));
        snprintf(resp, resp_sz, "{\"ok\":%s,\"msg\":\"%s\"}",
                 ok ? "true" : "false", ok ? "تم إرسال الإشعار التجريبي على تيليجرام" : eerr);
    } else {
        snprintf(resp, resp_sz, "{\"ok\":false,\"error\":\"unknown action\"}");
    }
}

static void *ctrl_ipc_thread(void *arg) {
    (void)arg;
    unlink(CTRL_SOCK_PATH);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) return NULL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CTRL_SOCK_PATH);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv);
        return NULL;
    }
    chmod(CTRL_SOCK_PATH, 0666);
    listen(srv, 8);

    while (g_running) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) {
            if (errno == EINTR) continue;
            break;
        }
        char req[6144] = {0};
        ssize_t n = read(cli, req, sizeof(req) - 1);
        if (n > 0) {
            req[n] = '\0';
            char resp[2048] = {0};
            process_ctrl_json(req, resp, sizeof(resp));
            write(cli, resp, strlen(resp));
        }
        close(cli);
    }
    close(srv);
    unlink(CTRL_SOCK_PATH);
    return NULL;
}

int main(void) {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    meter_init();
    meter_write_ram_json();
    telegram_init();
    fazakkir_init();

    pthread_t ipc_tid;
    if (pthread_create(&ipc_tid, NULL, ctrl_ipc_thread, NULL) == 0) {
        pthread_detach(ipc_tid);
    }

    time_t last_tick = time(NULL);
    time_t last_save = last_tick;
    int last_reboot_day = -1;

    while (g_running) {
        sleep(1);
        time_t now = time(NULL);
        double dt = difftime(now, last_tick);
        if (dt < 0.5) dt = 1.0;
        last_tick = now;

        meter_tick(dt);
        fazakkir_tick(now);
        meter_write_ram_json();

        if (g_flash_dirty && (now - last_save >= 600)) {
            meter_save_all();
            last_save = now;
        }

        /* Manual countdown reboot */
        if (g_reboot_countdown > 0) {
            g_reboot_countdown--;
            if (g_reboot_countdown == 0) {
                meter_save_all();
                sync();
                system("reboot");
                break;
            }
        }

        /* Scheduled daily auto-reboot (requires NTP valid year >= 2024 & uptime > 120s) */
        if (g_config.auto_reboot_enabled && get_uptime_s() > 120) {
            time_t local_t = now + (time_t)g_config.auto_reboot_tz * 3600;
            struct tm tm_val;
            if (gmtime_r(&local_t, &tm_val) && tm_val.tm_year + 1900 >= 2024) {
                if (tm_val.tm_hour == g_config.auto_reboot_hour &&
                    tm_val.tm_min == g_config.auto_reboot_min &&
                    last_reboot_day != tm_val.tm_yday) {
                    last_reboot_day = tm_val.tm_yday;
                    FILE *rf = fopen(RMETER_SCHED_RB_FLAG, "w");
                    if (rf) { fputs("1\n", rf); fclose(rf); }
                    meter_save_all();
                    sync();
                    system("reboot");
                    break;
                }
            }
        }
    }

    meter_save_all();
    return 0;
}

