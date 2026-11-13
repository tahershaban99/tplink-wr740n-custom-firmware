#include "telegram.h"
#include "meter.h"
#include "json_util.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TG_REQ_FILE  "/tmp/rmeter/tg_req.json"
#define TG_RESP_FILE "/tmp/rmeter/tg_resp.json"
#define TG_CA_FILE   "/etc/rmeter/tg_ca.pem"

static pthread_mutex_t s_tg_http_lock = PTHREAD_MUTEX_INITIALIZER;
static bool s_tg_thread_started = false;

typedef struct {
    char chat_id[32];
    char name[48];
    char username[32];
    time_t last_seen;
} tg_user_t;

static tg_user_t s_tg_users[12];
static int s_tg_user_count = 0;

static void fmt_bytes(uint64_t b, char *out, size_t sz) {
    double div_gb = (g_config.gb_standard == 1000) ? 1000.0 : 1024.0;
    double kb = (double)b / div_gb;
    double mb = kb / div_gb;
    double gb = mb / div_gb;
    if (gb >= 1.0) snprintf(out, sz, "%.2f GB", gb);
    else if (mb >= 1.0) snprintf(out, sz, "%.1f MB", mb);
    else snprintf(out, sz, "%.0f KB", kb);
}

static void fmt_bps(uint32_t bps, char *out, size_t sz) {
    if (bps >= 1000000U) snprintf(out, sz, "%.2f Mbps", (double)bps / 1000000.0);
    else if (bps >= 1000U) snprintf(out, sz, "%.0f Kbps", (double)bps / 1000.0);
    else snprintf(out, sz, "%u bps", (unsigned)bps);
}

static void save_discovered_users(void) {
    FILE *fp = fopen(RMETER_TG_USERS_RAM ".tmp", "w");
    if (!fp) return;
    fprintf(fp, "[");
    for (int i = 0; i < s_tg_user_count; i++) {
        char en[96], eu[64];
        json_escape(s_tg_users[i].name, en, sizeof(en));
        json_escape(s_tg_users[i].username, eu, sizeof(eu));
        fprintf(fp, "{\"chat_id\":\"%s\",\"name\":\"%s\",\"username\":\"%s\",\"last_seen\":%lld}%s",
                s_tg_users[i].chat_id, en, eu, (long long)s_tg_users[i].last_seen,
                (i + 1 < s_tg_user_count) ? "," : "");
    }
    fprintf(fp, "]\n");
    fclose(fp);
    rename(RMETER_TG_USERS_RAM ".tmp", RMETER_TG_USERS_RAM);
}

static void register_tg_user(const char *chat_id, const char *name, const char *username) {
    if (!chat_id || !chat_id[0]) return;
    time_t now = time(NULL);
    for (int i = 0; i < s_tg_user_count; i++) {
        if (strcmp(s_tg_users[i].chat_id, chat_id) == 0) {
            if (name && name[0]) snprintf(s_tg_users[i].name, sizeof(s_tg_users[i].name), "%s", name);
            if (username && username[0]) snprintf(s_tg_users[i].username, sizeof(s_tg_users[i].username), "%s", username);
            s_tg_users[i].last_seen = now;
            save_discovered_users();
            return;
        }
    }
    if (s_tg_user_count < 12) {
        tg_user_t *u = &s_tg_users[s_tg_user_count++];
        memset(u, 0, sizeof(*u));
        snprintf(u->chat_id, sizeof(u->chat_id), "%s", chat_id);
        snprintf(u->name, sizeof(u->name), "%s", name ? name : "");
        snprintf(u->username, sizeof(u->username), "%s", username ? username : "");
        u->last_seen = now;
        save_discovered_users();
    }
}

static bool tg_is_admin(const char *chat_id) {
    if (!chat_id || !chat_id[0]) return false;
    char copy[160];
    snprintf(copy, sizeof(copy), "%s", g_config.tg_admin_ids);
    char *tok = strtok(copy, ",; ");
    while (tok) {
        if (strcmp(tok, chat_id) == 0) return true;
        tok = strtok(NULL, ",; ");
    }
    return false;
}

static bool tg_post_api(const char *method, const char *json_body, char *resp_buf, size_t resp_sz) {
    if (!g_config.tg_token[0]) return false;
    pthread_mutex_lock(&s_tg_http_lock);

    FILE *fp = fopen(TG_REQ_FILE, "w");
    if (!fp) {
        pthread_mutex_unlock(&s_tg_http_lock);
        return false;
    }
    fputs(json_body, fp);
    fclose(fp);

    char cmd[512];
    const char *ca_opt = (access(TG_CA_FILE, R_OK) == 0)
                             ? "--ca-certificate=" TG_CA_FILE
                             : "--no-check-certificate";

    /* Prefer uclient-fetch (lightweight native OpenWrt HTTPS via libustream-mbedtls) */
    snprintf(cmd, sizeof(cmd),
             "uclient-fetch -q -T 20 %s --post-file=%s -O %s "
             "\"https://api.telegram.org/bot%s/%s\" 2>/dev/null",
             ca_opt, TG_REQ_FILE, TG_RESP_FILE, g_config.tg_token, method);

    int rc = system(cmd);
    bool ok = false;
    if (rc == 0) {
        FILE *rf = fopen(TG_RESP_FILE, "r");
        if (rf) {
            if (resp_buf && resp_sz > 0) {
                size_t n = fread(resp_buf, 1, resp_sz - 1, rf);
                resp_buf[n] = '\0';
                ok = (strstr(resp_buf, "\"ok\":true") != NULL);
            } else {
                char chk[256] = {0};
                size_t n = fread(chk, 1, sizeof(chk) - 1, rf);
                chk[n] = '\0';
                ok = (strstr(chk, "\"ok\":true") != NULL);
            }
            fclose(rf);
        }
    }

    pthread_mutex_unlock(&s_tg_http_lock);
    return ok;
}

bool telegram_send_message(const char *chat_id, const char *text, const char *reply_markup_json) {
    if (!chat_id || !chat_id[0] || !text) return false;
    char esc_text[3072];
    json_escape(text, esc_text, sizeof(esc_text));

    char body[4096];
    if (reply_markup_json && reply_markup_json[0]) {
        snprintf(body, sizeof(body),
                 "{\"chat_id\":\"%s\",\"text\":\"%s\",\"parse_mode\":\"HTML\",\"reply_markup\":%s}",
                 chat_id, esc_text, reply_markup_json);
    } else {
        snprintf(body, sizeof(body),
                 "{\"chat_id\":\"%s\",\"text\":\"%s\",\"parse_mode\":\"HTML\"}",
                 chat_id, esc_text);
    }
    return tg_post_api("sendMessage", body, NULL, 0);
}

bool telegram_broadcast_admins(const char *text, const char *reply_markup_json) {
    if (!g_config.tg_admin_ids[0] || !g_config.tg_token[0]) return false;
    char copy[160];
    snprintf(copy, sizeof(copy), "%s", g_config.tg_admin_ids);
    bool any = false;
    char *tok = strtok(copy, ",; ");
    while (tok) {
        if (telegram_send_message(tok, text, reply_markup_json)) any = true;
        tok = strtok(NULL, ",; ");
    }
    return any;
}

bool telegram_send_test(char *err_buf, size_t err_sz) {
    if (!g_config.tg_token[0] || !g_config.tg_admin_ids[0]) {
        snprintf(err_buf, err_sz, "Missing token or admin chat ID");
        return false;
    }
    bool ok = telegram_broadcast_admins(
        "✅ <b>اختبار اتصال بوت راوتر WR740N v4</b>\nالبوت متصل ويعمل بنجاح!", NULL);
    if (!ok && err_buf) snprintf(err_buf, err_sz, "HTTPS request failed or invalid token/chat_id");
    return ok;
}

static int parse_thresholds(uint8_t out[RMETER_MAX_THRESHOLDS]) {
    char copy[48];
    snprintf(copy, sizeof(copy), "%s", g_config.tg_thresholds);
    int n = 0;
    char *tok = strtok(copy, ",; ");
    while (tok && n < RMETER_MAX_THRESHOLDS) {
        int v = atoi(tok);
        if (v > 0 && v <= 100) out[n++] = (uint8_t)v;
        tok = strtok(NULL, ",; ");
    }
    return n;
}

void telegram_check_alerts(void) {
    if (!g_config.tg_enabled || !g_config.tg_token[0]) return;

    uint8_t th[RMETER_MAX_THRESHOLDS];
    int nth = parse_thresholds(th);
    if (nth == 0) return;

    pthread_mutex_lock(&g_lock);

    /* 1. Main Router Quota alerts */
    if (g_config.main_quota_bytes > 0) {
        uint64_t used = meter_total_used_bytes();
        uint32_t pct = (uint32_t)((used * 100ULL) / g_config.main_quota_bytes);
        if (pct > 100) pct = 100;
        for (int t = 0; t < nth; t++) {
            uint16_t bit = (uint16_t)(1U << t);
            if (pct >= th[t] && !(g_config.main_alert_flags & bit)) {
                g_config.main_alert_flags |= bit;
                g_flash_dirty = true;
                char ustr[32], qstr[32], msg[512];
                fmt_bytes(used, ustr, sizeof(ustr));
                fmt_bytes(g_config.main_quota_bytes, qstr, sizeof(qstr));
                snprintf(msg, sizeof(msg),
                         "⚠️ <b>تنبيه استهلاك الباقة الرئيسية (%u%%)</b>\n"
                         "📊 المستهلك: <b>%s</b> من أصل <b>%s</b>\n"
                         "📅 الدورة: %s ⬅️ %s",
                         (unsigned)th[t], ustr, qstr, g_config.start_date, g_config.end_date);
                pthread_mutex_unlock(&g_lock);
                telegram_broadcast_admins(msg, NULL);
                pthread_mutex_lock(&g_lock);
            }
        }
    }

    /* 2. Per-Device Quota alerts */
    for (int i = 0; i < g_device_count; i++) {
        rmeter_device_t *d = &g_devices[i];
        if (d->quota_bytes == 0) continue;
        uint64_t used = meter_scaled_bytes(d->up_bytes + d->down_bytes);
        uint32_t pct = (uint32_t)((used * 100ULL) / d->quota_bytes);
        if (pct > 100) pct = 100;
        for (int t = 0; t < nth; t++) {
            uint16_t bit = (uint16_t)(1U << t);
            if (pct >= th[t] && !(d->alert_flags & bit)) {
                d->alert_flags |= bit;
                g_flash_dirty = true;
                char ustr[32], qstr[32], msg[512];
                char dchat[32];
                snprintf(dchat, sizeof(dchat), "%s", d->tg_chat_id);
                const char *dname = d->name[0] ? d->name : d->ip;
                fmt_bytes(used, ustr, sizeof(ustr));
                fmt_bytes(d->quota_bytes, qstr, sizeof(qstr));
                snprintf(msg, sizeof(msg),
                         "%s <b>تنبيه حصة جهاز (%u%%)</b>\n"
                         "📱 الجهاز: <b>%s</b> (%s)\n"
                         "📊 الاستهلاك: <b>%s</b> / <b>%s</b>%s",
                         (th[t] >= 100) ? "⛔" : "🔔",
                         (unsigned)th[t], dname, d->ip[0] ? d->ip : d->mac,
                         ustr, qstr,
                         (th[t] >= 100) ? "\n🔒 تم قطع الإنترنت تلقائياً عن الجهاز." : "");
                pthread_mutex_unlock(&g_lock);
                telegram_broadcast_admins(msg, NULL);
                if (dchat[0] && !tg_is_admin(dchat)) {
                    telegram_send_message(dchat, msg, NULL);
                }
                pthread_mutex_lock(&g_lock);
            }
        }
    }

    pthread_mutex_unlock(&g_lock);
}

static void handle_command(const char *chat_id, const char *text) {
    bool is_adm = tg_is_admin(chat_id);
    char cmd[64] = {0}, arg1[64] = {0}, arg2[64] = {0};
    sscanf(text, "%63s %63s %63s", cmd, arg1, arg2);

    /* Strip @BotName suffix from /cmd@BotName */
    char *at = strchr(cmd, '@');
    if (at) *at = '\0';

    if (strcmp(cmd, "/start") == 0 || strcmp(cmd, "/help") == 0 || strcmp(cmd, "مساعدة") == 0) {
        char msg[1200];
        if (is_adm) {
            snprintf(msg, sizeof(msg),
                     "🤖 <b>أوامر إدارة راوتر WR740N v4</b>\n\n"
                     "📊 /status أو <code>حالة</code> — حالة الراوتر والسرعة الكلية\n"
                     "⚡ /speed أو <code>سرعة</code> — السرعات اللحظية لكل جهاز\n"
                     "🎯 /quota أو <code>استهلاك</code> — الباقة الرئيسية وحصص الأجهزة\n"
                     "👥 /devices أو <code>اجهزة</code> — قائمة الأجهزة + أزرار تحكم\n"
                     "🔒 /block [IP/MAC] — حظر جهاز\n"
                     "🔓 /unblock [IP/MAC] — فك حظر جهاز\n"
                     "➕ /add_quota [IP/MAC] [GB] — إضافة جيجات (مثال: <code>/add_quota 192.168.1.50 5</code>)\n"
                     "🎮 /vip [IP/MAC] — تبديل وضع الألعاب VIP\n"
                     "🔄 /reboot — إعادة تشغيل الراوتر بأمان");
        } else {
            snprintf(msg, sizeof(msg),
                     "👋 مرحباً بك!\nChat ID الخاص بك: <code>%s</code>\n\n"
                     "إذا ربط المشرف جهازك بهذا الـ ID يمكنك استخدام:\n"
                     "🎯 /quota — استهلاكك المتبقي\n"
                     "⚡ /speed — سرعتك الحالية",
                     chat_id);
        }
        telegram_send_message(chat_id, msg, NULL);
        return;
    }

    /* Non-admin device owner view */
    if (!is_adm) {
        pthread_mutex_lock(&g_lock);
        int found = -1;
        for (int i = 0; i < g_device_count; i++) {
            if (strcmp(g_devices[i].tg_chat_id, chat_id) == 0) {
                found = i;
                break;
            }
        }
        if (found < 0) {
            pthread_mutex_unlock(&g_lock);
            char msg[256];
            snprintf(msg, sizeof(msg), "⛔ هذا الحساب غير مصرح له.\nChat ID الخاص بك: <code>%s</code>", chat_id);
            telegram_send_message(chat_id, msg, NULL);
            return;
        }
        rmeter_device_t d = g_devices[found];
        uint64_t used = meter_scaled_bytes(d.up_bytes + d.down_bytes);
        pthread_mutex_unlock(&g_lock);

        char ustr[32], qstr[32], dn[32], up[32], msg[512];
        fmt_bytes(used, ustr, sizeof(ustr));
        fmt_bytes(d.quota_bytes, qstr, sizeof(qstr));
        fmt_bps(d.cur_down_bps, dn, sizeof(dn));
        fmt_bps(d.cur_up_bps, up, sizeof(up));
        snprintf(msg, sizeof(msg),
                 "📱 <b>جهازك: %s</b>\n"
                 "⬇️ تحميل: <b>%s</b> | ⬆️ رفع: <b>%s</b>\n"
                 "📊 الاستهلاك: <b>%s</b>%s%s\n"
                 "🔒 الحالة: %s",
                 d.name[0] ? d.name : d.ip, dn, up, ustr,
                 d.quota_bytes ? " / " : " (مفتوح)",
                 d.quota_bytes ? qstr : "",
                 d.blocked ? "محظور ⛔" : "نشط 🟢");
        telegram_send_message(chat_id, msg, NULL);
        return;
    }

    /* Admin Commands */
    if (strcmp(cmd, "/status") == 0 || strcmp(cmd, "حالة") == 0) {
        char dn[32], up[32], tu[32], mq[32], msg[640];
        FILE *fp = fopen("/proc/uptime", "r");
        unsigned long ups = 0;
        if (fp) { double u = 0; if (fscanf(fp, "%lf", &u) == 1) ups = (unsigned long)u; fclose(fp); }

        pthread_mutex_lock(&g_lock);
        fmt_bps(g_total_down_bps, dn, sizeof(dn));
        fmt_bps(g_total_up_bps, up, sizeof(up));
        fmt_bytes(meter_total_used_bytes(), tu, sizeof(tu));
        fmt_bytes(g_config.main_quota_bytes, mq, sizeof(mq));
        int online_cnt = 0;
        for (int i = 0; i < g_device_count; i++) if (g_devices[i].online) online_cnt++;
        pthread_mutex_unlock(&g_lock);

        snprintf(msg, sizeof(msg),
                 "📡 <b>حالة راوتر WR740N v4</b>\n"
                 "⏱ مدة التشغيل: %lu س %lu د\n"
                 "👥 المتصلون الآن: <b>%d</b> جهاز\n"
                 "⬇️ السرعة الكلية تحميل: <b>%s</b>\n"
                 "⬆️ السرعة الكلية رفع: <b>%s</b>\n"
                 "📊 استهلاك الباقة: <b>%s</b>%s%s",
                 ups / 3600, (ups % 3600) / 60, online_cnt, dn, up, tu,
                 g_config.main_quota_bytes ? " / " : "",
                 g_config.main_quota_bytes ? mq : "");
        telegram_send_message(chat_id, msg, NULL);
    } else if (strcmp(cmd, "/speed") == 0 || strcmp(cmd, "سرعة") == 0) {
        char msg[2400], dn[32], up[32];
        pthread_mutex_lock(&g_lock);
        fmt_bps(g_total_down_bps, dn, sizeof(dn));
        fmt_bps(g_total_up_bps, up, sizeof(up));
        int pos = snprintf(msg, sizeof(msg),
                           "⚡ <b>السرعات اللحظية</b>\n"
                           "🌐 الكلي: ⬇️ <b>%s</b> | ⬆️ <b>%s</b>\n\n", dn, up);
        for (int i = 0; i < g_device_count && pos < (int)sizeof(msg) - 180; i++) {
            if (!g_devices[i].online && g_devices[i].cur_down_bps == 0 && g_devices[i].cur_up_bps == 0) continue;
            fmt_bps(g_devices[i].cur_down_bps, dn, sizeof(dn));
            fmt_bps(g_devices[i].cur_up_bps, up, sizeof(up));
            pos += snprintf(msg + pos, sizeof(msg) - pos,
                            "• <b>%s</b> (%s)\n  ⬇️ %s | ⬆️ %s\n",
                            g_devices[i].name[0] ? g_devices[i].name : g_devices[i].ip,
                            g_devices[i].ip, dn, up);
        }
        pthread_mutex_unlock(&g_lock);
        telegram_send_message(chat_id, msg, NULL);
    } else if (strcmp(cmd, "/quota") == 0 || strcmp(cmd, "استهلاك") == 0 || strcmp(cmd, "باقي") == 0) {
        char msg[2600], ustr[32], qstr[32];
        pthread_mutex_lock(&g_lock);
        uint64_t tot = meter_total_used_bytes();
        fmt_bytes(tot, ustr, sizeof(ustr));
        fmt_bytes(g_config.main_quota_bytes, qstr, sizeof(qstr));
        int pos = snprintf(msg, sizeof(msg),
                           "🎯 <b>استهلاك الباقة</b>\n"
                           "📦 الكلي: <b>%s</b>%s%s\n\n",
                           ustr,
                           g_config.main_quota_bytes ? " / " : " (غير محددة)",
                           g_config.main_quota_bytes ? qstr : "");
        for (int i = 0; i < g_device_count && pos < (int)sizeof(msg) - 180; i++) {
            uint64_t du = meter_scaled_bytes(g_devices[i].up_bytes + g_devices[i].down_bytes);
            fmt_bytes(du, ustr, sizeof(ustr));
            fmt_bytes(g_devices[i].quota_bytes, qstr, sizeof(qstr));
            pos += snprintf(msg + pos, sizeof(msg) - pos,
                            "%s <b>%s</b>: %s%s%s\n",
                            g_devices[i].blocked ? "⛔" : "🔹",
                            g_devices[i].name[0] ? g_devices[i].name : g_devices[i].ip,
                            ustr,
                            g_devices[i].quota_bytes ? " / " : "",
                            g_devices[i].quota_bytes ? qstr : "");
        }
        pthread_mutex_unlock(&g_lock);
        telegram_send_message(chat_id, msg, NULL);
    } else if (strcmp(cmd, "/devices") == 0 || strcmp(cmd, "اجهزة") == 0 || strcmp(cmd, "أجهزة") == 0) {
        char msg[2048], kb[2048];
        pthread_mutex_lock(&g_lock);
        int pos = snprintf(msg, sizeof(msg), "👥 <b>الأجهزة (%d)</b>\nاختر جهازاً للتحكم السريع:\n", g_device_count);
        int kpos = snprintf(kb, sizeof(kb), "{\"inline_keyboard\":[");
        int rows = 0;
        for (int i = 0; i < g_device_count && i < 12; i++) {
            char dn[32], ustr[32];
            fmt_bps(g_devices[i].cur_down_bps, dn, sizeof(dn));
            fmt_bytes(meter_scaled_bytes(g_devices[i].up_bytes + g_devices[i].down_bytes), ustr, sizeof(ustr));
            const char *nm = g_devices[i].name[0] ? g_devices[i].name : g_devices[i].ip;
            if (pos < (int)sizeof(msg) - 160) {
                pos += snprintf(msg + pos, sizeof(msg) - pos,
                                "%s %s (%s) — %s | ⬇️%s\n",
                                g_devices[i].blocked ? "⛔" : (g_devices[i].online ? "🟢" : "⚪"),
                                nm, g_devices[i].ip, ustr, dn);
            }
            if (kpos < (int)sizeof(kb) - 160) {
                char esc_nm[64];
                json_escape(nm, esc_nm, sizeof(esc_nm));
                kpos += snprintf(kb + kpos, sizeof(kb) - kpos,
                                 "%s[{\"text\":\"%s %s\",\"callback_data\":\"dev:%s\"}]",
                                 rows ? "," : "",
                                 g_devices[i].blocked ? "⛔" : "📱",
                                 esc_nm, g_devices[i].mac);
                rows++;
            }
        }
        snprintf(kb + kpos, sizeof(kb) - kpos, "]}");
        pthread_mutex_unlock(&g_lock);
        telegram_send_message(chat_id, msg, rows ? kb : NULL);
    } else if (strcmp(cmd, "/block") == 0 || strcmp(cmd, "حظر") == 0) {
        if (!arg1[0]) {
            telegram_send_message(chat_id, "الاستخدام: <code>/block 192.168.1.50</code>", NULL);
        } else if (meter_set_device_blocked(arg1, true, false)) {
            meter_save_all();
            telegram_send_message(chat_id, "⛔ تم حظر الجهاز بنجاح.", NULL);
        } else {
            telegram_send_message(chat_id, "❌ لم يتم العثور على الجهاز.", NULL);
        }
    } else if (strcmp(cmd, "/unblock") == 0 || strcmp(cmd, "فك_حظر") == 0) {
        if (!arg1[0]) {
            telegram_send_message(chat_id, "الاستخدام: <code>/unblock 192.168.1.50</code>", NULL);
        } else if (meter_set_device_blocked(arg1, false, false)) {
            meter_save_all();
            telegram_send_message(chat_id, "🔓 تم فك الحظر عن الجهاز.", NULL);
        } else {
            telegram_send_message(chat_id, "❌ لم يتم العثور على الجهاز.", NULL);
        }
    } else if (strcmp(cmd, "/add_quota") == 0 || strcmp(cmd, "شحن") == 0) {
        if (!arg1[0] || !arg2[0]) {
            telegram_send_message(chat_id, "الاستخدام: <code>/add_quota 192.168.1.50 5</code>", NULL);
        } else {
            double gb = atof(arg2);
            uint64_t unit = (g_config.gb_standard == 1000) ? 1000000000ULL : 1073741824ULL;
            int64_t add_b = (int64_t)(gb * (double)unit);
            if (meter_add_device_quota(arg1, add_b)) {
                meter_save_all();
                telegram_send_message(chat_id, "✅ تم تعديل حصة الجيجات بنجاح (وتم فك الحظر التلقائي إن وجد).", NULL);
            } else {
                telegram_send_message(chat_id, "❌ لم يتم العثور على الجهاز.", NULL);
            }
        }
    } else if (strcmp(cmd, "/vip") == 0) {
        pthread_mutex_lock(&g_lock);
        int idx = meter_find_by_mac_or_ip(arg1);
        bool cur = (idx >= 0) ? g_devices[idx].gaming_mode : false;
        pthread_mutex_unlock(&g_lock);
        if (idx >= 0 && meter_set_device_gaming(arg1, !cur)) {
            meter_save_all();
            telegram_send_message(chat_id, !cur ? "🎮 تم تفعيل وضع الألعاب VIP للجهاز." : "تم إلغاء وضع الألعاب VIP.", NULL);
        } else {
            telegram_send_message(chat_id, "الاستخدام: <code>/vip 192.168.1.50</code>", NULL);
        }
    } else if (strcmp(cmd, "/reboot") == 0 || strcmp(cmd, "ريستارت") == 0) {
        telegram_send_message(chat_id, "🔄 جاري حفظ العدادات وإعادة تشغيل الراوتر خلال 3 ثوانٍ...", NULL);
        meter_save_all();
        g_reboot_countdown = 3;
    }
}

static void handle_callback(const char *cb_id, const char *chat_id, const char *data) {
    char ans_body[256];
    snprintf(ans_body, sizeof(ans_body), "{\"callback_query_id\":\"%s\"}", cb_id);
    tg_post_api("answerCallbackQuery", ans_body, NULL, 0);

    if (!tg_is_admin(chat_id)) return;

    if (strncmp(data, "dev:", 4) == 0) {
        const char *mac = data + 4;
        pthread_mutex_lock(&g_lock);
        int idx = meter_find_by_mac(mac);
        if (idx < 0) { pthread_mutex_unlock(&g_lock); return; }
        rmeter_device_t d = g_devices[idx];
        uint64_t used = meter_scaled_bytes(d.up_bytes + d.down_bytes);
        pthread_mutex_unlock(&g_lock);

        char ustr[32], qstr[32], dn[32], up[32], msg[512], kb[512];
        fmt_bytes(used, ustr, sizeof(ustr));
        fmt_bytes(d.quota_bytes, qstr, sizeof(qstr));
        fmt_bps(d.cur_down_bps, dn, sizeof(dn));
        fmt_bps(d.cur_up_bps, up, sizeof(up));
        snprintf(msg, sizeof(msg),
                 "📱 <b>%s</b>\nIP: <code>%s</code> | MAC: <code>%s</code>\n"
                 "⬇️ %s | ⬆️ %s\n📊 %s / %s\nالحالة: %s | VIP: %s",
                 d.name[0] ? d.name : d.ip, d.ip, d.mac, dn, up, ustr,
                 d.quota_bytes ? qstr : "مفتوح",
                 d.blocked ? "محظور ⛔" : "نشط 🟢",
                 d.gaming_mode ? "نعم 🎮" : "لا");
        snprintf(kb, sizeof(kb),
                 "{\"inline_keyboard\":["
                 "[{\"text\":\"%s\",\"callback_data\":\"%s:%s\"},"
                 "{\"text\":\"🎮 VIP\",\"callback_data\":\"vip:%s\"}],"
                 "[{\"text\":\"➕ +1 GB\",\"callback_data\":\"add1:%s\"},"
                 "{\"text\":\"➕ +5 GB\",\"callback_data\":\"add5:%s\"}]"
                 "]}",
                 d.blocked ? "🔓 فك الحظر" : "⛔ حظر",
                 d.blocked ? "unblk" : "blk", d.mac,
                 d.mac, d.mac, d.mac);
        telegram_send_message(chat_id, msg, kb);
    } else if (strncmp(data, "blk:", 4) == 0) {
        meter_set_device_blocked(data + 4, true, false);
        meter_save_all();
        telegram_send_message(chat_id, "⛔ تم حظر الجهاز.", NULL);
    } else if (strncmp(data, "unblk:", 6) == 0) {
        meter_set_device_blocked(data + 6, false, false);
        meter_save_all();
        telegram_send_message(chat_id, "🔓 تم فك الحظر عن الجهاز.", NULL);
    } else if (strncmp(data, "vip:", 4) == 0) {
        pthread_mutex_lock(&g_lock);
        int idx = meter_find_by_mac(data + 4);
        bool cur = (idx >= 0) ? g_devices[idx].gaming_mode : false;
        pthread_mutex_unlock(&g_lock);
        if (idx >= 0) {
            meter_set_device_gaming(data + 4, !cur);
            meter_save_all();
            telegram_send_message(chat_id, !cur ? "🎮 تم تفعيل VIP." : "تم إلغاء VIP.", NULL);
        }
    } else if (strncmp(data, "add1:", 5) == 0 || strncmp(data, "add5:", 5) == 0) {
        int gb = (data[3] == '1') ? 1 : 5;
        uint64_t unit = (g_config.gb_standard == 1000) ? 1000000000ULL : 1073741824ULL;
        meter_add_device_quota(data + 5, (int64_t)gb * (int64_t)unit);
        meter_save_all();
        telegram_send_message(chat_id, (gb == 1) ? "✅ تمت إضافة 1 GB." : "✅ تمت إضافة 5 GB.", NULL);
    }
}

static void process_updates_json(const char *json) {
    const char *p = json;
    while ((p = strstr(p, "\"update_id\":")) != NULL) {
        long long uid = 0;
        if (sscanf(p + 12, "%lld", &uid) == 1 && uid > g_config.tg_last_update_id) {
            g_config.tg_last_update_id = uid;
        }
        /* Bound search to next update_id */
        const char *next = strstr(p + 12, "\"update_id\":");
        size_t chunk_len = next ? (size_t)(next - p) : strlen(p);
        if (chunk_len > 4095) chunk_len = 4095;
        char chunk[4096];
        memcpy(chunk, p, chunk_len);
        chunk[chunk_len] = '\0';

        char chat_id[32] = {0}, text[512] = {0}, fname[48] = {0}, uname[32] = {0};
        char cb_id[64] = {0}, cb_data[64] = {0};

        if (strstr(chunk, "\"callback_query\"")) {
            json_get_str(chunk, "id", cb_id, sizeof(cb_id));
            json_get_str(chunk, "data", cb_data, sizeof(cb_data));
            const char *chat_blk = strstr(chunk, "\"chat\":");
            int64_t cid_num = 0;
            if (chat_blk && json_get_i64(chat_blk, "id", &cid_num)) {
                snprintf(chat_id, sizeof(chat_id), "%lld", (long long)cid_num);
            }
            if (cb_id[0] && chat_id[0] && cb_data[0]) {
                handle_callback(cb_id, chat_id, cb_data);
            }
        } else if (strstr(chunk, "\"message\"")) {
            const char *chat_blk = strstr(chunk, "\"chat\":");
            int64_t cid_num = 0;
            if (chat_blk && json_get_i64(chat_blk, "id", &cid_num)) {
                snprintf(chat_id, sizeof(chat_id), "%lld", (long long)cid_num);
            }
            json_get_str(chunk, "first_name", fname, sizeof(fname));
            json_get_str(chunk, "username", uname, sizeof(uname));
            json_get_str(chunk, "text", text, sizeof(text));
            if (chat_id[0]) {
                register_tg_user(chat_id, fname, uname);
                if (text[0]) handle_command(chat_id, text);
            }
        }
        p += 12;
    }
}

static void *tg_poll_thread(void *arg) {
    (void)arg;
    char *resp = malloc(16384);
    if (!resp) return NULL;

    while (1) {
        if (!g_config.tg_enabled || !g_config.tg_interactive || !g_config.tg_token[0]) {
            sleep(3);
            continue;
        }
        char body[192];
        long long offset = g_config.tg_last_update_id + 1;
        snprintf(body, sizeof(body), "{\"offset\":%lld,\"timeout\":15,\"limit\":5}", offset);
        if (tg_post_api("getUpdates", body, resp, 16384)) {
            process_updates_json(resp);
        } else {
            sleep(5);
        }
    }
    free(resp);
    return NULL;
}

void telegram_init(void) {
    if (!s_tg_thread_started) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, tg_poll_thread, NULL) == 0) {
            pthread_detach(tid);
            s_tg_thread_started = true;
        }
    }
}

