#define _POSIX_C_SOURCE 200809L
#include "fazakkir.h"
#include "rmeter.h"
#include "meter.h"
#include "json_util.h"
#include "telegram.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

fazakkir_cfg_t g_fazakkir;

static const char *PRAYER_KEYS[5] = {"Fajr", "Dhuhr", "Asr", "Maghrib", "Isha"};
static const char *PRAYER_AR[5]   = {"الفجر", "الظهر", "العصر", "المغرب", "العشاء"};

static const char *DEFAULT_AZKAR[] = {
    "﴿ أَلَا بِذِكْرِ اللَّهِ تَطْمَئِنُّ الْقُلُوبُ ﴾ [الرعد: 28]",
    "سُبْحَانَ اللَّهِ وَبِحَمْدِهِ، سُبْحَانَ اللَّهِ الْعَظِيمِ",
    "لَا إِلَهَ إِلَّا أَنْتَ سُبْحَانَكَ إِنِّي كُنْتُ مِنَ الظَّالِمِينَ",
    "اللَّهُمَّ صَلِّ وَسَلِّمْ عَلَى نَبِيِّنَا مُحَمَّدٍ",
    "أَسْتَغْفِرُ اللَّهَ الْعَظِيمَ الَّذِي لَا إِلَهَ إِلَّا هُوَ الْحَيُّ الْقَيُّومُ وَأَتُوبُ إِلَيْهِ",
    "حَسْبُنَا اللَّهُ وَنِعْمَ الْوَكِيلُ"
};

typedef struct {
    char mac[18];
    bool valid;
    bool was_blocked;
    bool was_auto_blocked;
    bool was_unlocked;
    uint32_t was_up;
    uint32_t was_down;
} saved_dev_state_t;

static saved_dev_state_t s_saved[FAZAKKIR_MAX_MACS];
static int s_saved_cnt = 0;

static char s_sent_date[5][16];
static time_t s_repeat_at[5];
static int s_last_reset_yday = -1;
static time_t s_next_azkar_at = 0;
static time_t s_last_prayer_fetch = 0;

static void url_encode_simple(const char *src, char *dst, size_t dsz) {
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 4 < dsz; i++) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            dst[j++] = (char)c;
        } else if (c == ' ') {
            dst[j++] = '%'; dst[j++] = '2'; dst[j++] = '0';
        } else {
            dst[j++] = '%'; dst[j++] = hex[c >> 4]; dst[j++] = hex[c & 15];
        }
    }
    dst[j] = '\0';
}

static bool safe_url_str(const char *s) {
    if (!s || !s[0]) return false;
    if (strncmp(s, "http://", 7) != 0 && strncmp(s, "https://", 8) != 0) return false;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '\'' || c == '"' || c == '`' || c == '$' || c == ';' ||
            c == '|' || c == '\n' || c == '\r' || c == ' ')
            return false;
    }
    return true;
}

static bool fetch_http_body(const char *url, char *buf, size_t bsz) {
    if (!safe_url_str(url) || !buf || bsz < 64) return false;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "uclient-fetch -q -T 8 --no-check-certificate -O - '%s' 2>/dev/null", url);
    FILE *fp = popen(cmd, "r");
    if (!fp) return false;
    size_t tot = 0;
    while (tot + 1 < bsz) {
        size_t n = fread(buf + tot, 1, bsz - 1 - tot, fp);
        if (n == 0) break;
        tot += n;
    }
    buf[tot] = '\0';
    pclose(fp);
    return tot > 0;
}

static void set_defaults(void) {
    memset(&g_fazakkir, 0, sizeof(g_fazakkir));
    g_fazakkir.prayer_enabled = true;
    snprintf(g_fazakkir.city, sizeof(g_fazakkir.city), "Cairo");
    snprintf(g_fazakkir.country, sizeof(g_fazakkir.country), "Egypt");
    g_fazakkir.method = 5;
    for (int i = 0; i < 5; i++) {
        g_fazakkir.prayer_on[i] = true;
        g_fazakkir.prayer_offset[i] = 0;
        snprintf(g_fazakkir.prayer_times[i], sizeof(g_fazakkir.prayer_times[i]), "--:--");
    }
    g_fazakkir.prayer_recipient_mode = 0;
    g_fazakkir.prayer_repeat_min = 10;
    g_fazakkir.prayer_action = 0;
    g_fazakkir.prayer_kbps = 5;
    g_fazakkir.prayer_dur_min = 15;

    g_fazakkir.azkar_enabled = false;
    g_fazakkir.azkar_interval_min = 60;
    g_fazakkir.azkar_recipient_mode = 0;
    g_fazakkir.azkar_auto_fetch = false;
    snprintf(g_fazakkir.azkar_source_mode, sizeof(g_fazakkir.azkar_source_mode), "quran");
    snprintf(g_fazakkir.azkar_url, sizeof(g_fazakkir.azkar_url),
             "https://api.alquran.cloud/v1/ayah/random/quran-uthmani");

    int n = (int)(sizeof(DEFAULT_AZKAR) / sizeof(DEFAULT_AZKAR[0]));
    for (int i = 0; i < n && i < FAZAKKIR_MAX_CARDS; i++) {
        snprintf(g_fazakkir.cards[i].text, sizeof(g_fazakkir.cards[i].text), "%s", DEFAULT_AZKAR[i]);
        g_fazakkir.cards[i].enabled = true;
        g_fazakkir.cards[i].max_daily = 2;
        g_fazakkir.cards[i].sent_today = 0;
    }
    g_fazakkir.card_count = n;
    g_fazakkir.azkar_cursor = -1;
    g_fazakkir.prayer_active_idx = -1;
}

static void parse_bool_arr(const char *arr, bool *out, int count) {
    if (!arr) return;
    const char *p = arr;
    int idx = 0;
    while (*p && idx < count) {
        if (strncmp(p, "true", 4) == 0) { out[idx++] = true; p += 4; }
        else if (strncmp(p, "false", 5) == 0) { out[idx++] = false; p += 5; }
        else p++;
    }
}

static void parse_int_arr(const char *arr, int *out, int count) {
    if (!arr) return;
    const char *p = arr;
    int idx = 0;
    while (*p && idx < count) {
        while (*p && *p != '-' && !isdigit((unsigned char)*p)) p++;
        if (!*p) break;
        out[idx++] = (int)strtol(p, (char **)&p, 10);
    }
}

static void load_cfg_file(void) {
    FILE *fp = fopen(FAZAKKIR_CFG_PATH, "r");
    if (!fp) return;
    char *buf = malloc(16384);
    if (!buf) { fclose(fp); return; }
    size_t n = fread(buf, 1, 16383, fp);
    buf[n] = '\0';
    fclose(fp);

    json_get_bool(buf, "prayer_enabled", &g_fazakkir.prayer_enabled);
    json_get_str(buf, "city", g_fazakkir.city, sizeof(g_fazakkir.city));
    json_get_str(buf, "country", g_fazakkir.country, sizeof(g_fazakkir.country));
    uint64_t uval = 0;
    if (json_get_u64(buf, "method", &uval)) g_fazakkir.method = (int)uval;
    if (json_get_u64(buf, "prayer_recipient_mode", &uval)) g_fazakkir.prayer_recipient_mode = (int)uval;
    if (json_get_u64(buf, "prayer_repeat_min", &uval)) g_fazakkir.prayer_repeat_min = (int)uval;
    if (json_get_u64(buf, "prayer_action", &uval)) g_fazakkir.prayer_action = (int)uval;
    if (json_get_u64(buf, "prayer_kbps", &uval)) g_fazakkir.prayer_kbps = (uint32_t)(uval > 0 ? uval : 5);
    if (json_get_u64(buf, "prayer_dur_min", &uval)) g_fazakkir.prayer_dur_min = (int)uval;

    const char *pon = strstr(buf, "\"prayer_on\"");
    if (pon) { const char *b = strchr(pon, '['); if (b) parse_bool_arr(b, g_fazakkir.prayer_on, 5); }
    const char *pof = strstr(buf, "\"prayer_offset\"");
    if (pof) { const char *b = strchr(pof, '['); if (b) parse_int_arr(b, g_fazakkir.prayer_offset, 5); }

    const char *pm = strstr(buf, "\"prayer_macs\"");
    if (pm) {
        const char *b = strchr(pm, '[');
        const char *e = b ? strchr(b, ']') : NULL;
        if (b && e) {
            g_fazakkir.prayer_mac_count = 0;
            const char *p = b + 1;
            while (p < e && g_fazakkir.prayer_mac_count < FAZAKKIR_MAX_MACS) {
                const char *q1 = strchr(p, '"');
                if (!q1 || q1 >= e) break;
                const char *q2 = strchr(q1 + 1, '"');
                if (!q2 || q2 >= e) break;
                size_t len = (size_t)(q2 - (q1 + 1));
                if (len == 17) {
                    memcpy(g_fazakkir.prayer_macs[g_fazakkir.prayer_mac_count], q1 + 1, 17);
                    g_fazakkir.prayer_macs[g_fazakkir.prayer_mac_count][17] = '\0';
                    g_fazakkir.prayer_mac_count++;
                }
                p = q2 + 1;
            }
        }
    }

    json_get_bool(buf, "azkar_enabled", &g_fazakkir.azkar_enabled);
    if (json_get_u64(buf, "azkar_interval_min", &uval))
        g_fazakkir.azkar_interval_min = (uval >= 1) ? (int)uval : 60;
    if (json_get_u64(buf, "azkar_recipient_mode", &uval)) g_fazakkir.azkar_recipient_mode = (int)uval;
    json_get_bool(buf, "azkar_auto_fetch", &g_fazakkir.azkar_auto_fetch);
    json_get_str(buf, "azkar_source_mode", g_fazakkir.azkar_source_mode, sizeof(g_fazakkir.azkar_source_mode));
    json_get_str(buf, "azkar_url", g_fazakkir.azkar_url, sizeof(g_fazakkir.azkar_url));

    const char *cards = strstr(buf, "\"cards\"");
    if (cards) {
        const char *arr = strchr(cards, '[');
        if (arr) {
            g_fazakkir.card_count = 0;
            const char *p = arr + 1;
            while (*p && *p != ']' && g_fazakkir.card_count < FAZAKKIR_MAX_CARDS) {
                const char *ob = strchr(p, '{');
                if (!ob) break;
                const char *cb = strchr(ob, '}');
                if (!cb) break;
                size_t olen = (size_t)(cb - ob + 1);
                char *obj = malloc(olen + 1);
                if (obj) {
                    memcpy(obj, ob, olen);
                    obj[olen] = '\0';
                    fazakkir_card_t *c = &g_fazakkir.cards[g_fazakkir.card_count];
                    memset(c, 0, sizeof(*c));
                    c->enabled = true;
                    c->max_daily = 2;
                    json_get_str(obj, "text", c->text, sizeof(c->text));
                    json_get_bool(obj, "enabled", &c->enabled);
                    if (json_get_u64(obj, "max_daily", &uval)) c->max_daily = (int)uval;
                    if (c->text[0]) g_fazakkir.card_count++;
                    free(obj);
                }
                p = cb + 1;
            }
        }
    }

    free(buf);
}

void fazakkir_init(void) {
    set_defaults();
    load_cfg_file();
    memset(s_sent_date, 0, sizeof(s_sent_date));
    memset(s_repeat_at, 0, sizeof(s_repeat_at));
    s_saved_cnt = 0;
    s_next_azkar_at = 0;
    s_last_prayer_fetch = 0;
    fazakkir_write_status_json();
}

void fazakkir_reload(void) {
    char saved_times[5][8];
    char saved_date[16];
    int saved_sent[FAZAKKIR_MAX_CARDS];
    int old_cnt = g_fazakkir.card_count;
    memcpy(saved_times, g_fazakkir.prayer_times, sizeof(saved_times));
    memcpy(saved_date, g_fazakkir.prayer_date, sizeof(saved_date));
    for (int i = 0; i < old_cnt && i < FAZAKKIR_MAX_CARDS; i++) saved_sent[i] = g_fazakkir.cards[i].sent_today;
    int old_active = g_fazakkir.prayer_active_idx;
    time_t old_end = g_fazakkir.prayer_window_end;
    int old_cursor = g_fazakkir.azkar_cursor;

    set_defaults();
    load_cfg_file();

    memcpy(g_fazakkir.prayer_times, saved_times, sizeof(saved_times));
    memcpy(g_fazakkir.prayer_date, saved_date, sizeof(saved_date));
    for (int i = 0; i < g_fazakkir.card_count && i < old_cnt; i++) g_fazakkir.cards[i].sent_today = saved_sent[i];
    g_fazakkir.prayer_active_idx = old_active;
    g_fazakkir.prayer_window_end = old_end;
    g_fazakkir.azkar_cursor = old_cursor;
    s_next_azkar_at = 0;
    fazakkir_write_status_json();
}

void fazakkir_write_status_json(void) {
    mkdir("/tmp/rmeter", 0755);
    char tmp_path[128];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", FAZAKKIR_STATUS_PATH);
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) return;

    char ec_city[128], ec_country[128], ec_src[64], ec_url[512];
    json_escape(g_fazakkir.city, ec_city, sizeof(ec_city));
    json_escape(g_fazakkir.country, ec_country, sizeof(ec_country));
    json_escape(g_fazakkir.azkar_source_mode, ec_src, sizeof(ec_src));
    json_escape(g_fazakkir.azkar_url, ec_url, sizeof(ec_url));

    fprintf(fp, "{\n"
                "  \"ok\": true,\n"
                "  \"prayer_enabled\": %s,\n"
                "  \"city\": \"%s\",\n"
                "  \"country\": \"%s\",\n"
                "  \"method\": %d,\n"
                "  \"prayer_date\": \"%s\",\n"
                "  \"prayer_times\": [\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"],\n"
                "  \"prayer_on\": [%s,%s,%s,%s,%s],\n"
                "  \"prayer_offset\": [%d,%d,%d,%d,%d],\n"
                "  \"prayer_recipient_mode\": %d,\n"
                "  \"prayer_repeat_min\": %d,\n"
                "  \"prayer_action\": %d,\n"
                "  \"prayer_kbps\": %u,\n"
                "  \"prayer_dur_min\": %d,\n"
                "  \"prayer_active_idx\": %d,\n"
                "  \"prayer_macs\": [",
            g_fazakkir.prayer_enabled ? "true" : "false",
            ec_city, ec_country, g_fazakkir.method, g_fazakkir.prayer_date,
            g_fazakkir.prayer_times[0], g_fazakkir.prayer_times[1],
            g_fazakkir.prayer_times[2], g_fazakkir.prayer_times[3], g_fazakkir.prayer_times[4],
            g_fazakkir.prayer_on[0] ? "true" : "false", g_fazakkir.prayer_on[1] ? "true" : "false",
            g_fazakkir.prayer_on[2] ? "true" : "false", g_fazakkir.prayer_on[3] ? "true" : "false",
            g_fazakkir.prayer_on[4] ? "true" : "false",
            g_fazakkir.prayer_offset[0], g_fazakkir.prayer_offset[1],
            g_fazakkir.prayer_offset[2], g_fazakkir.prayer_offset[3], g_fazakkir.prayer_offset[4],
            g_fazakkir.prayer_recipient_mode, g_fazakkir.prayer_repeat_min,
            g_fazakkir.prayer_action, (unsigned)g_fazakkir.prayer_kbps,
            g_fazakkir.prayer_dur_min, g_fazakkir.prayer_active_idx);

    for (int i = 0; i < g_fazakkir.prayer_mac_count; i++) {
        fprintf(fp, "\"%s\"%s", g_fazakkir.prayer_macs[i],
                (i + 1 < g_fazakkir.prayer_mac_count) ? "," : "");
    }

    fprintf(fp, "],\n"
                "  \"azkar_enabled\": %s,\n"
                "  \"azkar_interval_min\": %d,\n"
                "  \"azkar_recipient_mode\": %d,\n"
                "  \"azkar_auto_fetch\": %s,\n"
                "  \"azkar_source_mode\": \"%s\",\n"
                "  \"azkar_url\": \"%s\",\n"
                "  \"cards\": [\n",
            g_fazakkir.azkar_enabled ? "true" : "false",
            g_fazakkir.azkar_interval_min, g_fazakkir.azkar_recipient_mode,
            g_fazakkir.azkar_auto_fetch ? "true" : "false", ec_src, ec_url);

    for (int i = 0; i < g_fazakkir.card_count; i++) {
        char et[768];
        json_escape(g_fazakkir.cards[i].text, et, sizeof(et));
        fprintf(fp, "    {\"text\":\"%s\",\"enabled\":%s,\"max_daily\":%d,\"sent_today\":%d}%s\n",
                et, g_fazakkir.cards[i].enabled ? "true" : "false",
                g_fazakkir.cards[i].max_daily, g_fazakkir.cards[i].sent_today,
                (i + 1 < g_fazakkir.card_count) ? "," : "");
    }
    fprintf(fp, "  ]\n}\n");
    fclose(fp);
    rename(tmp_path, FAZAKKIR_STATUS_PATH);
}

bool fazakkir_refresh_prayers(char *err, size_t err_sz) {
    char c_enc[128], co_enc[128], url[384];
    url_encode_simple(g_fazakkir.city[0] ? g_fazakkir.city : "Cairo", c_enc, sizeof(c_enc));
    url_encode_simple(g_fazakkir.country[0] ? g_fazakkir.country : "Egypt", co_enc, sizeof(co_enc));
    snprintf(url, sizeof(url),
             "https://api.aladhan.com/v1/timingsByCity?city=%s&country=%s&method=%d",
             c_enc, co_enc, g_fazakkir.method > 0 ? g_fazakkir.method : 5);

    char *buf = malloc(8192);
    if (!buf) {
        if (err) snprintf(err, err_sz, "نفاد الذاكرة");
        return false;
    }
    if (!fetch_http_body(url, buf, 8192) || !strstr(buf, "\"timings\"")) {
        snprintf(url, sizeof(url),
                 "http://api.aladhan.com/v1/timingsByCity?city=%s&country=%s&method=%d",
                 c_enc, co_enc, g_fazakkir.method > 0 ? g_fazakkir.method : 5);
        if (!fetch_http_body(url, buf, 8192)) {
            free(buf);
            if (err) snprintf(err, err_sz, "تعذر الاتصال بخادم مواقيت الصلاة");
            return false;
        }
    }

    const char *tim = strstr(buf, "\"timings\"");
    if (!tim) {
        free(buf);
        if (err) snprintf(err, err_sz, "استجابة غير صالحة من الخادم");
        return false;
    }

    int parsed = 0;
    for (int i = 0; i < 5; i++) {
        char val[16] = {0};
        if (json_get_str(tim, PRAYER_KEYS[i], val, sizeof(val)) && strlen(val) >= 5) {
            memcpy(g_fazakkir.prayer_times[i], val, 5);
            g_fazakkir.prayer_times[i][5] = '\0';
            parsed++;
        }
    }
    free(buf);
    if (parsed < 5) {
        if (err) snprintf(err, err_sz, "لم يتم العثور على كل المواقيت");
        return false;
    }

    time_t local_t = time(NULL) + (time_t)g_config.auto_reboot_tz * 3600;
    struct tm tm_val;
    if (gmtime_r(&local_t, &tm_val)) {
        snprintf(g_fazakkir.prayer_date, sizeof(g_fazakkir.prayer_date),
                 "%04d-%02d-%02d", tm_val.tm_year + 1900, tm_val.tm_mon + 1, tm_val.tm_mday);
    }
    s_last_prayer_fetch = time(NULL);
    fazakkir_write_status_json();
    return true;
}

bool fazakkir_autolocate(char *city_out, size_t csz, char *country_out, size_t rsz,
                         char *err, size_t err_sz) {
    char buf[2048] = {0};
    if ((!fetch_http_body("http://ip-api.com/json/?fields=city,country", buf, sizeof(buf)) ||
         !strstr(buf, "\"city\"")) &&
        !fetch_http_body("https://ipwho.is/", buf, sizeof(buf))) {
        if (err) snprintf(err, err_sz, "تعذر تحديد الموقع تلقائياً");
        return false;
    }
    char c[48] = {0}, co[48] = {0};
    if (!json_get_str(buf, "city", c, sizeof(c)) || !json_get_str(buf, "country", co, sizeof(co)) ||
        !c[0] || !co[0]) {
        if (err) snprintf(err, err_sz, "استجابة موقع غير مكتملة");
        return false;
    }
    snprintf(g_fazakkir.city, sizeof(g_fazakkir.city), "%s", c);
    snprintf(g_fazakkir.country, sizeof(g_fazakkir.country), "%s", co);
    if (city_out) snprintf(city_out, csz, "%s", c);
    if (country_out) snprintf(country_out, rsz, "%s", co);
    return true;
}

bool fazakkir_fetch_zikr(bool add_card, char *out_text, size_t out_sz, char *err, size_t err_sz) {
    const char *url = g_fazakkir.azkar_url[0]
                          ? g_fazakkir.azkar_url
                          : "https://api.alquran.cloud/v1/ayah/random/quran-uthmani";
    char *buf = malloc(8192);
    if (!buf) {
        if (err) snprintf(err, err_sz, "نفاد الذاكرة");
        return false;
    }
    if (!fetch_http_body(url, buf, 8192)) {
        free(buf);
        if (err) snprintf(err, err_sz, "تعذر جلب الذكر من الرابط المحدد");
        return false;
    }

    char txt[384] = {0};
    char raw_txt[320] = {0}, surah[64] = {0};
    uint64_t ayah_num = 0;

    if (json_get_str(buf, "text", raw_txt, sizeof(raw_txt)) && raw_txt[0]) {
        const char *sp = strstr(buf, "\"surah\"");
        if (sp && json_get_str(sp, "name", surah, sizeof(surah)) &&
            json_get_u64(buf, "numberInSurah", &ayah_num)) {
            snprintf(txt, sizeof(txt), "﴿ %s ﴾ [%s: %llu]",
                     raw_txt, surah, (unsigned long long)ayah_num);
        } else {
            snprintf(txt, sizeof(txt), "%s", raw_txt);
        }
    } else if (json_get_str(buf, "zekr", raw_txt, sizeof(raw_txt)) && raw_txt[0]) {
        snprintf(txt, sizeof(txt), "%s", raw_txt);
    } else if (json_get_str(buf, "content", raw_txt, sizeof(raw_txt)) && raw_txt[0]) {
        snprintf(txt, sizeof(txt), "%s", raw_txt);
    } else {
        /* Plain text fallback: first non-empty line */
        char *line = buf;
        while (*line == '\r' || *line == '\n' || *line == ' ') line++;
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        if (line[0] && line[0] != '<' && line[0] != '{') {
            snprintf(txt, sizeof(txt), "%s", line);
        }
    }
    free(buf);

    if (!txt[0]) {
        if (err) snprintf(err, err_sz, "لم يتم العثور على نص ذكر صالح في الاستجابة");
        return false;
    }
    if (out_text) snprintf(out_text, out_sz, "%s", txt);

    if (add_card) {
        if (g_fazakkir.card_count < FAZAKKIR_MAX_CARDS) {
            fazakkir_card_t *c = &g_fazakkir.cards[g_fazakkir.card_count++];
            snprintf(c->text, sizeof(c->text), "%s", txt);
            c->enabled = true;
            c->max_daily = 2;
            c->sent_today = 0;
        } else {
            /* Replace oldest slot after cursor */
            int rep = (g_fazakkir.azkar_cursor + 1) % FAZAKKIR_MAX_CARDS;
            snprintf(g_fazakkir.cards[rep].text, sizeof(g_fazakkir.cards[rep].text), "%s", txt);
            g_fazakkir.cards[rep].enabled = true;
            g_fazakkir.cards[rep].sent_today = 0;
        }
        fazakkir_write_status_json();
    }
    return true;
}

static int collect_recipients(int mode, char ids[][32], int max_ids) {
    int cnt = 0;
    /* Add configured admin IDs */
    char adm_copy[128];
    snprintf(adm_copy, sizeof(adm_copy), "%s", g_config.tg_admin_ids);
    char *tok = adm_copy;
    while (*tok && cnt < max_ids) {
        while (*tok && (*tok == ',' || *tok == ' ' || *tok == '\t')) tok++;
        if (!*tok) break;
        char *end = tok;
        while (*end && *end != ',' && *end != ' ' && *end != '\t') end++;
        if (*end) *end++ = '\0';
        if (*tok) {
            bool dup = false;
            for (int k = 0; k < cnt; k++) if (strcmp(ids[k], tok) == 0) { dup = true; break; }
            if (!dup) snprintf(ids[cnt++], 32, "%s", tok);
        }
        tok = end;
    }

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_device_count && cnt < max_ids; i++) {
        if (!g_devices[i].tg_chat_id[0]) continue;
        if (mode == 0 && !g_devices[i].online) continue;
        bool dup = false;
        for (int k = 0; k < cnt; k++) {
            if (strcmp(ids[k], g_devices[i].tg_chat_id) == 0) { dup = true; break; }
        }
        if (!dup) snprintf(ids[cnt++], 32, "%s", g_devices[i].tg_chat_id);
    }
    pthread_mutex_unlock(&g_lock);
    return cnt;
}

static void broadcast_tg(int recipient_mode, const char *msg) {
    if (!g_config.tg_enabled || !g_config.tg_token[0] || !msg || !msg[0]) return;
    char ids[48][32];
    int cnt = collect_recipients(recipient_mode, ids, 48);
    for (int i = 0; i < cnt; i++) {
        telegram_send_message(ids[i], msg, NULL);
    }
}

static void apply_prayer_restriction(int p_idx, time_t now) {
    if (g_fazakkir.prayer_action <= 0 || g_fazakkir.prayer_mac_count <= 0 ||
        g_fazakkir.prayer_dur_min <= 0) return;

    pthread_mutex_lock(&g_lock);
    if (s_saved_cnt == 0) {
        for (int m = 0; m < g_fazakkir.prayer_mac_count && s_saved_cnt < FAZAKKIR_MAX_MACS; m++) {
            int idx = meter_find_by_mac(g_fazakkir.prayer_macs[m]);
            if (idx < 0) continue;
            saved_dev_state_t *sv = &s_saved[s_saved_cnt++];
            snprintf(sv->mac, sizeof(sv->mac), "%s", g_devices[idx].mac);
            sv->valid = true;
            sv->was_blocked = g_devices[idx].blocked;
            sv->was_auto_blocked = g_devices[idx].auto_blocked;
            sv->was_unlocked = g_devices[idx].speed_unlocked;
            sv->was_up = g_devices[idx].cap_up_kbps;
            sv->was_down = g_devices[idx].cap_down_kbps;
        }
    }
    for (int k = 0; k < s_saved_cnt; k++) {
        int idx = meter_find_by_mac(s_saved[k].mac);
        if (idx < 0) continue;
        if (g_fazakkir.prayer_action == 1) {
            g_devices[idx].blocked = true;
            g_devices[idx].auto_blocked = false;
        } else if (g_fazakkir.prayer_action == 2) {
            uint32_t lim = g_fazakkir.prayer_kbps > 0 ? g_fazakkir.prayer_kbps : 5;
            g_devices[idx].speed_unlocked = false;
            g_devices[idx].cap_down_kbps = lim;
            g_devices[idx].cap_up_kbps = lim;
        }
        g_fw_dirty = true;
    }
    pthread_mutex_unlock(&g_lock);

    g_fazakkir.prayer_active_idx = p_idx;
    g_fazakkir.prayer_window_end = now + (time_t)g_fazakkir.prayer_dur_min * 60;
    fazakkir_write_status_json();
}

static void restore_prayer_restriction(void) {
    if (s_saved_cnt <= 0) {
        g_fazakkir.prayer_active_idx = -1;
        g_fazakkir.prayer_window_end = 0;
        return;
    }
    pthread_mutex_lock(&g_lock);
    for (int k = 0; k < s_saved_cnt; k++) {
        if (!s_saved[k].valid) continue;
        int idx = meter_find_by_mac(s_saved[k].mac);
        if (idx < 0) continue;
        g_devices[idx].blocked = s_saved[k].was_blocked;
        g_devices[idx].auto_blocked = s_saved[k].was_auto_blocked;
        g_devices[idx].speed_unlocked = s_saved[k].was_unlocked;
        g_devices[idx].cap_up_kbps = s_saved[k].was_up;
        g_devices[idx].cap_down_kbps = s_saved[k].was_down;
        g_fw_dirty = true;
    }
    pthread_mutex_unlock(&g_lock);
    s_saved_cnt = 0;
    g_fazakkir.prayer_active_idx = -1;
    g_fazakkir.prayer_window_end = 0;
    fazakkir_write_status_json();
}

static int pick_next_zikr_index(void) {
    if (g_fazakkir.card_count <= 0) return -1;
    for (int step = 1; step <= g_fazakkir.card_count; step++) {
        int idx = (g_fazakkir.azkar_cursor + step) % g_fazakkir.card_count;
        fazakkir_card_t *c = &g_fazakkir.cards[idx];
        if (!c->enabled || !c->text[0]) continue;
        if (c->max_daily > 0 && c->sent_today >= c->max_daily) continue;
        return idx;
    }
    return -1;
}

bool fazakkir_send_test(int kind, char *err, size_t err_sz) {
    if (!g_config.tg_enabled || !g_config.tg_token[0]) {
        if (err) snprintf(err, err_sz, "تأكد من تفعيل بوت تيليجرام وإدخال التوكن أولاً");
        return false;
    }
    char msg[512];
    if (kind == 1) {
        snprintf(msg, sizeof(msg),
                 "🕌 <b>تذكير بموعد الصلاة (تجريبي)</b>\n"
                 "حان الآن موعد صلاة <b>الظهر</b> (%s)\n"
                 "﴿ إِنَّ الصَّلَاةَ كَانَتْ عَلَى الْمُؤْمِنِينَ كِتَابًا مَوْقُوتًا ﴾",
                 g_fazakkir.prayer_times[1]);
        broadcast_tg(g_fazakkir.prayer_recipient_mode, msg);
    } else {
        int idx = pick_next_zikr_index();
        if (idx < 0 && g_fazakkir.card_count > 0) idx = 0;
        if (idx < 0) {
            if (err) snprintf(err, err_sz, "لا توجد بطاقات أذكار مضافة");
            return false;
        }
        snprintf(msg, sizeof(msg), "📿 <b>فَذَكِّرْ</b>\n%s", g_fazakkir.cards[idx].text);
        broadcast_tg(g_fazakkir.azkar_recipient_mode, msg);
    }
    return true;
}

void fazakkir_tick(time_t now) {
    /* 1. Restore prayer restriction when duration ends */
    if (g_fazakkir.prayer_window_end > 0 && now >= g_fazakkir.prayer_window_end) {
        restore_prayer_restriction();
    }

    time_t local_t = now + (time_t)g_config.auto_reboot_tz * 3600;
    struct tm tm_val;
    if (!gmtime_r(&local_t, &tm_val)) return;

    /* Reset daily counters at midnight */
    if (s_last_reset_yday != tm_val.tm_yday) {
        s_last_reset_yday = tm_val.tm_yday;
        for (int i = 0; i < g_fazakkir.card_count; i++) {
            g_fazakkir.cards[i].sent_today = 0;
        }
        fazakkir_write_status_json();
    }

    bool valid_clock = (tm_val.tm_year + 1900 >= 2024);
    char today_ymd[16];
    snprintf(today_ymd, sizeof(today_ymd), "%04d-%02d-%02d",
             tm_val.tm_year + 1900, tm_val.tm_mon + 1, tm_val.tm_mday);

    /* 2. Daily refresh of prayer times when clock is valid */
    if (g_fazakkir.prayer_enabled && valid_clock &&
        strcmp(g_fazakkir.prayer_date, today_ymd) != 0 &&
        (now - s_last_prayer_fetch >= 300)) {
        char err[64];
        fazakkir_refresh_prayers(err, sizeof(err));
    }

    /* 3. Prayer reminders & restrictions */
    if (g_fazakkir.prayer_enabled && valid_clock) {
        int now_min = tm_val.tm_hour * 60 + tm_val.tm_min;
        for (int i = 0; i < 5; i++) {
            if (!g_fazakkir.prayer_on[i]) continue;
            int hh = -1, mm = -1;
            if (sscanf(g_fazakkir.prayer_times[i], "%d:%d", &hh, &mm) != 2) continue;
            int target_min = hh * 60 + mm + g_fazakkir.prayer_offset[i];
            if (target_min < 0) target_min += 1440;
            if (target_min >= 1440) target_min -= 1440;

            if (now_min == target_min && strcmp(s_sent_date[i], today_ymd) != 0) {
                snprintf(s_sent_date[i], sizeof(s_sent_date[i]), "%s", today_ymd);
                char msg[512];
                snprintf(msg, sizeof(msg),
                         "🕌 <b>حان الآن موعد صلاة %s</b> (%s)\n"
                         "﴿ حَافِظُوا عَلَى الصَّلَوَاتِ وَالصَّلَاةِ الْوُسْطَىٰ ﴾",
                         PRAYER_AR[i], g_fazakkir.prayer_times[i]);
                broadcast_tg(g_fazakkir.prayer_recipient_mode, msg);
                if (g_fazakkir.prayer_repeat_min > 0) {
                    s_repeat_at[i] = now + (time_t)g_fazakkir.prayer_repeat_min * 60;
                }
                apply_prayer_restriction(i, now);
            }

            if (s_repeat_at[i] > 0 && now >= s_repeat_at[i]) {
                s_repeat_at[i] = 0;
                char msg[384];
                snprintf(msg, sizeof(msg),
                         "🔔 <b>تذكير بصلاة %s</b>\n"
                         "لا تنسَ أداء الصلاة في وقتها بارك الله فيك.",
                         PRAYER_AR[i]);
                broadcast_tg(g_fazakkir.prayer_recipient_mode, msg);
            }
        }
    }

    /* 4. Periodic sequential & randomized Azkar */
    if (g_fazakkir.azkar_enabled && g_fazakkir.card_count > 0) {
        int base_sec = (g_fazakkir.azkar_interval_min >= 1 ? g_fazakkir.azkar_interval_min : 60) * 60;
        if (s_next_azkar_at == 0) {
            int jitter = 70 + (rand() % 61); /* 70% - 130% */
            time_t dly = (time_t)((long long)base_sec * jitter / 100);
            if (dly < 60) dly = 60;
            s_next_azkar_at = now + dly;
        } else if (now >= s_next_azkar_at) {
            if (g_fazakkir.azkar_auto_fetch) {
                char out_t[384], err[64];
                fazakkir_fetch_zikr(true, out_t, sizeof(out_t), err, sizeof(err));
            }
            int idx = pick_next_zikr_index();
            if (idx >= 0) {
                char msg[512];
                snprintf(msg, sizeof(msg), "📿 <b>فَذَكِّرْ</b>\n%s", g_fazakkir.cards[idx].text);
                broadcast_tg(g_fazakkir.azkar_recipient_mode, msg);
                g_fazakkir.cards[idx].sent_today++;
                g_fazakkir.azkar_cursor = idx;
                fazakkir_write_status_json();
            }
            int jitter = 70 + (rand() % 61);
            time_t dly = (time_t)((long long)base_sec * jitter / 100);
            if (dly < 60) dly = 60;
            s_next_azkar_at = now + dly;
        }
    }
}

static int calc_prayer_target_min(int idx) {
    if (idx < 0 || idx >= 5) return -1;
    int hh = -1, mm = -1;
    if (sscanf(g_fazakkir.prayer_times[idx], "%d:%d", &hh, &mm) != 2) return -1;
    if (hh < 0 || hh > 23 || mm < 0 || mm > 59) return -1;
    int t = hh * 60 + mm + g_fazakkir.prayer_offset[idx];
    while (t < 0) t += 1440;
    while (t >= 1440) t -= 1440;
    return t;
}

bool fazakkir_get_next_prayer(time_t now, char *name_out, size_t nsz,
                              char *time_out, size_t tsz, int *rem_min_out) {
    if (name_out && nsz) name_out[0] = '\0';
    if (time_out && tsz) time_out[0] = '\0';
    if (rem_min_out) *rem_min_out = -1;

    time_t local_t = now + (time_t)g_config.auto_reboot_tz * 3600;
    struct tm tm_val;
    if (!gmtime_r(&local_t, &tm_val) || tm_val.tm_year + 1900 < 2024) return false;
    int now_min = tm_val.tm_hour * 60 + tm_val.tm_min;

    int first_idx = -1, first_min = -1;
    int next_idx = -1, next_min = -1;

    for (int i = 0; i < 5; i++) {
        if (!g_fazakkir.prayer_on[i]) continue;
        int t = calc_prayer_target_min(i);
        if (t < 0) continue;
        if (first_idx < 0 || t < first_min) {
            first_idx = i;
            first_min = t;
        }
        if (t >= now_min && (next_idx < 0 || t < next_min)) {
            next_idx = i;
            next_min = t;
        }
    }

    int chosen_idx = -1, chosen_min = -1, rem = -1;
    if (next_idx >= 0) {
        chosen_idx = next_idx;
        chosen_min = next_min;
        rem = next_min - now_min;
    } else if (first_idx >= 0) {
        chosen_idx = first_idx;
        chosen_min = first_min;
        rem = (1440 - now_min) + first_min;
    } else {
        return false;
    }

    if (name_out && nsz) snprintf(name_out, nsz, "%s", PRAYER_AR[chosen_idx]);
    if (time_out && tsz) snprintf(time_out, tsz, "%02d:%02d", chosen_min / 60, chosen_min % 60);
    if (rem_min_out) *rem_min_out = rem;
    return true;
}

void fazakkir_format_today_prayers(char *out, size_t sz) {
    if (!out || sz == 0) return;
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, sz - pos,
                            "📅 <b>مواقيت الصلاة اليوم</b> (%s، %s)\n\n",
                            g_fazakkir.city[0] ? g_fazakkir.city : "Cairo",
                            g_fazakkir.prayer_date[0] ? g_fazakkir.prayer_date : "-");
    for (int i = 0; i < 5 && pos + 64 < sz; i++) {
        int t = calc_prayer_target_min(i);
        if (t >= 0) {
            pos += (size_t)snprintf(out + pos, sz - pos,
                                    "• <b>%s:</b> <code>%02d:%02d</code>%s\n",
                                    PRAYER_AR[i], t / 60, t % 60,
                                    g_fazakkir.prayer_on[i] ? "" : " (معطّل)");
        } else {
            pos += (size_t)snprintf(out + pos, sz - pos,
                                    "• <b>%s:</b> <code>--:--</code>\n", PRAYER_AR[i]);
        }
    }
}

