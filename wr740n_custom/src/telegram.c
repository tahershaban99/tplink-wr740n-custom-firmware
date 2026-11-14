#define _GNU_SOURCE
#include "telegram.h"
#include "meter.h"
#include "json_util.h"
#include "fazakkir.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TG_CA_FILE   "/etc/rmeter/tg_ca.pem"
#define TG_THREAD_STACK 98304
#define TG_API_HOST  "api.telegram.org"

static pthread_mutex_t s_tg_seq_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_tg_tx_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned s_tg_req_seq = 0;
static bool s_tg_thread_started = false;
static bool s_skip_ui_edit = false;

static pthread_mutex_t s_edit_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static char s_last_edit_chat[32];
static int64_t s_last_edit_msg_id = 0;
static uint64_t s_last_edit_hash = 0;

static pthread_mutex_t s_ca_lock = PTHREAD_MUTEX_INITIALIZER;
static int s_ca_state = 0; /* 0 = unknown, 1 = verified CA OK, -1 = fallback no-check */
static time_t s_ca_fail_ts = 0;

static pthread_mutex_t s_ota_bg_lock = PTHREAD_MUTEX_INITIALIZER;
static bool s_ota_bg_running = false;

static const char *TG_ADMIN_KEYBOARD =
    "{\"keyboard\":["
    "[{\"text\":\"🏠 القائمة الرئيسية\"},{\"text\":\"👥 الأجهزة المتصلة\"}],"
    "[{\"text\":\"📊 استهلاك الباقة\"},{\"text\":\"⚡ فحص السرعة\"}],"
    "[{\"text\":\"⚙️ حالة الراوتر\"},{\"text\":\"📡 الوايفاي والشبكة\"}],"
    "[{\"text\":\"🕌 الصلاة القادمة\"},{\"text\":\"🚀 فحص التحديثات\"}],"
    "[{\"text\":\"🔄 إعادة التشغيل\"}]"
    "],\"resize_keyboard\":true}";

static const char *TG_USER_KEYBOARD =
    "{\"keyboard\":["
    "[{\"text\":\"📊 استهلاكي\"},{\"text\":\"⚡ سرعتي\"}],"
    "[{\"text\":\"🕌 الصلاة القادمة\"},{\"text\":\"📋 مساعدة\"}]"
    "],\"resize_keyboard\":true}";

typedef struct {
    char chat_id[32];
    char name[48];
    char username[32];
    time_t last_seen;
} tg_user_t;

static tg_user_t s_tg_users[12];
static int s_tg_user_count = 0;

typedef enum {
    PEND_NONE = 0,
    PEND_WIFI_SSID,
    PEND_WIFI_KEY,
    PEND_DEV_NAME,
    PEND_DEV_IP,
    PEND_DEV_CHAT,
    PEND_DEV_SPD,
    PEND_MAIN_QUOTA,
    PEND_WAN_SPD,
    PEND_REBOOT_TIME
} pend_kind_t;

typedef struct {
    char chat_id[32];
    pend_kind_t kind;
    char mac[24];
    time_t expires_at;
} tg_pending_t;

static pthread_mutex_t s_pend_lock = PTHREAD_MUTEX_INITIALIZER;
static tg_pending_t s_pend[4];

typedef struct {
    char ssid[64];
    char key[96];
    char encryption[32];
    char channel[16];
    char htmode[16];
    char txpower[16];
    char country[16];
    bool disabled;
    char wan_proto[24];
    char wan_ip[24];
} wifi_wan_info_t;

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

static void fmt_dur(time_t sec, char *out, size_t sz) {
    if (sec <= 0) { snprintf(out, sz, "-"); return; }
    unsigned long d = (unsigned long)(sec / 86400);
    unsigned long h = (unsigned long)((sec % 86400) / 3600);
    unsigned long m = (unsigned long)((sec % 3600) / 60);
    if (d) snprintf(out, sz, "%luي %luس", d, h);
    else if (h) snprintf(out, sz, "%luس %luد", h, m);
    else snprintf(out, sz, "%luد %luث", m, (unsigned long)(sec % 60));
}

static void utf8_copy_clean(const char *in, char *out, size_t sz, bool json_label, bool html_esc) {
    if (!out || sz == 0) return;
    if (!in) { out[0] = '\0'; return; }
    size_t i = 0, j = 0;
    while (in[i] && j + 1 < sz) {
        unsigned char b0 = (unsigned char)in[i];
        if (b0 < 0x80) {
            if (b0 < 0x20) {
                char rep = (html_esc && b0 == '\n') ? '\n' : ' ';
                out[j++] = rep;
                i++;
                continue;
            }
            if (json_label && (b0 == '"' || b0 == '\\')) {
                out[j++] = '\'';
                i++;
                continue;
            }
            if (html_esc) {
                if (b0 == '&') {
                    if (j + 5 >= sz) break;
                    memcpy(out + j, "&amp;", 5);
                    j += 5;
                    i++;
                    continue;
                }
                if (b0 == '<') {
                    if (j + 4 >= sz) break;
                    memcpy(out + j, "&lt;", 4);
                    j += 4;
                    i++;
                    continue;
                }
                if (b0 == '>') {
                    if (j + 4 >= sz) break;
                    memcpy(out + j, "&gt;", 4);
                    j += 4;
                    i++;
                    continue;
                }
            }
            out[j++] = (char)b0;
            i++;
            continue;
        }

        size_t need = 0;
        if ((b0 & 0xE0) == 0xC0 && b0 >= 0xC2) need = 2;
        else if ((b0 & 0xF0) == 0xE0) need = 3;
        else if ((b0 & 0xF8) == 0xF0 && b0 <= 0xF4) need = 4;
        else { i++; continue; }

        bool ok = true;
        for (size_t k = 1; k < need; k++) {
            unsigned char bk = (unsigned char)in[i + k];
            if (bk == 0 || (bk & 0xC0) != 0x80) {
                ok = false;
                break;
            }
        }
        if (!ok) { i++; continue; }
        if (j + need >= sz) break;
        memcpy(out + j, in + i, need);
        j += need;
        i += need;
    }
    out[j] = '\0';
}

static void html_escape(const char *in, char *out, size_t sz) {
    utf8_copy_clean(in, out, sz, false, true);
}

static void json_safe_label(const char *in, char *out, size_t sz) {
    utf8_copy_clean(in, out, sz, true, false);
}

static uint64_t fnv1a_pair(const char *a, const char *b) {
    uint64_t h = 1469598103934665603ULL;
    const char *strs[2] = { a ? a : "", b ? b : "" };
    for (int s = 0; s < 2; s++) {
        for (const unsigned char *p = (const unsigned char *)strs[s]; *p; p++) {
            h ^= *p;
            h *= 1099511628211ULL;
        }
        h ^= 0xFFU;
        h *= 1099511628211ULL;
    }
    return h;
}

static bool parse_mac_tail(const char *arg, int suffix_cols, char *mac, size_t mac_sz, const char **out_tail) {
    if (!arg || !mac || mac_sz < 2 || suffix_cols <= 0) return false;
    size_t len = strlen(arg);
    const char *p = arg + len;
    int found = 0;
    while (p > arg) {
        p--;
        if (*p == ':') {
            found++;
            if (found == suffix_cols) {
                size_t mlen = (size_t)(p - arg);
                if (mlen == 0 || mlen >= mac_sz) return false;
                memcpy(mac, arg, mlen);
                mac[mlen] = '\0';
                if (out_tail) *out_tail = p + 1;
                return true;
            }
        }
    }
    return false;
}

static bool safe_tg_uci_str(const char *s) {
    if (!s) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c < 0x20 || c == '\'' || c == '"' || c == '`' || c == '$' ||
            c == '\\' || c == ';' || c == '|' || c == '&' || c == '<' || c == '>') {
            return false;
        }
    }
    return true;
}

static void copy_uci_val(const char *src, char *dst, size_t sz) {
    if (!dst || sz == 0) return;
    dst[0] = '\0';
    if (!src) return;
    size_t len = strlen(src);
    while (len > 0 && (src[len - 1] == '\n' || src[len - 1] == '\r')) len--;
    if (len >= 2 && ((src[0] == '\'' && src[len - 1] == '\'') || (src[0] == '"' && src[len - 1] == '"'))) {
        src++;
        len -= 2;
    }
    if (len >= sz) len = sz - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static void read_wifi_wan_snapshot(wifi_wan_info_t *info) {
    memset(info, 0, sizeof(*info));
    snprintf(info->ssid, sizeof(info->ssid), "RouterMeter");
    snprintf(info->channel, sizeof(info->channel), "auto");
    snprintf(info->htmode, sizeof(info->htmode), "HT40");
    snprintf(info->country, sizeof(info->country), "JP");
    snprintf(info->wan_proto, sizeof(info->wan_proto), "dhcp");

    FILE *fp = popen("uci show wireless 2>/dev/null; uci show network.wan 2>/dev/null", "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = line;
        const char *v = eq + 1;
        if (strcmp(k, "wireless.default_radio0.ssid") == 0) copy_uci_val(v, info->ssid, sizeof(info->ssid));
        else if (strcmp(k, "wireless.default_radio0.key") == 0) copy_uci_val(v, info->key, sizeof(info->key));
        else if (strcmp(k, "wireless.default_radio0.encryption") == 0) copy_uci_val(v, info->encryption, sizeof(info->encryption));
        else if (strcmp(k, "wireless.radio0.channel") == 0) copy_uci_val(v, info->channel, sizeof(info->channel));
        else if (strcmp(k, "wireless.radio0.htmode") == 0) copy_uci_val(v, info->htmode, sizeof(info->htmode));
        else if (strcmp(k, "wireless.radio0.txpower") == 0) copy_uci_val(v, info->txpower, sizeof(info->txpower));
        else if (strcmp(k, "wireless.radio0.country") == 0) copy_uci_val(v, info->country, sizeof(info->country));
        else if (strcmp(k, "wireless.radio0.disabled") == 0) {
            char tmp[8];
            copy_uci_val(v, tmp, sizeof(tmp));
            info->disabled = (strcmp(tmp, "1") == 0);
        } else if (strcmp(k, "network.wan.proto") == 0) copy_uci_val(v, info->wan_proto, sizeof(info->wan_proto));
        else if (strcmp(k, "network.wan.ipaddr") == 0) copy_uci_val(v, info->wan_ip, sizeof(info->wan_ip));
    }
    pclose(fp);
}

static void sync_static_lease_tg(const char *mac, const char *ip, const char *name) {
    if (!mac || !mac[0]) return;
    char clean_id[32];
    int j = 0;
    for (int i = 0; mac[i] && j < 20; i++) {
        if (isalnum((unsigned char)mac[i])) clean_id[j++] = mac[i];
    }
    clean_id[j] = '\0';

    char cmd[384];
    snprintf(cmd, sizeof(cmd), "uci -q delete dhcp.rm_%s 2>/dev/null || true", clean_id);
    system(cmd);
    if (ip && ip[0] && safe_tg_uci_str(ip)) {
        const char *nm = (name && name[0] && safe_tg_uci_str(name)) ? name : "device";
        snprintf(cmd, sizeof(cmd),
                 "uci set dhcp.rm_%s=host && uci set dhcp.rm_%s.mac='%s' && "
                 "uci set dhcp.rm_%s.ip='%s' && uci set dhcp.rm_%s.name='%s' && "
                 "uci commit dhcp && (/etc/init.d/dnsmasq reload >/dev/null 2>&1 &)",
                 clean_id, clean_id, mac, clean_id, ip, clean_id, nm);
        system(cmd);
    } else {
        system("uci commit dhcp 2>/dev/null");
    }
}

static void read_sys_mem_uptime(unsigned long *up_s, unsigned long *ram_tot_kb, unsigned long *ram_free_kb) {
    *up_s = 0; *ram_tot_kb = 0; *ram_free_kb = 0;
    FILE *fp = fopen("/proc/uptime", "r");
    if (fp) {
        double u = 0;
        if (fscanf(fp, "%lf", &u) == 1) *up_s = (unsigned long)u;
        fclose(fp);
    }
    fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[128];
        unsigned long mf = 0, mb = 0, mc = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "MemTotal:", 9) == 0) sscanf(line + 9, "%lu", ram_tot_kb);
            else if (strncmp(line, "MemFree:", 8) == 0) sscanf(line + 8, "%lu", &mf);
            else if (strncmp(line, "Buffers:", 8) == 0) sscanf(line + 8, "%lu", &mb);
            else if (strncmp(line, "Cached:", 7) == 0) sscanf(line + 7, "%lu", &mc);
        }
        *ram_free_kb = mf + mb + mc;
        fclose(fp);
    }
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

static void pend_set(const char *chat_id, pend_kind_t kind, const char *mac) {
    if (!chat_id || !chat_id[0]) return;
    time_t exp = time(NULL) + 180;
    pthread_mutex_lock(&s_pend_lock);
    int free_idx = 0;
    for (int i = 0; i < 4; i++) {
        if (strcmp(s_pend[i].chat_id, chat_id) == 0) { free_idx = i; break; }
        if (s_pend[i].kind == PEND_NONE) free_idx = i;
    }
    snprintf(s_pend[free_idx].chat_id, sizeof(s_pend[free_idx].chat_id), "%s", chat_id);
    s_pend[free_idx].kind = kind;
    snprintf(s_pend[free_idx].mac, sizeof(s_pend[free_idx].mac), "%s", mac ? mac : "");
    s_pend[free_idx].expires_at = exp;
    pthread_mutex_unlock(&s_pend_lock);
}

static void pend_clear(const char *chat_id) {
    if (!chat_id) return;
    pthread_mutex_lock(&s_pend_lock);
    for (int i = 0; i < 4; i++) {
        if (strcmp(s_pend[i].chat_id, chat_id) == 0) {
            s_pend[i].kind = PEND_NONE;
            s_pend[i].mac[0] = '\0';
        }
    }
    pthread_mutex_unlock(&s_pend_lock);
}

static bool pend_pop(const char *chat_id, pend_kind_t *out_kind, char *out_mac, size_t mac_sz) {
    bool found = false;
    time_t now = time(NULL);
    pthread_mutex_lock(&s_pend_lock);
    for (int i = 0; i < 4; i++) {
        if (strcmp(s_pend[i].chat_id, chat_id) == 0 && s_pend[i].kind != PEND_NONE) {
            if (now <= s_pend[i].expires_at) {
                *out_kind = s_pend[i].kind;
                if (out_mac && mac_sz) snprintf(out_mac, mac_sz, "%s", s_pend[i].mac);
                found = true;
            }
            s_pend[i].kind = PEND_NONE;
            s_pend[i].mac[0] = '\0';
            break;
        }
    }
    pthread_mutex_unlock(&s_pend_lock);
    return found;
}

static size_t url_encode(const char *src, char *dst, size_t dst_sz) {
    static const char hex[] = "0123456789ABCDEF";
    size_t pos = 0;
    if (!dst || dst_sz == 0) return 0;
    if (!src) { dst[0] = '\0'; return 0; }
    for (const unsigned char *p = (const unsigned char *)src; *p && pos + 4 <= dst_sz; p++) {
        unsigned char c = *p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            dst[pos++] = (char)c;
        } else {
            dst[pos++] = '%';
            dst[pos++] = hex[c >> 4];
            dst[pos++] = hex[c & 0x0F];
        }
    }
    dst[pos] = '\0';
    return pos;
}

typedef int (*tg_io_write_fn)(void *ctx, const char *buf, size_t len, int timeout_s);
typedef int (*tg_io_read_fn)(void *ctx, char *buf, size_t len, int timeout_s);

static int ci_find_header(const char *hdrs, size_t hdr_len, const char *name, char *val, size_t val_sz) {
    size_t nlen = strlen(name);
    const char *p = hdrs;
    const char *end = hdrs + hdr_len;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        size_t llen = eol ? (size_t)(eol - p) : (size_t)(end - p);
        if (llen > nlen + 1 && strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            const char *v = p + nlen + 1;
            size_t rem = llen - nlen - 1;
            while (rem > 0 && (*v == ' ' || *v == '\t')) { v++; rem--; }
            while (rem > 0 && (v[rem - 1] == '\r' || v[rem - 1] == ' ')) rem--;
            size_t cp = (rem + 1 < val_sz) ? rem : (val_sz - 1);
            memcpy(val, v, cp);
            val[cp] = '\0';
            return 1;
        }
        p = eol ? (eol + 1) : end;
    }
    return 0;
}

typedef struct {
    void *ctx;
    tg_io_read_fn rd;
    int timeout_s;
    char buf[4096];
    size_t pos;
    size_t len;
} tg_rbuf_t;

static int rbuf_read(tg_rbuf_t *rb, char *out, size_t want) {
    if (rb->pos < rb->len) {
        size_t avail = rb->len - rb->pos;
        size_t cp = (want < avail) ? want : avail;
        memcpy(out, rb->buf + rb->pos, cp);
        rb->pos += cp;
        return (int)cp;
    }
    return rb->rd(rb->ctx, out, want, rb->timeout_s);
}

static int rbuf_read_line(tg_rbuf_t *rb, char *line, size_t sz) {
    size_t i = 0;
    while (i + 1 < sz) {
        if (rb->pos >= rb->len) {
            rb->pos = 0;
            int n = rb->rd(rb->ctx, rb->buf, sizeof(rb->buf), rb->timeout_s);
            if (n <= 0) {
                rb->len = 0;
                line[i] = '\0';
                return (i > 0) ? (int)i : -1;
            }
            rb->len = (size_t)n;
        }
        char c = rb->buf[rb->pos++];
        line[i++] = c;
        if (c == '\n') {
            line[i] = '\0';
            return (int)i;
        }
    }
    line[i] = '\0';
    return (int)i;
}

static bool tg_http_roundtrip(void *io_ctx, tg_io_write_fn wr, tg_io_read_fn rd,
                              const char *host, const char *path, const char *form_body,
                              char *resp_buf, size_t resp_sz, int timeout_s,
                              int *out_http_code, bool *out_conn_close, bool *out_early_eof) {
    if (out_http_code) *out_http_code = 0;
    if (out_conn_close) *out_conn_close = false;
    if (out_early_eof) *out_early_eof = false;
    if (resp_buf && resp_sz > 0) resp_buf[0] = '\0';

    size_t blen = form_body ? strlen(form_body) : 0;
    char hdr_req[512];
    int hlen = snprintf(hdr_req, sizeof(hdr_req),
                        "POST %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: %zu\r\n"
                        "Connection: keep-alive\r\n\r\n",
                        path, host, blen);
    if (hlen <= 0 || (size_t)hlen >= sizeof(hdr_req)) return false;

    size_t off = 0;
    while (off < (size_t)hlen) {
        int n = wr(io_ctx, hdr_req + off, (size_t)hlen - off, timeout_s);
        if (n <= 0) {
            if (out_early_eof) *out_early_eof = true;
            return false;
        }
        off += (size_t)n;
    }
    off = 0;
    while (off < blen) {
        int n = wr(io_ctx, form_body + off, blen - off, timeout_s);
        if (n <= 0) {
            if (out_early_eof) *out_early_eof = true;
            return false;
        }
        off += (size_t)n;
    }

    char hbuf[4096];
    size_t hpos = 0;
    size_t hdr_end = 0;
    while (hpos < sizeof(hbuf) - 1) {
        int n = rd(io_ctx, hbuf + hpos, sizeof(hbuf) - 1 - hpos, timeout_s);
        if (n <= 0) {
            if (hpos == 0 && out_early_eof) *out_early_eof = true;
            return false;
        }
        hpos += (size_t)n;
        hbuf[hpos] = '\0';
        char *eoh = strstr(hbuf, "\r\n\r\n");
        if (eoh) {
            hdr_end = (size_t)(eoh - hbuf) + 4;
            break;
        }
    }
    if (hdr_end == 0) return false;

    int http_code = 0;
    if (sscanf(hbuf, "HTTP/%*d.%*d %d", &http_code) != 1) return false;
    if (out_http_code) *out_http_code = http_code;

    char hval[64];
    bool is_chunked = (ci_find_header(hbuf, hdr_end, "Transfer-Encoding", hval, sizeof(hval)) &&
                       strcasestr(hval, "chunked") != NULL);
    bool has_cl = false;
    size_t cl_len = 0;
    if (!is_chunked && ci_find_header(hbuf, hdr_end, "Content-Length", hval, sizeof(hval))) {
        has_cl = true;
        cl_len = (size_t)strtoul(hval, NULL, 10);
    }
    if (ci_find_header(hbuf, hdr_end, "Connection", hval, sizeof(hval)) &&
        strcasestr(hval, "close") != NULL) {
        if (out_conn_close) *out_conn_close = true;
    }

    tg_rbuf_t rb;
    memset(&rb, 0, sizeof(rb));
    rb.ctx = io_ctx;
    rb.rd = rd;
    rb.timeout_s = timeout_s;
    size_t leftover = hpos - hdr_end;
    if (leftover > sizeof(rb.buf)) return false;
    if (leftover > 0) {
        memcpy(rb.buf, hbuf + hdr_end, leftover);
        rb.len = leftover;
    }

    size_t out_pos = 0;
    if (is_chunked) {
        char lbuf[64];
        while (1) {
            if (rbuf_read_line(&rb, lbuf, sizeof(lbuf)) < 0) return false;
            unsigned long csz = strtoul(lbuf, NULL, 16);
            if (csz == 0) {
                while (rbuf_read_line(&rb, lbuf, sizeof(lbuf)) > 2) {}
                break;
            }
            size_t rem = (size_t)csz;
            while (rem > 0) {
                char tmp[1024];
                size_t want = rem < sizeof(tmp) ? rem : sizeof(tmp);
                int n = rbuf_read(&rb, tmp, want);
                if (n <= 0) return false;
                if (resp_buf && resp_sz > 1 && out_pos + 1 < resp_sz) {
                    size_t cp = (size_t)n;
                    if (out_pos + cp >= resp_sz) cp = resp_sz - 1 - out_pos;
                    memcpy(resp_buf + out_pos, tmp, cp);
                    out_pos += cp;
                }
                rem -= (size_t)n;
            }
            char crlf[2];
            int got = 0;
            while (got < 2) {
                int n = rbuf_read(&rb, crlf + got, (size_t)(2 - got));
                if (n <= 0) return false;
                got += n;
            }
        }
    } else if (has_cl) {
        size_t rem = cl_len;
        while (rem > 0) {
            char tmp[1024];
            size_t want = rem < sizeof(tmp) ? rem : sizeof(tmp);
            int n = rbuf_read(&rb, tmp, want);
            if (n <= 0) return false;
            if (resp_buf && resp_sz > 1 && out_pos + 1 < resp_sz) {
                size_t cp = (size_t)n;
                if (out_pos + cp >= resp_sz) cp = resp_sz - 1 - out_pos;
                memcpy(resp_buf + out_pos, tmp, cp);
                out_pos += cp;
            }
            rem -= (size_t)n;
        }
    } else {
        if (out_conn_close) *out_conn_close = true;
        while (1) {
            char tmp[1024];
            int n = rbuf_read(&rb, tmp, sizeof(tmp));
            if (n <= 0) break;
            if (resp_buf && resp_sz > 1 && out_pos + 1 < resp_sz) {
                size_t cp = (size_t)n;
                if (out_pos + cp >= resp_sz) cp = resp_sz - 1 - out_pos;
                memcpy(resp_buf + out_pos, tmp, cp);
                out_pos += cp;
            }
        }
    }

    if (resp_buf && resp_sz > 0) resp_buf[out_pos] = '\0';
    return true;
}

/* ==================== PERSISTENT MBEDTLS KEEP-ALIVE ENGINE ==================== */
#define TG_MBED_OPAQUE_SZ 2048

typedef struct {
    bool ready;
    bool tried;
    void *h_tls;
    void *h_x509;
    void (*ssl_init)(void *);
    void (*ssl_free)(void *);
    void (*ssl_config_init)(void *);
    void (*ssl_config_free)(void *);
    int (*ssl_config_defaults)(void *, int, int, int);
    void (*ssl_conf_authmode)(void *, int);
    void (*ssl_conf_rng)(void *, int (*)(void *, unsigned char *, size_t), void *);
    void (*ssl_conf_ca_chain)(void *, void *, void *);
    int (*ssl_set_hostname)(void *, const char *);
    int (*ssl_setup)(void *, const void *);
    void (*ssl_set_bio)(void *, void *, int (*)(void *, const unsigned char *, size_t),
                        int (*)(void *, unsigned char *, size_t), void *);
    int (*ssl_handshake)(void *);
    int (*ssl_read)(void *, unsigned char *, size_t);
    int (*ssl_write)(void *, const unsigned char *, size_t);
    int (*ssl_close_notify)(void *);
    void (*x509_crt_init)(void *);
    void (*x509_crt_free)(void *);
    int (*x509_crt_parse_file)(void *, const char *);
} tg_mbed_api_t;

static pthread_mutex_t s_mbed_lock = PTHREAD_MUTEX_INITIALIZER;
static tg_mbed_api_t s_mb;
static pthread_mutex_t s_dns_lock = PTHREAD_MUTEX_INITIALIZER;
static struct in_addr s_tg_ip;
static time_t s_tg_ip_ts = 0;

typedef struct {
    int fd;
    void *ssl;
    void *conf;
    void *crt;
    int timeout_s;
    bool active;
} tg_tls_conn_t;

static tg_tls_conn_t s_poll_conn = { .fd = -1 };
static tg_tls_conn_t s_tx_conn = { .fd = -1 };

static bool tg_mbed_load(void) {
    pthread_mutex_lock(&s_mbed_lock);
    if (s_mb.tried) {
        bool ok = s_mb.ready;
        pthread_mutex_unlock(&s_mbed_lock);
        return ok;
    }
    s_mb.tried = true;
    void *ht = dlopen("libmbedtls.so.10", RTLD_NOW | RTLD_GLOBAL);
    void *hx = dlopen("libmbedx509.so.0", RTLD_NOW | RTLD_GLOBAL);
    if (!ht || !hx) {
        pthread_mutex_unlock(&s_mbed_lock);
        return false;
    }
    s_mb.h_tls = ht;
    s_mb.h_x509 = hx;
#define LOAD_SYM(dst, h, name) do { *(void **)(&(dst)) = dlsym((h), (name)); if (!(dst)) { pthread_mutex_unlock(&s_mbed_lock); return false; } } while (0)
    LOAD_SYM(s_mb.ssl_init, ht, "mbedtls_ssl_init");
    LOAD_SYM(s_mb.ssl_free, ht, "mbedtls_ssl_free");
    LOAD_SYM(s_mb.ssl_config_init, ht, "mbedtls_ssl_config_init");
    LOAD_SYM(s_mb.ssl_config_free, ht, "mbedtls_ssl_config_free");
    LOAD_SYM(s_mb.ssl_config_defaults, ht, "mbedtls_ssl_config_defaults");
    LOAD_SYM(s_mb.ssl_conf_authmode, ht, "mbedtls_ssl_conf_authmode");
    LOAD_SYM(s_mb.ssl_conf_rng, ht, "mbedtls_ssl_conf_rng");
    LOAD_SYM(s_mb.ssl_conf_ca_chain, ht, "mbedtls_ssl_conf_ca_chain");
    LOAD_SYM(s_mb.ssl_set_hostname, ht, "mbedtls_ssl_set_hostname");
    LOAD_SYM(s_mb.ssl_setup, ht, "mbedtls_ssl_setup");
    LOAD_SYM(s_mb.ssl_set_bio, ht, "mbedtls_ssl_set_bio");
    LOAD_SYM(s_mb.ssl_handshake, ht, "mbedtls_ssl_handshake");
    LOAD_SYM(s_mb.ssl_read, ht, "mbedtls_ssl_read");
    LOAD_SYM(s_mb.ssl_write, ht, "mbedtls_ssl_write");
    LOAD_SYM(s_mb.ssl_close_notify, ht, "mbedtls_ssl_close_notify");
    LOAD_SYM(s_mb.x509_crt_init, hx, "mbedtls_x509_crt_init");
    LOAD_SYM(s_mb.x509_crt_free, hx, "mbedtls_x509_crt_free");
    LOAD_SYM(s_mb.x509_crt_parse_file, hx, "mbedtls_x509_crt_parse_file");
#undef LOAD_SYM
    s_mb.ready = true;
    pthread_mutex_unlock(&s_mbed_lock);
    return true;
}

static int urandom_rng_cb(void *p, unsigned char *buf, size_t len) {
    (void)p;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            close(fd);
            return -1;
        }
        got += (size_t)n;
    }
    close(fd);
    return 0;
}

static int bio_net_send(void *ctx, const unsigned char *buf, size_t len) {
    tg_tls_conn_t *c = (tg_tls_conn_t *)ctx;
    if (!c || c->fd < 0) return -0x004E;
    struct pollfd pfd = { .fd = c->fd, .events = POLLOUT, .revents = 0 };
    int pr = poll(&pfd, 1, (c->timeout_s > 0 ? c->timeout_s : 8) * 1000);
    if (pr == 0) return -0x6800;
    if (pr < 0) return (errno == EINTR) ? -0x6880 : -0x004E;
    ssize_t n = send(c->fd, buf, len, MSG_NOSIGNAL);
    if (n >= 0) return (int)n;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return -0x6880;
    return -0x004E;
}

static int bio_net_recv(void *ctx, unsigned char *buf, size_t len) {
    tg_tls_conn_t *c = (tg_tls_conn_t *)ctx;
    if (!c || c->fd < 0) return -0x004C;
    struct pollfd pfd = { .fd = c->fd, .events = POLLIN, .revents = 0 };
    int pr = poll(&pfd, 1, (c->timeout_s > 0 ? c->timeout_s : 8) * 1000);
    if (pr == 0) return -0x6800;
    if (pr < 0) return (errno == EINTR) ? -0x6900 : -0x004C;
    ssize_t n = recv(c->fd, buf, len, 0);
    if (n >= 0) return (int)n;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return -0x6900;
    return -0x004C;
}

static void tg_tls_close(tg_tls_conn_t *c) {
    if (!c) return;
    if (c->ssl) {
        s_mb.ssl_free(c->ssl);
        free(c->ssl);
        c->ssl = NULL;
    }
    if (c->conf) {
        s_mb.ssl_config_free(c->conf);
        free(c->conf);
        c->conf = NULL;
    }
    if (c->crt) {
        s_mb.x509_crt_free(c->crt);
        free(c->crt);
        c->crt = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->active = false;
}

static int connect_tg_tcp(int timeout_ms) {
    struct in_addr addr;
    bool have_ip = false;
    time_t now = time(NULL);

    pthread_mutex_lock(&s_dns_lock);
    if (s_tg_ip_ts > 0 && (now - s_tg_ip_ts) < 300) {
        addr = s_tg_ip;
        have_ip = true;
    }
    pthread_mutex_unlock(&s_dns_lock);

    if (!have_ip) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(TG_API_HOST, "443", &hints, &res) != 0 || !res) {
            if (res) freeaddrinfo(res);
            return -1;
        }
        addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
        pthread_mutex_lock(&s_dns_lock);
        s_tg_ip = addr;
        s_tg_ip_ts = now;
        pthread_mutex_unlock(&s_dns_lock);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(443);
    sin.sin_addr = addr;

    int rc = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        pthread_mutex_lock(&s_dns_lock);
        s_tg_ip_ts = 0;
        pthread_mutex_unlock(&s_dns_lock);
        return -1;
    }
    if (rc < 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
        int pr = poll(&pfd, 1, timeout_ms);
        int so_err = 0;
        socklen_t sl = sizeof(so_err);
        if (pr <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &sl) < 0 || so_err != 0) {
            close(fd);
            pthread_mutex_lock(&s_dns_lock);
            s_tg_ip_ts = 0;
            pthread_mutex_unlock(&s_dns_lock);
            return -1;
        }
    }
    if (flags >= 0) fcntl(fd, F_SETFL, flags);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    return fd;
}

static bool tg_tls_connect(tg_tls_conn_t *c, int timeout_s, bool try_ca) {
    tg_tls_close(c);
    c->timeout_s = timeout_s;
    c->fd = connect_tg_tcp(5000);
    if (c->fd < 0) return false;

    c->ssl = calloc(1, TG_MBED_OPAQUE_SZ);
    c->conf = calloc(1, TG_MBED_OPAQUE_SZ);
    if (!c->ssl || !c->conf) {
        tg_tls_close(c);
        return false;
    }
    s_mb.ssl_init(c->ssl);
    s_mb.ssl_config_init(c->conf);
    if (s_mb.ssl_config_defaults(c->conf, 0, 0, 0) != 0) {
        tg_tls_close(c);
        return false;
    }
    s_mb.ssl_conf_rng(c->conf, urandom_rng_cb, NULL);

    bool use_ca = false;
    if (try_ca && access(TG_CA_FILE, R_OK) == 0 && time(NULL) >= 1704067200LL) {
        c->crt = calloc(1, TG_MBED_OPAQUE_SZ);
        if (c->crt) {
            s_mb.x509_crt_init(c->crt);
            if (s_mb.x509_crt_parse_file(c->crt, TG_CA_FILE) == 0) {
                s_mb.ssl_conf_ca_chain(c->conf, c->crt, NULL);
                use_ca = true;
            }
        }
    }
    s_mb.ssl_conf_authmode(c->conf, use_ca ? 2 : 0);
    if (s_mb.ssl_setup(c->ssl, c->conf) != 0 ||
        s_mb.ssl_set_hostname(c->ssl, TG_API_HOST) != 0) {
        tg_tls_close(c);
        return false;
    }
    s_mb.ssl_set_bio(c->ssl, c, bio_net_send, bio_net_recv, NULL);

    int hr;
    while ((hr = s_mb.ssl_handshake(c->ssl)) != 0) {
        if (hr != -0x6900 && hr != -0x6880) {
            tg_tls_close(c);
            return false;
        }
    }
    c->active = true;
    return true;
}

static int tls_io_write(void *ctx, const char *buf, size_t len, int timeout_s) {
    tg_tls_conn_t *c = (tg_tls_conn_t *)ctx;
    c->timeout_s = timeout_s;
    int n;
    while ((n = s_mb.ssl_write(c->ssl, (const unsigned char *)buf, len)) < 0) {
        if (n != -0x6900 && n != -0x6880) return -1;
    }
    return n;
}

static int tls_io_read(void *ctx, char *buf, size_t len, int timeout_s) {
    tg_tls_conn_t *c = (tg_tls_conn_t *)ctx;
    c->timeout_s = timeout_s;
    int n;
    while ((n = s_mb.ssl_read(c->ssl, (unsigned char *)buf, len)) < 0) {
        if (n == -0x7880) return 0; /* peer close_notify */
        if (n != -0x6900 && n != -0x6880) return -1;
    }
    return n;
}

static bool tg_post_tls_keepalive(tg_tls_conn_t *c, const char *method, const char *form_body,
                                  char *resp_buf, size_t resp_sz, int timeout_s, int *out_http_err) {
    char path[256];
    snprintf(path, sizeof(path), "/bot%s/%s", g_config.tg_token, method);

    time_t now = time(NULL);
    bool try_ca = false;
    pthread_mutex_lock(&s_ca_lock);
    if (access(TG_CA_FILE, R_OK) == 0 && now >= 1704067200LL) {
        if (s_ca_state >= 0 || (now - s_ca_fail_ts) >= 3600) try_ca = true;
    }
    pthread_mutex_unlock(&s_ca_lock);

    for (int attempt = 0; attempt < 2; attempt++) {
        bool was_active = c->active;
        if (!c->active) {
            if (!tg_tls_connect(c, timeout_s, try_ca)) {
                if (try_ca) {
                    pthread_mutex_lock(&s_ca_lock);
                    s_ca_state = -1;
                    s_ca_fail_ts = now;
                    pthread_mutex_unlock(&s_ca_lock);
                    try_ca = false;
                    if (!tg_tls_connect(c, timeout_s, false)) return false;
                } else {
                    return false;
                }
            } else if (try_ca) {
                pthread_mutex_lock(&s_ca_lock);
                s_ca_state = 1;
                pthread_mutex_unlock(&s_ca_lock);
            }
        }

        int hc = 0;
        bool conn_close = false;
        bool early_eof = false;
        bool ok_rt = tg_http_roundtrip(c, tls_io_write, tls_io_read, TG_API_HOST, path, form_body,
                                       resp_buf, resp_sz, timeout_s, &hc, &conn_close, &early_eof);
        if (ok_rt) {
            if (conn_close) tg_tls_close(c);
            if (out_http_err) *out_http_err = (hc >= 400) ? hc : 0;
            bool api_ok = (hc == 200);
            if (api_ok && resp_buf && resp_sz > 0) {
                if (!json_get_bool(resp_buf, "ok", &api_ok)) {
                    api_ok = (strstr(resp_buf, "\"ok\":true") != NULL);
                }
            }
            return api_ok;
        }
        tg_tls_close(c);
        if (!was_active || !early_eof) break;
    }
    return false;
}

static bool run_uclient_fetch(const char *ca_opt, int timeout_s, const char *post_data,
                              const char *resp_file, const char *url,
                              char *err_buf, size_t err_sz) {
    if (err_buf && err_sz > 0) err_buf[0] = '\0';

    size_t post_len = post_data ? strlen(post_data) : 0;
    char *post_arg = NULL;
    if (post_len > 0) {
        post_arg = malloc(12 + post_len + 1);
        if (!post_arg) return false;
        memcpy(post_arg, "--post-data=", 12);
        memcpy(post_arg + 12, post_data, post_len + 1);
    }

    char tmo_str[16];
    snprintf(tmo_str, sizeof(tmo_str), "%d", timeout_s > 0 ? timeout_s : 15);

    int err_pipe[2] = {-1, -1};
    bool has_pipe = (pipe(err_pipe) == 0);

    pid_t pid = fork();
    if (pid < 0) {
        if (has_pipe) { close(err_pipe[0]); close(err_pipe[1]); }
        free(post_arg);
        return false;
    }
    if (pid == 0) {
        int devnull_r = open("/dev/null", O_RDONLY);
        if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }
        int devnull_w = open("/dev/null", O_WRONLY);
        if (devnull_w >= 0) { dup2(devnull_w, STDOUT_FILENO); close(devnull_w); }
        if (has_pipe) {
            close(err_pipe[0]);
            dup2(err_pipe[1], STDERR_FILENO);
            close(err_pipe[1]);
        }

        char *argv[12];
        int argc = 0;
        argv[argc++] = "uclient-fetch";
        argv[argc++] = "-4";
        argv[argc++] = "-T";
        argv[argc++] = tmo_str;
        argv[argc++] = (char *)ca_opt;
        if (post_arg) argv[argc++] = post_arg;
        argv[argc++] = "-O";
        argv[argc++] = (char *)resp_file;
        argv[argc++] = (char *)url;
        argv[argc] = NULL;

        execvp("uclient-fetch", argv);
        _exit(127);
    }

    free(post_arg);
    if (has_pipe) {
        close(err_pipe[1]);
        size_t off = 0;
        if (err_buf && err_sz > 1) {
            while (off + 1 < err_sz) {
                ssize_t r = read(err_pipe[0], err_buf + off, err_sz - 1 - off);
                if (r <= 0) break;
                off += (size_t)r;
            }
            err_buf[off] = '\0';
        }
        char drain[128];
        while (read(err_pipe[0], drain, sizeof(drain)) > 0) {}
        close(err_pipe[0]);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool tg_post_api(const char *method, const char *form_body, char *resp_buf,
                        size_t resp_sz, int timeout_s, int *out_http_err) {
    if (out_http_err) *out_http_err = 0;
    if (!g_config.tg_token[0] || !method) return false;

    bool is_poll = (strcmp(method, "getUpdates") == 0);
    if (!is_poll) pthread_mutex_lock(&s_tg_tx_lock);

    /* Fast path: persistent TLS Keep-Alive via preinstalled libmbedtls.so.10 (0ms handshake reuse!) */
    if (tg_mbed_load()) {
        tg_tls_conn_t *conn = is_poll ? &s_poll_conn : &s_tx_conn;
        char local_chk[512];
        char *rb = (resp_buf && resp_sz > 0) ? resp_buf : local_chk;
        size_t rsz = (resp_buf && resp_sz > 0) ? resp_sz : sizeof(local_chk);
        bool ok = tg_post_tls_keepalive(conn, method, form_body, rb, rsz, timeout_s, out_http_err);
        if (!is_poll) pthread_mutex_unlock(&s_tg_tx_lock);
        return ok;
    }

    pthread_mutex_lock(&s_tg_seq_lock);
    unsigned seq = ++s_tg_req_seq;
    pthread_mutex_unlock(&s_tg_seq_lock);

    char resp_file[64];
    snprintf(resp_file, sizeof(resp_file), "/tmp/rmeter/tg_resp_%u.json", seq);

    char url[256];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/%s", g_config.tg_token, method);

    bool has_ca = (access(TG_CA_FILE, R_OK) == 0);
    time_t now = time(NULL);
    bool try_ca = false;

    /* Skip doomed CA checks when clock isn't synced (<2024) or CA recently failed */
    pthread_mutex_lock(&s_ca_lock);
    if (has_ca && now >= 1704067200LL) {
        if (s_ca_state >= 0 || (now - s_ca_fail_ts) >= 3600) {
            try_ca = true;
        }
    }
    pthread_mutex_unlock(&s_ca_lock);

    char err_txt[512];
    bool proc_ok = false;
    int http_code = 0;

    if (try_ca) {
        unlink(resp_file);
        proc_ok = run_uclient_fetch("--ca-certificate=" TG_CA_FILE, timeout_s, form_body,
                                    resp_file, url, err_txt, sizeof(err_txt));
        const char *he = strstr(err_txt, "HTTP error ");
        http_code = he ? atoi(he + 11) : 0;
        if (http_code > 0 || (proc_ok && access(resp_file, R_OK) == 0)) {
            pthread_mutex_lock(&s_ca_lock);
            s_ca_state = 1;
            pthread_mutex_unlock(&s_ca_lock);
        } else {
            pthread_mutex_lock(&s_ca_lock);
            s_ca_state = -1;
            s_ca_fail_ts = now;
            pthread_mutex_unlock(&s_ca_lock);

            unlink(resp_file);
            proc_ok = run_uclient_fetch("--no-check-certificate", timeout_s, form_body,
                                        resp_file, url, err_txt, sizeof(err_txt));
            he = strstr(err_txt, "HTTP error ");
            http_code = he ? atoi(he + 11) : 0;
        }
    } else {
        unlink(resp_file);
        time_t t0 = time(NULL);
        proc_ok = run_uclient_fetch("--no-check-certificate", timeout_s, form_body,
                                    resp_file, url, err_txt, sizeof(err_txt));
        const char *he = strstr(err_txt, "HTTP error ");
        http_code = he ? atoi(he + 11) : 0;
        if (!proc_ok && http_code == 0 && timeout_s <= 6 && (time(NULL) - t0) < 3) {
            unlink(resp_file);
            proc_ok = run_uclient_fetch("--no-check-certificate", timeout_s, form_body,
                                        resp_file, url, err_txt, sizeof(err_txt));
            he = strstr(err_txt, "HTTP error ");
            http_code = he ? atoi(he + 11) : 0;
        }
    }

    if (out_http_err) *out_http_err = http_code;

    bool ok = false;
    if (proc_ok && http_code == 0) {
        FILE *rf = fopen(resp_file, "r");
        if (rf) {
            if (resp_buf && resp_sz > 0) {
                size_t n = fread(resp_buf, 1, resp_sz - 1, rf);
                resp_buf[n] = '\0';
                if (!json_get_bool(resp_buf, "ok", &ok)) {
                    ok = (strstr(resp_buf, "\"ok\":true") != NULL);
                }
            } else {
                char chk[256] = {0};
                size_t n = fread(chk, 1, sizeof(chk) - 1, rf);
                chk[n] = '\0';
                if (!json_get_bool(chk, "ok", &ok)) {
                    ok = (strstr(chk, "\"ok\":true") != NULL);
                }
            }
            fclose(rf);
        }
    }

    unlink(resp_file);
    if (!is_poll) pthread_mutex_unlock(&s_tg_tx_lock);
    return ok;
}

static void tg_answer_callback_sync(const char *cb_id, const char *toast_txt) {
    if (!cb_id || !cb_id[0]) return;
    char enc_cb[192], enc_txt[288], body[520];
    url_encode(cb_id, enc_cb, sizeof(enc_cb));
    if (toast_txt && toast_txt[0]) {
        url_encode(toast_txt, enc_txt, sizeof(enc_txt));
        snprintf(body, sizeof(body), "callback_query_id=%s&text=%s", enc_cb, enc_txt);
    } else {
        snprintf(body, sizeof(body), "callback_query_id=%s", enc_cb);
    }
    tg_post_api("answerCallbackQuery", body, NULL, 0, 6, NULL);
}

static bool tg_send_message_ex(const char *chat_id, const char *text,
                               const char *reply_markup_json, int *out_http_err) {
    if (out_http_err) *out_http_err = 0;
    if (!chat_id || !chat_id[0] || !text) return false;

    size_t cid_len = strlen(chat_id);
    size_t txt_len = strlen(text);
    size_t kb_len = (reply_markup_json && reply_markup_json[0]) ? strlen(reply_markup_json) : 0;

    char *enc_cid = malloc(cid_len * 3 + 1);
    char *enc_txt = malloc(txt_len * 3 + 1);
    char *enc_kb = kb_len ? malloc(kb_len * 3 + 1) : NULL;
    if (!enc_cid || !enc_txt || (kb_len && !enc_kb)) {
        free(enc_cid); free(enc_txt); free(enc_kb);
        return false;
    }

    url_encode(chat_id, enc_cid, cid_len * 3 + 1);
    url_encode(text, enc_txt, txt_len * 3 + 1);
    if (kb_len) url_encode(reply_markup_json, enc_kb, kb_len * 3 + 1);

    size_t body_sz = strlen(enc_cid) + strlen(enc_txt) + (enc_kb ? strlen(enc_kb) : 0) + 96;
    char *body = malloc(body_sz);
    bool ok = false;
    if (body) {
        if (enc_kb && enc_kb[0]) {
            snprintf(body, body_sz, "chat_id=%s&text=%s&parse_mode=HTML&reply_markup=%s",
                     enc_cid, enc_txt, enc_kb);
        } else {
            snprintf(body, body_sz, "chat_id=%s&text=%s&parse_mode=HTML",
                     enc_cid, enc_txt);
        }
        ok = tg_post_api("sendMessage", body, NULL, 0, 8, out_http_err);
        free(body);
    }

    free(enc_cid);
    free(enc_txt);
    free(enc_kb);
    return ok;
}

static void tg_edit_or_send(const char *chat_id, int64_t edit_msg_id,
                            const char *text, const char *inline_kb_json) {
    if (!chat_id || !chat_id[0] || !text || s_skip_ui_edit) return;
    if (edit_msg_id <= 0) {
        tg_send_message_ex(chat_id, text, inline_kb_json, NULL);
        return;
    }

    size_t cid_len = strlen(chat_id);
    size_t txt_len = strlen(text);
    size_t kb_len = (inline_kb_json && inline_kb_json[0]) ? strlen(inline_kb_json) : 0;

    char *enc_cid = malloc(cid_len * 3 + 1);
    char *enc_txt = malloc(txt_len * 3 + 1);
    char *enc_kb = kb_len ? malloc(kb_len * 3 + 1) : NULL;
    if (!enc_cid || !enc_txt || (kb_len && !enc_kb)) {
        free(enc_cid); free(enc_txt); free(enc_kb);
        return;
    }
    url_encode(chat_id, enc_cid, cid_len * 3 + 1);
    url_encode(text, enc_txt, txt_len * 3 + 1);
    if (kb_len) url_encode(inline_kb_json, enc_kb, kb_len * 3 + 1);

    size_t body_sz = strlen(enc_cid) + strlen(enc_txt) + (enc_kb ? strlen(enc_kb) : 0) + 128;
    char *body = malloc(body_sz);
    bool edited = false;
    int hc = 0;
    if (body) {
        if (enc_kb && enc_kb[0]) {
            snprintf(body, body_sz,
                     "chat_id=%s&message_id=%lld&text=%s&parse_mode=HTML&reply_markup=%s",
                     enc_cid, (long long)edit_msg_id, enc_txt, enc_kb);
        } else {
            snprintf(body, body_sz,
                     "chat_id=%s&message_id=%lld&text=%s&parse_mode=HTML",
                     enc_cid, (long long)edit_msg_id, enc_txt);
        }
        edited = tg_post_api("editMessageText", body, NULL, 0, 8, &hc);
        free(body);
    }
    free(enc_cid);
    free(enc_txt);
    free(enc_kb);

    uint64_t h = fnv1a_pair(text, inline_kb_json ? inline_kb_json : "");
    bool same_as_last = false;
    pthread_mutex_lock(&s_edit_cache_lock);
    same_as_last = (s_last_edit_msg_id == edit_msg_id && s_last_edit_hash == h &&
                    strcmp(s_last_edit_chat, chat_id) == 0);
    if (edited) {
        snprintf(s_last_edit_chat, sizeof(s_last_edit_chat), "%s", chat_id);
        s_last_edit_msg_id = edit_msg_id;
        s_last_edit_hash = h;
    }
    pthread_mutex_unlock(&s_edit_cache_lock);

    /* Only fall back to sendMessage when Telegram genuinely rejects editing an old/deleted message (HTTP 400 != unchanged) */
    if (!edited && hc == 400 && !same_as_last) {
        tg_send_message_ex(chat_id, text, inline_kb_json, NULL);
    }
}

bool telegram_send_message(const char *chat_id, const char *text, const char *reply_markup_json) {
    return tg_send_message_ex(chat_id, text, reply_markup_json, NULL);
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
    char copy[160];
    snprintf(copy, sizeof(copy), "%s", g_config.tg_admin_ids);
    bool any = false;
    int last_http = 0;
    char *tok = strtok(copy, ",; ");
    while (tok) {
        int hc = 0;
        if (tg_send_message_ex(tok,
                "✅ <b>اختبار اتصال بوت راوتر WR740N v4</b>\nالبوت متصل ويعمل بسرعة وكفاءة مع لوحة التحكم التفاعلية الكاملة!",
                TG_ADMIN_KEYBOARD, &hc)) {
            any = true;
        } else if (hc > 0) {
            last_http = hc;
        }
        tok = strtok(NULL, ",; ");
    }
    if (!any && err_buf) {
        if (last_http == 400) {
            snprintf(err_buf, err_sz, "Telegram rejected chat_id (HTTP 400) - press /start in the bot first");
        } else if (last_http == 401 || last_http == 404) {
            snprintf(err_buf, err_sz, "Invalid Bot Token (HTTP %d)", last_http);
        } else {
            snprintf(err_buf, err_sz, "HTTPS request failed or invalid token/chat_id");
        }
    }
    return any;
}

static bool is_remote_ver_newer(const char *remote, const char *local) {
    int r_maj = 0, r_min = 0, r_pat = 0;
    int l_maj = 0, l_min = 0, l_pat = 0;
    if (sscanf(remote ? remote : "", "%d.%d.%d", &r_maj, &r_min, &r_pat) < 1) return false;
    if (sscanf(local ? local : "", "%d.%d.%d", &l_maj, &l_min, &l_pat) < 1) return true;
    if (r_maj != l_maj) return r_maj > l_maj;
    if (r_min != l_min) return r_min > l_min;
    return r_pat > l_pat;
}

bool telegram_check_ota_remote(char *out_ver, size_t vsz, char *out_url, size_t usz,
                               char *out_notes, size_t nsz, bool *out_newer) {
    if (out_ver && vsz) out_ver[0] = '\0';
    if (out_url && usz) out_url[0] = '\0';
    if (out_notes && nsz) out_notes[0] = '\0';
    if (out_newer) *out_newer = false;

    char ver_url[192] = {0}, cur_fw[24] = {0};
    pthread_mutex_lock(&g_lock);
    snprintf(ver_url, sizeof(ver_url), "%s", g_config.ota_version_url);
    snprintf(cur_fw, sizeof(cur_fw), "%s", g_config.fw_version);
    pthread_mutex_unlock(&g_lock);

    if (!ver_url[0]) return false;

    bool has_ca = (access(TG_CA_FILE, R_OK) == 0 && time(NULL) >= 1704067200LL);
    const char *ca_opt = has_ca ? ("--ca-certificate=" TG_CA_FILE) : "--no-check-certificate";
    char err_txt[256];
    bool ok = run_uclient_fetch(ca_opt, 10, NULL, RMETER_OTA_VER_RAM, ver_url, err_txt, sizeof(err_txt));
    if (!ok && has_ca) {
        ok = run_uclient_fetch("--no-check-certificate", 10, NULL, RMETER_OTA_VER_RAM, ver_url, err_txt, sizeof(err_txt));
    }
    if (!ok) return false;

    FILE *fp = fopen(RMETER_OTA_VER_RAM, "r");
    if (!fp) return false;
    char buf[2048] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';

    char ver[32] = {0}, url[256] = {0}, notes[256] = {0};
    json_get_str(buf, "version", ver, sizeof(ver));
    if (!json_get_str(buf, "firmware_url", url, sizeof(url)) || !url[0]) {
        json_get_str(buf, "url", url, sizeof(url));
    }
    if (!json_get_str(buf, "changelog", notes, sizeof(notes)) || !notes[0]) {
        json_get_str(buf, "notes", notes, sizeof(notes));
    }

    if (out_ver && vsz) snprintf(out_ver, vsz, "%s", ver);
    if (out_url && usz) snprintf(out_url, usz, "%s", url);
    if (out_notes && nsz) snprintf(out_notes, nsz, "%s", notes);
    if (out_newer) *out_newer = (ver[0] && is_remote_ver_newer(ver, cur_fw));
    return true;
}

static void *bg_ota_check_worker(void *arg) {
    (void)arg;
    char r_ver[32] = {0}, r_url[256] = {0}, r_log[256] = {0};
    bool newer = false;
    if (telegram_check_ota_remote(r_ver, sizeof(r_ver), r_url, sizeof(r_url), r_log, sizeof(r_log), &newer) &&
        newer && r_url[0] && g_config.tg_enabled && g_config.tg_token[0]) {
        char esc_log[320], ota_msg[768];
        html_escape(r_log[0] ? r_log : "تحسينات عامة في الأداء والاستقرار", esc_log, sizeof(esc_log));
        snprintf(ota_msg, sizeof(ota_msg),
                 "🎉 <b>تحديث سحابي جديد متاح لراوترك (v%s)!</b>\n\n"
                 "🔖 <b>الإصدار الحالي:</b> <code>v%s</code>\n"
                 "📝 <b>التغييرات:</b> %s\n\n"
                 "👇 اضغط على الزر بالأسفل عند رغبتك في التثبيت:",
                 r_ver, g_config.fw_version, esc_log);
        telegram_broadcast_admins(ota_msg,
                                  "{\"inline_keyboard\":[[{\"text\":\"⚡ تثبيت التحديث الآن\",\"callback_data\":\"ota_ask\"},"
                                  "{\"text\":\"🔍 تفاصيل التحديث\",\"callback_data\":\"adm_ota\"}]]}");
    }
    pthread_mutex_lock(&s_ota_bg_lock);
    s_ota_bg_running = false;
    pthread_mutex_unlock(&s_ota_bg_lock);
    return NULL;
}

static void launch_bg_ota_check(void) {
    pthread_mutex_lock(&s_ota_bg_lock);
    bool busy = s_ota_bg_running;
    if (!busy) s_ota_bg_running = true;
    pthread_mutex_unlock(&s_ota_bg_lock);
    if (busy) return;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, TG_THREAD_STACK);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t tid;
    if (pthread_create(&tid, &attr, bg_ota_check_worker, NULL) != 0) {
        pthread_mutex_lock(&s_ota_bg_lock);
        s_ota_bg_running = false;
        pthread_mutex_unlock(&s_ota_bg_lock);
    }
    pthread_attr_destroy(&attr);
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
        uint64_t rem = (g_config.main_quota_bytes > used) ? (g_config.main_quota_bytes - used) : 0;
        uint32_t pct = (uint32_t)((used * 100ULL) / g_config.main_quota_bytes);
        if (pct > 100) pct = 100;
        for (int t = 0; t < nth; t++) {
            uint16_t bit = (uint16_t)(1U << t);
            if (pct >= th[t] && !(g_config.main_alert_flags & bit)) {
                g_config.main_alert_flags |= bit;
                g_flash_dirty = true;
                char ustr[32], qstr[32], rstr[32], msg[640], custom_msg[512];
                fmt_bytes(used, ustr, sizeof(ustr));
                fmt_bytes(g_config.main_quota_bytes, qstr, sizeof(qstr));
                fmt_bytes(rem, rstr, sizeof(rstr));

                if (g_config.tg_alert_msgs[t][0]) {
                    meter_format_alert_template(g_config.tg_alert_msgs[t],
                                                "الباقة الرئيسية", g_config.start_date,
                                                (unsigned)th[t], ustr, qstr, rstr,
                                                custom_msg, sizeof(custom_msg));
                    snprintf(msg, sizeof(msg), "%s", custom_msg);
                } else {
                    snprintf(msg, sizeof(msg),
                             "⚠️ <b>تنبيه استهلاك الباقة الرئيسية (%u%%)</b>\n"
                             "📊 المستهلك: <b>%s</b> من أصل <b>%s</b>\n"
                             "💾 المتبقي: <b>%s</b>\n"
                             "📅 الدورة: %s ⬅️ %s",
                             (unsigned)th[t], ustr, qstr, rstr,
                             g_config.start_date, g_config.end_date);
                }
                pthread_mutex_unlock(&g_lock);
                telegram_broadcast_admins(msg, NULL);
                pthread_mutex_lock(&g_lock);
            }
        }
    }

    /* 2. Per-Device Quota alerts (uses customizable per-threshold template if set) */
    for (int i = 0; i < g_device_count; i++) {
        rmeter_device_t dc = g_devices[i];
        if (dc.quota_bytes == 0) continue;
        uint64_t used = meter_scaled_bytes(dc.up_bytes + dc.down_bytes);
        uint64_t rem = (dc.quota_bytes > used) ? (dc.quota_bytes - used) : 0;
        uint32_t pct = (uint32_t)((used * 100ULL) / dc.quota_bytes);
        if (pct > 100) pct = 100;
        for (int t = 0; t < nth; t++) {
            uint16_t bit = (uint16_t)(1U << t);
            if (pct >= th[t] && !(dc.alert_flags & bit)) {
                g_devices[i].alert_flags |= bit;
                dc.alert_flags |= bit;
                g_flash_dirty = true;
                char ustr[32], qstr[32], rstr[32], msg[640], custom_msg[512];
                char dchat[32], dname_raw[RMETER_MAX_NAME], dname[128], dip[24];
                utf8_copy_clean(dc.tg_chat_id, dchat, sizeof(dchat), false, false);
                utf8_copy_clean(dc.name[0] ? dc.name : (dc.ip[0] ? dc.ip : dc.mac),
                                dname_raw, sizeof(dname_raw), false, false);
                utf8_copy_clean(dc.ip[0] ? dc.ip : dc.mac, dip, sizeof(dip), false, false);
                html_escape(dname_raw, dname, sizeof(dname));
                fmt_bytes(used, ustr, sizeof(ustr));
                fmt_bytes(dc.quota_bytes, qstr, sizeof(qstr));
                fmt_bytes(rem, rstr, sizeof(rstr));

                if (g_config.tg_alert_msgs[t][0]) {
                    meter_format_alert_template(g_config.tg_alert_msgs[t],
                                                dname, dip, (unsigned)th[t],
                                                ustr, qstr, rstr,
                                                custom_msg, sizeof(custom_msg));
                    snprintf(msg, sizeof(msg), "%s", custom_msg);
                } else {
                    snprintf(msg, sizeof(msg),
                             "%s <b>تنبيه استهلاك الباقة (%u%%)</b>\n"
                             "📱 الجهاز: <b>%s</b> (<code>%s</code>)\n"
                             "📊 المستهلك: <b>%s</b> / <b>%s</b>\n"
                             "💾 المتبقي: <b>%s</b>%s",
                             (th[t] >= 100) ? "⛔" : "🔔",
                             (unsigned)th[t], dname, dip, ustr, qstr, rstr,
                             (th[t] >= 100) ? "\n🔒 تم إيقاف الإنترنت تلقائياً لانتهاء الباقة." : "");
                }
                pthread_mutex_unlock(&g_lock);
                telegram_broadcast_admins(msg, NULL);
                if (dchat[0] && !tg_is_admin(dchat)) {
                    telegram_send_message(dchat, msg, NULL);
                }
                pthread_mutex_lock(&g_lock);
                if (i >= g_device_count) break;
            }
        }
    }

    pthread_mutex_unlock(&g_lock);
}

/* ==================== ADMIN INTERACTIVE HUB & MENUS ==================== */

static void send_admin_home_menu(const char *chat_id, int64_t edit_msg_id) {
    unsigned long ups = 0, rtot = 0, rfree = 0;
    read_sys_mem_uptime(&ups, &rtot, &rfree);

    char *msg = calloc(1, 1400);
    char *kb = calloc(1, 800);
    if (!msg || !kb) { free(msg); free(kb); return; }

    char dn[24], up[24], tu[32], mq[32];
    pthread_mutex_lock(&g_lock);
    fmt_bps(g_total_down_bps, dn, sizeof(dn));
    fmt_bps(g_total_up_bps, up, sizeof(up));
    uint64_t used = meter_total_used_bytes();
    uint64_t mqb = g_config.main_quota_bytes;
    fmt_bytes(used, tu, sizeof(tu));
    fmt_bytes(mqb, mq, sizeof(mq));
    int on_cnt = 0, blk_cnt = 0, tot_cnt = g_device_count;
    for (int i = 0; i < g_device_count; i++) {
        if (g_devices[i].online) on_cnt++;
        if (g_devices[i].blocked) blk_cnt++;
    }
    char fw[24];
    snprintf(fw, sizeof(fw), "%s", g_config.fw_version);
    pthread_mutex_unlock(&g_lock);

    double pct = (mqb > 0) ? (((double)used * 100.0) / (double)mqb) : 0.0;
    snprintf(msg, 1400,
             "🏠 <b>لوحة تحكم راوتر TP-Link WR740N v4</b> (<code>v%s</code>)\n\n"
             "👥 <b>الأجهزة المتصلة:</b> <b>%d</b> / %d %s\n"
             "⚡ <b>السرعة الآن:</b> ⬇️ %s | ⬆️ %s\n"
             "📊 <b>الباقة:</b> %s %s%s (%.0f%%)\n"
             "🧠 <b>الرام الحرة:</b> %.1f / %.1f MB | ⏱️ %luس %luد\n\n"
             "👇 <b>اختر القسم المطلوب للتحكم الكامل بالراوتر:</b>",
             fw, on_cnt, tot_cnt, blk_cnt ? "(يوجد محظور)" : "",
             dn, up, tu, mqb ? "/ " : "(مفتوحة)", mqb ? mq : "", mqb ? pct : 0.0,
             (double)rfree / 1024.0, (double)rtot / 1024.0,
             ups / 3600, (ups % 3600) / 60);

    snprintf(kb, 800,
             "{\"inline_keyboard\":["
             "[{\"text\":\"👥 الأجهزة والتحكم (%d)\",\"callback_data\":\"adm_devs:on\"},"
             "{\"text\":\"📊 الباقة والمعايرة\",\"callback_data\":\"adm_quota\"}],"
             "[{\"text\":\"📡 الوايفاي والشبكة\",\"callback_data\":\"adm_net\"},"
             "{\"text\":\"⚡ السرعة اللحظية\",\"callback_data\":\"adm_speed\"}],"
             "[{\"text\":\"⚙️ النظام والأدوات\",\"callback_data\":\"adm_status\"},"
             "{\"text\":\"🔄 إعادة التشغيل\",\"callback_data\":\"adm_reboot\"}],"
             "[{\"text\":\"🚀 تحديث OTA\",\"callback_data\":\"adm_ota\"},"
             "{\"text\":\"🕌 الصلاة القادمة\",\"callback_data\":\"adm_prayer\"}],"
             "[{\"text\":\"🔄 تحديث اللوحة\",\"callback_data\":\"adm_home\"}]"
             "]}", on_cnt);

    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
    free(msg);
    free(kb);
}

static void send_admin_quota_menu(const char *chat_id, int64_t edit_msg_id) {
    char *msg = calloc(1, 2048);
    char *kb = calloc(1, 700);
    if (!msg || !kb) { free(msg); free(kb); return; }

    pthread_mutex_lock(&g_lock);
    uint64_t tot = meter_total_used_bytes();
    uint64_t mq = g_config.main_quota_bytes;
    uint64_t rem = (mq > tot) ? (mq - tot) : 0;
    double div_gb = (g_config.gb_standard == 1000) ? 1000000000.0 : (1024.0 * 1024.0 * 1024.0);
    double rem_gb = (double)rem / div_gb;
    double tot_gb = (double)tot / div_gb;
    double mq_gb = (double)mq / div_gb;
    double pct = (mq > 0) ? (((double)tot * 100.0) / (double)mq) : 0.0;

    char sd[12], ed[12];
    snprintf(sd, sizeof(sd), "%s", g_config.start_date);
    snprintf(ed, sizeof(ed), "%s", g_config.end_date);
    uint16_t pdays = g_config.period_days ? g_config.period_days : 30;
    uint32_t wdl = g_config.wan_down_kbps, wul = g_config.wan_up_kbps;
    uint16_t spct = g_config.scale_pct ? g_config.scale_pct : 100;
    uint16_t gbs = g_config.gb_standard ? g_config.gb_standard : 1024;
    pthread_mutex_unlock(&g_lock);

    time_t now = time(NULL);
    double safe_daily = 0.0;
    long rem_days = pdays;
    struct tm tm_end = {0};
    int ey = 0, em = 0, eday = 0;
    if (sscanf(ed, "%d-%d-%d", &ey, &em, &eday) == 3 && ey >= 2024) {
        tm_end.tm_year = ey - 1900;
        tm_end.tm_mon = em - 1;
        tm_end.tm_mday = eday;
        tm_end.tm_hour = 23;
        tm_end.tm_min = 59;
        time_t end_t = mktime(&tm_end);
        if (end_t > now) rem_days = (long)((end_t - now + 86399) / 86400);
        else rem_days = 1;
    }
    if (rem_days < 1) rem_days = 1;
    if (mq > 0) safe_daily = rem_gb / (double)rem_days;

    if (mq > 0) {
        snprintf(msg, 2048,
                 "📊 <b>تحليل الباقة والمعايرة وسرعة الخط:</b>\n\n"
                 "📦 <b>الاستهلاك:</b> %.2f GB / %.2f GB (<b>%.1f%%</b>)\n"
                 "💾 <b>المتبقي:</b> %.2f GB | ⏱️ %ld يوم متبقي\n"
                 "🛡️ <b>المعدل اليومي الآمن:</b> <b>%.2f GB / يوم</b>\n"
                 "📅 <b>الدورة:</b> %s ⬅️ %s\n"
                 "🌐 <b>سرعة الخط WAN:</b> %uM ⬇️ / %uM ⬆️\n"
                 "⚖️ <b>المعايرة:</b> %u%% • وحدة %u",
                 tot_gb, mq_gb, pct, rem_gb, rem_days, safe_daily, sd, ed,
                 (unsigned)(wdl / 1000), (unsigned)(wul / 1000),
                 (unsigned)spct, (unsigned)gbs);
    } else {
        snprintf(msg, 2048,
                 "📊 <b>الاستهلاك الكلي والمعايرة:</b>\n\n"
                 "📦 <b>المستهلك:</b> %.2f GB (الباقة الرئيسية مفتوحة ♾️)\n"
                 "📅 <b>الدورة:</b> %s ⬅️ %s\n"
                 "🌐 <b>سرعة الخط WAN:</b> %uM ⬇️ / %uM ⬆️\n"
                 "⚖️ <b>المعايرة:</b> %u%% • وحدة %u",
                 tot_gb, sd, ed,
                 (unsigned)(wdl / 1000), (unsigned)(wul / 1000),
                 (unsigned)spct, (unsigned)gbs);
    }

    snprintf(kb, 700,
             "{\"inline_keyboard\":["
             "[{\"text\":\"📦 تعديل الباقة الرئيسية\",\"callback_data\":\"adm_qset\"},"
             "{\"text\":\"🌐 سرعة الخط WAN\",\"callback_data\":\"adm_wan\"}],"
             "[{\"text\":\"⚖️ المعايرة (Scale)\",\"callback_data\":\"adm_scale\"},"
             "{\"text\":\"👥 الأجهزة\",\"callback_data\":\"adm_devs:on\"}],"
             "[{\"text\":\"🧹 تصفير استهلاك الكل\",\"callback_data\":\"rstall_ask\"}],"
             "[{\"text\":\"🔄 تحديث\",\"callback_data\":\"adm_quota\"},"
             "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]"
             "]}");

    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
    free(msg);
    free(kb);
}

static void send_admin_qset_menu(const char *chat_id, int64_t edit_msg_id) {
    const char *kb =
        "{\"inline_keyboard\":["
        "[{\"text\":\"100 GB\",\"callback_data\":\"setq:100\"},"
        "{\"text\":\"200 GB\",\"callback_data\":\"setq:200\"},"
        "{\"text\":\"300 GB\",\"callback_data\":\"setq:300\"}],"
        "[{\"text\":\"500 GB\",\"callback_data\":\"setq:500\"},"
        "{\"text\":\"♾️ مفتوحة\",\"callback_data\":\"setq:0\"},"
        "{\"text\":\"✏️ رقم مخصص\",\"callback_data\":\"pqmain\"}],"
        "[{\"text\":\"🔙 رجوع للباقة\",\"callback_data\":\"adm_quota\"},"
        "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]"
        "]}";
    tg_edit_or_send(chat_id, edit_msg_id,
                    "📦 <b>اختر سعة الباقة الرئيسية للراوتر (بالجيجابايت):</b>", kb);
}

static void send_admin_wan_menu(const char *chat_id, int64_t edit_msg_id) {
    const char *kb =
        "{\"inline_keyboard\":["
        "[{\"text\":\"10M / 2M\",\"callback_data\":\"setwan:10000:2000\"},"
        "{\"text\":\"20M / 5M\",\"callback_data\":\"setwan:20000:5000\"}],"
        "[{\"text\":\"30M / 5M\",\"callback_data\":\"setwan:30000:5000\"},"
        "{\"text\":\"50M / 10M\",\"callback_data\":\"setwan:50000:10000\"}],"
        "[{\"text\":\"♾️ بلا تحديد (0)\",\"callback_data\":\"setwan:0:0\"},"
        "{\"text\":\"✏️ إدخال مخصص\",\"callback_data\":\"pwan\"}],"
        "[{\"text\":\"🔙 رجوع للباقة\",\"callback_data\":\"adm_quota\"},"
        "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]"
        "]}";
    tg_edit_or_send(chat_id, edit_msg_id,
                    "🌐 <b>تحديد السرعة الكلية للخط (WAN QoS):</b>\n"
                    "تُستخدم لتنظيم الأولويات ومنع الاختناق عند تفعيل وضع الألعاب VIP.", kb);
}

static void send_admin_scale_menu(const char *chat_id, int64_t edit_msg_id) {
    pthread_mutex_lock(&g_lock);
    uint16_t spct = g_config.scale_pct ? g_config.scale_pct : 100;
    uint16_t gbs = g_config.gb_standard ? g_config.gb_standard : 1024;
    pthread_mutex_unlock(&g_lock);

    char msg[320], kb[640];
    snprintf(msg, sizeof(msg),
             "⚖️ <b>معايرة عداد الباقة:</b>\n\n"
             "• <b>نسبة التعديل:</b> %u%%\n"
             "• <b>معيار الجيجابايت:</b> %u (%s)",
             (unsigned)spct, (unsigned)gbs, (gbs == 1000) ? "عشري 1000" : "ثنائي 1024");
    snprintf(kb, sizeof(kb),
             "{\"inline_keyboard\":["
             "[{\"text\":\"95%%\",\"callback_data\":\"sscale:95\"},"
             "{\"text\":\"100%%\",\"callback_data\":\"sscale:100\"},"
             "{\"text\":\"105%%\",\"callback_data\":\"sscale:105\"},"
             "{\"text\":\"110%%\",\"callback_data\":\"sscale:110\"}],"
             "[{\"text\":\"🔄 تبديل معيار GB (%u)\",\"callback_data\":\"sgb_tog\"}],"
             "[{\"text\":\"🔙 رجوع للباقة\",\"callback_data\":\"adm_quota\"},"
             "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]"
             "]}", (unsigned)gbs);
    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
}

static void send_admin_devices_menu_page(const char *chat_id, int64_t edit_msg_id, bool show_offline, int page) {
    rmeter_device_t *snap = calloc(RMETER_MAX_DEVICES, sizeof(*snap));
    if (!snap) return;
    int count = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_device_count && count < RMETER_MAX_DEVICES; i++) {
        if (show_offline || g_devices[i].online || g_devices[i].blocked) {
            snap[count++] = g_devices[i];
        }
    }
    if (!show_offline && count == 0 && g_device_count > 0) {
        for (int i = 0; i < g_device_count && count < RMETER_MAX_DEVICES; i++) snap[count++] = g_devices[i];
    }
    pthread_mutex_unlock(&g_lock);

    const int per_page = 8;
    int total_pages = (count > 0) ? ((count + per_page - 1) / per_page) : 1;
    if (page < 0) page = 0;
    if (page >= total_pages) page = total_pages - 1;
    int start = page * per_page;
    int end = start + per_page;
    if (end > count) end = count;

    char *msg = calloc(1, 2400);
    char *kb = calloc(1, 2048);
    if (!msg || !kb) { free(msg); free(kb); free(snap); return; }

    size_t mpos = 0;
    int mn = snprintf(msg, 2400,
                      "👥 <b>%s (%d):</b>%s\nاضغط على أي جهاز لفتح كافة خيارات التحكم به:\n\n",
                      show_offline ? "كل الأجهزة المسجلة" : "الأجهزة المتصلة حالياً", count,
                      (total_pages > 1) ? "" : "");
    if (mn > 0) mpos = ((size_t)mn < 2400) ? (size_t)mn : 2399;
    if (total_pages > 1 && mpos + 32 < 2400) {
        mn = snprintf(msg + mpos, 2400 - mpos, "📄 <i>صفحة %d من %d</i>\n\n", page + 1, total_pages);
        if (mn > 0) mpos += ((size_t)mn < 2400 - mpos) ? (size_t)mn : (2399 - mpos);
    }

    size_t kpos = 0;
    int kn = snprintf(kb, 2048, "{\"inline_keyboard\":[");
    if (kn > 0) kpos = ((size_t)kn < 2048) ? (size_t)kn : 2047;
    bool in_row = false;
    bool first_row = true;

    for (int i = start; i < end; i++) {
        rmeter_device_t *d = &snap[i];
        int num = i + 1;
        char esc_nm[96], ustr[32], qstr[32], dn[24], up[24];
        const char *raw_nm = d->name[0] ? d->name : (d->ip[0] ? d->ip : d->mac);
        html_escape(raw_nm, esc_nm, sizeof(esc_nm));
        fmt_bytes(meter_scaled_bytes(d->up_bytes + d->down_bytes), ustr, sizeof(ustr));
        fmt_bytes(d->quota_bytes, qstr, sizeof(qstr));
        fmt_bps(d->cur_down_bps, dn, sizeof(dn));
        fmt_bps(d->cur_up_bps, up, sizeof(up));

        if (mpos + 220 < 2350) {
            mn = snprintf(msg + mpos, 2400 - mpos,
                          "%d. <b>%s</b> (<code>%s</code>) %s%s%s\n"
                          "   ⬇️ %s | ⬆️ %s | 📊 %s%s%s\n",
                          num, esc_nm, d->ip[0] ? d->ip : d->mac,
                          d->blocked ? "⛔" : (d->online ? "🟢" : "⚪"),
                          d->gaming_mode ? " 🎮" : "",
                          d->speed_unlocked ? " 🚀" : "",
                          dn, up, ustr,
                          d->quota_bytes ? " / " : "",
                          d->quota_bytes ? qstr : " (∞)");
            if (mn > 0) mpos += ((size_t)mn < 2400 - mpos) ? (size_t)mn : (2399 - mpos);
        }

        if (kpos + 140 < 1780) {
            char bname[32];
            json_safe_label(raw_nm, bname, sizeof(bname));

            char label[48];
            snprintf(label, sizeof(label), "%s %d. %s",
                     d->blocked ? "⛔" : (d->gaming_mode ? "🎮" : "⚙️"), num, bname);
            if (!in_row) {
                kn = snprintf(kb + kpos, 2048 - kpos,
                              "%s[{\"text\":\"%s\",\"callback_data\":\"mdev:%s\"}",
                              first_row ? "" : ",", label, d->mac);
                first_row = false;
                in_row = true;
            } else {
                kn = snprintf(kb + kpos, 2048 - kpos,
                              ",{\"text\":\"%s\",\"callback_data\":\"mdev:%s\"}]",
                              label, d->mac);
                in_row = false;
            }
            if (kn > 0) kpos += ((size_t)kn < 2048 - kpos) ? (size_t)kn : (2047 - kpos);
        }
    }
    if (in_row && kpos + 2 < 2048) {
        kb[kpos++] = ']';
        kb[kpos] = '\0';
    }
    if (total_pages > 1 && kpos + 180 < 2048) {
        const char *mode = show_offline ? "all" : "on";
        kn = snprintf(kb + kpos, 2048 - kpos, "%s[", first_row ? "" : ",");
        if (kn > 0) kpos += ((size_t)kn < 2048 - kpos) ? (size_t)kn : (2047 - kpos);
        first_row = false;
        bool pfirst = true;
        if (page > 0) {
            kn = snprintf(kb + kpos, 2048 - kpos,
                          "{\"text\":\"◀️ السابق\",\"callback_data\":\"adm_devs:%s:%d\"}",
                          mode, page - 1);
            if (kn > 0) kpos += ((size_t)kn < 2048 - kpos) ? (size_t)kn : (2047 - kpos);
            pfirst = false;
        }
        kn = snprintf(kb + kpos, 2048 - kpos,
                      "%s{\"text\":\"📄 %d/%d\",\"callback_data\":\"adm_devs:%s:%d\"}",
                      pfirst ? "" : ",", page + 1, total_pages, mode, page);
        if (kn > 0) kpos += ((size_t)kn < 2048 - kpos) ? (size_t)kn : (2047 - kpos);
        if (page + 1 < total_pages && kpos + 90 < 2048) {
            kn = snprintf(kb + kpos, 2048 - kpos,
                          ",{\"text\":\"التالي ▶️\",\"callback_data\":\"adm_devs:%s:%d\"}",
                          mode, page + 1);
            if (kn > 0) kpos += ((size_t)kn < 2048 - kpos) ? (size_t)kn : (2047 - kpos);
        }
        if (kpos + 2 < 2048) { kb[kpos++] = ']'; kb[kpos] = '\0'; }
    }
    if (kpos + 220 < 2048) {
        snprintf(kb + kpos, 2048 - kpos,
                 "%s[{\"text\":\"%s\",\"callback_data\":\"%s:0\"},"
                 "{\"text\":\"🔄 تحديث\",\"callback_data\":\"%s:%d\"},"
                 "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}",
                 first_row ? "" : ",",
                 show_offline ? "🟢 المتصلة فقط" : "⚪ عرض الكل",
                 show_offline ? "adm_devs:on" : "adm_devs:all",
                 show_offline ? "adm_devs:all" : "adm_devs:on",
                 page);
    }

    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
    free(msg);
    free(kb);
    free(snap);
}

static void send_admin_devices_menu(const char *chat_id, int64_t edit_msg_id, bool show_offline) {
    send_admin_devices_menu_page(chat_id, edit_msg_id, show_offline, 0);
}

static void send_admin_device_control(const char *chat_id, int64_t edit_msg_id, const char *mac) {
    pthread_mutex_lock(&g_lock);
    int idx = meter_find_by_mac(mac);
    if (idx < 0) {
        pthread_mutex_unlock(&g_lock);
        tg_edit_or_send(chat_id, edit_msg_id, "❌ لم يتم العثور على الجهاز.",
                        "{\"inline_keyboard\":[[{\"text\":\"🔙 الأجهزة\",\"callback_data\":\"adm_devs:on\"},"
                        "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}");
        return;
    }
    rmeter_device_t d = g_devices[idx];
    uint64_t used = meter_scaled_bytes(d.up_bytes + d.down_bytes);
    pthread_mutex_unlock(&g_lock);

    char *msg = calloc(1, 1400);
    char *kb = calloc(1, 1600);
    if (!msg || !kb) { free(msg); free(kb); return; }

    char nm[96], ustr[32], qstr[32], rstr[32], dn[24], up[24], dur[32], cap_str[64];
    html_escape(d.name[0] ? d.name : (d.ip[0] ? d.ip : d.mac), nm, sizeof(nm));
    fmt_bytes(used, ustr, sizeof(ustr));
    fmt_bytes(d.quota_bytes, qstr, sizeof(qstr));
    uint64_t rem = (d.quota_bytes > used) ? (d.quota_bytes - used) : 0;
    fmt_bytes(rem, rstr, sizeof(rstr));
    fmt_bps(d.cur_down_bps, dn, sizeof(dn));
    fmt_bps(d.cur_up_bps, up, sizeof(up));
    time_t now = time(NULL);
    fmt_dur((d.online && d.connected_at > 0 && now >= d.connected_at) ? (now - d.connected_at) : 0, dur, sizeof(dur));

    if (d.speed_unlocked) {
        snprintf(cap_str, sizeof(cap_str), "🚀 مفتوحة مؤقتاً (المحفوظ: %.1f/%.1f M)",
                 d.cap_down_kbps / 1000.0, d.cap_up_kbps / 1000.0);
    } else if (d.cap_down_kbps > 0 || d.cap_up_kbps > 0) {
        snprintf(cap_str, sizeof(cap_str), "🔒 %.1fM ⬇️ / %.1fM ⬆️",
                 d.cap_down_kbps / 1000.0, d.cap_up_kbps / 1000.0);
    } else {
        snprintf(cap_str, sizeof(cap_str), "مفتوحة (بلا تحديد)");
    }

    snprintf(msg, 1400,
             "🎛️ <b>تحكم الجهاز: %s</b>\n\n"
             "🌐 <b>IP:</b> <code>%s</code>%s\n"
             "🔗 <b>MAC:</b> <code>%s</code>\n"
             "📡 <b>الاتصال:</b> %s (%s | %s)\n"
             "⚡ <b>السرعة الآن:</b> ⬇️ %s | ⬆️ %s\n"
             "🎚️ <b>تحديد السرعة:</b> %s\n"
             "📊 <b>الباقة:</b> %s %s%s (متبقي %s)\n"
             "🎮 <b>وضع الألعاب VIP:</b> %s\n"
             "👤 <b>معرف التليجرام:</b> <code>%s</code>",
             nm, d.ip[0] ? d.ip : "-", d.bound_ip[0] ? " 📌" : "",
             d.mac, d.blocked ? "⛔ محظور" : (d.online ? "🟢 متصل" : "⚪ غير متصل"),
             d.is_wifi ? "Wi-Fi" : "LAN", dur,
             dn, up, cap_str,
             ustr, d.quota_bytes ? "/ " : "(مفتوحة ♾️)", d.quota_bytes ? qstr : "",
             d.quota_bytes ? rstr : "∞",
             d.gaming_mode ? "مفعل ✅" : "غير مفعل",
             d.tg_chat_id[0] ? d.tg_chat_id : "غير مربوط");

    snprintf(kb, 1600,
             "{\"inline_keyboard\":["
             "[{\"text\":\"➕ +1G\",\"callback_data\":\"addq:%s:1\"},"
             "{\"text\":\"➕ +5G\",\"callback_data\":\"addq:%s:5\"},"
             "{\"text\":\"➕ +10G\",\"callback_data\":\"addq:%s:10\"},"
             "{\"text\":\"➕ +20G\",\"callback_data\":\"addq:%s:20\"}],"
             "[{\"text\":\"♾️ باقة مفتوحة\",\"callback_data\":\"addq:%s:0\"},"
             "{\"text\":\"🔄 تصفير العداد\",\"callback_data\":\"rstu:%s\"}],"
             "[{\"text\":\"🎚️ تغيير السرعة\",\"callback_data\":\"spdmenu:%s\"},"
             "{\"text\":\"%s\",\"callback_data\":\"unlim:%s\"}],"
             "[{\"text\":\"%s\",\"callback_data\":\"vip:%s\"},"
             "{\"text\":\"%s\",\"callback_data\":\"%s:%s\"}],"
             "[{\"text\":\"✏️ تعديل الاسم\",\"callback_data\":\"pname:%s\"},"
             "{\"text\":\"📌 تثبيت IP\",\"callback_data\":\"pip:%s\"},"
             "{\"text\":\"👤 ربط تليجرام\",\"callback_data\":\"tgp:%s\"}],"
             "[{\"text\":\"🗑️ حذف\",\"callback_data\":\"deld_ask:%s\"},"
             "{\"text\":\"🔄 تحديث\",\"callback_data\":\"mdev:%s\"},"
             "{\"text\":\"🔙 الأجهزة\",\"callback_data\":\"adm_devs:on\"},"
             "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]"
             "]}",
             d.mac, d.mac, d.mac, d.mac,
             d.mac, d.mac,
             d.mac, d.speed_unlocked ? "🔒 تطبيق التحديد" : "🚀 فتح السرعة", d.mac,
             d.gaming_mode ? "🎮 إلغاء VIP" : "🎮 تفعيل VIP", d.mac,
             d.blocked ? "✅ فك الحظر" : "⛔ حظر الجهاز", d.blocked ? "ublk" : "blk", d.mac,
             d.mac, d.mac, d.mac,
             d.mac, d.mac);

    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
    free(msg);
    free(kb);
}

static void send_admin_speed_submenu(const char *chat_id, int64_t edit_msg_id, const char *mac) {
    char *kb = calloc(1, 1280);
    if (!kb) return;
    snprintf(kb, 1280,
             "{\"inline_keyboard\":["
             "[{\"text\":\"🐢 1M / 1M\",\"callback_data\":\"setspd:%s:1000:1000\"},"
             "{\"text\":\"🚶 2M / 1M\",\"callback_data\":\"setspd:%s:2000:1000\"}],"
             "[{\"text\":\"🚗 5M / 2M\",\"callback_data\":\"setspd:%s:5000:2000\"},"
             "{\"text\":\"🏎️ 10M / 3M\",\"callback_data\":\"setspd:%s:10000:3000\"}],"
             "[{\"text\":\"⚡ 20M / 5M\",\"callback_data\":\"setspd:%s:20000:5000\"},"
             "{\"text\":\"♾️ بلا تحديد (0)\",\"callback_data\":\"setspd:%s:0:0\"}],"
             "[{\"text\":\"✏️ سرعة مخصصة\",\"callback_data\":\"pspd:%s\"},"
             "{\"text\":\"🔙 رجوع للجهاز\",\"callback_data\":\"mdev:%s\"}]"
             "]}",
             mac, mac, mac, mac, mac, mac, mac, mac);

    tg_edit_or_send(chat_id, edit_msg_id,
                    "🎚️ <b>اختر سرعة التحميل / الرفع للجهاز:</b>", kb);
    free(kb);
}

static void send_device_tg_picker(const char *chat_id, int64_t edit_msg_id, const char *mac) {
    char *kb = calloc(1, 1400);
    if (!kb) return;
    size_t pos = snprintf(kb, 1400, "{\"inline_keyboard\":[");
    bool first = true;
    for (int i = 0; i < s_tg_user_count && i < 6 && pos + 140 < 1200; i++) {
        char nm[32];
        json_safe_label(s_tg_users[i].name[0] ? s_tg_users[i].name : s_tg_users[i].chat_id,
                        nm, sizeof(nm));
        int kn = snprintf(kb + pos, 1400 - pos,
                          "%s[{\"text\":\"👤 %s (%s)\",\"callback_data\":\"tgset:%s:%s\"}]",
                          first ? "" : ",", nm, s_tg_users[i].chat_id, mac, s_tg_users[i].chat_id);
        if (kn > 0) pos += ((size_t)kn < 1400 - pos) ? (size_t)kn : (1399 - pos);
        first = false;
    }
    pos += snprintf(kb + pos, 1400 - pos,
                    "%s[{\"text\":\"✏️ إدخال Chat ID يدوياً\",\"callback_data\":\"ptg:%s\"},"
                    "{\"text\":\"❌ فك الربط\",\"callback_data\":\"tgclr:%s\"}],"
                    "[{\"text\":\"🔙 رجوع للجهاز\",\"callback_data\":\"mdev:%s\"},"
                    "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}",
                    first ? "" : ",", mac, mac, mac);

    tg_edit_or_send(chat_id, edit_msg_id,
                    "👤 <b>ربط الجهاز بحساب تليجرام:</b>\n"
                    "اختر أحد المستخدمين المكتشفين بالأسفل ليصله إشعار استهلاكه الخاص، أو أدخل المعرف يدوياً:",
                    kb);
    free(kb);
}

static void send_admin_speed_report(const char *chat_id, int64_t edit_msg_id) {
    char *msg = calloc(1, 2200);
    char *kb = calloc(1, 400);
    if (!msg || !kb) { free(msg); free(kb); return; }

    char dn[24], up[24];
    pthread_mutex_lock(&g_lock);
    fmt_bps(g_total_down_bps, dn, sizeof(dn));
    fmt_bps(g_total_up_bps, up, sizeof(up));
    size_t pos = snprintf(msg, 2200,
                          "⚡ <b>السرعات اللحظية للشبكة:</b>\n\n"
                          "🌐 <b>الإجمالي الآن:</b> ⬇️ <b>%s</b> | ⬆️ <b>%s</b>\n\n",
                          dn, up);
    int active = 0;
    for (int i = 0; i < g_device_count && pos < 2000; i++) {
        rmeter_device_t *d = &g_devices[i];
        if (!d->online && d->cur_down_bps == 0 && d->cur_up_bps == 0) continue;
        active++;
        char nm[64];
        html_escape(d->name[0] ? d->name : d->ip, nm, sizeof(nm));
        fmt_bps(d->cur_down_bps, dn, sizeof(dn));
        fmt_bps(d->cur_up_bps, up, sizeof(up));
        pos += snprintf(msg + pos, 2200 - pos,
                        "• <b>%s</b> (%s)%s\n  ⬇️ %s | ⬆️ %s\n",
                        nm, d->ip, d->speed_unlocked ? " 🚀" : (d->gaming_mode ? " 🎮" : ""), dn, up);
    }
    if (active == 0) {
        snprintf(msg + pos, 2200 - pos, "<i>لا يوجد سحب بيانات لحظي الآن.</i>");
    }
    pthread_mutex_unlock(&g_lock);

    snprintf(kb, 400,
             "{\"inline_keyboard\":[[{\"text\":\"🔄 تحديث السرعة\",\"callback_data\":\"adm_speed\"},"
             "{\"text\":\"👥 الأجهزة\",\"callback_data\":\"adm_devs:on\"},"
             "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}");
    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
    free(msg);
    free(kb);
}

static void send_admin_status_report(const char *chat_id, int64_t edit_msg_id, const char *extra_note) {
    unsigned long ups = 0, rtot = 0, rfree = 0;
    read_sys_mem_uptime(&ups, &rtot, &rfree);

    char *msg = calloc(1, 1500);
    char *kb = calloc(1, 650);
    if (!msg || !kb) { free(msg); free(kb); return; }

    char dn[24], up[24], tu[32], mq[32], rtime[64] = "غير متزامن";
    bool obs = false;
    time_t now = time(NULL);
    pthread_mutex_lock(&g_lock);
    fmt_bps(g_total_down_bps, dn, sizeof(dn));
    fmt_bps(g_total_up_bps, up, sizeof(up));
    fmt_bytes(meter_total_used_bytes(), tu, sizeof(tu));
    fmt_bytes(g_config.main_quota_bytes, mq, sizeof(mq));
    int on_cnt = 0, wf_cnt = 0;
    for (int i = 0; i < g_device_count; i++) {
        if (g_devices[i].online) {
            on_cnt++;
            if (g_devices[i].is_wifi) wf_cnt++;
        }
    }
    bool rb_en = g_config.auto_reboot_enabled;
    uint8_t rb_h = g_config.auto_reboot_hour, rb_m = g_config.auto_reboot_min;
    int8_t rb_tz = g_config.auto_reboot_tz;
    obs = g_config.observer_mode_enabled;
    char fw[24], wan[32];
    snprintf(fw, sizeof(fw), "%s", g_config.fw_version);
    snprintf(wan, sizeof(wan), "%s", g_wan_if);
    pthread_mutex_unlock(&g_lock);

    time_t lt = now + (time_t)rb_tz * 3600;
    struct tm tmv;
    if (gmtime_r(&lt, &tmv) && tmv.tm_year + 1900 >= 2024) {
        snprintf(rtime, sizeof(rtime), "%04d-%02d-%02d %02d:%02d:%02d",
                 tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                 tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    }

    snprintf(msg, 1500,
             "⚙️ <b>حالة راوتر TP-Link WR740N v4 والأدوات:</b>\n\n"
             "🔖 <b>الإصدار:</b> <code>v%s</code>\n"
             "🕒 <b>الوقت:</b> <code>%s</code>\n"
             "⏱️ <b>التشغيل:</b> %lu يوم %lu س %lu د\n"
             "🧠 <b>الرام الحرة:</b> %.1f / %.1f MB\n"
             "👥 <b>المتصلون:</b> <b>%d</b> (%d Wi-Fi) • WAN: <code>%s</code>\n"
             "⚡ <b>السرعة:</b> ⬇️ %s | ⬆️ %s\n"
             "📊 <b>الباقة:</b> %s%s%s\n"
             "👁️ <b>وضع المراقبة:</b> %s\n"
             "🔄 <b>الريستارت اليومي:</b> %s (%02u:%02u UTC%+d)%s%s",
             fw, rtime, ups / 86400, (ups % 86400) / 3600, (ups % 3600) / 60,
             (double)rfree / 1024.0, (double)rtot / 1024.0,
             on_cnt, wf_cnt, wan, dn, up, tu,
             g_config.main_quota_bytes ? " / " : " (مفتوحة)",
             g_config.main_quota_bytes ? mq : "",
             obs ? "🟢 مفعل" : "⚪ معطل",
             rb_en ? "🟢 مفعل" : "⚪ متوقف",
             (unsigned)rb_h, (unsigned)rb_m, (int)rb_tz,
             extra_note ? "\n\n" : "", extra_note ? extra_note : "");

    snprintf(kb, 650,
             "{\"inline_keyboard\":["
             "[{\"text\":\"🕒 مزامنة الوقت NTP\",\"callback_data\":\"sys_ntp\"},"
             "{\"text\":\"%s وضع المراقبة\",\"callback_data\":\"sys_obs\"}],"
             "[{\"text\":\"🔍 فحص الإنترنت (Ping)\",\"callback_data\":\"sys_ping\"},"
             "{\"text\":\"📡 الوايفاي والشبكة\",\"callback_data\":\"adm_net\"}],"
             "[{\"text\":\"🔄 إعادة التشغيل\",\"callback_data\":\"adm_reboot\"},"
             "{\"text\":\"🔄 تحديث\",\"callback_data\":\"adm_status\"}],"
             "[{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]"
             "]}",
             obs ? "🔴 إيقاف" : "🟢 تفعيل");
    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
    free(msg);
    free(kb);
}

static void send_admin_wifi_menu(const char *chat_id, int64_t edit_msg_id, bool reveal_key) {
    wifi_wan_info_t wi;
    read_wifi_wan_snapshot(&wi);

    int wf_cnt = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_device_count; i++) {
        if (g_devices[i].online && g_devices[i].is_wifi) wf_cnt++;
    }
    pthread_mutex_unlock(&g_lock);

    char esc_ssid[96], esc_key[128];
    html_escape(wi.ssid[0] ? wi.ssid : "RouterMeter", esc_ssid, sizeof(esc_ssid));
    if (reveal_key) html_escape(wi.key[0] ? wi.key : "(بدون كلمة سر)", esc_key, sizeof(esc_key));
    else snprintf(esc_key, sizeof(esc_key), "%s", wi.key[0] ? "•••••••• (اضغط كشف)" : "(شبكة مفتوحة)");

    char *msg = calloc(1, 1200);
    char *kb = calloc(1, 1024);
    if (!msg || !kb) { free(msg); free(kb); return; }

    snprintf(msg, 1200,
             "📡 <b>إعدادات الوايفاي والشبكة (2.4GHz ath9k):</b>\n\n"
             "📶 <b>الاسم (SSID):</b> <code>%s</code>\n"
             "🔑 <b>كلمة السر:</b> <code>%s</code>\n"
             "🔌 <b>حالة البث:</b> %s\n"
             "📻 <b>القناة والعرض:</b> CH %s • %s • TX %s (%s)\n"
             "📱 <b>عملاء الوايفاي:</b> %d جهاز\n"
             "🌐 <b>الإنترنت WAN:</b> %s %s\n\n"
             "👇 تحكم بكل إعدادات الوايفاي مباشرة:",
             esc_ssid, esc_key, wi.disabled ? "🔴 متوقف" : "🟢 نشط",
             wi.channel, wi.htmode, wi.txpower[0] ? wi.txpower : "تلقائي", wi.country,
             wf_cnt, wi.wan_proto, wi.wan_ip);

    const char *next_ht = (strcmp(wi.htmode, "HT40") == 0) ? "HT20 (استقرار أعلى)" : "HT40 (سرعة أعلى)";
    snprintf(kb, 1024,
             "{\"inline_keyboard\":["
             "[{\"text\":\"CH 1\",\"callback_data\":\"wch:1\"},"
             "{\"text\":\"CH 6\",\"callback_data\":\"wch:6\"},"
             "{\"text\":\"CH 11\",\"callback_data\":\"wch:11\"},"
             "{\"text\":\"CH 13\",\"callback_data\":\"wch:13\"},"
             "{\"text\":\"تلقائي\",\"callback_data\":\"wch:auto\"}],"
             "[{\"text\":\"✏️ تغيير اسم الشبكة\",\"callback_data\":\"pwssid\"},"
             "{\"text\":\"🔑 تغيير كلمة السر\",\"callback_data\":\"pwkey\"}],"
             "[{\"text\":\"%s\",\"callback_data\":\"%s\"},"
             "{\"text\":\"📶 %s\",\"callback_data\":\"wht_tog\"}],"
             "[{\"text\":\"📡 طاقة البث TX\",\"callback_data\":\"wtx_menu\"},"
             "{\"text\":\"🔄 إعادة تشغيل الوايفاي\",\"callback_data\":\"wreload\"}],"
             "[{\"text\":\"%s\",\"callback_data\":\"wtog_ask\"},"
             "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]"
             "]}",
             reveal_key ? "🙈 إخفاء الباسورد" : "👁️ كشف الباسورد",
             reveal_key ? "adm_net" : "adm_net:key",
             next_ht,
             wi.disabled ? "🟢 تشغيل الوايفاي" : "🔴 إيقاف الوايفاي");

    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
    free(msg);
    free(kb);
}

static void send_admin_tx_menu(const char *chat_id, int64_t edit_msg_id) {
    const char *kb =
        "{\"inline_keyboard\":["
        "[{\"text\":\"⚡ أقصى طاقة (تلقائي)\",\"callback_data\":\"wtx:auto\"},"
        "{\"text\":\"🔋 17 dBm (متوسط)\",\"callback_data\":\"wtx:17\"}],"
        "[{\"text\":\"🔋 14 dBm (منخفض)\",\"callback_data\":\"wtx:14\"},"
        "{\"text\":\"🔋 10 dBm (مدى قريب)\",\"callback_data\":\"wtx:10\"}],"
        "[{\"text\":\"🔙 رجوع للوايفاي\",\"callback_data\":\"adm_net\"},"
        "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]"
        "]}";
    tg_edit_or_send(chat_id, edit_msg_id, "📡 <b>اختر طاقة بث الوايفاي (TX Power):</b>", kb);
}

static void send_admin_reboot_menu(const char *chat_id, int64_t edit_msg_id) {
    char *msg = calloc(1, 960);
    char *kb = calloc(1, 1100);
    if (!msg || !kb) { free(msg); free(kb); return; }

    pthread_mutex_lock(&g_lock);
    bool en = g_config.auto_reboot_enabled;
    uint8_t hr = g_config.auto_reboot_hour, mn = g_config.auto_reboot_min;
    int8_t tz = g_config.auto_reboot_tz;
    int32_t cd = g_reboot_countdown;
    pthread_mutex_unlock(&g_lock);

    char sched[128];
    if (en) {
        int h12 = hr % 12; if (h12 == 0) h12 = 12;
        snprintf(sched, sizeof(sched), "🟢 يومياً الساعة <b>%d:%02u %s</b> (UTC%+d)",
                 h12, (unsigned)mn, (hr < 12) ? "ص" : "م", (int)tz);
    } else {
        snprintf(sched, sizeof(sched), "⚪ غير مفعل حالياً");
    }

    char cd_str[96] = "";
    if (cd > 0) snprintf(cd_str, sizeof(cd_str), "⏳ <b>مؤقت نشط:</b> خلال %d دقيقة (%d ثانية)\n", (cd + 59) / 60, cd);

    snprintf(msg, 960,
             "🔄 <b>إدارة إعادة التشغيل والمؤقتات:</b>\n\n"
             "⏰ <b>الجدول اليومي:</b> %s\n%s\n"
             "👇 اختر إعادة تشغيل فورية، مؤقت تنازلي، أو موعد يومي:",
             sched, cd_str);

    snprintf(kb, 1100,
             "{\"inline_keyboard\":["
             "[{\"text\":\"🔴 إعادة تشغيل الراوتر فوراً\",\"callback_data\":\"rb_ask\"}],"
             "[{\"text\":\"⏳ بعد 15د\",\"callback_data\":\"rbcd:900\"},"
             "{\"text\":\"⏳ بعد 30د\",\"callback_data\":\"rbcd:1800\"},"
             "{\"text\":\"⏳ بعد 60د\",\"callback_data\":\"rbcd:3600\"},"
             "{\"text\":\"❌ إلغاء المؤقت\",\"callback_data\":\"rbcd:-1\"}],"
             "[{\"text\":\"🕐 1:00 ص\",\"callback_data\":\"rbs:1\"},"
             "{\"text\":\"🕓 4:00 ص\",\"callback_data\":\"rbs:4\"},"
             "{\"text\":\"🕕 6:00 ص\",\"callback_data\":\"rbs:6\"},"
             "{\"text\":\"🕛 12:00 ص\",\"callback_data\":\"rbs:0\"}],"
             "[{\"text\":\"✏️ وقت يومي مخصص\",\"callback_data\":\"prbtime\"},"
             "{\"text\":\"⏸️ إيقاف اليومي\",\"callback_data\":\"rbs:off\"}],"
             "[{\"text\":\"🔄 تحديث\",\"callback_data\":\"adm_reboot\"},"
             "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]"
             "]}");

    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
    free(msg);
    free(kb);
}

static void send_admin_ota_menu(const char *chat_id, int64_t edit_msg_id) {
    char *msg = calloc(1, 1400);
    char *kb = calloc(1, 760);
    if (!msg || !kb) { free(msg); free(kb); return; }

    char r_ver[32] = {0}, r_url[256] = {0}, r_log[256] = {0};
    bool newer = false;
    bool ok = telegram_check_ota_remote(r_ver, sizeof(r_ver), r_url, sizeof(r_url), r_log, sizeof(r_log), &newer);

    pthread_mutex_lock(&g_lock);
    bool auto_chk = g_config.ota_auto_check_enabled;
    char cur_fw[24], ver_url[192];
    snprintf(cur_fw, sizeof(cur_fw), "%s", g_config.fw_version);
    snprintf(ver_url, sizeof(ver_url), "%s", g_config.ota_version_url);
    pthread_mutex_unlock(&g_lock);

    const char *auto_str = auto_chk ? "🟢 مفعل (فحص كل 6 ساعات)" : "⚪ متوقف (يدوي فقط)";
    const char *toggle_btn = auto_chk ? "⏸️ إيقاف الفحص التلقائي" : "▶️ تفعيل الفحص التلقائي";

    if (!ver_url[0]) {
        snprintf(msg, 1400,
                 "🚀 <b>إدارة التحديث السحابي (OTA):</b>\n\n"
                 "⚠️ لم يتم ضبط رابط <code>version.json</code> بعد في لوحة الويب.\n"
                 "🔖 <b>الإصدار الحالي:</b> <code>v%s</code>\n"
                 "⚙️ <b>الفحص التلقائي:</b> %s",
                 cur_fw, auto_str);
        snprintf(kb, 760,
                 "{\"inline_keyboard\":[[{\"text\":\"%s\",\"callback_data\":\"ota_toggle\"},"
                 "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}", toggle_btn);
    } else if (ok && newer) {
        char esc_log[320];
        html_escape(r_log[0] ? r_log : "تحسينات عامة في الأداء والاستقرار", esc_log, sizeof(esc_log));
        snprintf(msg, 1400,
                 "🚀 <b>إدارة التحديث السحابي (OTA):</b>\n\n"
                 "🎉 <b>يوجد تحديث جديد متاح!</b>\n"
                 "🔖 <b>الحالي:</b> <code>v%s</code> ⬅️ <b>الجديد:</b> <code>v%s</code>\n"
                 "📝 <b>التغييرات:</b> %s\n"
                 "⚙️ <b>الفحص التلقائي:</b> %s\n\n"
                 "⚠️ <i>لتأمين فلاش WR740N، يبدأ التثبيت فقط بعد موافقتك:</i>",
                 cur_fw, r_ver, esc_log, auto_str);
        snprintf(kb, 760,
                 "{\"inline_keyboard\":["
                 "[{\"text\":\"⚡ تثبيت التحديث الآن\",\"callback_data\":\"ota_ask\"}],"
                 "[{\"text\":\"%s\",\"callback_data\":\"ota_toggle\"},"
                 "{\"text\":\"🔍 إعادة الفحص\",\"callback_data\":\"adm_ota\"},"
                 "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}",
                 toggle_btn);
    } else if (ok) {
        snprintf(msg, 1400,
                 "🚀 <b>إدارة التحديث السحابي (OTA):</b>\n\n"
                 "✅ <b>راوترك يعمل بأحدث إصدار متاح!</b>\n"
                 "🔖 <b>الإصدار الحالي:</b> <code>v%s</code>\n"
                 "☁️ <b>أحدث إصدار بالسحابة:</b> <code>%s</code>\n"
                 "⚙️ <b>الفحص التلقائي:</b> %s",
                 cur_fw, r_ver[0] ? r_ver : cur_fw, auto_str);
        snprintf(kb, 760,
                 "{\"inline_keyboard\":["
                 "[{\"text\":\"🔍 فحص الآن\",\"callback_data\":\"adm_ota\"},"
                 "{\"text\":\"%s\",\"callback_data\":\"ota_toggle\"}],"
                 "[{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}",
                 toggle_btn);
    } else {
        snprintf(msg, 1400,
                 "🚀 <b>إدارة التحديث السحابي (OTA):</b>\n\n"
                 "⚠️ تعذر الاتصال بملف <code>version.json</code> حالياً.\n"
                 "🔖 <b>الإصدار الحالي:</b> <code>v%s</code>\n"
                 "⚙️ <b>الفحص التلقائي:</b> %s",
                 cur_fw, auto_str);
        snprintf(kb, 760,
                 "{\"inline_keyboard\":["
                 "[{\"text\":\"🔄 إعادة المحاولة\",\"callback_data\":\"adm_ota\"},"
                 "{\"text\":\"%s\",\"callback_data\":\"ota_toggle\"}],"
                 "[{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}",
                 toggle_btn);
    }

    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
    free(msg);
    free(kb);
}

/* ==================== NORMAL USER PRIVATE VIEW ==================== */

static void send_normal_user_report(const char *chat_id) {
    rmeter_device_t own[8];
    int n = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_device_count && n < 8; i++) {
        if (strcmp(g_devices[i].tg_chat_id, chat_id) == 0) {
            own[n++] = g_devices[i];
        }
    }
    pthread_mutex_unlock(&g_lock);

    if (n == 0) {
        char msg[320];
        snprintf(msg, sizeof(msg),
                 "👋 مرحباً بك!\nChat ID الخاص بك: <code>%s</code>\n\n"
                 "⛔ لم يربط المشرف جهازك بهذا المعرف بعد.\nأرسل هذا الرقم للمشرف ليتم ربط جهازك وتلقي إشعارات الباقة.",
                 chat_id);
        telegram_send_message(chat_id, msg, TG_USER_KEYBOARD);
        return;
    }

    char *msg = calloc(1, 2048);
    if (!msg) return;
    size_t pos = snprintf(msg, 2048, "📱 <b>بيانات أجهزتك المربوطة (%d):</b>\n\n", n);
    time_t now = time(NULL);

    for (int i = 0; i < n && pos + 280 < 2000; i++) {
        rmeter_device_t *d = &own[i];
        uint64_t used = meter_scaled_bytes(d->up_bytes + d->down_bytes);
        uint64_t rem = (d->quota_bytes > used) ? (d->quota_bytes - used) : 0;
        double pct = (d->quota_bytes > 0) ? (((double)used * 100.0) / (double)d->quota_bytes) : 0.0;
        if (pct > 100.0) pct = 100.0;

        char nm[64], ustr[32], qstr[32], rstr[32], dn[24], up[24], dur[32], spd_mode[48];
        html_escape(d->name[0] ? d->name : d->ip, nm, sizeof(nm));
        fmt_bytes(used, ustr, sizeof(ustr));
        fmt_bytes(d->quota_bytes, qstr, sizeof(qstr));
        fmt_bytes(rem, rstr, sizeof(rstr));
        fmt_bps(d->cur_down_bps, dn, sizeof(dn));
        fmt_bps(d->cur_up_bps, up, sizeof(up));
        fmt_dur((d->online && d->connected_at > 0 && now >= d->connected_at) ? (now - d->connected_at) : 0, dur, sizeof(dur));

        if (d->speed_unlocked) snprintf(spd_mode, sizeof(spd_mode), "🚀 مفتوحة");
        else if (d->cap_down_kbps > 0 || d->cap_up_kbps > 0) snprintf(spd_mode, sizeof(spd_mode), "🔒 %.1f/%.1f Mbps", d->cap_down_kbps / 1000.0, d->cap_up_kbps / 1000.0);
        else snprintf(spd_mode, sizeof(spd_mode), "بلا تحديد");

        pos += snprintf(msg + pos, 2048 - pos,
                        "🔹 <b>%s</b> (<code>%s</code>)\n"
                        "   📡 الحالة: %s (%s)%s\n"
                        "   ⚡ السرعة: ⬇️ <b>%s</b> | ⬆️ <b>%s</b>\n"
                        "   🎚️ الحد: %s\n"
                        "   📊 الاستهلاك: <b>%s</b>",
                        nm, d->ip[0] ? d->ip : d->mac,
                        d->blocked ? "⛔ محظور" : (d->online ? "🟢 متصل" : "⚪ غير متصل"),
                        dur, d->gaming_mode ? " 🎮" : "",
                        dn, up, spd_mode, ustr);
        if (d->quota_bytes > 0) {
            pos += snprintf(msg + pos, 2048 - pos, " / <b>%s</b> (%.0f%%)\n   💾 المتبقي: <b>%s</b>\n\n",
                            qstr, pct, rstr);
        } else {
            pos += snprintf(msg + pos, 2048 - pos, " (باقة مفتوحة ♾️)\n\n");
        }
    }

    telegram_send_message(chat_id, msg, TG_USER_KEYBOARD);
    free(msg);
}

/* ==================== PENDING INPUT & COMMAND ROUTER ==================== */

static bool is_nav_or_cmd(const char *text, const char *cmd) {
    if (!text || text[0] == '/') return true;
    (void)cmd;
    if (strstr(text, "القائمة الرئيسية") || strstr(text, "استهلاك الباقة") ||
        strstr(text, "الأجهزة المتصلة") || strstr(text, "فحص السرعة") ||
        strstr(text, "حالة الراوتر") || strstr(text, "الوايفاي والشبكة") ||
        strstr(text, "إعادة التشغيل") || strstr(text, "فحص التحديثات") ||
        strstr(text, "مساعدة")) {
        return true;
    }
    return false;
}

static void handle_pending_input(const char *chat_id, pend_kind_t kind, const char *mac, const char *raw) {
    char val[128];
    snprintf(val, sizeof(val), "%s", raw);
    char *s = val;
    while (*s && isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';

    if (kind == PEND_WIFI_SSID) {
        if (!len || len > 32 || !safe_tg_uci_str(s)) {
            telegram_send_message(chat_id, "⚠️ اسم الشبكة غير صالح (1-32 حرف بدون رموز خاصة).", NULL);
            return;
        }
        char cmd[192];
        snprintf(cmd, sizeof(cmd),
                 "uci set wireless.default_radio0.ssid='%s' && uci commit wireless && (sleep 1; wifi reload) >/dev/null 2>&1 &",
                 s);
        system(cmd);
        telegram_send_message(chat_id, "✅ تم تحديث اسم شبكة الوايفاي وتطبيقه بنجاح.", TG_ADMIN_KEYBOARD);
        send_admin_wifi_menu(chat_id, 0, false);
    } else if (kind == PEND_WIFI_KEY) {
        if (len < 8 || len > 63 || !safe_tg_uci_str(s)) {
            telegram_send_message(chat_id, "⚠️ كلمة سر الوايفاي يجب أن تكون بين 8 و 63 حرفاً وبدون علامات اقتباس.", NULL);
            return;
        }
        char cmd[220];
        snprintf(cmd, sizeof(cmd),
                 "uci set wireless.default_radio0.encryption='psk2' && "
                 "uci set wireless.default_radio0.key='%s' && uci commit wireless && (sleep 1; wifi reload) >/dev/null 2>&1 &",
                 s);
        system(cmd);
        telegram_send_message(chat_id, "✅ تم تغيير كلمة سر الوايفاي وتفعيلها بنجاح.", TG_ADMIN_KEYBOARD);
        send_admin_wifi_menu(chat_id, 0, false);
    } else if (kind == PEND_DEV_NAME) {
        if (!len || !safe_tg_uci_str(s)) {
            telegram_send_message(chat_id, "⚠️ الاسم غير صالح.", NULL);
            return;
        }
        meter_set_device_name(mac, s);
        meter_save_all();
        meter_write_ram_json();
        send_admin_device_control(chat_id, 0, mac);
    } else if (kind == PEND_DEV_IP) {
        const char *bip = (strcmp(s, "0") == 0 || strcmp(s, "off") == 0) ? "" : s;
        if (bip[0] && (!safe_tg_uci_str(bip) || strlen(bip) < 7)) {
            telegram_send_message(chat_id, "⚠️ صيغة IP غير صحيحة (مثال: <code>192.168.1.50</code> أو <code>0</code> للإلغاء).", NULL);
            return;
        }
        char dname[RMETER_MAX_NAME] = {0};
        pthread_mutex_lock(&g_lock);
        int idx = meter_find_by_mac(mac);
        if (idx >= 0) snprintf(dname, sizeof(dname), "%s", g_devices[idx].name);
        pthread_mutex_unlock(&g_lock);
        meter_set_device_binding(mac, bip);
        sync_static_lease_tg(mac, bip, dname);
        meter_save_all();
        meter_write_ram_json();
        send_admin_device_control(chat_id, 0, mac);
    } else if (kind == PEND_DEV_CHAT) {
        const char *cid = (strcmp(s, "0") == 0 || strcmp(s, "off") == 0) ? "" : s;
        meter_set_device_telegram(mac, cid);
        meter_save_all();
        meter_write_ram_json();
        send_admin_device_control(chat_id, 0, mac);
    } else if (kind == PEND_DEV_SPD) {
        double dl_m = 0, ul_m = -1;
        int n = sscanf(s, "%lf %lf", &dl_m, &ul_m);
        if (n < 1 || dl_m < 0) {
            telegram_send_message(chat_id, "⚠️ أرسل رقمي التحميل والرفع بالميجابت مثل: <code>5 2</code> أو <code>0</code>.", NULL);
            return;
        }
        if (ul_m < 0) ul_m = dl_m;
        meter_set_device_speed_cap(mac, (uint32_t)(ul_m * 1000.0), (uint32_t)(dl_m * 1000.0));
        meter_save_all();
        meter_write_ram_json();
        send_admin_device_control(chat_id, 0, mac);
    } else if (kind == PEND_MAIN_QUOTA) {
        double gb = atof(s);
        if (gb < 0) gb = 0;
        uint64_t unit = (g_config.gb_standard == 1000) ? 1000000000ULL : 1073741824ULL;
        pthread_mutex_lock(&g_lock);
        g_config.main_quota_bytes = (uint64_t)(gb * (double)unit);
        g_config.main_alert_flags = 0;
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        send_admin_quota_menu(chat_id, 0);
    } else if (kind == PEND_WAN_SPD) {
        double dl_m = 0, ul_m = -1;
        int n = sscanf(s, "%lf %lf", &dl_m, &ul_m);
        if (n < 1 || dl_m < 0) {
            telegram_send_message(chat_id, "⚠️ أرسل السرعة مثل: <code>30 5</code> أو <code>0 0</code>.", NULL);
            return;
        }
        if (ul_m < 0) ul_m = dl_m / 2.0;
        pthread_mutex_lock(&g_lock);
        g_config.wan_down_kbps = (uint32_t)(dl_m * 1000.0);
        g_config.wan_up_kbps = (uint32_t)(ul_m * 1000.0);
        g_tc_dirty = true;
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        send_admin_quota_menu(chat_id, 0);
    } else if (kind == PEND_REBOOT_TIME) {
        if (strcmp(s, "off") == 0 || strcmp(s, "00") == 0) {
            pthread_mutex_lock(&g_lock);
            g_config.auto_reboot_enabled = false;
            pthread_mutex_unlock(&g_lock);
            meter_save_all();
            meter_write_ram_json();
            send_admin_reboot_menu(chat_id, 0);
            return;
        }
        int hr = -1, mn = 0;
        if (sscanf(s, "%d:%d", &hr, &mn) >= 1 && hr >= 0 && hr < 24 && mn >= 0 && mn < 60) {
            pthread_mutex_lock(&g_lock);
            g_config.auto_reboot_enabled = true;
            g_config.auto_reboot_hour = (uint8_t)hr;
            g_config.auto_reboot_min = (uint8_t)mn;
            pthread_mutex_unlock(&g_lock);
            meter_save_all();
            meter_write_ram_json();
            send_admin_reboot_menu(chat_id, 0);
        } else {
            telegram_send_message(chat_id, "⚠️ صيغة غير صحيحة! اكتب الساعة مثل <code>04:30</code> أو <code>off</code>.", NULL);
        }
    }
}

static void send_prayer_info(const char *chat_id, int64_t edit_msg_id, bool is_admin, bool show_all) {
    char msg[1024] = {0};
    char kb[512] = {0};
    char np_name[32] = {0}, np_time[12] = {0};
    int rem = -1;
    bool ok = fazakkir_get_next_prayer(time(NULL), np_name, sizeof(np_name), np_time, sizeof(np_time), &rem);

    char rem_str[64] = {0};
    if (ok && rem >= 0) {
        int hrs = rem / 60, mins = rem % 60;
        if (hrs > 0 && mins > 0) snprintf(rem_str, sizeof(rem_str), "%d ساعة و %d دقيقة", hrs, mins);
        else if (hrs > 0) snprintf(rem_str, sizeof(rem_str), "%d ساعة", hrs);
        else snprintf(rem_str, sizeof(rem_str), "%d دقيقة", mins);
    }

    if (show_all) {
        fazakkir_format_today_prayers(msg, sizeof(msg));
        if (ok) {
            size_t len = strlen(msg);
            snprintf(msg + len, sizeof(msg) - len,
                     "\n🕌 <b>الصلاة القادمة:</b> صلاة <b>%s</b> (%s)\n⏳ المتبقي: <b>%s</b>",
                     np_name, np_time, rem_str);
        }
        snprintf(kb, sizeof(kb),
                 "{\"inline_keyboard\":[[{\"text\":\"🕌 الصلاة القادمة\",\"callback_data\":\"prayer_next\"}%s]]}",
                 is_admin ? ",{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}" : "");
    } else {
        if (ok) {
            snprintf(msg, sizeof(msg),
                     "🕌 <b>الصلاة القادمة: صلاة %s</b>\n"
                     "⏰ الموعد: <code>%s</code> (%s)\n"
                     "⏳ المتبقي عليها: <b>%s</b>",
                     np_name, np_time,
                     g_fazakkir.city[0] ? g_fazakkir.city : "Cairo",
                     rem_str);
        } else {
            snprintf(msg, sizeof(msg),
                     "⚠️ تعذر تحديد الصلاة القادمة حالياً.\n"
                     "تأكد من تزامن ساعة الراوتر وتحديث مواقيت الصلاة من تبويب <b>فذكر</b>.");
        }
        snprintf(kb, sizeof(kb),
                 "{\"inline_keyboard\":["
                 "[{\"text\":\"📅 مواقيت اليوم كلها\",\"callback_data\":\"prayer_all\"},"
                 "{\"text\":\"🔄 تحديث\",\"callback_data\":\"prayer_next\"}]%s]}",
                 is_admin ? ",[{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]" : "");
    }
    tg_edit_or_send(chat_id, edit_msg_id, msg, kb);
}

static void handle_command(const char *chat_id, const char *text) {
    bool is_adm = tg_is_admin(chat_id);
    char cmd[64] = {0}, arg1[64] = {0}, arg2[64] = {0}, arg3[64] = {0};
    sscanf(text, "%63s %63s %63s %63s", cmd, arg1, arg2, arg3);

    char *at = strchr(cmd, '@');
    if (at) *at = '\0';

    /* Normal non-admin user view (strictly limited to own linked device(s)) */
    if (!is_adm) {
        if (strstr(text, "استهلاك") || strstr(text, "سرع") || strcmp(cmd, "/quota") == 0 || strcmp(cmd, "/speed") == 0) {
            send_normal_user_report(chat_id);
        } else if (strstr(text, "الصلاة") || strstr(text, "صلاه") || strcmp(cmd, "/prayer") == 0) {
            send_prayer_info(chat_id, 0, false, false);
        } else if (strcmp(cmd, "/id") == 0) {
            char msg[192];
            snprintf(msg, sizeof(msg), "🆔 معرف التليجرام الخاص بك:\n<code>%s</code>", chat_id);
            telegram_send_message(chat_id, msg, TG_USER_KEYBOARD);
        } else {
            char msg[384];
            snprintf(msg, sizeof(msg),
                     "👋 <b>أهلاً بك في متابعة الباقة</b>\n"
                     "🆔 معرفك: <code>%s</code>\n\n"
                     "استخدم الأزرار بالأسفل لعرض استهلاك وسرعة أجهزتك المربوطة، وستصلك تنبيهات تلقائية عند الاقتراب من حد الباقة.",
                     chat_id);
            telegram_send_message(chat_id, msg, TG_USER_KEYBOARD);
        }
        return;
    }

    if (!is_nav_or_cmd(text, cmd)) {
        pend_kind_t pkind = PEND_NONE;
        char pmac[24] = {0};
        if (pend_pop(chat_id, &pkind, pmac, sizeof(pmac))) {
            handle_pending_input(chat_id, pkind, pmac, text);
            return;
        }
    } else {
        pend_clear(chat_id);
    }

    if (strcmp(cmd, "/start") == 0 || strcmp(cmd, "/menu") == 0 || strstr(text, "القائمة الرئيسية")) {
        telegram_send_message(chat_id, "🎛️ <b>تم تفعيل لوحة التحكم الكاملة بالراوتر</b>", TG_ADMIN_KEYBOARD);
        send_admin_home_menu(chat_id, 0);
        return;
    }

    if (strcmp(cmd, "/help") == 0 || strstr(text, "مساعدة")) {
        char *msg = calloc(1, 1400);
        if (msg) {
            snprintf(msg, 1400,
                     "🤖 <b>مساعدة وأوامر المشرف السريعة:</b>\n\n"
                     "اضغط 🏠 <b>القائمة الرئيسية</b> أو أي زر بالأسفل للدخول للقوائم التفاعلية.\n\n"
                     "💡 <b>أوامر سلاش المباشرة:</b>\n"
                     "• <code>/menu</code> القائمة الرئيسية التفاعلية\n"
                     "• <code>/add_quota IP 5</code> إضافة 5 جيجا\n"
                     "• <code>/limit IP 5 2</code> تحديد السرعة\n"
                     "• <code>/vip IP</code> تبديل وضع VIP\n"
                     "• <code>/block IP</code> / <code>/unblock IP</code>\n"
                     "• <code>/reboot_time 04:30</code> / <code>off</code>");
            telegram_send_message(chat_id, msg, TG_ADMIN_KEYBOARD);
            free(msg);
        }
        send_admin_home_menu(chat_id, 0);
        return;
    }

    if (strcmp(cmd, "/quota") == 0 || strstr(text, "استهلاك الباقة") || strcmp(cmd, "استهلاك") == 0) {
        send_admin_quota_menu(chat_id, 0);
    } else if (strcmp(cmd, "/devices") == 0 || strstr(text, "الأجهزة المتصلة") || strcmp(cmd, "اجهزة") == 0) {
        send_admin_devices_menu(chat_id, 0, false);
    } else if (strcmp(cmd, "/speed") == 0 || strstr(text, "فحص السرعة") || strcmp(cmd, "سرعة") == 0) {
        send_admin_speed_report(chat_id, 0);
    } else if (strcmp(cmd, "/status") == 0 || strstr(text, "حالة الراوتر") || strcmp(cmd, "حالة") == 0) {
        send_admin_status_report(chat_id, 0, NULL);
    } else if (strcmp(cmd, "/wifi") == 0 || strstr(text, "الوايفاي والشبكة")) {
        send_admin_wifi_menu(chat_id, 0, false);
    } else if (strcmp(cmd, "/reboot") == 0 || strstr(text, "إعادة التشغيل") || strcmp(cmd, "ريستارت") == 0) {
        send_admin_reboot_menu(chat_id, 0);
    } else if (strcmp(cmd, "/ota") == 0 || strcmp(cmd, "/update") == 0 || strstr(text, "فحص التحديثات")) {
        send_admin_ota_menu(chat_id, 0);
    } else if (strcmp(cmd, "/prayer") == 0 || strstr(text, "الصلاة") || strstr(text, "صلاه")) {
        send_prayer_info(chat_id, 0, true, false);
    } else if (strcmp(cmd, "/reboot_time") == 0) {
        handle_pending_input(chat_id, PEND_REBOOT_TIME, "", arg1);
    } else if (strcmp(cmd, "/block") == 0 || strcmp(cmd, "حظر") == 0) {
        if (arg1[0] && meter_set_device_blocked(arg1, true, false)) {
            meter_save_all();
            meter_write_ram_json();
            telegram_send_message(chat_id, "⛔ تم حظر الجهاز بنجاح.", TG_ADMIN_KEYBOARD);
        } else {
            telegram_send_message(chat_id, "الاستخدام: <code>/block 192.168.1.50</code>", TG_ADMIN_KEYBOARD);
        }
    } else if (strcmp(cmd, "/unblock") == 0 || strcmp(cmd, "فك_حظر") == 0) {
        if (arg1[0] && meter_set_device_blocked(arg1, false, false)) {
            meter_save_all();
            meter_write_ram_json();
            telegram_send_message(chat_id, "🔓 تم فك الحظر عن الجهاز.", TG_ADMIN_KEYBOARD);
        } else {
            telegram_send_message(chat_id, "الاستخدام: <code>/unblock 192.168.1.50</code>", TG_ADMIN_KEYBOARD);
        }
    } else if (strcmp(cmd, "/add_quota") == 0 || strcmp(cmd, "/add") == 0 || strcmp(cmd, "شحن") == 0) {
        if (arg1[0] && arg2[0]) {
            double gb = atof(arg2);
            uint64_t unit = (g_config.gb_standard == 1000) ? 1000000000ULL : 1073741824ULL;
            if (meter_add_device_quota(arg1, (int64_t)(gb * (double)unit))) {
                meter_save_all();
                meter_write_ram_json();
                telegram_send_message(chat_id, "✅ تم تعديل حصة الجيجات بنجاح.", TG_ADMIN_KEYBOARD);
                return;
            }
        }
        telegram_send_message(chat_id, "الاستخدام: <code>/add_quota 192.168.1.50 5</code>", TG_ADMIN_KEYBOARD);
    } else if (strcmp(cmd, "/limit") == 0) {
        if (arg1[0] && arg2[0]) {
            uint32_t dl = (uint32_t)(atof(arg2) * 1000.0);
            uint32_t ul = arg3[0] ? (uint32_t)(atof(arg3) * 1000.0) : dl;
            if (meter_set_device_speed_cap(arg1, ul, dl)) {
                meter_save_all();
                meter_write_ram_json();
                telegram_send_message(chat_id, "✅ تم تحديد سرعة الجهاز وتطبيقها بنجاح.", TG_ADMIN_KEYBOARD);
                return;
            }
        }
        telegram_send_message(chat_id, "الاستخدام: <code>/limit 192.168.1.50 5 2</code> (0 لإلغاء التحديد)", TG_ADMIN_KEYBOARD);
    } else if (strcmp(cmd, "/vip") == 0) {
        pthread_mutex_lock(&g_lock);
        int idx = meter_find_by_mac_or_ip(arg1);
        bool cur = (idx >= 0) ? g_devices[idx].gaming_mode : false;
        pthread_mutex_unlock(&g_lock);
        if (idx >= 0 && meter_set_device_gaming(arg1, !cur)) {
            meter_save_all();
            meter_write_ram_json();
            telegram_send_message(chat_id, !cur ? "🎮 تم تفعيل VIP للجهاز." : "تم إلغاء VIP.", TG_ADMIN_KEYBOARD);
        } else {
            telegram_send_message(chat_id, "الاستخدام: <code>/vip 192.168.1.50</code>", TG_ADMIN_KEYBOARD);
        }
    } else {
        send_admin_home_menu(chat_id, 0);
    }
}

/* ==================== CALLBACK HANDLER ==================== */

static void send_prompt_msg(const char *chat_id, int64_t edit_msg_id, const char *text) {
    tg_edit_or_send(chat_id, edit_msg_id, text,
                    "{\"inline_keyboard\":[[{\"text\":\"❌ إلغاء العملية\",\"callback_data\":\"cancel_pend\"},"
                    "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}");
}

static bool handle_callback_admin(const char *cb_id, const char *chat_id, int64_t msg_id, const char *data) {
    if (strcmp(data, "cancel_pend") == 0) {
        pend_clear(chat_id);
        send_admin_home_menu(chat_id, msg_id);
    } else if (strcmp(data, "adm_home") == 0) {
        pend_clear(chat_id);
        send_admin_home_menu(chat_id, msg_id);
    } else if (strncmp(data, "adm_devs:", 9) == 0) {
        pend_clear(chat_id);
        bool show_all = (strncmp(data + 9, "all", 3) == 0);
        int page = 0;
        const char *pcol = strchr(data + 9, ':');
        if (pcol) page = atoi(pcol + 1);
        send_admin_devices_menu_page(chat_id, msg_id, show_all, page);
    } else if (strcmp(data, "adm_quota") == 0) {
        send_admin_quota_menu(chat_id, msg_id);
    } else if (strcmp(data, "adm_qset") == 0) {
        send_admin_qset_menu(chat_id, msg_id);
    } else if (strcmp(data, "adm_wan") == 0) {
        send_admin_wan_menu(chat_id, msg_id);
    } else if (strcmp(data, "adm_scale") == 0) {
        send_admin_scale_menu(chat_id, msg_id);
    } else if (strcmp(data, "adm_speed") == 0) {
        send_admin_speed_report(chat_id, msg_id);
    } else if (strcmp(data, "adm_status") == 0) {
        send_admin_status_report(chat_id, msg_id, NULL);
    } else if (strcmp(data, "adm_net") == 0) {
        send_admin_wifi_menu(chat_id, msg_id, false);
    } else if (strcmp(data, "adm_net:key") == 0) {
        send_admin_wifi_menu(chat_id, msg_id, true);
    } else if (strcmp(data, "wtx_menu") == 0) {
        send_admin_tx_menu(chat_id, msg_id);
    } else if (strcmp(data, "adm_reboot") == 0) {
        send_admin_reboot_menu(chat_id, msg_id);
    } else if (strcmp(data, "adm_ota") == 0) {
        send_admin_ota_menu(chat_id, msg_id);
    } else if (strcmp(data, "adm_prayer") == 0) {
        send_prayer_info(chat_id, msg_id, true, false);
    } else if (strncmp(data, "mdev:", 5) == 0 || strncmp(data, "dev:", 4) == 0) {
        pend_clear(chat_id);
        const char *mac = (data[0] == 'm') ? (data + 5) : (data + 4);
        send_admin_device_control(chat_id, msg_id, mac);
    } else if (strncmp(data, "spdmenu:", 8) == 0) {
        send_admin_speed_submenu(chat_id, msg_id, data + 8);
    } else if (strncmp(data, "tgp:", 4) == 0) {
        send_device_tg_picker(chat_id, msg_id, data + 4);
    } else if (strncmp(data, "tgset:", 6) == 0) {
        char mac[24] = {0}, cid[32] = {0};
        const char *tail = NULL;
        if (parse_mac_tail(data + 6, 1, mac, sizeof(mac), &tail) && sscanf(tail, "%31s", cid) == 1) {
            meter_set_device_telegram(mac, cid);
            meter_write_ram_json();
            send_admin_device_control(chat_id, msg_id, mac);
        }
    } else if (strncmp(data, "tgclr:", 6) == 0) {
        const char *mac = data + 6;
        meter_set_device_telegram(mac, "");
        meter_save_all();
        meter_write_ram_json();
        send_admin_device_control(chat_id, msg_id, mac);
    } else if (strncmp(data, "pname:", 6) == 0) {
        pend_set(chat_id, PEND_DEV_NAME, data + 6);
        send_prompt_msg(chat_id, msg_id, "✏️ أرسل الآن <b>الاسم الجديد</b> للجهاز:");
    } else if (strncmp(data, "pip:", 4) == 0) {
        pend_set(chat_id, PEND_DEV_IP, data + 4);
        send_prompt_msg(chat_id, msg_id, "📌 أرسل الآن <b>الـ IP الثابت</b> للجهاز (مثال: <code>192.168.1.50</code> أو <code>0</code> لإلغاء التثبيت):");
    } else if (strncmp(data, "ptg:", 4) == 0) {
        pend_set(chat_id, PEND_DEV_CHAT, data + 4);
        send_prompt_msg(chat_id, msg_id, "👤 أرسل الآن <b>Chat ID</b> المطلوب ربطه بالجهاز (أو <code>0</code> لفك الربط):");
    } else if (strncmp(data, "pspd:", 5) == 0) {
        pend_set(chat_id, PEND_DEV_SPD, data + 5);
        send_prompt_msg(chat_id, msg_id, "🎚️ أرسل الآن السرعة بالميجابت (تحميل رفع، مثال: <code>8 2</code> أو <code>0</code> لإلغاء القيد):");
    } else if (strcmp(data, "pqmain") == 0) {
        pend_set(chat_id, PEND_MAIN_QUOTA, "");
        send_prompt_msg(chat_id, msg_id, "📦 أرسل سعة الباقة الرئيسية بالجيجابايت (مثال: <code>250</code> أو <code>0</code> لمفتوحة):");
    } else if (strcmp(data, "pwan") == 0) {
        pend_set(chat_id, PEND_WAN_SPD, "");
        send_prompt_msg(chat_id, msg_id, "🌐 أرسل سرعة خط الإنترنت بالميجابت (تحميل رفع، مثال: <code>30 5</code> أو <code>0 0</code>):");
    } else if (strcmp(data, "pwssid") == 0) {
        pend_set(chat_id, PEND_WIFI_SSID, "");
        send_prompt_msg(chat_id, msg_id, "📶 أرسل الآن <b>اسم شبكة الوايفاي الجديد (SSID)</b>:");
    } else if (strcmp(data, "pwkey") == 0) {
        pend_set(chat_id, PEND_WIFI_KEY, "");
        send_prompt_msg(chat_id, msg_id, "🔑 أرسل الآن <b>كلمة سر الوايفاي الجديدة</b> (8 أحرف فأكثر):");
    } else if (strcmp(data, "prbtime") == 0) {
        pend_set(chat_id, PEND_REBOOT_TIME, "");
        send_prompt_msg(chat_id, msg_id, "⏰ أرسل موعد إعادة التشغيل اليومي بصيغة <code>HH:MM</code> (مثال: <code>04:30</code>) أو <code>off</code>:");
    } else if (strncmp(data, "setq:", 5) == 0) {
        double gb = atof(data + 5);
        uint64_t unit = (g_config.gb_standard == 1000) ? 1000000000ULL : 1073741824ULL;
        pthread_mutex_lock(&g_lock);
        g_config.main_quota_bytes = (gb > 0) ? (uint64_t)(gb * (double)unit) : 0;
        g_config.main_alert_flags = 0;
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        send_admin_quota_menu(chat_id, msg_id);
    } else if (strncmp(data, "setwan:", 7) == 0) {
        uint32_t dl = 0, ul = 0;
        if (sscanf(data + 7, "%u:%u", &dl, &ul) == 2) {
            pthread_mutex_lock(&g_lock);
            g_config.wan_down_kbps = dl;
            g_config.wan_up_kbps = ul;
            g_tc_dirty = true;
            pthread_mutex_unlock(&g_lock);
            meter_save_all();
            meter_write_ram_json();
            send_admin_quota_menu(chat_id, msg_id);
        }
    } else if (strncmp(data, "sscale:", 7) == 0) {
        int pct = atoi(data + 7);
        if (pct >= 50 && pct <= 200) {
            pthread_mutex_lock(&g_lock);
            g_config.scale_pct = (uint16_t)pct;
            pthread_mutex_unlock(&g_lock);
            meter_save_all();
            meter_write_ram_json();
            send_admin_scale_menu(chat_id, msg_id);
        }
    } else if (strcmp(data, "sgb_tog") == 0) {
        pthread_mutex_lock(&g_lock);
        g_config.gb_standard = (g_config.gb_standard == 1000) ? 1024 : 1000;
        g_flash_dirty = true;
        pthread_mutex_unlock(&g_lock);
        meter_write_ram_json();
        send_admin_scale_menu(chat_id, msg_id);
    } else if (strncmp(data, "setspd:", 7) == 0) {
        char mac[24] = {0};
        uint32_t dl = 0, ul = 0;
        const char *tail = NULL;
        if (parse_mac_tail(data + 7, 2, mac, sizeof(mac), &tail) && sscanf(tail, "%u:%u", &dl, &ul) == 2) {
            meter_set_device_speed_cap(mac, ul, dl);
            meter_write_ram_json();
            send_admin_device_control(chat_id, msg_id, mac);
        }
    } else if (strncmp(data, "blk:", 4) == 0) {
        meter_set_device_blocked(data + 4, true, false);
        meter_write_ram_json();
        send_admin_device_control(chat_id, msg_id, data + 4);
    } else if (strncmp(data, "ublk:", 5) == 0 || strncmp(data, "unblk:", 6) == 0) {
        const char *mac = (data[1] == 'b') ? (data + 5) : (data + 6);
        meter_set_device_blocked(mac, false, false);
        meter_write_ram_json();
        send_admin_device_control(chat_id, msg_id, mac);
    } else if (strncmp(data, "vip:", 4) == 0) {
        const char *mac = data + 4;
        pthread_mutex_lock(&g_lock);
        int idx = meter_find_by_mac(mac);
        bool cur = (idx >= 0) ? g_devices[idx].gaming_mode : false;
        pthread_mutex_unlock(&g_lock);
        if (idx >= 0) {
            meter_set_device_gaming(mac, !cur);
            meter_write_ram_json();
            send_admin_device_control(chat_id, msg_id, mac);
        }
    } else if (strncmp(data, "unlim:", 6) == 0) {
        const char *mac = data + 6;
        pthread_mutex_lock(&g_lock);
        int idx = meter_find_by_mac(mac);
        bool cur = (idx >= 0) ? g_devices[idx].speed_unlocked : false;
        pthread_mutex_unlock(&g_lock);
        if (idx >= 0) {
            meter_set_device_speed_unlocked(mac, !cur);
            meter_write_ram_json();
            send_admin_device_control(chat_id, msg_id, mac);
        }
    } else if (strncmp(data, "rstu:", 5) == 0) {
        const char *mac = data + 5;
        meter_reset_device_usage(mac);
        meter_write_ram_json();
        send_admin_device_control(chat_id, msg_id, mac);
    } else if (strncmp(data, "deld_ask:", 9) == 0) {
        const char *mac = data + 9;
        char kb[512];
        snprintf(kb, sizeof(kb),
                 "{\"inline_keyboard\":[[{\"text\":\"🗑️ نعم، احذف الجهاز\",\"callback_data\":\"deld_yes:%s\"},"
                 "{\"text\":\"❌ إلغاء\",\"callback_data\":\"mdev:%s\"}]]}", mac, mac);
        tg_edit_or_send(chat_id, msg_id, "⚠️ <b>تأكيد حذف الجهاز ومسح إعداداته؟</b>", kb);
    } else if (strncmp(data, "deld_yes:", 9) == 0) {
        meter_delete_device(data + 9);
        meter_write_ram_json();
        send_admin_devices_menu(chat_id, msg_id, false);
    } else if (strncmp(data, "addq:", 5) == 0) {
        char mac[24] = {0};
        int gb = 0;
        const char *tail = NULL;
        if (parse_mac_tail(data + 5, 1, mac, sizeof(mac), &tail) && sscanf(tail, "%d", &gb) == 1) {
            if (gb == 0) {
                meter_set_device_quota(mac, 0);
            } else {
                uint64_t unit = (g_config.gb_standard == 1000) ? 1000000000ULL : 1073741824ULL;
                meter_add_device_quota(mac, (int64_t)gb * (int64_t)unit);
            }
            meter_write_ram_json();
            send_admin_device_control(chat_id, msg_id, mac);
        }
    } else if (strcmp(data, "rstall_ask") == 0) {
        tg_edit_or_send(chat_id, msg_id,
                        "⚠️ <b>تأكيد تصفير استهلاك جميع الأجهزة؟</b>\nسيتم مسح عداد كل الأجهزة والبدء من الصفر.",
                        "{\"inline_keyboard\":[[{\"text\":\"✅ نعم، صفّر الكل\",\"callback_data\":\"rstall_yes\"},"
                        "{\"text\":\"❌ إلغاء\",\"callback_data\":\"adm_quota\"}]]}");
    } else if (strcmp(data, "rstall_yes") == 0) {
        meter_reset_all_usage();
        meter_write_ram_json();
        send_admin_quota_menu(chat_id, msg_id);
    } else if (strncmp(data, "wch:", 4) == 0) {
        const char *ch = data + 4;
        if (strcmp(ch, "1") == 0 || strcmp(ch, "6") == 0 || strcmp(ch, "11") == 0 ||
            strcmp(ch, "13") == 0 || strcmp(ch, "auto") == 0) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                     "uci set wireless.radio0.channel='%s' && uci commit wireless && (sleep 1; wifi reload) >/dev/null 2>&1 &", ch);
            system(cmd);
            send_admin_wifi_menu(chat_id, msg_id, false);
        }
    } else if (strcmp(data, "wht_tog") == 0) {
        wifi_wan_info_t wi;
        read_wifi_wan_snapshot(&wi);
        bool to_ht20 = (strcmp(wi.htmode, "HT40") == 0);
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "uci set wireless.radio0.htmode='%s' && uci set wireless.radio0.noscan='%s' && "
                 "uci commit wireless && (sleep 1; wifi reload) >/dev/null 2>&1 &",
                 to_ht20 ? "HT20" : "HT40", to_ht20 ? "0" : "1");
        system(cmd);
        send_admin_wifi_menu(chat_id, msg_id, false);
    } else if (strncmp(data, "wtx:", 4) == 0) {
        const char *tx = data + 4;
        char cmd[256];
        if (strcmp(tx, "auto") == 0) {
            snprintf(cmd, sizeof(cmd), "uci -q delete wireless.radio0.txpower || true; uci commit wireless && (sleep 1; wifi reload) >/dev/null 2>&1 &");
        } else if (strcmp(tx, "17") == 0 || strcmp(tx, "14") == 0 || strcmp(tx, "10") == 0) {
            snprintf(cmd, sizeof(cmd), "uci set wireless.radio0.txpower='%s' && uci commit wireless && (sleep 1; wifi reload) >/dev/null 2>&1 &", tx);
        } else {
            return false;
        }
        system(cmd);
        send_admin_wifi_menu(chat_id, msg_id, false);
    } else if (strcmp(data, "wreload") == 0) {
        system("(sleep 1; wifi reload) >/dev/null 2>&1 &");
        send_admin_wifi_menu(chat_id, msg_id, false);
    } else if (strcmp(data, "wtog_ask") == 0) {
        tg_edit_or_send(chat_id, msg_id,
                        "⚠️ <b>تأكيد تبديل حالة بث الوايفاي (تشغيل/إيقاف)؟</b>",
                        "{\"inline_keyboard\":[[{\"text\":\"✅ نعم، نفّذ الآن\",\"callback_data\":\"wtog_yes\"},"
                        "{\"text\":\"❌ إلغاء\",\"callback_data\":\"adm_net\"}]]}");
    } else if (strcmp(data, "wtog_yes") == 0) {
        wifi_wan_info_t wi;
        read_wifi_wan_snapshot(&wi);
        int next_dis = wi.disabled ? 0 : 1;
        char cmd[192];
        snprintf(cmd, sizeof(cmd),
                 "uci set wireless.radio0.disabled='%d' && uci commit wireless && (sleep 1; wifi reload) >/dev/null 2>&1 &",
                 next_dis);
        system(cmd);
        tg_edit_or_send(chat_id, msg_id,
                        next_dis ? "🔴 تم إيقاف بث الوايفاي." : "🟢 تم تشغيل بث الوايفاي بنجاح.",
                        "{\"inline_keyboard\":[[{\"text\":\"🔙 للوايفاي\",\"callback_data\":\"adm_net\"},"
                        "{\"text\":\"🏠 الرئيسية\",\"callback_data\":\"adm_home\"}]]}");
    } else if (strcmp(data, "sys_ntp") == 0) {
        tg_answer_callback_sync(cb_id, "⏳ جاري مزامنة الوقت...");
        system("ntpd -n -q -p pool.ntp.org >/dev/null 2>&1 || ntpd -n -q -p time.google.com >/dev/null 2>&1");
        meter_write_ram_json();
        send_admin_status_report(chat_id, msg_id, "🕒 <i>تمت مزامنة الوقت بنجاح.</i>");
        return true;
    } else if (strcmp(data, "sys_obs") == 0) {
        pthread_mutex_lock(&g_lock);
        g_config.observer_mode_enabled = !g_config.observer_mode_enabled;
        g_flash_dirty = true;
        pthread_mutex_unlock(&g_lock);
        meter_write_ram_json();
        send_admin_status_report(chat_id, msg_id, NULL);
    } else if (strcmp(data, "sys_ping") == 0) {
        tg_answer_callback_sync(cb_id, "🌐 جاري فحص الاتصال...");
        int rc = system("ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1");
        send_admin_status_report(chat_id, msg_id,
                                 (rc == 0) ? "🌐 <b>فحص الإنترنت:</b> ✅ متصل بالإنترنت (8.8.8.8 يستجيب)"
                                           : "🌐 <b>فحص الإنترنت:</b> ❌ تعذر الوصول إلى 8.8.8.8");
        return true;
    } else if (strcmp(data, "rb_ask") == 0) {
        tg_edit_or_send(chat_id, msg_id,
                        "🔴 <b>هل أنت متأكد من إعادة تشغيل الراوتر الآن؟</b>",
                        "{\"inline_keyboard\":[[{\"text\":\"✅ نعم، أعد التشغيل فوراً\",\"callback_data\":\"rb_yes\"},"
                        "{\"text\":\"❌ إلغاء\",\"callback_data\":\"adm_reboot\"}]]}");
    } else if (strcmp(data, "rb_yes") == 0) {
        tg_edit_or_send(chat_id, msg_id, "🔄 جاري حفظ البيانات وإعادة تشغيل الراوتر خلال 3 ثوانٍ...", NULL);
        meter_save_all();
        g_reboot_countdown = 3;
    } else if (strncmp(data, "rbcd:", 5) == 0) {
        int32_t cd = atoi(data + 5);
        if (cd < -1) cd = -1;
        if (cd > 86400) cd = 86400;
        meter_save_all();
        g_reboot_countdown = cd;
        meter_write_ram_json();
        send_admin_reboot_menu(chat_id, msg_id);
    } else if (strncmp(data, "rbs:", 4) == 0) {
        const char *arg = data + 4;
        pthread_mutex_lock(&g_lock);
        if (strcmp(arg, "off") == 0) {
            g_config.auto_reboot_enabled = false;
        } else {
            int hr = atoi(arg);
            if (hr >= 0 && hr < 24) {
                g_config.auto_reboot_enabled = true;
                g_config.auto_reboot_hour = (uint8_t)hr;
                g_config.auto_reboot_min = 0;
            }
        }
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        send_admin_reboot_menu(chat_id, msg_id);
    } else if (strcmp(data, "ota_toggle") == 0) {
        pthread_mutex_lock(&g_lock);
        g_config.ota_auto_check_enabled = !g_config.ota_auto_check_enabled;
        pthread_mutex_unlock(&g_lock);
        meter_save_all();
        meter_write_ram_json();
        send_admin_ota_menu(chat_id, msg_id);
    } else if (strcmp(data, "ota_ask") == 0) {
        tg_edit_or_send(chat_id, msg_id,
                        "⚠️ <b>تأكيد تنزيل وتثبيت التحديث الآن؟</b>\nسيتم التحقق من سلامة الملف عبر <code>sysupgrade -T</code> قبل التثبيت ثم إعادة التشغيل تلقائياً.",
                        "{\"inline_keyboard\":[[{\"text\":\"⚡ تأكيد البدء الآن\",\"callback_data\":\"ota_yes\"},"
                        "{\"text\":\"❌ إلغاء\",\"callback_data\":\"adm_ota\"}]]}");
    } else if (strcmp(data, "ota_yes") == 0) {
        tg_answer_callback_sync(cb_id, "⏳ جاري بدء التحديث...");
        char r_ver[32] = {0}, r_url[256] = {0}, r_log[256] = {0};
        bool newer = false;
        if (!telegram_check_ota_remote(r_ver, sizeof(r_ver), r_url, sizeof(r_url), r_log, sizeof(r_log), &newer) || !r_url[0]) {
            tg_edit_or_send(chat_id, msg_id, "❌ تعذر الحصول على رابط الفيرموير من السحابة.", NULL);
            return true;
        }
        tg_edit_or_send(chat_id, msg_id, "⏳ جاري تنزيل الفيرموير والتحقق منه في الخلفية... يرجى عدم فصل الكهرباء.", NULL);
        const char *ca_opt = (access(TG_CA_FILE, R_OK) == 0 && time(NULL) >= 1704067200LL)
                                 ? ("--ca-certificate=" TG_CA_FILE)
                                 : "--no-check-certificate";
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "uclient-fetch -q -T 60 %s -O /tmp/fw_ota.bin '%s' 2>/dev/null", ca_opt, r_url);
        if (system(cmd) == 0 && system("sysupgrade -T /tmp/fw_ota.bin >/dev/null 2>&1") == 0) {
            meter_save_all();
            telegram_send_message(chat_id, "✅ تم التحقق من التحديث بنجاح! جاري الترقية وإعادة التشغيل الآن...", NULL);
            system("(sleep 2; sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; /etc/init.d/rmeterd stop 2>/dev/null; exec /sbin/sysupgrade /tmp/fw_ota.bin) >/dev/null 2>&1 &");
        } else {
            unlink("/tmp/fw_ota.bin");
            telegram_send_message(chat_id, "❌ فشل تنزيل ملف التحديث أو فشل التحقق (sysupgrade -T). لم يتم المساس بالنظام.", NULL);
        }
        return true;
    }
    return false;
}

static void handle_callback(const char *cb_id, const char *chat_id, int64_t msg_id, const char *data) {
    bool acked = false;
    bool is_adm = tg_is_admin(chat_id);
    if (strcmp(data, "prayer_next") == 0) {
        send_prayer_info(chat_id, msg_id, is_adm, false);
        tg_answer_callback_sync(cb_id, "🕌 تم تحديث وقت الصلاة القادمة");
        return;
    }
    if (strcmp(data, "prayer_all") == 0) {
        send_prayer_info(chat_id, msg_id, is_adm, true);
        tg_answer_callback_sync(cb_id, "📅 مواقيت الصلاة اليوم");
        return;
    }
    if (is_adm) {
        acked = handle_callback_admin(cb_id, chat_id, msg_id, data);
    }
    if (!acked) tg_answer_callback_sync(cb_id, NULL);
}

/* ==================== ASYNC WORKER QUEUE & COALESCING ==================== */
#define TG_JOB_CAP 24

typedef struct {
    bool is_cb;
    char cb_id[64];
    char chat_id[32];
    int64_t msg_id;
    char data[96];
    char text[512];
    char fname[48];
    char uname[32];
} tg_job_t;

static pthread_mutex_t s_q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_q_cond = PTHREAD_COND_INITIALIZER;
static tg_job_t s_q[TG_JOB_CAP];
static int s_q_head = 0;
static int s_q_count = 0;

static void tg_queue_push(const tg_job_t *j) {
    pthread_mutex_lock(&s_q_lock);
    if (s_q_count == TG_JOB_CAP) {
        s_q_head = (s_q_head + 1) % TG_JOB_CAP;
        s_q_count--;
    }
    int tail = (s_q_head + s_q_count) % TG_JOB_CAP;
    s_q[tail] = *j;
    s_q_count++;
    pthread_cond_signal(&s_q_cond);
    pthread_mutex_unlock(&s_q_lock);
}

static bool tg_queue_has_later_msg_cb_locked(const char *chat_id, int64_t msg_id) {
    if (msg_id <= 0) return false;
    for (int k = 0; k < s_q_count; k++) {
        const tg_job_t *j = &s_q[(s_q_head + k) % TG_JOB_CAP];
        if (j->is_cb && j->msg_id == msg_id && strcmp(j->chat_id, chat_id) == 0) {
            return true;
        }
    }
    return false;
}

static void tg_drain_queue_sync(void) {
    while (1) {
        tg_job_t j;
        bool has_later_same = false;
        int rem_cnt = 0;

        pthread_mutex_lock(&s_q_lock);
        if (s_q_count <= 0) {
            pthread_mutex_unlock(&s_q_lock);
            break;
        }
        j = s_q[s_q_head];
        s_q_head = (s_q_head + 1) % TG_JOB_CAP;
        s_q_count--;
        rem_cnt = s_q_count;
        if (j.is_cb) {
            has_later_same = tg_queue_has_later_msg_cb_locked(j.chat_id, j.msg_id);
        }
        pthread_mutex_unlock(&s_q_lock);

        if (j.is_cb) {
            /* If another click on the same inline message is already queued, apply state mutation
             * + ack spinner now and skip the redundant intermediate editMessageText! */
            s_skip_ui_edit = has_later_same;
            handle_callback(j.cb_id, j.chat_id, j.msg_id, j.data);
            s_skip_ui_edit = false;
        } else {
            register_tg_user(j.chat_id, j.fname, j.uname);
            if (j.text[0]) handle_command(j.chat_id, j.text);
        }

        if (rem_cnt == 0 && g_flash_dirty) {
            meter_save_all();
        }
    }
}

static void *tg_worker_thread(void *arg) {
    (void)arg;
    time_t last_alert = 0;
    while (1) {
        pthread_mutex_lock(&s_q_lock);
        if (s_q_count == 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 5;
            pthread_cond_timedwait(&s_q_cond, &s_q_lock, &ts);
        }
        pthread_mutex_unlock(&s_q_lock);

        tg_drain_queue_sync();

        time_t now = time(NULL);
        if (now - last_alert >= 5) {
            last_alert = now;
            telegram_check_alerts();
        }
        if (g_flash_dirty) {
            meter_save_all();
        }
    }
    return NULL;
}

static void process_updates_json(const char *json) {
    const char *p = json;
    while ((p = strstr(p, "\"update_id\":")) != NULL) {
        long long uid = 0;
        if (sscanf(p + 12, "%lld", &uid) == 1 && uid > g_config.tg_last_update_id) {
            g_config.tg_last_update_id = uid;
        }
        const char *next = strstr(p + 12, "\"update_id\":");
        size_t chunk_len = next ? (size_t)(next - p) : strlen(p);
        if (chunk_len > 32767) chunk_len = 32767;

        char stack_chunk[4096];
        char *heap_chunk = NULL;
        char *chunk = stack_chunk;
        if (chunk_len >= sizeof(stack_chunk)) {
            heap_chunk = malloc(chunk_len + 1);
            if (!heap_chunk) break;
            chunk = heap_chunk;
        }
        memcpy(chunk, p, chunk_len);
        chunk[chunk_len] = '\0';

        tg_job_t job;
        memset(&job, 0, sizeof(job));

        const char *cb_blk = strstr(chunk, "\"callback_query\"");
        if (cb_blk) {
            job.is_cb = true;
            json_get_str(cb_blk, "id", job.cb_id, sizeof(job.cb_id));
            json_get_str(cb_blk, "data", job.data, sizeof(job.data));
            const char *msg_blk = strstr(cb_blk, "\"message\":");
            if (msg_blk) json_get_i64(msg_blk, "message_id", &job.msg_id);
            const char *chat_blk = msg_blk ? strstr(msg_blk, "\"chat\":") : strstr(cb_blk, "\"chat\":");
            int64_t cid_num = 0;
            if (chat_blk && json_get_i64(chat_blk, "id", &cid_num)) {
                snprintf(job.chat_id, sizeof(job.chat_id), "%lld", (long long)cid_num);
            }
            if (job.cb_id[0] && job.chat_id[0] && job.data[0]) {
                if (s_tg_thread_started) tg_queue_push(&job);
                else handle_callback(job.cb_id, job.chat_id, job.msg_id, job.data);
            }
        } else {
            const char *msg_blk = strstr(chunk, "\"message\":");
            const char *src = msg_blk ? msg_blk : chunk;
            const char *chat_blk = strstr(src, "\"chat\":");
            int64_t cid_num = 0;
            if (chat_blk && json_get_i64(chat_blk, "id", &cid_num)) {
                snprintf(job.chat_id, sizeof(job.chat_id), "%lld", (long long)cid_num);
            }
            json_get_str(src, "first_name", job.fname, sizeof(job.fname));
            json_get_str(src, "username", job.uname, sizeof(job.uname));
            json_get_str(src, "text", job.text, sizeof(job.text));
            if (job.chat_id[0]) {
                if (s_tg_thread_started) tg_queue_push(&job);
                else {
                    register_tg_user(job.chat_id, job.fname, job.uname);
                    if (job.text[0]) handle_command(job.chat_id, job.text);
                }
            }
        }
        free(heap_chunk);
        p += 12;
    }
}

static void *tg_poll_thread(void *arg) {
    (void)arg;
    const size_t resp_cap = 32768;
    char *resp = malloc(resp_cap);
    if (!resp) return NULL;

    time_t last_ota_check = 0;
    bool boot_ota_done = false;
    bool boot_rb_checked = false;

    while (1) {
        time_t now = time(NULL);
        unsigned long up_s = 0, r1 = 0, r2 = 0;
        read_sys_mem_uptime(&up_s, &r1, &r2);

        /* 1. Post-Scheduled Daily Reboot Confirmation Alert */
        if (!boot_rb_checked && up_s >= 35 && access(RMETER_SCHED_RB_FLAG, F_OK) == 0) {
            if (g_config.tg_enabled && g_config.tg_token[0] && g_config.tg_admin_ids[0]) {
                if (telegram_broadcast_admins(
                        "✅ <b>تمت إعادة التشغيل اليومية المجدولة بنجاح!</b>\nالراوتر متصل الآن ويعمل بكامل كفاءته.",
                        TG_ADMIN_KEYBOARD)) {
                    unlink(RMETER_SCHED_RB_FLAG);
                    boot_rb_checked = true;
                }
            } else {
                unlink(RMETER_SCHED_RB_FLAG);
                boot_rb_checked = true;
            }
        } else if (up_s >= 60 && access(RMETER_SCHED_RB_FLAG, F_OK) != 0) {
            boot_rb_checked = true;
        }

        /* 2. Cloud OTA Auto-Check in non-blocking worker thread (boot + every 6h) */
        if (g_config.ota_auto_check_enabled && g_config.ota_version_url[0] &&
            ((!boot_ota_done && up_s >= 60) || (last_ota_check > 0 && (now - last_ota_check) >= 21600))) {
            boot_ota_done = true;
            last_ota_check = now;
            launch_bg_ota_check();
        }

        if (!g_config.tg_enabled || !g_config.tg_interactive || !g_config.tg_token[0]) {
            sleep(3);
            continue;
        }
        char body[192];
        long long offset = g_config.tg_last_update_id + 1;
        snprintf(body, sizeof(body), "offset=%lld&timeout=20&limit=5", offset);
        if (tg_post_api("getUpdates", body, resp, resp_cap, 26, NULL)) {
            process_updates_json(resp);
        } else {
            sleep(2);
        }
    }
    free(resp);
    return NULL;
}

void telegram_init(void) {
    if (!s_tg_thread_started) {
        s_tg_thread_started = true;
        pthread_t wtid, ptid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, TG_THREAD_STACK);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&wtid, &attr, tg_worker_thread, NULL) != 0) {
            s_tg_thread_started = false;
        } else if (pthread_create(&ptid, &attr, tg_poll_thread, NULL) != 0) {
            /* worker runs alerts even if poll failed */
        }
        pthread_attr_destroy(&attr);
    }
}
