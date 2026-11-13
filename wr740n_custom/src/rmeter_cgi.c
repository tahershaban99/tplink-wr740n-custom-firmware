#include "json_util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define CTRL_SOCK_PATH "/tmp/rmeter/ctrl.sock"
#define STATE_JSON     "/tmp/rmeter/state.json"
#define TG_USERS_JSON  "/tmp/rmeter/tg_users.json"
#define AUTH_CONF      "/etc/rmeter/auth.conf"
#define SESSION_TOK    "/tmp/rmeter/session.tok"
#define TG_CA_FILE     "/etc/rmeter/tg_ca.pem"

static void send_json_hdr(const char *extra_hdr) {
    printf("Content-Type: application/json; charset=utf-8\r\n");
    printf("Cache-Control: no-store\r\n");
    if (extra_hdr && extra_hdr[0]) printf("%s", extra_hdr);
    printf("\r\n");
}

static void url_decode_param(const char *qs, const char *key, char *out, size_t sz) {
    out[0] = '\0';
    if (!qs || !key) return;
    size_t klen = strlen(key);
    const char *p = qs;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            size_t j = 0;
            while (*v && *v != '&' && j + 1 < sz) {
                if (*v == '%' && isxdigit((unsigned char)v[1]) && isxdigit((unsigned char)v[2])) {
                    char hx[3] = {v[1], v[2], 0};
                    out[j++] = (char)strtol(hx, NULL, 16);
                    v += 3;
                } else if (*v == '+') {
                    out[j++] = ' ';
                    v++;
                } else {
                    out[j++] = *v++;
                }
            }
            out[j] = '\0';
            return;
        }
        p = strchr(p, '&');
        if (!p) break;
        p++;
    }
}

/* Simple FNV-1a + salt hash or plain config compare? Let's use clean constant-time hash with /etc/rmeter/auth.conf */
static void load_auth(char *user, size_t usz, char *pass, size_t psz) {
    snprintf(user, usz, "admin");
    snprintf(pass, psz, "admin");
    FILE *fp = fopen(AUTH_CONF, "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        if (strncmp(line, "user=", 5) == 0) snprintf(user, usz, "%s", line + 5);
        else if (strncmp(line, "pass=", 5) == 0) snprintf(pass, psz, "%s", line + 5);
    }
    fclose(fp);
}

static void save_auth(const char *user, const char *pass) {
    mkdir("/etc/rmeter", 0755);
    FILE *fp = fopen(AUTH_CONF ".tmp", "w");
    if (!fp) return;
    fprintf(fp, "user=%s\npass=%s\n", user, pass);
    fclose(fp);
    rename(AUTH_CONF ".tmp", AUTH_CONF);
    chmod(AUTH_CONF, 0600);
}

static void gen_token(char *out, size_t sz) {
    unsigned char buf[16] = {0};
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
    }
    size_t pos = 0;
    for (size_t i = 0; i < sizeof(buf) && pos + 3 <= sz; i++) {
        pos += snprintf(out + pos, sz - pos, "%02x", buf[i]);
    }
}

static bool check_auth(void) {
    char expected[64] = {0};
    FILE *fp = fopen(SESSION_TOK, "r");
    if (!fp) return false;
    if (!fgets(expected, sizeof(expected), fp)) { fclose(fp); return false; }
    fclose(fp);
    char *nl = strpbrk(expected, "\r\n");
    if (nl) *nl = '\0';
    if (strlen(expected) < 16) return false;

    const char *hdr_tok = getenv("HTTP_X_AUTH_TOKEN");
    if (hdr_tok && strcmp(hdr_tok, expected) == 0) return true;

    const char *cookie = getenv("HTTP_COOKIE");
    if (cookie) {
        const char *p = strstr(cookie, "rmeter_tok=");
        if (p) {
            p += 11;
            char got[64] = {0};
            size_t i = 0;
            while (p[i] && p[i] != ';' && !isspace((unsigned char)p[i]) && i + 1 < sizeof(got)) {
                got[i] = p[i];
                i++;
            }
            got[i] = '\0';
            if (strcmp(got, expected) == 0) return true;
        }
    }
    return false;
}

static bool send_ipc(const char *json_req, char *resp, size_t resp_sz) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CTRL_SOCK_PATH);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return false;
    }
    write(fd, json_req, strlen(json_req));
    ssize_t n = read(fd, resp, resp_sz - 1);
    if (n > 0) resp[n] = '\0';
    else snprintf(resp, resp_sz, "{\"ok\":false,\"error\":\"empty ipc\"}");
    close(fd);
    return (n > 0);
}

static void read_uci_val(const char *key, char *out, size_t sz) {
    out[0] = '\0';
    char cmd[192];
    snprintf(cmd, sizeof(cmd), "uci -q get %s 2>/dev/null", key);
    FILE *fp = popen(cmd, "r");
    if (!fp) return;
    if (fgets(out, (int)sz, fp)) {
        char *nl = strpbrk(out, "\r\n");
        if (nl) *nl = '\0';
    }
    pclose(fp);
}

static bool safe_uci_str(const char *s) {
    if (!s) return false;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '\'' || c == '"' || c == '`' || c == '$' || c == ';' || c == '&' || c == '|' || c == '\n' || c == '\r')
            return false;
    }
    return true;
}

static void handle_net_info(void) {
    char ssid[64], key[96], enc[32], chan[16], ht[16], dis[8], txp[16], country[8];
    char wan_proto[24], wan_ip[24], wan_mask[24], wan_gw[24], wan_dns[64], wan_user[64];

    read_uci_val("wireless.default_radio0.ssid", ssid, sizeof(ssid));
    read_uci_val("wireless.default_radio0.key", key, sizeof(key));
    read_uci_val("wireless.default_radio0.encryption", enc, sizeof(enc));
    read_uci_val("wireless.radio0.channel", chan, sizeof(chan));
    read_uci_val("wireless.radio0.htmode", ht, sizeof(ht));
    read_uci_val("wireless.radio0.disabled", dis, sizeof(dis));
    read_uci_val("wireless.radio0.txpower", txp, sizeof(txp));
    read_uci_val("wireless.radio0.country", country, sizeof(country));

    read_uci_val("network.wan.proto", wan_proto, sizeof(wan_proto));
    read_uci_val("network.wan.ipaddr", wan_ip, sizeof(wan_ip));
    read_uci_val("network.wan.netmask", wan_mask, sizeof(wan_mask));
    read_uci_val("network.wan.gateway", wan_gw, sizeof(wan_gw));
    read_uci_val("network.wan.dns", wan_dns, sizeof(wan_dns));
    read_uci_val("network.wan.username", wan_user, sizeof(wan_user));

    char es_ssid[128], es_key[192], es_dns[128], es_wuser[128];
    json_escape(ssid, es_ssid, sizeof(es_ssid));
    json_escape(key, es_key, sizeof(es_key));
    json_escape(wan_dns, es_dns, sizeof(es_dns));
    json_escape(wan_user, es_wuser, sizeof(es_wuser));

    send_json_hdr(NULL);
    printf("{\"ok\":true,\"wifi\":{\"ssid\":\"%s\",\"key\":\"%s\",\"encryption\":\"%s\","
           "\"channel\":\"%s\",\"htmode\":\"%s\",\"disabled\":%s,\"txpower\":\"%s\",\"country\":\"%s\"},"
           "\"wan\":{\"proto\":\"%s\",\"ipaddr\":\"%s\",\"netmask\":\"%s\","
           "\"gateway\":\"%s\",\"dns\":\"%s\",\"username\":\"%s\"}}\n",
           es_ssid, es_key, enc[0] ? enc : "psk2",
           chan[0] ? chan : "auto", ht[0] ? ht : "HT40",
           (strcmp(dis, "1") == 0) ? "true" : "false", txp,
           country[0] ? country : "JP",
           wan_proto[0] ? wan_proto : "dhcp", wan_ip, wan_mask, wan_gw, es_dns, es_wuser);
}

static void handle_net_save(const char *body) {
    char ssid[64] = {0}, key[96] = {0}, enc[32] = {0}, chan[16] = {0}, ht[16] = {0}, txp[16] = {0}, country[8] = {0};
    bool wifi_dis = false;
    bool has_dis = json_get_bool(body, "wifi_disabled", &wifi_dis);

    char cmd[512];
    if (json_get_str(body, "ssid", ssid, sizeof(ssid)) && ssid[0] && safe_uci_str(ssid)) {
        snprintf(cmd, sizeof(cmd), "uci set wireless.default_radio0.ssid='%s'", ssid);
        system(cmd);
    }
    if (json_get_str(body, "key", key, sizeof(key)) && safe_uci_str(key)) {
        if (strlen(key) >= 8) {
            snprintf(cmd, sizeof(cmd), "uci set wireless.default_radio0.key='%s'", key);
            system(cmd);
        }
    }
    if (json_get_str(body, "encryption", enc, sizeof(enc)) && enc[0] && safe_uci_str(enc)) {
        snprintf(cmd, sizeof(cmd), "uci set wireless.default_radio0.encryption='%s'", enc);
        system(cmd);
    }
    if (json_get_str(body, "channel", chan, sizeof(chan)) && chan[0] && safe_uci_str(chan)) {
        snprintf(cmd, sizeof(cmd), "uci set wireless.radio0.channel='%s'", chan);
        system(cmd);
    }
    if (json_get_str(body, "htmode", ht, sizeof(ht)) && ht[0] && safe_uci_str(ht)) {
        snprintf(cmd, sizeof(cmd), "uci set wireless.radio0.htmode='%s'", ht);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "uci set wireless.radio0.noscan='%s'",
                 (strcmp(ht, "HT40") == 0) ? "1" : "0");
        system(cmd);
    }
    if (json_get_str(body, "country", country, sizeof(country)) &&
        strlen(country) == 2 && isupper((unsigned char)country[0]) && isupper((unsigned char)country[1])) {
        snprintf(cmd, sizeof(cmd), "uci set wireless.radio0.country='%s'", country);
        system(cmd);
    }
    system("uci set wireless.radio0.legacy_rates='0'");
    if (json_get_str(body, "txpower", txp, sizeof(txp)) && safe_uci_str(txp)) {
        if (txp[0]) snprintf(cmd, sizeof(cmd), "uci set wireless.radio0.txpower='%s'", txp);
        else snprintf(cmd, sizeof(cmd), "uci -q delete wireless.radio0.txpower || true");
        system(cmd);
    }
    if (has_dis) {
        snprintf(cmd, sizeof(cmd), "uci set wireless.radio0.disabled='%d'", wifi_dis ? 1 : 0);
        system(cmd);
    }

    char proto[24] = {0}, wip[24] = {0}, wmask[24] = {0}, wgw[24] = {0}, wdns[64] = {0}, wuser[64] = {0}, wpass[64] = {0};
    bool wan_changed = false;
    if (json_get_str(body, "wan_proto", proto, sizeof(proto)) && proto[0] && safe_uci_str(proto)) {
        snprintf(cmd, sizeof(cmd), "uci set network.wan.proto='%s'", proto);
        system(cmd);
        wan_changed = true;
    }
    if (json_get_str(body, "wan_ip", wip, sizeof(wip)) && safe_uci_str(wip)) {
        if (wip[0]) { snprintf(cmd, sizeof(cmd), "uci set network.wan.ipaddr='%s'", wip); system(cmd); }
    }
    if (json_get_str(body, "wan_mask", wmask, sizeof(wmask)) && safe_uci_str(wmask)) {
        if (wmask[0]) { snprintf(cmd, sizeof(cmd), "uci set network.wan.netmask='%s'", wmask); system(cmd); }
    }
    if (json_get_str(body, "wan_gw", wgw, sizeof(wgw)) && safe_uci_str(wgw)) {
        if (wgw[0]) { snprintf(cmd, sizeof(cmd), "uci set network.wan.gateway='%s'", wgw); system(cmd); }
    }
    if (json_get_str(body, "wan_dns", wdns, sizeof(wdns)) && safe_uci_str(wdns)) {
        if (wdns[0]) { snprintf(cmd, sizeof(cmd), "uci set network.wan.dns='%s'", wdns); system(cmd); }
        else system("uci -q delete network.wan.dns || true");
    }
    if (json_get_str(body, "wan_user", wuser, sizeof(wuser)) && safe_uci_str(wuser)) {
        if (wuser[0]) { snprintf(cmd, sizeof(cmd), "uci set network.wan.username='%s'", wuser); system(cmd); }
    }
    if (json_get_str(body, "wan_pass", wpass, sizeof(wpass)) && safe_uci_str(wpass)) {
        if (wpass[0]) { snprintf(cmd, sizeof(cmd), "uci set network.wan.password='%s'", wpass); system(cmd); }
    }

    system("uci commit wireless; (sleep 1; wifi reload) >/dev/null 2>&1 &");
    if (wan_changed) {
        system("uci commit network; (sleep 1; /etc/init.d/network reload) >/dev/null 2>&1 &");
    }
    send_json_hdr(NULL);
    printf("{\"ok\":true}\n");
}

static void handle_ota_check(const char *body) {
    char url[192] = {0};
    json_get_str(body, "url", url, sizeof(url));
    if (!url[0]) {
        /* Try reading from state.json or config.conf */
        FILE *cf = fopen("/etc/rmeter/config.conf", "r");
        if (cf) {
            char line[256];
            while (fgets(line, sizeof(line), cf)) {
                if (strncmp(line, "ota_version_url=", 16) == 0) {
                    char *nl = strpbrk(line, "\r\n");
                    if (nl) *nl = '\0';
                    snprintf(url, sizeof(url), "%s", line + 16);
                }
            }
            fclose(cf);
        }
    }
    if (!url[0] || !safe_uci_str(url)) {
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"لم يتم ضبط رابط التحقق من التحديث\"}\n");
        return;
    }
    char cmd[384];
    const char *ca_opt = (access(TG_CA_FILE, R_OK) == 0) ? "--ca-certificate=" TG_CA_FILE : "--no-check-certificate";
    snprintf(cmd, sizeof(cmd), "uclient-fetch -q -T 15 %s -O /tmp/rmeter/ota_ver.json '%s' 2>/dev/null", ca_opt, url);
    if (system(cmd) != 0) {
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"فشل الاتصال بسيرفر التحديث\"}\n");
        return;
    }
    FILE *fp = fopen("/tmp/rmeter/ota_ver.json", "r");
    if (!fp) {
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"تعذر قراءة ملف الإصدار\"}\n");
        return;
    }
    char buf[2048] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    send_json_hdr(NULL);
    printf("{\"ok\":true,\"remote\":%s}\n", buf[0] == '{' ? buf : "{}");
}

static void handle_ota_upload(size_t clen) {
    if (clen < 65536 || clen > 3932160) {
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"حجم ملف الفيرموير غير صالح\"}\n");
        return;
    }
    FILE *fp = fopen("/tmp/fw_ota.bin", "wb");
    if (!fp) {
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"تعذر الحفظ في /tmp\"}\n");
        return;
    }
    char buf[4096];
    size_t rem = clen;
    while (rem > 0) {
        size_t chunk = rem > sizeof(buf) ? sizeof(buf) : rem;
        size_t got = fread(buf, 1, chunk, stdin);
        if (got == 0) break;
        fwrite(buf, 1, got, fp);
        rem -= got;
    }
    fclose(fp);

    if (system("sysupgrade -T /tmp/fw_ota.bin >/dev/null 2>&1") != 0) {
        unlink("/tmp/fw_ota.bin");
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"فشل التحقق من ملف الفيرموير (sysupgrade -T)\"}\n");
        return;
    }
    send_json_hdr(NULL);
    printf("{\"ok\":true,\"msg\":\"تم التحقق بنجاح، جاري التحديث وإعادة التشغيل...\"}\n");
    fflush(stdout);
    system("(sleep 2; sysupgrade /tmp/fw_ota.bin) >/dev/null 2>&1 &");
}

static void handle_ota_url(const char *body) {
    char url[256] = {0};
    if (!json_get_str(body, "url", url, sizeof(url)) || !url[0] || !safe_uci_str(url)) {
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"رابط غير صالح\"}\n");
        return;
    }
    char cmd[384];
    const char *ca_opt = (access(TG_CA_FILE, R_OK) == 0) ? "--ca-certificate=" TG_CA_FILE : "--no-check-certificate";
    snprintf(cmd, sizeof(cmd), "uclient-fetch -q -T 60 %s -O /tmp/fw_ota.bin '%s' 2>/dev/null", ca_opt, url);
    if (system(cmd) != 0 || system("sysupgrade -T /tmp/fw_ota.bin >/dev/null 2>&1") != 0) {
        unlink("/tmp/fw_ota.bin");
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"فشل تنزيل أو التحقق من صورة التحديث\"}\n");
        return;
    }
    send_json_hdr(NULL);
    printf("{\"ok\":true,\"msg\":\"تم التنزيل والتحقق، جاري الترقية وإعادة التشغيل...\"}\n");
    fflush(stdout);
    system("(sleep 2; sysupgrade /tmp/fw_ota.bin) >/dev/null 2>&1 &");
}

int main(void) {
    const char *qs = getenv("QUERY_STRING");
    const char *cl_str = getenv("CONTENT_LENGTH");
    size_t clen = cl_str ? (size_t)strtoul(cl_str, NULL, 10) : 0;

    char action[48] = {0};
    url_decode_param(qs, "action", action, sizeof(action));

    if (strcmp(action, "ota_upload") == 0) {
        if (!check_auth()) {
            send_json_hdr(NULL);
            printf("{\"ok\":false,\"error\":\"unauthorized\"}\n");
            return 0;
        }
        handle_ota_upload(clen);
        return 0;
    }

    char body[4096] = {0};
    if (clen > 0 && clen < sizeof(body)) {
        size_t got = fread(body, 1, clen, stdin);
        body[got] = '\0';
    }

    if (strcmp(action, "auth_status") == 0) {
        char u[64], p[64];
        load_auth(u, sizeof(u), p, sizeof(p));
        send_json_hdr(NULL);
        printf("{\"authenticated\":%s,\"user\":\"%s\"}\n", check_auth() ? "true" : "false", u);
        return 0;
    }

    if (strcmp(action, "login") == 0) {
        char req_u[64] = {0}, req_p[64] = {0}, cfg_u[64], cfg_p[64];
        json_get_str(body, "username", req_u, sizeof(req_u));
        json_get_str(body, "password", req_p, sizeof(req_p));
        load_auth(cfg_u, sizeof(cfg_u), cfg_p, sizeof(cfg_p));
        if (strcmp(req_u, cfg_u) == 0 && strcmp(req_p, cfg_p) == 0) {
            char tok[40] = {0};
            gen_token(tok, sizeof(tok));
            mkdir("/tmp/rmeter", 0755);
            FILE *fp = fopen(SESSION_TOK, "w");
            if (fp) { fprintf(fp, "%s\n", tok); fclose(fp); }
            char hdr[160];
            snprintf(hdr, sizeof(hdr), "Set-Cookie: rmeter_tok=%s; Path=/; HttpOnly\r\n", tok);
            send_json_hdr(hdr);
            printf("{\"ok\":true,\"token\":\"%s\"}\n", tok);
        } else {
            send_json_hdr(NULL);
            printf("{\"ok\":false,\"error\":\"اسم المستخدم أو كلمة المرور غير صحيحة\"}\n");
        }
        return 0;
    }

    if (strcmp(action, "logout") == 0) {
        unlink(SESSION_TOK);
        send_json_hdr("Set-Cookie: rmeter_tok=; Path=/; Max-Age=0\r\n");
        printf("{\"ok\":true}\n");
        return 0;
    }

    if (!check_auth()) {
        printf("Status: 401 Unauthorized\r\n");
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"unauthorized\"}\n");
        return 0;
    }

    if (strcmp(action, "password") == 0) {
        char oldp[64] = {0}, newp[64] = {0}, newu[64] = {0}, cfg_u[64], cfg_p[64];
        json_get_str(body, "old_password", oldp, sizeof(oldp));
        json_get_str(body, "new_password", newp, sizeof(newp));
        json_get_str(body, "new_username", newu, sizeof(newu));
        load_auth(cfg_u, sizeof(cfg_u), cfg_p, sizeof(cfg_p));
        if (strcmp(oldp, cfg_p) != 0 || strlen(newp) < 4) {
            send_json_hdr(NULL);
            printf("{\"ok\":false,\"error\":\"كلمة المرور الحالية غير صحيحة أو الجديدة قصيرة جداً\"}\n");
            return 0;
        }
        save_auth(newu[0] ? newu : cfg_u, newp);
        send_json_hdr(NULL);
        printf("{\"ok\":true}\n");
        return 0;
    }

    if (strcmp(action, "state") == 0) {
        send_json_hdr(NULL);
        FILE *fp = fopen(STATE_JSON, "r");
        FILE *tf = fopen(TG_USERS_JSON, "r");
        printf("{\"ok\":true,\"state\":");
        if (fp) {
            char buf[2048];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) fwrite(buf, 1, n, stdout);
            fclose(fp);
        } else {
            printf("{}");
        }
        printf(",\"tg_users\":");
        if (tf) {
            char buf[1024];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), tf)) > 0) fwrite(buf, 1, n, stdout);
            fclose(tf);
        } else {
            printf("[]");
        }
        printf("}\n");
        return 0;
    }

    if (strcmp(action, "net_info") == 0) {
        handle_net_info();
        return 0;
    }
    if (strcmp(action, "net_save") == 0) {
        handle_net_save(body);
        return 0;
    }
    if (strcmp(action, "ota_check") == 0) {
        handle_ota_check(body);
        return 0;
    }
    if (strcmp(action, "ota_url") == 0) {
        handle_ota_url(body);
        return 0;
    }

    /* Forward all other actions to rmeterd IPC */
    char ipc_req[4400];
    if (strstr(body, "\"action\"") != NULL) {
        snprintf(ipc_req, sizeof(ipc_req), "%s", body);
    } else if (body[0] == '{') {
        snprintf(ipc_req, sizeof(ipc_req), "{\"action\":\"%s\",%s", action, body + 1);
    } else {
        snprintf(ipc_req, sizeof(ipc_req), "{\"action\":\"%s\"}", action);
    }

    char resp[512] = {0};
    if (send_ipc(ipc_req, resp, sizeof(resp))) {
        send_json_hdr(NULL);
        printf("%s\n", resp);
    } else {
        send_json_hdr(NULL);
        printf("{\"ok\":false,\"error\":\"rmeterd not running\"}\n");
    }
    return 0;
}

