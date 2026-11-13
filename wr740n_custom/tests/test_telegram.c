#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>

/* Include telegram.c directly to test internal menu builders, callback handlers & parser */
#include "telegram.c"

/* Minimal firewall.c stubs needed by meter.c */
void fw_detect_wan_if(void) {}
void fw_init(void) {}
void fw_ensure_device_rules(void) {}
void fw_sync_blocks_and_vip(void) {}
void fw_read_counters(void) {}
void fw_check_hooks(void) {}
void fw_apply_tc(void) {}

static const char *MOCK_DIR = "/tmp/tg_unit_mock_bin";
static const char *MOCK_LOG = "/tmp/tg_unit_calls.log";
static const char *MOCK_400_FLAG = "/tmp/tg_unit_force400";

static void setup_mock_uclient_fetch(void) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p /tmp/rmeter %s", MOCK_DIR);
    assert(system(cmd) == 0);
    unlink(MOCK_LOG);
    unlink(MOCK_400_FLAG);

    char path[256];
    snprintf(path, sizeof(path), "%s/uclient-fetch", MOCK_DIR);
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fprintf(f,
            "#!/usr/bin/env python3\n"
            "import sys, os, urllib.parse, json, re\n"
            "post_data = ''\n"
            "out_file = ''\n"
            "url = ''\n"
            "i = 1\n"
            "while i < len(sys.argv):\n"
            "    a = sys.argv[i]\n"
            "    if a.startswith('--post-data='):\n"
            "        post_data = a[12:]\n"
            "    elif a == '-O' and i + 1 < len(sys.argv):\n"
            "        i += 1\n"
            "        out_file = sys.argv[i]\n"
            "    elif a.startswith('http'):\n"
            "        url = a\n"
            "    i += 1\n"
            "method = url.rsplit('/', 1)[-1] if '/' in url else url\n"
            "params = urllib.parse.parse_qs(post_data, keep_blank_values=True)\n"
            "errors = []\n"
            "if method == 'editMessageText' and os.path.exists('%s'):\n"
            "    os.unlink('%s')\n"
            "    errors.append('Forced stale message 400')\n"
            "if 'reply_markup' in params:\n"
            "    rm_raw = params['reply_markup'][0]\n"
            "    if '\\ufffd' in rm_raw:\n"
            "        errors.append('Invalid UTF-8 in reply_markup')\n"
            "    try:\n"
            "        rm = json.loads(rm_raw)\n"
            "        for row in rm.get('inline_keyboard', []):\n"
            "            for btn in row:\n"
            "                cb = btn.get('callback_data', '')\n"
            "                txt = btn.get('text', '')\n"
            "                if len(cb.encode('utf-8')) > 64:\n"
            "                    errors.append('BUTTON_DATA_INVALID: ' + cb)\n"
            "                if not txt:\n"
            "                    errors.append('Empty button text')\n"
            "    except Exception as e:\n"
            "        errors.append('Invalid reply_markup JSON: ' + str(e))\n"
            "if 'text' in params:\n"
            "    txt = params['text'][0]\n"
            "    if len(txt) > 4096:\n"
            "        errors.append('Text too long: ' + str(len(txt)))\n"
            "    if '\\ufffd' in txt:\n"
            "        errors.append('Invalid UTF-8 U+FFFD in text')\n"
            "    for tag in ('b', 'code', 'i'):\n"
            "        if len(re.findall('<'+tag+'>', txt)) != len(re.findall('</'+tag+'>', txt)):\n"
            "            errors.append('Unbalanced <' + tag + '>')\n"
            "kb_str = params['reply_markup'][0] if 'reply_markup' in params else ''\n"
            "txt_str = params['text'][0] if 'text' in params else ''\n"
            "with open('%s', 'a', encoding='utf-8') as lf:\n"
            "    lf.write(json.dumps({'method':method,'errors':errors,'text':txt_str,'kb':kb_str}, ensure_ascii=False) + '\\n')\n"
            "if errors:\n"
            "    sys.stderr.write('HTTP error 400\\n')\n"
            "    if out_file:\n"
            "        with open(out_file, 'w') as of:\n"
            "            json.dump({'ok': False, 'error_code': 400, 'description': '; '.join(errors)}, of, separators=(',', ':'))\n"
            "    sys.exit(8)\n"
            "if out_file:\n"
            "    with open(out_file, 'w') as of:\n"
            "        json.dump({'ok': True, 'result': {'message_id': 777}}, of, separators=(',', ':'))\n"
            "sys.exit(0)\n",
            MOCK_400_FLAG, MOCK_400_FLAG, MOCK_LOG);
    fclose(f);
    snprintf(cmd, sizeof(cmd), "chmod +x %s/uclient-fetch", MOCK_DIR);
    assert(system(cmd) == 0);

    const char *old_path = getenv("PATH");
    static char new_path[4096];
    snprintf(new_path, sizeof(new_path), "%s:%s", MOCK_DIR, old_path ? old_path : "/usr/bin:/bin");
    setenv("PATH", new_path, 1);
}

static void setup_state(void) {
    pthread_mutex_lock(&g_lock);
    memset(&g_config, 0, sizeof(g_config));
    snprintf(g_config.tg_token, sizeof(g_config.tg_token), "12345:TEST_TOKEN");
    snprintf(g_config.tg_admin_ids, sizeof(g_config.tg_admin_ids), "6627478378");
    g_config.tg_enabled = true;
    g_config.tg_interactive = true;
    g_config.gb_standard = 1024;
    g_config.scale_pct = 100;
    snprintf(g_config.fw_version, sizeof(g_config.fw_version), "1.0.0-wr740nv4");
    snprintf(g_config.start_date, sizeof(g_config.start_date), "2026-11-01");
    snprintf(g_config.end_date, sizeof(g_config.end_date), "2026-12-01");

    g_device_count = 10;
    memset(g_devices, 0, sizeof(g_devices));

    const char *names[10] = {
        "موبايل محمد الشخصي الطويل جداًجداً",
        "أحمد",
        "Test\"Quote\\Slash\nNewline",
        "User<HTML>&Tag",
        "لابتوب الشغل المكتبي رقم واحد",
        "شاشة الصالة الذكية",
        "ايفون سارة",
        "جهاز بلايستيشن 5",
        "كاميرا المراقبة الخارجية",
        "ضيف رقم 10 اسم طويل للغاية جداً"
    };
    for (int i = 0; i < 10; i++) {
        snprintf(g_devices[i].mac, sizeof(g_devices[i].mac), "AA:BB:CC:DD:EE:%02X", i + 1);
        snprintf(g_devices[i].ip, sizeof(g_devices[i].ip), "192.168.1.%d", 10 + i);
        snprintf(g_devices[i].name, sizeof(g_devices[i].name), "%s", names[i]);
        g_devices[i].online = true;
        g_devices[i].quota_bytes = 5ULL * 1073741824ULL;
        g_devices[i].down_bytes = 1ULL * 1073741824ULL;
    }
    /* Device #2 exhausted & auto-blocked */
    g_devices[1].down_bytes = 6ULL * 1073741824ULL;
    g_devices[1].blocked = true;
    g_devices[1].auto_blocked = true;

    s_tg_user_count = 1;
    snprintf(s_tg_users[0].chat_id, sizeof(s_tg_users[0].chat_id), "999888777");
    snprintf(s_tg_users[0].name, sizeof(s_tg_users[0].name), "محمد\"علي\nالطويل جداً جداً");
    pthread_mutex_unlock(&g_lock);
}

static char *read_mock_log(void) {
    FILE *f = fopen(MOCK_LOG, "r");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = calloc(1, (size_t)sz + 1);
    assert(buf != NULL);
    if (sz > 0) {
        size_t n = fread(buf, 1, (size_t)sz, f);
        buf[n] = '\0';
    }
    fclose(f);
    return buf;
}

#include <sys/socket.h>
#include <netinet/in.h>

struct srv_arg { int lfd; int reqs; };

static void *ka_server_fn(void *p) {
    struct srv_arg *a = (struct srv_arg *)p;
    int cfd = accept(a->lfd, NULL, NULL);
    if (cfd < 0) return NULL;
    char reqbuf[4096];
    for (int r = 0; r < 4; r++) {
        ssize_t tot = 0;
        while (tot < (ssize_t)sizeof(reqbuf) - 1) {
            ssize_t n = recv(cfd, reqbuf + tot, sizeof(reqbuf) - 1 - (size_t)tot, 0);
            if (n <= 0) break;
            tot += n;
            reqbuf[tot] = '\0';
            char *hend = strstr(reqbuf, "\r\n\r\n");
            if (hend) {
                const char *cl = strstr(reqbuf, "Content-Length:");
                size_t need = (size_t)(hend + 4 - reqbuf);
                if (cl) need += (size_t)atoi(cl + 15);
                if ((size_t)tot >= need) break;
            }
        }
        a->reqs++;
        char rsp[4096];
        if (r == 0) {
            const char *b1 = "{\"ok\":true,\"n\":1}";
            int rl = snprintf(rsp, sizeof(rsp),
                              "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nConnection: keep-alive\r\n\r\n%s",
                              strlen(b1), b1);
            ssize_t wr = send(cfd, rsp, (size_t)rl, 0);
            (void)wr;
        } else if (r == 1) {
            /* Realistic >2KB callback_query JSON arriving in a SINGLE TLS/TCP read with headers! */
            char big[2400];
            memset(big, 'x', sizeof(big));
            const char *prefix = "{\"ok\":true,\"result\":[{\"update_id\":99,\"callback_query\":{\"id\":\"c1\",\"message\":{\"text\":\"";
            const char *suffix = "\"},\"data\":\"mdev:AA:BB:CC:DD:EE:02\"}}]}";
            size_t plen = strlen(prefix), slen = strlen(suffix);
            memcpy(big, prefix, plen);
            memcpy(big + sizeof(big) - 1 - slen, suffix, slen + 1);
            int rl = snprintf(rsp, sizeof(rsp),
                              "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nConnection: keep-alive\r\n\r\n%s",
                              strlen(big), big);
            ssize_t wr = send(cfd, rsp, (size_t)rl, 0);
            (void)wr;
        } else if (r == 2) {
            const char *c1 = "{\"ok\":true,\"pad\":\"";
            char c2[2400];
            memset(c2, 'y', sizeof(c2));
            const char *end2 = "\",\"n\":2}";
            size_t elen = strlen(end2);
            memcpy(c2 + sizeof(c2) - 1 - elen, end2, elen + 1);
            int rl = snprintf(rsp, sizeof(rsp),
                              "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%zx\r\n%s\r\n%zx\r\n%s\r\n0\r\n\r\n",
                              strlen(c1), c1, strlen(c2), c2);
            ssize_t wr = send(cfd, rsp, (size_t)rl, 0);
            (void)wr;
        } else {
            const char *b3 = "{\"ok\":false,\"err\":400}";
            int rl = snprintf(rsp, sizeof(rsp),
                              "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: %zu\r\n\r\n%s",
                              strlen(b3), b3);
            ssize_t wr = send(cfd, rsp, (size_t)rl, 0);
            (void)wr;
        }
    }
    close(cfd);
    return NULL;
}

static int sock_wr_fn(void *ctx, const char *buf, size_t len, int tmo) {
    (void)tmo;
    int fd = *(int *)ctx;
    return (int)send(fd, buf, len, 0);
}

static int sock_rd_fn(void *ctx, char *buf, size_t len, int tmo) {
    int fd = *(int *)ctx;
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    if (poll(&pfd, 1, tmo * 1000) <= 0) return -1;
    return (int)recv(fd, buf, len, 0);
}

int main(void) {
    setup_mock_uclient_fetch();
    setup_state();

    printf("[TEST] Telegram extra quota (addq), speed preset (setspd), tg link (tgset)...\n");
    uint64_t q0 = g_devices[0].quota_bytes;
    handle_callback("cb1", "6627478378", 100, "addq:AA:BB:CC:DD:EE:01:5");
    assert(g_devices[0].quota_bytes == q0 + 5ULL * 1073741824ULL);

    handle_callback("cb2", "6627478378", 100, "addq:AA:BB:CC:DD:EE:01:10");
    assert(g_devices[0].quota_bytes == q0 + 15ULL * 1073741824ULL);

    /* Unblocking auto-blocked device #2 via +5G (5 -> 10 GiB > 6 GiB used) */
    handle_callback("cb2b", "6627478378", 100, "addq:AA:BB:CC:DD:EE:02:5");
    assert(g_devices[1].quota_bytes == 10ULL * 1073741824ULL);
    assert(g_devices[1].blocked == false);

    handle_callback("cb3", "6627478378", 100, "addq:AA:BB:CC:DD:EE:01:0");
    assert(g_devices[0].quota_bytes == 0);

    handle_callback("cb4", "6627478378", 100, "setspd:AA:BB:CC:DD:EE:01:5000:2000");
    assert(g_devices[0].cap_down_kbps == 5000 && g_devices[0].cap_up_kbps == 2000);

    handle_callback("cb5", "6627478378", 100, "tgset:AA:BB:CC:DD:EE:01:999888777");
    assert(strcmp(g_devices[0].tg_chat_id, "999888777") == 0);

    printf("[TEST] Connected devices menu UTF-8, JSON, control chars & pagination...\n");
    unlink(MOCK_LOG);
    handle_callback("cb_d0", "6627478378", 101, "adm_devs:on");
    handle_callback("cb_d1", "6627478378", 101, "adm_devs:on:1");
    handle_callback("cb_m3", "6627478378", 102, "mdev:AA:BB:CC:DD:EE:03");
    handle_callback("cb_m1", "6627478378", 103, "mdev:AA:BB:CC:DD:EE:01");
    handle_callback("cb_tgp", "6627478378", 104, "tgp:AA:BB:CC:DD:EE:01");

    printf("[TEST] process_updates_json >4096 byte callback_query & \\uXXXX reply keyboard...\n");
    char big_filler[5001];
    memset(big_filler, 'A', 5000);
    big_filler[5000] = '\0';
    char *big_json = malloc(8192);
    assert(big_json != NULL);
    snprintf(big_json, 8192,
             "{\"ok\":true,\"result\":[{\"update_id\":555,\"callback_query\":{"
             "\"id\":\"cb_big_555\",\"from\":{\"id\":6627478378},"
             "\"message\":{\"message_id\":300,\"chat\":{\"id\":6627478378},\"text\":\"%s\"},"
             "\"chat_instance\":\"123\",\"data\":\"vip:AA:BB:CC:DD:EE:01\"}}]}",
             big_filler);
    bool vip_before = g_devices[0].gaming_mode;
    process_updates_json(big_json);
    assert(g_devices[0].gaming_mode == !vip_before);
    free(big_json);

    /* Reply keyboard Arabic "👥 الأجهزة المتصلة" via \uXXXX escapes */
    const char *kb_upd =
        "{\"ok\":true,\"result\":[{\"update_id\":556,\"message\":{"
        "\"message_id\":301,\"chat\":{\"id\":6627478378},\"from\":{\"first_name\":\"Admin\"},"
        "\"text\":\"\\ud83d\\udc65 \\u0627\\u0644\\u0623\\u062c\\u0647\\u0632\\u0629 \\u0627\\u0644\\u0645\\u062a\\u0635\\u0644\\u0629\"}}]}";
    process_updates_json(kb_upd);

    /* Stale message HTTP 400 fallback to sendMessage */
    FILE *ff = fopen(MOCK_400_FLAG, "w");
    if (ff) { fputs("1", ff); fclose(ff); }
    handle_callback("cb_stale", "6627478378", 999, "adm_home");

    usleep(300000);
    char *log = read_mock_log();
    assert(strstr(log, "\"errors\": []") != NULL);
    /* Every valid button must preserve full short Arabic name 'أحمد' */
    assert(strstr(log, "أحمد") != NULL);
    /* Page 2 button must exist and page 2 must render device 9/10 */
    assert(strstr(log, "adm_devs:on:1") != NULL);
    /* Ensure no validation error other than the forced stale test */
    assert(strstr(log, "Invalid reply_markup JSON") == NULL);
    assert(strstr(log, "Invalid UTF-8") == NULL);
    assert(strstr(log, "BUTTON_DATA_INVALID") == NULL);
    assert(strstr(log, "Unbalanced") == NULL);
    /* Ensure stale 400 fell back to sendMessage */
    assert(strstr(log, "\"method\": \"sendMessage\"") != NULL);
    free(log);

    /* TEST 4: HTTP/1.1 Keep-Alive + chunked + Connection: close on ONE loopback TCP socket */
    printf("[TEST] HTTP/1.1 Keep-Alive & chunked framing over single TCP socket...\n");
    {
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        assert(lfd >= 0);
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0;
        assert(bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
        assert(listen(lfd, 2) == 0);
        socklen_t slen = sizeof(sa);
        assert(getsockname(lfd, (struct sockaddr *)&sa, &slen) == 0);

        struct srv_arg sarg = { lfd, 0 };

        pthread_t sth;
        assert(pthread_create(&sth, NULL, ka_server_fn, &sarg) == 0);

        int cfd = socket(AF_INET, SOCK_STREAM, 0);
        assert(cfd >= 0);
        assert(connect(cfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);

        char resp[4096];
        int hc = 0;
        bool cc = false, eof = false;

        assert(tg_http_roundtrip(&cfd, sock_wr_fn, sock_rd_fn, "127.0.0.1", "/botT/m1", "a=1",
                                 resp, sizeof(resp), 2, &hc, &cc, &eof));
        assert(hc == 200 && !cc && !eof && strcmp(resp, "{\"ok\":true,\"n\":1}") == 0);

        assert(tg_http_roundtrip(&cfd, sock_wr_fn, sock_rd_fn, "127.0.0.1", "/botT/getUpdates", "offset=1",
                                 resp, sizeof(resp), 2, &hc, &cc, &eof));
        assert(hc == 200 && !cc && !eof && strlen(resp) == 2399);
        assert(strstr(resp, "\"data\":\"mdev:AA:BB:CC:DD:EE:02\"") != NULL);

        assert(tg_http_roundtrip(&cfd, sock_wr_fn, sock_rd_fn, "127.0.0.1", "/botT/m2", "a=2",
                                 resp, sizeof(resp), 2, &hc, &cc, &eof));
        assert(hc == 200 && !cc && !eof && strlen(resp) == 2417);
        assert(strncmp(resp, "{\"ok\":true,\"pad\":\"", 18) == 0);
        assert(strstr(resp, "\",\"n\":2}") != NULL);

        assert(tg_http_roundtrip(&cfd, sock_wr_fn, sock_rd_fn, "127.0.0.1", "/botT/m3", "a=3",
                                 resp, sizeof(resp), 2, &hc, &cc, &eof));
        assert(hc == 400 && cc && !eof && strcmp(resp, "{\"ok\":false,\"err\":400}") == 0);

        close(cfd);
        pthread_join(sth, NULL);
        close(lfd);
        assert(sarg.reqs == 4);
    }

    /* TEST 5: Worker queue burst coalescing + new submenu/buffer callbacks */
    printf("[TEST] Burst callback coalescing & submenu callbacks (spdmenu, deld_ask, wch, wtx)...\n");
    {
        setup_state();
        unlink(MOCK_LOG);
        unlink(MOCK_400_FLAG);
        pthread_mutex_lock(&s_q_lock);
        s_q_head = 0; s_q_count = 0;
        pthread_mutex_unlock(&s_q_lock);

        const char *mac1 = "AA:BB:CC:DD:EE:01";
        tg_job_t j1, j2, j3;
        memset(&j1, 0, sizeof(j1));
        j1.is_cb = true; j1.msg_id = 777;
        snprintf(j1.chat_id, sizeof(j1.chat_id), "6627478378");
        snprintf(j1.cb_id, sizeof(j1.cb_id), "cb1");
        snprintf(j1.data, sizeof(j1.data), "addq:%s:5", mac1);

        j2 = j1;
        snprintf(j2.cb_id, sizeof(j2.cb_id), "cb2");
        snprintf(j2.data, sizeof(j2.data), "addq:%s:10", mac1);

        j3 = j1;
        snprintf(j3.cb_id, sizeof(j3.cb_id), "cb3");
        snprintf(j3.data, sizeof(j3.data), "blk:%s", mac1);

        tg_queue_push(&j1);
        tg_queue_push(&j2);
        tg_queue_push(&j3);
        tg_drain_queue_sync();

        pthread_mutex_lock(&g_lock);
        assert(g_devices[0].quota_bytes == 20ULL * 1073741824ULL);
        assert(g_devices[0].blocked == true);
        pthread_mutex_unlock(&g_lock);

        char *blog = read_mock_log();
        int ack_cnt = 0, edit_cnt = 0;
        const char *p = blog;
        while ((p = strstr(p, "answerCallbackQuery")) != NULL) { ack_cnt++; p += 19; }
        p = blog;
        while ((p = strstr(p, "editMessageText")) != NULL) { edit_cnt++; p += 15; }
        assert(ack_cnt == 3);
        assert(edit_cnt == 1);
        assert(strstr(blog, "Invalid") == NULL);
        assert(strstr(blog, "Unbalanced") == NULL);
        free(blog);

        /* Regression test expanded callback buffers */
        unlink(MOCK_LOG);
        handle_callback("cb4", "6627478378", 778, "spdmenu:AA:BB:CC:DD:EE:01");
        handle_callback("cb5", "6627478378", 778, "deld_ask:AA:BB:CC:DD:EE:01");
        handle_callback("cb6", "6627478378", 778, "wch:6");
        handle_callback("cb7", "6627478378", 778, "wtx:17");

        char *rlog = read_mock_log();
        assert(strstr(rlog, "Invalid reply_markup JSON") == NULL);
        assert(strstr(rlog, "BUTTON_DATA_INVALID") == NULL);
        assert(strstr(rlog, "Unbalanced") == NULL);
        free(rlog);

        assert(pthread_mutex_trylock(&s_tg_tx_lock) == 0);
        pthread_mutex_unlock(&s_tg_tx_lock);
    }

    /* Cleanup mock artifacts */
    char rm_cmd[256];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s %s %s", MOCK_DIR, MOCK_LOG, MOCK_400_FLAG);
    assert(system(rm_cmd) == 0);

    printf("ALL test_telegram PASSED!\n");
    return 0;
}

