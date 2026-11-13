#include "../src/rmeter.h"
#include "../src/json_util.h"
#include "../src/meter.h"
#include "../src/firewall.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Stub firewall functions for unit testing meter logic in memory */
void fw_detect_wan_if(char *out_if, size_t sz) { snprintf(out_if, sz, "eth1"); }
void fw_init(void) {}
void fw_ensure_device_rules(rmeter_device_t *devs, int count) { (void)devs; (void)count; }
void fw_read_counters(rmeter_device_t *devs, int count) { (void)devs; (void)count; }
void fw_sync_blocks_and_vip(rmeter_device_t *devs, int count) { (void)devs; (void)count; }
void fw_apply_tc(rmeter_device_t *devs, int count, const char *lan_if, const char *wan_if,
                 uint32_t wan_dl_kbps, uint32_t wan_ul_kbps) {
    (void)devs; (void)count; (void)lan_if; (void)wan_if;
    (void)wan_dl_kbps; (void)wan_ul_kbps;
}
bool fw_check_hooks(void) { return false; }

static void test_json_util(void) {
    const char *j = "{\"action\":\"device_save\",\"mac\":\"AA:BB:CC:DD:EE:FF\","
                    "\"name\":\"Phone \\\"Ali\\\"\",\"quota_bytes\":2147483648,"
                    "\"tz\":-3,\"blocked\":true,\"gaming_mode\":false}";
    char buf[64] = {0};
    assert(json_get_str(j, "action", buf, sizeof(buf)));
    assert(strcmp(buf, "device_save") == 0);
    assert(json_get_str(j, "mac", buf, sizeof(buf)));
    assert(strcmp(buf, "AA:BB:CC:DD:EE:FF") == 0);
    assert(json_get_str(j, "name", buf, sizeof(buf)));
    assert(strcmp(buf, "Phone \"Ali\"") == 0);

    uint64_t u = 0;
    assert(json_get_u64(j, "quota_bytes", &u));
    assert(u == 2147483648ULL);

    int64_t tz = 0;
    assert(json_get_i64(j, "tz", &tz));
    assert(tz == -3);

    bool b = false, g = true;
    assert(json_get_bool(j, "blocked", &b) && b == true);
    assert(json_get_bool(j, "gaming_mode", &g) && g == false);

    char esc[64];
    json_escape("a\"b\\c\nd", esc, sizeof(esc));
    assert(strcmp(esc, "a\\\"b\\\\c\\nd") == 0);

    /* Telegram getUpdates JSON escaped Arabic + UTF-16 surrogate pair emoji */
    const char *tg_j = "{\"text\":\"\\ud83d\\udcca \\u0627\\u0633\\u062a\\u0647\\u0644\\u0627\\u0643 \\u0627\\u0644\\u0628\\u0627\\u0642\\u0629\"}";
    char tg_out[128] = {0};
    assert(json_get_str(tg_j, "text", tg_out, sizeof(tg_out)));
    assert(strcmp(tg_out, "📊 استهلاك الباقة") == 0);
    printf("[PASS] test_json_util\n");
}

static void test_meter_scaling_and_quota(void) {
    memset(&g_config, 0, sizeof(g_config));
    g_config.gb_standard = 1024;
    g_config.scale_pct = 100;
    g_config.scale_mode = 0;
    g_device_count = 1;
    memset(g_devices, 0, sizeof(g_devices));

    snprintf(g_devices[0].mac, sizeof(g_devices[0].mac), "11:22:33:44:55:66");
    snprintf(g_devices[0].ip, sizeof(g_devices[0].ip), "192.168.1.50");
    g_devices[0].down_bytes = 900ULL * 1024ULL * 1024ULL;
    g_devices[0].up_bytes = 124ULL * 1024ULL * 1024ULL;
    g_devices[0].quota_bytes = 1024ULL * 1024ULL * 1024ULL;

    assert(meter_scaled_bytes(1000) == 1000);
    g_config.scale_pct = 120;
    assert(meter_scaled_bytes(1000) == 1200);
    g_config.scale_mode = 1;
    assert(meter_scaled_bytes(1000) == 1000);
    g_config.scale_mode = 0;
    g_config.scale_pct = 100;

    assert(meter_find_by_mac_or_ip("11:22:33:44:55:66") == 0);
    assert(meter_find_by_mac_or_ip("192.168.1.50") == 0);
    assert(meter_total_used_bytes() == 1024ULL * 1024ULL * 1024ULL);

    /* Simulate 100% auto-block then add_quota auto-unblock */
    assert(meter_set_device_blocked("11:22:33:44:55:66", true, true));
    assert(g_devices[0].blocked && g_devices[0].auto_blocked);
    assert(meter_add_device_quota("11:22:33:44:55:66", (int64_t)(512ULL * 1024ULL * 1024ULL)));
    assert(g_devices[0].quota_bytes == 1536ULL * 1024ULL * 1024ULL);
    assert(!g_devices[0].blocked && !g_devices[0].auto_blocked);

    assert(meter_set_device_gaming("11:22:33:44:55:66", true));
    assert(g_devices[0].gaming_mode && g_fw_dirty && g_tc_dirty);
    g_fw_dirty = false; g_tc_dirty = false;
    assert(meter_set_device_speed_cap("11:22:33:44:55:66", 2000, 5000));
    assert(g_devices[0].cap_up_kbps == 2000 && g_devices[0].cap_down_kbps == 5000);
    assert(g_tc_dirty);

    /* Unlock full speed without altering saved cap values */
    g_tc_dirty = false;
    assert(meter_set_device_speed_unlocked("11:22:33:44:55:66", true));
    assert(g_devices[0].speed_unlocked);
    assert(g_devices[0].cap_up_kbps == 2000 && g_devices[0].cap_down_kbps == 5000);
    assert(g_tc_dirty);
    /* Saving unrelated fields (same caps) preserves speed_unlocked */
    assert(meter_set_device_speed_cap("11:22:33:44:55:66", 2000, 5000));
    assert(g_devices[0].speed_unlocked);
    /* Saving new cap values re-engages cap enforcement */
    assert(meter_set_device_speed_cap("11:22:33:44:55:66", 3000, 6000));
    assert(!g_devices[0].speed_unlocked);
    assert(g_devices[0].cap_up_kbps == 3000 && g_devices[0].cap_down_kbps == 6000);

    /* Verify binding, telegram, reset & delete */
    assert(meter_set_device_binding("11:22:33:44:55:66", "192.168.1.55"));
    assert(strcmp(g_devices[0].bound_ip, "192.168.1.55") == 0);
    assert(meter_set_device_telegram("11:22:33:44:55:66", "123456789"));
    assert(strcmp(g_devices[0].tg_chat_id, "123456789") == 0);
    assert(meter_reset_device_usage("11:22:33:44:55:66"));
    assert(g_devices[0].up_bytes == 0 && g_devices[0].down_bytes == 0);
    assert(meter_delete_device("11:22:33:44:55:66"));
    assert(g_device_count == 0);
    printf("[PASS] test_meter_scaling_and_quota\n");
}

static void test_alert_templates_and_flags(void) {
    memset(&g_config, 0, sizeof(g_config));
    g_config.gb_standard = 1024;
    g_config.observer_mode_enabled = true;
    g_config.ota_auto_check_enabled = false;
    meter_set_tg_alert_msg(0, "تنبيه {name} ({ip}): وصلت {pct}\nالمستخدم: {used} من {quota}\nالمتبقي: {rem}");
    meter_set_tg_alert_msg(4, "انتهت باقة {name} تماماً ({pct})!");
    assert(strcmp(g_config.tg_alert_msgs[4], "انتهت باقة {name} تماماً ({pct})!") == 0);

    char out[512] = {0};
    meter_format_alert_template(g_config.tg_alert_msgs[0], "Laptop", "192.168.1.10", 50,
                                "5.00 GB", "10.00 GB", "5.00 GB", out, sizeof(out));
    assert(strstr(out, "Laptop (192.168.1.10): وصلت 50%") != NULL);
    assert(strstr(out, "المستخدم: 5.00 GB من 10.00 GB") != NULL);
    assert(strstr(out, "المتبقي: 5.00 GB") != NULL);

    /* Empty template cleanly returns empty output */
    meter_format_alert_template("", "Laptop", "192.168.1.10", 50,
                                "5.00 GB", "10.00 GB", "5.00 GB", out, sizeof(out));
    assert(out[0] == '\0');

    char bfmt[32] = {0};
    meter_fmt_bytes_short(512ULL * 1024ULL * 1024ULL, bfmt, sizeof(bfmt));
    assert(strstr(bfmt, "512.0 MB") != NULL);
    printf("[PASS] test_alert_templates_and_flags\n");
}

#include <pthread.h>

static volatile int s_concurrent_run = 1;
static void *concurrent_lock_mutator(void *arg) {
    (void)arg;
    for (int i = 0; i < 400 && s_concurrent_run; i++) {
        pthread_mutex_lock(&g_lock);
        g_devices[0].down_bytes += 1024ULL;
        g_flash_dirty = true;
        pthread_mutex_unlock(&g_lock);
    }
    return NULL;
}

static void test_meter_save_all_snapshot_concurrent(void) {
    pthread_mutex_lock(&g_lock);
    g_device_count = 1;
    memset(&g_devices[0], 0, sizeof(g_devices[0]));
    snprintf(g_devices[0].mac, sizeof(g_devices[0].mac), "AA:BB:CC:11:22:33");
    g_devices[0].down_bytes = 0;
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);

    s_concurrent_run = 1;
    pthread_t th;
    assert(pthread_create(&th, NULL, concurrent_lock_mutator, NULL) == 0);
    for (int i = 0; i < 40; i++) {
        meter_save_all();
    }
    s_concurrent_run = 0;
    pthread_join(th, NULL);

    pthread_mutex_lock(&g_lock);
    g_flash_dirty = true;
    pthread_mutex_unlock(&g_lock);
    meter_save_all();

    pthread_mutex_lock(&g_lock);
    assert(g_flash_dirty == false);
    assert(strcmp(g_devices[0].mac, "AA:BB:CC:11:22:33") == 0);
    pthread_mutex_unlock(&g_lock);
    printf("[PASS] test_meter_save_all_snapshot_concurrent\n");
}

int main(void) {
    test_json_util();
    test_meter_scaling_and_quota();
    test_alert_templates_and_flags();
    test_meter_save_all_snapshot_concurrent();
    printf("ALL UNIT TESTS PASSED\n");
    return 0;
}
