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
void fw_apply_tc(rmeter_device_t *devs, int count, const char *lan_if, const char *wan_if) {
    (void)devs; (void)count; (void)lan_if; (void)wan_if;
}

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
    assert(g_devices[0].gaming_mode);
    assert(meter_set_device_speed_cap("11:22:33:44:55:66", 2000, 5000));
    assert(g_devices[0].cap_up_kbps == 2000 && g_devices[0].cap_down_kbps == 5000);
    assert(meter_reset_device_usage("11:22:33:44:55:66"));
    assert(g_devices[0].up_bytes == 0 && g_devices[0].down_bytes == 0);
    assert(meter_delete_device("11:22:33:44:55:66"));
    assert(g_device_count == 0);
    printf("[PASS] test_meter_scaling_and_quota\n");
}

int main(void) {
    test_json_util();
    test_meter_scaling_and_quota();
    printf("ALL UNIT TESTS PASSED\n");
    return 0;
}
