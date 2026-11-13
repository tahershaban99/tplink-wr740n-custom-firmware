#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/rmeter.h"
#include "../src/meter.h"
#include "../src/firewall.h"

extern int __real_system(const char *cmd);
extern FILE *__real_popen(const char *cmd, const char *type);

static char s_cmds[64][512];
static int s_cmd_cnt = 0;
static int s_ipt_c_cnt = 0;

static char s_dl_ips[16][32];
static uint64_t s_dl_bytes[16];
static int s_dl_cnt = 0;

static char s_ul_ips[16][32];
static uint64_t s_ul_bytes[16];
static int s_ul_cnt = 0;

static bool list_has_ip(char ips[][32], int cnt, const char *ip) {
    for (int i = 0; i < cnt; i++) {
        if (strcmp(ips[i], ip) == 0) return true;
    }
    return false;
}

static void list_add_ip(char ips[][32], uint64_t *bytes, int *cnt, const char *ip) {
    if (*cnt >= 16) return;
    snprintf(ips[*cnt], 32, "%s", ip);
    bytes[*cnt] = 0;
    (*cnt)++;
}

static bool list_del_ip(char ips[][32], uint64_t *bytes, int *cnt, const char *ip) {
    for (int i = 0; i < *cnt; i++) {
        if (strcmp(ips[i], ip) == 0) {
            for (int j = i; j + 1 < *cnt; j++) {
                memcpy(ips[j], ips[j + 1], 32);
                bytes[j] = bytes[j + 1];
            }
            (*cnt)--;
            return true;
        }
    }
    return false;
}

int __wrap_system(const char *cmd) {
    if (!cmd) return 0;
    if (s_cmd_cnt < 64) {
        snprintf(s_cmds[s_cmd_cnt++], sizeof(s_cmds[0]), "%s", cmd);
    }
    char ip[32] = {0};
    if (strstr(cmd, "iptables -C ")) {
        s_ipt_c_cnt++;
        const char *p = strstr(cmd, "-d ");
        if (p && sscanf(p + 3, "%31s", ip) == 1 && strstr(cmd, "RMETER_DL")) {
            return list_has_ip(s_dl_ips, s_dl_cnt, ip) ? 0 : 1;
        }
        p = strstr(cmd, "-s ");
        if (p && sscanf(p + 3, "%31s", ip) == 1 && strstr(cmd, "RMETER_UL")) {
            return list_has_ip(s_ul_ips, s_ul_cnt, ip) ? 0 : 1;
        }
        return 0;
    }
    if (strstr(cmd, "iptables -A RMETER_DL") && strstr(cmd, "-d ")) {
        const char *p = strstr(cmd, "-d ");
        if (p && sscanf(p + 3, "%31s", ip) == 1) list_add_ip(s_dl_ips, s_dl_bytes, &s_dl_cnt, ip);
    } else if (strstr(cmd, "iptables -A RMETER_UL") && strstr(cmd, "-s ")) {
        const char *p = strstr(cmd, "-s ");
        if (p && sscanf(p + 3, "%31s", ip) == 1) list_add_ip(s_ul_ips, s_ul_bytes, &s_ul_cnt, ip);
    } else if (strstr(cmd, "iptables -D RMETER_DL") && strstr(cmd, "-d ")) {
        const char *p = strstr(cmd, "-d ");
        if (p && sscanf(p + 3, "%31s", ip) == 1) {
            return list_del_ip(s_dl_ips, s_dl_bytes, &s_dl_cnt, ip) ? 0 : 1;
        }
        return 1;
    } else if (strstr(cmd, "iptables -D RMETER_UL") && strstr(cmd, "-s ")) {
        const char *p = strstr(cmd, "-s ");
        if (p && sscanf(p + 3, "%31s", ip) == 1) {
            return list_del_ip(s_ul_ips, s_ul_bytes, &s_ul_cnt, ip) ? 0 : 1;
        }
        return 1;
    } else if (strstr(cmd, "iptables -F RMETER_DL")) {
        s_dl_cnt = 0;
    } else if (strstr(cmd, "iptables -F RMETER_UL")) {
        s_ul_cnt = 0;
    }
    return 0;
}

static uint64_t s_mock_rx = 0, s_mock_tx = 0;
static int s_mock_delay_ms = 0;

FILE *__wrap_popen(const char *cmd, const char *type) {
    (void)type;
    if (cmd && strstr(cmd, "iptables -L RMETER_DL")) {
        if (s_mock_delay_ms > 0) {
            struct timespec ts = {s_mock_delay_ms / 1000, (s_mock_delay_ms % 1000) * 1000000L};
            nanosleep(&ts, NULL);
        }
        FILE *f = tmpfile();
        fprintf(f, "Chain RMETER_DL (1 references)\n pkts bytes target prot opt in out source destination\n");
        for (int i = 0; i < s_dl_cnt; i++) {
            fprintf(f, " 100 %llu RETURN all -- !br-lan br-lan 0.0.0.0/0 %s\n",
                    (unsigned long long)s_dl_bytes[i], s_dl_ips[i]);
        }
        rewind(f);
        return f;
    }
    if (cmd && strstr(cmd, "iptables -L RMETER_UL")) {
        FILE *f = tmpfile();
        fprintf(f, "Chain RMETER_UL (1 references)\n pkts bytes target prot opt in out source destination\n");
        for (int i = 0; i < s_ul_cnt; i++) {
            fprintf(f, " 100 %llu RETURN all -- br-lan !br-lan %s 0.0.0.0/0\n",
                    (unsigned long long)s_ul_bytes[i], s_ul_ips[i]);
        }
        rewind(f);
        return f;
    }
    if (cmd && (strstr(cmd, "iwinfo") || strstr(cmd, "ip route"))) {
        FILE *f = tmpfile();
        if (strstr(cmd, "ip route")) fprintf(f, "default via 2.2.2.2 dev eth1\n");
        rewind(f);
        return f;
    }
    return __real_popen(cmd, type);
}

int __wrap_pclose(FILE *stream) {
    return fclose(stream);
}

extern FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode) {
    if (path && strcmp(path, "/sys/class/net/eth1/statistics/rx_bytes") == 0) {
        FILE *f = tmpfile();
        fprintf(f, "%llu\n", (unsigned long long)s_mock_rx);
        rewind(f);
        return f;
    }
    if (path && strcmp(path, "/sys/class/net/eth1/statistics/tx_bytes") == 0) {
        FILE *f = tmpfile();
        fprintf(f, "%llu\n", (unsigned long long)s_mock_tx);
        rewind(f);
        return f;
    }
    return __real_fopen(path, mode);
}

static void test_htb_global_and_headroom(void) {
    s_cmd_cnt = 0;
    rmeter_device_t devs[1];
    memset(devs, 0, sizeof(devs));
    snprintf(devs[0].mac, sizeof(devs[0].mac), "AA:BB:CC:DD:EE:01");
    snprintf(devs[0].ip, sizeof(devs[0].ip), "192.168.1.10");

    /* Global WAN cap alone (no per-device cap or VIP) must still create HTB root */
    fw_apply_tc(devs, 1, "br-lan", "eth1", 30000, 10000);
    bool has_dl_root = false, has_ul_root = false;
    for (int i = 0; i < s_cmd_cnt; i++) {
        if (strstr(s_cmds[i], "tc qdisc add dev br-lan root handle 1: htb") &&
            strstr(s_cmds[i], "rate 31800kbit ceil 31800kbit")) {
            has_dl_root = true;
        }
        if (strstr(s_cmds[i], "tc qdisc add dev eth1 root handle 2: htb") &&
            strstr(s_cmds[i], "rate 10600kbit ceil 10600kbit")) {
            has_ul_root = true;
        }
    }
    assert(has_dl_root && has_ul_root);

    /* Per-device 30 Mbps cap must include burst, cburst, quantum, and +6% overhead headroom */
    s_cmd_cnt = 0;
    devs[0].cap_down_kbps = 30000;
    devs[0].cap_up_kbps = 10000;
    fw_apply_tc(devs, 1, "br-lan", "eth1", 0, 0);
    bool has_dev_dl = false, has_dev_ul = false;
    for (int i = 0; i < s_cmd_cnt; i++) {
        if (strstr(s_cmds[i], "tc class add dev br-lan parent 1:1 classid 1:10 htb") &&
            strstr(s_cmds[i], "rate 31800kbit ceil 31800kbit burst 65536 cburst 65536 quantum 39750")) {
            has_dev_dl = true;
        }
        if (strstr(s_cmds[i], "tc class add dev eth1 parent 2:1 classid 2:10 htb") &&
            strstr(s_cmds[i], "rate 10600kbit ceil 10600kbit burst 26500 cburst 26500 quantum 13250")) {
            has_dev_ul = true;
        }
    }
    assert(has_dev_dl && has_dev_ul);
    printf("[PASS] test_htb_global_and_headroom\n");
}

static void test_ipt_ip_reuse_and_no_fork_storm(void) {
    s_dl_cnt = s_ul_cnt = 0;
    list_add_ip(s_dl_ips, s_dl_bytes, &s_dl_cnt, "192.168.1.50");
    s_dl_bytes[0] = 500000000ULL;
    list_add_ip(s_ul_ips, s_ul_bytes, &s_ul_cnt, "192.168.1.50");
    s_ul_bytes[0] = 50000000ULL;

    rmeter_device_t devs[1];
    memset(devs, 0, sizeof(devs));
    snprintf(devs[0].mac, sizeof(devs[0].mac), "AA:BB:CC:DD:EE:02");
    snprintf(devs[0].ip, sizeof(devs[0].ip), "192.168.1.50");

    fw_ensure_device_rules(devs, 1);
    fw_read_counters(devs, 1);
    assert(devs[0].down_bytes == 0 && devs[0].up_bytes == 0);

    /* Steady-state second tick must not fork any iptables -C probes */
    s_ipt_c_cnt = 0;
    fw_ensure_device_rules(devs, 1);
    assert(s_ipt_c_cnt == 0);

    /* Traffic delta counts cleanly and orphan pruning cleans deleted devices */
    s_dl_bytes[0] = 1500000ULL;
    fw_read_counters(devs, 1);
    assert(devs[0].down_bytes == 1500000ULL);
    fw_sync_blocks_and_vip(devs, 0);
    assert(s_dl_cnt == 0 && s_ul_cnt == 0);
    printf("[PASS] test_ipt_ip_reuse_and_no_fork_storm\n");
}

static void test_monotonic_speed_and_dirty_flash(void) {
    memset(&g_config, 0, sizeof(g_config));
    g_config.gb_standard = 1024;
    g_config.scale_pct = 100;
    g_device_count = 1;
    memset(g_devices, 0, sizeof(g_devices));
    snprintf(g_devices[0].mac, sizeof(g_devices[0].mac), "AA:BB:CC:DD:EE:02");
    snprintf(g_devices[0].ip, sizeof(g_devices[0].ip), "192.168.1.50");
    g_flash_dirty = false;

    s_dl_cnt = s_ul_cnt = 0;
    s_mock_delay_ms = 0;
    s_mock_rx = 1000000ULL;
    meter_tick(1.0);

    /* Simulate 1.2s real elapsed (with internal 1000ms popen stall) while caller passes stale dt=1.0 */
    s_mock_delay_ms = 1000;
    s_mock_rx = 6000000ULL; /* +5 MB over >=1.2s -> <= 33.3 Mbps inst, <= 26 Mbps smoothed */
    s_dl_bytes[0] += 5000000ULL;
    struct timespec s1 = {0, 200000000L};
    nanosleep(&s1, NULL);
    meter_tick(1.0);

    assert(g_total_down_bps > 15000000U && g_total_down_bps < 34000000U);
    assert(g_flash_dirty == true);
    printf("[PASS] test_monotonic_speed_and_dirty_flash\n");
}

int main(void) {
    test_htb_global_and_headroom();
    test_ipt_ip_reuse_and_no_fork_storm();
    test_monotonic_speed_and_dirty_flash();
    printf("ALL test_meter_fw PASSED!\n");
    return 0;
}

