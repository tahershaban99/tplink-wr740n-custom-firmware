#include "firewall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int run_cmd(const char *cmd) {
    return system(cmd);
}

static bool ip_valid(const char *ip) {
    if (!ip || !ip[0]) return false;
    int a, b, c, d;
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return false;
    return (a >= 1 && a <= 254 && b >= 0 && b <= 255 && c >= 0 && c <= 255 && d >= 1 && d <= 254);
}

static bool mac_valid(const char *mac) {
    if (!mac || strlen(mac) != 17) return false;
    for (int i = 0; i < 17; i++) {
        if ((i % 3) == 2) {
            if (mac[i] != ':') return false;
        } else {
            char c = mac[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
    }
    return true;
}

void fw_detect_wan_if(char *out_if, size_t sz) {
    if (!out_if || sz == 0) return;
    snprintf(out_if, sz, "eth1");
    FILE *fp = popen("ip route show default 2>/dev/null", "r");
    if (!fp) return;
    char line[256];
    if (fgets(line, sizeof(line), fp)) {
        char *dev = strstr(line, " dev ");
        if (dev) {
            dev += 5;
            while (*dev == ' ') dev++;
            char ifn[32] = {0};
            if (sscanf(dev, "%31s", ifn) == 1 && ifn[0]) {
                snprintf(out_if, sz, "%s", ifn);
            }
        }
    }
    pclose(fp);
}

void fw_init(void) {
    /* Create filter chains if not present and hook at top of FORWARD */
    run_cmd("iptables -N RMETER_BLK 2>/dev/null || iptables -F RMETER_BLK");
    run_cmd("iptables -N RMETER_DL  2>/dev/null || true");
    run_cmd("iptables -N RMETER_UL  2>/dev/null || true");

    run_cmd("iptables -C FORWARD -j RMETER_BLK 2>/dev/null || iptables -I FORWARD 1 -j RMETER_BLK");
    run_cmd("iptables -C FORWARD -j RMETER_DL  2>/dev/null || iptables -I FORWARD 2 -j RMETER_DL");
    run_cmd("iptables -C FORWARD -j RMETER_UL  2>/dev/null || iptables -I FORWARD 3 -j RMETER_UL");

    /* Optional mangle VIP DSCP chain */
    run_cmd("iptables -t mangle -N RMETER_VIP 2>/dev/null || iptables -t mangle -F RMETER_VIP 2>/dev/null");
    run_cmd("iptables -t mangle -C FORWARD -j RMETER_VIP 2>/dev/null || iptables -t mangle -I FORWARD 1 -j RMETER_VIP 2>/dev/null");
}

static bool chain_has_ip(const char *chain, const char *ip, bool is_src) {
    char cmd[192];
    snprintf(cmd, sizeof(cmd), "iptables -C %s %s %s -j RETURN 2>/dev/null",
             chain, is_src ? "-s" : "-d", ip);
    return (run_cmd(cmd) == 0);
}

void fw_ensure_device_rules(rmeter_device_t *devs, int count) {
    char cmd[192];
    for (int i = 0; i < count; i++) {
        if (!ip_valid(devs[i].ip)) continue;
        if (!chain_has_ip("RMETER_DL", devs[i].ip, false)) {
            snprintf(cmd, sizeof(cmd), "iptables -A RMETER_DL -d %s -j RETURN", devs[i].ip);
            run_cmd(cmd);
            devs[i].prev_ipt_down = 0;
        }
        if (!chain_has_ip("RMETER_UL", devs[i].ip, true)) {
            snprintf(cmd, sizeof(cmd), "iptables -A RMETER_UL -s %s -j RETURN", devs[i].ip);
            run_cmd(cmd);
            devs[i].prev_ipt_up = 0;
        }
    }
}

static void parse_chain_counters(const char *chain, bool is_src, rmeter_device_t *devs, int count) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iptables -L %s -v -n -x 2>/dev/null", chain);
    FILE *fp = popen(cmd, "r");
    if (!fp) return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Chain ", 6) == 0 || strstr(line, "pkts")) continue;
        unsigned long long pkts = 0, bytes = 0;
        char target[32], prot[16], opt[16], in_if[32], out_if[32], src[32], dst[32];
        /* Format with -j RETURN: pkts bytes target prot opt in out source destination */
        int n = sscanf(line, " %llu %llu %31s %15s %15s %31s %31s %31s %31s",
                       &pkts, &bytes, target, prot, opt, in_if, out_if, src, dst);
        if (n < 9) continue;

        const char *target_ip = is_src ? src : dst;
        for (int i = 0; i < count; i++) {
            if (devs[i].ip[0] && strcmp(devs[i].ip, target_ip) == 0) {
                if (is_src) {
                    if (bytes >= devs[i].prev_ipt_up) {
                        uint64_t delta = bytes - devs[i].prev_ipt_up;
                        devs[i].up_bytes += delta;
                    } else {
                        devs[i].up_bytes += bytes;
                    }
                    devs[i].prev_ipt_up = bytes;
                } else {
                    if (bytes >= devs[i].prev_ipt_down) {
                        uint64_t delta = bytes - devs[i].prev_ipt_down;
                        devs[i].down_bytes += delta;
                    } else {
                        devs[i].down_bytes += bytes;
                    }
                    devs[i].prev_ipt_down = bytes;
                }
                break;
            }
        }
    }
    pclose(fp);
}

void fw_read_counters(rmeter_device_t *devs, int count) {
    /* Snapshot previous totals to compute 1-sec bps accurately in meter.c */
    parse_chain_counters("RMETER_DL", false, devs, count);
    parse_chain_counters("RMETER_UL", true, devs, count);
}

void fw_sync_blocks_and_vip(rmeter_device_t *devs, int count) {
    char cmd[256];
    run_cmd("iptables -F RMETER_BLK 2>/dev/null");
    run_cmd("iptables -t mangle -F RMETER_VIP 2>/dev/null");

    for (int i = 0; i < count; i++) {
        if (devs[i].blocked) {
            if (mac_valid(devs[i].mac)) {
                snprintf(cmd, sizeof(cmd),
                         "iptables -A RMETER_BLK -m mac --mac-source %s -j DROP 2>/dev/null",
                         devs[i].mac);
                run_cmd(cmd);
            }
            if (ip_valid(devs[i].ip)) {
                snprintf(cmd, sizeof(cmd), "iptables -A RMETER_BLK -s %s -j DROP", devs[i].ip);
                run_cmd(cmd);
                snprintf(cmd, sizeof(cmd), "iptables -A RMETER_BLK -d %s -j DROP", devs[i].ip);
                run_cmd(cmd);
            }
        }
        if (devs[i].gaming_mode && !devs[i].blocked && ip_valid(devs[i].ip)) {
            snprintf(cmd, sizeof(cmd),
                     "iptables -t mangle -A RMETER_VIP -s %s -j DSCP --set-dscp 46 2>/dev/null",
                     devs[i].ip);
            run_cmd(cmd);
            snprintf(cmd, sizeof(cmd),
                     "iptables -t mangle -A RMETER_VIP -d %s -j DSCP --set-dscp 46 2>/dev/null",
                     devs[i].ip);
            run_cmd(cmd);
        }
    }
}

void fw_apply_tc(rmeter_device_t *devs, int count, const char *lan_if, const char *wan_if) {
    bool any_dl_cap = false;
    bool any_ul_cap = false;
    for (int i = 0; i < count; i++) {
        if (!devs[i].blocked && ip_valid(devs[i].ip)) {
            if (devs[i].cap_down_kbps > 0) any_dl_cap = true;
            if (devs[i].cap_up_kbps > 0) any_ul_cap = true;
        }
    }

    char cmd[512];
    /* Always clear old qdiscs & upload marks first */
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", lan_if);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", wan_if);
    run_cmd(cmd);
    run_cmd("iptables -t mangle -F RMETER_MARK 2>/dev/null");

    /* If no caps set, keep native zero-overhead wire speed! */
    if (any_dl_cap) {
        snprintf(cmd, sizeof(cmd),
                 "tc qdisc add dev %s root handle 1: htb default 999 2>/dev/null && "
                 "tc class add dev %s parent 1: classid 1:1 htb rate 100mbit ceil 100mbit && "
                 "tc class add dev %s parent 1:1 classid 1:999 htb rate 100mbit ceil 100mbit prio 2",
                 lan_if, lan_if, lan_if);
        if (run_cmd(cmd) == 0) {
            snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s parent 1:999 handle 999: fq_codel 2>/dev/null || true", lan_if);
            run_cmd(cmd);
            for (int i = 0; i < count; i++) {
                if (!devs[i].blocked && ip_valid(devs[i].ip) && devs[i].cap_down_kbps > 0) {
                    int cid = 10 + i;
                    uint32_t rate = devs[i].cap_down_kbps;
                    int prio = devs[i].gaming_mode ? 1 : 3;
                    snprintf(cmd, sizeof(cmd),
                             "tc class add dev %s parent 1:1 classid 1:%d htb rate %ukbit ceil %ukbit prio %d && "
                             "tc filter add dev %s protocol ip parent 1:0 prio 1 u32 match ip dst %s/32 flowid 1:%d",
                             lan_if, cid, rate, rate, prio,
                             lan_if, devs[i].ip, cid);
                    run_cmd(cmd);
                    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s parent 1:%d handle %d: fq_codel 2>/dev/null || true", lan_if, cid, cid);
                    run_cmd(cmd);
                }
            }
        }
    }

    if (any_ul_cap) {
        /* Note: On OpenWrt WAN egress, SNAT changes src IP, so mark packets pre-NAT in mangle FORWARD */
        run_cmd("iptables -t mangle -N RMETER_MARK 2>/dev/null || iptables -t mangle -F RMETER_MARK 2>/dev/null");
        run_cmd("iptables -t mangle -C FORWARD -j RMETER_MARK 2>/dev/null || iptables -t mangle -A FORWARD -j RMETER_MARK 2>/dev/null");

        snprintf(cmd, sizeof(cmd),
                 "tc qdisc add dev %s root handle 2: htb default 999 2>/dev/null && "
                 "tc class add dev %s parent 2: classid 2:1 htb rate 100mbit ceil 100mbit && "
                 "tc class add dev %s parent 2:1 classid 2:999 htb rate 100mbit ceil 100mbit prio 2",
                 wan_if, wan_if, wan_if);
        if (run_cmd(cmd) == 0) {
            snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s parent 2:999 handle 999: fq_codel 2>/dev/null || true", wan_if);
            run_cmd(cmd);
            for (int i = 0; i < count; i++) {
                if (!devs[i].blocked && ip_valid(devs[i].ip) && devs[i].cap_up_kbps > 0) {
                    int cid = 10 + i;
                    uint32_t rate = devs[i].cap_up_kbps;
                    int prio = devs[i].gaming_mode ? 1 : 3;
                    snprintf(cmd, sizeof(cmd),
                             "iptables -t mangle -A RMETER_MARK -s %s -j MARK --set-mark %d 2>/dev/null",
                             devs[i].ip, cid);
                    run_cmd(cmd);
                    snprintf(cmd, sizeof(cmd),
                             "tc class add dev %s parent 2:1 classid 2:%d htb rate %ukbit ceil %ukbit prio %d && "
                             "tc filter add dev %s protocol ip parent 2:0 prio 1 handle %d fw flowid 2:%d",
                             wan_if, cid, rate, rate, prio,
                             wan_if, cid, cid);
                    run_cmd(cmd);
                    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s parent 2:%d handle %d: fq_codel 2>/dev/null || true", wan_if, cid, cid);
                    run_cmd(cmd);
                }
            }
        }
    }
}
