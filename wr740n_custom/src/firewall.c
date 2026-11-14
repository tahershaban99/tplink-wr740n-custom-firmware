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

    /* Optional mangle VIP DSCP & Upload MARK chains */
    run_cmd("iptables -t mangle -N RMETER_VIP 2>/dev/null || iptables -t mangle -F RMETER_VIP 2>/dev/null");
    run_cmd("iptables -t mangle -C FORWARD -j RMETER_VIP 2>/dev/null || iptables -t mangle -I FORWARD 1 -j RMETER_VIP 2>/dev/null");
    run_cmd("iptables -t mangle -N RMETER_MARK 2>/dev/null || true");
    run_cmd("iptables -t mangle -C FORWARD -j RMETER_MARK 2>/dev/null || iptables -t mangle -A FORWARD -j RMETER_MARK 2>/dev/null");
}

bool fw_check_hooks(void) {
    if (run_cmd("iptables -C FORWARD -j RMETER_BLK 2>/dev/null") != 0 ||
        run_cmd("iptables -t mangle -C FORWARD -j RMETER_VIP 2>/dev/null") != 0 ||
        run_cmd("iptables -t mangle -C FORWARD -j RMETER_MARK 2>/dev/null") != 0) {
        fw_init();
        return true;
    }
    return false;
}

static void del_ip_rules(const char *chain, const char *ip, bool is_src) {
    char cmd[224];
    const char *dir = is_src ? "-s" : "-d";
    const char *ifc = is_src ? "-i br-lan ! -o br-lan" : "! -i br-lan -o br-lan";
    snprintf(cmd, sizeof(cmd), "iptables -D %s %s %s %s -j RETURN 2>/dev/null", chain, ifc, dir, ip);
    for (int k = 0; k < 4 && run_cmd(cmd) == 0; k++) {}
    snprintf(cmd, sizeof(cmd), "iptables -D %s %s %s -j RETURN 2>/dev/null", chain, dir, ip);
    for (int k = 0; k < 4 && run_cmd(cmd) == 0; k++) {}
}

static bool any_other_device_uses_ip(const rmeter_device_t *devs, int count, int skip_idx, const char *ip) {
    for (int j = 0; j < count; j++) {
        if (j != skip_idx && devs[j].ip[0] && strcmp(devs[j].ip, ip) == 0) return true;
    }
    return false;
}

static bool any_other_device_ensured_ip(const rmeter_device_t *devs, int count, int skip_idx, const char *ip) {
    for (int j = 0; j < count; j++) {
        if (j != skip_idx && devs[j].ipt_ip[0] && strcmp(devs[j].ipt_ip, ip) == 0) return true;
    }
    return false;
}

static void prune_orphan_chain_rules(const char *chain, bool is_src, const rmeter_device_t *devs, int count) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iptables -L %s -v -n -x 2>/dev/null", chain);
    FILE *fp = popen(cmd, "r");
    if (!fp) return;

    char orphans[32][32];
    int o_cnt = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Chain ", 6) == 0 || strstr(line, "pkts")) continue;
        unsigned long long pkts = 0, bytes = 0;
        char target[32], prot[16], opt[16], in_if[32], out_if[32], src[32], dst[32];
        if (sscanf(line, " %llu %llu %31s %15s %15s %31s %31s %31s %31s",
                   &pkts, &bytes, target, prot, opt, in_if, out_if, src, dst) < 9) continue;
        const char *tip = is_src ? src : dst;
        if (!ip_valid(tip)) continue;
        bool active = false;
        for (int i = 0; i < count; i++) {
            if (devs[i].ip[0] && strcmp(devs[i].ip, tip) == 0) { active = true; break; }
        }
        if (!active && o_cnt < 32) {
            snprintf(orphans[o_cnt++], 32, "%s", tip);
        }
    }
    pclose(fp);
    for (int i = 0; i < o_cnt; i++) {
        del_ip_rules(chain, orphans[i], is_src);
    }
}

void fw_ensure_device_rules(rmeter_device_t *devs, int count) {
    char cmd[224];
    for (int i = 0; i < count; i++) {
        bool valid = ip_valid(devs[i].ip);
        if (devs[i].ipt_ip[0] && (!valid || strcmp(devs[i].ipt_ip, devs[i].ip) != 0)) {
            if (!any_other_device_uses_ip(devs, count, i, devs[i].ipt_ip)) {
                del_ip_rules("RMETER_DL", devs[i].ipt_ip, false);
                del_ip_rules("RMETER_UL", devs[i].ipt_ip, true);
            }
            devs[i].ipt_ip[0] = '\0';
            devs[i].prev_ipt_down = 0;
            devs[i].prev_ipt_up = 0;
        }
        if (!valid) continue;
        if (strcmp(devs[i].ipt_ip, devs[i].ip) == 0) continue;

        /* Remove any stale prior counters for this IP unless another active entry owns it */
        if (!any_other_device_ensured_ip(devs, count, i, devs[i].ip)) {
            del_ip_rules("RMETER_DL", devs[i].ip, false);
            del_ip_rules("RMETER_UL", devs[i].ip, true);
            snprintf(cmd, sizeof(cmd), "iptables -A RMETER_DL ! -i br-lan -o br-lan -d %s -j RETURN", devs[i].ip);
            run_cmd(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -A RMETER_UL -i br-lan ! -o br-lan -s %s -j RETURN", devs[i].ip);
            run_cmd(cmd);
        }
        snprintf(devs[i].ipt_ip, sizeof(devs[i].ipt_ip), "%s", devs[i].ip);
        devs[i].prev_ipt_down = 0;
        devs[i].prev_ipt_up = 0;
    }
}

static bool parse_chain_counters(const char *chain, bool is_src, rmeter_device_t *devs, int count) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iptables -L %s -v -n -x 2>/dev/null", chain);
    FILE *fp = popen(cmd, "r");
    if (!fp) return false;

    bool saw_rule = false;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Chain ", 6) == 0 || strstr(line, "pkts")) continue;
        unsigned long long pkts = 0, bytes = 0;
        char target[32], prot[16], opt[16], in_if[32], out_if[32], src[32], dst[32];
        /* Format with -j RETURN: pkts bytes target prot opt in out source destination */
        int n = sscanf(line, " %llu %llu %31s %15s %15s %31s %31s %31s %31s",
                       &pkts, &bytes, target, prot, opt, in_if, out_if, src, dst);
        if (n < 9) continue;
        saw_rule = true;

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
    return saw_rule;
}

void fw_read_counters(rmeter_device_t *devs, int count) {
    /* Snapshot previous totals to compute 1-sec bps accurately in meter.c */
    bool dl_ok = parse_chain_counters("RMETER_DL", false, devs, count);
    bool ul_ok = parse_chain_counters("RMETER_UL", true, devs, count);
    if (!dl_ok || !ul_ok) {
        for (int i = 0; i < count; i++) {
            if (!dl_ok) devs[i].prev_ipt_down = 0;
            if (!ul_ok) devs[i].prev_ipt_up = 0;
            devs[i].ipt_ip[0] = '\0';
        }
    }
}

static void add_vip_dscp_pair(const char *ip) {
    static const char *const specs[] = {
        "-p udp",
        "-p icmp",
        "-p tcp -m length --length 0:300"
    };
    static const char *const dirs[] = {"-s", "-d"};
    char cmd[256];
    for (int s = 0; s < 3; s++) {
        for (int d = 0; d < 2; d++) {
            snprintf(cmd, sizeof(cmd),
                     "iptables -t mangle -A RMETER_VIP %s %s %s -j DSCP --set-dscp 46 2>/dev/null",
                     dirs[d], ip, specs[s]);
            run_cmd(cmd);
        }
    }
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
            add_vip_dscp_pair(devs[i].ip);
        }
    }
    prune_orphan_chain_rules("RMETER_DL", false, devs, count);
    prune_orphan_chain_rules("RMETER_UL", true, devs, count);
}

/* Compensate L2/IP/TCP framing + ACK pacing overhead (~6%) so TCP goodput hits target Mbps */
static uint32_t compensate_goodput_kbps(uint32_t target_kbps) {
    if (target_kbps == 0) return 0;
    uint64_t comp = ((uint64_t)target_kbps * 106ULL + 50ULL) / 100ULL;
    if (comp < 64ULL) comp = 64ULL;
    if (comp > 1000000ULL) comp = 1000000ULL;
    return (uint32_t)comp;
}

/* ~20 ms token bucket burst clamped to [16k, 64k] to prevent tick-interval starvation on HZ=100 MIPS */
static uint32_t calc_htb_burst(uint32_t wire_kbps) {
    uint64_t b = ((uint64_t)wire_kbps * 1000ULL / 8ULL) / 50ULL;
    if (b < 16384ULL) b = 16384ULL;
    if (b > 65536ULL) b = 65536ULL;
    return (uint32_t)b;
}

/* Explicit DRR quantum >= Ethernet MTU so low-rate classes never suffer sub-MTU quantum warnings */
static uint32_t calc_htb_quantum(uint32_t wire_kbps) {
    uint64_t q = ((uint64_t)wire_kbps * 1000ULL / 8ULL) / 100ULL;
    if (q < 1514ULL) q = 1514ULL;
    if (q > 60000ULL) q = 60000ULL;
    return (uint32_t)q;
}

/* Configure HTB root/default/per-device QoS for one direction (DL=true on lan_if, DL=false on wan_if) */
static void apply_dir_htb(rmeter_device_t *devs, int count, const char *ifname,
                          uint32_t root_kbps, bool is_dl, bool wan_capped) {
    int major = is_dl ? 1 : 2;
    uint32_t vip_cnt = 0;
    for (int i = 0; i < count; i++) {
        if (!devs[i].blocked && ip_valid(devs[i].ip) && devs[i].gaming_mode) vip_cnt++;
    }
    uint32_t root_wire = compensate_goodput_kbps(root_kbps);
    if (root_wire < 256) root_wire = 256;

    uint32_t def_rate = vip_cnt ? ((root_wire * 10U) / 100U) : ((root_wire * 50U) / 100U);
    if (def_rate < 256) def_rate = 256;
    if (def_rate > root_wire) def_rate = root_wire;

    uint32_t vip_share = vip_cnt ? ((root_wire * 80U) / 100U) / vip_cnt : ((root_wire * 80U) / 100U);
    if (vip_share < 256) vip_share = 256;
    if (vip_share > root_wire) vip_share = root_wire;

    uint32_t root_burst = calc_htb_burst(root_wire);
    uint32_t def_burst = calc_htb_burst(root_wire);
    uint32_t def_q = calc_htb_quantum(def_rate);
    char cmd[640];

    if (!is_dl) {
        run_cmd("iptables -t mangle -N RMETER_MARK 2>/dev/null || iptables -t mangle -F RMETER_MARK 2>/dev/null");
        run_cmd("iptables -t mangle -C FORWARD -j RMETER_MARK 2>/dev/null || iptables -t mangle -A FORWARD -j RMETER_MARK 2>/dev/null");
    }

    snprintf(cmd, sizeof(cmd),
             "tc qdisc add dev %s root handle %d: htb default 999 r2q 10 2>/dev/null && "
             "tc class add dev %s parent %d: classid %d:1 htb rate %ukbit ceil %ukbit burst %u cburst %u && "
             "tc class add dev %s parent %d:1 classid %d:999 htb rate %ukbit ceil %ukbit burst %u cburst %u quantum %u prio 5",
             ifname, major,
             ifname, major, major, root_wire, root_wire, root_burst, root_burst,
             ifname, major, major, def_rate, root_wire, def_burst, root_burst, def_q);
    if (run_cmd(cmd) != 0) return;

    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s parent %d:999 handle 999: fq_codel limit 1000 quantum 300 2>/dev/null || true",
             ifname, major);
    run_cmd(cmd);

    for (int i = 0; i < count; i++) {
        if (devs[i].blocked || !ip_valid(devs[i].ip)) continue;
        uint32_t cap = devs[i].speed_unlocked ? 0 : (is_dl ? devs[i].cap_down_kbps : devs[i].cap_up_kbps);
        if (cap == 0 && !devs[i].gaming_mode) continue;

        unsigned int cid = 0x10U + (unsigned int)i;
        uint32_t cap_wire = compensate_goodput_kbps(cap);
        uint32_t ceil_k = (cap_wire > 0) ? ((wan_capped && cap_wire > root_wire) ? root_wire : cap_wire) : root_wire;
        if (ceil_k < 64) ceil_k = 64;
        uint32_t rate_k = (cap_wire > 0) ? ceil_k : (devs[i].gaming_mode ? vip_share : def_rate);
        if (rate_k < 64) rate_k = 64;
        if (rate_k > ceil_k) rate_k = ceil_k;
        uint32_t dev_burst = calc_htb_burst(ceil_k);
        uint32_t dev_q = calc_htb_quantum(rate_k);
        int prio = devs[i].gaming_mode ? 1 : 3;

        if (is_dl) {
            snprintf(cmd, sizeof(cmd),
                     "tc class add dev %s parent %d:1 classid %d:%x htb rate %ukbit ceil %ukbit burst %u cburst %u quantum %u prio %d && "
                     "tc filter add dev %s protocol ip parent %d:0 prio 1 u32 match ip dst %s/32 flowid %d:%x",
                     ifname, major, major, cid, rate_k, ceil_k, dev_burst, dev_burst, dev_q, prio,
                     ifname, major, devs[i].ip, major, cid);
        } else {
            snprintf(cmd, sizeof(cmd),
                     "iptables -t mangle -A RMETER_MARK -s %s -j MARK --set-mark 0x%x 2>/dev/null",
                     devs[i].ip, cid);
            run_cmd(cmd);
            snprintf(cmd, sizeof(cmd),
                     "tc class add dev %s parent %d:1 classid %d:%x htb rate %ukbit ceil %ukbit burst %u cburst %u quantum %u prio %d && "
                     "tc filter add dev %s protocol ip parent %d:0 prio 1 handle 0x%x fw flowid %d:%x",
                     ifname, major, major, cid, rate_k, ceil_k, dev_burst, dev_burst, dev_q, prio,
                     ifname, major, cid, major, cid);
        }
        run_cmd(cmd);
        snprintf(cmd, sizeof(cmd),
                 "tc qdisc add dev %s parent %d:%x handle %x: fq_codel limit 1000 quantum 300 2>/dev/null || true",
                 ifname, major, cid, cid);
        run_cmd(cmd);
    }
}

void fw_apply_tc(rmeter_device_t *devs, int count, const char *lan_if, const char *wan_if,
                 uint32_t wan_dl_kbps, uint32_t wan_ul_kbps) {
    bool any_dl_qos = (wan_dl_kbps > 0);
    bool any_ul_qos = (wan_ul_kbps > 0);
    for (int i = 0; i < count; i++) {
        if (!devs[i].blocked && ip_valid(devs[i].ip)) {
            if ((!devs[i].speed_unlocked && devs[i].cap_down_kbps > 0) || devs[i].gaming_mode) any_dl_qos = true;
            if ((!devs[i].speed_unlocked && devs[i].cap_up_kbps > 0) || devs[i].gaming_mode) any_ul_qos = true;
        }
    }

    char cmd[256];
    /* Always clear old qdiscs & upload marks first */
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", lan_if);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", wan_if);
    run_cmd(cmd);
    run_cmd("iptables -t mangle -F RMETER_MARK 2>/dev/null");

    /* If no WAN cap, no device caps, and no VIP devices active, keep native wire speed */
    if (any_dl_qos) {
        uint32_t root_dl = (wan_dl_kbps > 0) ? wan_dl_kbps : 100000U;
        apply_dir_htb(devs, count, lan_if, root_dl, true, wan_dl_kbps > 0);
    }
    if (any_ul_qos) {
        uint32_t root_ul = (wan_ul_kbps > 0) ? wan_ul_kbps : 100000U;
        apply_dir_htb(devs, count, wan_if, root_ul, false, wan_ul_kbps > 0);
    }
}
