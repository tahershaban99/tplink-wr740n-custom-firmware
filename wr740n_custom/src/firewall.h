#ifndef FIREWALL_H
#define FIREWALL_H

#include "rmeter.h"

void fw_init(void);
void fw_detect_wan_if(char *out_if, size_t sz);
void fw_ensure_device_rules(rmeter_device_t *devs, int count);
void fw_read_counters(rmeter_device_t *devs, int count);
void fw_sync_blocks_and_vip(rmeter_device_t *devs, int count);
void fw_apply_tc(rmeter_device_t *devs, int count, const char *lan_if, const char *wan_if);

#endif /* FIREWALL_H */

