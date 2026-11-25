#ifndef METER_H
#define METER_H

#include "rmeter.h"
#include <pthread.h>

extern rmeter_device_t g_devices[RMETER_MAX_DEVICES];
extern int g_device_count;
extern rmeter_tg_user_quota_t g_tg_quotas[RMETER_MAX_TG_QUOTAS];
extern int g_tg_quota_count;
extern rmeter_config_t g_config;
extern pthread_mutex_t g_lock;

extern uint32_t g_total_up_bps;
extern uint32_t g_total_down_bps;
extern char g_wan_if[32];
extern char g_lan_if[32];
extern int32_t g_reboot_countdown;
extern bool g_fw_dirty;
extern bool g_tc_dirty;
extern bool g_flash_dirty;

void meter_init(void);
void meter_load_all(void);
bool meter_save_all(void);
void meter_tick(double dt_sec);
void meter_write_ram_json(void);

uint64_t meter_scaled_bytes(uint64_t raw);
uint64_t meter_total_used_bytes(void);

int meter_find_by_mac(const char *mac);
int meter_find_by_ip(const char *ip);
int meter_find_by_mac_or_ip(const char *id);

bool meter_set_device_blocked(const char *mac, bool blocked, bool is_auto);
bool meter_set_device_gaming(const char *mac, bool gaming);
bool meter_set_device_quota(const char *mac, uint64_t quota_bytes);
bool meter_add_device_quota(const char *mac, int64_t add_bytes);
bool meter_set_device_speed_cap(const char *mac, uint32_t up_kbps, uint32_t down_kbps);
bool meter_set_device_speed_unlocked(const char *mac, bool unlocked);
bool meter_set_device_name(const char *mac, const char *name);
bool meter_set_device_binding(const char *mac, const char *bound_ip);
bool meter_set_device_telegram(const char *mac, const char *chat_id);
bool meter_set_tg_user_quota(const char *chat_id, const char *label, uint64_t total_bytes);
bool meter_delete_tg_user_quota(const char *chat_id);
int  meter_find_tg_user_quota(const char *chat_id);
bool meter_check_tg_user_overage(const char *chat_id, uint64_t *sum_out, uint64_t *limit_out);
bool meter_user_redistribute_quota(const char *chat_id, const char *mac, uint64_t new_quota_bytes,
                                   char *err_buf, size_t err_sz);
int  meter_apply_unassigned_policy_to_existing(void);
bool meter_reset_device_usage(const char *mac);
bool meter_delete_device(const char *mac);
void meter_reset_all_usage(void);

void meter_set_tg_alert_msg(int slot, const char *msg);
void meter_format_alert_template(const char *tmpl, const char *name, const char *ip,
                                 unsigned pct, const char *used_str,
                                 const char *quota_str, const char *rem_str,
                                 char *out, size_t out_sz);
void meter_fmt_bytes_short(uint64_t b, char *out, size_t sz);

#endif /* METER_H */

