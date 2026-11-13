#ifndef RMETER_H
#define RMETER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define RMETER_MAX_DEVICES     64
#define RMETER_MAX_NAME        64
#define RMETER_MAX_CHAT_ID     32
#define RMETER_MAX_THRESHOLDS  8

#define RMETER_STATE_RAM       "/tmp/rmeter/state.json"
#define RMETER_STATE_FLASH     "/etc/rmeter/devices.db"
#define RMETER_CFG_FLASH       "/etc/rmeter/config.conf"
#define RMETER_TG_USERS_RAM    "/tmp/rmeter/tg_users.json"

typedef struct {
    char mac[18];              /* AA:BB:CC:DD:EE:FF */
    char ip[16];               /* current or static IPv4 */
    char bound_ip[16];         /* static DHCP bound IP, or empty */
    char name[RMETER_MAX_NAME];
    char tg_chat_id[RMETER_MAX_CHAT_ID];

    uint64_t up_bytes;         /* cumulative upload bytes (client -> WAN) */
    uint64_t down_bytes;       /* cumulative download bytes (WAN -> client) */
    uint64_t quota_bytes;      /* 0 = unlimited */

    uint32_t cap_up_kbps;      /* 0 = unlimited (full wire speed) */
    uint32_t cap_down_kbps;    /* 0 = unlimited (full wire speed) */

    uint32_t cur_up_bps;       /* live smoothed upload bits/sec */
    uint32_t cur_down_bps;     /* live smoothed download bits/sec */

    uint64_t prev_ipt_up;      /* last raw iptables byte counter */
    uint64_t prev_ipt_down;    /* last raw iptables byte counter */

    bool online;
    bool is_wifi;
    bool blocked;              /* manual block or quota-100% auto-block */
    bool auto_blocked;         /* blocked specifically due to 100% quota */
    bool gaming_mode;          /* VIP DSCP EF + HTB prio 1 */

    uint16_t alert_flags;      /* bitmask of sent threshold alerts */
    time_t last_seen;
    time_t connected_at;
} rmeter_device_t;

typedef struct {
    uint64_t main_quota_bytes; /* 0 = unlimited */
    uint32_t wan_down_kbps;    /* 0 = auto 100mbit default */
    uint32_t wan_up_kbps;      /* 0 = auto 100mbit default */
    char start_date[12];       /* YYYY-MM-DD */
    char end_date[12];         /* YYYY-MM-DD */
    uint16_t period_days;

    uint16_t gb_standard;      /* 1000 or 1024 */
    uint16_t scale_pct;        /* 50..200, default 100 */
    uint8_t  scale_mode;       /* 0 = dynamic, 1 = cumulative */

    bool auto_reboot_enabled;
    uint8_t auto_reboot_hour;
    uint8_t auto_reboot_min;
    int8_t auto_reboot_tz;

    bool tg_enabled;
    bool tg_interactive;
    char tg_token[96];
    char tg_admin_ids[160];    /* comma-separated chat IDs */
    char tg_thresholds[48];    /* e.g. "50,75,90,95,100" */
    uint16_t main_alert_flags;
    int64_t tg_last_update_id;

    char ota_version_url[192];
    char fw_version[24];
} rmeter_config_t;

#endif /* RMETER_H */

