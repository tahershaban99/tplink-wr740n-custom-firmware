#ifndef RMETER_FAZAKKIR_H
#define RMETER_FAZAKKIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define FAZAKKIR_MAX_CARDS 24
#define FAZAKKIR_MAX_MACS  32
#define FAZAKKIR_CFG_PATH    "/etc/rmeter/fazakkir.json"
#define FAZAKKIR_STATUS_PATH "/tmp/rmeter/fazakkir_status.json"

typedef struct {
    char text[384];
    bool enabled;
    int max_daily;
    int sent_today;
} fazakkir_card_t;

typedef struct {
    bool prayer_enabled;
    char city[48];
    char country[48];
    int method;
    bool prayer_on[5];
    int prayer_offset[5];
    int prayer_recipient_mode; /* 0 = online only + admins, 1 = all registered + admins */
    int prayer_repeat_min;     /* 0 = no repeat */
    int prayer_action;         /* 0 = none, 1 = block, 2 = throttle */
    uint32_t prayer_kbps;      /* default 5 */
    int prayer_dur_min;        /* default 15 */
    char prayer_macs[FAZAKKIR_MAX_MACS][18];
    int prayer_mac_count;

    bool azkar_enabled;
    int azkar_interval_min;    /* base interval in minutes */
    int azkar_recipient_mode;  /* 0 = online only + admins, 1 = all registered + admins */
    bool azkar_auto_fetch;
    char azkar_source_mode[24]; /* "quran" or "custom" */
    char azkar_url[256];
    fazakkir_card_t cards[FAZAKKIR_MAX_CARDS];
    int card_count;
    int azkar_cursor;

    /* Runtime / cached daily prayer times */
    char prayer_times[5][8];   /* Fajr, Dhuhr, Asr, Maghrib, Isha ("HH:MM") */
    char prayer_date[16];      /* "YYYY-MM-DD" */
    int prayer_active_idx;     /* -1 when idle */
    time_t prayer_window_end;
} fazakkir_cfg_t;

extern fazakkir_cfg_t g_fazakkir;

void fazakkir_init(void);
void fazakkir_reload(void);
void fazakkir_tick(time_t now);
void fazakkir_write_status_json(void);

bool fazakkir_refresh_prayers(char *err, size_t err_sz);
bool fazakkir_autolocate(char *city_out, size_t csz, char *country_out, size_t rsz,
                         char *err, size_t err_sz);
bool fazakkir_fetch_zikr(bool add_card, char *out_text, size_t out_sz,
                         char *err, size_t err_sz);
bool fazakkir_send_test(int kind, char *err, size_t err_sz);
bool fazakkir_get_next_prayer(time_t now, char *name_out, size_t nsz,
                              char *time_out, size_t tsz, int *rem_min_out);
void fazakkir_format_today_prayers(char *out, size_t sz);

#endif

