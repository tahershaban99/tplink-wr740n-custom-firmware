#ifndef TELEGRAM_H
#define TELEGRAM_H

#include <stdbool.h>
#include <stddef.h>

void telegram_init(void);
void telegram_check_alerts(void);
bool telegram_send_message(const char *chat_id, const char *text, const char *reply_markup_json);
bool telegram_broadcast_admins(const char *text, const char *reply_markup_json);
bool telegram_send_test(char *err_buf, size_t err_sz);
bool telegram_check_ota_remote(char *out_ver, size_t vsz, char *out_url, size_t usz,
                               char *out_notes, size_t nsz, bool *out_newer);

#endif /* TELEGRAM_H */
