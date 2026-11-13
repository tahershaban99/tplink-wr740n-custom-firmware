#ifndef JSON_UTIL_H
#define JSON_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

void json_escape(const char *in, char *out, size_t out_sz);
bool json_get_str(const char *json, const char *key, char *out, size_t out_sz);
bool json_get_i64(const char *json, const char *key, int64_t *out);
bool json_get_u64(const char *json, const char *key, uint64_t *out);
bool json_get_bool(const char *json, const char *key, bool *out);

#endif /* JSON_UTIL_H */

