#include "json_util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static bool parse_hex4(const char *s, uint32_t *out) {
    uint32_t val = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!c) return false;
        val <<= 4;
        if (c >= '0' && c <= '9') val |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') val |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') val |= (uint32_t)(c - 'A' + 10);
        else return false;
    }
    *out = val;
    return true;
}

static size_t append_utf8_cp(uint32_t cp, char *out, size_t max_rem) {
    if (cp <= 0x7FU) {
        if (max_rem < 1) return 0;
        out[0] = (char)cp;
        return 1;
    } else if (cp <= 0x7FFU) {
        if (max_rem < 2) return 0;
        out[0] = (char)(0xC0U | (cp >> 6));
        out[1] = (char)(0x80U | (cp & 0x3FU));
        return 2;
    } else if (cp <= 0xFFFFU) {
        if (max_rem < 3) return 0;
        out[0] = (char)(0xE0U | (cp >> 12));
        out[1] = (char)(0x80U | ((cp >> 6) & 0x3FU));
        out[2] = (char)(0x80U | (cp & 0x3FU));
        return 3;
    } else if (cp <= 0x10FFFFU) {
        if (max_rem < 4) return 0;
        out[0] = (char)(0xF0U | (cp >> 18));
        out[1] = (char)(0x80U | ((cp >> 12) & 0x3FU));
        out[2] = (char)(0x80U | ((cp >> 6) & 0x3FU));
        out[3] = (char)(0x80U | (cp & 0x3FU));
        return 4;
    }
    return 0;
}

void json_escape(const char *in, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    if (!in) {
        out[0] = '\0';
        return;
    }
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 2 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= out_sz) break;
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c == '\n') {
            if (j + 2 >= out_sz) break;
            out[j++] = '\\';
            out[j++] = 'n';
        } else if (c == '\r') {
            if (j + 2 >= out_sz) break;
            out[j++] = '\\';
            out[j++] = 'r';
        } else if (c == '\t') {
            if (j + 2 >= out_sz) break;
            out[j++] = '\\';
            out[j++] = 't';
        } else if (c < 0x20) {
            continue;
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

static const char *find_json_key(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char pat[96];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *q = p + strlen(pat);
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q == ':') {
            q++;
            while (*q && isspace((unsigned char)*q)) q++;
            return q;
        }
        p += strlen(pat);
    }
    return NULL;
}

bool json_get_str(const char *json, const char *key, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return false;
    const char *v = find_json_key(json, key);
    if (!v || *v != '"') return false;
    v++;
    size_t j = 0;
    while (*v && *v != '"' && j + 1 < out_sz) {
        if (*v == '\\' && v[1] != '\0') {
            v++;
            if (*v == 'u') {
                uint32_t u1 = 0, u2 = 0;
                if (parse_hex4(v + 1, &u1)) {
                    v += 5;
                    uint32_t cp = u1;
                    if (u1 >= 0xD800U && u1 <= 0xDBFFU && v[0] == '\\' && v[1] == 'u' &&
                        parse_hex4(v + 2, &u2) && u2 >= 0xDC00U && u2 <= 0xDFFFU) {
                        cp = 0x10000U + (((u1 - 0xD800U) << 10) | (u2 - 0xDC00U));
                        v += 6;
                    }
                    size_t w = append_utf8_cp(cp, out + j, out_sz - 1 - j);
                    if (w == 0) break;
                    j += w;
                    continue;
                }
            }
            if (*v == 'n') out[j++] = '\n';
            else if (*v == 'r') out[j++] = '\r';
            else if (*v == 't') out[j++] = '\t';
            else if (*v == 'b') out[j++] = '\b';
            else if (*v == 'f') out[j++] = '\f';
            else out[j++] = *v;
        } else {
            out[j++] = *v;
        }
        v++;
    }
    out[j] = '\0';
    return true;
}

bool json_get_i64(const char *json, const char *key, int64_t *out) {
    const char *v = find_json_key(json, key);
    if (!v) return false;
    if (*v == '"') v++;
    if (!isdigit((unsigned char)*v) && *v != '-') return false;
    char *end = NULL;
    long long val = strtoll(v, &end, 10);
    if (end == v) return false;
    if (out) *out = (int64_t)val;
    return true;
}

bool json_get_u64(const char *json, const char *key, uint64_t *out) {
    const char *v = find_json_key(json, key);
    if (!v) return false;
    if (*v == '"') v++;
    if (!isdigit((unsigned char)*v)) return false;
    char *end = NULL;
    unsigned long long val = strtoull(v, &end, 10);
    if (end == v) return false;
    if (out) *out = (uint64_t)val;
    return true;
}

bool json_get_bool(const char *json, const char *key, bool *out) {
    const char *v = find_json_key(json, key);
    if (!v) return false;
    if (strncmp(v, "true", 4) == 0 || *v == '1') {
        if (out) *out = true;
        return true;
    }
    if (strncmp(v, "false", 5) == 0 || *v == '0') {
        if (out) *out = false;
        return true;
    }
    return false;
}

