#include "json_util.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

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
            if (*v == 'n') out[j++] = '\n';
            else if (*v == 'r') out[j++] = '\r';
            else if (*v == 't') out[j++] = '\t';
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

