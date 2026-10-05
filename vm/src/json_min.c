#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "svm_internal.h"

static int svm_json_streq(const char *a, size_t alen, const char *b) {
    size_t blen = strlen(b);
    if (alen != blen) return 0;
    return memcmp(a, b, alen) == 0;
}

static size_t svm_json_skip_ws(const char *s, size_t len, size_t i) {
    while (i < len) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') i++;
        else break;
    }
    return i;
}

static int svm_json_parse_str(const char *s, size_t len, size_t *pi,
                              const char **out, size_t *out_len) {
    size_t i = *pi;
    if (i >= len || s[i] != '"') return 0;
    i++;
    size_t start = i;
    while (i < len) {
        char c = s[i];
        if (c == '\\') {
            if (i + 1 >= len) return 0;
            i += 2;
            continue;
        }
        if (c == '"') {
            *out = s + start;
            *out_len = i - start;
            *pi = i + 1;
            return 1;
        }
        i++;
    }
    return 0;
}

static int svm_json_skip_value(const char *s, size_t len, size_t *pi) {
    size_t i = svm_json_skip_ws(s, len, *pi);
    if (i >= len) return 0;
    char c = s[i];
    if (c == '"') {
        const char *v;
        size_t vl;
        *pi = i;
        return svm_json_parse_str(s, len, pi, &v, &vl);
    }
    if (c == '{' || c == '[') {
        char open = c, close = (c == '{') ? '}' : ']';
        int depth = 1;
        i++;
        while (i < len && depth > 0) {
            char d = s[i];
            if (d == '"') {
                size_t k = i;
                const char *v;
                size_t vl;
                if (!svm_json_parse_str(s, len, &k, &v, &vl)) return 0;
                i = k;
                continue;
            }
            if (d == open) depth++;
            else if (d == close) depth--;
            i++;
        }
        *pi = i;
        return depth == 0;
    }
    while (i < len) {
        char d = s[i];
        if (d == ',' || d == '}' || d == ']') break;
        i++;
    }
    *pi = i;
    return 1;
}

static int svm_json_find_key(const char *src, size_t len, const char *key,
                             size_t *out_val_idx) {
    size_t i = svm_json_skip_ws(src, len, 0);
    if (i >= len || src[i] != '{') return 0;
    i++;
    for (;;) {
        i = svm_json_skip_ws(src, len, i);
        if (i >= len) return 0;
        if (src[i] == '}') return 0;
        const char *k;
        size_t klen;
        if (!svm_json_parse_str(src, len, &i, &k, &klen)) return 0;
        i = svm_json_skip_ws(src, len, i);
        if (i >= len || src[i] != ':') return 0;
        i++;
        i = svm_json_skip_ws(src, len, i);
        if (svm_json_streq(k, klen, key)) {
            *out_val_idx = i;
            return 1;
        }
        if (!svm_json_skip_value(src, len, &i)) return 0;
        i = svm_json_skip_ws(src, len, i);
        if (i < len && src[i] == ',') { i++; continue; }
        if (i < len && src[i] == '}') return 0;
    }
}

int svm_json_find_string(const char *src, size_t len, const char *key,
                         const char **val, size_t *vlen) {
    size_t vi;
    if (!svm_json_find_key(src, len, key, &vi)) return 0;
    return svm_json_parse_str(src, len, &vi, val, vlen);
}

int svm_json_find_int(const char *src, size_t len, const char *key, int64_t *val) {
    size_t vi;
    if (!svm_json_find_key(src, len, key, &vi)) return 0;
    int neg = 0;
    if (vi < len && src[vi] == '-') { neg = 1; vi++; }
    if (vi >= len) return 0;
    int64_t v = 0;
    int saw = 0;
    while (vi < len) {
        char c = src[vi];
        if (c < '0' || c > '9') break;
        v = v * 10 + (c - '0');
        vi++;
        saw = 1;
    }
    if (!saw) return 0;
    *val = neg ? -v : v;
    return 1;
}
