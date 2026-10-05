#include <stddef.h>
#include <stdint.h>

#include "svm_internal.h"

static int svm_b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

int svm_base64_decode(const char *s, size_t slen, uint8_t *out, size_t *inout_len) {
    size_t cap = *inout_len;
    size_t w = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < slen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        if (c == '=') break;
        int v = svm_b64_val(c);
        if (v < 0) return 0;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (w >= cap) return 0;
            out[w++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    *inout_len = w;
    return 1;
}
