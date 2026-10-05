#include <stddef.h>
#include <stdint.h>

#include "svm_internal.h"

static int svm_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

int svm_hex_decode(const char *s, size_t slen, uint8_t *out, size_t out_len) {
    if (slen != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++) {
        int hi = svm_hex_nibble(s[i * 2]);
        int lo = svm_hex_nibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}
