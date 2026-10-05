#include <stdint.h>
#include <string.h>

#include "chacha20_internal.h"

static uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static void qr(uint32_t *s, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a], 8);
    s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c], 7);
}

static void twenty_rounds(uint32_t s[16]) {
    for (uint32_t i = 0; i < 10u; i++) {
        qr(s, 0, 4, 8, 12);
        qr(s, 1, 5, 9, 13);
        qr(s, 2, 6, 10, 14);
        qr(s, 3, 7, 11, 15);
        qr(s, 0, 5, 10, 15);
        qr(s, 1, 6, 11, 12);
        qr(s, 2, 7, 8, 13);
        qr(s, 3, 4, 9, 14);
    }
}

void svm__chacha20_block(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce12[12], uint8_t out[64]) {
    uint32_t state[16];
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (uint32_t i = 0; i < 8u; i++) {
        state[4 + i] = load_le32(key + i * 4);
    }
    state[12] = counter;
    state[13] = load_le32(nonce12 + 0);
    state[14] = load_le32(nonce12 + 4);
    state[15] = load_le32(nonce12 + 8);
    uint32_t working[16];
    for (uint32_t i = 0; i < 16u; i++) {
        working[i] = state[i];
    }
    twenty_rounds(working);
    for (uint32_t i = 0; i < 16u; i++) {
        store_le32(out + i * 4, working[i] + state[i]);
    }
}

void svm__chacha20_xor(const uint8_t key[32], uint32_t counter,
                       const uint8_t nonce12[12], const uint8_t *in,
                       uint8_t *out, size_t len) {
    uint8_t ks[64];
    uint32_t ctr = counter;
    size_t offset = 0;
    while (offset < len) {
        svm__chacha20_block(key, ctr, nonce12, ks);
        size_t take = len - offset;
        if (take > 64u) take = 64u;
        for (size_t i = 0; i < take; i++) {
            out[offset + i] = in[offset + i] ^ ks[i];
        }
        offset += take;
        ctr++;
    }
    for (uint32_t i = 0; i < 64u; i++) {
        ks[i] = 0;
    }
}

void svm__hchacha20(const uint8_t key[32], const uint8_t nonce16[16], uint8_t out[32]) {
    uint32_t state[16];
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (uint32_t i = 0; i < 8u; i++) {
        state[4 + i] = load_le32(key + i * 4);
    }
    for (uint32_t i = 0; i < 4u; i++) {
        state[12 + i] = load_le32(nonce16 + i * 4);
    }
    twenty_rounds(state);
    for (uint32_t i = 0; i < 4u; i++) {
        store_le32(out + i * 4, state[i]);
    }
    for (uint32_t i = 0; i < 4u; i++) {
        store_le32(out + 16 + i * 4, state[12 + i]);
    }
}
