#include <stdint.h>
#include <string.h>

#include "poly1305_internal.h"

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t buffer[16];
    size_t buflen;
} poly1305_state;

static void poly1305_init(poly1305_state *st, const uint8_t key[32]) {
    uint32_t t0 = load_le32(key + 0);
    uint32_t t1 = load_le32(key + 4);
    uint32_t t2 = load_le32(key + 8);
    uint32_t t3 = load_le32(key + 12);
    st->r[0] = (t0) & 0x3ffffffu;
    st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
    st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
    st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
    st->r[4] = (t3 >> 8) & 0x00fffffu;
    for (uint32_t i = 0; i < 5u; i++) {
        st->h[i] = 0;
    }
    st->pad[0] = load_le32(key + 16);
    st->pad[1] = load_le32(key + 20);
    st->pad[2] = load_le32(key + 24);
    st->pad[3] = load_le32(key + 28);
    st->buflen = 0;
}

static void poly1305_block(poly1305_state *st, const uint8_t block[16], uint32_t hibit) {
    uint32_t r0 = st->r[0];
    uint32_t r1 = st->r[1];
    uint32_t r2 = st->r[2];
    uint32_t r3 = st->r[3];
    uint32_t r4 = st->r[4];
    uint32_t s1 = r1 * 5u;
    uint32_t s2 = r2 * 5u;
    uint32_t s3 = r3 * 5u;
    uint32_t s4 = r4 * 5u;
    uint32_t h0 = st->h[0];
    uint32_t h1 = st->h[1];
    uint32_t h2 = st->h[2];
    uint32_t h3 = st->h[3];
    uint32_t h4 = st->h[4];
    uint32_t t0 = load_le32(block + 0);
    uint32_t t1 = load_le32(block + 4);
    uint32_t t2 = load_le32(block + 8);
    uint32_t t3 = load_le32(block + 12);
    h0 += (t0) & 0x3ffffffu;
    h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffffu;
    h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffffu;
    h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffffu;
    h4 += (t3 >> 8) | hibit;
    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
    uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
    uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
    uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
    uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;
    uint32_t c;
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffffu;
    d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffffu;
    d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffffu;
    d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffffu;
    d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffffu;
    h0 += c * 5u; c = h0 >> 26; h0 &= 0x3ffffffu;
    h1 += c;
    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

static void poly1305_update(poly1305_state *st, const uint8_t *msg, size_t len) {
    while (len > 0) {
        if (st->buflen == 0u && len >= 16u) {
            poly1305_block(st, msg, 1u << 24);
            msg += 16;
            len -= 16;
        } else {
            size_t space = 16u - st->buflen;
            size_t take = len < space ? len : space;
            memcpy(st->buffer + st->buflen, msg, take);
            st->buflen += take;
            msg += take;
            len -= take;
            if (st->buflen == 16u) {
                poly1305_block(st, st->buffer, 1u << 24);
                st->buflen = 0;
            }
        }
    }
}

static void poly1305_finish(poly1305_state *st, uint8_t tag[16]) {
    if (st->buflen > 0u) {
        st->buffer[st->buflen++] = 1u;
        while (st->buflen < 16u) {
            st->buffer[st->buflen++] = 0u;
        }
        poly1305_block(st, st->buffer, 0);
    }
    uint32_t h0 = st->h[0];
    uint32_t h1 = st->h[1];
    uint32_t h2 = st->h[2];
    uint32_t h3 = st->h[3];
    uint32_t h4 = st->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffffu; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffffu; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffffu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;
    uint32_t g0 = h0 + 5u;
    c = g0 >> 26; g0 &= 0x3ffffffu;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffffu;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffffu;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffffu;
    uint32_t g4 = h4 + c - (1u << 26);
    uint32_t mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;
    uint32_t f0 = (h0) | (h1 << 26);
    uint32_t f1 = (h1 >> 6) | (h2 << 20);
    uint32_t f2 = (h2 >> 12) | (h3 << 14);
    uint32_t f3 = (h3 >> 18) | (h4 << 8);
    uint64_t t;
    t = (uint64_t)f0 + st->pad[0]; f0 = (uint32_t)t;
    t = (uint64_t)f1 + st->pad[1] + (t >> 32); f1 = (uint32_t)t;
    t = (uint64_t)f2 + st->pad[2] + (t >> 32); f2 = (uint32_t)t;
    t = (uint64_t)f3 + st->pad[3] + (t >> 32); f3 = (uint32_t)t;
    store_le32(tag + 0, f0);
    store_le32(tag + 4, f1);
    store_le32(tag + 8, f2);
    store_le32(tag + 12, f3);
    for (uint32_t i = 0; i < 5u; i++) st->h[i] = 0;
    for (uint32_t i = 0; i < 5u; i++) st->r[i] = 0;
    for (uint32_t i = 0; i < 4u; i++) st->pad[i] = 0;
    for (uint32_t i = 0; i < 16u; i++) st->buffer[i] = 0;
}

void svm__poly1305(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t tag[16]) {
    poly1305_state st;
    poly1305_init(&st, key);
    poly1305_update(&st, msg, len);
    poly1305_finish(&st, tag);
}

int svm__poly1305_verify(const uint8_t key[32], const uint8_t *msg, size_t len, const uint8_t tag[16]) {
    uint8_t computed[16];
    svm__poly1305(key, msg, len, computed);
    uint32_t diff = 0;
    for (uint32_t i = 0; i < 16u; i++) {
        diff |= (uint32_t)(computed[i] ^ tag[i]);
    }
    for (uint32_t i = 0; i < 16u; i++) computed[i] = 0;
    return (int)((diff - 1u) >> 31);
}
