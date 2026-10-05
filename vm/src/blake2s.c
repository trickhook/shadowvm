#include <stdint.h>
#include <string.h>

#include "blake2s_internal.h"

static const uint32_t IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static const uint8_t SIGMA[10][16] = {
    {  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    { 14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    { 11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    {  7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    {  9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    {  2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    { 12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    { 13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    {  6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 }
};

static uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
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

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[64];
    size_t buflen;
    size_t out_len;
} blake2s_ctx;

static void G(uint32_t *v, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t y) {
    v[a] = v[a] + v[b] + x;
    v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 7);
}

static void blake2s_compress(blake2s_ctx *ctx, const uint8_t block[64]) {
    uint32_t m[16];
    uint32_t v[16];
    for (uint32_t i = 0; i < 16u; i++) {
        m[i] = load_le32(block + i * 4);
    }
    for (uint32_t i = 0; i < 8u; i++) {
        v[i] = ctx->h[i];
        v[8 + i] = IV[i];
    }
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] ^= ctx->f[0];
    v[15] ^= ctx->f[1];
    for (uint32_t r = 0; r < 10u; r++) {
        const uint8_t *s = SIGMA[r];
        G(v, 0, 4, 8,12, m[s[ 0]], m[s[ 1]]);
        G(v, 1, 5, 9,13, m[s[ 2]], m[s[ 3]]);
        G(v, 2, 6,10,14, m[s[ 4]], m[s[ 5]]);
        G(v, 3, 7,11,15, m[s[ 6]], m[s[ 7]]);
        G(v, 0, 5,10,15, m[s[ 8]], m[s[ 9]]);
        G(v, 1, 6,11,12, m[s[10]], m[s[11]]);
        G(v, 2, 7, 8,13, m[s[12]], m[s[13]]);
        G(v, 3, 4, 9,14, m[s[14]], m[s[15]]);
    }
    for (uint32_t i = 0; i < 8u; i++) {
        ctx->h[i] ^= v[i] ^ v[8 + i];
    }
}

static void blake2s_increment(blake2s_ctx *ctx, uint32_t inc) {
    ctx->t[0] += inc;
    if (ctx->t[0] < inc) {
        ctx->t[1] += 1u;
    }
}

static void blake2s_init(blake2s_ctx *ctx, size_t key_len, size_t out_len) {
    for (uint32_t i = 0; i < 8u; i++) {
        ctx->h[i] = IV[i];
    }
    ctx->h[0] ^= 0x01010000u ^ ((uint32_t)key_len << 8) ^ (uint32_t)out_len;
    ctx->t[0] = 0; ctx->t[1] = 0;
    ctx->f[0] = 0; ctx->f[1] = 0;
    ctx->buflen = 0;
    ctx->out_len = out_len;
    for (uint32_t i = 0; i < 64u; i++) ctx->buf[i] = 0;
}

static void blake2s_update(blake2s_ctx *ctx, const uint8_t *in, size_t len) {
    while (len > 0u) {
        if (ctx->buflen == 64u) {
            blake2s_increment(ctx, 64u);
            blake2s_compress(ctx, ctx->buf);
            ctx->buflen = 0;
        }
        size_t space = 64u - ctx->buflen;
        size_t take = len < space ? len : space;
        memcpy(ctx->buf + ctx->buflen, in, take);
        ctx->buflen += take;
        in += take;
        len -= take;
    }
}

static void blake2s_final(blake2s_ctx *ctx, uint8_t *out) {
    blake2s_increment(ctx, (uint32_t)ctx->buflen);
    ctx->f[0] = 0xffffffffu;
    while (ctx->buflen < 64u) {
        ctx->buf[ctx->buflen++] = 0u;
    }
    blake2s_compress(ctx, ctx->buf);
    uint8_t full[32];
    for (uint32_t i = 0; i < 8u; i++) {
        store_le32(full + i * 4, ctx->h[i]);
    }
    for (size_t i = 0; i < ctx->out_len; i++) {
        out[i] = full[i];
    }
    for (uint32_t i = 0; i < 32u; i++) full[i] = 0;
    for (uint32_t i = 0; i < 8u; i++) ctx->h[i] = 0;
}

void svm__blake2s(const uint8_t *key, size_t key_len,
                  const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t out_len) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, key_len, out_len);
    if (key_len > 0u) {
        uint8_t keyblock[64];
        for (uint32_t i = 0; i < 64u; i++) keyblock[i] = 0;
        memcpy(keyblock, key, key_len);
        blake2s_update(&ctx, keyblock, 64);
        for (uint32_t i = 0; i < 64u; i++) keyblock[i] = 0;
    }
    blake2s_update(&ctx, in, in_len);
    blake2s_final(&ctx, out);
}
