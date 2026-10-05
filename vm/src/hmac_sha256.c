#include <stdint.h>
#include <string.h>

#include "hmac_sha256_internal.h"
#include "sha256_internal.h"

void svm__hmac_sha256_init(svm_hmac_sha256_ctx *ctx, const uint8_t *key, size_t key_len) {
    uint8_t keyblock[64];
    memset(keyblock, 0, sizeof(keyblock));
    if (key_len > 64u) {
        svm__sha256(key, key_len, keyblock);
    } else {
        memcpy(keyblock, key, key_len);
    }
    uint8_t ipad[64];
    uint8_t opad[64];
    for (uint32_t i = 0; i < 64u; i++) {
        ipad[i] = keyblock[i] ^ 0x36u;
        opad[i] = keyblock[i] ^ 0x5cu;
    }
    svm__sha256_init(&ctx->inner);
    svm__sha256_update(&ctx->inner, ipad, 64);
    svm__sha256_init(&ctx->outer);
    svm__sha256_update(&ctx->outer, opad, 64);
    for (uint32_t i = 0; i < 64u; i++) {
        keyblock[i] = 0;
        ipad[i] = 0;
        opad[i] = 0;
    }
}

void svm__hmac_sha256_update(svm_hmac_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    svm__sha256_update(&ctx->inner, data, len);
}

void svm__hmac_sha256_final(svm_hmac_sha256_ctx *ctx, uint8_t out[32]) {
    uint8_t inner_digest[32];
    svm__sha256_final(&ctx->inner, inner_digest);
    svm__sha256_update(&ctx->outer, inner_digest, 32);
    svm__sha256_final(&ctx->outer, out);
    for (uint32_t i = 0; i < 32u; i++) {
        inner_digest[i] = 0;
    }
}

void svm__hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t len,
                      uint8_t out[32]) {
    svm_hmac_sha256_ctx ctx;
    svm__hmac_sha256_init(&ctx, key, key_len);
    svm__hmac_sha256_update(&ctx, data, len);
    svm__hmac_sha256_final(&ctx, out);
}
