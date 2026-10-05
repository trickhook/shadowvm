#include <stdint.h>
#include <string.h>

#include "hmac_sha256_internal.h"
#include "pbkdf2_internal.h"

void svm__pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                             const uint8_t *salt, size_t salt_len,
                             uint32_t iters, uint8_t *out, size_t out_len) {
    uint32_t block_index = 1u;
    size_t produced = 0;
    while (produced < out_len) {
        uint8_t idx_be[4];
        idx_be[0] = (uint8_t)(block_index >> 24);
        idx_be[1] = (uint8_t)(block_index >> 16);
        idx_be[2] = (uint8_t)(block_index >> 8);
        idx_be[3] = (uint8_t)(block_index);
        svm_hmac_sha256_ctx ctx;
        svm__hmac_sha256_init(&ctx, password, password_len);
        svm__hmac_sha256_update(&ctx, salt, salt_len);
        svm__hmac_sha256_update(&ctx, idx_be, 4);
        uint8_t u[32];
        svm__hmac_sha256_final(&ctx, u);
        uint8_t t[32];
        for (uint32_t i = 0; i < 32u; i++) t[i] = u[i];
        for (uint32_t j = 1u; j < iters; j++) {
            svm__hmac_sha256(password, password_len, u, 32, u);
            for (uint32_t i = 0; i < 32u; i++) t[i] ^= u[i];
        }
        size_t remaining = out_len - produced;
        size_t take = remaining < 32u ? remaining : 32u;
        for (size_t i = 0; i < take; i++) {
            out[produced + i] = t[i];
        }
        for (uint32_t i = 0; i < 32u; i++) { u[i] = 0; t[i] = 0; }
        produced += take;
        block_index++;
    }
}
