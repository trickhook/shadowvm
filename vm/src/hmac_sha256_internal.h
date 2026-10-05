#ifndef SVM_HMAC_SHA256_INTERNAL_H
#define SVM_HMAC_SHA256_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "sha256_internal.h"

typedef struct {
    svm_sha256_ctx inner;
    svm_sha256_ctx outer;
} svm_hmac_sha256_ctx;

__attribute__((visibility("hidden"))) void svm__hmac_sha256_init(svm_hmac_sha256_ctx *ctx,
                                                                 const uint8_t *key, size_t key_len);
__attribute__((visibility("hidden"))) void svm__hmac_sha256_update(svm_hmac_sha256_ctx *ctx,
                                                                   const uint8_t *data, size_t len);
__attribute__((visibility("hidden"))) void svm__hmac_sha256_final(svm_hmac_sha256_ctx *ctx, uint8_t out[32]);
__attribute__((visibility("hidden"))) void svm__hmac_sha256(const uint8_t *key, size_t key_len,
                                                            const uint8_t *data, size_t len,
                                                            uint8_t out[32]);

#endif
