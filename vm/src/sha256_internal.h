#ifndef SVM_SHA256_INTERNAL_H
#define SVM_SHA256_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t buflen;
} svm_sha256_ctx;

__attribute__((visibility("hidden"))) void svm__sha256_init(svm_sha256_ctx *ctx);
__attribute__((visibility("hidden"))) void svm__sha256_update(svm_sha256_ctx *ctx, const uint8_t *data, size_t len);
__attribute__((visibility("hidden"))) void svm__sha256_final(svm_sha256_ctx *ctx, uint8_t out[32]);
__attribute__((visibility("hidden"))) void svm__sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#endif
