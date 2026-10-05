#ifndef SHADOWVM_CRYPTO_H
#define SHADOWVM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void svm_xchacha20(const uint8_t key[32], const uint8_t nonce[24],
                   uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);

void svm_poly1305(const uint8_t key[32], const uint8_t *msg, size_t len,
                  uint8_t tag[16]);

int svm_poly1305_verify(const uint8_t key[32], const uint8_t *msg, size_t len,
                        const uint8_t tag[16]);

void svm_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                            const uint8_t *salt, size_t salt_len,
                            uint32_t iters, uint8_t *out, size_t out_len);

void svm_blake2s(const uint8_t *key, size_t key_len,
                 const uint8_t *in, size_t in_len,
                 uint8_t *out, size_t out_len);

uint32_t svm_fnv1a32(const uint8_t *data, size_t len);

void svm_pc_mask(const uint8_t key[32], uint32_t pc, uint8_t out[4]);

void svm_secure_zero(void *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif
