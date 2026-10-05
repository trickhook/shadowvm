#ifndef SVM_PBKDF2_INTERNAL_H
#define SVM_PBKDF2_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

__attribute__((visibility("hidden"))) void svm__pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                                                                    const uint8_t *salt, size_t salt_len,
                                                                    uint32_t iters, uint8_t *out, size_t out_len);

#endif
