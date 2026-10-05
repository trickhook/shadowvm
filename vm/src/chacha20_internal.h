#ifndef SVM_CHACHA20_INTERNAL_H
#define SVM_CHACHA20_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

__attribute__((visibility("hidden"))) void svm__chacha20_block(const uint8_t key[32],
                                                               uint32_t counter,
                                                               const uint8_t nonce12[12],
                                                               uint8_t out[64]);

__attribute__((visibility("hidden"))) void svm__chacha20_xor(const uint8_t key[32],
                                                             uint32_t counter,
                                                             const uint8_t nonce12[12],
                                                             const uint8_t *in,
                                                             uint8_t *out,
                                                             size_t len);

__attribute__((visibility("hidden"))) void svm__hchacha20(const uint8_t key[32],
                                                          const uint8_t nonce16[16],
                                                          uint8_t out[32]);

#endif
