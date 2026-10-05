#ifndef SVM_BLAKE2S_INTERNAL_H
#define SVM_BLAKE2S_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

__attribute__((visibility("hidden"))) void svm__blake2s(const uint8_t *key, size_t key_len,
                                                        const uint8_t *in, size_t in_len,
                                                        uint8_t *out, size_t out_len);

#endif
