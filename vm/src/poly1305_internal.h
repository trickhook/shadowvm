#ifndef SVM_POLY1305_INTERNAL_H
#define SVM_POLY1305_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

__attribute__((visibility("hidden"))) void svm__poly1305(const uint8_t key[32],
                                                         const uint8_t *msg, size_t len,
                                                         uint8_t tag[16]);

__attribute__((visibility("hidden"))) int svm__poly1305_verify(const uint8_t key[32],
                                                               const uint8_t *msg, size_t len,
                                                               const uint8_t tag[16]);

#endif
