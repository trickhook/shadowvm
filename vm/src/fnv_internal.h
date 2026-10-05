#ifndef SVM_FNV_INTERNAL_H
#define SVM_FNV_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

__attribute__((visibility("hidden"))) uint32_t svm__fnv1a32(const uint8_t *data, size_t len);

#endif
