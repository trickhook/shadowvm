#include <stdint.h>
#include <stddef.h>

#include "fnv_internal.h"

uint32_t svm__fnv1a32(const uint8_t *data, size_t len) {
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint32_t)data[i];
        h *= 0x01000193u;
    }
    return h;
}
