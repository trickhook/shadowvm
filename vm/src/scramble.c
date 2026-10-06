#include <stddef.h>
#include <stdint.h>

#include "svm_internal.h"

void svm_unxor_pad(const uint8_t *ct, const uint8_t *pad_x, size_t n,
                   const uint8_t master[32], char *out) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)(ct[i] ^ pad_x[i] ^ master[i & 31]);
    }
    out[n] = 0;
    __asm__ __volatile__ ("" : : "r"(out) : "memory");
}

void svm_hot_wake(svm_ctx *vm) {
    for (int i = 0; i < 32; i++) {
        vm->kmaster[i] = vm->kmaster_vault[i] ^ vm->kmaster_pad[i];
    }
    __asm__ __volatile__ ("" : : "r"(vm->kmaster) : "memory");
}

void svm_hot_rest(svm_ctx *vm) {
    svm_secure_zero(vm->kmaster, 32);
}
