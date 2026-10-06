#include <stddef.h>
#include <stdint.h>

#include "svm_internal.h"

void svm_unxor(const uint8_t *in, size_t n, char *out) {
    uint8_t k = 0x5A;
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)(in[i] ^ (uint8_t)(k + (uint8_t)i));
    }
    out[n] = 0;
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
