#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "svm_internal.h"

#define SVM_EXPORT __attribute__((visibility("default")))

SVM_EXPORT svm_ctx *svm_open_local(const uint8_t *blob, size_t blob_len,
                                   const char *password, size_t password_len,
                                   svm_status *status) {
    svm_status s;
    svm_ctx *vm = NULL;

    s = svm_antire_check();
    if (s != SVM_OK) {
        if (status) *status = s;
        return NULL;
    }

    if (!blob || blob_len < (size_t)SVM_HDR_SIZE + SVM_MAC_SIZE || !password) {
        if (status) *status = SVM_E_BAD_MAGIC;
        return NULL;
    }

    uint32_t magic = (uint32_t)blob[0] | ((uint32_t)blob[1] << 8)
                   | ((uint32_t)blob[2] << 16) | ((uint32_t)blob[3] << 24);
    if (magic != SVM_MAGIC) {
        if (status) *status = SVM_E_BAD_MAGIC;
        return NULL;
    }

    uint32_t body_len = (uint32_t)blob[8] | ((uint32_t)blob[9] << 8)
                      | ((uint32_t)blob[10] << 16) | ((uint32_t)blob[11] << 24);
    uint32_t kdf_iters = (uint32_t)blob[28] | ((uint32_t)blob[29] << 8)
                       | ((uint32_t)blob[30] << 16) | ((uint32_t)blob[31] << 24);

    if ((size_t)SVM_HDR_SIZE + (size_t)body_len + (size_t)SVM_MAC_SIZE != blob_len) {
        if (status) *status = SVM_E_BAD_MAC;
        return NULL;
    }
    if (body_len < 16) {
        if (status) *status = SVM_E_TAMPER;
        return NULL;
    }

    const uint8_t *salt = blob + SVM_HDR_SIZE;
    uint8_t kmaster[32];
    svm_pbkdf2_hmac_sha256((const uint8_t *)password, password_len,
                           salt, 16, kdf_iters ? kdf_iters : 100000,
                           kmaster, 32);

    s = svm_loader_open(blob, blob_len, kmaster, &vm, 1);
    svm_secure_zero(kmaster, 32);
    if (status) *status = s;
    if (s != SVM_OK) return NULL;
    return vm;
}

SVM_EXPORT svm_ctx *svm_open_remote(const svm_remote_cfg *cfg, svm_status *status) {
    svm_status rs = svm_antire_check();
    if (rs != SVM_OK) {
        if (status) *status = rs;
        return NULL;
    }
    if (!cfg) {
        if (status) *status = SVM_E_ATTEST;
        return NULL;
    }
    svm_session sess;
    memset(&sess, 0, sizeof(sess));
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    svm_status s = svm_attest(cfg, &sess, &blob, &blob_len);
    if (s != SVM_OK) {
        if (status) *status = s;
        svm_session_zero(&sess);
        return NULL;
    }

    svm_ctx *vm = NULL;
    s = svm_loader_open(blob, blob_len, sess.session_key, &vm, 1);

    svm_session_zero(&sess);
    if (blob) {
        svm_secure_zero(blob, blob_len);
        free(blob);
    }
    if (status) *status = s;
    if (s != SVM_OK) return NULL;
    return vm;
}

SVM_EXPORT void svm_set_syscall(svm_ctx *vm, uint32_t idx, svm_syscall_fn fn) {
    if (!vm) return;
    if (idx >= 256) return;
    vm->syscalls[idx] = fn;
}

static void svm_lowercase(const char *in, size_t n, uint8_t *out) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        out[i] = c;
    }
}

static int svm_entry_lookup(const svm_ctx *vm, uint32_t name_hash, uint32_t *out_off) {
    for (uint32_t i = 0; i < vm->entry_count; i++) {
        const uint8_t *e = vm->entry + i * 8;
        uint32_t h = (uint32_t)e[0] | ((uint32_t)e[1] << 8)
                   | ((uint32_t)e[2] << 16) | ((uint32_t)e[3] << 24);
        if (h == name_hash) {
            *out_off = (uint32_t)e[4] | ((uint32_t)e[5] << 8)
                     | ((uint32_t)e[6] << 16) | ((uint32_t)e[7] << 24);
            return 1;
        }
    }
    return 0;
}

SVM_EXPORT svm_status svm_run(svm_ctx *vm, const char *symbol,
                              const int64_t *argv, size_t argc, int64_t *result) {
    if (!vm || !symbol) return SVM_E_BAD_SYMBOL;

    size_t nlen = strlen(symbol);
    uint8_t stackbuf[128];
    uint8_t *lc = stackbuf;
    uint8_t *heap = NULL;
    if (nlen > sizeof(stackbuf)) {
        heap = (uint8_t *)malloc(nlen);
        if (!heap) return SVM_E_NOMEM;
        lc = heap;
    }
    svm_lowercase(symbol, nlen, lc);
    uint32_t h = svm_fnv1a32(lc, nlen);
    if (heap) {
        svm_secure_zero(heap, nlen);
        free(heap);
    }

    uint32_t off;
    if (!svm_entry_lookup(vm, h, &off)) return SVM_E_BAD_SYMBOL;
    if ((size_t)off >= vm->code_len) return SVM_E_BAD_PC;

    memset(vm->regs, 0, sizeof(vm->regs));
    memset(vm->mem, 0, SVM_STACK);
    vm->flags = 0;

    size_t n = argc < 6 ? argc : 6;
    for (size_t i = 0; i < n; i++) vm->regs[i] = argv[i];

    vm->regs[31] = (int64_t)SVM_STACK;
    uint64_t sp = (uint64_t)vm->regs[31] - 8;
    if (sp + 8 > (uint64_t)SVM_STACK) return SVM_E_STACK;
    uint8_t *mp = vm->mem + sp;
    uint64_t sent = SVM_SENTINEL_RET;
    for (int i = 0; i < 8; i++) mp[i] = (uint8_t)(sent >> (i * 8));
    vm->regs[31] = (int64_t)sp;

    vm->pc = off;
    svm_hot_wake(vm);
    svm_status s = svm_dispatch(vm);
    svm_hot_rest(vm);
    if (s == SVM_OK && result) *result = vm->regs[0];
    return s;
}

SVM_EXPORT void svm_close(svm_ctx *vm) {
    if (!vm) return;
    if (vm->body) {
        svm_secure_zero(vm->body, vm->body_len);
        free(vm->body);
    }
    if (vm->mem) {
        svm_secure_zero(vm->mem, SVM_STACK);
        free(vm->mem);
    }
    svm_secure_zero(vm->kmaster, 32);
    svm_secure_zero(vm->kmaster_vault, 32);
    svm_secure_zero(vm->kmaster_pad, 32);
    svm_secure_zero(vm, sizeof(*vm));
    free(vm);
}

SVM_EXPORT const char *svm_strerror(svm_status s) {
    switch (s) {
        case SVM_OK:            return "ok";
        case SVM_E_BAD_MAGIC:   return "bad magic";
        case SVM_E_BAD_VERSION: return "bad version";
        case SVM_E_BAD_MAC:     return "bad mac";
        case SVM_E_BAD_SYMBOL:  return "bad symbol";
        case SVM_E_BAD_PC:      return "bad pc";
        case SVM_E_BAD_OPCODE:  return "bad opcode";
        case SVM_E_DIV_ZERO:    return "division by zero";
        case SVM_E_STACK:       return "stack bounds";
        case SVM_E_SYSCALL:     return "bad syscall";
        case SVM_E_HALT:        return "halt";
        case SVM_E_TAMPER:      return "tamper";
        case SVM_E_NOMEM:       return "out of memory";
        case SVM_E_NET:         return "network error";
        case SVM_E_SERVER:      return "server error";
        case SVM_E_ATTEST:      return "attestation error";
        case SVM_E_EXPIRED:     return "session expired";
        case SVM_E_SIG:         return "signature error";
    }
    return "unknown";
}

SVM_EXPORT void svm_session_zero(svm_session *s) {
    if (!s) return;
    svm_secure_zero(s, sizeof(*s));
}
