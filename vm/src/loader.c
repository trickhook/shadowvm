#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "svm_internal.h"

static uint32_t svm_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t svm_rd16(const uint8_t *p) {
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

static int svm_bounds_check(size_t total, size_t off, size_t len) {
    if (off > total) return 0;
    if (total - off < len) return 0;
    return 1;
}

svm_status svm_loader_open(const uint8_t *blob, size_t blob_len,
                           const uint8_t kmaster[32], svm_ctx **out,
                           int zero_kmaster) {
    *out = NULL;

    if (blob_len < (size_t)SVM_HDR_SIZE + SVM_MAC_SIZE) return SVM_E_BAD_MAGIC;

    uint32_t magic = svm_rd32(blob + 0);
    if (magic != SVM_MAGIC) return SVM_E_BAD_MAGIC;

    uint16_t version = svm_rd16(blob + 4);
    if (version != SVM_VERSION) return SVM_E_BAD_VERSION;

    uint32_t body_len = svm_rd32(blob + 8);
    uint32_t entry_off = svm_rd32(blob + 12);
    uint32_t code_off = svm_rd32(blob + 16);
    uint32_t data_off = svm_rd32(blob + 20);
    uint32_t mask_off = svm_rd32(blob + 24);

    if ((size_t)SVM_HDR_SIZE + (size_t)body_len + (size_t)SVM_MAC_SIZE != blob_len)
        return SVM_E_BAD_MAC;

    const uint8_t *body_ct = blob + SVM_HDR_SIZE;
    const uint8_t *mac = blob + SVM_HDR_SIZE + body_len;

    uint8_t kauth_input[36];
    memcpy(kauth_input, kmaster, 32);
    memcpy(kauth_input + 32, "auth", 4);
    uint8_t kauth[32];
    svm_blake2s(NULL, 0, kauth_input, 36, kauth, 32);

    size_t mac_in_len = (size_t)SVM_HDR_SIZE + body_len;
    uint8_t *mac_in = (uint8_t *)malloc(mac_in_len);
    if (!mac_in) {
        svm_secure_zero(kauth, 32);
        svm_secure_zero(kauth_input, 36);
        return SVM_E_NOMEM;
    }
    memcpy(mac_in, blob, mac_in_len);
    int ok = svm_poly1305_verify(kauth, mac_in, mac_in_len, mac);
    free(mac_in);
    svm_secure_zero(kauth, 32);
    svm_secure_zero(kauth_input, 36);
    if (!ok) return SVM_E_BAD_MAC;

    uint8_t nonce_input[8];
    memcpy(nonce_input, blob, 4);
    memcpy(nonce_input + 4, blob + 8, 4);
    uint8_t nonce[24];
    svm_blake2s(NULL, 0, nonce_input, 8, nonce, 24);

    uint8_t *body = (uint8_t *)malloc(body_len);
    if (!body) return SVM_E_NOMEM;
    svm_xchacha20(kmaster, nonce, 0, body_ct, body, body_len);

    svm_secure_zero(nonce, 24);
    svm_secure_zero(nonce_input, 8);

    if (!svm_bounds_check(body_len, entry_off, 4) ||
        !svm_bounds_check(body_len, mask_off, 1024)) {
        svm_secure_zero(body, body_len);
        free(body);
        return SVM_E_TAMPER;
    }

    uint32_t entry_count = svm_rd32(body + entry_off);
    if (!svm_bounds_check(body_len, entry_off + 4, (size_t)entry_count * 8)) {
        svm_secure_zero(body, body_len);
        free(body);
        return SVM_E_TAMPER;
    }

    size_t code_len = 0;
    if (code_off > body_len) {
        svm_secure_zero(body, body_len);
        free(body);
        return SVM_E_TAMPER;
    }
    if (data_off >= code_off && data_off <= body_len) {
        code_len = (size_t)data_off - (size_t)code_off;
    } else if (mask_off >= code_off && mask_off <= body_len) {
        code_len = (size_t)mask_off - (size_t)code_off;
    } else {
        code_len = (size_t)body_len - (size_t)code_off;
    }

    size_t data_len = 0;
    if (data_off > body_len) {
        svm_secure_zero(body, body_len);
        free(body);
        return SVM_E_TAMPER;
    }
    if (mask_off >= data_off && mask_off <= body_len) {
        data_len = (size_t)mask_off - (size_t)data_off;
    } else {
        data_len = (size_t)body_len - (size_t)data_off;
    }

    svm_ctx *vm = (svm_ctx *)calloc(1, sizeof(*vm));
    if (!vm) {
        svm_secure_zero(body, body_len);
        free(body);
        return SVM_E_NOMEM;
    }

    vm->mem = (uint8_t *)calloc(1, SVM_STACK);
    if (!vm->mem) {
        free(vm);
        svm_secure_zero(body, body_len);
        free(body);
        return SVM_E_NOMEM;
    }

    memcpy(vm->kmaster, kmaster, 32);
    vm->body = body;
    vm->body_len = body_len;
    vm->entry_off = entry_off;
    vm->code_off = code_off;
    vm->data_off = data_off;
    vm->mask_off = mask_off;
    vm->entry_count = entry_count;
    vm->entry = body + entry_off + 4;
    vm->code = body + code_off;
    vm->code_len = code_len;
    vm->data = body + data_off;
    vm->data_len = data_len;
    vm->mask = body + mask_off;

    if (body_len >= 16) {
        svm_secure_zero(body, 16);
    }

    (void)zero_kmaster;

    *out = vm;
    return SVM_OK;
}
