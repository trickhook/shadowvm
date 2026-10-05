#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "shadowvm_crypto.h"

#include "blake2s_internal.h"
#include "chacha20_internal.h"
#include "fnv_internal.h"
#include "pbkdf2_internal.h"
#include "poly1305_internal.h"

#if defined(__GNUC__) || defined(__clang__)
#define SVM_EXPORT __attribute__((visibility("default")))
#else
#define SVM_EXPORT
#endif

SVM_EXPORT void svm_xchacha20(const uint8_t key[32], const uint8_t nonce[24],
                              uint32_t counter, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t subkey[32];
    svm__hchacha20(key, nonce, subkey);
    uint8_t nonce12[12];
    nonce12[0] = 0; nonce12[1] = 0; nonce12[2] = 0; nonce12[3] = 0;
    for (uint32_t i = 0; i < 8u; i++) {
        nonce12[4 + i] = nonce[16 + i];
    }
    svm__chacha20_xor(subkey, counter, nonce12, in, out, len);
    for (uint32_t i = 0; i < 32u; i++) subkey[i] = 0;
    for (uint32_t i = 0; i < 12u; i++) nonce12[i] = 0;
}

SVM_EXPORT void svm_poly1305(const uint8_t key[32], const uint8_t *msg, size_t len,
                             uint8_t tag[16]) {
    svm__poly1305(key, msg, len, tag);
}

SVM_EXPORT int svm_poly1305_verify(const uint8_t key[32], const uint8_t *msg, size_t len,
                                   const uint8_t tag[16]) {
    return svm__poly1305_verify(key, msg, len, tag);
}

SVM_EXPORT void svm_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                                       const uint8_t *salt, size_t salt_len,
                                       uint32_t iters, uint8_t *out, size_t out_len) {
    svm__pbkdf2_hmac_sha256(password, password_len, salt, salt_len, iters, out, out_len);
}

SVM_EXPORT void svm_blake2s(const uint8_t *key, size_t key_len,
                            const uint8_t *in, size_t in_len,
                            uint8_t *out, size_t out_len) {
    svm__blake2s(key, key_len, in, in_len, out, out_len);
}

SVM_EXPORT uint32_t svm_fnv1a32(const uint8_t *data, size_t len) {
    return svm__fnv1a32(data, len);
}

SVM_EXPORT void svm_pc_mask(const uint8_t key[32], uint32_t pc, uint8_t out[4]) {
    uint8_t pc_le[4];
    pc_le[0] = (uint8_t)pc;
    pc_le[1] = (uint8_t)(pc >> 8);
    pc_le[2] = (uint8_t)(pc >> 16);
    pc_le[3] = (uint8_t)(pc >> 24);
    svm__blake2s(key, 32, pc_le, 4, out, 4);
}

SVM_EXPORT void svm_secure_zero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) {
        *vp++ = 0;
    }
}
