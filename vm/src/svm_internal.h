#ifndef SVM_INTERNAL_H
#define SVM_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "shadowvm.h"
#include "shadowvm_crypto.h"
#include "shadowvm_attest.h"

#define SVM_FLAG_ZF 0x1u
#define SVM_FLAG_SF 0x2u
#define SVM_FLAG_CF 0x4u
#define SVM_FLAG_OF 0x8u

#define SVM_SENTINEL_RET 0xDEADC0DEDEADC0DEULL

#define SVM_REAL_OPS 0x1C
#define SVM_VARIANT_LIMIT 0x70

struct svm_ctx {
    uint8_t kmaster[32];
    uint8_t kmaster_vault[32];
    uint8_t kmaster_pad[32];
    uint8_t *body;
    size_t body_len;
    uint32_t entry_off;
    uint32_t code_off;
    uint32_t data_off;
    uint32_t mask_off;
    uint32_t entry_count;
    const uint8_t *entry;
    const uint8_t *code;
    size_t code_len;
    const uint8_t *data;
    size_t data_len;
    const uint8_t *mask;
    uint8_t *mem;
    svm_syscall_fn syscalls[256];
    int64_t regs[SVM_NREG];
    uint32_t flags;
    uint32_t pc;
};

svm_status svm_dispatch(svm_ctx *vm);

svm_status svm_loader_open(const uint8_t *blob, size_t blob_len,
                           const uint8_t kmaster[32], svm_ctx **out,
                           int zero_kmaster);

int svm_hex_decode(const char *s, size_t slen, uint8_t *out, size_t out_len);
int svm_base64_decode(const char *s, size_t slen, uint8_t *out, size_t *inout_len);

int svm_json_find_string(const char *src, size_t len, const char *key,
                         const char **val, size_t *vlen);
int svm_json_find_int(const char *src, size_t len, const char *key, int64_t *val);

int svm_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t mlen,
                       const uint8_t pub[32]);

void svm_hot_wake(svm_ctx *vm);
void svm_hot_rest(svm_ctx *vm);

svm_status svm_antire_check(void);

void svm_unxor_pad(const uint8_t *ct, const uint8_t *pad_x, size_t n,
                   const uint8_t master[32], char *out);
#define SVM_UNXOR(name, buf) \
    svm_unxor_pad(OBF_##name, PAD_##name, OBF_##name##_LEN, SVM_OBF_MASTER, (buf))

#endif
