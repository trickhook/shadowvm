#ifndef SHADOWVM_H
#define SHADOWVM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SVM_MAGIC    0x314d5653u
#define SVM_VERSION  0x0001
#define SVM_HDR_SIZE 32
#define SVM_MAC_SIZE 16
#define SVM_NREG     32
#define SVM_STACK    4096

#define SVM_FLAG_ANTI_DEBUG  0x0001
#define SVM_FLAG_STRIP_NAMES 0x0002

typedef enum {
    SVM_OK            = 0,
    SVM_E_BAD_MAGIC   = -1,
    SVM_E_BAD_VERSION = -2,
    SVM_E_BAD_MAC     = -3,
    SVM_E_BAD_SYMBOL  = -4,
    SVM_E_BAD_PC      = -5,
    SVM_E_BAD_OPCODE  = -6,
    SVM_E_DIV_ZERO    = -7,
    SVM_E_STACK       = -8,
    SVM_E_SYSCALL     = -9,
    SVM_E_HALT        = -10,
    SVM_E_TAMPER      = -11,
    SVM_E_NOMEM       = -12,
    SVM_E_NET         = -20,
    SVM_E_SERVER      = -21,
    SVM_E_ATTEST      = -22,
    SVM_E_EXPIRED     = -23,
    SVM_E_SIG         = -24
} svm_status;

typedef struct svm_ctx svm_ctx;

typedef int64_t (*svm_syscall_fn)(svm_ctx *vm, int64_t a0, int64_t a1,
                                  int64_t a2, int64_t a3, int64_t a4, int64_t a5);

typedef struct {
    const char *server_url;
    const char *blob_id;
    const char *loader_id;
    const uint8_t *k_hmac;
    size_t k_hmac_len;
    const uint8_t *k_sign_pub;
    size_t k_sign_pub_len;
    const uint8_t *device_fp;
    size_t device_fp_len;
} svm_remote_cfg;

svm_ctx *svm_open_remote(const svm_remote_cfg *cfg, svm_status *status);

svm_ctx *svm_open_local(const uint8_t *blob, size_t blob_len,
                        const char *password, size_t password_len,
                        svm_status *status);

void svm_set_syscall(svm_ctx *vm, uint32_t idx, svm_syscall_fn fn);

svm_status svm_run(svm_ctx *vm, const char *symbol,
                   const int64_t *argv, size_t argc, int64_t *result);

void svm_close(svm_ctx *vm);

const char *svm_strerror(svm_status s);

#ifdef __cplusplus
}
#endif

#endif
