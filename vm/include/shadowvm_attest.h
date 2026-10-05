#ifndef SHADOWVM_ATTEST_H
#define SHADOWVM_ATTEST_H

#include <stddef.h>
#include <stdint.h>

#include "shadowvm.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t session_id[16];
    uint8_t session_key[32];
    uint8_t blob_nonce[24];
    uint64_t expires_unix_ms;
} svm_session;

svm_status svm_attest(const svm_remote_cfg *cfg, svm_session *out_session,
                      uint8_t **out_blob, size_t *out_blob_len);

void svm_session_zero(svm_session *s);

#ifdef __cplusplus
}
#endif

#endif
