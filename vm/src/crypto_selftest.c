#ifdef SVM_CRYPTO_SELFTEST

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "shadowvm_crypto.h"

int svm_crypto_selftest(void);

static int bufcmp(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return 1;
    }
    return 0;
}

int svm_crypto_selftest(void) {
    static const uint8_t xkey[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };
    static const uint8_t xnonce[24] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,
        0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x58
    };
    static const char dhole_msg[] =
        "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, red dog, and whistling dog. "
        "It is about the size of a German shepherd but looks more like a long-legged fox. "
        "This highly elusive and skilled jumper is classified with wolves, coyotes, jackals, "
        "and foxes in the taxonomic family Canidae.";
    static const uint8_t xexpect16[16] = {
        0x7d,0x0a,0x2e,0x6b,0x7f,0x7c,0x65,0xa2,0x36,0x54,0x26,0x30,0x29,0x4e,0x06,0x3b
    };
    size_t msglen = sizeof(dhole_msg) - 1u;
    uint8_t ctbuf[320];
    uint8_t ptbuf[320];
    svm_xchacha20(xkey, xnonce, 1u, (const uint8_t *)dhole_msg, ctbuf, msglen);
    if (bufcmp(ctbuf, xexpect16, 16)) return 1;
    svm_xchacha20(xkey, xnonce, 1u, ctbuf, ptbuf, msglen);
    if (bufcmp(ptbuf, (const uint8_t *)dhole_msg, msglen)) return 2;

    static const uint8_t pkey[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    static const char pmsg[] = "Cryptographic Forum Research Group";
    static const uint8_t ptag_expect[16] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
    };
    uint8_t tag[16];
    svm_poly1305(pkey, (const uint8_t *)pmsg, sizeof(pmsg) - 1u, tag);
    if (bufcmp(tag, ptag_expect, 16)) return 3;
    if (!svm_poly1305_verify(pkey, (const uint8_t *)pmsg, sizeof(pmsg) - 1u, ptag_expect)) return 4;
    uint8_t badtag[16];
    for (uint32_t i = 0; i < 16u; i++) badtag[i] = ptag_expect[i];
    badtag[0] ^= 1u;
    if (svm_poly1305_verify(pkey, (const uint8_t *)pmsg, sizeof(pmsg) - 1u, badtag)) return 5;

    static const uint8_t pbkdf2_expect[32] = {
        0xc5,0xe4,0x78,0xd5,0x92,0x88,0xc8,0x41,0xaa,0x53,0x0d,0xb6,0x84,0x5c,0x4c,0x8d,
        0x96,0x28,0x93,0xa0,0x01,0xce,0x4e,0x11,0xa4,0x96,0x38,0x73,0xaa,0x98,0x13,0x4a
    };
    uint8_t pbkdf2_out[32];
    svm_pbkdf2_hmac_sha256((const uint8_t *)"password", 8u,
                           (const uint8_t *)"salt", 4u, 4096u, pbkdf2_out, 32);
    if (bufcmp(pbkdf2_out, pbkdf2_expect, 32)) return 6;

    static const uint8_t blake2s_expect[32] = {
        0x69,0x21,0x7a,0x30,0x79,0x90,0x80,0x94,0xe1,0x11,0x21,0xd0,0x42,0x35,0x4a,0x7c,
        0x1f,0x55,0xb6,0x48,0x2c,0xa1,0xa5,0x1e,0x1b,0x25,0x0d,0xfd,0x1e,0xd0,0xee,0xf9
    };
    uint8_t b2out[32];
    svm_blake2s(NULL, 0, NULL, 0, b2out, 32);
    if (bufcmp(b2out, blake2s_expect, 32)) return 7;

    uint32_t h = svm_fnv1a32((const uint8_t *)"hello", 5u);
    if (h != 0x4f9f2cabu) return 8;

    uint8_t mask[4];
    svm_pc_mask(xkey, 0x12345678u, mask);
    uint8_t mask_input[4] = { 0x78, 0x56, 0x34, 0x12 };
    uint8_t mask_check[4];
    svm_blake2s(xkey, 32u, mask_input, 4u, mask_check, 4u);
    if (bufcmp(mask, mask_check, 4)) return 9;

    uint8_t zbuf[16];
    for (uint32_t i = 0; i < 16u; i++) zbuf[i] = (uint8_t)(i + 1u);
    svm_secure_zero(zbuf, 16);
    for (uint32_t i = 0; i < 16u; i++) {
        if (zbuf[i] != 0u) return 10;
    }

    return 0;
}

#endif
