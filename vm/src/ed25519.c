#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "svm_internal.h"

typedef struct { uint64_t v[5]; } fe;

static const uint64_t MASK51 = ((uint64_t)1 << 51) - 1;

static void fe_zero(fe *r) { r->v[0] = r->v[1] = r->v[2] = r->v[3] = r->v[4] = 0; }
static void fe_one(fe *r)  { r->v[0] = 1; r->v[1] = r->v[2] = r->v[3] = r->v[4] = 0; }
static void fe_copy(fe *r, const fe *a) { for (int i=0;i<5;i++) r->v[i]=a->v[i]; }

static void fe_add(fe *r, const fe *a, const fe *b) {
    for (int i=0;i<5;i++) r->v[i] = a->v[i] + b->v[i];
}

static void fe_sub(fe *r, const fe *a, const fe *b) {
    uint64_t t0 = a->v[0] + 0xFFFFFFFFFFFDAULL - b->v[0];
    uint64_t t1 = a->v[1] + 0xFFFFFFFFFFFFEULL - b->v[1];
    uint64_t t2 = a->v[2] + 0xFFFFFFFFFFFFEULL - b->v[2];
    uint64_t t3 = a->v[3] + 0xFFFFFFFFFFFFEULL - b->v[3];
    uint64_t t4 = a->v[4] + 0xFFFFFFFFFFFFEULL - b->v[4];
    r->v[0]=t0; r->v[1]=t1; r->v[2]=t2; r->v[3]=t3; r->v[4]=t4;
}

static void fe_carry(fe *r) {
    uint64_t c;
    c = r->v[0] >> 51; r->v[0] &= MASK51; r->v[1] += c;
    c = r->v[1] >> 51; r->v[1] &= MASK51; r->v[2] += c;
    c = r->v[2] >> 51; r->v[2] &= MASK51; r->v[3] += c;
    c = r->v[3] >> 51; r->v[3] &= MASK51; r->v[4] += c;
    c = r->v[4] >> 51; r->v[4] &= MASK51; r->v[0] += c * 19;
    c = r->v[0] >> 51; r->v[0] &= MASK51; r->v[1] += c;
}

static void fe_mul(fe *r, const fe *a, const fe *b) {
    __uint128_t t0,t1,t2,t3,t4;
    uint64_t a0=a->v[0], a1=a->v[1], a2=a->v[2], a3=a->v[3], a4=a->v[4];
    uint64_t b0=b->v[0], b1=b->v[1], b2=b->v[2], b3=b->v[3], b4=b->v[4];
    uint64_t b1_19=b1*19, b2_19=b2*19, b3_19=b3*19, b4_19=b4*19;

    t0 = (__uint128_t)a0*b0 + (__uint128_t)a1*b4_19 + (__uint128_t)a2*b3_19 + (__uint128_t)a3*b2_19 + (__uint128_t)a4*b1_19;
    t1 = (__uint128_t)a0*b1 + (__uint128_t)a1*b0 + (__uint128_t)a2*b4_19 + (__uint128_t)a3*b3_19 + (__uint128_t)a4*b2_19;
    t2 = (__uint128_t)a0*b2 + (__uint128_t)a1*b1 + (__uint128_t)a2*b0 + (__uint128_t)a3*b4_19 + (__uint128_t)a4*b3_19;
    t3 = (__uint128_t)a0*b3 + (__uint128_t)a1*b2 + (__uint128_t)a2*b1 + (__uint128_t)a3*b0 + (__uint128_t)a4*b4_19;
    t4 = (__uint128_t)a0*b4 + (__uint128_t)a1*b3 + (__uint128_t)a2*b2 + (__uint128_t)a3*b1 + (__uint128_t)a4*b0;

    uint64_t c;
    r->v[0] = (uint64_t)(t0 & MASK51); c = (uint64_t)(t0 >> 51); t1 += c;
    r->v[1] = (uint64_t)(t1 & MASK51); c = (uint64_t)(t1 >> 51); t2 += c;
    r->v[2] = (uint64_t)(t2 & MASK51); c = (uint64_t)(t2 >> 51); t3 += c;
    r->v[3] = (uint64_t)(t3 & MASK51); c = (uint64_t)(t3 >> 51); t4 += c;
    r->v[4] = (uint64_t)(t4 & MASK51); c = (uint64_t)(t4 >> 51); r->v[0] += c * 19;
    c = r->v[0] >> 51; r->v[0] &= MASK51; r->v[1] += c;
}

static void fe_sq(fe *r, const fe *a) { fe_mul(r, a, a); }

static void fe_pow(fe *r, const fe *a, const uint8_t *exp, int bits) {
    fe acc;
    fe_one(&acc);
    for (int i = bits - 1; i >= 0; i--) {
        fe_sq(&acc, &acc);
        if ((exp[i >> 3] >> (i & 7)) & 1) fe_mul(&acc, &acc, a);
    }
    fe_copy(r, &acc);
}

static void fe_invert(fe *r, const fe *a) {
    static const uint8_t e[32] = {
        0xeb,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f
    };
    fe_pow(r, a, e, 255);
}

static void fe_pow22523(fe *r, const fe *a) {
    static const uint8_t e[32] = {
        0xfd,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x0f
    };
    fe_pow(r, a, e, 253);
}

static void fe_tobytes(uint8_t s[32], const fe *a) {
    fe t;
    fe_copy(&t, a);
    fe_carry(&t);
    fe_carry(&t);
    fe_carry(&t);
    uint64_t h0=t.v[0]+19, h1=t.v[1]+(h0>>51); h0 &= MASK51;
    uint64_t h2=t.v[2]+(h1>>51); h1 &= MASK51;
    uint64_t h3=t.v[3]+(h2>>51); h2 &= MASK51;
    uint64_t h4=t.v[4]+(h3>>51); h3 &= MASK51;
    uint64_t q = h4 >> 51; h4 &= MASK51;
    (void)q;
    h0 = t.v[0] + 19 * (h4 >> 51 ? 1 : 0);
    uint64_t a0=t.v[0], a1=t.v[1], a2=t.v[2], a3=t.v[3], a4=t.v[4];
    uint64_t c;
    a0 += 19;
    c = a0 >> 51; a0 &= MASK51; a1 += c;
    c = a1 >> 51; a1 &= MASK51; a2 += c;
    c = a2 >> 51; a2 &= MASK51; a3 += c;
    c = a3 >> 51; a3 &= MASK51; a4 += c;
    uint64_t carry = a4 >> 51;
    a4 &= MASK51;
    if (carry) {
        a0 = t.v[0] + 19;
        c = a0 >> 51; a0 &= MASK51; a1 = t.v[1] + c;
        c = a1 >> 51; a1 &= MASK51; a2 = t.v[2] + c;
        c = a2 >> 51; a2 &= MASK51; a3 = t.v[3] + c;
        c = a3 >> 51; a3 &= MASK51; a4 = t.v[4] + c;
        a4 &= MASK51;
    } else {
        a0 = t.v[0]; a1 = t.v[1]; a2 = t.v[2]; a3 = t.v[3]; a4 = t.v[4];
    }
    uint64_t out[4];
    out[0] = a0 | (a1 << 51);
    out[1] = (a1 >> 13) | (a2 << 38);
    out[2] = (a2 >> 26) | (a3 << 25);
    out[3] = (a3 >> 39) | (a4 << 12);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            s[i * 8 + j] = (uint8_t)(out[i] >> (j * 8));
    s[31] &= 0x7F;
}

static void fe_frombytes(fe *r, const uint8_t s[32]) {
    uint64_t h[4];
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v |= (uint64_t)s[i * 8 + j] << (j * 8);
        h[i] = v;
    }
    r->v[0] = h[0] & MASK51;
    r->v[1] = (h[0] >> 51 | h[1] << 13) & MASK51;
    r->v[2] = (h[1] >> 38 | h[2] << 26) & MASK51;
    r->v[3] = (h[2] >> 25 | h[3] << 39) & MASK51;
    r->v[4] = (h[3] >> 12) & MASK51 & (((uint64_t)1 << 51) - 1);
    r->v[4] &= ((uint64_t)1 << 51) - 1;
}

static int fe_isnegative(const fe *a) {
    uint8_t s[32];
    fe_tobytes(s, a);
    return s[0] & 1;
}

static int fe_isnonzero(const fe *a) {
    uint8_t s[32];
    fe_tobytes(s, a);
    uint8_t r = 0;
    for (int i = 0; i < 32; i++) r |= s[i];
    return r != 0;
}

static void fe_neg(fe *r, const fe *a) {
    fe z; fe_zero(&z);
    fe_sub(r, &z, a);
}

typedef struct { fe X, Y, Z, T; } ge;

static const uint8_t D_BYTES[32] = {
    0xa3,0x78,0x59,0x13,0xca,0x4d,0xeb,0x75,
    0xab,0xd8,0x41,0x41,0x4d,0x0a,0x70,0x00,
    0x98,0xe8,0x79,0x77,0x94,0x0c,0x78,0xc7,
    0x3f,0xe6,0xf2,0xbe,0xe6,0xc0,0x35,0x52
};

static const uint8_t SQRTM1_BYTES[32] = {
    0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,
    0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
    0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,
    0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b
};

static const uint8_t BX_BYTES[32] = {
    0x1a,0xd5,0x25,0x8f,0x60,0x2d,0x56,0xc9,
    0xb2,0xa7,0x25,0x95,0x60,0xc7,0x2c,0x69,
    0x5c,0xdc,0xd6,0xfd,0x31,0xe2,0xa4,0xc0,
    0xfe,0x53,0x6e,0xcd,0xd3,0x36,0x69,0x21
};

static const uint8_t BY_BYTES[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
};

static void ge_zero(ge *r) {
    fe_zero(&r->X);
    fe_one(&r->Y);
    fe_one(&r->Z);
    fe_zero(&r->T);
}

static int ge_decompress(ge *r, const uint8_t s[32]) {
    uint8_t s2[32];
    memcpy(s2, s, 32);
    int sign = (s2[31] >> 7) & 1;
    s2[31] &= 0x7F;
    fe y;
    fe_frombytes(&y, s2);
    fe u, v, D;
    fe_frombytes(&D, D_BYTES);
    fe_sq(&u, &y);
    fe one; fe_one(&one);
    fe v_tmp;
    fe_mul(&v_tmp, &u, &D);
    fe_sub(&u, &u, &one);
    fe_add(&v, &v_tmp, &one);
    fe v3, v7;
    fe_sq(&v3, &v);
    fe_mul(&v3, &v3, &v);
    fe_sq(&v7, &v3);
    fe_mul(&v7, &v7, &v);
    fe x;
    fe_mul(&x, &u, &v7);
    fe_pow22523(&x, &x);
    fe_mul(&x, &x, &v3);
    fe_mul(&x, &x, &u);

    fe vxx, chk, sqrtm1, x2;
    fe_sq(&vxx, &x);
    fe_mul(&vxx, &vxx, &v);
    fe_sub(&chk, &vxx, &u);
    if (fe_isnonzero(&chk)) {
        fe_add(&chk, &vxx, &u);
        if (fe_isnonzero(&chk)) return 0;
        fe_frombytes(&sqrtm1, SQRTM1_BYTES);
        fe_mul(&x2, &x, &sqrtm1);
        fe_copy(&x, &x2);
    }
    if (fe_isnegative(&x) != sign) {
        if (!fe_isnonzero(&x) && sign) return 0;
        fe nx;
        fe_neg(&nx, &x);
        fe_copy(&x, &nx);
    }
    fe_copy(&r->X, &x);
    fe_copy(&r->Y, &y);
    fe_one(&r->Z);
    fe_mul(&r->T, &x, &y);
    return 1;
}

static void ge_double(ge *r, const ge *p) {
    fe A, B, C, E, G, F, H, xpy;
    fe_sq(&A, &p->X);
    fe_sq(&B, &p->Y);
    fe_sq(&C, &p->Z);
    fe_add(&C, &C, &C);
    fe_add(&H, &A, &B);
    fe_add(&xpy, &p->X, &p->Y);
    fe_sq(&E, &xpy);
    fe_sub(&E, &H, &E);
    fe_sub(&G, &A, &B);
    fe_add(&F, &C, &G);
    fe_mul(&r->X, &E, &F);
    fe_mul(&r->Y, &G, &H);
    fe_mul(&r->T, &E, &H);
    fe_mul(&r->Z, &F, &G);
    fe_carry(&r->X); fe_carry(&r->Y); fe_carry(&r->Z); fe_carry(&r->T);
}

static void ge_add(ge *r, const ge *p, const ge *q) {
    fe A, B, C, D, E, F, G, H, tmp1, tmp2, two_d;
    fe_frombytes(&two_d, D_BYTES);
    fe_add(&two_d, &two_d, &two_d);
    fe_sub(&tmp1, &p->Y, &p->X);
    fe_sub(&tmp2, &q->Y, &q->X);
    fe_mul(&A, &tmp1, &tmp2);
    fe_add(&tmp1, &p->Y, &p->X);
    fe_add(&tmp2, &q->Y, &q->X);
    fe_mul(&B, &tmp1, &tmp2);
    fe_mul(&C, &p->T, &q->T);
    fe_mul(&C, &C, &two_d);
    fe_mul(&D, &p->Z, &q->Z);
    fe_add(&D, &D, &D);
    fe_sub(&E, &B, &A);
    fe_sub(&F, &D, &C);
    fe_add(&G, &D, &C);
    fe_add(&H, &B, &A);
    fe_mul(&r->X, &E, &F);
    fe_mul(&r->Y, &G, &H);
    fe_mul(&r->T, &E, &H);
    fe_mul(&r->Z, &F, &G);
    fe_carry(&r->X); fe_carry(&r->Y); fe_carry(&r->Z); fe_carry(&r->T);
}

static void ge_scalarmult(ge *r, const uint8_t *scalar, size_t scalar_bits,
                          const ge *p) {
    ge acc;
    ge_zero(&acc);
    for (int i = (int)scalar_bits - 1; i >= 0; i--) {
        ge_double(&acc, &acc);
        if ((scalar[i >> 3] >> (i & 7)) & 1) {
            ge_add(&acc, &acc, p);
        }
    }
    *r = acc;
}

static void ge_tobytes(uint8_t s[32], const ge *p) {
    fe recip, x, y;
    fe_invert(&recip, &p->Z);
    fe_mul(&x, &p->X, &recip);
    fe_mul(&y, &p->Y, &recip);
    fe_tobytes(s, &y);
    s[31] ^= (uint8_t)(fe_isnegative(&x) << 7);
}

typedef struct {
    uint64_t h[8];
    uint64_t len;
    uint8_t buf[128];
    size_t off;
} sha512_ctx;

static const uint64_t K512[80] = {
    0x428A2F98D728AE22ULL,0x7137449123EF65CDULL,0xB5C0FBCFEC4D3B2FULL,0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL,0x59F111F1B605D019ULL,0x923F82A4AF194F9BULL,0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL,0x12835B0145706FBEULL,0x243185BE4EE4B28CULL,0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL,0x80DEB1FE3B1696B1ULL,0x9BDC06A725C71235ULL,0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL,0xEFBE4786384F25E3ULL,0x0FC19DC68B8CD5B5ULL,0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL,0x4A7484AA6EA6E483ULL,0x5CB0A9DCBD41FBD4ULL,0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL,0xA831C66D2DB43210ULL,0xB00327C898FB213FULL,0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL,0xD5A79147930AA725ULL,0x06CA6351E003826FULL,0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL,0x2E1B21385C26C926ULL,0x4D2C6DFC5AC42AEDULL,0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL,0x766A0ABB3C77B2A8ULL,0x81C2C92E47EDAEE6ULL,0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL,0xA81A664BBC423001ULL,0xC24B8B70D0F89791ULL,0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL,0xD69906245565A910ULL,0xF40E35855771202AULL,0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL,0x1E376C085141AB53ULL,0x2748774CDF8EEB99ULL,0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL,0x4ED8AA4AE3418ACBULL,0x5B9CCA4F7763E373ULL,0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL,0x78A5636F43172F60ULL,0x84C87814A1F0AB72ULL,0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL,0xA4506CEBDE82BDE9ULL,0xBEF9A3F7B2C67915ULL,0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL,0xD186B8C721C0C207ULL,0xEADA7DD6CDE0EB1EULL,0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL,0x0A637DC5A2C898A6ULL,0x113F9804BEF90DAEULL,0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL,0x32CAAB7B40C72493ULL,0x3C9EBE0A15C9BEBCULL,0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL,0x597F299CFC657E2AULL,0x5FCB6FAB3AD6FAECULL,0x6C44198C4A475817ULL
};

static uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512_compress(sha512_ctx *c, const uint8_t block[128]) {
    uint64_t W[80];
    for (int i = 0; i < 16; i++) {
        W[i] = 0;
        for (int j = 0; j < 8; j++) W[i] = (W[i] << 8) | block[i * 8 + j];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = rotr64(W[i-15],1) ^ rotr64(W[i-15],8) ^ (W[i-15] >> 7);
        uint64_t s1 = rotr64(W[i-2],19) ^ rotr64(W[i-2],61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    uint64_t a=c->h[0],b=c->h[1],d=c->h[2],e=c->h[3],f=c->h[4],g=c->h[5],hh=c->h[6],ii=c->h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = rotr64(f,14) ^ rotr64(f,18) ^ rotr64(f,41);
        uint64_t ch = (f & g) ^ ((~f) & hh);
        uint64_t t1 = ii + S1 + ch + K512[i] + W[i];
        uint64_t S0 = rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39);
        uint64_t mj = (a & b) ^ (a & d) ^ (b & d);
        uint64_t t2 = S0 + mj;
        ii = hh; hh = g; g = f; f = e + t1; e = d; d = b; b = a; a = t1 + t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=d; c->h[3]+=e;
    c->h[4]+=f; c->h[5]+=g; c->h[6]+=hh; c->h[7]+=ii;
}

static void sha512_init(sha512_ctx *c) {
    static const uint64_t iv[8] = {
        0x6A09E667F3BCC908ULL,0xBB67AE8584CAA73BULL,0x3C6EF372FE94F82BULL,0xA54FF53A5F1D36F1ULL,
        0x510E527FADE682D1ULL,0x9B05688C2B3E6C1FULL,0x1F83D9ABFB41BD6BULL,0x5BE0CD19137E2179ULL
    };
    for (int i = 0; i < 8; i++) c->h[i] = iv[i];
    c->len = 0;
    c->off = 0;
}

static void sha512_update(sha512_ctx *c, const uint8_t *data, size_t n) {
    c->len += n;
    while (n > 0) {
        size_t t = 128 - c->off;
        if (t > n) t = n;
        memcpy(c->buf + c->off, data, t);
        c->off += t;
        data += t;
        n -= t;
        if (c->off == 128) {
            sha512_compress(c, c->buf);
            c->off = 0;
        }
    }
}

static void sha512_final(sha512_ctx *c, uint8_t out[64]) {
    uint64_t bits = c->len * 8;
    c->buf[c->off++] = 0x80;
    if (c->off > 112) {
        memset(c->buf + c->off, 0, 128 - c->off);
        sha512_compress(c, c->buf);
        c->off = 0;
    }
    memset(c->buf + c->off, 0, 112 - c->off);
    memset(c->buf + 112, 0, 8);
    for (int i = 0; i < 8; i++) c->buf[127 - i] = (uint8_t)(bits >> (i * 8));
    sha512_compress(c, c->buf);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t)(c->h[i] >> ((7 - j) * 8));
}

static const uint8_t L_BYTES[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
    0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
};

static int sc_lt_L(const uint8_t s[32]) {
    for (int i = 31; i >= 0; i--) {
        if (s[i] < L_BYTES[i]) return 1;
        if (s[i] > L_BYTES[i]) return 0;
    }
    return 0;
}

static void sc_reduce(uint8_t s[32], const uint8_t in[64]) {
    uint32_t t[64];
    for (int i = 0; i < 64; i++) t[i] = in[i];
    for (int iter = 0; iter < 2; iter++) {
        for (int i = 63; i >= 32; i--) {
            uint32_t v = t[i];
            if (!v) continue;
            t[i] = 0;
            uint64_t ll[32];
            for (int k = 0; k < 32; k++) ll[k] = (uint64_t)v * L_BYTES[k];
            int base = i - 32;
            uint64_t carry = 0;
            for (int k = 0; k < 32 && base + k < 64; k++) {
                uint64_t x = (uint64_t)t[base + k] + ll[k] + carry;
                carry = x >> 8;
                t[base + k] = (uint32_t)(x & 0xFF);
            }
            if (base + 32 < 64) {
                uint64_t x = (uint64_t)t[base + 32] + carry;
                carry = x >> 8;
                t[base + 32] = (uint32_t)(x & 0xFF);
            }
        }
    }
    uint8_t out[32];
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)t[i];
    while (!sc_lt_L(out)) {
        uint32_t borrow = 0;
        for (int i = 0; i < 32; i++) {
            int32_t v = (int32_t)out[i] - (int32_t)L_BYTES[i] - (int32_t)borrow;
            borrow = (v < 0) ? 1 : 0;
            out[i] = (uint8_t)(v & 0xFF);
        }
    }
    memcpy(s, out, 32);
}

int svm_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t mlen,
                       const uint8_t pub[32]) {
    if (sig[63] & 0xE0) return 0;
    uint8_t s_sc[32];
    memcpy(s_sc, sig + 32, 32);
    if (!sc_lt_L(s_sc)) return 0;

    ge A;
    uint8_t pub_neg[32];
    memcpy(pub_neg, pub, 32);
    pub_neg[31] ^= 0x80;
    if (!ge_decompress(&A, pub_neg)) return 0;

    sha512_ctx c;
    sha512_init(&c);
    sha512_update(&c, sig, 32);
    sha512_update(&c, pub, 32);
    sha512_update(&c, msg, mlen);
    uint8_t h_full[64];
    sha512_final(&c, h_full);

    uint8_t h_sc[32];
    sc_reduce(h_sc, h_full);

    ge B, sB, hA, R_calc;
    if (!ge_decompress(&B, BY_BYTES)) return 0;
    (void)BX_BYTES;

    ge_scalarmult(&sB, s_sc, 256, &B);
    ge_scalarmult(&hA, h_sc, 256, &A);
    ge_add(&R_calc, &sB, &hA);

    uint8_t r_bytes[32];
    ge_tobytes(r_bytes, &R_calc);

    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= r_bytes[i] ^ sig[i];
    return diff == 0;
}
