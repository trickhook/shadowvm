#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "svm_internal.h"
#include "hmac_sha256_internal.h"

#define SVM_EXPORT __attribute__((visibility("default")))

#ifdef SHADOWVM_USE_CURL
#include <curl/curl.h>

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} svm_buf;

static size_t svm_curl_write(void *ptr, size_t sz, size_t nm, void *ud) {
    svm_buf *b = (svm_buf *)ud;
    size_t n = sz * nm;
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 256;
        while (nc < b->len + n) nc *= 2;
        uint8_t *np = (uint8_t *)realloc(b->data, nc);
        if (!np) return 0;
        b->data = np;
        b->cap = nc;
    }
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    return n;
}

static int svm_http_post(const char *url, const char *body, size_t body_len,
                         uint8_t **out, size_t *out_len) {
    CURL *c = curl_easy_init();
    if (!c) return 0;
    svm_buf b;
    b.data = NULL; b.len = 0; b.cap = 0;
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)body_len);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, svm_curl_write);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &b);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    CURLcode rc = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    if (rc != CURLE_OK || code < 200 || code >= 300) {
        free(b.data);
        return 0;
    }
    *out = b.data;
    *out_len = b.len;
    return 1;
}
#else
static int svm_http_post(const char *url, const char *body, size_t body_len,
                         uint8_t **out, size_t *out_len) {
    (void)url; (void)body; (void)body_len; (void)out; (void)out_len;
    return 0;
}
#endif

static void svm_hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char tab[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = tab[in[i] >> 4];
        out[i * 2 + 1] = tab[in[i] & 0xF];
    }
    out[len * 2] = 0;
}

static int svm_random(uint8_t *buf, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t r = fread(buf, 1, n, f);
    fclose(f);
    return r == n;
}

SVM_EXPORT svm_status svm_attest(const svm_remote_cfg *cfg, svm_session *out_session,
                                 uint8_t **out_blob, size_t *out_blob_len) {
    if (!cfg || !out_session || !out_blob || !out_blob_len) return SVM_E_ATTEST;
    if (!cfg->server_url || !cfg->blob_id || !cfg->loader_id ||
        !cfg->k_hmac || cfg->k_hmac_len != 32 ||
        !cfg->k_sign_pub || cfg->k_sign_pub_len != 32 ||
        !cfg->device_fp || cfg->device_fp_len != 32)
        return SVM_E_ATTEST;

    *out_blob = NULL;
    *out_blob_len = 0;

    uint8_t nonce_c[16];
    if (!svm_random(nonce_c, 16)) return SVM_E_ATTEST;

    char nonce_c_hex[33];
    svm_hex_encode(nonce_c, 16, nonce_c_hex);
    char device_fp_hex[65];
    svm_hex_encode(cfg->device_fp, 32, device_fp_hex);

    char url1[1024];
    int ul = snprintf(url1, sizeof(url1), "%s/v1/session/challenge", cfg->server_url);
    if (ul < 0 || (size_t)ul >= sizeof(url1)) return SVM_E_ATTEST;

    char body1[2048];
    int bl = snprintf(body1, sizeof(body1),
        "{\"blob_id\":\"%s\",\"loader_id\":\"%s\",\"device_fp\":\"%s\",\"nonce_c\":\"%s\"}",
        cfg->blob_id, cfg->loader_id, device_fp_hex, nonce_c_hex);
    if (bl < 0 || (size_t)bl >= sizeof(body1)) return SVM_E_ATTEST;

    uint8_t *resp1 = NULL;
    size_t resp1_len = 0;
    if (!svm_http_post(url1, body1, (size_t)bl, &resp1, &resp1_len)) {
        return SVM_E_NET;
    }

    const char *challenge_id_s, *nonce_s_hex_s;
    size_t challenge_id_len, nonce_s_hex_len;
    if (!svm_json_find_string((const char *)resp1, resp1_len, "challenge_id",
                              &challenge_id_s, &challenge_id_len) ||
        !svm_json_find_string((const char *)resp1, resp1_len, "nonce_s",
                              &nonce_s_hex_s, &nonce_s_hex_len)) {
        free(resp1);
        return SVM_E_SERVER;
    }

    uint8_t nonce_s[16];
    if (nonce_s_hex_len != 32 || !svm_hex_decode(nonce_s_hex_s, nonce_s_hex_len, nonce_s, 16)) {
        free(resp1);
        return SVM_E_SERVER;
    }

    size_t prefix_len = 14;
    size_t blob_id_len = strlen(cfg->blob_id);
    size_t loader_id_len = strlen(cfg->loader_id);
    size_t pin_len = prefix_len + blob_id_len + loader_id_len + 32 + 16 + 16;
    uint8_t *pin = (uint8_t *)malloc(pin_len);
    if (!pin) { free(resp1); return SVM_E_NOMEM; }
    size_t po = 0;
    memcpy(pin + po, "svm-attest|v1|", 14); po += 14;
    memcpy(pin + po, cfg->blob_id, blob_id_len); po += blob_id_len;
    memcpy(pin + po, cfg->loader_id, loader_id_len); po += loader_id_len;
    memcpy(pin + po, cfg->device_fp, 32); po += 32;
    memcpy(pin + po, nonce_c, 16); po += 16;
    memcpy(pin + po, nonce_s, 16); po += 16;

    uint8_t proof[32];
    svm__hmac_sha256(cfg->k_hmac, cfg->k_hmac_len, pin, pin_len, proof);
    svm_secure_zero(pin, pin_len);
    free(pin);

    char proof_hex[65];
    svm_hex_encode(proof, 32, proof_hex);

    char challenge_id_c[128];
    if (challenge_id_len >= sizeof(challenge_id_c)) {
        free(resp1);
        return SVM_E_SERVER;
    }
    memcpy(challenge_id_c, challenge_id_s, challenge_id_len);
    challenge_id_c[challenge_id_len] = 0;

    free(resp1);

    char url2[1024];
    ul = snprintf(url2, sizeof(url2), "%s/v1/session/complete", cfg->server_url);
    if (ul < 0 || (size_t)ul >= sizeof(url2)) return SVM_E_ATTEST;

    char body2[1024];
    bl = snprintf(body2, sizeof(body2),
        "{\"challenge_id\":\"%s\",\"proof\":\"%s\"}", challenge_id_c, proof_hex);
    if (bl < 0 || (size_t)bl >= sizeof(body2)) return SVM_E_ATTEST;

    uint8_t *resp2 = NULL;
    size_t resp2_len = 0;
    if (!svm_http_post(url2, body2, (size_t)bl, &resp2, &resp2_len)) {
        return SVM_E_NET;
    }

    const char *env_s, *sig_s, *sid_s;
    size_t env_len_b64, sig_len_b64, sid_len;
    if (!svm_json_find_string((const char *)resp2, resp2_len, "envelope_sealed",
                              &env_s, &env_len_b64) ||
        !svm_json_find_string((const char *)resp2, resp2_len, "envelope_sig",
                              &sig_s, &sig_len_b64) ||
        !svm_json_find_string((const char *)resp2, resp2_len, "session_id",
                              &sid_s, &sid_len)) {
        free(resp2);
        return SVM_E_SERVER;
    }

    size_t env_len = env_len_b64;
    uint8_t *env = (uint8_t *)malloc(env_len);
    if (!env) { free(resp2); return SVM_E_NOMEM; }
    if (!svm_base64_decode(env_s, env_len_b64, env, &env_len)) {
        free(env);
        free(resp2);
        return SVM_E_SERVER;
    }

    uint8_t sig_buf[128];
    if (sig_len_b64 > sizeof(sig_buf)) {
        free(env);
        free(resp2);
        return SVM_E_SERVER;
    }
    size_t sig_cap = sizeof(sig_buf);
    if (!svm_base64_decode(sig_s, sig_len_b64, sig_buf, &sig_cap) || sig_cap != 64) {
        free(env);
        free(resp2);
        return SVM_E_SIG;
    }

    if (!svm_ed25519_verify(sig_buf, env, env_len, cfg->k_sign_pub)) {
        free(env);
        free(resp2);
        return SVM_E_SIG;
    }

    if (env_len < 24) {
        free(env);
        free(resp2);
        return SVM_E_SERVER;
    }

    uint8_t ephem_in[64];
    memcpy(ephem_in, cfg->k_hmac, 32);
    memcpy(ephem_in + 32, nonce_c, 16);
    memcpy(ephem_in + 48, nonce_s, 16);
    uint8_t ephem_key[32];
    svm_blake2s(NULL, 0, ephem_in, 64, ephem_key, 32);
    svm_secure_zero(ephem_in, 64);

    uint8_t *env_nonce = env;
    uint8_t *env_ct = env + 24;
    size_t env_pt_len = env_len - 24;
    uint8_t *env_pt = (uint8_t *)malloc(env_pt_len + 1);
    if (!env_pt) {
        svm_secure_zero(ephem_key, 32);
        free(env);
        free(resp2);
        return SVM_E_NOMEM;
    }
    svm_xchacha20(ephem_key, env_nonce, 0, env_ct, env_pt, env_pt_len);
    env_pt[env_pt_len] = 0;
    svm_secure_zero(ephem_key, 32);

    const char *key_hex_s, *bnonce_hex_s, *sid2_s;
    size_t key_hex_len, bnonce_hex_len, sid2_len;
    int64_t expires = 0;
    int ok = svm_json_find_string((const char *)env_pt, env_pt_len, "key",
                                  &key_hex_s, &key_hex_len) &&
             svm_json_find_string((const char *)env_pt, env_pt_len, "nonce",
                                  &bnonce_hex_s, &bnonce_hex_len) &&
             svm_json_find_string((const char *)env_pt, env_pt_len, "session_id",
                                  &sid2_s, &sid2_len) &&
             svm_json_find_int((const char *)env_pt, env_pt_len, "expires", &expires);

    if (!ok || key_hex_len != 64 || bnonce_hex_len != 48) {
        svm_secure_zero(env_pt, env_pt_len);
        free(env_pt);
        free(env);
        free(resp2);
        return SVM_E_SERVER;
    }

    memset(out_session, 0, sizeof(*out_session));
    if (!svm_hex_decode(key_hex_s, key_hex_len, out_session->session_key, 32) ||
        !svm_hex_decode(bnonce_hex_s, bnonce_hex_len, out_session->blob_nonce, 24)) {
        svm_secure_zero(env_pt, env_pt_len);
        free(env_pt);
        free(env);
        free(resp2);
        return SVM_E_SERVER;
    }

    size_t idc = sid2_len > 16 ? 16 : sid2_len;
    memcpy(out_session->session_id, sid2_s, idc);
    out_session->expires_unix_ms = (uint64_t)expires;

    svm_secure_zero(env_pt, env_pt_len);
    free(env_pt);
    free(env);
    free(resp2);

    return SVM_OK;
}
