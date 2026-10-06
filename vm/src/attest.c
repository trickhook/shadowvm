#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "svm_internal.h"
#include "hmac_sha256_internal.h"
#include "obf_strings.h"

#define SVM_EXPORT __attribute__((visibility("default")))

static int svm_http_post(const char *url, const char *body, size_t body_len,
                         uint8_t **out, size_t *out_len) {
    (void)url; (void)body; (void)body_len; (void)out; (void)out_len;
    return 0;
}

static void svm_hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char tab[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = tab[in[i] >> 4];
        out[i * 2 + 1] = tab[in[i] & 0xF];
    }
    out[len * 2] = 0;
}

static int svm_random(uint8_t *buf, size_t n) {
    char path[16], mode[4];
    SVM_UNXOR(URANDOM, path);
    SVM_UNXOR(FOPEN_RB, mode);
    FILE *f = fopen(path, mode);
    svm_secure_zero(path, sizeof(path));
    svm_secure_zero(mode, sizeof(mode));
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
    char fmt_url[32];
    SVM_UNXOR(URL_CHAL, fmt_url);
    int ul = snprintf(url1, sizeof(url1), fmt_url, cfg->server_url);
    svm_secure_zero(fmt_url, sizeof(fmt_url));
    if (ul < 0 || (size_t)ul >= sizeof(url1)) return SVM_E_ATTEST;

    char body1[2048];
    char fmt_body1[80];
    SVM_UNXOR(JSON_CHAL, fmt_body1);
    int bl = snprintf(body1, sizeof(body1), fmt_body1,
        cfg->blob_id, cfg->loader_id, device_fp_hex, nonce_c_hex);
    svm_secure_zero(fmt_body1, sizeof(fmt_body1));
    if (bl < 0 || (size_t)bl >= sizeof(body1)) return SVM_E_ATTEST;

    uint8_t *resp1 = NULL;
    size_t resp1_len = 0;
    if (!svm_http_post(url1, body1, (size_t)bl, &resp1, &resp1_len)) {
        return SVM_E_NET;
    }

    const char *challenge_id_s, *nonce_s_hex_s;
    size_t challenge_id_len, nonce_s_hex_len;
    char key_chal_id[16], key_nonce_s[16];
    SVM_UNXOR(K_CHAL_ID, key_chal_id);
    SVM_UNXOR(K_NONCE_S, key_nonce_s);
    int ok1 = svm_json_find_string((const char *)resp1, resp1_len, key_chal_id,
                                   &challenge_id_s, &challenge_id_len) &&
              svm_json_find_string((const char *)resp1, resp1_len, key_nonce_s,
                                   &nonce_s_hex_s, &nonce_s_hex_len);
    svm_secure_zero(key_chal_id, sizeof(key_chal_id));
    svm_secure_zero(key_nonce_s, sizeof(key_nonce_s));
    if (!ok1) {
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
    char pfx[16];
    SVM_UNXOR(ATTEST_PIN, pfx);
    memcpy(pin + po, pfx, 14); po += 14;
    svm_secure_zero(pfx, sizeof(pfx));
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
    char fmt_url2[32];
    SVM_UNXOR(URL_COMP, fmt_url2);
    ul = snprintf(url2, sizeof(url2), fmt_url2, cfg->server_url);
    svm_secure_zero(fmt_url2, sizeof(fmt_url2));
    if (ul < 0 || (size_t)ul >= sizeof(url2)) return SVM_E_ATTEST;

    char body2[1024];
    char fmt_body2[48];
    SVM_UNXOR(JSON_COMP, fmt_body2);
    bl = snprintf(body2, sizeof(body2), fmt_body2, challenge_id_c, proof_hex);
    svm_secure_zero(fmt_body2, sizeof(fmt_body2));
    if (bl < 0 || (size_t)bl >= sizeof(body2)) return SVM_E_ATTEST;

    uint8_t *resp2 = NULL;
    size_t resp2_len = 0;
    if (!svm_http_post(url2, body2, (size_t)bl, &resp2, &resp2_len)) {
        return SVM_E_NET;
    }

    const char *env_s, *sig_s, *sid_s;
    size_t env_len_b64, sig_len_b64, sid_len;
    char key_env_se[20], key_env_si[16], key_sid[16];
    SVM_UNXOR(K_ENV_SE, key_env_se);
    SVM_UNXOR(K_ENV_SI, key_env_si);
    SVM_UNXOR(K_SID, key_sid);
    int ok2 = svm_json_find_string((const char *)resp2, resp2_len, key_env_se,
                                   &env_s, &env_len_b64) &&
              svm_json_find_string((const char *)resp2, resp2_len, key_env_si,
                                   &sig_s, &sig_len_b64) &&
              svm_json_find_string((const char *)resp2, resp2_len, key_sid,
                                   &sid_s, &sid_len);
    svm_secure_zero(key_env_se, sizeof(key_env_se));
    svm_secure_zero(key_env_si, sizeof(key_env_si));
    svm_secure_zero(key_sid, sizeof(key_sid));
    if (!ok2) {
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
    char k_key[8], k_nonce[8], k_sid2[16], k_expires[12];
    SVM_UNXOR(K_KEY, k_key);
    SVM_UNXOR(K_NONCE, k_nonce);
    SVM_UNXOR(K_SID, k_sid2);
    SVM_UNXOR(K_EXPIRES, k_expires);
    int ok = svm_json_find_string((const char *)env_pt, env_pt_len, k_key,
                                  &key_hex_s, &key_hex_len) &&
             svm_json_find_string((const char *)env_pt, env_pt_len, k_nonce,
                                  &bnonce_hex_s, &bnonce_hex_len) &&
             svm_json_find_string((const char *)env_pt, env_pt_len, k_sid2,
                                  &sid2_s, &sid2_len) &&
             svm_json_find_int((const char *)env_pt, env_pt_len, k_expires, &expires);
    svm_secure_zero(k_key, sizeof(k_key));
    svm_secure_zero(k_nonce, sizeof(k_nonce));
    svm_secure_zero(k_sid2, sizeof(k_sid2));
    svm_secure_zero(k_expires, sizeof(k_expires));

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
