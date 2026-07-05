// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "pair_test_crypto.h"

#include <string.h>

/* ---- PQClean entry points (namespaced; declared here to avoid pulling in
 * the two schemes' identically-named api.h headers). --------------------- */

extern int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss,
                                                 const uint8_t *pk);
extern int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct,
                                                 const uint8_t *sk);
extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
    const uint8_t *sk);
extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
    const uint8_t *pk);

/* PQClean common SHA-256 one-shot. */
extern void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

/* ---- Randomness: injectable fixed seed + reproducible PRNG fallback ----- */

static uint8_t s_seed[128];
static size_t  s_seed_len;
static size_t  s_seed_pos;
static uint64_t s_prng = 0x0123456789ABCDEFULL; /* fixed → reproducible */

void osdp_pair_test_seed_push(const uint8_t *bytes, size_t len)
{
    if (len > sizeof(s_seed)) {
        len = sizeof(s_seed);
    }
    (void)memcpy(s_seed, bytes, len);
    s_seed_len = len;
    s_seed_pos = 0;
}

void osdp_pair_test_seed_clear(void)
{
    s_seed_len = 0;
    s_seed_pos = 0;
}

/* Definition of PQClean's randombytes hook (declared as PQCLEAN_randombytes
 * behind the randombytes macro in the vendored code). Serves queued seed
 * bytes first, then a splitmix64 stream so tests are hermetic and
 * reproducible without OS entropy. */
int PQCLEAN_randombytes(uint8_t *out, size_t n);
int PQCLEAN_randombytes(uint8_t *out, size_t n)
{
    size_t i = 0;
    while (i < n && s_seed_pos < s_seed_len) {
        out[i++] = s_seed[s_seed_pos++];
    }
    for (; i < n; i++) {
        s_prng += 0x9E3779B97F4A7C15ULL;
        uint64_t z = s_prng;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        z ^= z >> 31;
        out[i] = (uint8_t)z;
    }
    return 0;
}

/* ---- HMAC-SHA256 / HKDF-SHA256 over the PQClean SHA-256 ------------------ */

#define SHA256_BLOCK 64U
#define SHA256_LEN   32U
#define HMAC_DATA_MAX 512U   /* pairing HMAC inputs are small (<= ~64 B) */

static osdp_status_t hmac_sha256_impl(const uint8_t *key, size_t key_len,
                                      const uint8_t *data, size_t data_len,
                                      uint8_t out[SHA256_LEN])
{
    if (data_len > HMAC_DATA_MAX) {
        return OSDP_ERR_INVALID_ARG;
    }

    uint8_t k[SHA256_BLOCK];
    (void)memset(k, 0, sizeof(k));
    if (key_len > SHA256_BLOCK) {
        sha256(k, key, key_len);          /* k = H(key), zero-padded */
    } else if (key_len > 0) {
        (void)memcpy(k, key, key_len);
    }

    uint8_t inner_in[SHA256_BLOCK + HMAC_DATA_MAX];
    uint8_t outer_in[SHA256_BLOCK + SHA256_LEN];
    for (size_t i = 0; i < SHA256_BLOCK; i++) {
        inner_in[i] = (uint8_t)(k[i] ^ 0x36U);
        outer_in[i] = (uint8_t)(k[i] ^  0x5CU);
    }
    if (data_len > 0) {
        (void)memcpy(&inner_in[SHA256_BLOCK], data, data_len);
    }
    sha256(&outer_in[SHA256_BLOCK], inner_in, SHA256_BLOCK + data_len);
    sha256(out, outer_in, SHA256_BLOCK + SHA256_LEN);
    return OSDP_OK;
}

#define HKDF_INFO_MAX 64U

static osdp_status_t hkdf_sha256_impl(const uint8_t *salt, size_t salt_len,
                                      const uint8_t *ikm, size_t ikm_len,
                                      const uint8_t *info, size_t info_len,
                                      uint8_t *out, size_t out_len)
{
    if (info_len > HKDF_INFO_MAX) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Extract: PRK = HMAC(salt, IKM). Empty salt → HashLen zero bytes. */
    static const uint8_t zeros[SHA256_LEN] = { 0 };
    const uint8_t *s = (salt != NULL && salt_len > 0) ? salt : zeros;
    const size_t   s_len = (salt != NULL && salt_len > 0) ? salt_len
                                                          : SHA256_LEN;
    uint8_t prk[SHA256_LEN];
    osdp_status_t st = hmac_sha256_impl(s, s_len, ikm, ikm_len, prk);
    if (st != OSDP_OK) {
        return st;
    }

    /* Expand: T(i) = HMAC(PRK, T(i-1) || info || i). */
    uint8_t t[SHA256_LEN];
    size_t  t_len = 0;
    size_t  done = 0;
    uint8_t counter = 1;
    while (done < out_len) {
        uint8_t block[SHA256_LEN + HKDF_INFO_MAX + 1];
        size_t p = 0;
        if (t_len > 0) {
            (void)memcpy(&block[p], t, t_len);
            p += t_len;
        }
        if (info_len > 0) {
            (void)memcpy(&block[p], info, info_len);
            p += info_len;
        }
        block[p++] = counter;
        st = hmac_sha256_impl(prk, SHA256_LEN, block, p, t);
        if (st != OSDP_OK) {
            return st;
        }
        t_len = SHA256_LEN;

        const size_t take = (out_len - done < SHA256_LEN) ? (out_len - done)
                                                          : SHA256_LEN;
        (void)memcpy(&out[done], t, take);
        done += take;
        counter++;
    }
    return OSDP_OK;
}

/* ---- osdp_pair_crypto_t vtable ------------------------------------------ */

static osdp_status_t cb_kem_keygen(void *user, uint8_t ek[OSDP_MLKEM768_EK_LEN])
{
    osdp_pair_test_ctx_t *c = (osdp_pair_test_ctx_t *)user;
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(ek, c->kem_sk) != 0) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    c->has_kem_sk = true;
    return OSDP_OK;
}

static osdp_status_t cb_kem_encaps(void *user,
                                   const uint8_t ek[OSDP_MLKEM768_EK_LEN],
                                   uint8_t ct[OSDP_MLKEM768_CT_LEN],
                                   uint8_t ss[OSDP_MLKEM_SS_LEN])
{
    (void)user;
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, ek) != 0) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    return OSDP_OK;
}

static osdp_status_t cb_kem_decaps(void *user,
                                   const uint8_t ct[OSDP_MLKEM768_CT_LEN],
                                   uint8_t ss[OSDP_MLKEM_SS_LEN])
{
    osdp_pair_test_ctx_t *c = (osdp_pair_test_ctx_t *)user;
    if (!c->has_kem_sk) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, c->kem_sk) != 0) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    return OSDP_OK;
}

static osdp_status_t cb_dsa_sign(void *user, const uint8_t *msg, size_t msg_len,
                                 uint8_t sig[OSDP_MLDSA44_SIG_LEN])
{
    osdp_pair_test_ctx_t *c = (osdp_pair_test_ctx_t *)user;
    if (!c->has_dsa) {
        return OSDP_ERR_INVALID_ARG;
    }
    size_t siglen = 0;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, msg, msg_len,
                                                    c->dsa_sk) != 0
        || siglen != OSDP_MLDSA44_SIG_LEN) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    return OSDP_OK;
}

static osdp_status_t cb_dsa_verify(void *user,
                                   const uint8_t pk[OSDP_MLDSA44_PK_LEN],
                                   const uint8_t *msg, size_t msg_len,
                                   const uint8_t sig[OSDP_MLDSA44_SIG_LEN])
{
    (void)user;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, OSDP_MLDSA44_SIG_LEN,
                                                 msg, msg_len, pk) != 0) {
        return OSDP_ERR_BAD_CRC;   /* invalid signature — reject */
    }
    return OSDP_OK;
}

static osdp_status_t cb_sha256(void *user, const uint8_t *data, size_t len,
                               uint8_t out[OSDP_PAIR_HASH_LEN])
{
    (void)user;
    sha256(out, data, len);
    return OSDP_OK;
}

static osdp_status_t cb_hmac(void *user,
                             const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t out[OSDP_PAIR_HASH_LEN])
{
    (void)user;
    return hmac_sha256_impl(key, key_len, data, data_len, out);
}

static osdp_status_t cb_hkdf(void *user,
                             const uint8_t *salt, size_t salt_len,
                             const uint8_t *ikm, size_t ikm_len,
                             const uint8_t *info, size_t info_len,
                             uint8_t *out, size_t out_len)
{
    (void)user;
    return hkdf_sha256_impl(salt, salt_len, ikm, ikm_len, info, info_len,
                            out, out_len);
}

static osdp_status_t cb_rand(void *user, uint8_t *out, size_t len)
{
    (void)user;
    (void)PQCLEAN_randombytes(out, len);
    return OSDP_OK;
}

void osdp_pair_test_crypto_init(osdp_pair_crypto_t *crypto,
                                osdp_pair_test_ctx_t *ctx)
{
    (void)memset(ctx, 0, sizeof(*ctx));
    crypto->ml_kem768_keygen = cb_kem_keygen;
    crypto->ml_kem768_encaps = cb_kem_encaps;
    crypto->ml_kem768_decaps = cb_kem_decaps;
    crypto->ml_dsa44_sign    = cb_dsa_sign;
    crypto->ml_dsa44_verify  = cb_dsa_verify;
    crypto->sha256           = cb_sha256;
    crypto->hmac_sha256      = cb_hmac;
    crypto->hkdf_sha256      = cb_hkdf;
    crypto->rand_bytes       = cb_rand;
    crypto->user             = ctx;
}

osdp_status_t osdp_pair_test_gen_dsa(osdp_pair_test_ctx_t *ctx)
{
    extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk,
                                                         uint8_t *sk);
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(ctx->dsa_pk, ctx->dsa_sk)
        != 0) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    ctx->has_dsa = true;
    return OSDP_OK;
}
