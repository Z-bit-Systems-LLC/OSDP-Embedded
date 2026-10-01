// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp_pair_wolfcrypt.h"

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <string.h>

/* ---- Build requirements ---------------------------------------------------
 *
 * wolfSSL 5.9 renamed the ML-DSA option macros (WOLFSSL_DILITHIUM_* ->
 * WOLFSSL_MLDSA_*) and translates the old names forward, not back, so both
 * spellings are checked. HAVE_DILITHIUM is still defined by both versions. */

#if !defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_NO_ML_KEM_768)
#error "osdp_pair_wolfcrypt needs wolfSSL ML-KEM-768 (WOLFSSL_HAVE_MLKEM, not WOLFSSL_NO_ML_KEM_768)"
#endif
#if !defined(HAVE_DILITHIUM) || defined(WOLFSSL_NO_ML_DSA_44)
#error "osdp_pair_wolfcrypt needs wolfSSL ML-DSA-44 (HAVE_DILITHIUM, not WOLFSSL_NO_ML_DSA_44)"
#endif
#if defined(WOLFSSL_DILITHIUM_NO_SIGN) || defined(WOLFSSL_MLDSA_NO_SIGN) || \
    defined(WOLFSSL_DILITHIUM_VERIFY_ONLY) || defined(WOLFSSL_MLDSA_VERIFY_ONLY)
#error "osdp_pair_wolfcrypt needs ML-DSA signing: both pairing roles sign"
#endif
#if defined(WOLFSSL_DILITHIUM_NO_VERIFY) || defined(WOLFSSL_MLDSA_NO_VERIFY)
#error "osdp_pair_wolfcrypt needs ML-DSA verification: both pairing roles verify"
#endif
#if !defined(HAVE_HKDF)
#error "osdp_pair_wolfcrypt needs wolfSSL built with HAVE_HKDF"
#endif

/* Optional halves. A PD only encapsulates and an ACU only generates and
 * decapsulates, so a trimmed wolfSSL may drop the other side; the matching
 * callbacks then report OSDP_ERR_NOT_SUPPORTED instead of failing to build. */
#if !defined(WOLFSSL_MLKEM_NO_MAKE_KEY)
#define PAIR_WC_KEM_KEYGEN 1
#endif
#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE)
#define PAIR_WC_KEM_ENCAPS 1
#endif
#if !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
#define PAIR_WC_KEM_DECAPS 1
#endif
#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && !defined(WOLFSSL_MLDSA_NO_MAKE_KEY)
#define PAIR_WC_DSA_KEYGEN 1
#endif

/* Random-draw sizes. They mirror PQClean's randombytes() calls one for one
 * (crypto_kem_keypair: d||z; crypto_kem_enc: m; crypto_sign_keypair: xi;
 * crypto_sign_signature: rnd), which is what lets the KATs feed both
 * backends the same stream and compare output bytes. */
#define KEM_KEYGEN_RAND_LEN 64U
#define KEM_ENCAPS_RAND_LEN 32U
#define DSA_SEED_LEN        32U
#define DSA_SIGN_RAND_LEN   32U

/* FIPS 204 pure ML-DSA with an empty context string. Passed as a real
 * pointer with length 0 rather than NULL, which some wolfCrypt entry points
 * reject regardless of the length. */
static const byte k_empty_ctx[1] = { 0 };

/* ForceZero() is internal to wolfSSL, so wipe through a volatile pointer the
 * optimiser must keep. */
static void pair_wipe(void *p, size_t n)
{
    for (volatile uint8_t *v = (volatile uint8_t *)p; n > 0; --n) {
        *v++ = 0;
    }
}

static bool fits_word32(size_t n)
{
    return n <= (size_t)0xFFFFFFFFu;
}

/* ---- Entropy ------------------------------------------------------------- */

static osdp_status_t pair_draw(osdp_pair_wolfcrypt_t *ctx,
                               uint8_t *out, size_t len)
{
    if (len == 0) {
        return OSDP_OK;
    }
    if (out == NULL || !fits_word32(len)) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (ctx->rand != NULL) {
        osdp_status_t st = ctx->rand(ctx->rand_user, out, len);
        if (st != OSDP_OK) {
            /* Never leave a half-written buffer looking like randomness. */
            pair_wipe(out, len);
            return OSDP_ERR_NOT_SUPPORTED;
        }
        return OSDP_OK;
    }
    if (ctx->rng_ready) {
        if (wc_RNG_GenerateBlock(&ctx->rng, out, (word32)len) == 0) {
            return OSDP_OK;
        }
        pair_wipe(out, len);
        return OSDP_ERR_NOT_SUPPORTED;
    }
    /* No source installed — fail, do not improvise. */
    pair_wipe(out, len);
    return OSDP_ERR_NOT_SUPPORTED;
}

/* ---- Key-object lifecycle ------------------------------------------------ */

static bool dsa_key_init(dilithium_key *key)
{
    if (wc_dilithium_init_ex(key, NULL, INVALID_DEVID) != 0) {
        return false;
    }
    if (wc_dilithium_set_level(key, WC_ML_DSA_44) != 0) {
        wc_dilithium_free(key);
        return false;
    }
    return true;
}

/* Drop whatever key material the object holds and leave it ready for the
 * next import — wolfCrypt has no "clear key" call, so free and re-init. */
static bool dsa_key_reset(dilithium_key *key)
{
    wc_dilithium_free(key);
    return dsa_key_init(key);
}

static bool kem_key_reset(MlKemKey *key)
{
    (void)wc_MlKemKey_Free(key);
    return wc_MlKemKey_Init(key, WC_ML_KEM_768, NULL, INVALID_DEVID) == 0;
}

/* ---- osdp_pair_crypto_t callbacks ---------------------------------------- */

static osdp_status_t cb_kem_keygen(void *user, uint8_t ek[OSDP_MLKEM768_EK_LEN])
{
    osdp_pair_wolfcrypt_t *ctx = (osdp_pair_wolfcrypt_t *)user;
    if (ctx == NULL || !ctx->kem_ready || ek == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
#if defined(PAIR_WC_KEM_KEYGEN)
    uint8_t       rnd[KEM_KEYGEN_RAND_LEN];
    osdp_status_t st = OSDP_ERR_NOT_SUPPORTED;

    ctx->has_kem_sk = false;
    if (kem_key_reset(&ctx->kem)) {
        st = pair_draw(ctx, rnd, sizeof(rnd));
    }
    if (st == OSDP_OK &&
        (wc_MlKemKey_MakeKeyWithRandom(&ctx->kem, rnd, (int)sizeof(rnd)) != 0 ||
         wc_MlKemKey_EncodePublicKey(&ctx->kem, ek, OSDP_MLKEM768_EK_LEN) != 0)) {
        st = OSDP_ERR_NOT_SUPPORTED;
    }
    pair_wipe(rnd, sizeof(rnd));

    if (st != OSDP_OK) {
        (void)kem_key_reset(&ctx->kem);   /* no half-made ephemeral key */
        return st;
    }
    ctx->has_kem_sk = true;
    return OSDP_OK;
#else
    return OSDP_ERR_NOT_SUPPORTED;
#endif
}

static osdp_status_t cb_kem_encaps(void *user,
                                   const uint8_t ek[OSDP_MLKEM768_EK_LEN],
                                   uint8_t ct[OSDP_MLKEM768_CT_LEN],
                                   uint8_t ss[OSDP_MLKEM_SS_LEN])
{
    osdp_pair_wolfcrypt_t *ctx = (osdp_pair_wolfcrypt_t *)user;
    if (ctx == NULL || !ctx->kem_ready ||
        ek == NULL || ct == NULL || ss == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
#if defined(PAIR_WC_KEM_ENCAPS)
    uint8_t       rnd[KEM_ENCAPS_RAND_LEN];
    osdp_status_t st = OSDP_ERR_NOT_SUPPORTED;

    /* Loading the peer's key replaces any stashed decapsulation key. */
    ctx->has_kem_sk = false;
    if (kem_key_reset(&ctx->kem) &&
        wc_MlKemKey_DecodePublicKey(&ctx->kem, ek, OSDP_MLKEM768_EK_LEN) == 0) {
        st = pair_draw(ctx, rnd, sizeof(rnd));
        if (st == OSDP_OK &&
            wc_MlKemKey_EncapsulateWithRandom(&ctx->kem, ct, ss, rnd,
                                              (int)sizeof(rnd)) != 0) {
            st = OSDP_ERR_NOT_SUPPORTED;
        }
    }
    pair_wipe(rnd, sizeof(rnd));
    if (st != OSDP_OK) {
        pair_wipe(ss, OSDP_MLKEM_SS_LEN);
    }
    return st;
#else
    return OSDP_ERR_NOT_SUPPORTED;
#endif
}

static osdp_status_t cb_kem_decaps(void *user,
                                   const uint8_t ct[OSDP_MLKEM768_CT_LEN],
                                   uint8_t ss[OSDP_MLKEM_SS_LEN])
{
    osdp_pair_wolfcrypt_t *ctx = (osdp_pair_wolfcrypt_t *)user;
    if (ctx == NULL || !ctx->has_kem_sk || ct == NULL || ss == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
#if defined(PAIR_WC_KEM_DECAPS)
    if (wc_MlKemKey_Decapsulate(&ctx->kem, ss, ct, OSDP_MLKEM768_CT_LEN) != 0) {
        pair_wipe(ss, OSDP_MLKEM_SS_LEN);
        return OSDP_ERR_NOT_SUPPORTED;
    }
    return OSDP_OK;
#else
    return OSDP_ERR_NOT_SUPPORTED;
#endif
}

static osdp_status_t cb_dsa_sign(void *user, const uint8_t *msg, size_t msg_len,
                                 uint8_t sig[OSDP_MLDSA44_SIG_LEN])
{
    osdp_pair_wolfcrypt_t *ctx = (osdp_pair_wolfcrypt_t *)user;
    if (ctx == NULL || !ctx->has_dsa || sig == NULL ||
        (msg == NULL && msg_len > 0) || !fits_word32(msg_len)) {
        return OSDP_ERR_INVALID_ARG;
    }

    uint8_t       rnd[DSA_SIGN_RAND_LEN];
    word32        sig_len = OSDP_MLDSA44_SIG_LEN;
    osdp_status_t st = pair_draw(ctx, rnd, sizeof(rnd));

    if (st == OSDP_OK &&
        (wc_dilithium_sign_ctx_msg_with_seed(k_empty_ctx, 0,
                                             msg, (word32)msg_len,
                                             sig, &sig_len,
                                             &ctx->dsa, rnd) != 0 ||
         sig_len != OSDP_MLDSA44_SIG_LEN)) {
        st = OSDP_ERR_NOT_SUPPORTED;
    }
    pair_wipe(rnd, sizeof(rnd));
    return st;
}

static osdp_status_t cb_dsa_verify(void *user,
                                   const uint8_t pk[OSDP_MLDSA44_PK_LEN],
                                   const uint8_t *msg, size_t msg_len,
                                   const uint8_t sig[OSDP_MLDSA44_SIG_LEN])
{
    osdp_pair_wolfcrypt_t *ctx = (osdp_pair_wolfcrypt_t *)user;
    int                    res = 0;

    if (ctx == NULL || !ctx->peer_ready || pk == NULL || sig == NULL ||
        (msg == NULL && msg_len > 0) || !fits_word32(msg_len)) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Any failure — a public key wolfCrypt will not load, a malformed or
     * wrong signature — is a rejection, as in the PQClean port. */
    if (!dsa_key_reset(&ctx->peer)) {
        ctx->peer_ready = false;
        return OSDP_ERR_INVALID_ARG;
    }
    if (wc_dilithium_import_public(pk, OSDP_MLDSA44_PK_LEN, &ctx->peer) != 0 ||
        wc_dilithium_verify_ctx_msg(sig, OSDP_MLDSA44_SIG_LEN, k_empty_ctx, 0,
                                    msg, (word32)msg_len, &res,
                                    &ctx->peer) != 0 ||
        res != 1) {
        return OSDP_ERR_BAD_CRC;
    }
    return OSDP_OK;
}

static osdp_status_t cb_sha256(void *user, const uint8_t *data, size_t len,
                               uint8_t out[OSDP_PAIR_HASH_LEN])
{
    (void)user;
    if (out == NULL || (data == NULL && len > 0) || !fits_word32(len)) {
        return OSDP_ERR_INVALID_ARG;
    }
    return (wc_Sha256Hash(data, (word32)len, out) == 0)
         ? OSDP_OK : OSDP_ERR_NOT_SUPPORTED;
}

static osdp_status_t cb_hmac(void *user,
                             const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t out[OSDP_PAIR_HASH_LEN])
{
    Hmac h;
    int  rc;

    (void)user;
    if (out == NULL || (key == NULL && key_len > 0) ||
        (data == NULL && data_len > 0) ||
        !fits_word32(key_len) || !fits_word32(data_len)) {
        return OSDP_ERR_INVALID_ARG;
    }

    rc = wc_HmacInit(&h, NULL, INVALID_DEVID);
    if (rc != 0) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    rc = wc_HmacSetKey(&h, WC_SHA256, key != NULL ? key : k_empty_ctx,
                       (word32)key_len);
    if (rc == 0 && data_len > 0) {
        rc = wc_HmacUpdate(&h, data, (word32)data_len);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(&h, out);
    }
    wc_HmacFree(&h);
    pair_wipe(&h, sizeof(h));   /* keyed pads */
    return (rc == 0) ? OSDP_OK : OSDP_ERR_NOT_SUPPORTED;
}

static osdp_status_t cb_hkdf(void *user,
                             const uint8_t *salt, size_t salt_len,
                             const uint8_t *ikm, size_t ikm_len,
                             const uint8_t *info, size_t info_len,
                             uint8_t *out, size_t out_len)
{
    (void)user;
    if (out == NULL || (ikm == NULL && ikm_len > 0) ||
        (info == NULL && info_len > 0) ||
        !fits_word32(salt_len) || !fits_word32(ikm_len) ||
        !fits_word32(info_len) || !fits_word32(out_len)) {
        return OSDP_ERR_INVALID_ARG;
    }
    /* RFC 5869: an absent salt is HashLen zero bytes. Spelled out rather
     * than left to wolfCrypt so the two absent forms (NULL, or length 0)
     * mean the same thing whatever the version does with each. */
    static const uint8_t zeros[OSDP_PAIR_HASH_LEN] = { 0 };
    if (salt == NULL || salt_len == 0) {
        salt     = zeros;
        salt_len = sizeof(zeros);
    }
    return (wc_HKDF(WC_SHA256, ikm != NULL ? ikm : k_empty_ctx, (word32)ikm_len,
                    salt, (word32)salt_len,
                    info != NULL ? info : k_empty_ctx, (word32)info_len,
                    out, (word32)out_len) == 0)
         ? OSDP_OK : OSDP_ERR_NOT_SUPPORTED;
}

static osdp_status_t cb_rand(void *user, uint8_t *out, size_t len)
{
    osdp_pair_wolfcrypt_t *ctx = (osdp_pair_wolfcrypt_t *)user;
    if (ctx == NULL || !ctx->lib_ready) {
        return OSDP_ERR_INVALID_ARG;
    }
    return pair_draw(ctx, out, len);
}

/* ---- Public API ---------------------------------------------------------- */

osdp_status_t osdp_pair_wolfcrypt_init(osdp_pair_wolfcrypt_t *ctx,
                                       osdp_pair_crypto_t    *out)
{
    if (ctx == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    (void)memset(ctx, 0, sizeof(*ctx));
    if (wolfCrypt_Init() != 0) {
        return OSDP_ERR_INVALID_ARG;
    }
    ctx->lib_ready = true;

    ctx->dsa_ready  = dsa_key_init(&ctx->dsa);
    ctx->peer_ready = ctx->dsa_ready && dsa_key_init(&ctx->peer);
    ctx->kem_ready  = ctx->peer_ready &&
        wc_MlKemKey_Init(&ctx->kem, WC_ML_KEM_768, NULL, INVALID_DEVID) == 0;
    if (!ctx->kem_ready) {
        osdp_pair_wolfcrypt_free(ctx);
        return OSDP_ERR_INVALID_ARG;
    }

    out->ml_kem768_keygen = cb_kem_keygen;
    out->ml_kem768_encaps = cb_kem_encaps;
    out->ml_kem768_decaps = cb_kem_decaps;
    out->ml_dsa44_sign    = cb_dsa_sign;
    out->ml_dsa44_verify  = cb_dsa_verify;
    out->sha256           = cb_sha256;
    out->hmac_sha256      = cb_hmac;
    out->hkdf_sha256      = cb_hkdf;
    out->rand_bytes       = cb_rand;
    out->user             = ctx;
    return OSDP_OK;
}

osdp_status_t osdp_pair_wolfcrypt_rng(osdp_pair_wolfcrypt_t *ctx)
{
    if (ctx == NULL || !ctx->lib_ready) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (!ctx->rng_ready) {
        if (wc_InitRng(&ctx->rng) != 0) {
            return OSDP_ERR_INVALID_ARG;
        }
        ctx->rng_ready = true;
    }
    ctx->rand      = NULL;   /* the DRBG is now the source */
    ctx->rand_user = NULL;
    return OSDP_OK;
}

void osdp_pair_wolfcrypt_set_rand(osdp_pair_wolfcrypt_t      *ctx,
                                  osdp_pair_wolfcrypt_rand_fn fn,
                                  void                       *user)
{
    if (ctx == NULL) {
        return;
    }
    ctx->rand      = fn;
    ctx->rand_user = (fn != NULL) ? user : NULL;
}

osdp_status_t osdp_pair_wolfcrypt_set_dsa(
    osdp_pair_wolfcrypt_t *ctx,
    const uint8_t          pk[OSDP_MLDSA44_PK_LEN],
    const uint8_t         *sk, size_t sk_len)
{
    if (ctx == NULL || !ctx->dsa_ready || pk == NULL || sk == NULL ||
        sk_len != OSDP_PAIR_WOLFCRYPT_DSA_SK_LEN) {
        return OSDP_ERR_INVALID_ARG;
    }

    ctx->has_dsa = false;
    if (!dsa_key_reset(&ctx->dsa)) {
        ctx->dsa_ready = false;
        return OSDP_ERR_INVALID_ARG;
    }
    if (wc_dilithium_import_key(sk, (word32)sk_len,
                                pk, OSDP_MLDSA44_PK_LEN, &ctx->dsa) != 0) {
        (void)dsa_key_reset(&ctx->dsa);   /* nothing half-imported */
        return OSDP_ERR_INVALID_ARG;
    }
    ctx->has_dsa = true;
    return OSDP_OK;
}

osdp_status_t osdp_pair_wolfcrypt_gen_dsa(
    osdp_pair_wolfcrypt_t *ctx,
    uint8_t                pk_out[OSDP_MLDSA44_PK_LEN])
{
    if (ctx == NULL || !ctx->dsa_ready || pk_out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
#if defined(PAIR_WC_DSA_KEYGEN)
    uint8_t       seed[DSA_SEED_LEN];
    word32        pk_len = OSDP_MLDSA44_PK_LEN;
    osdp_status_t st;

    ctx->has_dsa = false;
    if (!dsa_key_reset(&ctx->dsa)) {
        ctx->dsa_ready = false;
        return OSDP_ERR_INVALID_ARG;
    }
    st = pair_draw(ctx, seed, sizeof(seed));
    if (st == OSDP_OK &&
        (wc_dilithium_make_key_from_seed(&ctx->dsa, seed) != 0 ||
         wc_dilithium_export_public(&ctx->dsa, pk_out, &pk_len) != 0 ||
         pk_len != OSDP_MLDSA44_PK_LEN)) {
        st = OSDP_ERR_NOT_SUPPORTED;
    }
    pair_wipe(seed, sizeof(seed));

    if (st != OSDP_OK) {
        (void)dsa_key_reset(&ctx->dsa);
        pair_wipe(pk_out, OSDP_MLDSA44_PK_LEN);
        return st;
    }
    ctx->has_dsa = true;
    return OSDP_OK;
#else
    return OSDP_ERR_NOT_SUPPORTED;
#endif
}

void osdp_pair_wolfcrypt_free(osdp_pair_wolfcrypt_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->kem_ready) {
        (void)wc_MlKemKey_Free(&ctx->kem);
    }
    if (ctx->peer_ready) {
        wc_dilithium_free(&ctx->peer);
    }
    if (ctx->dsa_ready) {
        wc_dilithium_free(&ctx->dsa);
    }
    if (ctx->rng_ready) {
        (void)wc_FreeRng(&ctx->rng);
    }
    const bool lib_ready = ctx->lib_ready;
    /* The key objects hold the signing key and any ephemeral decapsulation
     * key; wolfCrypt's free does not promise to scrub every cached vector. */
    pair_wipe(ctx, sizeof(*ctx));
    if (lib_ready) {
        (void)wolfCrypt_Cleanup();
    }
}
