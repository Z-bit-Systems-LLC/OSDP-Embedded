// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp_sc2_wolfcrypt.h"

#include <wolfssl/wolfcrypt/error-crypt.h>

#include <string.h>

#if !defined(HAVE_AESGCM)
#error "osdp_sc2_wolfcrypt needs wolfSSL built with HAVE_AESGCM"
#endif
#if !defined(HAVE_AES_ECB) && !defined(WOLFSSL_AES_DIRECT)
#error "osdp_sc2_wolfcrypt needs wolfSSL built with HAVE_AES_ECB or WOLFSSL_AES_DIRECT"
#endif

/* ForceZero() is internal to wolfSSL, so wipe through a volatile pointer the
 * optimiser must keep. */
static void sc2_wipe(void *p, size_t n)
{
    for (volatile uint8_t *v = (volatile uint8_t *)p; n > 0; --n) {
        *v++ = 0;
    }
}

/* wolfCrypt sizes are word32; the HAL's are size_t. */
static bool fits_word32(size_t n)
{
    return n <= (size_t)0xFFFFFFFFu;
}

static osdp_status_t sc2_gcm_encrypt(
    void          *user,
    const uint8_t  key  [OSDP_AES256_KEY_LEN],
    const uint8_t  nonce[OSDP_SC2_GCM_NONCE_LEN],
    const uint8_t *aad,  size_t aad_len,
    const uint8_t *pt,   size_t pt_len,
    uint8_t       *ct,
    uint8_t        tag  [OSDP_SC2_GCM_TAG_LEN])
{
    osdp_sc2_wolfcrypt_t *ctx = (osdp_sc2_wolfcrypt_t *)user;
    int                   rc;

    if (ctx == NULL || !ctx->aes_ready || key == NULL || nonce == NULL ||
        tag == NULL || (aad == NULL && aad_len > 0) ||
        (pt_len > 0 && (pt == NULL || ct == NULL)) ||
        !fits_word32(aad_len) || !fits_word32(pt_len)) {
        return OSDP_ERR_INVALID_ARG;
    }

    rc = wc_AesGcmSetKey(&ctx->aes, key, OSDP_AES256_KEY_LEN);
    if (rc == 0) {
        rc = wc_AesGcmEncrypt(&ctx->aes, ct, pt, (word32)pt_len,
                              nonce, OSDP_SC2_GCM_NONCE_LEN,
                              tag, OSDP_SC2_GCM_TAG_LEN,
                              aad, (word32)aad_len);
    }
    return (rc == 0) ? OSDP_OK : OSDP_ERR_INVALID_ARG;
}

static osdp_status_t sc2_gcm_decrypt(
    void          *user,
    const uint8_t  key  [OSDP_AES256_KEY_LEN],
    const uint8_t  nonce[OSDP_SC2_GCM_NONCE_LEN],
    const uint8_t *aad,  size_t aad_len,
    const uint8_t *ct,   size_t ct_len,
    const uint8_t  tag  [OSDP_SC2_GCM_TAG_LEN],
    uint8_t       *pt)
{
    osdp_sc2_wolfcrypt_t *ctx = (osdp_sc2_wolfcrypt_t *)user;
    int                   rc;

    if (ctx == NULL || !ctx->aes_ready || key == NULL || nonce == NULL ||
        tag == NULL || (aad == NULL && aad_len > 0) ||
        (ct_len > 0 && (ct == NULL || pt == NULL)) ||
        !fits_word32(aad_len) || !fits_word32(ct_len)) {
        return OSDP_ERR_INVALID_ARG;
    }

    rc = wc_AesGcmSetKey(&ctx->aes, key, OSDP_AES256_KEY_LEN);
    if (rc == 0) {
        rc = wc_AesGcmDecrypt(&ctx->aes, pt, ct, (word32)ct_len,
                              nonce, OSDP_SC2_GCM_NONCE_LEN,
                              tag, OSDP_SC2_GCM_TAG_LEN,
                              aad, (word32)aad_len);
    }
    if (rc == 0) {
        return OSDP_OK;
    }

    /* wolfCrypt's software GCM decrypts into `pt` before comparing the tag,
     * so on any failure `pt` may hold plaintext of a frame that did not
     * authenticate. The HAL promises output only on a valid tag. */
    if (ct_len > 0) {
        sc2_wipe(pt, ct_len);
    }
    return (rc == WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) ? OSDP_ERR_BAD_CRC
                                                   : OSDP_ERR_INVALID_ARG;
}

/* The block is produced into a local and copied out: SC2 calls with
 * out == in, and routing through `tmp` keeps that safe on every wolfCrypt AES
 * backend, including hardware ones that DMA from the input. */
static osdp_status_t sc2_ecb_encrypt(
    void          *user,
    const uint8_t  key[OSDP_AES256_KEY_LEN],
    const uint8_t  in [16],
    uint8_t        out[16])
{
    osdp_sc2_wolfcrypt_t *ctx = (osdp_sc2_wolfcrypt_t *)user;
    byte                  tmp[AES_BLOCK_SIZE];
    int                   rc;

    if (ctx == NULL || !ctx->aes_ready ||
        key == NULL || in == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    rc = wc_AesSetKey(&ctx->aes, key, OSDP_AES256_KEY_LEN, NULL,
                      AES_ENCRYPTION);
    if (rc == 0) {
#if defined(HAVE_AES_ECB)
        rc = wc_AesEcbEncrypt(&ctx->aes, tmp, in, AES_BLOCK_SIZE);
#else
        rc = wc_AesEncryptDirect(&ctx->aes, tmp, in);
#endif
    }
    if (rc == 0) {
        (void)memcpy(out, tmp, AES_BLOCK_SIZE);
    }
    sc2_wipe(tmp, sizeof(tmp));

    /* The HAL reserves failure for caller violations; a wolfCrypt error
     * (e.g. a hardware engine fault) is reported the same way, and the SC2
     * layer abandons the operation rather than using `out`. */
    return (rc == 0) ? OSDP_OK : OSDP_ERR_INVALID_ARG;
}

static osdp_status_t sc2_rand(void *user, uint8_t *out, size_t len)
{
    osdp_sc2_wolfcrypt_t *ctx = (osdp_sc2_wolfcrypt_t *)user;

    if (ctx == NULL || !ctx->rng_ready) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return OSDP_OK;
    }
    if (out == NULL || !fits_word32(len)) {
        return OSDP_ERR_INVALID_ARG;
    }
    return (wc_RNG_GenerateBlock(&ctx->rng, out, (word32)len) == 0)
         ? OSDP_OK : OSDP_ERR_INVALID_ARG;
}

osdp_status_t osdp_sc2_wolfcrypt_aes256(osdp_sc2_wolfcrypt_t *ctx,
                                        osdp_sc2_crypto_t    *out)
{
    if (ctx == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    (void)memset(ctx, 0, sizeof(*ctx));
    if (wolfCrypt_Init() != 0) {
        return OSDP_ERR_INVALID_ARG;
    }
    ctx->lib_ready = true;

    if (wc_AesInit(&ctx->aes, NULL, INVALID_DEVID) != 0) {
        osdp_sc2_wolfcrypt_free(ctx);
        return OSDP_ERR_INVALID_ARG;
    }
    ctx->aes_ready = true;

    out->aes256_gcm_encrypt = sc2_gcm_encrypt;
    out->aes256_gcm_decrypt = sc2_gcm_decrypt;
    out->aes256_ecb_encrypt = sc2_ecb_encrypt;
    out->user               = ctx;
    return OSDP_OK;
}

osdp_status_t osdp_sc2_wolfcrypt_rng(osdp_sc2_wolfcrypt_t *ctx,
                                     osdp_sc2_crypto_t    *out)
{
    if (ctx == NULL || out == NULL || !ctx->aes_ready || out->user != ctx) {
        return OSDP_ERR_INVALID_ARG;
    }

    if (!ctx->rng_ready) {
        if (wc_InitRng(&ctx->rng) != 0) {
            return OSDP_ERR_INVALID_ARG;
        }
        ctx->rng_ready = true;
    }

    out->rand_bytes = sc2_rand;
    return OSDP_OK;
}

void osdp_sc2_wolfcrypt_free(osdp_sc2_wolfcrypt_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->rng_ready) {
        (void)wc_FreeRng(&ctx->rng);
        ctx->rng_ready = false;
    }
    if (ctx->aes_ready) {
        wc_AesFree(&ctx->aes);
        ctx->aes_ready = false;
    }
    if (ctx->lib_ready) {
        (void)wolfCrypt_Cleanup();
        ctx->lib_ready = false;
    }
}
