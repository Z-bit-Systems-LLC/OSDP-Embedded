// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp_sc_wolfcrypt.h"

#include <string.h>

#if !defined(HAVE_AES_ECB)
#error "osdp_sc_wolfcrypt needs wolfSSL built with HAVE_AES_ECB (CMake: -DWOLFSSL_AESECB=yes)"
#endif
#if !defined(HAVE_AES_DECRYPT)
#error "osdp_sc_wolfcrypt needs wolfSSL AES decryption (do not define NO_AES_DECRYPT)"
#endif

/* The HAL hands over the key with every block, and SC alternates S-ENC,
 * S-MAC1, S-MAC2 and the SCBK within one message, so the key is expanded on
 * every call rather than cached — a cache would thrash.
 *
 * The block is produced into a local and copied out: the SC payload path
 * calls with out == in, and routing through `tmp` keeps that safe on every
 * wolfCrypt AES backend, including hardware ones that DMA from the input. */
static osdp_status_t wolfcrypt_block(
    void          *user,
    const uint8_t  key[OSDP_AES_KEY_LEN],
    const uint8_t  in [OSDP_AES_BLOCK_LEN],
    uint8_t        out[OSDP_AES_BLOCK_LEN],
    int            dir)
{
    osdp_sc_wolfcrypt_t *ctx = (osdp_sc_wolfcrypt_t *)user;
    byte                 tmp[AES_BLOCK_SIZE];
    int                  rc;

    if (ctx == NULL || !ctx->aes_ready ||
        key == NULL || in == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    rc = wc_AesSetKey(&ctx->aes, key, OSDP_AES_KEY_LEN, NULL, dir);
    if (rc == 0) {
        rc = (dir == AES_ENCRYPTION)
           ? wc_AesEcbEncrypt(&ctx->aes, tmp, in, AES_BLOCK_SIZE)
           : wc_AesEcbDecrypt(&ctx->aes, tmp, in, AES_BLOCK_SIZE);
    }
    if (rc == 0) {
        (void)memcpy(out, tmp, OSDP_AES_BLOCK_LEN);
    }

    /* After a decrypt `tmp` holds SC plaintext. ForceZero() is internal to
     * wolfSSL, so wipe through a volatile pointer the optimiser must keep. */
    for (volatile byte *p = tmp; p < tmp + sizeof(tmp); ++p) {
        *p = 0;
    }

    /* The HAL reserves failure for caller violations; a wolfCrypt error
     * (e.g. a hardware engine fault) is reported the same way, and the SC
     * layer abandons the operation rather than using `out`. */
    return (rc == 0) ? OSDP_OK : OSDP_ERR_INVALID_ARG;
}

static osdp_status_t wolfcrypt_encrypt(
    void          *user,
    const uint8_t  key[OSDP_AES_KEY_LEN],
    const uint8_t  in [OSDP_AES_BLOCK_LEN],
    uint8_t        out[OSDP_AES_BLOCK_LEN])
{
    return wolfcrypt_block(user, key, in, out, AES_ENCRYPTION);
}

static osdp_status_t wolfcrypt_decrypt(
    void          *user,
    const uint8_t  key[OSDP_AES_KEY_LEN],
    const uint8_t  in [OSDP_AES_BLOCK_LEN],
    uint8_t        out[OSDP_AES_BLOCK_LEN])
{
    return wolfcrypt_block(user, key, in, out, AES_DECRYPTION);
}

static osdp_status_t wolfcrypt_rand(void *user, uint8_t *out, size_t len)
{
    osdp_sc_wolfcrypt_t *ctx = (osdp_sc_wolfcrypt_t *)user;

    if (ctx == NULL || !ctx->rng_ready) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return OSDP_OK;
    }
    if (out == NULL || len > (size_t)0xFFFFFFFFu) {
        return OSDP_ERR_INVALID_ARG;
    }
    return (wc_RNG_GenerateBlock(&ctx->rng, out, (word32)len) == 0)
         ? OSDP_OK : OSDP_ERR_INVALID_ARG;
}

osdp_status_t osdp_sc_wolfcrypt_aes128(osdp_sc_wolfcrypt_t *ctx,
                                       osdp_sc_crypto_t    *out)
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
        osdp_sc_wolfcrypt_free(ctx);
        return OSDP_ERR_INVALID_ARG;
    }
    ctx->aes_ready = true;

    out->aes128_ecb_encrypt = wolfcrypt_encrypt;
    out->aes128_ecb_decrypt = wolfcrypt_decrypt;
    out->user               = ctx;
    return OSDP_OK;
}

osdp_status_t osdp_sc_wolfcrypt_rng(osdp_sc_wolfcrypt_t *ctx,
                                    osdp_sc_crypto_t    *out)
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

    out->rand_bytes = wolfcrypt_rand;
    return OSDP_OK;
}

void osdp_sc_wolfcrypt_free(osdp_sc_wolfcrypt_t *ctx)
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
