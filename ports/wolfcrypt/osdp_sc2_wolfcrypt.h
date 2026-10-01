// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_SC2_WOLFCRYPT_H
#define OSDP_SC2_WOLFCRYPT_H

/* osdp_sc2_crypto_t backend over wolfCrypt (wolfSSL): AES-256-GCM and the
 * raw AES-256 block, plus an opt-in DRBG. The SC2 sibling of
 * osdp_sc_wolfcrypt.h, with the same shape and the same rules.
 *
 * NOT supplied: kmac256. wolfCrypt has SHA-3 and SHAKE but no cSHAKE, so it
 * cannot express KMAC256 (checked against 5.8.2 and 5.9.2). The caller binds
 * kmac256 itself after the setter — vendor/tiny-kmac is what the tests and
 * OpenReader use:
 *
 *     static osdp_status_t my_kmac(void *user, const uint8_t *k, size_t kl,
 *                                  const uint8_t *d, size_t dl,
 *                                  uint8_t *out, size_t ol)
 *     {
 *         (void)user;                      // the wolfCrypt context; unused
 *         tiny_kmac256(k, kl, d, dl, out, ol);
 *         return OSDP_OK;
 *     }
 *
 *     osdp_sc2_wolfcrypt_aes256(&wc, &crypto2);
 *     osdp_sc2_wolfcrypt_rng(&wc, &crypto2);    // or bind your own RNG
 *     crypto2.kmac256 = my_kmac;
 *
 * Both setters leave members they do not own exactly as the caller had them,
 * so kmac256 can be bound before or after.
 *
 * wolfSSL requirements: HAVE_AESGCM, and for the single block either
 * HAVE_AES_ECB or WOLFSSL_AES_DIRECT (whichever is present is used). A
 * missing feature is a compile error, not a runtime surprise.
 *
 * The context carries the wolfCrypt Aes object, re-keyed on every call (SC2
 * alternates S-ENC, S-MAC and the SCBK within one message), so no call puts a
 * key schedule on the stack. It is mutated on every call: one context per
 * osdp_pd_t / osdp_acu_t, outliving the instance it is bound to.
 *
 * Each context holds one wolfCrypt_Init() reference, taken by
 * osdp_sc2_wolfcrypt_aes256() and dropped by osdp_sc2_wolfcrypt_free(). */

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <stdbool.h>

#include "osdp/osdp_sc2_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct osdp_sc2_wolfcrypt {
    Aes    aes;
    WC_RNG rng;
    bool   lib_ready;   /* holds a wolfCrypt_Init() reference */
    bool   aes_ready;
    bool   rng_ready;
} osdp_sc2_wolfcrypt_t;

/* Initialise `ctx` and populate `out`'s aes256_gcm_encrypt,
 * aes256_gcm_decrypt and aes256_ecb_encrypt members, with out->user = ctx.
 * kmac256 and rand_bytes are left as the caller had them.
 *
 * GCM decrypt honours the HAL's "plaintext only on a valid tag": wolfCrypt's
 * software GCM writes plaintext before it compares the tag, so on a mismatch
 * the port wipes the `ct_len` output bytes before returning OSDP_ERR_BAD_CRC.
 * When `pt` aliases `ct` that wipes the rejected ciphertext too, which the
 * caller is discarding anyway.
 *
 * Call once per context, before osdp_sc2_wolfcrypt_rng(). Returns
 * OSDP_ERR_INVALID_ARG for NULL arguments or a wolfCrypt init failure. */
osdp_status_t osdp_sc2_wolfcrypt_aes256(osdp_sc2_wolfcrypt_t *ctx,
                                        osdp_sc2_crypto_t    *out);

/* Seed wolfCrypt's DRBG in `ctx` and set out->rand_bytes to draw from it.
 * `ctx` must already be initialised by osdp_sc2_wolfcrypt_aes256() and bound
 * to `out`. Returns OSDP_ERR_INVALID_ARG otherwise, or if the DRBG cannot be
 * seeded. Optional: a caller with its own entropy source binds rand_bytes
 * itself instead. */
osdp_status_t osdp_sc2_wolfcrypt_rng(osdp_sc2_wolfcrypt_t *ctx,
                                     osdp_sc2_crypto_t    *out);

/* Release whatever the setters acquired. Safe to call twice; no-op for NULL.
 * Unbind the vtable from its PD/ACU (or stop using that instance) first. */
void osdp_sc2_wolfcrypt_free(osdp_sc2_wolfcrypt_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_SC2_WOLFCRYPT_H */
