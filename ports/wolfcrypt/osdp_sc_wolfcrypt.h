// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_SC_WOLFCRYPT_H
#define OSDP_SC_WOLFCRYPT_H

/* osdp_sc_crypto_t backend over wolfCrypt (wolfSSL).
 *
 * Unlike ports/tiny this is a production-grade binding: wolfCrypt brings
 * hardware AES offload on many MCUs and a SP 800-90A DRBG. It is still a
 * port, not part of the freestanding library — osdp_core never links it.
 *
 * wolfSSL requirements: HAVE_AES_ECB (off by default in wolfSSL's CMake
 * build — pass -DWOLFSSL_AESECB=yes; on by default under ./configure) and
 * AES decryption (on unless NO_AES_DECRYPT). A missing feature is a compile
 * error, not a runtime surprise.
 *
 * Two independent setters, matching the ports/ rule that no port installs an
 * RNG as a side effect:
 *
 *   osdp_sc_wolfcrypt_aes128()  AES-128 ECB encrypt + decrypt. Always.
 *   osdp_sc_wolfcrypt_rng()     rand_bytes over wolfCrypt's DRBG. Opt-in —
 *                               call it when the DRBG is the RNG you want
 *                               (on bare metal that means wolfSSL has a real
 *                               seed source configured).
 *
 * The context carries the wolfCrypt Aes object so no block call needs a
 * ~1 KB key-schedule struct on the stack. It is mutated on every call, so use
 * one context per osdp_pd_t / osdp_acu_t (an ACU shares one across all its
 * PDs). It must outlive the instance it is bound to.
 *
 * Each context holds one wolfCrypt_Init() reference, taken by
 * osdp_sc_wolfcrypt_aes128() and dropped by osdp_sc_wolfcrypt_free().
 * wolfCrypt refcounts these, so an application that also initialises
 * wolfCrypt itself is unaffected — and one that does not still gets a
 * working DRBG (wc_InitRng faults without a prior wolfCrypt_Init()). */

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <stdbool.h>

#include "osdp/osdp_sc_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct osdp_sc_wolfcrypt {
    Aes    aes;
    WC_RNG rng;
    bool   lib_ready;   /* holds a wolfCrypt_Init() reference */
    bool   aes_ready;
    bool   rng_ready;
} osdp_sc_wolfcrypt_t;

/* Initialise `ctx` and populate `out`'s aes128_ecb_encrypt /
 * aes128_ecb_decrypt members. Sets out->user = ctx, which the callbacks
 * need; rand_bytes is left exactly as the caller had it, so a custom RNG
 * bound afterwards receives this context as its `user`.
 *
 * Call once per context, before osdp_sc_wolfcrypt_rng(). Returns
 * OSDP_ERR_INVALID_ARG for NULL arguments or a wolfCrypt init failure. */
osdp_status_t osdp_sc_wolfcrypt_aes128(osdp_sc_wolfcrypt_t *ctx,
                                       osdp_sc_crypto_t    *out);

/* Seed wolfCrypt's DRBG in `ctx` and set out->rand_bytes to draw from it.
 * `ctx` must already be initialised by osdp_sc_wolfcrypt_aes128() and bound
 * to `out`. Returns OSDP_ERR_INVALID_ARG otherwise, or if the DRBG cannot be
 * seeded. */
osdp_status_t osdp_sc_wolfcrypt_rng(osdp_sc_wolfcrypt_t *ctx,
                                    osdp_sc_crypto_t    *out);

/* Release whatever the setters acquired. Safe to call twice; no-op for NULL.
 * Unbind the vtable from its PD/ACU (or stop using that instance) first. */
void osdp_sc_wolfcrypt_free(osdp_sc_wolfcrypt_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_SC_WOLFCRYPT_H */
