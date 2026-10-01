// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* The AES backend is chosen at compile time. tests/CMakeLists.txt builds this
 * file twice when osdp_port_sc2_wolfcrypt exists — once over the vendored
 * tiny-AES/tiny-GCM, once with OSDP_SC2_TEST_WOLFCRYPT over ports/wolfcrypt —
 * and links the whole SC2 suite against each, so every SC2 test doubles as a
 * wolfCrypt conformance test. KMAC256 is the port's when wolfSSL has it
 * (5.9.4+ with WOLFSSL_KMAC) and tiny-kmac otherwise, and the RNG stays the
 * deterministic one below: the tests pin RND
 * values, and the port's DRBG has its own test in test_port_sc2_wolfcrypt.c. */

#include "sc2_test_crypto.h"

#include "kmac.h"   /* vendor/tiny-kmac */

#ifdef OSDP_SC2_TEST_WOLFCRYPT
#include "osdp_sc2_wolfcrypt.h"
#else
#include "aes.h"    /* vendor/tiny-aes/aes.h, AES256 + renamed via tiny_aes256 */
#include "gcm.h"    /* vendor/tiny-gcm */
#endif

#include <stdbool.h>
#include <string.h>

#ifndef OSDP_SC2_TEST_WOLFCRYPT

/* ---- AES-256 single block (ECB) ----------------------------------------*/

static osdp_status_t adapter_ecb(
    void *user, const uint8_t key[32], const uint8_t in[16], uint8_t out[16])
{
    (void)user;
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    if (out != in) {
        (void)memcpy(out, in, 16);
    }
    AES_ECB_encrypt(&ctx, out);
    return OSDP_OK;
}

/* ---- AES-256-GCM (shared vendor/tiny-gcm) ------------------------------*/

static osdp_status_t adapter_gcm_encrypt(
    void *user, const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *pt, size_t pt_len,
    uint8_t *ct, uint8_t tag[16])
{
    (void)user;
    tiny_gcm256_encrypt(key, nonce, aad, aad_len, pt, pt_len, ct, tag);
    return OSDP_OK;
}

static osdp_status_t adapter_gcm_decrypt(
    void *user, const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ct, size_t ct_len,
    const uint8_t tag[16], uint8_t *pt)
{
    (void)user;
    if (tiny_gcm256_decrypt(key, nonce, aad, aad_len, ct, ct_len, tag, pt)
            != 0) {
        return OSDP_ERR_BAD_CRC;
    }
    return OSDP_OK;
}

#endif /* !OSDP_SC2_TEST_WOLFCRYPT */

/* ---- KMAC256 -----------------------------------------------------------*/

#if !defined(OSDP_SC2_TEST_WOLFCRYPT) || !OSDP_SC2_WOLFCRYPT_HAS_KMAC
static osdp_status_t adapter_kmac(
    void *user,
    const uint8_t *key,  size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t *out, size_t out_len)
{
    (void)user;
    tiny_kmac256(key, key_len, data, data_len, out, out_len);
    return OSDP_OK;
}
#endif

/* ---- RNG ---------------------------------------------------------------*/

static uint32_t g_prng_state = 0xCAFEBABEu;
static const uint8_t *g_fixed_rand     = NULL;
static size_t         g_fixed_rand_len = 0;

static osdp_status_t adapter_rand(void *user, uint8_t *out, size_t len)
{
    (void)user;
    if (g_fixed_rand != NULL && g_fixed_rand_len > 0) {
        for (size_t i = 0; i < len; i++) {
            out[i] = g_fixed_rand[i % g_fixed_rand_len];
        }
        return OSDP_OK;
    }
    for (size_t i = 0; i < len; i++) {
        g_prng_state = g_prng_state * 1103515245u + 12345u;
        out[i] = (uint8_t)(g_prng_state >> 16);
    }
    return OSDP_OK;
}

void sc2_test_crypto_seed_prng(uint32_t seed)
{
    g_prng_state = seed;
}

void sc2_test_crypto_set_fixed_rand(const uint8_t *buf, size_t len)
{
    g_fixed_rand     = (len > 0) ? buf : NULL;
    g_fixed_rand_len = (buf != NULL) ? len : 0;
}

#ifdef OSDP_SC2_TEST_WOLFCRYPT

/* Built once on first use: the AES members come from the port's setter, and
 * its callbacks need their context through `user`. adapter_kmac and
 * adapter_rand ignore `user`, so all three coexist. Never freed — it lives as
 * long as the test process. Tests are single-threaded, so the flag is the
 * only guard the lazy init needs. */
static osdp_sc2_wolfcrypt_t g_wolfcrypt_ctx;
static osdp_sc2_crypto_t    g_sc2_vtable;
static bool                 g_sc2_ready;

const osdp_sc2_crypto_t *sc2_test_crypto(void)
{
    if (!g_sc2_ready) {
        if (osdp_sc2_wolfcrypt_aes256(&g_wolfcrypt_ctx,
                                      &g_sc2_vtable) != OSDP_OK) {
            return NULL;
        }
#if !OSDP_SC2_WOLFCRYPT_HAS_KMAC
        /* wolfSSL without KMAC (before 5.9.4, or WOLFSSL_KMAC off): the
         * port leaves kmac256 to us. With it, the port's KMAC is what the
         * suite exercises against the SC2 session-key vectors. */
        g_sc2_vtable.kmac256    = adapter_kmac;
#endif
        g_sc2_vtable.rand_bytes = adapter_rand;
        g_sc2_ready             = true;
    }
    return &g_sc2_vtable;
}

#else

static const osdp_sc2_crypto_t k_sc2_vtable = {
    .kmac256            = adapter_kmac,
    .aes256_gcm_encrypt = adapter_gcm_encrypt,
    .aes256_gcm_decrypt = adapter_gcm_decrypt,
    .aes256_ecb_encrypt = adapter_ecb,
    .rand_bytes         = adapter_rand,
    .user               = NULL,
};

const osdp_sc2_crypto_t *sc2_test_crypto(void)
{
    return &k_sc2_vtable;
}

#endif /* OSDP_SC2_TEST_WOLFCRYPT */
