// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "sc_test_aes.h"

#include "aes.h"   /* tests/vendor/tiny-aes/aes.h */

#include <stdint.h>
#include <string.h>

static osdp_status_t adapter_encrypt(
    void          *user,
    const uint8_t  key[OSDP_AES_KEY_LEN],
    const uint8_t  in [OSDP_AES_BLOCK_LEN],
    uint8_t        out[OSDP_AES_BLOCK_LEN])
{
    (void)user;
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    if (out != in) {
        (void)memcpy(out, in, OSDP_AES_BLOCK_LEN);
    }
    AES_ECB_encrypt(&ctx, out);
    return OSDP_OK;
}

static osdp_status_t adapter_decrypt(
    void          *user,
    const uint8_t  key[OSDP_AES_KEY_LEN],
    const uint8_t  in [OSDP_AES_BLOCK_LEN],
    uint8_t        out[OSDP_AES_BLOCK_LEN])
{
    (void)user;
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    if (out != in) {
        (void)memcpy(out, in, OSDP_AES_BLOCK_LEN);
    }
    AES_ECB_decrypt(&ctx, out);
    return OSDP_OK;
}

/* Deterministic LCG so tests get reproducible RND values. Reset via
 * sc_test_crypto_seed_prng() at the start of each test. */
static uint32_t g_prng_state = 0xCAFEBABEu;

/* Fixed-bytes mode for capture-replay tests: when g_fixed_rand_len > 0,
 * rand_bytes returns slices of g_fixed_rand[] (cycling) instead of LCG
 * output. Cleared by sc_test_crypto_set_fixed_rand(NULL, 0). */
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

void sc_test_crypto_seed_prng(uint32_t seed)
{
    g_prng_state = seed;
}

void sc_test_crypto_set_fixed_rand(const uint8_t *buf, size_t len)
{
    g_fixed_rand     = (len > 0) ? buf : NULL;
    g_fixed_rand_len = (buf != NULL) ? len : 0;
}

static const osdp_sc_crypto_t k_tiny_aes_vtable = {
    .aes128_ecb_encrypt = adapter_encrypt,
    .aes128_ecb_decrypt = adapter_decrypt,
    .rand_bytes         = adapter_rand,
    .user               = NULL,
};

const osdp_sc_crypto_t *sc_test_crypto_tiny_aes(void)
{
    return &k_tiny_aes_vtable;
}
