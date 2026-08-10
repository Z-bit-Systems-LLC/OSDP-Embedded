// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* The AES half of this adapter now comes from ports/tiny — it was identical
 * to osdp-pd-mock's copy, byte for byte. What stays here is the part that is
 * genuinely test-specific: an RNG that replays a fixed sequence so a KAT or a
 * captured session reproduces exactly. */

#include "sc_test_aes.h"

#include "osdp_sc_tiny.h"

#include <stdbool.h>
#include <stdint.h>

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

/* Built once on first use rather than as a static initialiser, because the
 * AES members come from a function call now. Tests are single-threaded, so
 * the lazy init needs no guard beyond the flag. */
static osdp_sc_crypto_t g_tiny_aes_vtable;
static bool             g_tiny_aes_ready;

const osdp_sc_crypto_t *sc_test_crypto_tiny_aes(void)
{
    if (!g_tiny_aes_ready) {
        osdp_sc_tiny_aes128(&g_tiny_aes_vtable);
        g_tiny_aes_vtable.rand_bytes = adapter_rand;
        g_tiny_aes_vtable.user       = NULL;
        g_tiny_aes_ready             = true;
    }
    return &g_tiny_aes_vtable;
}
