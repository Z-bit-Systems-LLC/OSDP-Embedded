// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* The AES half now comes from ports/tiny — it was identical to the tests'
 * copy, byte for byte. What stays here is this tool's RNG policy, which is
 * the member a port deliberately does not supply. */

#include "aes_adapter.h"

#include "osdp_sc_tiny.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

static int g_seeded = 0;

static void seed_once_lazily(void)
{
    if (!g_seeded) {
        srand((unsigned int)time(NULL));
        g_seeded = 1;
    }
}

static osdp_status_t adapter_rand(void *user, uint8_t *out, size_t len)
{
    (void)user;
    seed_once_lazily();
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(rand() & 0xFF);
    }
    return OSDP_OK;
}

void pd_mock_aes_seed_rand(uint32_t seed)
{
    if (seed == 0U) {
        srand((unsigned int)time(NULL));
    } else {
        srand((unsigned int)seed);
    }
    g_seeded = 1;
}

/* Built once on first use rather than as a static initialiser, because the
 * AES members come from a function call now. The tool is single-threaded. */
static osdp_sc_crypto_t g_vtable;
static bool             g_vtable_ready;

const osdp_sc_crypto_t *pd_mock_aes_crypto(void)
{
    if (!g_vtable_ready) {
        osdp_sc_tiny_aes128(&g_vtable);
        g_vtable.rand_bytes = adapter_rand;
        g_vtable.user       = NULL;
        g_vtable_ready      = true;
    }
    return &g_vtable;
}
