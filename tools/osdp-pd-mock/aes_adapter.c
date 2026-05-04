// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "aes_adapter.h"

#include "aes.h"   /* vendor/tiny-aes/aes.h */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static const osdp_sc_crypto_t k_vtable = {
    .aes128_ecb_encrypt = adapter_encrypt,
    .aes128_ecb_decrypt = adapter_decrypt,
    .rand_bytes         = adapter_rand,
    .user               = NULL,
};

const osdp_sc_crypto_t *pd_mock_aes_crypto(void)
{
    return &k_vtable;
}
