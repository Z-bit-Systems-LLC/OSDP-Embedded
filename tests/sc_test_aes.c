// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "sc_test_aes.h"

#include "aes.h"   /* tests/vendor/tiny-aes/aes.h */

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

static const osdp_sc_crypto_t k_tiny_aes_vtable = {
    .aes128_ecb_encrypt = adapter_encrypt,
    .aes128_ecb_decrypt = adapter_decrypt,
    .user               = NULL,
};

const osdp_sc_crypto_t *sc_test_crypto_tiny_aes(void)
{
    return &k_tiny_aes_vtable;
}
