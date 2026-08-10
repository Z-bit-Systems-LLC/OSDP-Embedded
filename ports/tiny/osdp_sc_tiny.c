// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp_sc_tiny.h"

#include "aes.h"   /* vendor/tiny-aes/aes.h */

#include <string.h>

/* tiny-AES encrypts in place, so a caller passing distinct buffers gets the
 * copy done here. The `out != in` guard matters: self-memcpy is undefined
 * behaviour, and the SC payload path does call these with out == in. */
static osdp_status_t tiny_encrypt(
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

static osdp_status_t tiny_decrypt(
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

void osdp_sc_tiny_aes128(osdp_sc_crypto_t *out)
{
    if (out == NULL) {
        return;
    }
    out->aes128_ecb_encrypt = tiny_encrypt;
    out->aes128_ecb_decrypt = tiny_decrypt;
}
