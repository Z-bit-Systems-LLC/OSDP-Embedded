// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "sc2_adapter.h"

#include "aes.h"    /* vendor/tiny-aes/aes.h, AES256 + renamed via tiny_aes256 */
#include "gcm.h"    /* vendor/tiny-gcm */
#include "kmac.h"   /* vendor/tiny-kmac */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

void pd_mock_sc2_seed_rand(uint32_t seed)
{
    if (seed == 0U) {
        srand((unsigned int)time(NULL));
    } else {
        srand((unsigned int)seed);
    }
    g_seeded = 1;
}

static const osdp_sc2_crypto_t k_vtable = {
    .kmac256            = adapter_kmac,
    .aes256_gcm_encrypt = adapter_gcm_encrypt,
    .aes256_gcm_decrypt = adapter_gcm_decrypt,
    .aes256_ecb_encrypt = adapter_ecb,
    .rand_bytes         = adapter_rand,
    .user               = NULL,
};

const osdp_sc2_crypto_t *pd_mock_sc2_crypto(void)
{
    return &k_vtable;
}
