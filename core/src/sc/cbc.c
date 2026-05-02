// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_sc.h"

#include <string.h>

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b)
{
    for (size_t i = 0; i < OSDP_AES_BLOCK_LEN; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

osdp_status_t osdp_sc_cbc_encrypt(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            key       [OSDP_SC_KEY_LEN],
    const uint8_t            iv        [OSDP_AES_BLOCK_LEN],
    const uint8_t           *plaintext,
    size_t                   len,
    uint8_t                 *ciphertext)
{
    if (crypto == NULL || crypto->aes128_ecb_encrypt == NULL ||
        key == NULL || iv == NULL ||
        plaintext == NULL || ciphertext == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len == 0 || (len % OSDP_AES_BLOCK_LEN) != 0) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* The chaining block: starts as the IV, then becomes the most
     * recently produced ciphertext block. Held in a local buffer so
     * we tolerate `ciphertext == plaintext` aliasing. */
    uint8_t chain[OSDP_AES_BLOCK_LEN];
    (void)memcpy(chain, iv, OSDP_AES_BLOCK_LEN);

    const size_t blocks = len / OSDP_AES_BLOCK_LEN;
    for (size_t b = 0; b < blocks; b++) {
        uint8_t xored[OSDP_AES_BLOCK_LEN];
        xor_block(xored, &plaintext[b * OSDP_AES_BLOCK_LEN], chain);
        const osdp_status_t s = crypto->aes128_ecb_encrypt(
            crypto->user, key, xored,
            &ciphertext[b * OSDP_AES_BLOCK_LEN]);
        if (s != OSDP_OK) {
            return s;
        }
        (void)memcpy(chain, &ciphertext[b * OSDP_AES_BLOCK_LEN],
                     OSDP_AES_BLOCK_LEN);
    }
    return OSDP_OK;
}

osdp_status_t osdp_sc_cbc_decrypt(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            key        [OSDP_SC_KEY_LEN],
    const uint8_t            iv         [OSDP_AES_BLOCK_LEN],
    const uint8_t           *ciphertext,
    size_t                   len,
    uint8_t                 *plaintext)
{
    if (crypto == NULL || key == NULL || iv == NULL ||
        ciphertext == NULL || plaintext == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (crypto->aes128_ecb_decrypt == NULL) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    if (len == 0 || (len % OSDP_AES_BLOCK_LEN) != 0) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Track the previous ciphertext block (or IV for block 0) before
     * we possibly overwrite it via aliasing. */
    uint8_t prev[OSDP_AES_BLOCK_LEN];
    (void)memcpy(prev, iv, OSDP_AES_BLOCK_LEN);

    const size_t blocks = len / OSDP_AES_BLOCK_LEN;
    for (size_t b = 0; b < blocks; b++) {
        uint8_t cur_ct[OSDP_AES_BLOCK_LEN];
        (void)memcpy(cur_ct, &ciphertext[b * OSDP_AES_BLOCK_LEN],
                     OSDP_AES_BLOCK_LEN);

        uint8_t decrypted[OSDP_AES_BLOCK_LEN];
        const osdp_status_t s = crypto->aes128_ecb_decrypt(
            crypto->user, key, cur_ct, decrypted);
        if (s != OSDP_OK) {
            return s;
        }
        xor_block(&plaintext[b * OSDP_AES_BLOCK_LEN], decrypted, prev);
        (void)memcpy(prev, cur_ct, OSDP_AES_BLOCK_LEN);
    }
    return OSDP_OK;
}
