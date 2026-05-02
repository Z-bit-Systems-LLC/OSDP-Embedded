// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_sc.h"

#include <string.h>

/* OSDP custom CBC-MAC, per spec D.5.
 *
 * Differences from RFC 4493 / NIST SP 800-38B CMAC:
 *   - Two distinct keys (S-MAC1 for blocks 1..n-1, S-MAC2 for block n).
 *     Standard CMAC uses one key plus subkeys; this is simpler but
 *     non-standard.
 *   - Padding is the simple "0x80 || 0x00*" scheme, applied ONLY when
 *     the input length is not already a multiple of the block size.
 *     Standard CMAC always pads (and uses different sub-keys
 *     accordingly).
 *   - The IV ("ICV" in spec terminology) is the previous MAC in the
 *     rolling chain — initialised by the Initial R-MAC produced at
 *     the end of the SCS-CS handshake (osdp_sc_initial_rmac).
 *
 * The result of each AES_ECB(key, plaintext_block XOR chain) is the
 * next chain. After the final block, that chain IS the MAC.
 *
 * Single-block special case (one block after padding): the spec says
 * "If the message contains only one block, then only S-MAC2 is used."
 * The straightforward interpretation: for the only block, key is
 * S-MAC2 (so it acts as both first-and-last). Our code uses S-MAC2 on
 * the last block always; when there is exactly one block, that is the
 * only block, so S-MAC2 is used. */

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b)
{
    for (size_t i = 0; i < OSDP_AES_BLOCK_LEN; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

osdp_status_t osdp_sc_compute_mac(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_mac1[OSDP_SC_KEY_LEN],
    const uint8_t            s_mac2[OSDP_SC_KEY_LEN],
    const uint8_t            icv   [OSDP_SC_MAC_LEN],
    const uint8_t           *msg,
    size_t                   len,
    uint8_t                  out   [OSDP_SC_MAC_LEN])
{
    if (crypto == NULL || crypto->aes128_ecb_encrypt == NULL ||
        s_mac1 == NULL || s_mac2 == NULL ||
        icv == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len > 0 && msg == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Determine padded length. If `len` is exactly a multiple of 16,
     * no padding is added (per spec — note this differs from the
     * payload-padding rule which always pads). */
    const size_t remainder = len % OSDP_AES_BLOCK_LEN;
    const size_t padded_len =
        (remainder == 0 && len > 0) ? len
                                    : (len - remainder + OSDP_AES_BLOCK_LEN);
    if (padded_len == 0) {
        /* len == 0: degenerate, but the spec doesn't exclude it.
         * Single all-padding block: 0x80 followed by 15 × 0x00. */
        const size_t total_blocks = 1;
        uint8_t block[OSDP_AES_BLOCK_LEN];
        (void)memset(block, 0x00, sizeof(block));
        block[0] = 0x80U;

        uint8_t xored[OSDP_AES_BLOCK_LEN];
        xor_block(xored, block, icv);
        const osdp_status_t s = crypto->aes128_ecb_encrypt(
            crypto->user, s_mac2, xored, out);
        (void)total_blocks;
        return s;
    }

    /* Walk blocks. For each block but the last we use S-MAC1; the
     * final block uses S-MAC2. We materialise the (possibly partial)
     * final block from `msg` plus any padding into a 16-byte scratch.
     */
    const size_t total_blocks = padded_len / OSDP_AES_BLOCK_LEN;
    uint8_t chain[OSDP_AES_BLOCK_LEN];
    (void)memcpy(chain, icv, OSDP_AES_BLOCK_LEN);

    for (size_t b = 0; b < total_blocks; b++) {
        uint8_t block[OSDP_AES_BLOCK_LEN];
        const size_t block_off = b * OSDP_AES_BLOCK_LEN;

        if (block_off + OSDP_AES_BLOCK_LEN <= len) {
            /* Whole block from message. */
            (void)memcpy(block, &msg[block_off], OSDP_AES_BLOCK_LEN);
        } else {
            /* Last partial block: copy what's available, then pad. */
            const size_t avail = len - block_off;
            if (avail > 0) {
                (void)memcpy(block, &msg[block_off], avail);
            }
            block[avail] = 0x80U;
            if (avail + 1 < OSDP_AES_BLOCK_LEN) {
                (void)memset(&block[avail + 1], 0x00,
                             OSDP_AES_BLOCK_LEN - avail - 1);
            }
        }

        uint8_t xored[OSDP_AES_BLOCK_LEN];
        xor_block(xored, block, chain);

        const uint8_t *key = (b == total_blocks - 1) ? s_mac2 : s_mac1;
        uint8_t cipher[OSDP_AES_BLOCK_LEN];
        const osdp_status_t s = crypto->aes128_ecb_encrypt(
            crypto->user, key, xored, cipher);
        if (s != OSDP_OK) {
            return s;
        }
        (void)memcpy(chain, cipher, OSDP_AES_BLOCK_LEN);
    }

    (void)memcpy(out, chain, OSDP_SC_MAC_LEN);
    return OSDP_OK;
}
