// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_sc2.h"

#include <string.h>

/* SC2 cryptograms and nonce derivation.
 *
 * The cryptograms are AES-256-CBC with a zero IV and no padding over a
 * 32-byte input (two 16-byte blocks), genuinely chained — NOT ECB of
 * the two blocks. We build the two-block CBC from the HAL's single
 * AES-256 block encrypt:
 *
 *   C0 = E(K, P0 ^ IV) = E(K, P0)          (IV = 0)
 *   C1 = E(K, P1 ^ C0)
 *   cryptogram = C0 || C1
 *
 * The nonce derivation is a single AES-256 block over a structured
 * plaintext, keyed by S-NONCE. */

#define SC2_BLOCK 16U

static void xor16(uint8_t dst[SC2_BLOCK], const uint8_t a[SC2_BLOCK],
                  const uint8_t b[SC2_BLOCK])
{
    for (unsigned i = 0; i < SC2_BLOCK; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

/* Two-block AES-256-CBC (zero IV, no padding) over `in[0..31]` → `out`. */
static osdp_status_t cbc2_zero_iv(const osdp_sc2_crypto_t *crypto,
                                  const uint8_t key[OSDP_SC2_KEY_LEN],
                                  const uint8_t in [OSDP_SC2_CRYPTOGRAM_LEN],
                                  uint8_t       out[OSDP_SC2_CRYPTOGRAM_LEN])
{
    /* C0 = E(K, P0) since IV is all-zero. */
    osdp_status_t s =
        crypto->aes256_ecb_encrypt(crypto->user, key, &in[0], &out[0]);
    if (s != OSDP_OK) {
        return s;
    }
    /* C1 = E(K, P1 ^ C0). */
    uint8_t blk[SC2_BLOCK];
    xor16(blk, &in[SC2_BLOCK], &out[0]);
    return crypto->aes256_ecb_encrypt(crypto->user, key, blk, &out[SC2_BLOCK]);
}

static osdp_status_t cryptogram(const osdp_sc2_crypto_t *crypto,
                                const uint8_t s_enc[OSDP_SC2_KEY_LEN],
                                const uint8_t first [OSDP_SC2_RND_LEN],
                                const uint8_t second[OSDP_SC2_RND_LEN],
                                uint8_t out[OSDP_SC2_CRYPTOGRAM_LEN])
{
    if (crypto == NULL || crypto->aes256_ecb_encrypt == NULL ||
        s_enc == NULL || first == NULL || second == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    uint8_t in[OSDP_SC2_CRYPTOGRAM_LEN];
    (void)memcpy(&in[0], first, OSDP_SC2_RND_LEN);
    (void)memcpy(&in[OSDP_SC2_RND_LEN], second, OSDP_SC2_RND_LEN);
    return cbc2_zero_iv(crypto, s_enc, in, out);
}

osdp_status_t osdp_sc2_client_cryptogram(
    const osdp_sc2_crypto_t *crypto,
    const uint8_t            s_enc[OSDP_SC2_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC2_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC2_RND_LEN],
    uint8_t                  out  [OSDP_SC2_CRYPTOGRAM_LEN])
{
    /* Client Cryptogram = CBC(S-ENC, RND.A || RND.B). */
    return cryptogram(crypto, s_enc, rnd_a, rnd_b, out);
}

osdp_status_t osdp_sc2_server_cryptogram(
    const osdp_sc2_crypto_t *crypto,
    const uint8_t            s_enc[OSDP_SC2_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC2_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC2_RND_LEN],
    uint8_t                  out  [OSDP_SC2_CRYPTOGRAM_LEN])
{
    /* Server Cryptogram = CBC(S-ENC, RND.B || RND.A). */
    return cryptogram(crypto, s_enc, rnd_b, rnd_a, out);
}

osdp_status_t osdp_sc2_compute_nonce(
    const osdp_sc2_crypto_t *crypto,
    const uint8_t            s_nonce[OSDP_SC2_KEY_LEN],
    const uint8_t            cuid   [OSDP_SC2_CUID_LEN],
    uint32_t                 counter,
    uint8_t                  nonce  [OSDP_SC2_NONCE_LEN])
{
    if (crypto == NULL || crypto->aes256_ecb_encrypt == NULL ||
        s_nonce == NULL || cuid == NULL || nonce == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* PLAIN = cUID[8] || counter(4, little-endian) || 0x80 0x00 0x00 0x00 */
    uint8_t plain[SC2_BLOCK];
    (void)memcpy(&plain[0], cuid, OSDP_SC2_CUID_LEN);
    plain[8]  = (uint8_t)(counter & 0xFFu);
    plain[9]  = (uint8_t)((counter >> 8) & 0xFFu);
    plain[10] = (uint8_t)((counter >> 16) & 0xFFu);
    plain[11] = (uint8_t)((counter >> 24) & 0xFFu);
    plain[12] = 0x80u;
    plain[13] = 0x00u;
    plain[14] = 0x00u;
    plain[15] = 0x00u;

    uint8_t cipher[SC2_BLOCK];
    osdp_status_t s =
        crypto->aes256_ecb_encrypt(crypto->user, s_nonce, plain, cipher);
    if (s != OSDP_OK) {
        return s;
    }
    /* NONCE = first 12 bytes of the cipher block. */
    (void)memcpy(nonce, cipher, OSDP_SC2_NONCE_LEN);
    return OSDP_OK;
}
