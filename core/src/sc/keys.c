// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_sc.h"

#include <string.h>

/* SCBK-D, the install-time default key, declared extern in osdp_sc.h
 * and defined here so the linker has exactly one copy. Per spec section
 * D.4 / page 4090: 0x30, 0x31, 0x32, ... 0x3F (16 bytes inclusive). */
const uint8_t OSDP_SCBK_DEFAULT[OSDP_SC_KEY_LEN] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};

/* Build the 16-byte derivation input for a session key. Per spec
 * D.4.1, the layout is:
 *
 *   byte 0:  0x01      (constant)
 *   byte 1:  selector  (0x82 for S-ENC, 0x01 for S-MAC1, 0x02 for S-MAC2)
 *   2..7:    RND.A[0..5]
 *   8..15:   0x00 ×8
 *
 * Note that only the first 6 bytes of RND.A enter key derivation;
 * RND.A[6..7] participate only in the cryptogram computation later. */
static void build_derivation_input(
    uint8_t                  out[OSDP_AES_BLOCK_LEN],
    uint8_t                  selector,
    const uint8_t            rnd_a[OSDP_SC_RND_LEN])
{
    out[0] = 0x01U;
    out[1] = selector;
    (void)memcpy(&out[2], rnd_a, 6);
    (void)memset(&out[8], 0x00, 8);
}

osdp_status_t osdp_sc_derive_session_keys(
    const osdp_sc_crypto_t      *crypto,
    const uint8_t                scbk [OSDP_SC_KEY_LEN],
    const uint8_t                rnd_a[OSDP_SC_RND_LEN],
    osdp_sc_session_keys_t      *out)
{
    if (crypto == NULL || crypto->aes128_ecb_encrypt == NULL ||
        scbk == NULL || rnd_a == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    uint8_t input[OSDP_AES_BLOCK_LEN];

    /* S-ENC (selector 0x82) */
    build_derivation_input(input, 0x82U, rnd_a);
    osdp_status_t s = crypto->aes128_ecb_encrypt(crypto->user, scbk,
                                                 input, out->s_enc);
    if (s != OSDP_OK) return s;

    /* S-MAC1 (selector 0x01) */
    build_derivation_input(input, 0x01U, rnd_a);
    s = crypto->aes128_ecb_encrypt(crypto->user, scbk, input, out->s_mac1);
    if (s != OSDP_OK) return s;

    /* S-MAC2 (selector 0x02) */
    build_derivation_input(input, 0x02U, rnd_a);
    s = crypto->aes128_ecb_encrypt(crypto->user, scbk, input, out->s_mac2);
    if (s != OSDP_OK) return s;

    return OSDP_OK;
}

/* Cryptogram = Enc(S-ENC, A || B), where A and B are each 8 bytes
 * concatenated to form the 16-byte AES input. */
static osdp_status_t cryptogram(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_enc[OSDP_SC_KEY_LEN],
    const uint8_t            a    [OSDP_SC_RND_LEN],
    const uint8_t            b    [OSDP_SC_RND_LEN],
    uint8_t                  out  [OSDP_SC_CRYPTOGRAM_LEN])
{
    if (crypto == NULL || crypto->aes128_ecb_encrypt == NULL ||
        s_enc == NULL || a == NULL || b == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    uint8_t input[OSDP_AES_BLOCK_LEN];
    (void)memcpy(&input[0], a, OSDP_SC_RND_LEN);
    (void)memcpy(&input[OSDP_SC_RND_LEN], b, OSDP_SC_RND_LEN);
    return crypto->aes128_ecb_encrypt(crypto->user, s_enc, input, out);
}

osdp_status_t osdp_sc_client_cryptogram(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_enc[OSDP_SC_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC_RND_LEN],
    uint8_t                  out  [OSDP_SC_CRYPTOGRAM_LEN])
{
    return cryptogram(crypto, s_enc, rnd_a, rnd_b, out);
}

osdp_status_t osdp_sc_server_cryptogram(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_enc[OSDP_SC_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC_RND_LEN],
    uint8_t                  out  [OSDP_SC_CRYPTOGRAM_LEN])
{
    /* RND.B before RND.A — note the swap from Client Cryptogram. */
    return cryptogram(crypto, s_enc, rnd_b, rnd_a, out);
}

osdp_status_t osdp_sc_initial_rmac(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_mac1        [OSDP_SC_KEY_LEN],
    const uint8_t            s_mac2        [OSDP_SC_KEY_LEN],
    const uint8_t            server_crypto [OSDP_SC_CRYPTOGRAM_LEN],
    uint8_t                  out           [OSDP_SC_MAC_LEN])
{
    if (crypto == NULL || crypto->aes128_ecb_encrypt == NULL ||
        s_mac1 == NULL || s_mac2 == NULL ||
        server_crypto == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    uint8_t intermediate[OSDP_AES_BLOCK_LEN];
    osdp_status_t s = crypto->aes128_ecb_encrypt(crypto->user,
                                                 s_mac1,
                                                 server_crypto,
                                                 intermediate);
    if (s != OSDP_OK) {
        return s;
    }
    return crypto->aes128_ecb_encrypt(crypto->user, s_mac2,
                                      intermediate, out);
}
