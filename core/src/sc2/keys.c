// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_sc2.h"

#include <string.h>

/* SC2 session-key derivation (KMAC256, empty customization string):
 *
 *   S-ENC   = KMAC256(SCBK, RND.A || RND.B, 256 bits)
 *   S-NONCE = KMAC256(SCBK, RND.B || RND.A, 256 bits)
 *
 * The two keys differ only by the order of the concatenated randoms.
 * The concatenation input is 32 bytes (two 16-byte randoms). */

osdp_status_t osdp_sc2_derive_session_keys(
    const osdp_sc2_crypto_t *crypto,
    const uint8_t            scbk [OSDP_SC2_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC2_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC2_RND_LEN],
    osdp_sc2_session_keys_t *out)
{
    if (crypto == NULL || crypto->kmac256 == NULL ||
        scbk == NULL || rnd_a == NULL || rnd_b == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    uint8_t data[OSDP_SC2_RND_LEN * 2U];

    /* S-ENC over RND.A || RND.B. */
    (void)memcpy(&data[0], rnd_a, OSDP_SC2_RND_LEN);
    (void)memcpy(&data[OSDP_SC2_RND_LEN], rnd_b, OSDP_SC2_RND_LEN);
    osdp_status_t s = crypto->kmac256(
        crypto->user, scbk, OSDP_SC2_KEY_LEN,
        data, sizeof(data), out->s_enc, OSDP_SC2_KEY_LEN);
    if (s != OSDP_OK) {
        return s;
    }

    /* S-NONCE over RND.B || RND.A. */
    (void)memcpy(&data[0], rnd_b, OSDP_SC2_RND_LEN);
    (void)memcpy(&data[OSDP_SC2_RND_LEN], rnd_a, OSDP_SC2_RND_LEN);
    return crypto->kmac256(
        crypto->user, scbk, OSDP_SC2_KEY_LEN,
        data, sizeof(data), out->s_nonce, OSDP_SC2_KEY_LEN);
}
