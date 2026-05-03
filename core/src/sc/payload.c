// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_sc.h"

#include <string.h>

/* IV for SCS_17/18 payload encryption is the bitwise complement of
 * the 16-byte MAC of the most recent message in the opposite
 * direction (spec D.5.1 step 5 / D.5.2 step 4). */
static void invert_iv(uint8_t       out[OSDP_AES_BLOCK_LEN],
                      const uint8_t in [OSDP_SC_MAC_LEN])
{
    for (size_t i = 0; i < OSDP_AES_BLOCK_LEN; i++) {
        out[i] = (uint8_t)(~in[i]);
    }
}

osdp_status_t osdp_sc_encrypt_payload(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_enc           [OSDP_SC_KEY_LEN],
    const uint8_t            last_inbound_mac[OSDP_SC_MAC_LEN],
    const uint8_t           *plaintext,
    size_t                   plaintext_len,
    uint8_t                 *ciphertext,
    size_t                   ciphertext_cap,
    size_t                  *ciphertext_len)
{
    if (crypto == NULL || s_enc == NULL || last_inbound_mac == NULL ||
        ciphertext == NULL || ciphertext_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (plaintext_len > 0 && plaintext == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *ciphertext_len = 0;

    /* Padding rule (spec D.4.5): the data block always grows by at
     * least one byte (the 0x80 marker) and rounds up to a multiple of
     * the AES block size. */
    const size_t padded_len = ((plaintext_len / OSDP_AES_BLOCK_LEN) + 1U)
                              * OSDP_AES_BLOCK_LEN;
    if (padded_len > ciphertext_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    /* Build the padded plaintext into the output buffer in-place. We
     * read from `plaintext` (which may alias `ciphertext`) before
     * writing the padding, so handle aliasing carefully: copy first,
     * then append pad bytes. memmove handles overlap if it ever
     * occurs in practice. */
    if (plaintext_len > 0) {
        (void)memmove(ciphertext, plaintext, plaintext_len);
    }
    ciphertext[plaintext_len] = 0x80U;
    if (plaintext_len + 1U < padded_len) {
        (void)memset(&ciphertext[plaintext_len + 1U], 0x00,
                     padded_len - plaintext_len - 1U);
    }

    /* Encrypt the padded buffer in place. */
    uint8_t iv[OSDP_AES_BLOCK_LEN];
    invert_iv(iv, last_inbound_mac);
    const osdp_status_t r = osdp_sc_cbc_encrypt(crypto, s_enc, iv,
                                                ciphertext, padded_len,
                                                ciphertext);
    if (r != OSDP_OK) {
        return r;
    }
    *ciphertext_len = padded_len;
    return OSDP_OK;
}

osdp_status_t osdp_sc_decrypt_payload(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_enc            [OSDP_SC_KEY_LEN],
    const uint8_t            last_outbound_mac[OSDP_SC_MAC_LEN],
    const uint8_t           *ciphertext,
    size_t                   ciphertext_len,
    uint8_t                 *plaintext,
    size_t                   plaintext_cap,
    size_t                  *plaintext_len)
{
    if (crypto == NULL || s_enc == NULL || last_outbound_mac == NULL ||
        plaintext_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (ciphertext_len > 0 && ciphertext == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (plaintext_cap > 0 && plaintext == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *plaintext_len = 0;

    if (ciphertext_len == 0 ||
        (ciphertext_len % OSDP_AES_BLOCK_LEN) != 0) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (ciphertext_len > plaintext_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t iv[OSDP_AES_BLOCK_LEN];
    invert_iv(iv, last_outbound_mac);
    osdp_status_t r = osdp_sc_cbc_decrypt(crypto, s_enc, iv,
                                          ciphertext, ciphertext_len,
                                          plaintext);
    if (r != OSDP_OK) {
        return r;
    }

    /* Strip 0x80-padding: walk back from the end looking for the
     * 0x80 marker. Spec guarantees its presence; if not found, the
     * input must be corrupt. */
    size_t i = ciphertext_len;
    while (i > 0) {
        i--;
        if (plaintext[i] == 0x80U) {
            *plaintext_len = i;
            return OSDP_OK;
        }
        if (plaintext[i] != 0x00U) {
            return OSDP_ERR_BAD_PAYLOAD;
        }
    }
    /* Walked the entire decrypted block without finding 0x80 — the
     * decryption produced no recognisable padding. Treat as corrupt
     * (likely a wrong S-ENC or wrong IV). */
    return OSDP_ERR_BAD_PAYLOAD;
}
