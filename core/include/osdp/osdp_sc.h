// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_SC_H
#define OSDP_SC_H

#include "osdp/osdp_sc_crypto.h"
#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_sc — Secure Channel cryptographic primitives.
 *
 * Implements the algorithms of SIA OSDP v2.2.2 Annex D on top of an
 * abstract AES-128 ECB primitive supplied via osdp_sc_crypto_t. This
 * header exposes the primitives that the per-role state machines
 * (osdp::pd, osdp::acu) build on:
 *
 *   - Session key derivation: SCBK + RND.A → S-ENC, S-MAC1, S-MAC2.
 *   - Client / Server cryptogram computation.
 *   - Initial R-MAC = Enc(S-MAC2, Enc(S-MAC1, ServerCryptogram)).
 *   - Custom CBC-MAC over a padded message (S-MAC1 for blocks 1..n-1,
 *     S-MAC2 for block n; spec section D.5).
 *   - AES-128 CBC encrypt / decrypt of N×16-byte payloads.
 *
 * Every routine here is pure: no allocations, no globals, no I/O.
 * Failures are limited to caller-violation conditions (NULL pointers,
 * input lengths that aren't a multiple of 16, missing decrypt on a
 * crypto vtable) and propagation of errors from the supplied AES
 * primitive. */

#define OSDP_SC_KEY_LEN          16U
#define OSDP_SC_RND_LEN           8U
#define OSDP_SC_CUID_LEN          8U
#define OSDP_SC_CRYPTOGRAM_LEN   16U
#define OSDP_SC_MAC_LEN          16U
#define OSDP_SC_MAC_TRUNCATED    4U   /* sent on the wire             */

/* Trio of session keys derived from SCBK + RND.A at the start of an
 * SC session (spec D.4.1). All three are AES-128 keys; the consumer
 * is expected to keep them in memory only as long as the session is
 * active. */
typedef struct osdp_sc_session_keys {
    uint8_t s_enc [OSDP_SC_KEY_LEN];
    uint8_t s_mac1[OSDP_SC_KEY_LEN];
    uint8_t s_mac2[OSDP_SC_KEY_LEN];
} osdp_sc_session_keys_t;

/* Derive the session key trio from the static SCBK and the ACU's
 * 8-byte random number RND.A. Per spec D.4.1, only the first 6 bytes
 * of RND.A participate in derivation; the trailing two random bytes
 * are mixed into cryptograms but not into the key derivation input. */
osdp_status_t osdp_sc_derive_session_keys(
    const osdp_sc_crypto_t      *crypto,
    const uint8_t                scbk [OSDP_SC_KEY_LEN],
    const uint8_t                rnd_a[OSDP_SC_RND_LEN],
    osdp_sc_session_keys_t      *out);

/* Client Cryptogram = Enc(S-ENC, RND.A || RND.B). Per spec D.4.3. */
osdp_status_t osdp_sc_client_cryptogram(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_enc[OSDP_SC_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC_RND_LEN],
    uint8_t                  out  [OSDP_SC_CRYPTOGRAM_LEN]);

/* Server Cryptogram = Enc(S-ENC, RND.B || RND.A). Per spec D.4.4. */
osdp_status_t osdp_sc_server_cryptogram(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_enc[OSDP_SC_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC_RND_LEN],
    uint8_t                  out  [OSDP_SC_CRYPTOGRAM_LEN]);

/* Initial R-MAC = Enc(S-MAC2, Enc(S-MAC1, ServerCryptogram)).
 * Per spec D.3.2. The PD computes this and ships it to the ACU in the
 * osdp_RMAC_I reply (SCS_14). After this, both peers have the same
 * starting MAC chain ICV. */
osdp_status_t osdp_sc_initial_rmac(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_mac1        [OSDP_SC_KEY_LEN],
    const uint8_t            s_mac2        [OSDP_SC_KEY_LEN],
    const uint8_t            server_crypto [OSDP_SC_CRYPTOGRAM_LEN],
    uint8_t                  out           [OSDP_SC_MAC_LEN]);

/* Compute the OSDP custom CBC-MAC over `msg[0..len)`. Per spec D.5:
 *
 *   1. Pad to a multiple of 16 with 0x80, then 0x00s. Padding is
 *      applied iff `len` is not already a multiple of 16. (Note the
 *      asymmetry with payload padding, which always pads even on
 *      exact multiples.)
 *   2. CBC-encrypt the padded message with ICV = `icv`. For all
 *      blocks except the last, the key is S-MAC1; for the final
 *      block, the key is S-MAC2. If padding leaves only one block
 *      total, S-MAC2 is the only key used.
 *   3. The resulting ciphertext of the final block IS the MAC; only
 *      the first OSDP_SC_MAC_TRUNCATED bytes are actually transmitted
 *      on the wire, but this routine always outputs the full 16-byte
 *      MAC so the caller can keep it for the next ICV. */
osdp_status_t osdp_sc_compute_mac(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_mac1[OSDP_SC_KEY_LEN],
    const uint8_t            s_mac2[OSDP_SC_KEY_LEN],
    const uint8_t            icv   [OSDP_SC_MAC_LEN],
    const uint8_t           *msg,
    size_t                   len,
    uint8_t                  out   [OSDP_SC_MAC_LEN]);

/* AES-128 CBC encrypt of `len` plaintext bytes. `len` must be a
 * non-zero multiple of OSDP_AES_BLOCK_LEN (16). Output buffer must be
 * at least `len` bytes. `ciphertext` may alias `plaintext`. */
osdp_status_t osdp_sc_cbc_encrypt(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            key       [OSDP_SC_KEY_LEN],
    const uint8_t            iv        [OSDP_AES_BLOCK_LEN],
    const uint8_t           *plaintext,
    size_t                   len,
    uint8_t                 *ciphertext);

/* AES-128 CBC decrypt of `len` ciphertext bytes. `len` must be a
 * non-zero multiple of OSDP_AES_BLOCK_LEN (16). Output buffer must be
 * at least `len` bytes. Returns OSDP_ERR_NOT_SUPPORTED if the supplied
 * crypto vtable does not provide aes128_ecb_decrypt. */
osdp_status_t osdp_sc_cbc_decrypt(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            key        [OSDP_SC_KEY_LEN],
    const uint8_t            iv         [OSDP_AES_BLOCK_LEN],
    const uint8_t           *ciphertext,
    size_t                   len,
    uint8_t                 *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_SC_H */
