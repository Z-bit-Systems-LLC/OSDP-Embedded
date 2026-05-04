// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_SC_H
#define OSDP_SC_H

#include "osdp/osdp_frame.h"
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

/* Default install-time SCBK ("SCBK-D") per spec section D.4 / page 4090.
 * "Define the Default SCBK (SCBK-D) for use during installation as the
 * constant 0x30, 0x31 ... 0x3F (16 bytes inclusive). The SCBK-D shall
 * be supported by all implementations of OSDP-SC. The SCBK-D will be
 * known to anyone with the public spec; only PDs in installation mode
 * are allowed to use the SCBK-D." Linkage is in core/src/sc/keys.c. */
extern const uint8_t OSDP_SCBK_DEFAULT[OSDP_SC_KEY_LEN];

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

/* ---- Session state ------------------------------------------------------
 *
 * Both PD and ACU embed an osdp_sc_session_t per peer. The struct is
 * pure data: the higher-level state machines (osdp::pd, osdp::acu)
 * are responsible for advancing the chain on every send / verify.
 *
 *   keys              — derived once at handshake completion.
 *   last_outbound_mac — full 16-byte MAC of the most recent message
 *                       this peer sent. ICV for verifying the next
 *                       inbound MAC; basis (after one's-complement
 *                       inversion) for the IV when DECRYPTING the
 *                       next inbound SCS_17/18 payload.
 *   last_inbound_mac  — full 16-byte MAC of the most recent message
 *                       this peer received and verified. ICV for
 *                       computing the next outbound MAC; basis for
 *                       the IV when ENCRYPTING the next outbound
 *                       SCS_17/18 payload.
 *   established       — true after the SCS_11..14 handshake completes.
 *                       SCS_15..18 traffic is only valid while true.
 *
 * On both sides, both MAC fields are initialised to the Initial R-MAC
 * generated during the handshake (spec D.3.2 / D.4 / D.5). After that,
 * each successful send updates last_outbound_mac and each successful
 * verify updates last_inbound_mac. */
typedef struct osdp_sc_session {
    osdp_sc_session_keys_t keys;
    uint8_t                last_outbound_mac[OSDP_SC_MAC_LEN];
    uint8_t                last_inbound_mac [OSDP_SC_MAC_LEN];
    bool                   established;
} osdp_sc_session_t;

/* Initialise an SC session struct to a clean, un-established state.
 * Required before first use; equivalent to memset-zero. */
void osdp_sc_session_init(osdp_sc_session_t *session);

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

/* ---- SCS_17 / SCS_18 payload encryption ----------------------------------
 *
 * For Secure Channel commands and replies that carry encrypted data
 * (SEC_BLK_TYPE = SCS_17 or SCS_18), the data block is:
 *
 *   1. 0x80-padded to a multiple of 16. Per spec D.4.5, this padding
 *      is ALWAYS applied even on inputs whose length is already an
 *      exact multiple — distinct from the MAC padding rule.
 *   2. Encrypted with AES-128 CBC, key = S-ENC, IV = ones-complement
 *      of "the MAC of the last message received from the device the
 *      message is being prepared for" (spec D.5.1 step 5).
 *
 * On the receiving side, decrypt then trim padding. */

/* Encrypt a plaintext payload into ciphertext. Output is guaranteed
 * to be a multiple of OSDP_AES_BLOCK_LEN; specifically, output length =
 * plaintext_len rounded UP to the next multiple of 16, with at least
 * one pad byte (so even multiple-of-16 inputs grow by 16).
 *
 *   `last_inbound_mac` is the full 16-byte MAC most recently verified
 *   on a frame from the peer. The IV is the bit-wise complement of
 *   that value. */
osdp_status_t osdp_sc_encrypt_payload(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_enc           [OSDP_SC_KEY_LEN],
    const uint8_t            last_inbound_mac[OSDP_SC_MAC_LEN],
    const uint8_t           *plaintext,
    size_t                   plaintext_len,
    uint8_t                 *ciphertext,
    size_t                   ciphertext_cap,
    size_t                  *ciphertext_len);

/* Decrypt and depad. `last_outbound_mac` is the full 16-byte MAC most
 * recently sent to the peer; IV is its bit-wise complement.
 *
 * Returns OSDP_ERR_BAD_PAYLOAD if the depad step cannot find a 0x80
 * marker — typically a sign of MAC mismatch upstream or a corrupt
 * key. Returns OSDP_ERR_NOT_SUPPORTED if the crypto vtable lacks an
 * AES decrypt function. */
osdp_status_t osdp_sc_decrypt_payload(
    const osdp_sc_crypto_t  *crypto,
    const uint8_t            s_enc            [OSDP_SC_KEY_LEN],
    const uint8_t            last_outbound_mac[OSDP_SC_MAC_LEN],
    const uint8_t           *ciphertext,
    size_t                   ciphertext_len,
    uint8_t                 *plaintext,
    size_t                   plaintext_cap,
    size_t                  *plaintext_len);

/* ---- Frame wrap / unwrap -------------------------------------------------
 *
 * Build or consume a complete OSDP-SC operational frame (SCS_15..18).
 * These compose the lower-level primitives:
 *
 *   wrap   = optional payload encryption + frame_build with placeholder
 *            MAC + MAC computation + integrity recomputation. Updates
 *            session->last_outbound_mac on success.
 *
 *   unwrap = MAC verification on the already-decoded frame's `raw`
 *            slice + optional payload decryption. Updates
 *            session->last_inbound_mac on success.
 *
 * Both honour the spec D.5 ICV chain rules: outbound MAC ICV is the
 * peer's last-sent MAC (which from our perspective is
 * session->last_inbound_mac), inbound MAC ICV is our last-sent MAC
 * (session->last_outbound_mac). For SCS_17/18 payload encrypt/decrypt
 * the IV is the bit-wise complement of the same chain entry per
 * D.5.1 step 5 / D.5.2 step 4.
 *
 * Handshake frames (SCS_11..14) do NOT carry a MAC — those go through
 * osdp_frame_decode/build directly. Pre-handshake (un-established)
 * sessions cannot wrap/unwrap; the routines return
 * OSDP_ERR_INVALID_ARG until session->established is true. */

/* Build an outbound SCS_15..18 frame.
 *
 * `plain_template` carries the frame's headers, code, scb_type, and
 * (for the encrypted variants) the *plaintext* payload. The function
 * encrypts internally if scb_type is SCS_17/18, computes the MAC,
 * appends it before the trailing integrity bytes, and writes the
 * complete wire bytes to `out_buf`. `out_buf` may NOT alias the
 * template's payload pointer.
 *
 * On success, updates session->last_outbound_mac with the freshly-
 * computed full 16-byte MAC. */
osdp_status_t osdp_sc_wrap_frame(
    const osdp_sc_crypto_t  *crypto,
    osdp_sc_session_t       *session,
    const osdp_frame_t      *plain_template,
    uint8_t                 *out_buf,
    size_t                   out_cap,
    size_t                  *out_len);

/* Verify and unwrap an inbound SCS_15..18 frame.
 *
 * `frame` must already have come from a successful osdp_frame_decode
 * (so its CRC is valid and `mac` / `mac_len` are populated). The
 * function recomputes the expected MAC over `frame->raw[0..mac_offset)`
 * and compares the leading 4 bytes with the truncated MAC the peer
 * sent; on mismatch it returns OSDP_ERR_BAD_CRC. (Re-using the
 * existing error code rather than introducing a new one keeps the
 * caller's error-handling path uniform: any integrity failure means
 * "this frame should be ignored.")
 *
 * For SCS_15/16 the plaintext is just `frame->payload`; for SCS_17/18
 * the function decrypts and removes 0x80 padding. The decrypted /
 * copied result lands in `plaintext_out`; `*plaintext_len` receives
 * the byte count.
 *
 * On success, updates session->last_inbound_mac with the freshly-
 * computed full 16-byte MAC. */
osdp_status_t osdp_sc_unwrap_frame(
    const osdp_sc_crypto_t  *crypto,
    osdp_sc_session_t       *session,
    const osdp_frame_t      *frame,
    uint8_t                 *plaintext_out,
    size_t                   plain_cap,
    size_t                  *plain_len);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_SC_H */
