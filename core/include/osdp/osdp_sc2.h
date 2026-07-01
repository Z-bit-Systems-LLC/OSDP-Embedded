// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_SC2_H
#define OSDP_SC2_H

#include "osdp/osdp_frame.h"
#include "osdp/osdp_sc2_crypto.h"
#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_sc2 — Secure Channel 2 cryptographic primitives.
 *
 * SC2 is OSDP's quantum-resistant secure channel: AES-256-GCM message
 * protection with KMAC256-derived session keys, occupying the SCS_21..28
 * Security Block range parallel to SC1's SCS_11..18. This header exposes
 * the primitives the per-role state machines (osdp::pd, osdp::acu) build
 * on, all pure (no allocation, no globals, no I/O) and layered on the
 * osdp_sc2_crypto_t HAL:
 *
 *   - Session key derivation: SCBK + RND.A + RND.B → S-ENC, S-NONCE
 *     (KMAC256, empty customization).
 *   - Client / Server cryptogram (AES-256-CBC, zero IV, 32 bytes).
 *   - Per-message nonce derivation from cUID + a rolling counter.
 *   - Frame wrap / unwrap of SCS_25..28 (AES-256-GCM).
 *
 * Byte layouts and the exact key-derivation / cryptogram / nonce rules
 * were verified against the OSDP.Net feature/osdp-sc2 reference; see
 * the annex in docs and the known-answer vectors in the SC2 tests. */

#define OSDP_SC2_KEY_LEN         32U   /* AES-256 session/base key      */
#define OSDP_SC2_RND_LEN         16U   /* RND.A / RND.B                 */
#define OSDP_SC2_CUID_LEN         8U   /* client UID                    */
#define OSDP_SC2_CRYPTOGRAM_LEN  32U   /* client / server cryptogram    */
#define OSDP_SC2_NONCE_LEN       12U   /* AES-256-GCM nonce             */
#define OSDP_SC2_TAG_LEN         16U   /* AES-256-GCM tag (the "MAC")   */

/* SEC_BLK_DATA[0] value that selects SC2 during the SCS_21..24
 * handshake (0x00 = SC1 default key, 0x01 = SC1 device key). */
#define OSDP_SC2_SELECTOR        0x02U

/* SCS_24 (osdp_RMAC_I) status byte, carried in SEC_BLK_DATA[0]. */
#define OSDP_SC2_STATUS_OK       0x02U   /* handshake accepted          */
#define OSDP_SC2_STATUS_FAIL     0xFFU   /* server cryptogram rejected  */

/* Per NIST SP 800-38D, an AES-GCM key must not be used for more than
 * 2^32 invocations. The reference caps the message counter well below
 * that; once reached, the session must be torn down and re-handshaked
 * rather than allowed to roll over. */
#define OSDP_SC2_COUNTER_MAX     500000000UL

/* Two session keys derived from SCBK + RND.A + RND.B at the start of a
 * session. Both are AES-256 keys; keep them only while the session is
 * active. */
typedef struct osdp_sc2_session_keys {
    uint8_t s_enc  [OSDP_SC2_KEY_LEN];
    uint8_t s_nonce[OSDP_SC2_KEY_LEN];
} osdp_sc2_session_keys_t;

/* Derive the SC2 session keys:
 *   S-ENC   = KMAC256(SCBK, RND.A || RND.B, 256)
 *   S-NONCE = KMAC256(SCBK, RND.B || RND.A, 256)
 * (customization string empty). RND.A is the ACU's 16-byte random,
 * RND.B the PD's. */
osdp_status_t osdp_sc2_derive_session_keys(
    const osdp_sc2_crypto_t *crypto,
    const uint8_t            scbk [OSDP_SC2_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC2_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC2_RND_LEN],
    osdp_sc2_session_keys_t *out);

/* Client Cryptogram = AES-256-CBC(S-ENC, IV=0, RND.A || RND.B), no
 * padding — 32 bytes, genuinely chained across the two 16-byte blocks
 * (NOT ECB). Computed by the PD, verified by the ACU. */
osdp_status_t osdp_sc2_client_cryptogram(
    const osdp_sc2_crypto_t *crypto,
    const uint8_t            s_enc[OSDP_SC2_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC2_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC2_RND_LEN],
    uint8_t                  out  [OSDP_SC2_CRYPTOGRAM_LEN]);

/* Server Cryptogram = AES-256-CBC(S-ENC, IV=0, RND.B || RND.A), no
 * padding — 32 bytes. Computed by the ACU, verified by the PD. */
osdp_status_t osdp_sc2_server_cryptogram(
    const osdp_sc2_crypto_t *crypto,
    const uint8_t            s_enc[OSDP_SC2_KEY_LEN],
    const uint8_t            rnd_a[OSDP_SC2_RND_LEN],
    const uint8_t            rnd_b[OSDP_SC2_RND_LEN],
    uint8_t                  out  [OSDP_SC2_CRYPTOGRAM_LEN]);

/* Derive the 12-byte AES-256-GCM nonce for a given message counter:
 *   PLAIN = cUID[8] || counter(4, little-endian) || 0x80 0x00 0x00 0x00
 *   NONCE = first 12 bytes of AES-256(S-NONCE, PLAIN)
 * The single-block AES here is provided by the HAL's aes256_ecb_encrypt
 * (CBC with a zero IV over one block is identical to ECB). */
osdp_status_t osdp_sc2_compute_nonce(
    const osdp_sc2_crypto_t *crypto,
    const uint8_t            s_nonce[OSDP_SC2_KEY_LEN],
    const uint8_t            cuid   [OSDP_SC2_CUID_LEN],
    uint32_t                 counter,
    uint8_t                  nonce  [OSDP_SC2_NONCE_LEN]);

/* ---- Session state ------------------------------------------------------
 *
 * Both PD and ACU embed an osdp_sc2_session_t per peer. Unlike SC1's
 * rolling MAC chain, SC2 anti-replay is a single monotonic message
 * counter shared by BOTH directions: it starts at 0 when the session
 * is established and increments by one after every message the peer
 * sends OR receives. The counter feeds the per-message nonce.
 *
 *   keys        — derived once at handshake completion.
 *   cuid        — the PD's client UID; part of every nonce.
 *   counter     — next message's counter value (see above).
 *   established — true after SCS_21..24 completes; SCS_25..28 traffic
 *                 is only valid while true. */
typedef struct osdp_sc2_session {
    osdp_sc2_session_keys_t keys;
    uint8_t                 cuid[OSDP_SC2_CUID_LEN];
    uint32_t                counter;
    bool                    established;
} osdp_sc2_session_t;

/* Initialise an SC2 session struct to a clean, un-established state.
 * Required before first use; equivalent to memset-zero. */
void osdp_sc2_session_init(osdp_sc2_session_t *session);

/* ---- Frame wrap / unwrap -------------------------------------------------
 *
 * Build or consume a complete OSDP-SC2 operational frame (SCS_25..28).
 * These compose the primitives above with AES-256-GCM:
 *
 *   wrap   = derive nonce from session->counter, GCM-encrypt the
 *            plaintext (code||data) with S-ENC and AAD = the 6-byte
 *            frame header, append the 16-byte tag, add integrity.
 *            Increments session->counter on success.
 *
 *   unwrap = derive nonce, GCM-verify+decrypt over the same AAD, hand
 *            back the plaintext (code||data). Increments
 *            session->counter on success.
 *
 * The single counter advances on BOTH wrap and unwrap (one shared
 * counter per session, per the reference). Handshake frames (SCS_21..24)
 * carry no tag and go through osdp_frame_decode/build directly.
 * Un-established sessions cannot wrap/unwrap (returns
 * OSDP_ERR_INVALID_ARG until session->established is true).
 *
 * Project convention mirrors SC1: SCS_27/28 are for messages that carry
 * data; a zero-length payload with scb_type SCS_27/28 is coerced to
 * SCS_25/26. (Note the code byte itself is always present in the
 * plaintext, so the GCM plaintext is never empty even for an
 * empty-payload POLL.) */

/* Build an outbound SCS_25..28 frame.
 *
 * `plain_template` carries the headers, code, scb_type and the
 * *plaintext* payload. For SCS_25/26 the code+payload are transmitted
 * in the clear and only authenticated; for SCS_27/28 they are
 * encrypted. The 16-byte GCM tag is appended before the integrity
 * bytes. `out_buf` may NOT alias the template's payload pointer.
 *
 * On success, increments session->counter. */
osdp_status_t osdp_sc2_wrap_frame(
    const osdp_sc2_crypto_t *crypto,
    osdp_sc2_session_t      *session,
    const osdp_frame_t      *plain_template,
    uint8_t                 *out_buf,
    size_t                   out_cap,
    size_t                  *out_len);

/* Verify and unwrap an inbound SCS_25..28 frame.
 *
 * `frame` must already have come from a successful osdp_frame_decode
 * (so its CRC is valid and `mac`/`mac_len` hold the 16-byte tag). The
 * function derives the nonce, verifies the tag with AES-256-GCM over
 * AAD = the 6-byte header, and (for SCS_27/28) decrypts. On tag
 * mismatch it returns OSDP_ERR_BAD_CRC (uniform with SC1 — "ignore
 * this frame").
 *
 * The recovered plaintext is `code || data`; the leading code byte is
 * written to `*code_out` and the remaining data to `plaintext_out`
 * (`*plain_len` receives that data length, which may be 0). For
 * SCS_25/26 this simply reproduces the frame's own code+payload.
 *
 * On success, increments session->counter. */
osdp_status_t osdp_sc2_unwrap_frame(
    const osdp_sc2_crypto_t *crypto,
    osdp_sc2_session_t      *session,
    const osdp_frame_t      *frame,
    uint8_t                 *code_out,
    uint8_t                 *plaintext_out,
    size_t                   plain_cap,
    size_t                  *plain_len);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_SC2_H */
