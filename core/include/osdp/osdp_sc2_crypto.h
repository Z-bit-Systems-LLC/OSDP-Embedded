// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_SC2_CRYPTO_H
#define OSDP_SC2_CRYPTO_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_sc2_crypto — abstract cryptographic primitive HAL for OSDP-SC2.
 *
 * OSDP Secure Channel 2 (the quantum-resistant channel) is built on a
 * different primitive set than SC1: AES-256-GCM for authenticated
 * message protection, KMAC256 for session-key derivation, and a raw
 * AES-256 block encrypt for the nonce derivation and the (CBC-chained)
 * cryptograms. This HAL exposes exactly those primitives; every
 * higher-level SC2 routine in this library is built on top of them.
 *
 * Per CLAUDE.md the core never vendors a crypto implementation — and
 * SC2 explicitly does NOT put GHASH / GF(2^128) or Keccak inside the
 * freestanding core. The consumer supplies:
 *
 *   - Bare-metal MCU: a hardware AES-GCM peripheral where available
 *     (STM32 CRYP-GCM, etc.) plus a compact Keccak for KMAC.
 *   - Linux/POSIX: mbedTLS / OpenSSL / BearSSL for AES-256-GCM, and
 *     a SHA-3/KMAC provider for KMAC256.
 *   - Tests / tools: the vendored SC2 test backend (AES-256 + GCM +
 *     KMAC256), never linked into a production core.
 *
 * Constant-time and side-channel hardening are the implementer's
 * responsibility, exactly as for the SC1 HAL.
 *
 * The functions are NOT permitted to fail in normal operation; the
 * osdp_status_t return is reserved for caller-violation conditions
 * (NULL pointer, missing implementation) and — for GCM decrypt — the
 * one expected runtime failure, tag verification. */

#define OSDP_AES256_KEY_LEN   32U
#define OSDP_SC2_GCM_NONCE_LEN 12U
#define OSDP_SC2_GCM_TAG_LEN   16U

typedef struct osdp_sc2_crypto {
    /* KMAC256 (NIST SP 800-185) with an EMPTY customization string.
     * Computes a `out_len`-byte MAC over `data` keyed by `key`. SC2
     * only ever requests a 32-byte (256-bit) output. Required for both
     * roles (session-key derivation happens on PD and ACU). */
    osdp_status_t (*kmac256)(
        void          *user,
        const uint8_t *key,  size_t key_len,
        const uint8_t *data, size_t data_len,
        uint8_t       *out,  size_t out_len);

    /* AES-256-GCM authenticated encryption. Encrypts `pt_len` plaintext
     * bytes into `ct` (same length — GCM is CTR-based, no padding) and
     * writes the 16-byte authentication tag to `tag`. `aad`/`aad_len`
     * are the additional authenticated data (for SC2, the 6-byte frame
     * header). `ct` may alias `pt`. Required by both roles. */
    osdp_status_t (*aes256_gcm_encrypt)(
        void          *user,
        const uint8_t  key  [OSDP_AES256_KEY_LEN],
        const uint8_t  nonce[OSDP_SC2_GCM_NONCE_LEN],
        const uint8_t *aad,  size_t aad_len,
        const uint8_t *pt,   size_t pt_len,
        uint8_t       *ct,
        uint8_t        tag  [OSDP_SC2_GCM_TAG_LEN]);

    /* AES-256-GCM authenticated decryption. Verifies `tag` over
     * (`aad`, `ct`) and, iff it matches, writes `ct_len` plaintext
     * bytes to `pt`. Returns OSDP_OK on a valid tag, OSDP_ERR_BAD_CRC
     * on tag mismatch (the caller treats that as "ignore this frame,"
     * uniform with SC1). `pt` may alias `ct`. Required by both roles. */
    osdp_status_t (*aes256_gcm_decrypt)(
        void          *user,
        const uint8_t  key  [OSDP_AES256_KEY_LEN],
        const uint8_t  nonce[OSDP_SC2_GCM_NONCE_LEN],
        const uint8_t *aad,  size_t aad_len,
        const uint8_t *ct,   size_t ct_len,
        const uint8_t  tag  [OSDP_SC2_GCM_TAG_LEN],
        uint8_t       *pt);

    /* Encrypt one 16-byte block with a 256-bit key (raw AES-256 ECB /
     * single-block). SC2 uses this to derive the per-message nonce and,
     * with the library chaining two blocks itself, to compute the
     * client/server cryptograms (AES-256-CBC, zero IV). `out` may alias
     * `in`. Required by both roles. */
    osdp_status_t (*aes256_ecb_encrypt)(
        void          *user,
        const uint8_t  key[OSDP_AES256_KEY_LEN],
        const uint8_t  in [16],
        uint8_t        out[16]);

    /* Fill `out` with `len` cryptographically-random bytes. The PD
     * generates 16-byte RND.B; the ACU generates 16-byte RND.A. May be
     * NULL on a role that only consumes randomness from the peer.
     * Returns OSDP_OK on success. */
    osdp_status_t (*rand_bytes)(void *user, uint8_t *out, size_t len);

    /* Opaque pointer threaded back into all callbacks. */
    void *user;
} osdp_sc2_crypto_t;

#ifdef __cplusplus
}
#endif

#endif /* OSDP_SC2_CRYPTO_H */
