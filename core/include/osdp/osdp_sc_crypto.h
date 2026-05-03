// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_SC_CRYPTO_H
#define OSDP_SC_CRYPTO_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_sc_crypto — abstract cryptographic primitive HAL.
 *
 * OSDP Secure Channel (Annex D) is built entirely on top of AES-128
 * block operations. Key derivation, the Client/Server cryptograms,
 * the initial R-MAC, the rolling MAC, and the CBC-mode payload
 * encryption all reduce to repeated AES-128 ECB encrypt or decrypt of
 * single 16-byte blocks. This HAL exposes that one primitive in both
 * directions; every higher-level OSDP-SC routine in this library is
 * built on top of it.
 *
 * Per CLAUDE.md, the core never vendors a crypto implementation. The
 * consumer fills the vtable from whatever is appropriate for their
 * deployment:
 *
 *   - Bare-metal MCU: a hardware AES peripheral (STM32 CRYP,
 *     nRF CryptoCell, ESP32 AES accelerator).
 *   - Linux/POSIX: mbedTLS, OpenSSL, BearSSL, nettle.
 *   - Tests: a tiny portable AES (we vendor `kokke/tiny-AES-c` under
 *     `tests/vendor/tiny-aes/` purely for this purpose).
 *
 * Constant-time and side-channel hardening are the implementer's
 * responsibility — the OSDP-SC level neither requires nor enforces
 * them.
 *
 * The functions are NOT permitted to fail in normal operation; the
 * `osdp_status_t` return is reserved for caller-violation conditions
 * such as a NULL pointer or a missing implementation. A successful
 * encrypt/decrypt always returns OSDP_OK and writes 16 bytes. */

#define OSDP_AES_BLOCK_LEN 16U
#define OSDP_AES_KEY_LEN   16U

typedef struct osdp_sc_crypto {
    /* Encrypt one 16-byte block. `key`, `in`, and `out` are each
     * exactly OSDP_AES_BLOCK_LEN bytes. `out` may alias `in`. */
    osdp_status_t (*aes128_ecb_encrypt)(
        void          *user,
        const uint8_t  key[OSDP_AES_KEY_LEN],
        const uint8_t  in [OSDP_AES_BLOCK_LEN],
        uint8_t        out[OSDP_AES_BLOCK_LEN]);

    /* Decrypt one 16-byte block. Required for receiving SCS_17/18
     * encrypted payloads on the recipient side. May be NULL if the
     * consumer is implementing a one-direction agent (e.g. a Monitor
     * that only verifies MACs and never decrypts payloads); higher-
     * level routines that require decrypt return
     * OSDP_ERR_NOT_SUPPORTED. */
    osdp_status_t (*aes128_ecb_decrypt)(
        void          *user,
        const uint8_t  key[OSDP_AES_KEY_LEN],
        const uint8_t  in [OSDP_AES_BLOCK_LEN],
        uint8_t        out[OSDP_AES_BLOCK_LEN]);

    /* Fill `out` with `len` cryptographically-random bytes. Required
     * by either role for the side that generates randomness during
     * the SC handshake — the PD generates 8-byte RND.B; the ACU
     * generates 8-byte RND.A. May be NULL on roles that only consume
     * randomness from the peer (e.g. a Monitor) or that supply
     * randomness through a separate channel. Returns OSDP_OK on
     * success. */
    osdp_status_t (*rand_bytes)(void *user, uint8_t *out, size_t len);

    /* Opaque pointer threaded back into all callbacks. */
    void *user;
} osdp_sc_crypto_t;

#ifdef __cplusplus
}
#endif

#endif /* OSDP_SC_CRYPTO_H */
