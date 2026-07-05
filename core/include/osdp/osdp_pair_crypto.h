// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PAIR_CRYPTO_H
#define OSDP_PAIR_CRYPTO_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_pair_crypto — abstract cryptographic HAL for OSDP-SC2 asymmetric
 * device pairing.
 *
 * Pairing is a post-quantum, EDHOC-style mutual-auth key agreement:
 * ML-KEM-768 (FIPS 203) for key encapsulation, ML-DSA-44 (FIPS 204,
 * deterministic) for signatures and the C509 certificate PKI, and
 * HKDF/HMAC/SHA-256 for the key schedule and key confirmation. As with the
 * SC1 (osdp_sc_crypto_t) and SC2 (osdp_sc2_crypto_t) HALs, the freestanding
 * core implements NONE of it — the consumer supplies every primitive. A PQC
 * library (WolfSSL, mbedTLS + liboqs, OpenSSL 3.5+, a hardware accelerator,
 * an MCU PQClean build) binds to this one contract with no core change.
 *
 * Private-key handling: the core never sees private key bytes. Long-term
 * device keys (the ML-DSA-44 signing key) and transient per-handshake keys
 * (the ACU's ephemeral ML-KEM-768 decapsulation key) live inside the
 * consumer-owned `user` context. Because exactly one pairing runs at a time
 * per role, keygen/decaps are paired through `user`:
 *
 *   ACU: ml_kem768_keygen(user, ek) stashes the ephemeral dk in `user`;
 *        a later ml_kem768_decaps(user, ct, ss) consumes that stashed dk.
 *   Both: ml_dsa44_sign(user, msg, sig) signs with the device's long-term
 *        ML-DSA-44 key held in `user`.
 *
 * All sizes are the fixed FIPS parameter-set sizes. Callbacks return
 * OSDP_OK on success; ml_dsa44_verify returns a non-OK status when the
 * signature is invalid, and any callback may report OSDP_ERR_INVALID_ARG /
 * OSDP_ERR_NOT_SUPPORTED for a caller/backend fault. Constant-time and
 * side-channel hardening are the implementer's responsibility. */

#define OSDP_MLKEM768_EK_LEN   1184U  /* encapsulation (public) key         */
#define OSDP_MLKEM768_CT_LEN   1088U  /* ciphertext                         */
#define OSDP_MLKEM_SS_LEN        32U  /* shared secret                      */
#define OSDP_MLDSA44_PK_LEN    1312U  /* verification (public) key          */
#define OSDP_MLDSA44_SIG_LEN   2420U  /* signature                          */
#define OSDP_PAIR_HASH_LEN       32U  /* SHA-256 / HMAC-SHA256 output        */

typedef struct osdp_pair_crypto {
    /* Generate an ephemeral ML-KEM-768 keypair; write the encapsulation key
     * to `ek` and retain the decapsulation key in `user` for a subsequent
     * decaps. ACU (initiator) side only. */
    osdp_status_t (*ml_kem768_keygen)(
        void    *user,
        uint8_t  ek[OSDP_MLKEM768_EK_LEN]);

    /* Encapsulate to `ek`, producing ciphertext `ct` and shared secret
     * `ss`. Stateless. PD (responder) side. */
    osdp_status_t (*ml_kem768_encaps)(
        void          *user,
        const uint8_t  ek[OSDP_MLKEM768_EK_LEN],
        uint8_t        ct[OSDP_MLKEM768_CT_LEN],
        uint8_t        ss[OSDP_MLKEM_SS_LEN]);

    /* Decapsulate `ct` with the ephemeral decapsulation key stashed by the
     * preceding keygen, producing shared secret `ss`. ACU side. */
    osdp_status_t (*ml_kem768_decaps)(
        void          *user,
        const uint8_t  ct[OSDP_MLKEM768_CT_LEN],
        uint8_t        ss[OSDP_MLKEM_SS_LEN]);

    /* Sign `msg` with the device's long-term ML-DSA-44 key held in `user`,
     * writing the 2420-byte signature to `sig`. Deterministic signing (per
     * FIPS 204) so demo certs and test vectors reproduce. */
    osdp_status_t (*ml_dsa44_sign)(
        void          *user,
        const uint8_t *msg, size_t msg_len,
        uint8_t        sig[OSDP_MLDSA44_SIG_LEN]);

    /* Verify `sig` over `msg` under public key `pk`. Returns OSDP_OK iff the
     * signature is valid; a non-OK status otherwise. Stateless. */
    osdp_status_t (*ml_dsa44_verify)(
        void          *user,
        const uint8_t  pk[OSDP_MLDSA44_PK_LEN],
        const uint8_t *msg, size_t msg_len,
        const uint8_t  sig[OSDP_MLDSA44_SIG_LEN]);

    /* SHA-256 over `data`. */
    osdp_status_t (*sha256)(
        void          *user,
        const uint8_t *data, size_t len,
        uint8_t        out[OSDP_PAIR_HASH_LEN]);

    /* HMAC-SHA256 of `data` keyed by `key`. */
    osdp_status_t (*hmac_sha256)(
        void          *user,
        const uint8_t *key,  size_t key_len,
        const uint8_t *data, size_t data_len,
        uint8_t        out[OSDP_PAIR_HASH_LEN]);

    /* HKDF-SHA256 (RFC 5869 extract-then-expand) producing `out_len` bytes
     * from `salt` / `ikm` / `info`. */
    osdp_status_t (*hkdf_sha256)(
        void          *user,
        const uint8_t *salt, size_t salt_len,
        const uint8_t *ikm,  size_t ikm_len,
        const uint8_t *info, size_t info_len,
        uint8_t       *out,  size_t out_len);

    /* Fill `out` with `len` cryptographically-random bytes (nonces). */
    osdp_status_t (*rand_bytes)(void *user, uint8_t *out, size_t len);

    /* Opaque pointer threaded into every callback; also holds the private
     * key state described above. */
    void *user;
} osdp_pair_crypto_t;

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PAIR_CRYPTO_H */
