// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PAIR_PQCLEAN_H
#define OSDP_PAIR_PQCLEAN_H

/* Reference osdp_pair_crypto_t backend: ML-KEM-768 + ML-DSA-44 + SHA-256 over
 * the vendored PQClean (vendor/pqclean/, CC0), with HMAC-SHA256 and
 * HKDF-SHA256 layered on top.
 *
 * Host-side reference code, NOT part of the freestanding library. It exists so
 * the hermetic KATs and the interop tools share one implementation of the
 * pairing HAL instead of each carrying a copy. A shipping device is expected
 * to bind its own PQC library — WolfSSL is the documented production target —
 * behind the same osdp_pair_crypto_t.
 *
 * Its public keys are cross-checked against OSDP.Net's published constants
 * byte for byte, so a device using this backend interoperates with the
 * reference implementation.
 *
 * The context carries this side's long-term ML-DSA-44 signing key (for
 * ml_dsa44_sign) and, between keygen and decaps, the peer's ephemeral
 * ML-KEM-768 decapsulation key — exactly the private-key ownership the HAL
 * contract describes. One context per role; a PD needs only encaps and sign.
 *
 * Entropy is not supplied by this port; see osdp_pair_pqclean_set_rand. */

#include "osdp/osdp_pair_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OSDP_PAIR_PQCLEAN_DSA_SK_LEN 2560U  /* PQClean ML-DSA-44 secret key */
#define OSDP_PAIR_PQCLEAN_KEM_SK_LEN 2400U  /* PQClean ML-KEM-768 secret key */

typedef struct osdp_pair_pqclean_ctx {
    uint8_t dsa_pk[OSDP_MLDSA44_PK_LEN];         /* long-term device pubkey  */
    uint8_t dsa_sk[OSDP_PAIR_PQCLEAN_DSA_SK_LEN];/* long-term device privkey */
    bool    has_dsa;
    uint8_t kem_sk[OSDP_PAIR_PQCLEAN_KEM_SK_LEN];/* ephemeral KEM privkey    */
    bool    has_kem_sk;
} osdp_pair_pqclean_ctx_t;

/* Entropy source for ML-KEM / ML-DSA key generation and the pairing nonces.
 * Return 0 on success, non-zero on failure.
 *
 * There is NO default. Every key this port generates comes from here, so
 * leaving it unset makes the underlying PQClean hook fail rather than fall
 * back to something predictable — a missing CSPRNG should announce itself,
 * not degrade quietly. Install one before generating a keypair or pairing.
 *
 * A build with OSDP_PAIR_PQCLEAN_DETERMINISTIC defined falls back to a fixed
 * reproducible stream instead of failing; that is for KATs only and cannot be
 * reached from a build without the define. */
typedef int (*osdp_pair_pqclean_rand_fn)(uint8_t *out, size_t n);
void osdp_pair_pqclean_set_rand(osdp_pair_pqclean_rand_fn fn);

/* Bind `ctx` to `crypto` and populate the vtable. Does not generate keys. */
void osdp_pair_pqclean_crypto_init(osdp_pair_crypto_t *crypto,
                                   osdp_pair_pqclean_ctx_t *ctx);

/* Generate a fresh long-term ML-DSA-44 device keypair into `ctx`. The public
 * key is left in ctx->dsa_pk for building / self-signing a certificate.
 *
 * Fails if no entropy source is installed, rather than producing a key from
 * a zeroed seed — PQClean's keypair call cannot report that itself, so this
 * is checked here. */
osdp_status_t osdp_pair_pqclean_gen_dsa(osdp_pair_pqclean_ctx_t *ctx);

/* Install a previously generated long-term ML-DSA-44 keypair — the device
 * credential a provisioning step produced and the firmware carries. Avoids
 * poking ctx's fields directly, which is easy to get half-right (a key set
 * without has_dsa signs nothing, and the failure looks like a HAL fault).
 *
 * Returns OSDP_ERR_INVALID_ARG for a NULL argument or an sk_len that is not
 * OSDP_PAIR_PQCLEAN_DSA_SK_LEN; the context is left untouched. */
osdp_status_t osdp_pair_pqclean_set_dsa(
    osdp_pair_pqclean_ctx_t *ctx,
    const uint8_t            pk[OSDP_MLDSA44_PK_LEN],
    const uint8_t           *sk, size_t sk_len);

#ifdef OSDP_PAIR_PQCLEAN_DETERMINISTIC
/* Queue `len` deterministic bytes for the next PQCLEAN_randombytes calls, so
 * a KAT can reproduce a fixed-seed keypair. Cleared as it is consumed; once
 * exhausted, a reproducible internal PRNG supplies the rest. Compiled only
 * under OSDP_PAIR_PQCLEAN_DETERMINISTIC so no production build can link a
 * seedable RNG by accident. */
void osdp_pair_pqclean_seed_push(const uint8_t *bytes, size_t len);
void osdp_pair_pqclean_seed_clear(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PAIR_PQCLEAN_H */
