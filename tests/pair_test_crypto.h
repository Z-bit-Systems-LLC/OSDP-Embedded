// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PAIR_TEST_CRYPTO_H
#define OSDP_PAIR_TEST_CRYPTO_H

/* Test/tool backend for osdp_pair_crypto_t, built on the vendored PQClean
 * ML-KEM-768 + ML-DSA-44 (+ SHA-256), with HMAC/HKDF layered on top. Host-
 * only; never linked into a production core. Mirrors sc2_test_crypto.
 *
 * The context carries this side's long-term ML-DSA-44 signing key (for
 * ml_dsa44_sign) and, between keygen and decaps, the ACU's ephemeral
 * ML-KEM-768 decapsulation key — exactly the private-key ownership the HAL
 * contract describes. */

#include "osdp/osdp_pair_crypto.h"

#define OSDP_PAIR_TEST_DSA_SK_LEN 2560U  /* PQClean ML-DSA-44 secret key */
#define OSDP_PAIR_TEST_KEM_SK_LEN 2400U  /* PQClean ML-KEM-768 secret key */

typedef struct osdp_pair_test_ctx {
    uint8_t dsa_pk[OSDP_MLDSA44_PK_LEN];      /* long-term device pubkey  */
    uint8_t dsa_sk[OSDP_PAIR_TEST_DSA_SK_LEN];/* long-term device privkey */
    bool    has_dsa;
    uint8_t kem_sk[OSDP_PAIR_TEST_KEM_SK_LEN];/* ephemeral KEM privkey    */
    bool    has_kem_sk;
} osdp_pair_test_ctx_t;

/* Bind `ctx` to `crypto` and populate the vtable. Does not generate keys. */
void osdp_pair_test_crypto_init(osdp_pair_crypto_t *crypto,
                                osdp_pair_test_ctx_t *ctx);

/* Generate a fresh long-term ML-DSA-44 device keypair into `ctx`. The
 * public key is left in ctx->dsa_pk for building / self-signing a cert. */
osdp_status_t osdp_pair_test_gen_dsa(osdp_pair_test_ctx_t *ctx);

/* Queue `len` deterministic bytes for the next PQCLEAN_randombytes calls,
 * so a KAT can reproduce a fixed-seed keypair. Cleared as it is consumed;
 * once exhausted, a reproducible internal PRNG supplies the rest. */
void osdp_pair_test_seed_push(const uint8_t *bytes, size_t len);
void osdp_pair_test_seed_clear(void);

#endif /* OSDP_PAIR_TEST_CRYPTO_H */
