// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PAIR_WOLFCRYPT_H
#define OSDP_PAIR_WOLFCRYPT_H

/* osdp_pair_crypto_t backend over wolfCrypt (wolfSSL): ML-KEM-768,
 * ML-DSA-44, SHA-256, HMAC-SHA256 and HKDF-SHA256 for SC2 asymmetric
 * pairing. The production counterpart of ports/pqclean, and a drop-in for
 * it: fed the same random bytes, both produce byte-identical keys,
 * ciphertexts, shared secrets and signatures (tests/test_port_pair_wolfcrypt.c
 * checks exactly that), and the ML-DSA-44 private key format is the same
 * 2560-byte FIPS 204 encoding — so a credential written by
 * tools/osdp-pair-provision loads here unchanged.
 *
 * wolfSSL requirements (compile errors if missing): WOLFSSL_HAVE_MLKEM with
 * ML-KEM-768, HAVE_DILITHIUM with ML-DSA-44 signing, HAVE_HKDF, and
 * WOLFSSL_SHA3 + WOLFSSL_SHAKE128 + WOLFSSL_SHAKE256 (both PQC schemes are
 * built on them). Tested against wolfSSL 5.8.2 and 5.9.2.
 *
 * ---- Randomness ----------------------------------------------------------
 *
 * Every random byte this port uses — ML-KEM keygen (64 bytes) and encaps
 * (32), ML-DSA keygen (32) and per-signature hedging (32), and the pairing
 * nonces through rand_bytes — comes from ONE source in the context. There is
 * no default: until a source is installed every operation that needs one
 * fails, so a missing CSPRNG announces itself instead of degrading. Install
 * exactly one of:
 *
 *   osdp_pair_wolfcrypt_rng()       wolfCrypt's DRBG (WC_RNG). On ESP-IDF it
 *                                   is seeded from the hardware RNG.
 *   osdp_pair_wolfcrypt_set_rand()  the caller's own source.
 *
 * The draw sizes and order match PQClean's randombytes() calls, which is what
 * makes the byte-for-byte cross-check possible.
 *
 * ---- Signing -------------------------------------------------------------
 *
 * ML-DSA-44 signing is FIPS 204 hedged mode with an empty context string,
 * the same as PQClean's crypto_sign_signature: 32 fresh bytes per signature.
 * Signatures therefore differ run to run (as PQClean's do); verification is
 * what interoperates, and is exact.
 *
 * ---- Context -------------------------------------------------------------
 *
 * The context owns the device's long-term ML-DSA-44 key, a second ML-DSA
 * key object for verifying peer signatures, and one ML-KEM-768 key object.
 * ML-KEM is per role: the ACU's keygen stashes its ephemeral decapsulation
 * key there for the later decaps, and the PD's encaps loads the peer's
 * encapsulation key into the same object. Use one context per role (as with
 * every port); an encaps discards any stashed decapsulation key.
 *
 * The context is large (several KB; sizeof depends on the wolfSSL build's
 * caching options), so give it static storage rather than a stack slot. It
 * holds one wolfCrypt_Init() reference, taken by osdp_pair_wolfcrypt_init()
 * and dropped by osdp_pair_wolfcrypt_free(). */

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <stdbool.h>

#include "osdp/osdp_pair_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ML-DSA-44 private key length, FIPS 204 encoding — the format
 * osdp_pair_pqclean and tools/osdp-pair-provision use. */
#define OSDP_PAIR_WOLFCRYPT_DSA_SK_LEN 2560U

/* Caller-supplied entropy source. Fill `out` with `len` random bytes and
 * return OSDP_OK, or any other status to fail the operation. */
typedef osdp_status_t (*osdp_pair_wolfcrypt_rand_fn)(void    *user,
                                                     uint8_t *out,
                                                     size_t   len);

typedef struct osdp_pair_wolfcrypt {
    dilithium_key dsa;      /* own long-term signing key                 */
    dilithium_key peer;     /* scratch: peer public key, for verify      */
    MlKemKey      kem;      /* ACU: ephemeral keypair; PD: peer's ek     */
    WC_RNG        rng;
    osdp_pair_wolfcrypt_rand_fn rand;
    void         *rand_user;
    bool          lib_ready;   /* holds a wolfCrypt_Init() reference */
    bool          dsa_ready;   /* key objects initialised            */
    bool          peer_ready;
    bool          kem_ready;
    bool          rng_ready;   /* WC_RNG seeded                      */
    bool          has_dsa;     /* a signing key is loaded            */
    bool          has_kem_sk;  /* an ephemeral decaps key is stashed */
} osdp_pair_wolfcrypt_t;

/* Initialise `ctx` and populate every member of `out`, with out->user = ctx.
 * No entropy source and no signing key yet: install one of each with the
 * calls below before pairing. Returns OSDP_ERR_INVALID_ARG for NULL
 * arguments or a wolfCrypt init failure. */
osdp_status_t osdp_pair_wolfcrypt_init(osdp_pair_wolfcrypt_t *ctx,
                                       osdp_pair_crypto_t    *out);

/* Draw all randomness from wolfCrypt's DRBG, seeded here. Returns
 * OSDP_ERR_INVALID_ARG if `ctx` is not initialised or the DRBG cannot be
 * seeded. Replaces a source installed by osdp_pair_wolfcrypt_set_rand(). */
osdp_status_t osdp_pair_wolfcrypt_rng(osdp_pair_wolfcrypt_t *ctx);

/* Draw all randomness from `fn` (called with `user`) instead; it takes
 * precedence over the DRBG. Passing NULL removes it, leaving the DRBG as the
 * source if osdp_pair_wolfcrypt_rng() was called and no source otherwise. */
void osdp_pair_wolfcrypt_set_rand(osdp_pair_wolfcrypt_t      *ctx,
                                  osdp_pair_wolfcrypt_rand_fn fn,
                                  void                       *user);

/* Install the device's long-term ML-DSA-44 keypair: the 1312-byte public key
 * and the 2560-byte FIPS 204 private key, exactly as
 * tools/osdp-pair-provision writes them. Returns OSDP_ERR_INVALID_ARG for a
 * NULL argument, an sk_len other than OSDP_PAIR_WOLFCRYPT_DSA_SK_LEN, or a
 * key wolfCrypt rejects; the context then holds no signing key. */
osdp_status_t osdp_pair_wolfcrypt_set_dsa(
    osdp_pair_wolfcrypt_t *ctx,
    const uint8_t          pk[OSDP_MLDSA44_PK_LEN],
    const uint8_t         *sk, size_t sk_len);

/* Generate a fresh long-term ML-DSA-44 keypair from the installed entropy
 * source and keep it as the signing key. The public key is written to
 * `pk_out` (for building or self-signing a certificate). Needs an entropy
 * source; returns OSDP_ERR_NOT_SUPPORTED if the draw or keygen fails. */
osdp_status_t osdp_pair_wolfcrypt_gen_dsa(
    osdp_pair_wolfcrypt_t *ctx,
    uint8_t                pk_out[OSDP_MLDSA44_PK_LEN]);

/* Release whatever init and the setters acquired, wiping key material.
 * Safe to call twice; no-op for NULL. */
void osdp_pair_wolfcrypt_free(osdp_pair_wolfcrypt_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PAIR_WOLFCRYPT_H */
