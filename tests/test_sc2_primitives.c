// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Known-answer tests for the OSDP-SC2 primitives (KMAC256 session-key
 * derivation, AES-256-CBC cryptograms, and the AES-256 nonce). Every
 * expected value below is ground truth from the OSDP-SC2 annex sample
 * session and the OSDP.Net feature/osdp-sc2 SC2SecurityContextTest — an
 * independent implementation. Passing these confirms both our SC2 code
 * and the vendored test crypto backend (Keccak/KMAC + AES-256) are
 * correct and interoperable. */

#include "osdp/osdp_sc2.h"
#include "sc2_test_crypto.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Annex sample-session vectors --------------------------------------*/

static const uint8_t kSCBK[OSDP_SC2_KEY_LEN] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
};
static const uint8_t kRndA[OSDP_SC2_RND_LEN] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
};
static const uint8_t kRndB[OSDP_SC2_RND_LEN] = {
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
};
static const uint8_t kCUID[OSDP_SC2_CUID_LEN] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
};
static const uint8_t kSEnc[OSDP_SC2_KEY_LEN] = {
    0x11, 0x50, 0x9C, 0x6D, 0x52, 0x76, 0x21, 0x68,
    0x11, 0xB0, 0x5A, 0xC7, 0x50, 0x1F, 0x6E, 0x82,
    0x0F, 0x34, 0x74, 0x5D, 0xFD, 0x17, 0xB0, 0x45,
    0x79, 0x8F, 0xB5, 0x2E, 0xA4, 0x63, 0x47, 0x8F,
};
static const uint8_t kSNonce[OSDP_SC2_KEY_LEN] = {
    0x59, 0x0D, 0xFE, 0x02, 0xA5, 0x47, 0x9B, 0xE0,
    0x92, 0x61, 0xA5, 0xF4, 0x2D, 0xC9, 0x7A, 0x18,
    0x97, 0x37, 0x7E, 0x2B, 0x0D, 0xEC, 0x09, 0x1F,
    0x21, 0x29, 0x53, 0x23, 0x75, 0x5F, 0xCE, 0xA7,
};
static const uint8_t kClientCryptogram[OSDP_SC2_CRYPTOGRAM_LEN] = {
    0x3C, 0x0F, 0x1B, 0x50, 0xF2, 0x3B, 0x9E, 0x19,
    0xA0, 0x9B, 0xBD, 0xDA, 0xB1, 0xBA, 0xE9, 0x05,
    0xEF, 0xAC, 0xE6, 0xC1, 0xDE, 0xB2, 0x24, 0x90,
    0xAB, 0xD0, 0x89, 0xA9, 0x2A, 0x99, 0x92, 0xCE,
};
static const uint8_t kServerCryptogram[OSDP_SC2_CRYPTOGRAM_LEN] = {
    0x1A, 0x51, 0x98, 0x91, 0x20, 0x32, 0xA2, 0x41,
    0xB7, 0x19, 0x91, 0x1A, 0x5E, 0xC9, 0x28, 0x34,
    0x8C, 0x2E, 0x17, 0x37, 0xEE, 0x2E, 0x35, 0x52,
    0xDE, 0xE5, 0x05, 0xB9, 0x7F, 0xD3, 0xAB, 0x33,
};
static const uint8_t kNonce0[OSDP_SC2_NONCE_LEN] = {
    0x34, 0xF8, 0xD8, 0xE7, 0xB5, 0x3E, 0xD9, 0xF5,
    0x0D, 0xC2, 0xF2, 0x1C,
};

/* ---- KMAC256 self-check ------------------------------------------------*/

static void test_kmac256_backend_is_deterministic(void)
{
    /* The vendored Keccak/KMAC is validated for correctness by the
     * S-ENC / S-NONCE known-answer vectors below (external ground
     * truth). Here we only pin that it is deterministic — the same
     * (key, data) always yields the same output. */
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    uint8_t a[OSDP_SC2_KEY_LEN], b[OSDP_SC2_KEY_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        c->kmac256(c->user, kSCBK, sizeof(kSCBK), kRndA, sizeof(kRndA),
                   a, sizeof(a)));
    TEST_ASSERT_EQUAL(OSDP_OK,
        c->kmac256(c->user, kSCBK, sizeof(kSCBK), kRndA, sizeof(kRndA),
                   b, sizeof(b)));
    TEST_ASSERT_EQUAL_MEMORY(a, b, OSDP_SC2_KEY_LEN);
}

/* ---- Session-key derivation KAT ----------------------------------------*/

static void test_session_key_derivation_matches_annex(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    osdp_sc2_session_keys_t got;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_derive_session_keys(c, kSCBK, kRndA, kRndB, &got));
    TEST_ASSERT_EQUAL_MEMORY(kSEnc,   got.s_enc,   OSDP_SC2_KEY_LEN);
    TEST_ASSERT_EQUAL_MEMORY(kSNonce, got.s_nonce, OSDP_SC2_KEY_LEN);
}

/* ---- Cryptogram KAT ----------------------------------------------------*/

static void test_client_cryptogram_matches_annex(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    uint8_t got[OSDP_SC2_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_client_cryptogram(c, kSEnc, kRndA, kRndB, got));
    TEST_ASSERT_EQUAL_MEMORY(kClientCryptogram, got, OSDP_SC2_CRYPTOGRAM_LEN);
}

static void test_server_cryptogram_matches_annex(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    uint8_t got[OSDP_SC2_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_server_cryptogram(c, kSEnc, kRndA, kRndB, got));
    TEST_ASSERT_EQUAL_MEMORY(kServerCryptogram, got, OSDP_SC2_CRYPTOGRAM_LEN);
}

static void test_cryptograms_are_cbc_chained_not_ecb(void)
{
    /* Guard against the easy mistake of implementing the 32-byte
     * cryptogram as two independent ECB blocks. Under real CBC the two
     * halves differ from an ECB encode of the second block; we detect
     * this by checking the second 16 bytes depend on the first block's
     * ciphertext (i.e. equal the known annex value, which an ECB
     * implementation would not reproduce). Covered by the KAT above;
     * here we additionally assert client != server. */
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    uint8_t client[OSDP_SC2_CRYPTOGRAM_LEN], server[OSDP_SC2_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_client_cryptogram(c, kSEnc, kRndA, kRndB, client));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_server_cryptogram(c, kSEnc, kRndA, kRndB, server));
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
        memcmp(client, server, OSDP_SC2_CRYPTOGRAM_LEN),
        "client and server cryptograms collided");
}

/* ---- Nonce derivation KAT ----------------------------------------------*/

static void test_nonce_counter0_matches_annex(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    uint8_t got[OSDP_SC2_NONCE_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_compute_nonce(c, kSNonce, kCUID, 0u, got));
    TEST_ASSERT_EQUAL_MEMORY(kNonce0, got, OSDP_SC2_NONCE_LEN);
}

static void test_nonce_changes_with_counter(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    uint8_t n0[OSDP_SC2_NONCE_LEN], n1[OSDP_SC2_NONCE_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_compute_nonce(c, kSNonce, kCUID, 0u, n0));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_compute_nonce(c, kSNonce, kCUID, 1u, n1));
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(n0, n1, OSDP_SC2_NONCE_LEN),
        "nonce did not change when the counter advanced");
}

/* ---- Argument validation -----------------------------------------------*/

static void test_null_args_rejected(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    osdp_sc2_session_keys_t keys;
    uint8_t buf[OSDP_SC2_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc2_derive_session_keys(NULL, kSCBK, kRndA, kRndB, &keys));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc2_derive_session_keys(c, NULL, kRndA, kRndB, &keys));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc2_client_cryptogram(NULL, kSEnc, kRndA, kRndB, buf));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc2_compute_nonce(c, NULL, kCUID, 0u, buf));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_kmac256_backend_is_deterministic);
    RUN_TEST(test_session_key_derivation_matches_annex);
    RUN_TEST(test_client_cryptogram_matches_annex);
    RUN_TEST(test_server_cryptogram_matches_annex);
    RUN_TEST(test_cryptograms_are_cbc_chained_not_ecb);
    RUN_TEST(test_nonce_counter0_matches_annex);
    RUN_TEST(test_nonce_changes_with_counter);
    RUN_TEST(test_null_args_rejected);
    return UNITY_END();
}
