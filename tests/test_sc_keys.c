// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Tests for the OSDP-SC key-derivation, cryptogram, and initial-RMAC
 * primitives. Cross-checks against the same algorithm computed
 * directly via the tiny-AES adapter; this is enough to catch any
 * mistake in our higher-level routines (input layout, byte order,
 * key-of-the-key confusion). */

#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc_crypto.h"
#include "sc_test_aes.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static const uint8_t kSCBK[OSDP_SC_KEY_LEN] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};
static const uint8_t kRndA[OSDP_SC_RND_LEN] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
};
static const uint8_t kRndB[OSDP_SC_RND_LEN] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x99, 0x00,
};

static void test_session_key_derivation_matches_manual_computation(void)
{
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();

    /* Manually construct the three derivation inputs per spec D.4.1
     * (only the first 6 bytes of RND.A enter derivation) and encrypt
     * each with the SCBK to obtain the expected session keys. */
    uint8_t expected_s_enc [16];
    uint8_t expected_s_mac1[16];
    uint8_t expected_s_mac2[16];

    uint8_t input[16];
    input[0] = 0x01;
    (void)memset(&input[8], 0, 8);
    (void)memcpy(&input[2], kRndA, 6);

    input[1] = 0x82;
    TEST_ASSERT_EQUAL(OSDP_OK,
        c->aes128_ecb_encrypt(c->user, kSCBK, input, expected_s_enc));
    input[1] = 0x01;
    TEST_ASSERT_EQUAL(OSDP_OK,
        c->aes128_ecb_encrypt(c->user, kSCBK, input, expected_s_mac1));
    input[1] = 0x02;
    TEST_ASSERT_EQUAL(OSDP_OK,
        c->aes128_ecb_encrypt(c->user, kSCBK, input, expected_s_mac2));

    osdp_sc_session_keys_t got;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(c, kSCBK, kRndA, &got));
    TEST_ASSERT_EQUAL_MEMORY(expected_s_enc,  got.s_enc,  16);
    TEST_ASSERT_EQUAL_MEMORY(expected_s_mac1, got.s_mac1, 16);
    TEST_ASSERT_EQUAL_MEMORY(expected_s_mac2, got.s_mac2, 16);
}

static void test_session_keys_use_only_first_six_rnd_a_bytes(void)
{
    /* Spec: only RND.A[0..5] participate in key derivation. Verify
     * by deriving with two RND.As that differ ONLY in bytes 6..7;
     * the session keys should be identical. */
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    uint8_t rnd_a_alt[OSDP_SC_RND_LEN];
    (void)memcpy(rnd_a_alt, kRndA, 6);
    rnd_a_alt[6] = 0xFF;
    rnd_a_alt[7] = 0xAA;

    osdp_sc_session_keys_t a, b;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_derive_session_keys(c, kSCBK, kRndA,    &a));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_derive_session_keys(c, kSCBK, rnd_a_alt, &b));
    TEST_ASSERT_EQUAL_MEMORY(a.s_enc,  b.s_enc,  16);
    TEST_ASSERT_EQUAL_MEMORY(a.s_mac1, b.s_mac1, 16);
    TEST_ASSERT_EQUAL_MEMORY(a.s_mac2, b.s_mac2, 16);
}

static void test_client_cryptogram_is_enc_s_enc_rnd_a_then_rnd_b(void)
{
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    osdp_sc_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(c, kSCBK, kRndA, &keys));

    /* Manual: AES_ENC(S-ENC, RND.A || RND.B). */
    uint8_t input[16];
    (void)memcpy(&input[0], kRndA, 8);
    (void)memcpy(&input[8], kRndB, 8);
    uint8_t expected[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        c->aes128_ecb_encrypt(c->user, keys.s_enc, input, expected));

    uint8_t got[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_client_cryptogram(c, keys.s_enc, kRndA, kRndB, got));
    TEST_ASSERT_EQUAL_MEMORY(expected, got, 16);
}

static void test_server_cryptogram_swaps_rnd_b_and_rnd_a(void)
{
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    osdp_sc_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(c, kSCBK, kRndA, &keys));

    /* Manual: AES_ENC(S-ENC, RND.B || RND.A). */
    uint8_t input[16];
    (void)memcpy(&input[0], kRndB, 8);
    (void)memcpy(&input[8], kRndA, 8);
    uint8_t expected[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        c->aes128_ecb_encrypt(c->user, keys.s_enc, input, expected));

    uint8_t got[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_server_cryptogram(c, keys.s_enc, kRndA, kRndB, got));
    TEST_ASSERT_EQUAL_MEMORY(expected, got, 16);
}

static void test_client_and_server_cryptograms_differ(void)
{
    /* Sanity: the two cryptograms must NOT collide (otherwise the
     * mutual-authentication property of the handshake is broken).
     * Trivially true given the input ordering, but worth pinning. */
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    osdp_sc_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(c, kSCBK, kRndA, &keys));
    uint8_t client[16], server[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_client_cryptogram(c, keys.s_enc, kRndA, kRndB, client));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_server_cryptogram(c, keys.s_enc, kRndA, kRndB, server));
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(client, server, 16),
        "client and server cryptograms collided");
}

static void test_initial_rmac_is_double_aes_of_server_cryptogram(void)
{
    /* Initial R-MAC = AES(S-MAC2, AES(S-MAC1, ServerCryptogram)). */
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    osdp_sc_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(c, kSCBK, kRndA, &keys));
    uint8_t server[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_server_cryptogram(c, keys.s_enc, kRndA, kRndB, server));

    uint8_t intermediate[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        c->aes128_ecb_encrypt(c->user, keys.s_mac1, server, intermediate));
    uint8_t expected[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        c->aes128_ecb_encrypt(c->user, keys.s_mac2, intermediate, expected));

    uint8_t got[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_initial_rmac(c, keys.s_mac1, keys.s_mac2, server, got));
    TEST_ASSERT_EQUAL_MEMORY(expected, got, 16);
}

static void test_null_args_rejected(void)
{
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    osdp_sc_session_keys_t keys;
    uint8_t buf[16];
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_derive_session_keys(NULL, kSCBK, kRndA, &keys));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_derive_session_keys(c, NULL, kRndA, &keys));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_derive_session_keys(c, kSCBK, NULL, &keys));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_derive_session_keys(c, kSCBK, kRndA, NULL));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_client_cryptogram(NULL, kSCBK, kRndA, kRndB, buf));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_initial_rmac(NULL, kSCBK, kSCBK, buf, buf));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_session_key_derivation_matches_manual_computation);
    RUN_TEST(test_session_keys_use_only_first_six_rnd_a_bytes);
    RUN_TEST(test_client_cryptogram_is_enc_s_enc_rnd_a_then_rnd_b);
    RUN_TEST(test_server_cryptogram_swaps_rnd_b_and_rnd_a);
    RUN_TEST(test_client_and_server_cryptograms_differ);
    RUN_TEST(test_initial_rmac_is_double_aes_of_server_cryptogram);
    RUN_TEST(test_null_args_rejected);
    return UNITY_END();
}
