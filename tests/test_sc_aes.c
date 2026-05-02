// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Sanity tests of the tiny-AES-c reference + adapter, using the
 * canonical AES-128 test vector from FIPS 197 Appendix C.1 and a
 * round-trip self-consistency check. If this passes, every higher
 * SC test that uses this adapter has a trusted oracle to compare
 * against. */

#include "osdp/osdp_sc_crypto.h"
#include "sc_test_aes.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_aes128_fips_197_vector(void)
{
    /* FIPS 197 Appendix C.1 — AES-128 example. */
    static const uint8_t key[]        = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    static const uint8_t plaintext[]  = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    static const uint8_t expected[]   = {
        0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
        0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A,
    };

    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    uint8_t out[OSDP_AES_BLOCK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
                      c->aes128_ecb_encrypt(c->user, key, plaintext, out));
    TEST_ASSERT_EQUAL_MEMORY(expected, out, sizeof(expected));
}

static void test_aes128_decrypt_inverts_encrypt(void)
{
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    static const uint8_t key[OSDP_AES_KEY_LEN] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };
    /* A handful of arbitrary plaintexts. */
    static const uint8_t plaintexts[][OSDP_AES_BLOCK_LEN] = {
        {0},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
        {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
         0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
    };
    for (size_t i = 0; i < sizeof(plaintexts) / sizeof(plaintexts[0]); i++) {
        uint8_t encrypted[OSDP_AES_BLOCK_LEN];
        uint8_t decrypted[OSDP_AES_BLOCK_LEN];
        TEST_ASSERT_EQUAL(OSDP_OK,
                          c->aes128_ecb_encrypt(c->user, key,
                                                plaintexts[i], encrypted));
        TEST_ASSERT_EQUAL(OSDP_OK,
                          c->aes128_ecb_decrypt(c->user, key,
                                                encrypted, decrypted));
        TEST_ASSERT_EQUAL_MEMORY(plaintexts[i], decrypted,
                                 OSDP_AES_BLOCK_LEN);
    }
}

static void test_aes128_in_place_aliasing_works(void)
{
    /* The adapter and HAL contract allow `out == in`. Verify. */
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    static const uint8_t key[OSDP_AES_KEY_LEN] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };
    uint8_t buf[OSDP_AES_BLOCK_LEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    uint8_t expected[OSDP_AES_BLOCK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
                      c->aes128_ecb_encrypt(c->user, key, buf, expected));
    /* Now re-encrypt the same plaintext in-place. */
    uint8_t in_place[OSDP_AES_BLOCK_LEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    TEST_ASSERT_EQUAL(OSDP_OK,
                      c->aes128_ecb_encrypt(c->user, key, in_place, in_place));
    TEST_ASSERT_EQUAL_MEMORY(expected, in_place, OSDP_AES_BLOCK_LEN);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_aes128_fips_197_vector);
    RUN_TEST(test_aes128_decrypt_inverts_encrypt);
    RUN_TEST(test_aes128_in_place_aliasing_works);
    return UNITY_END();
}
