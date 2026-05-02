// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Tests for the OSDP-SC AES-128 CBC routines built on top of the
 * abstract ECB primitive. Validation is two-pronged:
 *
 *   - NIST SP 800-38A Appendix F.2 gives a known-good CBC vector,
 *     which we run through both encrypt and decrypt directions.
 *   - Round-trip property: decrypt(encrypt(x)) == x for arbitrary
 *     inputs, including 1-block and many-block lengths. */

#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc_crypto.h"
#include "sc_test_aes.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* NIST SP 800-38A F.2.1 CBC-AES128 example. */
static const uint8_t kNistKey[] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
};
static const uint8_t kNistIv[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};
static const uint8_t kNistPlaintext[] = {
    /* block 1 */
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    /* block 2 */
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    /* block 3 */
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
    0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    /* block 4 */
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
    0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
};
static const uint8_t kNistCiphertext[] = {
    0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46,
    0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
    0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE,
    0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2,
    0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B,
    0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16,
    0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09,
    0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7,
};

static void test_cbc_encrypt_matches_nist_vector(void)
{
    uint8_t out[64];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_cbc_encrypt(sc_test_crypto_tiny_aes(),
                            kNistKey, kNistIv,
                            kNistPlaintext, sizeof(kNistPlaintext),
                            out));
    TEST_ASSERT_EQUAL_MEMORY(kNistCiphertext, out, sizeof(kNistCiphertext));
}

static void test_cbc_decrypt_matches_nist_vector(void)
{
    uint8_t out[64];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_cbc_decrypt(sc_test_crypto_tiny_aes(),
                            kNistKey, kNistIv,
                            kNistCiphertext, sizeof(kNistCiphertext),
                            out));
    TEST_ASSERT_EQUAL_MEMORY(kNistPlaintext, out, sizeof(kNistPlaintext));
}

static void test_cbc_round_trip_for_various_lengths(void)
{
    static const uint8_t key[] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
    };
    static const uint8_t iv[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    /* 1, 2, 3, 8 blocks. */
    static const size_t lengths[] = { 16, 32, 48, 128 };
    uint8_t plaintext[128];
    uint8_t ciphertext[128];
    uint8_t recovered[128];
    /* Pseudorandom-but-deterministic plaintext. */
    uint32_t s = 0xDEADBEEFu;
    for (size_t i = 0; i < sizeof(plaintext); i++) {
        s = s * 1103515245u + 12345u;
        plaintext[i] = (uint8_t)(s >> 16);
    }
    for (size_t li = 0; li < sizeof(lengths) / sizeof(lengths[0]); li++) {
        const size_t len = lengths[li];
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc_cbc_encrypt(sc_test_crypto_tiny_aes(),
                                key, iv, plaintext, len, ciphertext));
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc_cbc_decrypt(sc_test_crypto_tiny_aes(),
                                key, iv, ciphertext, len, recovered));
        TEST_ASSERT_EQUAL_MEMORY(plaintext, recovered, len);
    }
}

static void test_cbc_in_place_aliasing_works(void)
{
    /* The contract permits ciphertext to alias plaintext. Verify by
     * encrypting two ways and comparing. */
    static const uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    static const uint8_t iv[16]  = {0xFF};
    uint8_t reference[64];
    uint8_t in_place [64];
    for (size_t i = 0; i < 64; i++) {
        reference[i] = in_place[i] = (uint8_t)(i ^ 0x5A);
    }
    uint8_t ref_out[64];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_cbc_encrypt(sc_test_crypto_tiny_aes(),
                            key, iv, reference, 64, ref_out));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_cbc_encrypt(sc_test_crypto_tiny_aes(),
                            key, iv, in_place, 64, in_place));
    TEST_ASSERT_EQUAL_MEMORY(ref_out, in_place, 64);
}

static void test_cbc_rejects_non_block_aligned_length(void)
{
    static const uint8_t k[16] = {0};
    static const uint8_t iv[16] = {0};
    uint8_t buf[20];
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_cbc_encrypt(sc_test_crypto_tiny_aes(),
                            k, iv, buf, 17, buf));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_cbc_encrypt(sc_test_crypto_tiny_aes(),
                            k, iv, buf, 0, buf));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_cbc_decrypt(sc_test_crypto_tiny_aes(),
                            k, iv, buf, 15, buf));
}

static void test_cbc_decrypt_rejects_when_no_decrypt_in_vtable(void)
{
    osdp_sc_crypto_t partial = *sc_test_crypto_tiny_aes();
    partial.aes128_ecb_decrypt = NULL;
    static const uint8_t k[16] = {0};
    static const uint8_t iv[16] = {0};
    uint8_t buf[16] = {0};
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
        osdp_sc_cbc_decrypt(&partial, k, iv, buf, sizeof(buf), buf));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cbc_encrypt_matches_nist_vector);
    RUN_TEST(test_cbc_decrypt_matches_nist_vector);
    RUN_TEST(test_cbc_round_trip_for_various_lengths);
    RUN_TEST(test_cbc_in_place_aliasing_works);
    RUN_TEST(test_cbc_rejects_non_block_aligned_length);
    RUN_TEST(test_cbc_decrypt_rejects_when_no_decrypt_in_vtable);
    return UNITY_END();
}
