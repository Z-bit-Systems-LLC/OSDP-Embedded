// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Contract tests for the SC2 half of ports/wolfcrypt. The SC2 behaviour of
 * its AES is covered by the *_wolfcrypt re-run of the whole SC2 suite; this
 * file covers what that re-run cannot see: independent AES-256 and GCM
 * vectors, the plaintext wipe on a bad tag, in-place operation, how the two
 * setters compose with a caller's vtable, the opt-in DRBG, and argument and
 * lifecycle refusals. */

#include "osdp_sc2_wolfcrypt.h"
#include "kmac.h"   /* vendor/tiny-kmac: the reference for the KMAC cross-check */
#include "unity.h"

#include <string.h>

/* FIPS-197 Appendix C.3, AES-256. */
static const uint8_t k_aes_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static const uint8_t k_aes_pt[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
};
static const uint8_t k_aes_ct[16] = {
    0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
    0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89,
};

/* McGrew & Viega, "The Galois/Counter Mode of Operation", Test Case 16:
 * AES-256, 96-bit IV, 20 bytes of AAD, 60 bytes of plaintext. */
static const uint8_t k_gcm_key[32] = {
    0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C,
    0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C,
    0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83, 0x08,
};
static const uint8_t k_gcm_iv[12] = {
    0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD,
    0xDE, 0xCA, 0xF8, 0x88,
};
static const uint8_t k_gcm_aad[20] = {
    0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
    0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
    0xAB, 0xAD, 0xDA, 0xD2,
};
static const uint8_t k_gcm_pt[60] = {
    0xD9, 0x31, 0x32, 0x25, 0xF8, 0x84, 0x06, 0xE5,
    0xA5, 0x59, 0x09, 0xC5, 0xAF, 0xF5, 0x26, 0x9A,
    0x86, 0xA7, 0xA9, 0x53, 0x15, 0x34, 0xF7, 0xDA,
    0x2E, 0x4C, 0x30, 0x3D, 0x8A, 0x31, 0x8A, 0x72,
    0x1C, 0x3C, 0x0C, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2F, 0xCF, 0x0E, 0x24, 0x49, 0xA6, 0xB5, 0x25,
    0xB1, 0x6A, 0xED, 0xF5, 0xAA, 0x0D, 0xE6, 0x57,
    0xBA, 0x63, 0x7B, 0x39,
};
static const uint8_t k_gcm_ct[60] = {
    0x52, 0x2D, 0xC1, 0xF0, 0x99, 0x56, 0x7D, 0x07,
    0xF4, 0x7F, 0x37, 0xA3, 0x2A, 0x84, 0x42, 0x7D,
    0x64, 0x3A, 0x8C, 0xDC, 0xBF, 0xE5, 0xC0, 0xC9,
    0x75, 0x98, 0xA2, 0xBD, 0x25, 0x55, 0xD1, 0xAA,
    0x8C, 0xB0, 0x8E, 0x48, 0x59, 0x0D, 0xBB, 0x3D,
    0xA7, 0xB0, 0x8B, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xC5, 0xF6, 0x1E, 0x63, 0x93, 0xBA, 0x7A, 0x0A,
    0xBC, 0xC9, 0xF6, 0x62,
};
static const uint8_t k_gcm_tag[16] = {
    0x76, 0xFC, 0x6E, 0xCE, 0x0F, 0x4E, 0x17, 0x68,
    0xCD, 0xDF, 0x88, 0x53, 0xBB, 0x2D, 0x55, 0x1B,
};

/* Same paper, Test Case 13: all-zero key and IV, no plaintext, no AAD — the
 * shape of an SC2 message with nothing to encrypt. */
static const uint8_t k_gcm_tc13_tag[16] = {
    0x53, 0x0F, 0x8A, 0xFB, 0xC7, 0x45, 0x36, 0xB9,
    0xA9, 0x63, 0xB4, 0xF1, 0xC4, 0xCB, 0x73, 0x8B,
};

static osdp_sc2_wolfcrypt_t g_ctx;
static osdp_sc2_crypto_t    g_vt;

static osdp_status_t sentinel_kmac(void *user, const uint8_t *k, size_t kl,
                                   const uint8_t *d, size_t dl,
                                   uint8_t *out, size_t ol)
{
    (void)user; (void)k; (void)kl; (void)d; (void)dl; (void)out; (void)ol;
    return OSDP_OK;
}

static osdp_status_t sentinel_rand(void *user, uint8_t *out, size_t len)
{
    (void)user; (void)out; (void)len;
    return OSDP_OK;
}

void setUp(void)
{
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(&g_vt, 0, sizeof(g_vt));
}

void tearDown(void)
{
    osdp_sc2_wolfcrypt_free(&g_ctx);
}

static void test_fips197_aes256_block(void)
{
    uint8_t out[16];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes256_ecb_encrypt(g_vt.user, k_aes_key, k_aes_pt, out));
    TEST_ASSERT_EQUAL_MEMORY(k_aes_ct, out, sizeof(out));

    /* In place, as SC2's nonce derivation calls it. */
    memcpy(out, k_aes_pt, sizeof(out));
    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes256_ecb_encrypt(g_vt.user, k_aes_key, out, out));
    TEST_ASSERT_EQUAL_MEMORY(k_aes_ct, out, sizeof(out));
}

static void test_gcm_tc16_encrypt_and_decrypt(void)
{
    uint8_t ct[sizeof(k_gcm_pt)], pt[sizeof(k_gcm_pt)], tag[16];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));

    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes256_gcm_encrypt(g_vt.user, k_gcm_key, k_gcm_iv,
                                k_gcm_aad, sizeof(k_gcm_aad),
                                k_gcm_pt, sizeof(k_gcm_pt), ct, tag));
    TEST_ASSERT_EQUAL_MEMORY(k_gcm_ct, ct, sizeof(ct));
    TEST_ASSERT_EQUAL_MEMORY(k_gcm_tag, tag, sizeof(tag));

    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes256_gcm_decrypt(g_vt.user, k_gcm_key, k_gcm_iv,
                                k_gcm_aad, sizeof(k_gcm_aad),
                                k_gcm_ct, sizeof(k_gcm_ct), k_gcm_tag, pt));
    TEST_ASSERT_EQUAL_MEMORY(k_gcm_pt, pt, sizeof(pt));
}

static void test_gcm_in_place_both_directions(void)
{
    uint8_t buf[sizeof(k_gcm_pt)], tag[16];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));

    memcpy(buf, k_gcm_pt, sizeof(buf));
    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes256_gcm_encrypt(g_vt.user, k_gcm_key, k_gcm_iv,
                                k_gcm_aad, sizeof(k_gcm_aad),
                                buf, sizeof(buf), buf, tag));
    TEST_ASSERT_EQUAL_MEMORY(k_gcm_ct, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_MEMORY(k_gcm_tag, tag, sizeof(tag));

    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes256_gcm_decrypt(g_vt.user, k_gcm_key, k_gcm_iv,
                                k_gcm_aad, sizeof(k_gcm_aad),
                                buf, sizeof(buf), tag, buf));
    TEST_ASSERT_EQUAL_MEMORY(k_gcm_pt, buf, sizeof(buf));
}

static void test_gcm_empty_payload(void)
{
    static const uint8_t zero_key[32] = { 0 };
    static const uint8_t zero_iv[12]  = { 0 };
    uint8_t tag[16];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes256_gcm_encrypt(g_vt.user, zero_key, zero_iv,
                                NULL, 0, NULL, 0, NULL, tag));
    TEST_ASSERT_EQUAL_MEMORY(k_gcm_tc13_tag, tag, sizeof(tag));
    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes256_gcm_decrypt(g_vt.user, zero_key, zero_iv,
                                NULL, 0, NULL, 0, tag, NULL));
}

/* The HAL promises plaintext only on a valid tag. wolfCrypt's software GCM
 * writes it first and checks afterwards, so this is the port's own wipe. */
static void test_gcm_bad_tag_rejects_and_wipes(void)
{
    uint8_t bad_tag[16], pt[sizeof(k_gcm_pt)];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));

    memcpy(bad_tag, k_gcm_tag, sizeof(bad_tag));
    bad_tag[15] ^= 0x01;
    memset(pt, 0xA5, sizeof(pt));
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CRC,
        g_vt.aes256_gcm_decrypt(g_vt.user, k_gcm_key, k_gcm_iv,
                                k_gcm_aad, sizeof(k_gcm_aad),
                                k_gcm_ct, sizeof(k_gcm_ct), bad_tag, pt));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, pt, sizeof(pt));

    /* Tampered AAD is the same failure. */
    uint8_t aad[sizeof(k_gcm_aad)];
    memcpy(aad, k_gcm_aad, sizeof(aad));
    aad[0] ^= 0x80;
    memset(pt, 0xA5, sizeof(pt));
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CRC,
        g_vt.aes256_gcm_decrypt(g_vt.user, k_gcm_key, k_gcm_iv,
                                aad, sizeof(aad),
                                k_gcm_ct, sizeof(k_gcm_ct), k_gcm_tag, pt));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, pt, sizeof(pt));
}

#if OSDP_SC2_WOLFCRYPT_HAS_KMAC

/* NIST SP 800-185 KMAC256 Sample #5: the empty customization string is
 * exactly the HAL's KMAC256, so this goes through the vtable. */
static void test_kmac256_sp800_185_sample5(void)
{
    static const uint8_t expect[64] = {
        0x75, 0x35, 0x8C, 0xF3, 0x9E, 0x41, 0x49, 0x4E,
        0x94, 0x97, 0x07, 0x92, 0x7C, 0xEE, 0x0A, 0xF2,
        0x0A, 0x3F, 0xF5, 0x53, 0x90, 0x4C, 0x86, 0xB0,
        0x8F, 0x21, 0xCC, 0x41, 0x4B, 0xCF, 0xD6, 0x91,
        0x58, 0x9D, 0x27, 0xCF, 0x5E, 0x15, 0x36, 0x9C,
        0xBB, 0xFF, 0x8B, 0x9A, 0x4C, 0x2E, 0xB1, 0x78,
        0x00, 0x85, 0x5D, 0x02, 0x35, 0xFF, 0x63, 0x5D,
        0xA8, 0x25, 0x33, 0xEC, 0x6B, 0x75, 0x9B, 0x69,
    };
    uint8_t key[32], data[200], out[64];
    for (size_t i = 0; i < sizeof(key); i++)  { key[i]  = (uint8_t)(0x40 + i); }
    for (size_t i = 0; i < sizeof(data); i++) { data[i] = (uint8_t)i; }

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.kmac256(g_vt.user, key, sizeof(key), data, sizeof(data),
                     out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(expect, out, sizeof(out));
}

/* Cross-check against vendor/tiny-kmac (the SC2 test backend) around the
 * KMAC256 rate (136 bytes), with empty and long keys, at the 32-byte output
 * SC2 asks for and a longer one. */
static void test_kmac256_matches_tiny_kmac(void)
{
    static const size_t key_lens[]  = { 0, 16, 32, 135, 136, 200 };
    static const size_t data_lens[] = { 0, 1, 32, 135, 136, 137, 300 };
    static const size_t out_lens[]  = { 32, 64 };
    uint8_t key[200], data[300], a[64], b[64];
    for (size_t i = 0; i < sizeof(key); i++)  { key[i]  = (uint8_t)(i * 7 + 1); }
    for (size_t i = 0; i < sizeof(data); i++) { data[i] = (uint8_t)(i * 13 + 5); }

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));
    for (size_t k = 0; k < sizeof(key_lens) / sizeof(key_lens[0]); k++) {
        for (size_t d = 0; d < sizeof(data_lens) / sizeof(data_lens[0]); d++) {
            for (size_t o = 0; o < sizeof(out_lens) / sizeof(out_lens[0]); o++) {
                TEST_ASSERT_EQUAL(OSDP_OK,
                    g_vt.kmac256(g_vt.user, key, key_lens[k],
                                 data, data_lens[d], a, out_lens[o]));
                tiny_kmac256(key, key_lens[k], data, data_lens[d],
                             b, out_lens[o]);
                TEST_ASSERT_EQUAL_MEMORY(b, a, out_lens[o]);
            }
        }
    }
}

/* With KMAC the setter owns kmac256 as well as the AES members; rand_bytes
 * is still the caller's. */
static void test_setter_owns_kmac_leaves_rand_alone(void)
{
    g_vt.kmac256    = sentinel_kmac;
    g_vt.rand_bytes = sentinel_rand;

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));
    TEST_ASSERT_NOT_NULL(g_vt.kmac256);
    TEST_ASSERT_TRUE(g_vt.kmac256 != sentinel_kmac);
    TEST_ASSERT_EQUAL_PTR(sentinel_rand, g_vt.rand_bytes);
    TEST_ASSERT_EQUAL_PTR(&g_ctx, g_vt.user);
}

#else

/* Without KMAC the setter owns the three AES members and `user`; kmac256 and
 * rand_bytes are the caller's and must survive it whichever order they are
 * bound in. */
static void test_setter_leaves_kmac_and_rand_alone(void)
{
    g_vt.kmac256    = sentinel_kmac;
    g_vt.rand_bytes = sentinel_rand;

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL_PTR(sentinel_kmac, g_vt.kmac256);
    TEST_ASSERT_EQUAL_PTR(sentinel_rand, g_vt.rand_bytes);
    TEST_ASSERT_NOT_NULL(g_vt.aes256_gcm_encrypt);
    TEST_ASSERT_NOT_NULL(g_vt.aes256_gcm_decrypt);
    TEST_ASSERT_NOT_NULL(g_vt.aes256_ecb_encrypt);
    TEST_ASSERT_EQUAL_PTR(&g_ctx, g_vt.user);
}

#endif /* OSDP_SC2_WOLFCRYPT_HAS_KMAC */

static void test_rng_is_opt_in_and_draws(void)
{
    uint8_t a[32] = { 0 }, b[32] = { 0 };

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));
    TEST_ASSERT_NULL(g_vt.rand_bytes);

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_rng(&g_ctx, &g_vt));
    TEST_ASSERT_NOT_NULL(g_vt.rand_bytes);
    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.rand_bytes(g_vt.user, a, sizeof(a)));
    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.rand_bytes(g_vt.user, b, sizeof(b)));
    TEST_ASSERT_TRUE(memcmp(a, b, sizeof(a)) != 0);
    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.rand_bytes(g_vt.user, NULL, 0));
}

static void test_refusals(void)
{
    osdp_sc2_crypto_t other;
    uint8_t           out[16];

    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc2_wolfcrypt_aes256(NULL, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc2_wolfcrypt_aes256(&g_ctx, NULL));

    /* The DRBG setter needs an initialised context bound to that vtable. */
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc2_wolfcrypt_rng(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_wolfcrypt_aes256(&g_ctx, &g_vt));
    memset(&other, 0, sizeof(other));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc2_wolfcrypt_rng(&g_ctx, &other));

    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.aes256_ecb_encrypt(NULL, k_aes_key, k_aes_pt, out));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.aes256_gcm_encrypt(g_vt.user, k_gcm_key, k_gcm_iv,
                                NULL, 4, k_gcm_pt, 16, out, out));

    /* After free the callbacks refuse rather than touch a dead Aes. */
    osdp_sc2_wolfcrypt_free(&g_ctx);
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.aes256_ecb_encrypt(g_vt.user, k_aes_key, k_aes_pt, out));
#if OSDP_SC2_WOLFCRYPT_HAS_KMAC
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.kmac256(g_vt.user, k_aes_key, 32, k_aes_pt, 16, out, 16));
#endif
    osdp_sc2_wolfcrypt_free(&g_ctx);   /* twice is fine */
    osdp_sc2_wolfcrypt_free(NULL);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_fips197_aes256_block);
    RUN_TEST(test_gcm_tc16_encrypt_and_decrypt);
    RUN_TEST(test_gcm_in_place_both_directions);
    RUN_TEST(test_gcm_empty_payload);
    RUN_TEST(test_gcm_bad_tag_rejects_and_wipes);
#if OSDP_SC2_WOLFCRYPT_HAS_KMAC
    RUN_TEST(test_kmac256_sp800_185_sample5);
    RUN_TEST(test_kmac256_matches_tiny_kmac);
    RUN_TEST(test_setter_owns_kmac_leaves_rand_alone);
#else
    RUN_TEST(test_setter_leaves_kmac_and_rand_alone);
#endif
    RUN_TEST(test_rng_is_opt_in_and_draws);
    RUN_TEST(test_refusals);
    return UNITY_END();
}
