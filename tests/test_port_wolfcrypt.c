// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Contract tests for ports/wolfcrypt. The SC behaviour of its AES is covered
 * by the *_wolfcrypt re-run of the whole SC suite; this file covers what that
 * re-run cannot see: independent AES vectors in both directions, how the two
 * setters compose with a caller's vtable, the opt-in DRBG, and argument and
 * lifecycle refusals. */

#include "osdp_sc_wolfcrypt.h"
#include "unity.h"

#include <string.h>

/* NIST SP 800-38A F.1.1 / F.1.2, ECB-AES128, block #1. */
static const uint8_t k_key[OSDP_AES_KEY_LEN] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
};
static const uint8_t k_pt[OSDP_AES_BLOCK_LEN] = {
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
};
static const uint8_t k_ct[OSDP_AES_BLOCK_LEN] = {
    0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60,
    0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
};

static osdp_sc_wolfcrypt_t g_ctx;
static osdp_sc_crypto_t    g_vt;

static osdp_status_t sentinel_rand(void *user, uint8_t *out, size_t len)
{
    (void)user;
    (void)out;
    (void)len;
    return OSDP_OK;
}

void setUp(void)
{
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(&g_vt, 0, sizeof(g_vt));
}

void tearDown(void)
{
    osdp_sc_wolfcrypt_free(&g_ctx);
}

static void test_sp800_38a_encrypt_and_decrypt(void)
{
    uint8_t out[OSDP_AES_BLOCK_LEN];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));

    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes128_ecb_encrypt(g_vt.user, k_key, k_pt, out));
    TEST_ASSERT_EQUAL_MEMORY(k_ct, out, sizeof(k_ct));

    /* Decrypt checked against the vector, not just as encrypt's inverse. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes128_ecb_decrypt(g_vt.user, k_key, k_ct, out));
    TEST_ASSERT_EQUAL_MEMORY(k_pt, out, sizeof(k_pt));
}

static void test_in_place_both_directions(void)
{
    uint8_t buf[OSDP_AES_BLOCK_LEN];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));

    memcpy(buf, k_pt, sizeof(buf));
    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes128_ecb_encrypt(g_vt.user, k_key, buf, buf));
    TEST_ASSERT_EQUAL_MEMORY(k_ct, buf, sizeof(buf));

    TEST_ASSERT_EQUAL(OSDP_OK,
        g_vt.aes128_ecb_decrypt(g_vt.user, k_key, buf, buf));
    TEST_ASSERT_EQUAL_MEMORY(k_pt, buf, sizeof(buf));
}

static void test_key_switch_between_calls(void)
{
    /* SC alternates keys block to block; a stale key schedule would show up
     * as the second key producing the first key's ciphertext. */
    static const uint8_t other_key[OSDP_AES_KEY_LEN] = {0};
    uint8_t a[OSDP_AES_BLOCK_LEN];
    uint8_t b[OSDP_AES_BLOCK_LEN];
    uint8_t c[OSDP_AES_BLOCK_LEN];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.aes128_ecb_encrypt(g_vt.user, k_key, k_pt, a));
    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.aes128_ecb_encrypt(g_vt.user, other_key, k_pt, b));
    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.aes128_ecb_encrypt(g_vt.user, k_key, k_pt, c));

    TEST_ASSERT_EQUAL_MEMORY(k_ct, a, sizeof(a));
    TEST_ASSERT_FALSE(memcmp(a, b, sizeof(a)) == 0);
    TEST_ASSERT_EQUAL_MEMORY(k_ct, c, sizeof(c));
}

static void test_aes_setter_leaves_rand_alone(void)
{
    g_vt.rand_bytes = sentinel_rand;

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));
    TEST_ASSERT_NOT_NULL(g_vt.aes128_ecb_encrypt);
    TEST_ASSERT_NOT_NULL(g_vt.aes128_ecb_decrypt);
    TEST_ASSERT_EQUAL_PTR(sentinel_rand, g_vt.rand_bytes);
    TEST_ASSERT_EQUAL_PTR(&g_ctx, g_vt.user);
}

static void test_aes_setter_installs_no_rng(void)
{
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));
    TEST_ASSERT_NULL(g_vt.rand_bytes);
}

static void test_rng_generates_distinct_blocks(void)
{
    uint8_t a[8];
    uint8_t b[8];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_rng(&g_ctx, &g_vt));
    TEST_ASSERT_NOT_NULL(g_vt.rand_bytes);

    /* The SC handshake draws 8 bytes (RND.A / RND.B). Two draws colliding
     * has probability 2^-64; equality means the DRBG is not advancing. */
    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.rand_bytes(g_vt.user, a, sizeof(a)));
    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.rand_bytes(g_vt.user, b, sizeof(b)));
    TEST_ASSERT_FALSE(memcmp(a, b, sizeof(a)) == 0);

    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.rand_bytes(g_vt.user, NULL, 0));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      g_vt.rand_bytes(g_vt.user, NULL, 8));
}

static void test_rng_setter_is_idempotent(void)
{
    uint8_t a[8];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_rng(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_rng(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK, g_vt.rand_bytes(g_vt.user, a, sizeof(a)));
}

static void test_rng_requires_aes_first(void)
{
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_sc_wolfcrypt_rng(&g_ctx, &g_vt));
    TEST_ASSERT_NULL(g_vt.rand_bytes);
}

static void test_rng_requires_vtable_bound_to_ctx(void)
{
    osdp_sc_crypto_t other;

    memset(&other, 0, sizeof(other));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_sc_wolfcrypt_rng(&g_ctx, &other));
    TEST_ASSERT_NULL(other.rand_bytes);
}

static void test_null_arguments_refused(void)
{
    uint8_t out[OSDP_AES_BLOCK_LEN];

    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_sc_wolfcrypt_aes128(NULL, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_sc_wolfcrypt_aes128(&g_ctx, NULL));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_sc_wolfcrypt_rng(NULL, &g_vt));

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.aes128_ecb_encrypt(NULL, k_key, k_pt, out));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.aes128_ecb_encrypt(g_vt.user, NULL, k_pt, out));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.aes128_ecb_decrypt(g_vt.user, k_key, NULL, out));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.aes128_ecb_decrypt(g_vt.user, k_key, k_ct, NULL));

    osdp_sc_wolfcrypt_free(NULL);
}

static void test_free_disarms_callbacks_and_is_repeatable(void)
{
    uint8_t out[OSDP_AES_BLOCK_LEN];

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_aes128(&g_ctx, &g_vt));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_wolfcrypt_rng(&g_ctx, &g_vt));

    osdp_sc_wolfcrypt_free(&g_ctx);
    osdp_sc_wolfcrypt_free(&g_ctx);

    /* A vtable left bound after free must fail closed, not run on a freed
     * key schedule or DRBG. */
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.aes128_ecb_encrypt(g_vt.user, k_key, k_pt, out));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        g_vt.rand_bytes(g_vt.user, out, 8));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sp800_38a_encrypt_and_decrypt);
    RUN_TEST(test_in_place_both_directions);
    RUN_TEST(test_key_switch_between_calls);
    RUN_TEST(test_aes_setter_leaves_rand_alone);
    RUN_TEST(test_aes_setter_installs_no_rng);
    RUN_TEST(test_rng_generates_distinct_blocks);
    RUN_TEST(test_rng_setter_is_idempotent);
    RUN_TEST(test_rng_requires_aes_first);
    RUN_TEST(test_rng_requires_vtable_bound_to_ctx);
    RUN_TEST(test_null_arguments_refused);
    RUN_TEST(test_free_disarms_callbacks_and_is_repeatable);
    return UNITY_END();
}
