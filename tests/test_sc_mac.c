// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Tests for the OSDP custom CBC-MAC algorithm (spec D.5).
 *
 * The MAC algorithm is non-standard, so there are no published test
 * vectors we can hard-code. The strategy is twofold:
 *
 *   1. Cross-check against a hand-rolled reference that walks the
 *      blocks one at a time using the tiny-AES adapter directly.
 *      Catches bugs in chaining / key selection / padding.
 *   2. Pin specific algorithmic properties (single-block uses S-MAC2,
 *      empty input is exactly one all-padding block, etc.) so future
 *      refactors can't drift. */

#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc_crypto.h"
#include "sc_test_aes.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static const uint8_t kSMAC1[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static const uint8_t kSMAC2[16] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
};
static const uint8_t kICV[16] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};

/* Hand-rolled reference: pad if needed, walk blocks XOR-then-AES with
 * S-MAC1 for blocks 1..n-1 and S-MAC2 for the last. */
static void reference_mac(const uint8_t *msg, size_t len, uint8_t out[16])
{
    const osdp_sc_crypto_t *c = sc_test_crypto_tiny_aes();
    const size_t rem = len % 16;
    const size_t padded = (rem == 0 && len > 0)
                              ? len
                              : (len + (16 - rem));
    /* Allocate a padding scratch covering the worst case (input + 16
     * bytes of pad). */
    uint8_t buf[256 + 32];
    if (padded > sizeof(buf)) {
        TEST_FAIL_MESSAGE("reference scratch too small for test input");
    }
    if (len > 0) {
        (void)memcpy(buf, msg, len);
    }
    if (padded != len) {
        buf[len] = 0x80;
        for (size_t i = len + 1; i < padded; i++) {
            buf[i] = 0x00;
        }
    }
    if (padded == 0) {
        /* len == 0 special case: one all-padding block. */
        buf[0] = 0x80;
        (void)memset(&buf[1], 0, 15);
    }
    const size_t blocks = (padded > 0) ? (padded / 16) : 1;

    uint8_t chain[16];
    (void)memcpy(chain, kICV, 16);
    for (size_t b = 0; b < blocks; b++) {
        uint8_t xored[16];
        for (size_t i = 0; i < 16; i++) {
            xored[i] = (uint8_t)(buf[b * 16 + i] ^ chain[i]);
        }
        const uint8_t *key = (b == blocks - 1) ? kSMAC2 : kSMAC1;
        TEST_ASSERT_EQUAL(OSDP_OK,
            c->aes128_ecb_encrypt(c->user, key, xored, chain));
    }
    (void)memcpy(out, chain, 16);
}

static void check_mac_matches_reference(const uint8_t *msg, size_t len)
{
    uint8_t expected[16];
    reference_mac(msg, len, expected);
    uint8_t got[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_compute_mac(sc_test_crypto_tiny_aes(),
                            kSMAC1, kSMAC2, kICV,
                            msg, len, got));
    TEST_ASSERT_EQUAL_MEMORY(expected, got, 16);
}

static void test_mac_empty_input_uses_padding_only_block(void)
{
    check_mac_matches_reference(NULL, 0);
}

static void test_mac_single_short_block_uses_smac2(void)
{
    static const uint8_t msg[] = { 0x53, 0x00, 0x07, 0x00, 0x04 };
    check_mac_matches_reference(msg, sizeof(msg));
}

static void test_mac_exactly_one_block_no_padding(void)
{
    static const uint8_t msg[16] = {
        0x53, 0x00, 0x10, 0x00, 0x04, 0x60, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    };
    check_mac_matches_reference(msg, sizeof(msg));
}

static void test_mac_two_blocks_uses_both_keys(void)
{
    static const uint8_t msg[32] = {0};
    check_mac_matches_reference(msg, sizeof(msg));
}

static void test_mac_two_and_a_half_blocks_pads_then_macs(void)
{
    /* 40 bytes → pad to 48 → 3 blocks; first two use S-MAC1, last
     * uses S-MAC2. */
    uint8_t msg[40];
    for (size_t i = 0; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i ^ 0xA5);
    }
    check_mac_matches_reference(msg, sizeof(msg));
}

static void test_mac_eight_blocks(void)
{
    uint8_t msg[128];
    uint32_t s = 0x12345678u;
    for (size_t i = 0; i < sizeof(msg); i++) {
        s = s * 1103515245u + 12345u;
        msg[i] = (uint8_t)(s >> 16);
    }
    check_mac_matches_reference(msg, sizeof(msg));
}

static void test_mac_changing_the_icv_changes_the_output(void)
{
    /* Sanity: the rolling chain matters — different ICV must produce
     * a different MAC for the same input. */
    static const uint8_t msg[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                    17,18,19,20};
    uint8_t a[16], b[16];
    static const uint8_t icv_other[16] = {0};
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_compute_mac(sc_test_crypto_tiny_aes(),
                            kSMAC1, kSMAC2, kICV,
                            msg, sizeof(msg), a));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_compute_mac(sc_test_crypto_tiny_aes(),
                            kSMAC1, kSMAC2, icv_other,
                            msg, sizeof(msg), b));
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(a, b, 16),
        "MAC didn't change with ICV");
}

static void test_mac_swapping_smac1_and_smac2_changes_multi_block_output(void)
{
    /* For a multi-block input, swapping S-MAC1 and S-MAC2 must alter
     * the result (otherwise the spec's distinction is meaningless).
     * A single-block input would be unaffected, since only S-MAC2 is
     * used; we test with two blocks. */
    static const uint8_t msg[32] = {0};
    uint8_t a[16], b[16];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_compute_mac(sc_test_crypto_tiny_aes(),
                            kSMAC1, kSMAC2, kICV, msg, sizeof(msg), a));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_compute_mac(sc_test_crypto_tiny_aes(),
                            kSMAC2, kSMAC1, kICV, msg, sizeof(msg), b));
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(a, b, 16),
        "MAC was symmetric under S-MAC1 ↔ S-MAC2 swap");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mac_empty_input_uses_padding_only_block);
    RUN_TEST(test_mac_single_short_block_uses_smac2);
    RUN_TEST(test_mac_exactly_one_block_no_padding);
    RUN_TEST(test_mac_two_blocks_uses_both_keys);
    RUN_TEST(test_mac_two_and_a_half_blocks_pads_then_macs);
    RUN_TEST(test_mac_eight_blocks);
    RUN_TEST(test_mac_changing_the_icv_changes_the_output);
    RUN_TEST(test_mac_swapping_smac1_and_smac2_changes_multi_block_output);
    return UNITY_END();
}
