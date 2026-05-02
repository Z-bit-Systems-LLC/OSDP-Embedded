// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_checksum.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

/* The defining invariant from spec 5.9 Table 2: the sum of all message
 * bytes plus the checksum byte is congruent to 0 mod 256. */
static uint8_t sum_mod_256(const uint8_t *data, size_t len)
{
    uint8_t s = 0;
    for (size_t i = 0; i < len; i++) {
        s = (uint8_t)(s + data[i]);
    }
    return s;
}

static void test_checksum_empty_input_is_zero(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x00U, osdp_checksum(NULL, 0));
    TEST_ASSERT_EQUAL_HEX8(0x00U, osdp_checksum((const uint8_t *)"", 0));
}

static void test_checksum_known_single_bytes(void)
{
    /* For a single-byte input, checksum = (uint8_t)(-byte). */
    static const struct { uint8_t in; uint8_t out; } cases[] = {
        { 0x00U, 0x00U },
        { 0x01U, 0xFFU },
        { 0xFFU, 0x01U },
        { 0x53U, 0xADU },   /* OSDP SOM */
        { 0x80U, 0x80U },
        { 0x7FU, 0x81U },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT_EQUAL_HEX8(cases[i].out,
                               osdp_checksum(&cases[i].in, 1));
    }
}

static void test_checksum_invariant_for_arbitrary_payloads(void)
{
    /* For any payload, (sum(data) + checksum) mod 256 == 0. */
    uint32_t s = 0xDEADBEEFU;
    uint8_t buf[256];

    for (int trial = 0; trial < 64; trial++) {
        const size_t len = (s % 256u) + 1u;
        s = s * 1103515245u + 12345u;
        for (size_t i = 0; i < len; i++) {
            buf[i] = (uint8_t)(s & 0xFFu);
            s = s * 1103515245u + 12345u;
        }
        const uint8_t cksum = osdp_checksum(buf, len);
        const uint8_t total = (uint8_t)(sum_mod_256(buf, len) + cksum);
        TEST_ASSERT_EQUAL_HEX8(0x00U, total);
    }
}

static void test_checksum_typical_osdp_poll_frame(void)
{
    /* Header bytes of a checksum-mode poll command from ACU at address
     * 0x00: SOM=0x53, ADDR=0x00, LEN_LSB=0x07, LEN_MSB=0x00, CTRL=0x00,
     * CMND=0x60. Sum = 0x53+0+7+0+0+0x60 = 0xBA. Checksum = 0x46. */
    static const uint8_t hdr[] = { 0x53, 0x00, 0x07, 0x00, 0x00, 0x60 };
    TEST_ASSERT_EQUAL_HEX8(0x46U, osdp_checksum(hdr, sizeof(hdr)));
}

static void test_checksum_handles_null_with_zero_length(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x00U, osdp_checksum(NULL, 0));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_checksum_empty_input_is_zero);
    RUN_TEST(test_checksum_known_single_bytes);
    RUN_TEST(test_checksum_invariant_for_arbitrary_payloads);
    RUN_TEST(test_checksum_typical_osdp_poll_frame);
    RUN_TEST(test_checksum_handles_null_with_zero_length);
    return UNITY_END();
}
