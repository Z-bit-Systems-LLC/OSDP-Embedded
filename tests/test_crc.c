// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_crc.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ----- Independent reference implementation -------------------------------
 *
 * A bit-serial shift-and-XOR computation, derived directly from the OSDP
 * Annex C definition. Used to cross-check the table-based fast path so we
 * catch transcription errors in the static table without trusting the
 * implementation under test. */
static uint16_t reference_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = OSDP_CRC16_INIT;
    for (size_t i = 0; i < len; i++) {
        /* Bytes are processed MSB first. The "augmentation with 16 zero
         * bits" of the textbook formulation is folded into the table init
         * value; doing the same here means starting from 0x1D0F and
         * XOR-ing the byte into the high half of the register before
         * shifting, which is equivalent to the table-based algorithm. */
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (int b = 0; b < 8; b++) {
            if (crc & 0x8000U) {
                crc = (uint16_t)((uint16_t)(crc << 1) ^ 0x1021U);
            } else {
                crc = (uint16_t)(crc << 1);
            }
        }
    }
    return crc;
}

/* ----- Tests --------------------------------------------------------------*/

static void test_crc_empty_input_returns_init_value(void)
{
    TEST_ASSERT_EQUAL_HEX16(OSDP_CRC16_INIT, osdp_crc16(NULL, 0));
    TEST_ASSERT_EQUAL_HEX16(OSDP_CRC16_INIT, osdp_crc16((const uint8_t *)"", 0));
    TEST_ASSERT_EQUAL_HEX16(0x1D0FU, osdp_crc16(NULL, 0));
}

static void test_crc_single_som_byte(void)
{
    /* Hand-traced from the algorithm:
     *   crc = 0x1D0F
     *   idx = ((0x1D0F >> 8) ^ 0x53) & 0xFF = 0x1D ^ 0x53 = 0x4E
     *   table[0x4E] = 0xA90A
     *   crc = (0x1D0F << 8) ^ 0xA90A = 0x0F00 ^ 0xA90A = 0xA60A
     */
    const uint8_t som = 0x53;
    TEST_ASSERT_EQUAL_HEX16(0xA60AU, osdp_crc16(&som, 1));
}

static void test_crc_table_matches_reference_for_all_byte_inputs(void)
{
    /* Sanity-check the static CRC table against the bit-serial reference
     * for every 1-byte input. Catches transcription errors in the table. */
    for (unsigned i = 0; i < 256u; i++) {
        const uint8_t b = (uint8_t)i;
        const uint16_t expected = reference_crc16(&b, 1);
        const uint16_t actual = osdp_crc16(&b, 1);
        char msg[64];
        (void)msg;
        TEST_ASSERT_EQUAL_HEX16_MESSAGE(expected, actual, "byte input mismatch");
    }
}

static void test_crc_table_matches_reference_for_random_payloads(void)
{
    /* Deterministic LCG so the test is reproducible across platforms. */
    uint32_t s = 0xC0FFEEU;
    uint8_t buf[256];

    for (int trial = 0; trial < 64; trial++) {
        const size_t len = (s % 256u) + 1u;
        s = s * 1103515245u + 12345u;
        for (size_t i = 0; i < len; i++) {
            buf[i] = (uint8_t)(s & 0xFFu);
            s = s * 1103515245u + 12345u;
        }
        const uint16_t expected = reference_crc16(buf, len);
        const uint16_t actual = osdp_crc16(buf, len);
        TEST_ASSERT_EQUAL_HEX16(expected, actual);
    }
}

static void test_crc_streaming_matches_oneshot(void)
{
    static const uint8_t buf[] = {
        0x53, 0x00, 0x08, 0x00, 0x00, 0x60, 0x12, 0x34
    };
    const size_t len = sizeof(buf);
    const uint16_t one_shot = osdp_crc16(buf, len);

    /* Try every possible 2-way split. */
    for (size_t split = 0; split <= len; split++) {
        uint16_t crc = osdp_crc16_update(OSDP_CRC16_INIT, buf, split);
        crc = osdp_crc16_update(crc, buf + split, len - split);
        TEST_ASSERT_EQUAL_HEX16(one_shot, crc);
    }

    /* Byte-at-a-time also matches. */
    uint16_t streaming = OSDP_CRC16_INIT;
    for (size_t i = 0; i < len; i++) {
        streaming = osdp_crc16_update(streaming, &buf[i], 1);
    }
    TEST_ASSERT_EQUAL_HEX16(one_shot, streaming);
}

static void test_crc_handles_null_data_with_zero_length(void)
{
    TEST_ASSERT_EQUAL_HEX16(OSDP_CRC16_INIT, osdp_crc16(NULL, 0));
    TEST_ASSERT_EQUAL_HEX16(OSDP_CRC16_INIT,
                            osdp_crc16_update(OSDP_CRC16_INIT, NULL, 0));
}

static void test_crc_typical_osdp_poll_frame_header(void)
{
    /* Header bytes of a CRC-mode poll command from ACU at address 0x00:
     *   SOM=0x53, ADDR=0x00, LEN_LSB=0x09, LEN_MSB=0x00, CTRL=0x04, CMND=0x60.
     * Total frame length 9 bytes (header + 2 CRC bytes).
     * Verifies the implementation works on a realistic OSDP byte sequence;
     * the actual CRC value is reproduced by the reference implementation. */
    static const uint8_t hdr[] = { 0x53, 0x00, 0x09, 0x00, 0x04, 0x60 };
    const uint16_t expected = reference_crc16(hdr, sizeof(hdr));
    const uint16_t actual = osdp_crc16(hdr, sizeof(hdr));
    TEST_ASSERT_EQUAL_HEX16(expected, actual);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_crc_empty_input_returns_init_value);
    RUN_TEST(test_crc_single_som_byte);
    RUN_TEST(test_crc_table_matches_reference_for_all_byte_inputs);
    RUN_TEST(test_crc_table_matches_reference_for_random_payloads);
    RUN_TEST(test_crc_streaming_matches_oneshot);
    RUN_TEST(test_crc_handles_null_data_with_zero_length);
    RUN_TEST(test_crc_typical_osdp_poll_frame_header);
    return UNITY_END();
}
