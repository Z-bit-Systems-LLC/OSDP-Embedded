// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ========================================================================
 * osdp_ACK
 * ====================================================================== */

static void test_ack_decode_accepts_empty(void)
{
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_ack_decode(NULL, 0));
}

static void test_ack_decode_rejects_nonempty(void)
{
    static const uint8_t b[] = { 0x00 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_ack_decode(b, 1));
}

static void test_ack_build_writes_nothing(void)
{
    uint8_t buf[2] = { 0x55, 0x55 };
    size_t n = 99;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_ack_build(buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(0, n);
}

/* ========================================================================
 * osdp_NAK
 * ====================================================================== */

static void test_nak_decode_with_just_error_code(void)
{
    static const uint8_t b[] = { OSDP_NAK_UNKNOWN_CMD };
    osdp_nak_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_nak_decode(b, 1, &got));
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, got.error_code);
    TEST_ASSERT_EQUAL_size_t(0, got.details_len);
    TEST_ASSERT_NULL(got.details);
}

static void test_nak_decode_with_details_round_trip(void)
{
    static const uint8_t details[] = { 0x09, 0xFF, 0x00 };
    osdp_nak_t in = {
        .error_code = OSDP_NAK_RECORD_INVALID,
        .details = details,
        .details_len = sizeof(details),
    };
    uint8_t buf[16]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_nak_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(1u + sizeof(details), w);

    osdp_nak_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_nak_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_RECORD_INVALID, got.error_code);
    TEST_ASSERT_EQUAL_size_t(sizeof(details), got.details_len);
    TEST_ASSERT_EQUAL_MEMORY(details, got.details, sizeof(details));
}

static void test_nak_decode_rejects_empty(void)
{
    osdp_nak_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_nak_decode(NULL, 0, &got));
}

/* ========================================================================
 * osdp_PDID
 * ====================================================================== */

static void test_pdid_round_trip_known_values(void)
{
    osdp_pdid_t in = {
        .vendor_code = { 0xCA, 0xFE, 0x42 },
        .model = 0x10,
        .version = 0x01,
        .serial = 0xDEADBEEFu,
        .firmware_major = 1,
        .firmware_minor = 2,
        .firmware_build = 3,
    };
    uint8_t buf[OSDP_PDID_PAYLOAD_BYTES]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdid_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_PDID_PAYLOAD_BYTES, w);

    /* Spot-check on-wire bytes. */
    TEST_ASSERT_EQUAL_HEX8(0xCA, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(0xEF, buf[5]);   /* serial LE: lowest byte */
    TEST_ASSERT_EQUAL_HEX8(0xDE, buf[8]);   /* serial LE: highest byte */

    osdp_pdid_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdid_decode(buf, w, &got));
    /* Compare field-by-field: osdp_pdid_t has alignment padding before
     * `serial`, so a whole-struct memcmp would trip over uninitialised
     * padding bytes in the decoded copy. */
    TEST_ASSERT_EQUAL_MEMORY(in.vendor_code, got.vendor_code, sizeof(in.vendor_code));
    TEST_ASSERT_EQUAL_HEX8(in.model, got.model);
    TEST_ASSERT_EQUAL_HEX8(in.version, got.version);
    TEST_ASSERT_EQUAL_HEX32(in.serial, got.serial);
    TEST_ASSERT_EQUAL_HEX8(in.firmware_major, got.firmware_major);
    TEST_ASSERT_EQUAL_HEX8(in.firmware_minor, got.firmware_minor);
    TEST_ASSERT_EQUAL_HEX8(in.firmware_build, got.firmware_build);
}

static void test_pdid_decode_rejects_wrong_length(void)
{
    osdp_pdid_t got;
    static const uint8_t short_payload[11] = {0};
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pdid_decode(short_payload, 11, &got));
}

/* ========================================================================
 * osdp_PDCAP
 * ====================================================================== */

static void test_pdcap_round_trip(void)
{
    osdp_pdcap_record_t in[] = {
        { .function_code = 1,  .compliance_level = 1, .num_objects = 4 },
        { .function_code = 2,  .compliance_level = 1, .num_objects = 2 },
        { .function_code = 4,  .compliance_level = 2, .num_objects = 8 },
        { .function_code = 9,  .compliance_level = 1, .num_objects = 0 },
        { .function_code = 16, .compliance_level = 2, .num_objects = 2 },
    };
    const size_t count = sizeof(in) / sizeof(in[0]);
    uint8_t buf[64]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pdcap_build(in, count, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(count * OSDP_PDCAP_RECORD_BYTES, w);

    osdp_pdcap_record_t got[8]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pdcap_decode(buf, w, got, 8, &n));
    TEST_ASSERT_EQUAL_size_t(count, n);
    TEST_ASSERT_EQUAL_MEMORY(in, got, count * sizeof(osdp_pdcap_record_t));
}

static void test_pdcap_decode_rejects_partial_record(void)
{
    static const uint8_t bad[] = { 1, 1, 0, 2, 1 };  /* 5 bytes */
    osdp_pdcap_record_t r[2]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pdcap_decode(bad, sizeof(bad), r, 2, &n));
}

static void test_pdcap_accepts_empty_list(void)
{
    osdp_pdcap_record_t r[1]; size_t n = 99;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_decode(NULL, 0, r, 1, &n));
    TEST_ASSERT_EQUAL_size_t(0, n);
}

/* ========================================================================
 * osdp_RAW
 * ====================================================================== */

static void test_raw_round_trip_26bit_wiegand(void)
{
    /* 26-bit Wiegand needs ceil(26/8) = 4 bytes of card data. */
    static const uint8_t card[4] = { 0x12, 0x34, 0x56, 0x78 };
    osdp_raw_t in = {
        .reader_no    = 0,
        .format_code  = OSDP_RAW_FORMAT_WIEGAND,
        .bit_count    = 26,
        .bit_data     = card,
        .bit_data_len = 4,
    };
    uint8_t buf[16]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_raw_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_RAW_HEADER_BYTES + 4u, w);

    osdp_raw_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_raw_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_UINT16(26, got.bit_count);
    TEST_ASSERT_EQUAL_size_t(4, got.bit_data_len);
    TEST_ASSERT_EQUAL_MEMORY(card, got.bit_data, 4);
}

static void test_raw_decode_rejects_data_length_mismatch(void)
{
    /* bit_count=16 expects 2 data bytes; payload supplies 3. */
    static const uint8_t bad[] = { 0, OSDP_RAW_FORMAT_WIEGAND,
                                   0x10, 0x00, 0xAA, 0xBB, 0xCC };
    osdp_raw_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_raw_decode(bad, sizeof(bad), &got));
}

static void test_raw_build_rejects_data_length_mismatch(void)
{
    static const uint8_t card[4] = {0};
    osdp_raw_t in = { .bit_count = 26, .bit_data = card, .bit_data_len = 3 };
    uint8_t buf[16]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_raw_build(&in, buf, sizeof(buf), &w));
}

/* ========================================================================
 * osdp_KEYPAD
 * ====================================================================== */

static void test_keypad_round_trip(void)
{
    static const uint8_t digits[] = "1234#";
    osdp_keypad_t in = {
        .reader_no   = 0,
        .digit_count = 5,
        .digits      = digits,
        .digits_len  = 5,
    };
    uint8_t buf[16]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_keypad_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_KEYPAD_HEADER_BYTES + 5u, w);

    osdp_keypad_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_keypad_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_UINT8(5, got.digit_count);
    TEST_ASSERT_EQUAL_MEMORY(digits, got.digits, 5);
}

static void test_keypad_decode_rejects_count_mismatch(void)
{
    /* digit_count = 3 but only 1 trailing byte. */
    static const uint8_t bad[] = { 0, 0x03, '1' };
    osdp_keypad_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_keypad_decode(bad, sizeof(bad), &got));
}

/* ========================================================================
 * osdp_COM
 * ====================================================================== */

static void test_com_round_trip(void)
{
    osdp_com_t in = { .address = 0x05, .baud_rate = 115200u };
    uint8_t buf[OSDP_COM_PAYLOAD_BYTES]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_com_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_COM_PAYLOAD_BYTES, w);

    osdp_com_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_com_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(in.address, got.address);
    TEST_ASSERT_EQUAL_HEX32(in.baud_rate, got.baud_rate);
}

static void test_com_decode_rejects_wrong_size(void)
{
    osdp_com_t got;
    static const uint8_t four[] = { 1, 2, 3, 4 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_com_decode(four, 4, &got));
}

/* ========================================================================
 * Registration
 * ====================================================================== */

int main(void)
{
    UNITY_BEGIN();
    /* ACK */
    RUN_TEST(test_ack_decode_accepts_empty);
    RUN_TEST(test_ack_decode_rejects_nonempty);
    RUN_TEST(test_ack_build_writes_nothing);
    /* NAK */
    RUN_TEST(test_nak_decode_with_just_error_code);
    RUN_TEST(test_nak_decode_with_details_round_trip);
    RUN_TEST(test_nak_decode_rejects_empty);
    /* PDID */
    RUN_TEST(test_pdid_round_trip_known_values);
    RUN_TEST(test_pdid_decode_rejects_wrong_length);
    /* PDCAP */
    RUN_TEST(test_pdcap_round_trip);
    RUN_TEST(test_pdcap_decode_rejects_partial_record);
    RUN_TEST(test_pdcap_accepts_empty_list);
    /* RAW */
    RUN_TEST(test_raw_round_trip_26bit_wiegand);
    RUN_TEST(test_raw_decode_rejects_data_length_mismatch);
    RUN_TEST(test_raw_build_rejects_data_length_mismatch);
    /* KEYPAD */
    RUN_TEST(test_keypad_round_trip);
    RUN_TEST(test_keypad_decode_rejects_count_mismatch);
    /* COM */
    RUN_TEST(test_com_round_trip);
    RUN_TEST(test_com_decode_rejects_wrong_size);
    return UNITY_END();
}
