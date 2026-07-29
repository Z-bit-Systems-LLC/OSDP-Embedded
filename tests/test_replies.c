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

/* ---- osdp_pdcap_validate_record -----------------------------------------
 *
 * A pure function of the three bytes, independent of any osdp_pd_t — so
 * these tests never touch osdp::pd, just the Annex B catalog. */

static void test_validate_record_rejects_null(void)
{
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pdcap_validate_record(NULL));
}

static void test_validate_record_rejects_unknown_function_code(void)
{
    const osdp_pdcap_record_t r0 = { .function_code = 0,
                                     .compliance_level = 0, .num_objects = 0 };
    const osdp_pdcap_record_t r18 = { .function_code = 18,
                                      .compliance_level = 0, .num_objects = 0 };
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pdcap_validate_record(&r0));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pdcap_validate_record(&r18));
}

/* fn 4 (Reader LED Control) is a contiguous 0..6 enumeration (B.5). */
static void test_validate_record_range_enum(void)
{
    const osdp_pdcap_record_t ok = { .function_code = 4,
                                     .compliance_level = 6, .num_objects = 1 };
    const osdp_pdcap_record_t bad = { .function_code = 4,
                                      .compliance_level = 7, .num_objects = 1 };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_validate_record(&ok));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pdcap_validate_record(&bad));
}

/* fn 3 (Card Data Format) requires num_objects == 0x00 (B.4). */
static void test_validate_record_zero_only_field(void)
{
    const osdp_pdcap_record_t ok = { .function_code = 3,
                                     .compliance_level = 1, .num_objects = 0 };
    const osdp_pdcap_record_t bad = { .function_code = 3,
                                      .compliance_level = 1, .num_objects = 1 };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_validate_record(&ok));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pdcap_validate_record(&bad));
}

/* fn 9 (Communication Security) is a 1-bit bitmap on both bytes (B.10). */
static void test_validate_record_bitmap_rejects_reserved_bits(void)
{
    const osdp_pdcap_record_t ok = { .function_code = 9,
                                     .compliance_level = 0x01,
                                     .num_objects = 0x01 };
    const osdp_pdcap_record_t bad = { .function_code = 9,
                                      .compliance_level = 0x02,
                                      .num_objects = 0x01 };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_validate_record(&ok));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pdcap_validate_record(&bad));
}

/* fn 16 (OSDP Version) allows a named 0..4 range plus 0x80..0xFF private
 * use (B.17); the gap in between is reserved. */
static void test_validate_record_range_or_private(void)
{
    const osdp_pdcap_record_t named   = { .function_code = 16,
                                          .compliance_level = 0x04,
                                          .num_objects = 0 };
    const osdp_pdcap_record_t private_use = { .function_code = 16,
                                              .compliance_level = 0x90,
                                              .num_objects = 0 };
    const osdp_pdcap_record_t reserved = { .function_code = 16,
                                           .compliance_level = 0x05,
                                           .num_objects = 0 };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_validate_record(&named));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_validate_record(&private_use));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pdcap_validate_record(&reserved));
}

/* fn 10 (Receive BufferSize) is a free-form 16-bit size split across both
 * bytes — every value is legal on its own terms. */
static void test_validate_record_any_field_accepts_everything(void)
{
    const osdp_pdcap_record_t lo = { .function_code = 10,
                                     .compliance_level = 0x00,
                                     .num_objects = 0x02 };
    const osdp_pdcap_record_t hi = { .function_code = 10,
                                     .compliance_level = 0xFF,
                                     .num_objects = 0xFF };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_validate_record(&lo));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_validate_record(&hi));
}

/* ========================================================================
 * osdp_LSTATR
 * ====================================================================== */

static void test_lstatr_round_trip(void)
{
    osdp_lstatr_t in = {
        .tamper = OSDP_LSTATR_TAMPER,
        .power  = OSDP_LSTATR_NORMAL,
    };
    uint8_t buf[OSDP_LSTATR_PAYLOAD_BYTES]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_lstatr_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_LSTATR_PAYLOAD_BYTES, w);
    TEST_ASSERT_EQUAL_HEX8(0x01, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[1]);

    osdp_lstatr_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_lstatr_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(in.tamper, got.tamper);
    TEST_ASSERT_EQUAL_HEX8(in.power,  got.power);
}

static void test_lstatr_decode_rejects_wrong_size(void)
{
    osdp_lstatr_t got;
    static const uint8_t one[1] = { 0 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_lstatr_decode(one, 1, &got));
}

/* ========================================================================
 * osdp_ISTATR
 * ====================================================================== */

static void test_istatr_round_trip(void)
{
    static const uint8_t in[] = {
        OSDP_ISTATR_INACTIVE, OSDP_ISTATR_ACTIVE,
        OSDP_ISTATR_OPEN,     OSDP_ISTATR_FAULT,
    };
    uint8_t buf[16]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_istatr_build(in, sizeof(in), buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(sizeof(in), w);
    TEST_ASSERT_EQUAL_MEMORY(in, buf, sizeof(in));

    uint8_t got[8]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_istatr_decode(buf, w, got, sizeof(got), &n));
    TEST_ASSERT_EQUAL_size_t(sizeof(in), n);
    TEST_ASSERT_EQUAL_MEMORY(in, got, sizeof(in));
}

static void test_istatr_decode_rejects_overflow(void)
{
    static const uint8_t three[] = { 0, 1, 2 };
    uint8_t got[2]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_istatr_decode(three, sizeof(three), got, 2, &n));
}

/* ========================================================================
 * osdp_OSTATR
 * ====================================================================== */

static void test_ostatr_round_trip(void)
{
    static const uint8_t in[] = { OSDP_OSTATR_ACTIVE, OSDP_OSTATR_INACTIVE };
    uint8_t buf[8]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_ostatr_build(in, sizeof(in), buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(sizeof(in), w);
    /* Encoding sanity: active encodes as 0x01, inactive as 0x00. Guards
     * against the OSDP.Net OutputStatus inversion regression (d42c1cad5). */
    TEST_ASSERT_EQUAL_HEX8(0x01, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[1]);

    uint8_t got[8]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_ostatr_decode(buf, w, got, sizeof(got), &n));
    TEST_ASSERT_EQUAL_size_t(sizeof(in), n);
    TEST_ASSERT_EQUAL_MEMORY(in, got, sizeof(in));
}

static void test_ostatr_build_rejects_small_buffer(void)
{
    static const uint8_t in[] = { 1, 0, 1 };
    uint8_t buf[2]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_ostatr_build(in, sizeof(in), buf, sizeof(buf), &w));
}

/* ========================================================================
 * osdp_RSTATR
 * ====================================================================== */

static void test_rstatr_round_trip(void)
{
    static const uint8_t in[] = { OSDP_RSTATR_NORMAL, OSDP_RSTATR_TAMPER };
    uint8_t buf[8]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_rstatr_build(in, sizeof(in), buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(sizeof(in), w);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(0x02, buf[1]);

    uint8_t got[8]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_rstatr_decode(buf, w, got, sizeof(got), &n));
    TEST_ASSERT_EQUAL_size_t(sizeof(in), n);
    TEST_ASSERT_EQUAL_MEMORY(in, got, sizeof(in));
}

static void test_rstatr_accepts_empty_list(void)
{
    uint8_t got[1]; size_t n = 99;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_rstatr_decode(NULL, 0, got, 1, &n));
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
 * osdp_FTSTAT
 * ====================================================================== */

static void test_ftstat_round_trip_positive_status(void)
{
    osdp_ftstat_t in = {
        .action         = OSDP_FTSTAT_ACTION_INTERLEAVE_OK,
        .delay_ms       = 250,
        .status_detail  = OSDP_FTSTAT_PROCESSED,
        .update_msg_max = 128,
    };
    uint8_t buf[OSDP_FTSTAT_PAYLOAD_BYTES]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_ftstat_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_FTSTAT_PAYLOAD_BYTES, w);

    osdp_ftstat_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_ftstat_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(in.action, got.action);
    TEST_ASSERT_EQUAL_UINT16(250, got.delay_ms);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_PROCESSED, got.status_detail);
    TEST_ASSERT_EQUAL_UINT16(128, got.update_msg_max);
}

/* The signed FtStatusDetail must survive the round trip through the
 * unsigned wire encoding. */
static void test_ftstat_round_trip_negative_status(void)
{
    osdp_ftstat_t in = {
        .action         = 0,
        .delay_ms       = 0,
        .status_detail  = OSDP_FTSTAT_MALFORMED,   /* -3 */
        .update_msg_max = 0,
    };
    uint8_t buf[OSDP_FTSTAT_PAYLOAD_BYTES]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_ftstat_build(&in, buf, sizeof(buf), &w));
    /* -3 as little-endian int16 is 0xFD 0xFF. */
    TEST_ASSERT_EQUAL_HEX8(0xFD, buf[3]);
    TEST_ASSERT_EQUAL_HEX8(0xFF, buf[4]);

    osdp_ftstat_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_ftstat_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_INT16(-3, got.status_detail);
}

static void test_ftstat_decode_rejects_wrong_size(void)
{
    osdp_ftstat_t got;
    static const uint8_t six[] = { 1, 2, 3, 4, 5, 6 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_ftstat_decode(six, sizeof(six), &got));
}

static void test_ftstat_build_rejects_small_buffer(void)
{
    osdp_ftstat_t in = { .action = 0, .delay_ms = 0,
                         .status_detail = 0, .update_msg_max = 0 };
    uint8_t buf[OSDP_FTSTAT_PAYLOAD_BYTES - 1]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_ftstat_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(0, w);
}

/* ========================================================================
 * Registration
 * ====================================================================== */

/* ========================================================================
 * osdp_BUSY — empty payload
 *
 * The interesting parts of osdp_BUSY (SQN always 0, sent in the clear under
 * Secure Channel, never cached as the retransmit reply) live in the PD state
 * machine, not here. The codec's whole job is to carry no data.
 * ====================================================================== */

static void test_busy_is_empty_payload(void)
{
    size_t  w = 999;
    uint8_t buf[4];
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_busy_build(buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(0, w);

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_busy_decode(NULL, 0));
    static const uint8_t stray[1] = { 0x00 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_busy_decode(stray, 1));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_busy_build(buf, sizeof(buf), NULL));
}

/* ========================================================================
 * osdp_FMT
 * ====================================================================== */

static void test_fmt_round_trip(void)
{
    static const uint8_t chars[] = { '1', '2', '3', '4', '5' };
    osdp_fmt_t in = {
        .reader_no  = 0x00,
        .direction  = OSDP_FMT_DIR_FORWARD,
        .char_count = (uint8_t)sizeof(chars),
        .chars      = chars,
        .chars_len  = sizeof(chars),
    };
    uint8_t buf[32];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_fmt_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_FMT_HEADER_BYTES + sizeof(chars), w);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(OSDP_FMT_DIR_FORWARD, buf[1]);
    TEST_ASSERT_EQUAL_HEX8(sizeof(chars), buf[2]);

    osdp_fmt_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_fmt_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(in.reader_no, got.reader_no);
    TEST_ASSERT_EQUAL_HEX8(in.direction, got.direction);
    TEST_ASSERT_EQUAL_UINT8(in.char_count, got.char_count);
    TEST_ASSERT_EQUAL_size_t(sizeof(chars), got.chars_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(chars, got.chars, sizeof(chars));
}

static void test_fmt_round_trip_zero_chars(void)
{
    osdp_fmt_t in = { .reader_no = 0x00, .direction = OSDP_FMT_DIR_REVERSE,
                      .char_count = 0, .chars = NULL, .chars_len = 0 };
    uint8_t buf[8];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_fmt_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_FMT_HEADER_BYTES, w);

    osdp_fmt_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_fmt_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_UINT8(0, got.char_count);
    TEST_ASSERT_NULL(got.chars);
}

/* The count field must agree with the bytes actually present, so a frame
 * padded or truncated in transit is rejected rather than mis-parsed. */
static void test_fmt_decode_rejects_count_mismatch(void)
{
    static const uint8_t claims_five[] = { 0x00, 0x01, 0x05, 'a', 'b' };
    osdp_fmt_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_fmt_decode(claims_five, sizeof(claims_five), &got));

    static const uint8_t claims_one[] = { 0x00, 0x01, 0x01, 'a', 'b' };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_fmt_decode(claims_one, sizeof(claims_one), &got));
}

static void test_fmt_decode_rejects_short_header(void)
{
    static const uint8_t two[2] = { 0x00, 0x01 };
    osdp_fmt_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_fmt_decode(two, 2, &got));
}

static void test_fmt_build_rejects_inconsistent_length_fields(void)
{
    static const uint8_t chars[] = { 'x', 'y' };
    osdp_fmt_t in = { .reader_no = 0, .direction = OSDP_FMT_DIR_FORWARD,
                      .char_count = 5,          /* disagrees with chars_len */
                      .chars = chars, .chars_len = sizeof(chars) };
    uint8_t buf[16];
    size_t  w = 999;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_fmt_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(0, w);
}

/* ========================================================================
 * osdp_MFGREP
 * ====================================================================== */

static void test_mfgrep_round_trip(void)
{
    static const uint8_t vendor_data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    osdp_mfgrep_t in = {
        .vendor_code = { 0x5A, 0x42, 0x43 },
        .data        = vendor_data,
        .data_len    = sizeof(vendor_data),
    };
    uint8_t buf[32];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfgrep_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_MFGREP_HEADER_BYTES + sizeof(vendor_data), w);
    TEST_ASSERT_EQUAL_HEX8(0x5A, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(0x42, buf[1]);
    TEST_ASSERT_EQUAL_HEX8(0x43, buf[2]);

    osdp_mfgrep_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfgrep_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(in.vendor_code, got.vendor_code,
                                 OSDP_MFGREP_VENDOR_CODE_BYTES);
    TEST_ASSERT_EQUAL_size_t(sizeof(vendor_data), got.data_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(vendor_data, got.data, sizeof(vendor_data));
}

static void test_mfgrep_round_trip_no_data(void)
{
    osdp_mfgrep_t in = { .vendor_code = { 1, 2, 3 },
                         .data = NULL, .data_len = 0 };
    uint8_t buf[8];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfgrep_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_MFGREP_HEADER_BYTES, w);

    osdp_mfgrep_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfgrep_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_size_t(0, got.data_len);
    TEST_ASSERT_NULL(got.data);
}

static void test_mfgrep_decode_rejects_truncated_vendor_code(void)
{
    static const uint8_t two[2] = { 0x5A, 0x42 };
    osdp_mfgrep_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_mfgrep_decode(two, 2, &got));
}

static void test_mfgrep_build_rejects_small_buffer(void)
{
    static const uint8_t data[4] = { 1, 2, 3, 4 };
    osdp_mfgrep_t in = { .vendor_code = { 1, 2, 3 },
                         .data = data, .data_len = sizeof(data) };
    uint8_t buf[OSDP_MFGREP_HEADER_BYTES + 3];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_mfgrep_build(&in, buf, sizeof(buf), &w));
}

/* ========================================================================
 * osdp_MFGSTATR / osdp_MFGERRR — one vendor byte each, both deprecated
 * ====================================================================== */

static void test_mfgstatr_round_trip(void)
{
    osdp_mfgstatr_t in = { .data = 0xA7 };
    uint8_t buf[OSDP_MFGSTATR_PAYLOAD_BYTES];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfgstatr_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_MFGSTATR_PAYLOAD_BYTES, w);
    TEST_ASSERT_EQUAL_HEX8(0xA7, buf[0]);

    osdp_mfgstatr_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfgstatr_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(in.data, got.data);
}

static void test_mfgerrr_round_trip(void)
{
    osdp_mfgerrr_t in = { .data = 0x5C };
    uint8_t buf[OSDP_MFGERRR_PAYLOAD_BYTES];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfgerrr_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_MFGERRR_PAYLOAD_BYTES, w);
    TEST_ASSERT_EQUAL_HEX8(0x5C, buf[0]);

    osdp_mfgerrr_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfgerrr_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(in.data, got.data);
}

static void test_mfgstatr_and_mfgerrr_reject_wrong_size(void)
{
    static const uint8_t two[2] = { 0x01, 0x02 };
    osdp_mfgstatr_t s;
    osdp_mfgerrr_t  e;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_mfgstatr_decode(two, 2, &s));
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_mfgstatr_decode(two, 0, &s));
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_mfgerrr_decode(two, 2, &e));
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_mfgerrr_decode(two, 0, &e));
}

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
    RUN_TEST(test_validate_record_rejects_null);
    RUN_TEST(test_validate_record_rejects_unknown_function_code);
    RUN_TEST(test_validate_record_range_enum);
    RUN_TEST(test_validate_record_zero_only_field);
    RUN_TEST(test_validate_record_bitmap_rejects_reserved_bits);
    RUN_TEST(test_validate_record_range_or_private);
    RUN_TEST(test_validate_record_any_field_accepts_everything);
    /* LSTATR */
    RUN_TEST(test_lstatr_round_trip);
    RUN_TEST(test_lstatr_decode_rejects_wrong_size);
    /* ISTATR */
    RUN_TEST(test_istatr_round_trip);
    RUN_TEST(test_istatr_decode_rejects_overflow);
    /* OSTATR */
    RUN_TEST(test_ostatr_round_trip);
    RUN_TEST(test_ostatr_build_rejects_small_buffer);
    /* RSTATR */
    RUN_TEST(test_rstatr_round_trip);
    RUN_TEST(test_rstatr_accepts_empty_list);
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
    /* FTSTAT */
    RUN_TEST(test_ftstat_round_trip_positive_status);
    RUN_TEST(test_ftstat_round_trip_negative_status);
    RUN_TEST(test_ftstat_decode_rejects_wrong_size);
    RUN_TEST(test_ftstat_build_rejects_small_buffer);
    /* BUSY */
    RUN_TEST(test_busy_is_empty_payload);
    /* FMT (deprecated by spec; decoded for Monitor use) */
    RUN_TEST(test_fmt_round_trip);
    RUN_TEST(test_fmt_round_trip_zero_chars);
    RUN_TEST(test_fmt_decode_rejects_count_mismatch);
    RUN_TEST(test_fmt_decode_rejects_short_header);
    RUN_TEST(test_fmt_build_rejects_inconsistent_length_fields);
    /* MFGREP */
    RUN_TEST(test_mfgrep_round_trip);
    RUN_TEST(test_mfgrep_round_trip_no_data);
    RUN_TEST(test_mfgrep_decode_rejects_truncated_vendor_code);
    RUN_TEST(test_mfgrep_build_rejects_small_buffer);
    /* MFGSTATR / MFGERRR (both deprecated by spec) */
    RUN_TEST(test_mfgstatr_round_trip);
    RUN_TEST(test_mfgerrr_round_trip);
    RUN_TEST(test_mfgstatr_and_mfgerrr_reject_wrong_size);
    return UNITY_END();
}
