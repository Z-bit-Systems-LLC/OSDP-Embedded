// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdpcap.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* The canonical example from the OSDPCAP format spec, copied verbatim. */
static const char EXAMPLE_RECORD[] =
    "{ \"timeSec\" : \"1580342115\", \"timeNano\" : \"984691851\", "
    "\"io\" : \"trace\", "
    "\"data\" : \" ff ff 53 80 08 00 01 4b 01 d8\", "
    "\"osdpTraceVersion\":\"1\", "
    "\"osdpSource\":\"libosdp-conformance 0.91-5\" }\n";

static void test_parse_canonical_spec_example(void)
{
    osdpcap_record_t r;
    TEST_ASSERT_EQUAL(OSDPCAP_OK, osdpcap_parse_line(EXAMPLE_RECORD, &r));
    TEST_ASSERT_EQUAL_UINT64(1580342115ULL, r.time_sec);
    TEST_ASSERT_EQUAL_UINT64(984691851ULL,  r.time_nano);
    TEST_ASSERT_EQUAL(OSDPCAP_IO_TRACE, r.io);
    TEST_ASSERT_EQUAL_size_t(10, r.data_len);

    static const uint8_t expected[] = {
        0xFF, 0xFF, 0x53, 0x80, 0x08, 0x00, 0x01, 0x4B, 0x01, 0xD8
    };
    TEST_ASSERT_EQUAL_MEMORY(expected, r.data, sizeof(expected));
    TEST_ASSERT_EQUAL_STRING("1", r.version);
    TEST_ASSERT_EQUAL_STRING("libosdp-conformance 0.91-5", r.source);
}

static void test_parse_empty_line_returns_skip_signal(void)
{
    osdpcap_record_t r;
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_EMPTY_LINE, osdpcap_parse_line("", &r));
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_EMPTY_LINE, osdpcap_parse_line("\n", &r));
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_EMPTY_LINE,
                      osdpcap_parse_line("   \t  \r\n", &r));
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_EMPTY_LINE,
                      osdpcap_parse_line("# this is a comment\n", &r));
}

static void test_parse_rejects_null_args(void)
{
    osdpcap_record_t r;
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_INVALID_ARG,
                      osdpcap_parse_line(NULL, &r));
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_INVALID_ARG,
                      osdpcap_parse_line("{\"data\":\"00\"}", NULL));
}

static void test_parse_missing_data_field(void)
{
    osdpcap_record_t r;
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_MISSING_DATA,
                      osdpcap_parse_line("{\"io\":\"trace\"}\n", &r));
}

static void test_parse_handles_io_input_and_output(void)
{
    osdpcap_record_t r;
    TEST_ASSERT_EQUAL(OSDPCAP_OK,
                      osdpcap_parse_line(
                          "{\"io\":\"input\",\"data\":\"53\"}\n", &r));
    TEST_ASSERT_EQUAL(OSDPCAP_IO_INPUT, r.io);

    TEST_ASSERT_EQUAL(OSDPCAP_OK,
                      osdpcap_parse_line(
                          "{\"io\":\"output\",\"data\":\"53\"}\n", &r));
    TEST_ASSERT_EQUAL(OSDPCAP_IO_OUTPUT, r.io);

    TEST_ASSERT_EQUAL(OSDPCAP_OK,
                      osdpcap_parse_line(
                          "{\"io\":\"weird\",\"data\":\"53\"}\n", &r));
    TEST_ASSERT_EQUAL(OSDPCAP_IO_UNKNOWN, r.io);
}

static void test_parse_accepts_zero_byte_data(void)
{
    osdpcap_record_t r;
    TEST_ASSERT_EQUAL(OSDPCAP_OK,
                      osdpcap_parse_line(
                          "{\"data\":\"\",\"io\":\"trace\"}\n", &r));
    TEST_ASSERT_EQUAL_size_t(0, r.data_len);
}

static void test_parse_handles_uppercase_and_lowercase_hex(void)
{
    osdpcap_record_t r;
    TEST_ASSERT_EQUAL(OSDPCAP_OK,
                      osdpcap_parse_line(
                          "{\"data\":\"DeAdBeEf\"}\n", &r));
    TEST_ASSERT_EQUAL_size_t(4, r.data_len);
    TEST_ASSERT_EQUAL_HEX8(0xDE, r.data[0]);
    TEST_ASSERT_EQUAL_HEX8(0xAD, r.data[1]);
    TEST_ASSERT_EQUAL_HEX8(0xBE, r.data[2]);
    TEST_ASSERT_EQUAL_HEX8(0xEF, r.data[3]);
}

static void test_parse_tolerates_arbitrary_whitespace_in_data(void)
{
    osdpcap_record_t r;
    TEST_ASSERT_EQUAL(OSDPCAP_OK,
                      osdpcap_parse_line(
                          "{\"data\":\"   53   80   60   \"}\n", &r));
    TEST_ASSERT_EQUAL_size_t(3, r.data_len);
    TEST_ASSERT_EQUAL_HEX8(0x53, r.data[0]);
    TEST_ASSERT_EQUAL_HEX8(0x80, r.data[1]);
    TEST_ASSERT_EQUAL_HEX8(0x60, r.data[2]);
}

static void test_parse_rejects_odd_hex_digits(void)
{
    osdpcap_record_t r;
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_BAD_HEX,
                      osdpcap_parse_line("{\"data\":\"5\"}\n", &r));
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_BAD_HEX,
                      osdpcap_parse_line("{\"data\":\"ZZ\"}\n", &r));
    TEST_ASSERT_EQUAL(OSDPCAP_ERR_BAD_HEX,
                      osdpcap_parse_line("{\"data\":\"5 3 8\"}\n", &r));
}

static void test_parse_field_order_is_irrelevant(void)
{
    osdpcap_record_t r;
    static const char line[] =
        "{\"data\":\"53\",\"timeSec\":\"42\",\"io\":\"trace\","
        "\"timeNano\":\"7\",\"osdpSource\":\"reorder-test\","
        "\"osdpTraceVersion\":\"1\"}\n";
    TEST_ASSERT_EQUAL(OSDPCAP_OK, osdpcap_parse_line(line, &r));
    TEST_ASSERT_EQUAL_UINT64(42, r.time_sec);
    TEST_ASSERT_EQUAL_UINT64(7,  r.time_nano);
    TEST_ASSERT_EQUAL(OSDPCAP_IO_TRACE, r.io);
    TEST_ASSERT_EQUAL_STRING("1", r.version);
    TEST_ASSERT_EQUAL_STRING("reorder-test", r.source);
}

static void test_parse_accepts_bare_numeric_time_fields(void)
{
    /* The spec example uses quoted strings for timeSec/timeNano, but
     * generic JSON producers may emit bare integers — be tolerant. */
    osdpcap_record_t r;
    static const char line[] =
        "{\"timeSec\":1580342115,\"timeNano\":984691851,"
        "\"io\":\"trace\",\"data\":\"53\"}\n";
    TEST_ASSERT_EQUAL(OSDPCAP_OK, osdpcap_parse_line(line, &r));
    TEST_ASSERT_EQUAL_UINT64(1580342115ULL, r.time_sec);
    TEST_ASSERT_EQUAL_UINT64(984691851ULL,  r.time_nano);
}

static void test_status_strings_are_non_null(void)
{
    static const osdpcap_status_t codes[] = {
        OSDPCAP_OK, OSDPCAP_ERR_INVALID_ARG, OSDPCAP_ERR_EMPTY_LINE,
        OSDPCAP_ERR_PARSE, OSDPCAP_ERR_MISSING_DATA, OSDPCAP_ERR_BAD_HEX,
        OSDPCAP_ERR_DATA_TOO_LARGE
    };
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
        const char *s = osdpcap_status_str(codes[i]);
        TEST_ASSERT_NOT_NULL(s);
        TEST_ASSERT_TRUE(strlen(s) > 0);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_parse_canonical_spec_example);
    RUN_TEST(test_parse_empty_line_returns_skip_signal);
    RUN_TEST(test_parse_rejects_null_args);
    RUN_TEST(test_parse_missing_data_field);
    RUN_TEST(test_parse_handles_io_input_and_output);
    RUN_TEST(test_parse_accepts_zero_byte_data);
    RUN_TEST(test_parse_handles_uppercase_and_lowercase_hex);
    RUN_TEST(test_parse_tolerates_arbitrary_whitespace_in_data);
    RUN_TEST(test_parse_rejects_odd_hex_digits);
    RUN_TEST(test_parse_field_order_is_irrelevant);
    RUN_TEST(test_parse_accepts_bare_numeric_time_fields);
    RUN_TEST(test_status_strings_are_non_null);
    return UNITY_END();
}
