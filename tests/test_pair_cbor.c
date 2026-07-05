// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Phase 1 tests for the canonical-CBOR codec used by OSDP-SC2 pairing
 * (C509 certificates + the pairing message bodies). No crypto involved. */

#include "osdp/osdp_cbor.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ========================================================================
 * Canonical integer encoding (RFC 8949 shortest-form heads)
 * ====================================================================== */

static void expect_uint_encoding(uint64_t v, const uint8_t *expect, size_t n)
{
    uint8_t buf[16];
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, buf, sizeof(buf));
    osdp_cbor_write_uint(&w, v);
    size_t len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_cbor_writer_finish(&w, &len));
    TEST_ASSERT_EQUAL_size_t(n, len);
    TEST_ASSERT_EQUAL_MEMORY(expect, buf, n);

    /* Round-trips back to the same value and consumes every byte. */
    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, buf, len);
    uint64_t got = 0;
    TEST_ASSERT_TRUE(osdp_cbor_read_uint(&r, &got));
    TEST_ASSERT_EQUAL_UINT64(v, got);
    TEST_ASSERT_TRUE(osdp_cbor_reader_done(&r));
}

static void test_uint_canonical_boundaries(void)
{
    static const uint8_t e0[]    = { 0x00 };
    static const uint8_t e23[]   = { 0x17 };
    static const uint8_t e24[]   = { 0x18, 0x18 };
    static const uint8_t e255[]  = { 0x18, 0xFF };
    static const uint8_t e256[]  = { 0x19, 0x01, 0x00 };
    static const uint8_t e65535[]= { 0x19, 0xFF, 0xFF };
    static const uint8_t e65536[]= { 0x1A, 0x00, 0x01, 0x00, 0x00 };
    static const uint8_t ebig[]  = { 0x1B, 0x00, 0x00, 0x00, 0x01,
                                     0x00, 0x00, 0x00, 0x00 };
    expect_uint_encoding(0, e0, sizeof(e0));
    expect_uint_encoding(23, e23, sizeof(e23));
    expect_uint_encoding(24, e24, sizeof(e24));
    expect_uint_encoding(255, e255, sizeof(e255));
    expect_uint_encoding(256, e256, sizeof(e256));
    expect_uint_encoding(65535, e65535, sizeof(e65535));
    expect_uint_encoding(65536, e65536, sizeof(e65536));
    expect_uint_encoding(0x100000000ULL, ebig, sizeof(ebig));
}

/* ========================================================================
 * String encoding + round trip
 * ====================================================================== */

static void test_bstr_round_trip(void)
{
    static const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t buf[16];
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, buf, sizeof(buf));
    osdp_cbor_write_bstr(&w, payload, sizeof(payload));
    size_t len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_cbor_writer_finish(&w, &len));
    /* 0x44 = bstr of length 4, then the bytes. */
    TEST_ASSERT_EQUAL_HEX8(0x44, buf[0]);
    TEST_ASSERT_EQUAL_size_t(5, len);

    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, buf, len);
    const uint8_t *data = NULL;
    size_t n = 0;
    TEST_ASSERT_TRUE(osdp_cbor_read_bstr(&r, &data, &n));
    TEST_ASSERT_EQUAL_size_t(sizeof(payload), n);
    TEST_ASSERT_EQUAL_MEMORY(payload, data, n);
    /* Zero-copy: the slice points into the source buffer. */
    TEST_ASSERT_EQUAL_PTR(&buf[1], data);
    TEST_ASSERT_TRUE(osdp_cbor_reader_done(&r));
}

static void test_tstr_round_trip(void)
{
    static const char text[] = "OSDP-DEMO-CA";
    const size_t tlen = strlen(text);
    uint8_t buf[32];
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, buf, sizeof(buf));
    osdp_cbor_write_tstr(&w, text, tlen);
    size_t len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_cbor_writer_finish(&w, &len));

    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, buf, len);
    const char *s = NULL;
    size_t n = 0;
    TEST_ASSERT_TRUE(osdp_cbor_read_tstr(&r, &s, &n));
    TEST_ASSERT_EQUAL_size_t(tlen, n);
    TEST_ASSERT_EQUAL_MEMORY(text, s, n);
    TEST_ASSERT_TRUE(osdp_cbor_reader_done(&r));
}

static void test_empty_bstr(void)
{
    uint8_t buf[8];
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, buf, sizeof(buf));
    osdp_cbor_write_bstr(&w, NULL, 0);
    size_t len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_cbor_writer_finish(&w, &len));
    TEST_ASSERT_EQUAL_size_t(1, len);
    TEST_ASSERT_EQUAL_HEX8(0x40, buf[0]); /* bstr, length 0 */

    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, buf, len);
    const uint8_t *data = (const uint8_t *)0x1;
    size_t n = 99;
    TEST_ASSERT_TRUE(osdp_cbor_read_bstr(&r, &data, &n));
    TEST_ASSERT_EQUAL_size_t(0, n);
    TEST_ASSERT_TRUE(osdp_cbor_reader_done(&r));
}

/* ========================================================================
 * Composite structure — a C509-TBS-shaped nested array
 * ====================================================================== */

static void test_composite_nested_array(void)
{
    /* Model: [ version:uint, serial:bstr, issuer:tstr, [nb:uint, na:uint] ] */
    static const uint8_t serial[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    static const char issuer[] = "self";

    uint8_t buf[64];
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, buf, sizeof(buf));
    osdp_cbor_write_array_header(&w, 4);
    osdp_cbor_write_uint(&w, 1);
    osdp_cbor_write_bstr(&w, serial, sizeof(serial));
    osdp_cbor_write_tstr(&w, issuer, strlen(issuer));
    osdp_cbor_write_array_header(&w, 2);
    osdp_cbor_write_uint(&w, 1700000000ULL);
    osdp_cbor_write_uint(&w, 2000000000ULL);
    size_t len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_cbor_writer_finish(&w, &len));

    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, buf, len);
    size_t outer = 0, inner = 0;
    uint64_t version = 0, nb = 0, na = 0;
    const uint8_t *ser = NULL;
    size_t ser_n = 0;
    const char *iss = NULL;
    size_t iss_n = 0;

    TEST_ASSERT_TRUE(osdp_cbor_read_array_header(&r, &outer));
    TEST_ASSERT_EQUAL_size_t(4, outer);
    TEST_ASSERT_TRUE(osdp_cbor_read_uint(&r, &version));
    TEST_ASSERT_EQUAL_UINT64(1, version);
    TEST_ASSERT_TRUE(osdp_cbor_read_bstr(&r, &ser, &ser_n));
    TEST_ASSERT_EQUAL_MEMORY(serial, ser, sizeof(serial));
    TEST_ASSERT_TRUE(osdp_cbor_read_tstr(&r, &iss, &iss_n));
    TEST_ASSERT_EQUAL_MEMORY(issuer, iss, iss_n);
    TEST_ASSERT_TRUE(osdp_cbor_read_array_header(&r, &inner));
    TEST_ASSERT_EQUAL_size_t(2, inner);
    TEST_ASSERT_TRUE(osdp_cbor_read_uint(&r, &nb));
    TEST_ASSERT_TRUE(osdp_cbor_read_uint(&r, &na));
    TEST_ASSERT_EQUAL_UINT64(1700000000ULL, nb);
    TEST_ASSERT_EQUAL_UINT64(2000000000ULL, na);
    TEST_ASSERT_TRUE(osdp_cbor_reader_done(&r));
}

/* ========================================================================
 * Reader negatives
 * ====================================================================== */

static void test_reader_rejects_type_mismatch(void)
{
    /* A uint where a bstr is expected. */
    static const uint8_t wire[] = { 0x01 };
    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, wire, sizeof(wire));
    const uint8_t *data = NULL;
    size_t n = 0;
    TEST_ASSERT_FALSE(osdp_cbor_read_bstr(&r, &data, &n));
    TEST_ASSERT_FALSE(osdp_cbor_reader_done(&r));
}

static void test_reader_rejects_truncated_head(void)
{
    /* 0x19 announces a 2-byte argument but only one follows. */
    static const uint8_t wire[] = { 0x19, 0x01 };
    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, wire, sizeof(wire));
    uint64_t v = 0;
    TEST_ASSERT_FALSE(osdp_cbor_read_uint(&r, &v));
}

static void test_reader_rejects_truncated_string(void)
{
    /* bstr length 4 but only 2 bytes present. */
    static const uint8_t wire[] = { 0x44, 0xAA, 0xBB };
    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, wire, sizeof(wire));
    const uint8_t *data = NULL;
    size_t n = 0;
    TEST_ASSERT_FALSE(osdp_cbor_read_bstr(&r, &data, &n));
}

static void test_reader_rejects_indefinite_length(void)
{
    /* 0x5F = indefinite-length bstr — unsupported. */
    static const uint8_t wire[] = { 0x5F, 0x40, 0xFF };
    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, wire, sizeof(wire));
    const uint8_t *data = NULL;
    size_t n = 0;
    TEST_ASSERT_FALSE(osdp_cbor_read_bstr(&r, &data, &n));
}

static void test_reader_rejects_reserved_ai(void)
{
    /* Additional info 28 (0x1C) is reserved. */
    static const uint8_t wire[] = { 0x1C };
    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, wire, sizeof(wire));
    uint64_t v = 0;
    TEST_ASSERT_FALSE(osdp_cbor_read_uint(&r, &v));
}

static void test_reader_done_false_with_trailing_bytes(void)
{
    static const uint8_t wire[] = { 0x01, 0x02 };
    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, wire, sizeof(wire));
    uint64_t v = 0;
    TEST_ASSERT_TRUE(osdp_cbor_read_uint(&r, &v));
    /* One item read, one byte left over. */
    TEST_ASSERT_FALSE(osdp_cbor_reader_done(&r));
}

/* ========================================================================
 * Writer overflow
 * ====================================================================== */

static void test_writer_overflow_is_sticky(void)
{
    static const uint8_t payload[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t buf[4]; /* too small for a 9-byte bstr item */
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, buf, sizeof(buf));
    osdp_cbor_write_bstr(&w, payload, sizeof(payload));
    size_t len = 99;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_cbor_writer_finish(&w, &len));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_uint_canonical_boundaries);
    RUN_TEST(test_bstr_round_trip);
    RUN_TEST(test_tstr_round_trip);
    RUN_TEST(test_empty_bstr);
    RUN_TEST(test_composite_nested_array);
    RUN_TEST(test_reader_rejects_type_mismatch);
    RUN_TEST(test_reader_rejects_truncated_head);
    RUN_TEST(test_reader_rejects_truncated_string);
    RUN_TEST(test_reader_rejects_indefinite_length);
    RUN_TEST(test_reader_rejects_reserved_ai);
    RUN_TEST(test_reader_done_false_with_trailing_bytes);
    RUN_TEST(test_writer_overflow_is_sticky);
    return UNITY_END();
}
