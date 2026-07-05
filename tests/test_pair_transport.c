// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Phase 0 transport tests for OSDP-SC2 asymmetric device pairing:
 * the osdp_PAIR / osdp_PAIRR fragment carrier codec and the multipart
 * reassembly / fragmentation helpers. */

#include "osdp/osdp_pair.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ========================================================================
 * Fragment carrier codec
 * ====================================================================== */

static void test_fragment_round_trip(void)
{
    static const uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x11 };
    osdp_pair_fragment_t in = {
        .total_size = 40,
        .offset     = 8,
        .data       = data,
        .frag_len   = sizeof(data),
    };

    uint8_t buf[OSDP_PAIR_FRAG_HEADER_BYTES + sizeof(data)];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pair_fragment_build(&in, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(sizeof(buf), n);

    /* Header is three little-endian u16s. */
    TEST_ASSERT_EQUAL_HEX8(40, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[1]);
    TEST_ASSERT_EQUAL_HEX8(8, buf[2]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[3]);
    TEST_ASSERT_EQUAL_HEX8(sizeof(data), buf[4]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[5]);
    TEST_ASSERT_EQUAL_MEMORY(data, &buf[6], sizeof(data));

    osdp_pair_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pair_fragment_decode(buf, n, &got));
    TEST_ASSERT_EQUAL_UINT16(in.total_size, got.total_size);
    TEST_ASSERT_EQUAL_UINT16(in.offset, got.offset);
    TEST_ASSERT_EQUAL_size_t(in.frag_len, got.frag_len);
    TEST_ASSERT_NOT_NULL(got.data);
    TEST_ASSERT_EQUAL_MEMORY(data, got.data, sizeof(data));
}

static void test_fragment_round_trip_empty(void)
{
    /* A header-only fragment (frag_len 0) is well-formed as long as it does
     * not claim data past total_size. */
    osdp_pair_fragment_t in = {
        .total_size = 16, .offset = 16, .data = NULL, .frag_len = 0,
    };
    uint8_t buf[OSDP_PAIR_FRAG_HEADER_BYTES];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pair_fragment_build(&in, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(OSDP_PAIR_FRAG_HEADER_BYTES, n);

    osdp_pair_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_fragment_decode(buf, n, &got));
    TEST_ASSERT_EQUAL_size_t(0, got.frag_len);
    TEST_ASSERT_NULL(got.data);
}

static void test_fragment_decode_rejects_short_header(void)
{
    static const uint8_t five[] = { 0, 0, 0, 0, 0 };
    osdp_pair_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pair_fragment_decode(five, sizeof(five), &got));
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pair_fragment_decode(NULL, 0, &got));
}

static void test_fragment_decode_rejects_size_mismatch(void)
{
    /* fragmentSize field says 3 but only 2 data bytes follow. */
    static const uint8_t wire[] = {
        10, 0,  /* total_size = 10 */
        0, 0,   /* offset = 0      */
        3, 0,   /* fragmentSize = 3 */
        0xAA, 0xBB,
    };
    osdp_pair_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pair_fragment_decode(wire, sizeof(wire), &got));
}

static void test_fragment_decode_rejects_overrun(void)
{
    /* offset 8 + fragmentSize 4 = 12 > total_size 10. */
    static const uint8_t wire[] = {
        10, 0,  /* total_size = 10 */
        8, 0,   /* offset = 8      */
        4, 0,   /* fragmentSize = 4 */
        1, 2, 3, 4,
    };
    osdp_pair_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pair_fragment_decode(wire, sizeof(wire), &got));
}

static void test_fragment_build_rejects_overrun(void)
{
    static const uint8_t data[] = { 1, 2, 3, 4 };
    osdp_pair_fragment_t in = {
        .total_size = 5, .offset = 4, .data = data, .frag_len = 4,
    };
    uint8_t buf[32];
    size_t n = 99;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pair_fragment_build(&in, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(0, n);
}

static void test_fragment_build_rejects_null_data(void)
{
    osdp_pair_fragment_t in = {
        .total_size = 8, .offset = 0, .data = NULL, .frag_len = 4,
    };
    uint8_t buf[32];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pair_fragment_build(&in, buf, sizeof(buf), &n));
}

static void test_fragment_build_rejects_buffer_too_small(void)
{
    static const uint8_t data[] = { 1, 2, 3, 4 };
    osdp_pair_fragment_t in = {
        .total_size = 4, .offset = 0, .data = data, .frag_len = 4,
    };
    uint8_t buf[OSDP_PAIR_FRAG_HEADER_BYTES + 3]; /* one short */
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pair_fragment_build(&in, buf, sizeof(buf), &n));
}

/* ========================================================================
 * Multipart reassembly + fragmentation
 * ====================================================================== */

/* Fragment a message, push every fragment back through the codec + the
 * reassembler, and require the reconstructed bytes to be identical. This is
 * the full Phase 0 transport round trip. */
static void test_multipart_round_trip(void)
{
    uint8_t msg[300];
    for (size_t i = 0; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i * 7u + 1u);
    }

    uint8_t reasm_buf[512];
    osdp_pair_reasm_t r;
    osdp_pair_reasm_init(&r, reasm_buf, sizeof(reasm_buf));

    osdp_pair_frag_iter_t it;
    osdp_pair_frag_iter_init(&it, msg, sizeof(msg), 128);

    osdp_pair_fragment_t frag;
    bool complete = false;
    int count = 0;
    while (osdp_pair_frag_iter_next(&it, &frag)) {
        uint8_t wire[OSDP_PAIR_FRAG_HEADER_BYTES + 128];
        size_t n = 0;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_pair_fragment_build(&frag, wire, sizeof(wire), &n));

        osdp_pair_fragment_t dec;
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_fragment_decode(wire, n, &dec));

        /* Not complete until the final fragment lands. */
        TEST_ASSERT_FALSE(complete);
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_pair_reasm_push(&r, &dec, &complete));
        count++;
    }

    TEST_ASSERT_EQUAL_INT(3, count); /* 128 + 128 + 44 */
    TEST_ASSERT_TRUE(complete);
    TEST_ASSERT_EQUAL_UINT16(sizeof(msg), r.total);
    TEST_ASSERT_EQUAL_UINT16(sizeof(msg), r.received);
    TEST_ASSERT_EQUAL_MEMORY(msg, r.buf, sizeof(msg));
}

static void test_multipart_single_fragment(void)
{
    static const uint8_t msg[] = { 0x04, 0x00, 0x20 }; /* tiny Result-like */
    uint8_t reasm_buf[64];
    osdp_pair_reasm_t r;
    osdp_pair_reasm_init(&r, reasm_buf, sizeof(reasm_buf));

    osdp_pair_frag_iter_t it;
    osdp_pair_frag_iter_init(&it, msg, sizeof(msg), 128);

    osdp_pair_fragment_t frag;
    TEST_ASSERT_TRUE(osdp_pair_frag_iter_next(&it, &frag));
    TEST_ASSERT_EQUAL_UINT16(0, frag.offset);
    TEST_ASSERT_EQUAL_size_t(sizeof(msg), frag.frag_len);

    bool complete = false;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &frag, &complete));
    TEST_ASSERT_TRUE(complete);
    TEST_ASSERT_EQUAL_MEMORY(msg, r.buf, sizeof(msg));

    /* Iterator is exhausted after the single fragment. */
    TEST_ASSERT_FALSE(osdp_pair_frag_iter_next(&it, &frag));
}

static void test_multipart_iter_empty_message(void)
{
    osdp_pair_frag_iter_t it;
    osdp_pair_fragment_t frag;
    osdp_pair_frag_iter_init(&it, (const uint8_t *)"x", 0, 128);
    TEST_ASSERT_FALSE(osdp_pair_frag_iter_next(&it, &frag));
}

static void test_multipart_reasm_rejects_buffer_too_small(void)
{
    uint8_t small[4];
    osdp_pair_reasm_t r;
    osdp_pair_reasm_init(&r, small, sizeof(small));

    static const uint8_t data[] = { 1, 2 };
    osdp_pair_fragment_t frag = {
        .total_size = 10, .offset = 0, .data = data, .frag_len = 2,
    };
    bool complete = false;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pair_reasm_push(&r, &frag, &complete));
}

static void test_multipart_reasm_rejects_bad_total(void)
{
    uint8_t buf[64];
    osdp_pair_reasm_t r;
    osdp_pair_reasm_init(&r, buf, sizeof(buf));

    /* total_size 0 at offset 0 is meaningless. */
    osdp_pair_fragment_t zero = {
        .total_size = 0, .offset = 0, .data = NULL, .frag_len = 0,
    };
    bool complete = false;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pair_reasm_push(&r, &zero, &complete));

    /* total_size beyond the wire ceiling is rejected regardless of the
     * bound buffer. */
    static const uint8_t data[] = { 1 };
    osdp_pair_fragment_t huge = {
        .total_size = OSDP_PAIR_MSG_MAX + 1, .offset = 0,
        .data = data, .frag_len = 1,
    };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pair_reasm_push(&r, &huge, &complete));
}

static void test_multipart_reasm_rejects_gap(void)
{
    uint8_t buf[64];
    osdp_pair_reasm_t r;
    osdp_pair_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t d0[] = { 1, 2, 3, 4 };
    osdp_pair_fragment_t f0 = {
        .total_size = 20, .offset = 0, .data = d0, .frag_len = 4,
    };
    bool complete = false;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &f0, &complete));
    TEST_ASSERT_FALSE(complete);

    /* offset 8 leaves a hole after the 4 bytes received. */
    static const uint8_t d1[] = { 9, 9 };
    osdp_pair_fragment_t f1 = {
        .total_size = 20, .offset = 8, .data = d1, .frag_len = 2,
    };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pair_reasm_push(&r, &f1, &complete));
}

static void test_multipart_reasm_rejects_total_mismatch(void)
{
    uint8_t buf[64];
    osdp_pair_reasm_t r;
    osdp_pair_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t d0[] = { 1, 2, 3, 4 };
    osdp_pair_fragment_t f0 = {
        .total_size = 20, .offset = 0, .data = d0, .frag_len = 4,
    };
    bool complete = false;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &f0, &complete));

    /* Continuation claims a different whole-message length. */
    static const uint8_t d1[] = { 5, 6 };
    osdp_pair_fragment_t f1 = {
        .total_size = 24, .offset = 4, .data = d1, .frag_len = 2,
    };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pair_reasm_push(&r, &f1, &complete));
}

static void test_multipart_reasm_idempotent_retransmit(void)
{
    uint8_t buf[64];
    osdp_pair_reasm_t r;
    osdp_pair_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t a[] = { 0x10, 0x11, 0x12, 0x13 }; /* [0,4)  */
    static const uint8_t b[] = { 0x20, 0x21, 0x22, 0x23 }; /* [4,8)  */
    static const uint8_t c[] = { 0x30, 0x31 };             /* [8,10) */

    osdp_pair_fragment_t fa = { .total_size = 10, .offset = 0, .data = a, .frag_len = 4 };
    osdp_pair_fragment_t fb = { .total_size = 10, .offset = 4, .data = b, .frag_len = 4 };
    osdp_pair_fragment_t fc = { .total_size = 10, .offset = 8, .data = c, .frag_len = 2 };

    bool complete = false;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &fa, &complete));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &fb, &complete));
    TEST_ASSERT_FALSE(complete);
    TEST_ASSERT_EQUAL_UINT16(8, r.received);

    /* Retransmit the middle fragment: allowed, idempotent, no progress. */
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &fb, &complete));
    TEST_ASSERT_FALSE(complete);
    TEST_ASSERT_EQUAL_UINT16(8, r.received);

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &fc, &complete));
    TEST_ASSERT_TRUE(complete);

    static const uint8_t expect[] = {
        0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31,
    };
    TEST_ASSERT_EQUAL_MEMORY(expect, r.buf, sizeof(expect));
}

static void test_multipart_reasm_restart_on_offset_zero(void)
{
    uint8_t buf[64];
    osdp_pair_reasm_t r;
    osdp_pair_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t stale[] = { 0xAA, 0xAA, 0xAA, 0xAA };
    osdp_pair_fragment_t f0 = { .total_size = 20, .offset = 0, .data = stale, .frag_len = 4 };
    bool complete = false;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &f0, &complete));
    TEST_ASSERT_EQUAL_UINT16(4, r.received);

    /* A fresh offset-0 fragment abandons the in-progress message. */
    static const uint8_t fresh[] = { 0x01, 0x02, 0x03 };
    osdp_pair_fragment_t f1 = { .total_size = 3, .offset = 0, .data = fresh, .frag_len = 3 };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &f1, &complete));
    TEST_ASSERT_TRUE(complete);
    TEST_ASSERT_EQUAL_UINT16(3, r.total);
    TEST_ASSERT_EQUAL_MEMORY(fresh, r.buf, sizeof(fresh));
}

static void test_multipart_reasm_rejects_null_args(void)
{
    osdp_pair_reasm_t r;
    uint8_t buf[8];
    osdp_pair_reasm_init(&r, buf, sizeof(buf));
    osdp_pair_fragment_t frag = { .total_size = 4, .offset = 0, .data = buf, .frag_len = 4 };
    bool complete = false;

    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pair_reasm_push(NULL, &frag, &complete));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pair_reasm_push(&r, NULL, &complete));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pair_reasm_push(&r, &frag, NULL));
}

int main(void)
{
    UNITY_BEGIN();
    /* Fragment carrier */
    RUN_TEST(test_fragment_round_trip);
    RUN_TEST(test_fragment_round_trip_empty);
    RUN_TEST(test_fragment_decode_rejects_short_header);
    RUN_TEST(test_fragment_decode_rejects_size_mismatch);
    RUN_TEST(test_fragment_decode_rejects_overrun);
    RUN_TEST(test_fragment_build_rejects_overrun);
    RUN_TEST(test_fragment_build_rejects_null_data);
    RUN_TEST(test_fragment_build_rejects_buffer_too_small);
    /* Multipart */
    RUN_TEST(test_multipart_round_trip);
    RUN_TEST(test_multipart_single_fragment);
    RUN_TEST(test_multipart_iter_empty_message);
    RUN_TEST(test_multipart_reasm_rejects_buffer_too_small);
    RUN_TEST(test_multipart_reasm_rejects_bad_total);
    RUN_TEST(test_multipart_reasm_rejects_gap);
    RUN_TEST(test_multipart_reasm_rejects_total_mismatch);
    RUN_TEST(test_multipart_reasm_idempotent_retransmit);
    RUN_TEST(test_multipart_reasm_restart_on_offset_zero);
    RUN_TEST(test_multipart_reasm_rejects_null_args);
    return UNITY_END();
}
