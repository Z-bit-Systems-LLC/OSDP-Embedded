// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_frame.h"
#include "osdp/osdp_stream.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Helpers -------------------------------------------------------------*/

static size_t make_poll_frame(uint8_t *buf, size_t cap, uint8_t addr,
                              osdp_integrity_t integ)
{
    osdp_frame_t f = {0};
    f.address = addr;
    f.integrity = integ;
    f.code = 0x60;
    size_t w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, cap, &w));
    return w;
}

/* ---- Tests ---------------------------------------------------------------*/

static void test_stream_starts_empty(void)
{
    osdp_stream_t s;
    osdp_stream_init(&s);
    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_TRUNCATED, osdp_stream_next(&s, &f));
}

static void test_stream_decodes_full_frame_in_one_feed(void)
{
    osdp_stream_t s;
    osdp_stream_init(&s);

    uint8_t bytes[16];
    const size_t n = make_poll_frame(bytes, sizeof(bytes), 5,
                                     OSDP_INTEGRITY_CRC);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_feed(&s, bytes, n));

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_next(&s, &f));
    TEST_ASSERT_EQUAL_HEX8(5, f.address);
    TEST_ASSERT_EQUAL_HEX8(0x60, f.code);

    /* No more frames. */
    TEST_ASSERT_EQUAL(OSDP_ERR_TRUNCATED, osdp_stream_next(&s, &f));
}

static void test_stream_decodes_frame_fed_byte_by_byte(void)
{
    osdp_stream_t s;
    osdp_stream_init(&s);

    uint8_t bytes[16];
    const size_t n = make_poll_frame(bytes, sizeof(bytes), 0x12,
                                     OSDP_INTEGRITY_CRC);

    osdp_frame_t f;
    /* Feeding incomplete data should return TRUNCATED at every step
     * until the final byte arrives. */
    for (size_t i = 0; i < n - 1; i++) {
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_feed(&s, &bytes[i], 1));
        TEST_ASSERT_EQUAL(OSDP_ERR_TRUNCATED, osdp_stream_next(&s, &f));
    }
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_feed(&s, &bytes[n - 1], 1));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_next(&s, &f));
    TEST_ASSERT_EQUAL_HEX8(0x12, f.address);
}

static void test_stream_three_frames_one_feed(void)
{
    osdp_stream_t s;
    osdp_stream_init(&s);

    uint8_t a[16], b[16], c[16];
    const size_t na = make_poll_frame(a, sizeof(a), 1, OSDP_INTEGRITY_CRC);
    const size_t nb = make_poll_frame(b, sizeof(b), 2, OSDP_INTEGRITY_CHECKSUM);
    const size_t nc = make_poll_frame(c, sizeof(c), 3, OSDP_INTEGRITY_CRC);

    uint8_t combined[64];
    (void)memcpy(combined,                a, na);
    (void)memcpy(combined + na,           b, nb);
    (void)memcpy(combined + na + nb,      c, nc);
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_stream_feed(&s, combined, na + nb + nc));

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_next(&s, &f));
    TEST_ASSERT_EQUAL_HEX8(1, f.address);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_next(&s, &f));
    TEST_ASSERT_EQUAL_HEX8(2, f.address);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_next(&s, &f));
    TEST_ASSERT_EQUAL_HEX8(3, f.address);
    TEST_ASSERT_EQUAL(OSDP_ERR_TRUNCATED, osdp_stream_next(&s, &f));
}

static void test_stream_resyncs_past_garbage_before_frame(void)
{
    osdp_stream_t s;
    osdp_stream_init(&s);

    uint8_t frame[16];
    const size_t n = make_poll_frame(frame, sizeof(frame), 7,
                                     OSDP_INTEGRITY_CRC);

    static const uint8_t garbage[] = { 0xFF, 0xAA, 0x12, 0x34, 0x52, 0x99 };
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_stream_feed(&s, garbage, sizeof(garbage)));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_feed(&s, frame, n));

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_next(&s, &f));
    TEST_ASSERT_EQUAL_HEX8(7, f.address);
}

static void test_stream_reports_bad_crc_then_resyncs(void)
{
    osdp_stream_t s;
    osdp_stream_init(&s);

    uint8_t bad[16];
    const size_t bn = make_poll_frame(bad, sizeof(bad), 1, OSDP_INTEGRITY_CRC);
    bad[bn - 1] ^= 0xFF;   /* corrupt CRC MSB */

    uint8_t good[16];
    const size_t gn = make_poll_frame(good, sizeof(good), 9,
                                      OSDP_INTEGRITY_CRC);

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_feed(&s, bad,  bn));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_feed(&s, good, gn));

    osdp_frame_t f;
    /* First call returns the CRC failure for the bad frame. */
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CRC, osdp_stream_next(&s, &f));
    /* Stream then drains until the next valid frame is found. We may
     * have to call _next a few times if the resync drops one byte at
     * a time before re-locking onto the next SOM. */
    for (int attempts = 0; attempts < 16; attempts++) {
        const osdp_status_t r = osdp_stream_next(&s, &f);
        if (r == OSDP_OK) {
            TEST_ASSERT_EQUAL_HEX8(9, f.address);
            return;
        }
        if (r == OSDP_ERR_TRUNCATED) {
            break;
        }
        /* Other resync errors are tolerated; keep looking. */
    }
    TEST_FAIL_MESSAGE("stream did not recover the second frame");
}

static void test_stream_reports_bad_length_field_and_resyncs(void)
{
    osdp_stream_t s;
    osdp_stream_init(&s);

    /* Hand-craft 5 bytes claiming a frame length of 6 (below the
     * minimum). Must be at least HEADER_LEN bytes for stream_next to
     * even read the length field. */
    static const uint8_t bogus[] = { 0x53, 0x00, 0x06, 0x00, 0x00 };

    uint8_t good[16];
    const size_t gn = make_poll_frame(good, sizeof(good), 4,
                                      OSDP_INTEGRITY_CRC);

    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_stream_feed(&s, bogus, sizeof(bogus)));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_feed(&s, good, gn));

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_LENGTH, osdp_stream_next(&s, &f));
    /* Drain until the next good frame surfaces. */
    for (int attempts = 0; attempts < 16; attempts++) {
        const osdp_status_t r = osdp_stream_next(&s, &f);
        if (r == OSDP_OK) {
            TEST_ASSERT_EQUAL_HEX8(4, f.address);
            return;
        }
        if (r == OSDP_ERR_TRUNCATED) {
            break;
        }
    }
    TEST_FAIL_MESSAGE("stream did not recover after bad length");
}

static void test_stream_frame_payload_pointer_remains_valid_until_next_call(void)
{
    /* The slice pointers returned by stream_next must be usable for as
     * long as the caller refrains from another stream_next/_feed call.
     * Verify by reading the payload bytes BEFORE calling next/feed
     * again. */
    osdp_stream_t s;
    osdp_stream_init(&s);

    osdp_frame_t built = {0};
    static const uint8_t payload[] = { 0xAA, 0xBB, 0xCC };
    built.integrity = OSDP_INTEGRITY_CRC;
    built.code = 0x69;  /* osdp_LED */
    built.payload = payload;
    built.payload_len = sizeof(payload);

    uint8_t bytes[32];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_build(&built, bytes, sizeof(bytes), &n));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_feed(&s, bytes, n));

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_next(&s, &f));
    TEST_ASSERT_EQUAL_size_t(3, f.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, f.payload, sizeof(payload));
}

static void test_stream_reset_drops_buffered_data(void)
{
    osdp_stream_t s;
    osdp_stream_init(&s);

    uint8_t frame[16];
    const size_t n = make_poll_frame(frame, sizeof(frame), 1,
                                     OSDP_INTEGRITY_CRC);
    /* Feed half the frame, then reset; the second half should not
     * complete a frame. */
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_stream_feed(&s, frame, n / 2));
    osdp_stream_reset(&s);

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_TRUNCATED, osdp_stream_next(&s, &f));
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_stream_feed(&s, &frame[n / 2], n - n / 2));
    /* Without the first half, we have only a tail of garbage; resync
     * should not produce a valid frame. */
    const osdp_status_t r = osdp_stream_next(&s, &f);
    TEST_ASSERT_TRUE(r == OSDP_ERR_TRUNCATED ||
                     r == OSDP_ERR_BAD_LENGTH ||
                     r == OSDP_ERR_BAD_CRC ||
                     r == OSDP_ERR_BAD_CHECKSUM ||
                     r == OSDP_ERR_BAD_CTRL);
}

static void test_stream_rejects_null_args(void)
{
    osdp_stream_t s;
    osdp_stream_init(&s);
    uint8_t b = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_stream_feed(NULL, &b, 1));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_stream_feed(&s, NULL, 1));
    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_stream_next(NULL, &f));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_stream_next(&s, NULL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_stream_starts_empty);
    RUN_TEST(test_stream_decodes_full_frame_in_one_feed);
    RUN_TEST(test_stream_decodes_frame_fed_byte_by_byte);
    RUN_TEST(test_stream_three_frames_one_feed);
    RUN_TEST(test_stream_resyncs_past_garbage_before_frame);
    RUN_TEST(test_stream_reports_bad_crc_then_resyncs);
    RUN_TEST(test_stream_reports_bad_length_field_and_resyncs);
    RUN_TEST(test_stream_frame_payload_pointer_remains_valid_until_next_call);
    RUN_TEST(test_stream_reset_drops_buffered_data);
    RUN_TEST(test_stream_rejects_null_args);
    return UNITY_END();
}
