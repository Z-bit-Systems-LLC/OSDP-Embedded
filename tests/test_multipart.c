// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Multi-part message transport (spec 5.10): the Table 4 fragment codec, the
 * inbound reassembler, and the outbound fragmenter. */

#include "osdp/osdp_multipart.h"
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
    osdp_mp_fragment_t in = {
        .total_size = 40,
        .offset     = 8,
        .data       = data,
        .frag_len   = sizeof(data),
    };

    uint8_t buf[OSDP_MP_HEADER_BYTES + sizeof(data)];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_mp_fragment_build(&in, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(sizeof(buf), n);

    /* Header is three little-endian u16s. */
    TEST_ASSERT_EQUAL_HEX8(40, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[1]);
    TEST_ASSERT_EQUAL_HEX8(8, buf[2]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[3]);
    TEST_ASSERT_EQUAL_HEX8(sizeof(data), buf[4]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[5]);
    TEST_ASSERT_EQUAL_MEMORY(data, &buf[6], sizeof(data));

    osdp_mp_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_mp_fragment_decode(buf, n, &got));
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
    osdp_mp_fragment_t in = {
        .total_size = 16, .offset = 16, .data = NULL, .frag_len = 0,
    };
    uint8_t buf[OSDP_MP_HEADER_BYTES];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_mp_fragment_build(&in, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(OSDP_MP_HEADER_BYTES, n);

    osdp_mp_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_fragment_decode(buf, n, &got));
    TEST_ASSERT_EQUAL_size_t(0, got.frag_len);
    TEST_ASSERT_NULL(got.data);
}

static void test_fragment_decode_rejects_short_header(void)
{
    static const uint8_t five[] = { 0, 0, 0, 0, 0 };
    osdp_mp_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_mp_fragment_decode(five, sizeof(five), &got));
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_mp_fragment_decode(NULL, 0, &got));
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
    osdp_mp_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_mp_fragment_decode(wire, sizeof(wire), &got));
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
    osdp_mp_fragment_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_mp_fragment_decode(wire, sizeof(wire), &got));
}

static void test_fragment_build_rejects_overrun(void)
{
    static const uint8_t data[] = { 1, 2, 3, 4 };
    osdp_mp_fragment_t in = {
        .total_size = 5, .offset = 4, .data = data, .frag_len = 4,
    };
    uint8_t buf[32];
    size_t n = 99;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_mp_fragment_build(&in, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(0, n);
}

static void test_fragment_build_rejects_null_data(void)
{
    osdp_mp_fragment_t in = {
        .total_size = 8, .offset = 0, .data = NULL, .frag_len = 4,
    };
    uint8_t buf[32];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_mp_fragment_build(&in, buf, sizeof(buf), &n));
}

static void test_fragment_build_rejects_buffer_too_small(void)
{
    static const uint8_t data[] = { 1, 2, 3, 4 };
    osdp_mp_fragment_t in = {
        .total_size = 4, .offset = 0, .data = data, .frag_len = 4,
    };
    uint8_t buf[OSDP_MP_HEADER_BYTES + 3]; /* one short */
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_mp_fragment_build(&in, buf, sizeof(buf), &n));
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
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, reasm_buf, sizeof(reasm_buf));

    osdp_mp_frag_iter_t it;
    osdp_mp_frag_iter_init(&it, msg, sizeof(msg), 128);

    osdp_mp_fragment_t frag;
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    int count = 0;
    while (osdp_mp_frag_iter_next(&it, &frag)) {
        uint8_t wire[OSDP_MP_HEADER_BYTES + 128];
        size_t n = 0;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_mp_fragment_build(&frag, wire, sizeof(wire), &n));

        osdp_mp_fragment_t dec;
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_fragment_decode(wire, n, &dec));

        /* Not complete until the final fragment lands. */
        TEST_ASSERT_EQUAL(OSDP_MP_IN_PROGRESS, state);
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_mp_reasm_push(&r, &dec, &state));
        count++;
    }

    TEST_ASSERT_EQUAL_INT(3, count); /* 128 + 128 + 44 */
    TEST_ASSERT_EQUAL(OSDP_MP_COMPLETE, state);
    TEST_ASSERT_EQUAL_UINT16(sizeof(msg), r.total);
    TEST_ASSERT_EQUAL_UINT16(sizeof(msg), r.received);
    TEST_ASSERT_EQUAL_MEMORY(msg, r.buf, sizeof(msg));
}

static void test_multipart_single_fragment(void)
{
    static const uint8_t msg[] = { 0x04, 0x00, 0x20 }; /* tiny Result-like */
    uint8_t reasm_buf[64];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, reasm_buf, sizeof(reasm_buf));

    osdp_mp_frag_iter_t it;
    osdp_mp_frag_iter_init(&it, msg, sizeof(msg), 128);

    osdp_mp_fragment_t frag;
    TEST_ASSERT_TRUE(osdp_mp_frag_iter_next(&it, &frag));
    TEST_ASSERT_EQUAL_UINT16(0, frag.offset);
    TEST_ASSERT_EQUAL_size_t(sizeof(msg), frag.frag_len);

    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &frag, &state));
    TEST_ASSERT_EQUAL(OSDP_MP_COMPLETE, state);
    TEST_ASSERT_EQUAL_MEMORY(msg, r.buf, sizeof(msg));

    /* Iterator is exhausted after the single fragment. */
    TEST_ASSERT_FALSE(osdp_mp_frag_iter_next(&it, &frag));
}

static void test_multipart_iter_empty_message(void)
{
    osdp_mp_frag_iter_t it;
    osdp_mp_fragment_t frag;
    osdp_mp_frag_iter_init(&it, (const uint8_t *)"x", 0, 128);
    TEST_ASSERT_FALSE(osdp_mp_frag_iter_next(&it, &frag));
}

static void test_multipart_reasm_rejects_buffer_too_small(void)
{
    uint8_t small[4];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, small, sizeof(small));

    static const uint8_t data[] = { 1, 2 };
    osdp_mp_fragment_t frag = {
        .total_size = 10, .offset = 0, .data = data, .frag_len = 2,
    };
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_mp_reasm_push(&r, &frag, &state));
}

static void test_multipart_reasm_rejects_bad_total(void)
{
    uint8_t buf[64];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, buf, sizeof(buf));

    /* total_size 0 at offset 0 is meaningless. */
    osdp_mp_fragment_t zero = {
        .total_size = 0, .offset = 0, .data = NULL, .frag_len = 0,
    };
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_mp_reasm_push(&r, &zero, &state));

    /* A message larger than the bound buffer is refused rather than
     * truncated. The ceiling is the buffer, not a hard-coded constant: the
     * shared transport serves several message families with different size
     * limits, so a caller that wants a tighter bound binds a smaller buffer. */
    static const uint8_t data[] = { 1 };
    osdp_mp_fragment_t huge = {
        .total_size = (uint16_t)(sizeof(buf) + 1), .offset = 0,
        .data = data, .frag_len = 1,
    };
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_mp_reasm_push(&r, &huge, &state));
}

static void test_multipart_reasm_rejects_gap(void)
{
    uint8_t buf[64];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t d0[] = { 1, 2, 3, 4 };
    osdp_mp_fragment_t f0 = {
        .total_size = 20, .offset = 0, .data = d0, .frag_len = 4,
    };
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &f0, &state));
    TEST_ASSERT_EQUAL(OSDP_MP_IN_PROGRESS, state);

    /* offset 8 leaves a hole after the 4 bytes received. */
    static const uint8_t d1[] = { 9, 9 };
    osdp_mp_fragment_t f1 = {
        .total_size = 20, .offset = 8, .data = d1, .frag_len = 2,
    };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_mp_reasm_push(&r, &f1, &state));
}

static void test_multipart_reasm_rejects_total_mismatch(void)
{
    uint8_t buf[64];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t d0[] = { 1, 2, 3, 4 };
    osdp_mp_fragment_t f0 = {
        .total_size = 20, .offset = 0, .data = d0, .frag_len = 4,
    };
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &f0, &state));

    /* Continuation claims a different whole-message length. */
    static const uint8_t d1[] = { 5, 6 };
    osdp_mp_fragment_t f1 = {
        .total_size = 24, .offset = 4, .data = d1, .frag_len = 2,
    };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_mp_reasm_push(&r, &f1, &state));
}

static void test_multipart_reasm_idempotent_retransmit(void)
{
    uint8_t buf[64];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t a[] = { 0x10, 0x11, 0x12, 0x13 }; /* [0,4)  */
    static const uint8_t b[] = { 0x20, 0x21, 0x22, 0x23 }; /* [4,8)  */
    static const uint8_t c[] = { 0x30, 0x31 };             /* [8,10) */

    osdp_mp_fragment_t fa = { .total_size = 10, .offset = 0, .data = a, .frag_len = 4 };
    osdp_mp_fragment_t fb = { .total_size = 10, .offset = 4, .data = b, .frag_len = 4 };
    osdp_mp_fragment_t fc = { .total_size = 10, .offset = 8, .data = c, .frag_len = 2 };

    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &fa, &state));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &fb, &state));
    TEST_ASSERT_EQUAL(OSDP_MP_IN_PROGRESS, state);
    TEST_ASSERT_EQUAL_UINT16(8, r.received);

    /* Retransmit the middle fragment: allowed, idempotent, no progress. */
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &fb, &state));
    TEST_ASSERT_EQUAL(OSDP_MP_IN_PROGRESS, state);
    TEST_ASSERT_EQUAL_UINT16(8, r.received);

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &fc, &state));
    TEST_ASSERT_EQUAL(OSDP_MP_COMPLETE, state);

    static const uint8_t expect[] = {
        0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31,
    };
    TEST_ASSERT_EQUAL_MEMORY(expect, r.buf, sizeof(expect));
}

static void test_multipart_reasm_restart_on_offset_zero(void)
{
    uint8_t buf[64];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t stale[] = { 0xAA, 0xAA, 0xAA, 0xAA };
    osdp_mp_fragment_t f0 = { .total_size = 20, .offset = 0, .data = stale, .frag_len = 4 };
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &f0, &state));
    TEST_ASSERT_EQUAL_UINT16(4, r.received);

    /* A fresh offset-0 fragment abandons the in-progress message. */
    static const uint8_t fresh[] = { 0x01, 0x02, 0x03 };
    osdp_mp_fragment_t f1 = { .total_size = 3, .offset = 0, .data = fresh, .frag_len = 3 };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &f1, &state));
    TEST_ASSERT_EQUAL(OSDP_MP_COMPLETE, state);
    TEST_ASSERT_EQUAL_UINT16(3, r.total);
    TEST_ASSERT_EQUAL_MEMORY(fresh, r.buf, sizeof(fresh));
}

static void test_multipart_reasm_rejects_null_args(void)
{
    osdp_mp_reasm_t r;
    uint8_t buf[8];
    osdp_mp_reasm_init(&r, buf, sizeof(buf));
    osdp_mp_fragment_t frag = { .total_size = 4, .offset = 0, .data = buf, .frag_len = 4 };
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;

    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_mp_reasm_push(NULL, &frag, &state));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_mp_reasm_push(&r, NULL, &state));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_mp_reasm_push(&r, &frag, NULL));
}

/* ========================================================================
 * Spec 5.10.2 early termination
 *
 * "The transfer of a multi-part message may be terminated by the sender
 * early by setting MpOffset to equal or greater than MpSizeTotal and setting
 * MpFragmentSize to 0x00. Conversely, the receiving device shall recognize
 * this condition as an early termination of the multi-part transfer."
 *
 * The pairing version of this transport never implemented it — its message
 * sizes are known up front, so nothing abandoned a transfer mid-flight. The
 * credential messages that will use this transport are exactly the ones that
 * can.
 * ====================================================================== */

static void test_early_termination_marker_is_recognised(void)
{
    /* Offset exactly at the total. */
    const osdp_mp_fragment_t at_end = {
        .total_size = 100, .offset = 100, .data = NULL, .frag_len = 0,
    };
    TEST_ASSERT_TRUE(osdp_mp_is_early_termination(&at_end));

    /* Spec says "equal or greater", so past the end counts too. */
    const osdp_mp_fragment_t past_end = {
        .total_size = 100, .offset = 250, .data = NULL, .frag_len = 0,
    };
    TEST_ASSERT_TRUE(osdp_mp_is_early_termination(&past_end));
}

static void test_ordinary_fragments_are_not_terminations(void)
{
    static const uint8_t d[4] = { 1, 2, 3, 4 };

    /* A normal fragment. */
    const osdp_mp_fragment_t normal = {
        .total_size = 100, .offset = 0, .data = d, .frag_len = 4,
    };
    TEST_ASSERT_FALSE(osdp_mp_is_early_termination(&normal));

    /* Offset past the end but CARRYING data is malformed, not a
     * termination — both halves of the rule are required. */
    const osdp_mp_fragment_t past_with_data = {
        .total_size = 100, .offset = 200, .data = d, .frag_len = 4,
    };
    TEST_ASSERT_FALSE(osdp_mp_is_early_termination(&past_with_data));

    /* An all-zero header satisfies "offset >= total" read literally, but a
     * transfer declaring no bytes has nothing to terminate — and all-zeros
     * is what a truncated frame usually looks like, so it must stay an
     * error rather than becoming a silent ACK. */
    const osdp_mp_fragment_t all_zero = {
        .total_size = 0, .offset = 0, .data = NULL, .frag_len = 0,
    };
    TEST_ASSERT_FALSE(osdp_mp_is_early_termination(&all_zero));
}

/* The marker has to survive the codec: decode must NOT apply the
 * "fragment cannot extend past total_size" rule to it, since being at or
 * past the end is precisely what identifies it. */
static void test_termination_marker_round_trips_through_the_codec(void)
{
    osdp_mp_fragment_t out;
    osdp_mp_frag_terminate(&out, 500);
    TEST_ASSERT_EQUAL_UINT16(500, out.total_size);
    TEST_ASSERT_EQUAL_UINT16(500, out.offset);
    TEST_ASSERT_EQUAL_size_t(0, out.frag_len);

    uint8_t buf[16];
    size_t  written = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_mp_fragment_build(&out, buf, sizeof(buf), &written));
    TEST_ASSERT_EQUAL_size_t(OSDP_MP_HEADER_BYTES, written);

    osdp_mp_fragment_t back;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_fragment_decode(buf, written, &back));
    TEST_ASSERT_TRUE(osdp_mp_is_early_termination(&back));
    TEST_ASSERT_EQUAL_UINT16(500, back.total_size);
}

/* A fragment past the end that is NOT a termination must still be rejected
 * by decode — the exception must not have widened into a hole. */
static void test_decode_still_rejects_an_overrunning_fragment(void)
{
    /* total 10, offset 8, fragmentSize 4 -> 12 > 10. */
    static const uint8_t wire[] = {
        0x0A, 0x00,             /* total  = 10 */
        0x08, 0x00,             /* offset = 8  */
        0x04, 0x00,             /* frag   = 4  */
        0xAA, 0xBB, 0xCC, 0xDD,
    };
    osdp_mp_fragment_t out;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_mp_fragment_decode(wire, sizeof(wire), &out));
}

/* The receiver's half of the rule: a termination mid-transfer discards what
 * arrived and returns to idle, so the next transfer starts clean rather than
 * inheriting half a message. */
static void test_termination_discards_a_partial_transfer(void)
{
    uint8_t buf[64];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t first[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    const osdp_mp_fragment_t f0 = {
        .total_size = 32, .offset = 0, .data = first, .frag_len = 8,
    };
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &f0, &state));
    TEST_ASSERT_EQUAL(OSDP_MP_IN_PROGRESS, state);
    TEST_ASSERT_TRUE(r.active);

    osdp_mp_fragment_t stop;
    osdp_mp_frag_terminate(&stop, 32);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &stop, &state));
    TEST_ASSERT_EQUAL(OSDP_MP_TERMINATED, state);
    TEST_ASSERT_FALSE(r.active);
    TEST_ASSERT_EQUAL_UINT16(0, r.received);

    /* And a fresh transfer works immediately afterwards. */
    static const uint8_t whole[4] = { 9, 9, 9, 9 };
    const osdp_mp_fragment_t f1 = {
        .total_size = 4, .offset = 0, .data = whole, .frag_len = 4,
    };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &f1, &state));
    TEST_ASSERT_EQUAL(OSDP_MP_COMPLETE, state);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(whole, r.buf, sizeof(whole));
}

/* A continuation arriving with no transfer in progress is a violation, which
 * spec 5.10.2 says the receiver answers with NAK 0x09 to abort the sender's
 * sequence. The transport reports it; the reply code is the caller's job. */
static void test_continuation_without_a_transfer_is_rejected(void)
{
    uint8_t buf[64];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, buf, sizeof(buf));

    static const uint8_t d[4] = { 1, 2, 3, 4 };
    const osdp_mp_fragment_t orphan = {
        .total_size = 32, .offset = 8, .data = d, .frag_len = 4,
    };
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_mp_reasm_push(&r, &orphan, &state));
}

/* An unbound reassembler must refuse rather than dereference NULL — the
 * "no buffer registered" case spec 5.10.2 also expects a NAK for. */
static void test_unbound_reassembler_is_rejected(void)
{
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, NULL, 0);

    static const uint8_t d[2] = { 1, 2 };
    const osdp_mp_fragment_t f = {
        .total_size = 2, .offset = 0, .data = d, .frag_len = 2,
    };
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_mp_reasm_push(&r, &f, &state));
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
    /* Spec 5.10.2 early termination + violation reporting. */
    RUN_TEST(test_early_termination_marker_is_recognised);
    RUN_TEST(test_ordinary_fragments_are_not_terminations);
    RUN_TEST(test_termination_marker_round_trips_through_the_codec);
    RUN_TEST(test_decode_still_rejects_an_overrunning_fragment);
    RUN_TEST(test_termination_discards_a_partial_transfer);
    RUN_TEST(test_continuation_without_a_transfer_is_rejected);
    RUN_TEST(test_unbound_reassembler_is_rejected);
    return UNITY_END();
}
