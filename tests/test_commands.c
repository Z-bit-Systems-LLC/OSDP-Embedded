// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ========================================================================
 * osdp_POLL
 * ====================================================================== */

static void test_poll_decode_accepts_empty_payload(void)
{
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_poll_decode(NULL, 0));
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_poll_decode((const uint8_t *)"ignored", 0));
}

static void test_poll_decode_rejects_nonempty_payload(void)
{
    static const uint8_t data[] = { 0x00 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_poll_decode(data, 1));
}

static void test_poll_build_writes_zero_bytes(void)
{
    uint8_t buf[4] = { 0xAA, 0xAA, 0xAA, 0xAA };
    size_t n = 99;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_poll_build(buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(0, n);
    /* Buffer is untouched. */
    for (size_t i = 0; i < sizeof(buf); i++) {
        TEST_ASSERT_EQUAL_HEX8(0xAA, buf[i]);
    }
}

/* ========================================================================
 * osdp_ID
 * ====================================================================== */

static void test_id_round_trip(void)
{
    osdp_id_cmd_t in = { .id_type = 0x00 };
    uint8_t buf[1];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_id_build(&in, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(1, n);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[0]);

    osdp_id_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_id_decode(buf, n, &got));
    TEST_ASSERT_EQUAL_HEX8(in.id_type, got.id_type);
}

static void test_id_decode_rejects_wrong_length(void)
{
    osdp_id_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_id_decode(NULL, 0, &got));
    static const uint8_t two[] = { 0x00, 0x01 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_id_decode(two, 2, &got));
}

static void test_id_build_rejects_buffer_too_small(void)
{
    osdp_id_cmd_t in = { .id_type = 0x00 };
    uint8_t buf[1] = {0};
    size_t n = 0;
    /* Zero capacity is too small to hold the 1-byte payload. */
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_id_build(&in, buf, 0, &n));
}

/* ========================================================================
 * osdp_CAP
 * ====================================================================== */

static void test_cap_round_trip(void)
{
    for (uint8_t t = 0; t < 4; t++) {
        osdp_cap_cmd_t in = { .reply_type = t };
        uint8_t buf[1];
        size_t n = 0;
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_cap_build(&in, buf, sizeof(buf), &n));
        osdp_cap_cmd_t got;
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_cap_decode(buf, n, &got));
        TEST_ASSERT_EQUAL_HEX8(t, got.reply_type);
    }
}

/* ========================================================================
 * osdp_OUT
 * ====================================================================== */

static void test_out_decode_known_two_record_payload(void)
{
    /* Spec example: turn off output 0, turn on output 1 (no timer):
     *   record 0: { 0x00, 0x01, 0x00, 0x00 }
     *   record 1: { 0x01, 0x02, 0x00, 0x00 }
     */
    static const uint8_t payload[] = {
        0x00, 0x01, 0x00, 0x00,
        0x01, 0x02, 0x00, 0x00,
    };
    osdp_out_record_t rec[4];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_out_decode(payload, sizeof(payload), rec, 4, &n));
    TEST_ASSERT_EQUAL_size_t(2, n);
    TEST_ASSERT_EQUAL_HEX8(0x00, rec[0].output_no);
    TEST_ASSERT_EQUAL_HEX8(0x01, rec[0].control_code);
    TEST_ASSERT_EQUAL_HEX16(0x0000, rec[0].timer_100ms);
    TEST_ASSERT_EQUAL_HEX8(0x01, rec[1].output_no);
    TEST_ASSERT_EQUAL_HEX8(0x02, rec[1].control_code);
}

static void test_out_round_trip_with_timer(void)
{
    osdp_out_record_t in[3] = {
        { .output_no = 0, .control_code = 0x05, .timer_100ms = 50 },
        { .output_no = 1, .control_code = 0x05, .timer_100ms = 30 },
        { .output_no = 2, .control_code = 0x06, .timer_100ms = 100 },
    };
    uint8_t buf[16];
    size_t w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_out_build(in, 3, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(12, w);

    osdp_out_record_t got[3];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_out_decode(buf, w, got, 3, &n));
    TEST_ASSERT_EQUAL_size_t(3, n);
    TEST_ASSERT_EQUAL_MEMORY(in, got, sizeof(in));
}

static void test_out_decode_rejects_partial_record(void)
{
    /* 5 bytes is not a multiple of 4. */
    static const uint8_t bad[] = { 0, 1, 0, 0, 1 };
    osdp_out_record_t rec[2];
    size_t n;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_out_decode(bad, sizeof(bad), rec, 2, &n));
}

static void test_out_decode_rejects_zero_records(void)
{
    osdp_out_record_t rec[1];
    size_t n;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_out_decode(NULL, 0, rec, 1, &n));
}

static void test_out_decode_rejects_records_buffer_too_small(void)
{
    static const uint8_t two[] = { 0, 0, 0, 0, 1, 0, 0, 0 };
    osdp_out_record_t rec[1];
    size_t n;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_out_decode(two, sizeof(two), rec, 1, &n));
}

/* ========================================================================
 * osdp_LED
 * ====================================================================== */

static void test_led_round_trip(void)
{
    osdp_led_record_t in = {
        .reader_no         = 0x00,
        .led_no            = 0x01,
        .temp_control_code = 0x02,   /* set temporary */
        .temp_on_time      = 5,
        .temp_off_time     = 10,
        .temp_on_color     = OSDP_LED_RED,
        .temp_off_color    = OSDP_LED_BLACK,
        .temp_timer_100ms  = 30,
        .perm_control_code = 0x01,   /* set permanent */
        .perm_on_time      = 0,
        .perm_off_time     = 0,
        .perm_on_color     = OSDP_LED_GREEN,
        .perm_off_color    = OSDP_LED_GREEN,
    };
    uint8_t buf[OSDP_LED_RECORD_BYTES];
    size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_led_build(&in, 1, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_LED_RECORD_BYTES, w);

    osdp_led_record_t got;
    size_t n;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_led_decode(buf, w, &got, 1, &n));
    TEST_ASSERT_EQUAL_size_t(1, n);

    /* Compare field-by-field, NOT memcmp over the whole struct: the
     * uint16_t temp_timer_100ms is preceded by 7 uint8_t fields, so the
     * compiler inserts a padding byte at offset 7 to 2-byte-align it.
     * Padding contents are unspecified in C (C11 6.2.6.1p6), so a
     * TEST_ASSERT_EQUAL_MEMORY over sizeof(struct) is non-portable — it
     * happened to match on MSVC but mismatched the pad byte on GCC. */
    TEST_ASSERT_EQUAL_HEX8(in.reader_no,          got.reader_no);
    TEST_ASSERT_EQUAL_HEX8(in.led_no,             got.led_no);
    TEST_ASSERT_EQUAL_HEX8(in.temp_control_code,  got.temp_control_code);
    TEST_ASSERT_EQUAL_HEX8(in.temp_on_time,       got.temp_on_time);
    TEST_ASSERT_EQUAL_HEX8(in.temp_off_time,      got.temp_off_time);
    TEST_ASSERT_EQUAL_HEX8(in.temp_on_color,      got.temp_on_color);
    TEST_ASSERT_EQUAL_HEX8(in.temp_off_color,     got.temp_off_color);
    TEST_ASSERT_EQUAL_UINT16(in.temp_timer_100ms, got.temp_timer_100ms);
    TEST_ASSERT_EQUAL_HEX8(in.perm_control_code,  got.perm_control_code);
    TEST_ASSERT_EQUAL_HEX8(in.perm_on_time,       got.perm_on_time);
    TEST_ASSERT_EQUAL_HEX8(in.perm_off_time,      got.perm_off_time);
    TEST_ASSERT_EQUAL_HEX8(in.perm_on_color,      got.perm_on_color);
    TEST_ASSERT_EQUAL_HEX8(in.perm_off_color,     got.perm_off_color);
}

static void test_led_decode_rejects_wrong_size(void)
{
    static const uint8_t junk[] = { 1, 2, 3 };
    osdp_led_record_t r[1]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_led_decode(junk, sizeof(junk), r, 1, &n));
}

/* ========================================================================
 * osdp_BUZ
 * ====================================================================== */

static void test_buz_round_trip(void)
{
    osdp_buz_cmd_t in = {
        .reader_no = 0,
        .tone_code = 0x02,
        .on_time_100ms = 1,
        .off_time_100ms = 1,
        .count = 3,
    };
    uint8_t buf[OSDP_BUZ_PAYLOAD_BYTES];
    size_t w; size_t n;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_buz_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_BUZ_PAYLOAD_BYTES, w);

    osdp_buz_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_buz_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_MEMORY(&in, &got, sizeof(in));
    (void)n;
}

static void test_buz_decode_rejects_wrong_size(void)
{
    osdp_buz_cmd_t got;
    static const uint8_t four[] = { 0, 0, 0, 0 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_buz_decode(four, sizeof(four), &got));
}

/* ========================================================================
 * osdp_TEXT
 * ====================================================================== */

static void test_text_round_trip(void)
{
    static const uint8_t text[] = "HELLO";
    osdp_text_cmd_t in = {
        .reader_no        = 0,
        .text_command     = OSDP_TEXT_PERM_NO_WRAP,
        .temp_text_time_s = 0,
        .row              = 1,
        .column           = 1,
        .text_length      = 5,
        .text             = text,
        .text_len         = 5,
    };
    uint8_t buf[64]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_text_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_TEXT_HEADER_BYTES + 5u, w);

    osdp_text_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_text_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(in.reader_no, got.reader_no);
    TEST_ASSERT_EQUAL_HEX8(in.text_command, got.text_command);
    TEST_ASSERT_EQUAL_UINT8(5, got.text_length);
    TEST_ASSERT_EQUAL_size_t(5, got.text_len);
    TEST_ASSERT_EQUAL_MEMORY(text, got.text, 5);
}

static void test_text_round_trip_zero_length(void)
{
    osdp_text_cmd_t in = { .row = 1, .column = 1,
                           .text_command = OSDP_TEXT_TEMP_NO_WRAP };
    uint8_t buf[OSDP_TEXT_HEADER_BYTES]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_text_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_TEXT_HEADER_BYTES, w);

    osdp_text_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_text_decode(buf, w, &got));
    TEST_ASSERT_NULL(got.text);
    TEST_ASSERT_EQUAL_size_t(0, got.text_len);
}

static void test_text_decode_rejects_length_mismatch(void)
{
    /* Header says 5 chars but only 3 trailing bytes. */
    static const uint8_t bad[] = { 0, 1, 0, 1, 1, 5, 'A', 'B', 'C' };
    osdp_text_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_text_decode(bad, sizeof(bad), &got));
}

static void test_text_build_rejects_inconsistent_length_fields(void)
{
    static const uint8_t s[] = "AB";
    osdp_text_cmd_t in = {
        .row = 1, .column = 1, .text_command = OSDP_TEXT_PERM_NO_WRAP,
        .text_length = 5,    /* header says 5 */
        .text = s, .text_len = 2 /* but only 2 supplied */
    };
    uint8_t buf[16]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_text_build(&in, buf, sizeof(buf), &w));
}

/* ========================================================================
 * osdp_COMSET
 * ====================================================================== */

static void test_comset_round_trip(void)
{
    osdp_comset_cmd_t in = { .address = 0x12, .baud_rate = 38400u };
    uint8_t buf[OSDP_COMSET_PAYLOAD_BYTES]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_comset_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_COMSET_PAYLOAD_BYTES, w);
    /* Verify on-wire LE encoding. */
    TEST_ASSERT_EQUAL_HEX8(0x12, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[1]);
    TEST_ASSERT_EQUAL_HEX8(0x96, buf[2]);  /* 38400 = 0x9600 */
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[3]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[4]);

    osdp_comset_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_comset_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(in.address, got.address);
    TEST_ASSERT_EQUAL_HEX32(in.baud_rate, got.baud_rate);
}

/* 0x7F (the config/broadcast address) is not an assignable COMSET target. */
static void test_comset_build_rejects_address_above_7e(void)
{
    osdp_comset_cmd_t in = { .address = 0x7F, .baud_rate = 9600u };
    uint8_t buf[8]; size_t w;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_comset_build(&in, buf, sizeof(buf), &w));
}

/* ========================================================================
 * osdp_KEYSET
 * ====================================================================== */

static void test_keyset_round_trip_scbk(void)
{
    /* A spec-shaped KEYSET: 2-byte header (key_type=SCBK, len=16) +
     * 16 bytes of key material. */
    static const uint8_t key[OSDP_KEYSET_HEADER_BYTES + 16] = {
        0x01, 0x10, /* SCBK, 16 bytes */
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    };

    osdp_keyset_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_keyset_decode(key, sizeof(key), &got));
    TEST_ASSERT_EQUAL_UINT8(OSDP_KEYSET_KEY_TYPE_SCBK, got.key_type);
    TEST_ASSERT_EQUAL_UINT8(16, got.key_length);
    TEST_ASSERT_EQUAL_size_t(16, got.key_data_len);
    TEST_ASSERT_EQUAL_MEMORY(&key[2], got.key_data, 16);

    /* Round-trip through the builder yields byte-identical output. */
    uint8_t out[OSDP_KEYSET_HEADER_BYTES + 16] = { 0 };
    size_t  written = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_keyset_build(&got, out, sizeof(out), &written));
    TEST_ASSERT_EQUAL_size_t(sizeof(key), written);
    TEST_ASSERT_EQUAL_MEMORY(key, out, sizeof(key));
}

static void test_keyset_decode_rejects_length_mismatch(void)
{
    /* Header claims 16-byte key but payload only carries 4 bytes — a
     * malicious or buggy ACU should not silently corrupt the SCBK. */
    static const uint8_t lying[6] = { 0x01, 0x10, 1, 2, 3, 4 };
    osdp_keyset_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_keyset_decode(lying, sizeof(lying), &got));
}

static void test_keyset_decode_rejects_short_payload(void)
{
    /* Anything < 2 bytes can't even hold the header. */
    static const uint8_t one[1] = { 0x01 };
    osdp_keyset_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_keyset_decode(one, sizeof(one), &got));
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_keyset_decode(NULL, 0, &got));
}

static void test_keyset_build_rejects_inconsistent_length(void)
{
    /* `key_length` field disagrees with `key_data_len` — we won't
     * happily put a lying frame on the wire. */
    static const uint8_t k[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    osdp_keyset_cmd_t in = {
        .key_type     = OSDP_KEYSET_KEY_TYPE_SCBK,
        .key_length   = 16,             /* lies */
        .key_data     = k,
        .key_data_len = 4,              /* truth */
    };
    uint8_t out[32];
    size_t written = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_keyset_build(&in, out, sizeof(out), &written));
}

static void test_keyset_build_rejects_buffer_too_small(void)
{
    static const uint8_t k[16] = { 0 };
    osdp_keyset_cmd_t in = {
        .key_type     = OSDP_KEYSET_KEY_TYPE_SCBK,
        .key_length   = 16,
        .key_data     = k,
        .key_data_len = 16,
    };
    uint8_t out[10]; /* needs 18 */
    size_t written = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_keyset_build(&in, out, sizeof(out), &written));
    TEST_ASSERT_EQUAL_size_t(0, written);
}

/* ========================================================================
 * osdp_FILETRANSFER
 * ====================================================================== */

static void test_filetransfer_round_trip_with_fragment(void)
{
    static const uint8_t frag[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    osdp_filetransfer_cmd_t in = {
        .ft_type       = OSDP_FT_TYPE_OPAQUE,
        .total_size    = 0x00012345u,
        .offset        = 0x00000100u,
        .fragment_size = 4,
        .data          = frag,
        .data_len      = 4,
    };
    uint8_t buf[OSDP_FILETRANSFER_HEADER_BYTES + 4];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_filetransfer_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_FILETRANSFER_HEADER_BYTES + 4, w);

    /* Header is little-endian: type, size(4), offset(4), frag(2). */
    TEST_ASSERT_EQUAL_HEX8(OSDP_FT_TYPE_OPAQUE, buf[0]);
    TEST_ASSERT_EQUAL_HEX8(0x45, buf[1]);
    TEST_ASSERT_EQUAL_HEX8(0x23, buf[2]);
    TEST_ASSERT_EQUAL_HEX8(0x01, buf[3]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[4]);
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[5]);  /* offset LSB */
    TEST_ASSERT_EQUAL_HEX8(0x01, buf[6]);
    TEST_ASSERT_EQUAL_HEX8(0x04, buf[9]);  /* frag size LSB */
    TEST_ASSERT_EQUAL_HEX8(0x00, buf[10]);

    osdp_filetransfer_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_filetransfer_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_HEX8(OSDP_FT_TYPE_OPAQUE, got.ft_type);
    TEST_ASSERT_EQUAL_UINT32(0x00012345u, got.total_size);
    TEST_ASSERT_EQUAL_UINT32(0x00000100u, got.offset);
    TEST_ASSERT_EQUAL_UINT16(4, got.fragment_size);
    TEST_ASSERT_EQUAL_size_t(4, got.data_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(frag, got.data, 4);
}

static void test_filetransfer_round_trip_empty_fragment(void)
{
    osdp_filetransfer_cmd_t in = {
        .ft_type       = OSDP_FT_TYPE_OPAQUE,
        .total_size    = 100,
        .offset        = 100,   /* an "idle" fragment at end-of-file */
        .fragment_size = 0,
        .data          = NULL,
        .data_len      = 0,
    };
    uint8_t buf[OSDP_FILETRANSFER_HEADER_BYTES];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_filetransfer_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(OSDP_FILETRANSFER_HEADER_BYTES, w);

    osdp_filetransfer_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_filetransfer_decode(buf, w, &got));
    TEST_ASSERT_EQUAL_UINT16(0, got.fragment_size);
    TEST_ASSERT_NULL(got.data);
    TEST_ASSERT_EQUAL_size_t(0, got.data_len);
}

static void test_filetransfer_decode_rejects_short_header(void)
{
    uint8_t buf[OSDP_FILETRANSFER_HEADER_BYTES - 1] = { 0 };
    osdp_filetransfer_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_filetransfer_decode(buf, sizeof(buf), &got));
}

static void test_filetransfer_decode_rejects_fragment_size_mismatch(void)
{
    /* Header declares a 4-byte fragment but only 2 bytes follow. */
    uint8_t buf[OSDP_FILETRANSFER_HEADER_BYTES + 2] = { 0 };
    buf[9]  = 0x04;   /* FtFragmentSize LSB = 4 */
    buf[10] = 0x00;
    osdp_filetransfer_cmd_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_filetransfer_decode(buf, sizeof(buf), &got));
}

static void test_filetransfer_build_rejects_inconsistent_length(void)
{
    static const uint8_t frag[2] = { 0x01, 0x02 };
    osdp_filetransfer_cmd_t in = {
        .ft_type       = OSDP_FT_TYPE_OPAQUE,
        .total_size    = 2,
        .offset        = 0,
        .fragment_size = 4,     /* claims 4 but data_len is 2 */
        .data          = frag,
        .data_len      = 2,
    };
    uint8_t buf[32];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_filetransfer_build(&in, buf, sizeof(buf), &w));
    TEST_ASSERT_EQUAL_size_t(0, w);
}

/* ========================================================================
 * Registration
 * ====================================================================== */

int main(void)
{
    UNITY_BEGIN();
    /* POLL */
    RUN_TEST(test_poll_decode_accepts_empty_payload);
    RUN_TEST(test_poll_decode_rejects_nonempty_payload);
    RUN_TEST(test_poll_build_writes_zero_bytes);
    /* ID */
    RUN_TEST(test_id_round_trip);
    RUN_TEST(test_id_decode_rejects_wrong_length);
    RUN_TEST(test_id_build_rejects_buffer_too_small);
    /* CAP */
    RUN_TEST(test_cap_round_trip);
    /* OUT */
    RUN_TEST(test_out_decode_known_two_record_payload);
    RUN_TEST(test_out_round_trip_with_timer);
    RUN_TEST(test_out_decode_rejects_partial_record);
    RUN_TEST(test_out_decode_rejects_zero_records);
    RUN_TEST(test_out_decode_rejects_records_buffer_too_small);
    /* LED */
    RUN_TEST(test_led_round_trip);
    RUN_TEST(test_led_decode_rejects_wrong_size);
    /* BUZ */
    RUN_TEST(test_buz_round_trip);
    RUN_TEST(test_buz_decode_rejects_wrong_size);
    /* TEXT */
    RUN_TEST(test_text_round_trip);
    RUN_TEST(test_text_round_trip_zero_length);
    RUN_TEST(test_text_decode_rejects_length_mismatch);
    RUN_TEST(test_text_build_rejects_inconsistent_length_fields);
    /* COMSET */
    RUN_TEST(test_comset_round_trip);
    RUN_TEST(test_comset_build_rejects_address_above_7e);
    /* KEYSET */
    RUN_TEST(test_keyset_round_trip_scbk);
    RUN_TEST(test_keyset_decode_rejects_length_mismatch);
    RUN_TEST(test_keyset_decode_rejects_short_payload);
    RUN_TEST(test_keyset_build_rejects_inconsistent_length);
    RUN_TEST(test_keyset_build_rejects_buffer_too_small);
    /* FILETRANSFER */
    RUN_TEST(test_filetransfer_round_trip_with_fragment);
    RUN_TEST(test_filetransfer_round_trip_empty_fragment);
    RUN_TEST(test_filetransfer_decode_rejects_short_header);
    RUN_TEST(test_filetransfer_decode_rejects_fragment_size_mismatch);
    RUN_TEST(test_filetransfer_build_rejects_inconsistent_length);
    return UNITY_END();
}
