// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_checksum.h"
#include "osdp/osdp_crc.h"
#include "osdp/osdp_frame.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Helpers -------------------------------------------------------------
 *
 * Build a tiny OSDP frame on the stack so individual tests don't have to
 * compute integrity bytes by hand. */

static size_t build_checksum_frame(uint8_t *buf, size_t cap,
                                   uint8_t addr, bool reply, uint8_t seq,
                                   uint8_t code,
                                   const uint8_t *payload, size_t payload_len)
{
    osdp_frame_t f = {0};
    f.address     = (uint8_t)(addr & OSDP_ADDR_MASK);
    f.reply       = reply;
    f.sequence    = seq;
    f.integrity   = OSDP_INTEGRITY_CHECKSUM;
    f.code        = code;
    f.payload     = payload;
    f.payload_len = payload_len;
    size_t written = 0;
    const osdp_status_t s = osdp_frame_build(&f, buf, cap, &written);
    TEST_ASSERT_EQUAL(OSDP_OK, s);
    return written;
}

static size_t build_crc_frame(uint8_t *buf, size_t cap,
                              uint8_t addr, bool reply, uint8_t seq,
                              uint8_t code,
                              const uint8_t *payload, size_t payload_len)
{
    osdp_frame_t f = {0};
    f.address     = (uint8_t)(addr & OSDP_ADDR_MASK);
    f.reply       = reply;
    f.sequence    = seq;
    f.integrity   = OSDP_INTEGRITY_CRC;
    f.code        = code;
    f.payload     = payload;
    f.payload_len = payload_len;
    size_t written = 0;
    const osdp_status_t s = osdp_frame_build(&f, buf, cap, &written);
    TEST_ASSERT_EQUAL(OSDP_OK, s);
    return written;
}

/* ---- Decode happy-path tests ---------------------------------------------*/

static void test_decode_minimal_poll_checksum(void)
{
    /* Hand-built smallest possible frame: ACU sends osdp_POLL (0x60) to
     * address 0x00 with sequence 0, checksum mode, no SCB.
     *
     *   SOM   ADDR  LEN_LSB LEN_MSB CTRL  CODE  CKSUM
     *   0x53  0x00  0x07    0x00    0x00  0x60  0x46
     *
     * sum = 0x53 + 0 + 7 + 0 + 0 + 0x60 = 0xBA → cksum = 0x46.
     */
    static const uint8_t frame[] = { 0x53, 0x00, 0x07, 0x00, 0x00, 0x60, 0x46 };
    osdp_frame_t f = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(frame, sizeof(frame), &f));
    TEST_ASSERT_EQUAL_HEX8(0x00, f.address);
    TEST_ASSERT_FALSE(f.reply);
    TEST_ASSERT_EQUAL_UINT8(0, f.sequence);
    TEST_ASSERT_EQUAL(OSDP_INTEGRITY_CHECKSUM, f.integrity);
    TEST_ASSERT_FALSE(f.has_scb);
    TEST_ASSERT_EQUAL_HEX8(0x60, f.code);
    TEST_ASSERT_EQUAL_size_t(0, f.payload_len);
    TEST_ASSERT_NULL(f.payload);
    TEST_ASSERT_EQUAL_PTR(frame, f.raw);
    TEST_ASSERT_EQUAL_size_t(sizeof(frame), f.raw_len);
}

static void test_decode_minimal_poll_crc(void)
{
    /* ACU poll with CRC mode (CTRL bit 2 set). */
    uint8_t frame[16];
    const size_t n = build_crc_frame(frame, sizeof(frame),
                                     0x12, false, 1, 0x60, NULL, 0);
    TEST_ASSERT_EQUAL_size_t(8, n); /* 5 hdr + 1 code + 2 CRC */

    osdp_frame_t f = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(frame, n, &f));
    TEST_ASSERT_EQUAL_HEX8(0x12, f.address);
    TEST_ASSERT_FALSE(f.reply);
    TEST_ASSERT_EQUAL_UINT8(1, f.sequence);
    TEST_ASSERT_EQUAL(OSDP_INTEGRITY_CRC, f.integrity);
    TEST_ASSERT_FALSE(f.has_scb);
    TEST_ASSERT_EQUAL_HEX8(0x60, f.code);
}

static void test_decode_reply_flag_set(void)
{
    uint8_t frame[16];
    const size_t n = build_checksum_frame(frame, sizeof(frame),
                                          0x05, /* reply = */ true,
                                          2, 0x40 /* osdp_ACK */, NULL, 0);
    osdp_frame_t f = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(frame, n, &f));
    TEST_ASSERT_EQUAL_HEX8(0x05, f.address);
    TEST_ASSERT_TRUE(f.reply);
    TEST_ASSERT_EQUAL_HEX8(0x40, f.code);
    /* Verify the on-wire ADDR byte has the reply flag bit. */
    TEST_ASSERT_TRUE((frame[1] & OSDP_REPLY_FLAG) != 0);
}

static void test_decode_broadcast_address(void)
{
    uint8_t frame[16];
    const size_t n = build_crc_frame(frame, sizeof(frame),
                                     OSDP_BROADCAST_ADDR, false, 0,
                                     0x60, NULL, 0);
    osdp_frame_t f = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(frame, n, &f));
    TEST_ASSERT_EQUAL_HEX8(OSDP_BROADCAST_ADDR, f.address);
}

static void test_decode_with_payload_round_trip(void)
{
    static const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };
    uint8_t frame[64];
    const size_t n = build_crc_frame(frame, sizeof(frame),
                                     0x03, false, 3, 0x69 /* osdp_LED */,
                                     payload, sizeof(payload));

    osdp_frame_t f = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(frame, n, &f));
    TEST_ASSERT_EQUAL_HEX8(0x69, f.code);
    TEST_ASSERT_EQUAL_size_t(sizeof(payload), f.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, f.payload, sizeof(payload));
    TEST_ASSERT_EQUAL_PTR(&frame[6], f.payload); /* zero-copy slice */
}

static void test_decode_with_scb_no_data(void)
{
    /* Manually construct a frame with SCB present (CTRL bit 3), checksum
     * integrity, SCB length 2 (header only), type 0x11 (SCS_11). */
    uint8_t frame[16];
    const uint16_t total = 9;  /* 5 hdr + 2 SCB + 1 code + 1 cksum */
    frame[0] = OSDP_SOM;
    frame[1] = 0x07;  /* address 7, no reply */
    frame[2] = (uint8_t)(total & 0xFF);
    frame[3] = (uint8_t)((total >> 8) & 0xFF);
    frame[4] = OSDP_CTRL_SCB;  /* checksum + SCB present */
    frame[5] = 0x02;  /* SCB length = 2 (just len + type) */
    frame[6] = 0x11;  /* SCB type = SCS_11 */
    frame[7] = 0x76;  /* osdp_CHLNG */
    frame[8] = osdp_checksum(frame, 8);

    osdp_frame_t f = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(frame, total, &f));
    TEST_ASSERT_TRUE(f.has_scb);
    TEST_ASSERT_EQUAL_UINT8(0x02, f.scb_length);
    TEST_ASSERT_EQUAL_HEX8(0x11, f.scb_type);
    TEST_ASSERT_EQUAL_size_t(0, f.scb_data_len);
    TEST_ASSERT_NULL(f.scb_data);
    TEST_ASSERT_EQUAL_HEX8(0x76, f.code);
}

static void test_decode_with_scb_data_round_trip(void)
{
    static const uint8_t scb_data[] = { 0x01, 0xAA, 0xBB };
    static const uint8_t payload[]  = { 0x42 };

    osdp_frame_t built = {0};
    built.address      = 0x10;
    built.reply        = false;
    built.sequence     = 1;
    built.integrity    = OSDP_INTEGRITY_CRC;
    built.has_scb      = true;
    built.scb_length   = (uint8_t)(OSDP_SCB_MIN_LEN + sizeof(scb_data));
    built.scb_type     = 0x11;
    built.scb_data     = scb_data;
    built.scb_data_len = sizeof(scb_data);
    built.code         = 0x76;
    built.payload      = payload;
    built.payload_len  = sizeof(payload);

    uint8_t buf[32];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&built, buf, sizeof(buf), &n));

    osdp_frame_t got = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(buf, n, &got));
    TEST_ASSERT_EQUAL_HEX8(built.address, got.address);
    TEST_ASSERT_EQUAL_UINT8(built.sequence, got.sequence);
    TEST_ASSERT_EQUAL(OSDP_INTEGRITY_CRC, got.integrity);
    TEST_ASSERT_TRUE(got.has_scb);
    TEST_ASSERT_EQUAL_UINT8(built.scb_length, got.scb_length);
    TEST_ASSERT_EQUAL_HEX8(built.scb_type, got.scb_type);
    TEST_ASSERT_EQUAL_size_t(sizeof(scb_data), got.scb_data_len);
    TEST_ASSERT_EQUAL_MEMORY(scb_data, got.scb_data, sizeof(scb_data));
    TEST_ASSERT_EQUAL_HEX8(built.code, got.code);
    TEST_ASSERT_EQUAL_size_t(sizeof(payload), got.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, got.payload, sizeof(payload));
}

static void test_decode_then_rebuild_produces_byte_identical_output(void)
{
    /* Symmetry: take a known frame, decode it, build it from the decoded
     * struct, and verify the bytes are identical. */
    static const uint8_t original[] = {
        0x53, 0x80 | 0x05, 0x08, 0x00, 0x04 | 0x02, 0x40,
        0x00, 0x00 /* CRC placeholder, computed below */
    };
    uint8_t frame[16];
    memcpy(frame, original, sizeof(original));
    const uint16_t crc = osdp_crc16(frame, sizeof(original) - 2);
    frame[6] = (uint8_t)(crc & 0xFF);
    frame[7] = (uint8_t)((crc >> 8) & 0xFF);

    osdp_frame_t f = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(frame, sizeof(original), &f));

    uint8_t rebuilt[16];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_build(&f, rebuilt, sizeof(rebuilt), &n));
    TEST_ASSERT_EQUAL_size_t(sizeof(original), n);
    TEST_ASSERT_EQUAL_MEMORY(frame, rebuilt, n);
}

/* ---- Decode error-path tests --------------------------------------------*/

static void test_decode_rejects_null_args(void)
{
    osdp_frame_t f;
    uint8_t buf[8] = {0};
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_frame_decode(NULL, 8, &f));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_frame_decode(buf,  8, NULL));
}

static void test_decode_rejects_truncated_buffer(void)
{
    osdp_frame_t f;
    uint8_t tiny[3] = { 0x53, 0x00, 0x00 };
    TEST_ASSERT_EQUAL(OSDP_ERR_TRUNCATED, osdp_frame_decode(tiny, 3, &f));
}

static void test_decode_rejects_bad_som(void)
{
    osdp_frame_t f;
    static const uint8_t frame[] = { 0x52, 0x00, 0x07, 0x00, 0x00, 0x60, 0x47 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_SOM,
                      osdp_frame_decode(frame, sizeof(frame), &f));
}

static void test_decode_rejects_bad_length_field(void)
{
    osdp_frame_t f;
    /* LEN says 8 but buffer is 7. */
    static const uint8_t frame[] = { 0x53, 0x00, 0x08, 0x00, 0x00, 0x60, 0x46 };
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_LENGTH,
                      osdp_frame_decode(frame, sizeof(frame), &f));
}

static void test_decode_rejects_reserved_ctrl_bits(void)
{
    /* Build a valid frame, then set a reserved bit in CTRL and recompute
     * checksum so length/integrity look fine. */
    uint8_t frame[8];
    const size_t n = build_checksum_frame(frame, sizeof(frame),
                                          0, false, 0, 0x60, NULL, 0);
    frame[4] |= 0x10;  /* set reserved bit */
    frame[n - 1] = osdp_checksum(frame, n - 1);

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CTRL, osdp_frame_decode(frame, n, &f));
}

static void test_decode_rejects_bad_crc(void)
{
    uint8_t frame[16];
    const size_t n = build_crc_frame(frame, sizeof(frame),
                                     0, false, 0, 0x60, NULL, 0);
    frame[n - 1] ^= 0xFF;  /* corrupt MSB of CRC */
    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CRC, osdp_frame_decode(frame, n, &f));
}

static void test_decode_rejects_bad_checksum(void)
{
    uint8_t frame[8];
    const size_t n = build_checksum_frame(frame, sizeof(frame),
                                          0, false, 0, 0x60, NULL, 0);
    frame[n - 1] ^= 0xFF;
    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CHECKSUM, osdp_frame_decode(frame, n, &f));
}

static void test_decode_rejects_scb_length_below_min(void)
{
    /* SCB present, but SEC_BLK_LEN = 1 (must be >= 2). */
    uint8_t frame[16];
    const uint16_t total = 9;
    frame[0] = OSDP_SOM;
    frame[1] = 0x00;
    frame[2] = (uint8_t)(total & 0xFF);
    frame[3] = 0x00;
    frame[4] = OSDP_CTRL_SCB;
    frame[5] = 0x01;   /* invalid */
    frame[6] = 0x11;
    frame[7] = 0x76;
    frame[8] = osdp_checksum(frame, 8);

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_LENGTH,
                      osdp_frame_decode(frame, total, &f));
}

static void test_decode_rejects_scb_overflowing_frame(void)
{
    /* SCB length larger than frame can possibly hold. */
    uint8_t frame[16];
    const uint16_t total = 9;
    frame[0] = OSDP_SOM;
    frame[1] = 0x00;
    frame[2] = (uint8_t)(total & 0xFF);
    frame[3] = 0x00;
    frame[4] = OSDP_CTRL_SCB;
    frame[5] = 0x10;   /* claims 16-byte SCB but frame is 9 bytes */
    frame[6] = 0x11;
    frame[7] = 0x00;
    frame[8] = osdp_checksum(frame, 8);

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_LENGTH,
                      osdp_frame_decode(frame, total, &f));
}

/* ---- Build error-path tests ---------------------------------------------*/

static void test_build_rejects_null_args(void)
{
    osdp_frame_t f = {0};
    f.integrity = OSDP_INTEGRITY_CHECKSUM;
    f.code = 0x60;

    uint8_t buf[8];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_frame_build(NULL, buf, 8, &n));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_frame_build(&f, NULL, 8, &n));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_frame_build(&f, buf, 8, NULL));
}

static void test_build_rejects_buffer_too_small(void)
{
    osdp_frame_t f = {0};
    f.integrity = OSDP_INTEGRITY_CHECKSUM;
    f.code = 0x60;

    uint8_t buf[6];   /* 1 byte short of minimum */
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_frame_build(&f, buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_size_t(0, n);
}

static void test_build_rejects_address_out_of_range(void)
{
    osdp_frame_t f = {0};
    f.address = 0x80;   /* invalid: bit 7 reserved for reply flag */
    f.integrity = OSDP_INTEGRITY_CHECKSUM;
    f.code = 0x60;
    uint8_t buf[16]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_frame_build(&f, buf, sizeof(buf), &n));
}

static void test_build_rejects_sequence_out_of_range(void)
{
    osdp_frame_t f = {0};
    f.sequence = 4;     /* only 0..3 valid */
    f.integrity = OSDP_INTEGRITY_CHECKSUM;
    f.code = 0x60;
    uint8_t buf[16]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_frame_build(&f, buf, sizeof(buf), &n));
}

static void test_build_rejects_inconsistent_scb(void)
{
    osdp_frame_t f = {0};
    f.integrity    = OSDP_INTEGRITY_CHECKSUM;
    f.code         = 0x76;
    f.has_scb      = true;
    f.scb_length   = 5;            /* claims 3 data bytes (5 - 2) */
    f.scb_type     = 0x11;
    static const uint8_t bad[] = { 0xAA };  /* but only 1 byte provided */
    f.scb_data     = bad;
    f.scb_data_len = 1;

    uint8_t buf[32]; size_t n;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_frame_build(&f, buf, sizeof(buf), &n));
}

/* ---- SCS_15..18 MAC handling -------------------------------------------*/

static void test_decode_splits_mac_for_scs_15_frame(void)
{
    /* Build an SCS_15 (ACU→PD plain+MAC) frame with a known MAC and
     * decode it; the four trailing bytes before CRC must come back
     * via `mac` / `mac_len`, NOT inside `payload`. */
    static const uint8_t mac_bytes[OSDP_FRAME_MAC_LEN] = {
        0xCA, 0xFE, 0xBA, 0xBE
    };
    static const uint8_t inner_payload[3] = { 0x11, 0x22, 0x33 };

    osdp_frame_t built = {0};
    built.address      = 0x05;
    built.integrity    = OSDP_INTEGRITY_CRC;
    built.has_scb      = true;
    built.scb_length   = OSDP_SCB_MIN_LEN;
    built.scb_type     = OSDP_SCS_15;
    built.code         = 0x60;     /* osdp_POLL */
    built.payload      = inner_payload;
    built.payload_len  = sizeof(inner_payload);
    built.mac          = mac_bytes;
    built.mac_len      = OSDP_FRAME_MAC_LEN;

    uint8_t buf[64];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&built, buf, sizeof(buf), &n));

    osdp_frame_t got = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(buf, n, &got));
    TEST_ASSERT_TRUE(got.has_scb);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_15, got.scb_type);
    TEST_ASSERT_EQUAL_size_t(sizeof(inner_payload), got.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(inner_payload, got.payload, sizeof(inner_payload));
    TEST_ASSERT_EQUAL_size_t(OSDP_FRAME_MAC_LEN, got.mac_len);
    TEST_ASSERT_EQUAL_MEMORY(mac_bytes, got.mac, OSDP_FRAME_MAC_LEN);
}

static void test_decode_handles_scs_15_with_zero_inner_payload(void)
{
    /* osdp_POLL under SCS_15 has empty data; the post-code area is
     * exactly 4 bytes of MAC. */
    static const uint8_t mac_bytes[OSDP_FRAME_MAC_LEN] = {
        0x11, 0x22, 0x33, 0x44
    };
    osdp_frame_t built = {0};
    built.address      = 0x10;
    built.integrity    = OSDP_INTEGRITY_CRC;
    built.has_scb      = true;
    built.scb_length   = OSDP_SCB_MIN_LEN;
    built.scb_type     = OSDP_SCS_16;  /* PD→ACU variant */
    built.reply        = true;
    built.code         = 0x40;     /* osdp_ACK */
    built.mac          = mac_bytes;
    built.mac_len      = OSDP_FRAME_MAC_LEN;

    uint8_t buf[64];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&built, buf, sizeof(buf), &n));

    osdp_frame_t got = {0};
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(buf, n, &got));
    TEST_ASSERT_EQUAL_size_t(0, got.payload_len);
    TEST_ASSERT_NULL(got.payload);
    TEST_ASSERT_EQUAL_size_t(OSDP_FRAME_MAC_LEN, got.mac_len);
    TEST_ASSERT_EQUAL_MEMORY(mac_bytes, got.mac, OSDP_FRAME_MAC_LEN);
}

static void test_decode_rejects_scs_17_with_room_for_mac_only(void)
{
    /* SCS_17 (encrypted+MAC) without enough bytes for both encrypted
     * data AND a 4-byte MAC. Concretely: post-code area is 3 bytes,
     * which is shorter than the minimum 4-byte MAC. */
    uint8_t buf[16];
    /* Manually craft a frame: SOM, ADDR, LEN(2), CTRL with SCB+CRC,
     * SCB len/type, code, 3 trailing bytes, 2-byte CRC. */
    const uint16_t total = 12;
    buf[0] = OSDP_SOM;
    buf[1] = 0x05;
    buf[2] = (uint8_t)(total & 0xFF);
    buf[3] = (uint8_t)(total >> 8);
    buf[4] = (uint8_t)(OSDP_CTRL_USE_CRC | OSDP_CTRL_SCB);
    buf[5] = OSDP_SCB_MIN_LEN;
    buf[6] = OSDP_SCS_17;
    buf[7] = 0x60;             /* code */
    buf[8] = 0xAA;             /* would be MAC byte 0 ... */
    buf[9] = 0xBB;             /* but only 3 trailing bytes */
    buf[10] = 0xCC;
    /* Compute CRC over bytes 0..9 inclusive. */
    extern uint16_t osdp_crc16(const uint8_t *data, size_t len);
    const uint16_t crc = osdp_crc16(buf, total - 2);
    buf[total - 2] = (uint8_t)(crc & 0xFF);
    buf[total - 1] = (uint8_t)((crc >> 8) & 0xFF);

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_frame_decode(buf, total, &f));
}

static void test_build_rejects_missing_mac_for_scs_15(void)
{
    osdp_frame_t f = {0};
    f.address    = 0x05;
    f.integrity  = OSDP_INTEGRITY_CRC;
    f.has_scb    = true;
    f.scb_length = OSDP_SCB_MIN_LEN;
    f.scb_type   = OSDP_SCS_15;
    f.code       = 0x60;
    /* mac_len intentionally 0 */
    uint8_t buf[32]; size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_frame_build(&f, buf, sizeof(buf), &n));
}

static void test_build_rejects_unexpected_mac_for_scs_11(void)
{
    /* SCS_11 is a handshake frame and must NOT carry a MAC. */
    static const uint8_t mac_bytes[OSDP_FRAME_MAC_LEN] = {1,2,3,4};
    osdp_frame_t f = {0};
    f.address    = 0x05;
    f.integrity  = OSDP_INTEGRITY_CRC;
    f.has_scb    = true;
    f.scb_length = OSDP_SCB_MIN_LEN;
    f.scb_type   = OSDP_SCS_11;
    f.code       = 0x76;
    f.mac        = mac_bytes;
    f.mac_len    = OSDP_FRAME_MAC_LEN;
    uint8_t buf[32]; size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_frame_build(&f, buf, sizeof(buf), &n));
}

static void test_build_rejects_mac_when_scb_absent(void)
{
    /* No SCB at all but caller sets a MAC — invalid. */
    static const uint8_t mac_bytes[OSDP_FRAME_MAC_LEN] = {1,2,3,4};
    osdp_frame_t f = {0};
    f.address   = 0x05;
    f.integrity = OSDP_INTEGRITY_CRC;
    f.code      = 0x60;
    f.mac       = mac_bytes;
    f.mac_len   = OSDP_FRAME_MAC_LEN;
    uint8_t buf[32]; size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_frame_build(&f, buf, sizeof(buf), &n));
}

static void test_scs_helpers_classify_correctly(void)
{
    TEST_ASSERT_FALSE(osdp_scb_has_mac(OSDP_SCS_11));
    TEST_ASSERT_FALSE(osdp_scb_has_mac(OSDP_SCS_14));
    TEST_ASSERT_TRUE (osdp_scb_has_mac(OSDP_SCS_15));
    TEST_ASSERT_TRUE (osdp_scb_has_mac(OSDP_SCS_16));
    TEST_ASSERT_TRUE (osdp_scb_has_mac(OSDP_SCS_17));
    TEST_ASSERT_TRUE (osdp_scb_has_mac(OSDP_SCS_18));
    TEST_ASSERT_FALSE(osdp_scb_has_mac(0x19));   /* unallocated */

    TEST_ASSERT_FALSE(osdp_scb_is_encrypted(OSDP_SCS_15));
    TEST_ASSERT_FALSE(osdp_scb_is_encrypted(OSDP_SCS_16));
    TEST_ASSERT_TRUE (osdp_scb_is_encrypted(OSDP_SCS_17));
    TEST_ASSERT_TRUE (osdp_scb_is_encrypted(OSDP_SCS_18));
}

/* ---- Symmetry: build → decode → build is byte-identical -----------------*/

static void test_build_decode_build_is_symmetric(void)
{
    static const uint8_t payloads[][8] = {
        {0},
        { 0x01 },
        { 0xAA, 0xBB, 0xCC, 0xDD },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
    };
    static const size_t plens[] = { 0, 1, 4, 8 };

    for (size_t pi = 0; pi < sizeof(plens) / sizeof(plens[0]); pi++) {
        for (int crc = 0; crc <= 1; crc++) {
            for (int rpl = 0; rpl <= 1; rpl++) {
                for (uint8_t addr = 0; addr <= OSDP_BROADCAST_ADDR; addr += 0x1Fu) {
                    osdp_frame_t f = {0};
                    f.address     = addr;
                    f.reply       = (rpl != 0);
                    f.sequence    = (uint8_t)(pi & OSDP_CTRL_SQN_MASK);
                    f.integrity   = crc ? OSDP_INTEGRITY_CRC
                                        : OSDP_INTEGRITY_CHECKSUM;
                    f.code        = (uint8_t)(0x60u + (uint8_t)pi);
                    f.payload     = (plens[pi] > 0) ? payloads[pi] : NULL;
                    f.payload_len = plens[pi];

                    uint8_t buf1[64], buf2[64];
                    size_t n1 = 0, n2 = 0;
                    TEST_ASSERT_EQUAL(OSDP_OK,
                                      osdp_frame_build(&f, buf1, sizeof(buf1), &n1));

                    osdp_frame_t got = {0};
                    TEST_ASSERT_EQUAL(OSDP_OK,
                                      osdp_frame_decode(buf1, n1, &got));
                    TEST_ASSERT_EQUAL(OSDP_OK,
                                      osdp_frame_build(&got, buf2, sizeof(buf2), &n2));
                    TEST_ASSERT_EQUAL_size_t(n1, n2);
                    TEST_ASSERT_EQUAL_MEMORY(buf1, buf2, n1);
                }
            }
        }
    }
}

int main(void)
{
    UNITY_BEGIN();
    /* Decode happy paths. */
    RUN_TEST(test_decode_minimal_poll_checksum);
    RUN_TEST(test_decode_minimal_poll_crc);
    RUN_TEST(test_decode_reply_flag_set);
    RUN_TEST(test_decode_broadcast_address);
    RUN_TEST(test_decode_with_payload_round_trip);
    RUN_TEST(test_decode_with_scb_no_data);
    RUN_TEST(test_decode_with_scb_data_round_trip);
    RUN_TEST(test_decode_then_rebuild_produces_byte_identical_output);
    /* Decode error paths. */
    RUN_TEST(test_decode_rejects_null_args);
    RUN_TEST(test_decode_rejects_truncated_buffer);
    RUN_TEST(test_decode_rejects_bad_som);
    RUN_TEST(test_decode_rejects_bad_length_field);
    RUN_TEST(test_decode_rejects_reserved_ctrl_bits);
    RUN_TEST(test_decode_rejects_bad_crc);
    RUN_TEST(test_decode_rejects_bad_checksum);
    RUN_TEST(test_decode_rejects_scb_length_below_min);
    RUN_TEST(test_decode_rejects_scb_overflowing_frame);
    /* Build error paths. */
    RUN_TEST(test_build_rejects_null_args);
    RUN_TEST(test_build_rejects_buffer_too_small);
    RUN_TEST(test_build_rejects_address_out_of_range);
    RUN_TEST(test_build_rejects_sequence_out_of_range);
    RUN_TEST(test_build_rejects_inconsistent_scb);
    /* SCS MAC handling. */
    RUN_TEST(test_decode_splits_mac_for_scs_15_frame);
    RUN_TEST(test_decode_handles_scs_15_with_zero_inner_payload);
    RUN_TEST(test_decode_rejects_scs_17_with_room_for_mac_only);
    RUN_TEST(test_build_rejects_missing_mac_for_scs_15);
    RUN_TEST(test_build_rejects_unexpected_mac_for_scs_11);
    RUN_TEST(test_build_rejects_mac_when_scb_absent);
    RUN_TEST(test_scs_helpers_classify_correctly);
    /* Symmetry. */
    RUN_TEST(test_build_decode_build_is_symmetric);
    return UNITY_END();
}
