// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* OSDP-SC2 frame wrap/unwrap known-answer + round-trip tests.
 *
 * The wrap KATs reproduce the two full operational frames from the
 * OSDP-SC2 annex sample session (an encrypted POLL at counter 0 and the
 * encrypted ACK reply at counter 1), byte-for-byte including the GCM
 * tag and CRC. Passing them pins the AES-256-GCM path, the AAD (7-byte
 * header incl. security block), the nonce derivation, and the shared
 * counter together against an independent implementation. */

#include "osdp/osdp_crc.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_sc2.h"
#include "sc2_test_crypto.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static const uint8_t kCUID[OSDP_SC2_CUID_LEN] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
};
static const uint8_t kSEnc[OSDP_SC2_KEY_LEN] = {
    0x11, 0x50, 0x9C, 0x6D, 0x52, 0x76, 0x21, 0x68,
    0x11, 0xB0, 0x5A, 0xC7, 0x50, 0x1F, 0x6E, 0x82,
    0x0F, 0x34, 0x74, 0x5D, 0xFD, 0x17, 0xB0, 0x45,
    0x79, 0x8F, 0xB5, 0x2E, 0xA4, 0x63, 0x47, 0x8F,
};
static const uint8_t kSNonce[OSDP_SC2_KEY_LEN] = {
    0x59, 0x0D, 0xFE, 0x02, 0xA5, 0x47, 0x9B, 0xE0,
    0x92, 0x61, 0xA5, 0xF4, 0x2D, 0xC9, 0x7A, 0x18,
    0x97, 0x37, 0x7E, 0x2B, 0x0D, 0xEC, 0x09, 0x1F,
    0x21, 0x29, 0x53, 0x23, 0x75, 0x5F, 0xCE, 0xA7,
};

/* Annex operational frames (whole packets, no marking byte). */
static const uint8_t kPollFrame[] = {
    0x53, 0x00, 0x1A, 0x00, 0x0D, 0x02, 0x27, 0x80,
    0x5D, 0x77, 0xA7, 0xE9, 0xB3, 0xDC, 0x46, 0x1E,
    0x72, 0xD4, 0x85, 0x8D, 0x4A, 0x28, 0x69, 0xEE,
    0xDE, 0x35,
};
static const uint8_t kAckFrame[] = {
    0x53, 0x80, 0x1A, 0x00, 0x0D, 0x02, 0x28, 0x77,
    0x6D, 0xB5, 0x9A, 0x9E, 0xED, 0x41, 0x36, 0x2D,
    0xEC, 0xC2, 0xBC, 0x94, 0x63, 0x89, 0xEE, 0x6C,
    0x2F, 0xC1,
};

#define OSDP_CMD_POLL  0x60u
#define OSDP_REPLY_ACK 0x40u

static void session_init(osdp_sc2_session_t *s)
{
    osdp_sc2_session_init(s);
    (void)memcpy(s->keys.s_enc,   kSEnc,   OSDP_SC2_KEY_LEN);
    (void)memcpy(s->keys.s_nonce, kSNonce, OSDP_SC2_KEY_LEN);
    (void)memcpy(s->cuid,         kCUID,   OSDP_SC2_CUID_LEN);
    s->counter     = 0;
    s->established = true;
}

/* ---- Wrap KATs ---------------------------------------------------------*/

static void test_wrap_poll_matches_annex_frame(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    osdp_sc2_session_t s;
    session_init(&s);

    osdp_frame_t tmpl = {0};
    tmpl.address     = 0x00;
    tmpl.sequence    = 1;              /* CTRL 0x0D → SQN 1 */
    tmpl.integrity   = OSDP_INTEGRITY_CRC;
    tmpl.has_scb     = true;
    tmpl.scb_length  = OSDP_SCB_MIN_LEN;
    tmpl.scb_type    = OSDP_SCS_27;
    tmpl.code        = OSDP_CMD_POLL;
    tmpl.payload_len = 0;

    uint8_t out[64];
    size_t  n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_wrap_frame(c, &s, &tmpl, out, sizeof(out), &n));

    /* out includes the leading 0xFF marking byte; the frame follows. */
    TEST_ASSERT_EQUAL_size_t(OSDP_FRAME_MARK_LEN + sizeof(kPollFrame), n);
    TEST_ASSERT_EQUAL_HEX8(OSDP_FRAME_MARK, out[0]);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kPollFrame, &out[OSDP_FRAME_MARK_LEN],
                                 sizeof(kPollFrame));
    TEST_ASSERT_EQUAL_UINT32(1u, s.counter);   /* advanced past 0 */
}

static void test_wrap_ack_matches_annex_frame(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    osdp_sc2_session_t s;
    session_init(&s);
    s.counter = 1;                     /* the ACK is sent at counter 1 */

    osdp_frame_t tmpl = {0};
    tmpl.address     = 0x00;
    tmpl.reply       = true;
    tmpl.sequence    = 1;
    tmpl.integrity   = OSDP_INTEGRITY_CRC;
    tmpl.has_scb     = true;
    tmpl.scb_length  = OSDP_SCB_MIN_LEN;
    tmpl.scb_type    = OSDP_SCS_28;
    tmpl.code        = OSDP_REPLY_ACK;
    tmpl.payload_len = 0;

    uint8_t out[64];
    size_t  n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_wrap_frame(c, &s, &tmpl, out, sizeof(out), &n));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kAckFrame, &out[OSDP_FRAME_MARK_LEN],
                                 sizeof(kAckFrame));
    TEST_ASSERT_EQUAL_UINT32(2u, s.counter);
}

/* ---- Unwrap KATs -------------------------------------------------------*/

static void test_unwrap_poll_recovers_code(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    osdp_sc2_session_t s;
    session_init(&s);

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_decode(kPollFrame, sizeof(kPollFrame), &f));

    uint8_t code = 0, data[32];
    size_t  data_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_unwrap_frame(c, &s, &f, &code, data, sizeof(data), &data_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, code);
    TEST_ASSERT_EQUAL_size_t(0, data_len);
    TEST_ASSERT_EQUAL_UINT32(1u, s.counter);
}

static void test_unwrap_ack_recovers_code(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    osdp_sc2_session_t s;
    session_init(&s);
    s.counter = 1;

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_decode(kAckFrame, sizeof(kAckFrame), &f));

    uint8_t code = 0, data[32];
    size_t  data_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_unwrap_frame(c, &s, &f, &code, data, sizeof(data), &data_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, code);
    TEST_ASSERT_EQUAL_size_t(0, data_len);
    TEST_ASSERT_EQUAL_UINT32(2u, s.counter);
}

static void test_unwrap_rejects_tampered_tag(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    osdp_sc2_session_t s;
    session_init(&s);

    uint8_t tampered[sizeof(kPollFrame)];
    (void)memcpy(tampered, kPollFrame, sizeof(kPollFrame));
    tampered[10] ^= 0x01u;             /* flip a tag byte */

    /* Recompute the CRC so the frame still decodes; this isolates the
     * failure to the GCM tag check rather than a CRC mismatch. */
    osdp_frame_t f;
    const uint16_t crc = osdp_crc16(tampered, sizeof(tampered) - 2u);
    tampered[sizeof(tampered) - 2u] = (uint8_t)(crc & 0xFFu);
    tampered[sizeof(tampered) - 1u] = (uint8_t)((crc >> 8) & 0xFFu);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_decode(tampered, sizeof(tampered), &f));

    uint8_t code = 0, data[32];
    size_t  data_len = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CRC,
        osdp_sc2_unwrap_frame(c, &s, &f, &code, data, sizeof(data), &data_len));
}

/* ---- Round-trip (with real data payloads, both SCB variants) -----------*/

static void roundtrip(uint8_t scb_type, const uint8_t *payload, size_t plen)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    osdp_sc2_session_t tx, rx;
    session_init(&tx);
    session_init(&rx);

    osdp_frame_t tmpl = {0};
    tmpl.address     = 0x03;
    tmpl.integrity   = OSDP_INTEGRITY_CRC;
    tmpl.has_scb     = true;
    tmpl.scb_length  = OSDP_SCB_MIN_LEN;
    tmpl.scb_type    = scb_type;
    tmpl.code        = 0x6A;
    tmpl.payload     = plen ? payload : NULL;
    tmpl.payload_len = plen;

    uint8_t wire[128];
    size_t  n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_wrap_frame(c, &tx, &tmpl, wire, sizeof(wire), &n));

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_decode(&wire[OSDP_FRAME_MARK_LEN], n - OSDP_FRAME_MARK_LEN,
                          &f));

    uint8_t code = 0, got[64];
    size_t  got_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_unwrap_frame(c, &rx, &f, &code, got, sizeof(got), &got_len));
    TEST_ASSERT_EQUAL_HEX8(0x6A, code);
    TEST_ASSERT_EQUAL_size_t(plen, got_len);
    if (plen) {
        TEST_ASSERT_EQUAL_HEX8_ARRAY(payload, got, plen);
    }
    /* Both peers advanced their shared counter in lockstep. */
    TEST_ASSERT_EQUAL_UINT32(tx.counter, rx.counter);
}

static void test_roundtrip_encrypted_with_data(void)
{
    static const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01 };
    roundtrip(OSDP_SCS_27, payload, sizeof(payload));
}

static void test_roundtrip_authonly_with_data(void)
{
    static const uint8_t payload[] = { 0x11, 0x22, 0x33 };
    roundtrip(OSDP_SCS_25, payload, sizeof(payload));
}

static void test_wrap_rejects_unestablished_session(void)
{
    const osdp_sc2_crypto_t *c = sc2_test_crypto();
    osdp_sc2_session_t s;
    osdp_sc2_session_init(&s);   /* not established */

    osdp_frame_t tmpl = {0};
    tmpl.address    = 0;
    tmpl.integrity  = OSDP_INTEGRITY_CRC;
    tmpl.has_scb    = true;
    tmpl.scb_length = OSDP_SCB_MIN_LEN;
    tmpl.scb_type   = OSDP_SCS_27;
    tmpl.code       = OSDP_CMD_POLL;

    uint8_t out[64]; size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc2_wrap_frame(c, &s, &tmpl, out, sizeof(out), &n));
}

/* ---- Sizing ---------------------------------------------------------------
 *
 * Same contract as osdp_sc_max_payload, checked the same way: ask the helper,
 * then confirm against what osdp_sc2_wrap_frame really accepts. SC2 has no
 * ciphertext expansion (GCM is a stream cipher), so the interesting part is
 * the asymmetry — a RECEIVE buffer needs one byte more than the payload,
 * because GCM recovers code||data as a single unit. */
static void test_sc2_max_payload_is_exactly_what_wrap_accepts(void)
{
    static uint8_t body[512];
    (void)memset(body, 0x3C, sizeof(body));

    const size_t caps[] = { 40, 64, 100, 128, 256, 400 };

    for (size_t c = 0; c < sizeof(caps) / sizeof(caps[0]); c++) {
        osdp_frame_t tmpl = {0};
        tmpl.address     = 0x03;
        tmpl.integrity   = OSDP_INTEGRITY_CRC;
        tmpl.has_scb     = true;
        tmpl.scb_length  = OSDP_SCB_MIN_LEN;
        tmpl.scb_type    = OSDP_SCS_27;
        tmpl.code        = OSDP_CMD_POLL;

        size_t max = 0;
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc2_max_payload(&tmpl, caps[c], &max));
        TEST_ASSERT_LESS_THAN_size_t(sizeof(body), max);
        if (max == 0) {
            continue;
        }

        uint8_t out[512];
        size_t  out_len = 0;

        osdp_sc2_session_t s_max;
        session_init(&s_max);
        tmpl.payload     = body;
        tmpl.payload_len = max;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc2_wrap_frame(sc2_test_crypto(), &s_max, &tmpl,
                                out, caps[c], &out_len));
        TEST_ASSERT_LESS_OR_EQUAL_size_t(caps[c], out_len);

        osdp_sc2_session_t s_over;
        session_init(&s_over);
        tmpl.payload_len = max + 1U;
        TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
            osdp_sc2_wrap_frame(sc2_test_crypto(), &s_over, &tmpl,
                                out, caps[c], &out_len));
    }
}

/* Pins the documented receive-side rule: plain_cap must hold code||data, so
 * a buffer of exactly payload_len is one byte short. Getting this wrong is
 * an unwrap that fails only on the largest messages — the worst kind of
 * intermittent — so it is worth an explicit test rather than a comment. */
static void test_sc2_unwrap_needs_one_byte_more_than_the_payload(void)
{
    static const uint8_t body[24] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    };

    osdp_sc2_session_t tx, rx;
    session_init(&tx);
    session_init(&rx);

    osdp_frame_t tmpl = {0};
    tmpl.address     = 0x03;
    tmpl.integrity   = OSDP_INTEGRITY_CRC;
    tmpl.has_scb     = true;
    tmpl.scb_length  = OSDP_SCB_MIN_LEN;
    tmpl.scb_type    = OSDP_SCS_27;
    tmpl.code        = OSDP_CMD_POLL;
    tmpl.payload     = body;
    tmpl.payload_len = sizeof(body);

    uint8_t wire[128];
    size_t  n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_wrap_frame(sc2_test_crypto(), &tx, &tmpl, wire, sizeof(wire), &n));

    osdp_frame_t f;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_decode(&wire[OSDP_FRAME_MARK_LEN], n - OSDP_FRAME_MARK_LEN, &f));

    uint8_t code = 0;
    uint8_t got[sizeof(body) + 1U];
    size_t  got_len = 0;

    /* Exactly payload_len is NOT enough — one byte belongs to the code. */
    osdp_sc2_session_t rx_tight = rx;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
        osdp_sc2_unwrap_frame(sc2_test_crypto(), &rx_tight, &f, &code,
                              got, sizeof(body), &got_len));

    /* payload_len + 1 succeeds and yields the data, code stripped. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_unwrap_frame(sc2_test_crypto(), &rx, &f, &code,
                              got, sizeof(body) + 1U, &got_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, code);
    TEST_ASSERT_EQUAL_size_t(sizeof(body), got_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(body, got, sizeof(body));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sc2_max_payload_is_exactly_what_wrap_accepts);
    RUN_TEST(test_sc2_unwrap_needs_one_byte_more_than_the_payload);
    RUN_TEST(test_wrap_poll_matches_annex_frame);
    RUN_TEST(test_wrap_ack_matches_annex_frame);
    RUN_TEST(test_unwrap_poll_recovers_code);
    RUN_TEST(test_unwrap_ack_recovers_code);
    RUN_TEST(test_unwrap_rejects_tampered_tag);
    RUN_TEST(test_roundtrip_encrypted_with_data);
    RUN_TEST(test_roundtrip_authonly_with_data);
    RUN_TEST(test_wrap_rejects_unestablished_session);
    return UNITY_END();
}
