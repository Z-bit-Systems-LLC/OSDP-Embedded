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

int main(void)
{
    UNITY_BEGIN();
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
