// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Tests for osdp_sc_wrap_frame and osdp_sc_unwrap_frame.
 *
 * Strategy: drive both routines with a fully-populated session struct
 * (no actual handshake; we just memset known keys and ICV) and verify
 * that:
 *
 *   - wrap → unwrap round-trips both SCS_15 (plain+MAC) and SCS_17
 *     (encrypted+MAC) frames byte-cleanly with the original plaintext
 *     intact.
 *   - The session's MAC chain advances on every successful wrap and
 *     unwrap, mirroring across the two endpoints.
 *   - MAC tampering is detected (BAD_CRC).
 *   - Calling wrap/unwrap on an unestablished session is rejected.
 *   - Calling them on non-SCS_15..18 SCB types is rejected. */

#include "osdp/osdp_crc.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc_crypto.h"
#include "sc_test_aes.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* Initialize an osdp_sc_session_t with deterministic keys + ICV so
 * the two simulated peers can be set up identically. */
static void init_session(osdp_sc_session_t *s)
{
    osdp_sc_session_init(s);
    for (size_t i = 0; i < OSDP_SC_KEY_LEN; i++) {
        s->keys.s_enc [i] = (uint8_t)(0xA0u + i);
        s->keys.s_mac1[i] = (uint8_t)(0xB0u + i);
        s->keys.s_mac2[i] = (uint8_t)(0xC0u + i);
    }
    for (size_t i = 0; i < OSDP_SC_MAC_LEN; i++) {
        s->last_outbound_mac[i] = (uint8_t)(0x10u + i);
        s->last_inbound_mac [i] = (uint8_t)(0x20u + i);
    }
    s->established = true;
}

/* For a clean wrap→unwrap round-trip, the receiver's
 * `last_outbound_mac` must equal the sender's `last_inbound_mac` (so
 * it computes the same MAC ICV) and vice versa. Set up two structs
 * that mirror each other: peer A sends to peer B, then B sends to A. */
static void make_paired_sessions(osdp_sc_session_t *a, osdp_sc_session_t *b)
{
    init_session(a);
    /* B has the same keys but its inbound/outbound MACs are swapped
     * relative to A's, since "what A sent" == "what B received". */
    osdp_sc_session_init(b);
    (void)memcpy(&b->keys, &a->keys, sizeof(a->keys));
    (void)memcpy(b->last_outbound_mac, a->last_inbound_mac,  OSDP_SC_MAC_LEN);
    (void)memcpy(b->last_inbound_mac,  a->last_outbound_mac, OSDP_SC_MAC_LEN);
    b->established = true;
}

static void build_template(osdp_frame_t *t, uint8_t scb_type,
                           uint8_t code,
                           const uint8_t *payload, size_t payload_len)
{
    (void)memset(t, 0, sizeof(*t));
    t->address      = 0x05;
    t->reply        = false;
    t->sequence     = 1;
    t->integrity    = OSDP_INTEGRITY_CRC;
    t->has_scb      = true;
    t->scb_length   = OSDP_SCB_MIN_LEN;
    t->scb_type     = scb_type;
    t->code         = code;
    t->payload      = payload;
    t->payload_len  = payload_len;
}

/* Decode the SOM-aligned frame inside wrap output, skipping the
 * spec-5.7 marking byte(s) osdp_frame_build prepends ahead of the SOM. */
static osdp_status_t decode_wire(const uint8_t *wire, size_t wire_len,
                                 osdp_frame_t *out)
{
    if (wire_len < OSDP_FRAME_MARK_LEN) {
        return OSDP_ERR_TRUNCATED;
    }
    return osdp_frame_decode(wire + OSDP_FRAME_MARK_LEN,
                             wire_len - OSDP_FRAME_MARK_LEN, out);
}

static void test_wrap_unwrap_scs15_round_trip(void)
{
    /* SCS_15 is "no data + MAC" — the canonical case is POLL,
     * which has an empty payload. */
    osdp_sc_session_t a, b;
    make_paired_sessions(&a, &b);

    osdp_frame_t tmpl;
    build_template(&tmpl, OSDP_SCS_15, 0x60, NULL, 0);

    uint8_t wire[64];
    size_t wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &a, &tmpl,
                           wire, sizeof(wire), &wire_len));

    /* Decode the wire bytes from B's side and verify MAC. */
    osdp_frame_t decoded;
    TEST_ASSERT_EQUAL(OSDP_OK, decode_wire(wire, wire_len, &decoded));
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_15, decoded.scb_type);

    uint8_t recovered[64];
    size_t recovered_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &b, &decoded,
                             recovered, sizeof(recovered), &recovered_len));
    TEST_ASSERT_EQUAL_size_t(0, recovered_len);

    /* Both sides' MAC chains advanced to the same value: A's
     * last_outbound == B's last_inbound. */
    TEST_ASSERT_EQUAL_MEMORY(a.last_outbound_mac, b.last_inbound_mac,
                             OSDP_SC_MAC_LEN);
}

/* Regression: SCS_15/16 carry only a MAC; passing a non-empty
 * payload with SCS_15 used to silently emit a malformed frame that
 * OSDP.Net's ACU rejected, tearing the session down. The wrap step
 * now upgrades SCS_15→SCS_17 and SCS_16→SCS_18 when the caller
 * passes data — see wrap.c. */
static void test_wrap_upgrades_scs15_to_scs17_when_payload_nonempty(void)
{
    osdp_sc_session_t a, b;
    make_paired_sessions(&a, &b);

    static const uint8_t cmd_payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    osdp_frame_t tmpl;
    build_template(&tmpl, OSDP_SCS_15, 0x60, cmd_payload, sizeof(cmd_payload));

    uint8_t wire[64];
    size_t wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &a, &tmpl,
                           wire, sizeof(wire), &wire_len));

    osdp_frame_t decoded;
    TEST_ASSERT_EQUAL(OSDP_OK, decode_wire(wire, wire_len, &decoded));
    /* The SCB type on the wire must be SCS_17 — the data-bearing
     * variant — not the SCS_15 we passed in. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_17, decoded.scb_type);
    /* And the payload bytes must be encrypted (not the plaintext). */
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
        memcmp(cmd_payload, decoded.payload, sizeof(cmd_payload)),
        "payload was not encrypted on the wire");

    uint8_t recovered[64];
    size_t recovered_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &b, &decoded,
                             recovered, sizeof(recovered), &recovered_len));
    TEST_ASSERT_EQUAL_size_t(sizeof(cmd_payload), recovered_len);
    TEST_ASSERT_EQUAL_MEMORY(cmd_payload, recovered, sizeof(cmd_payload));
}

/* Mirror of the above for the reply direction (SCS_16 → SCS_18
 * when a data-bearing event reply rides on top of an empty POLL). */
static void test_wrap_upgrades_scs16_to_scs18_when_payload_nonempty(void)
{
    osdp_sc_session_t a, b;
    make_paired_sessions(&a, &b);

    /* Simulate a KEYPAD reply: code 0x53, 5-byte payload. */
    static const uint8_t reply_payload[] = { 0x00, 0x04, '1', '2', '#' };
    osdp_frame_t tmpl;
    build_template(&tmpl, OSDP_SCS_16, 0x53,
                   reply_payload, sizeof(reply_payload));
    tmpl.reply = true;

    uint8_t wire[64];
    size_t wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &a, &tmpl,
                           wire, sizeof(wire), &wire_len));

    osdp_frame_t decoded;
    TEST_ASSERT_EQUAL(OSDP_OK, decode_wire(wire, wire_len, &decoded));
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_18, decoded.scb_type);

    uint8_t recovered[64];
    size_t recovered_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &b, &decoded,
                             recovered, sizeof(recovered), &recovered_len));
    TEST_ASSERT_EQUAL_size_t(sizeof(reply_payload), recovered_len);
    TEST_ASSERT_EQUAL_MEMORY(reply_payload, recovered, sizeof(reply_payload));
}

static void test_wrap_unwrap_scs17_encrypted_round_trip(void)
{
    osdp_sc_session_t a, b;
    make_paired_sessions(&a, &b);

    static const uint8_t cmd_payload[] = "GET_STATUS";
    osdp_frame_t tmpl;
    build_template(&tmpl, OSDP_SCS_17, 0x60, cmd_payload, 10);

    uint8_t wire[64];
    size_t wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &a, &tmpl,
                           wire, sizeof(wire), &wire_len));

    /* The on-wire payload bytes (between code and MAC) must NOT
     * match the plaintext — they should have been encrypted. The
     * decoded payload length should be 16 (one full pad block, since
     * the plaintext is 10 bytes). */
    osdp_frame_t decoded;
    TEST_ASSERT_EQUAL(OSDP_OK, decode_wire(wire, wire_len, &decoded));
    TEST_ASSERT_EQUAL_size_t(16, decoded.payload_len);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0,
        memcmp(cmd_payload, decoded.payload, 10),
        "payload was not encrypted on the wire");

    uint8_t recovered[64];
    size_t recovered_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &b, &decoded,
                             recovered, sizeof(recovered), &recovered_len));
    TEST_ASSERT_EQUAL_size_t(10, recovered_len);
    TEST_ASSERT_EQUAL_MEMORY(cmd_payload, recovered, 10);
}

static void test_chained_wraps_and_unwraps_advance_sessions_in_lockstep(void)
{
    /* Send three SCS_17 frames from A→B, with each side advancing
     * its MAC chain on every operation. After each round, the chain
     * states must remain mirrored. */
    osdp_sc_session_t a, b;
    make_paired_sessions(&a, &b);

    for (int i = 0; i < 3; i++) {
        const uint8_t payload[] = { (uint8_t)i, 0xAA, 0xBB };
        osdp_frame_t tmpl;
        build_template(&tmpl, OSDP_SCS_17, 0x60, payload, sizeof(payload));

        uint8_t wire[64];
        size_t wire_len = 0;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &a, &tmpl,
                               wire, sizeof(wire), &wire_len));
        osdp_frame_t decoded;
        TEST_ASSERT_EQUAL(OSDP_OK, decode_wire(wire, wire_len, &decoded));
        uint8_t recovered[64];
        size_t recovered_len = 0;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &b, &decoded,
                                 recovered, sizeof(recovered), &recovered_len));
        TEST_ASSERT_EQUAL_MEMORY(payload, recovered, sizeof(payload));

        /* A's outbound is B's inbound after each round. */
        TEST_ASSERT_EQUAL_MEMORY(a.last_outbound_mac, b.last_inbound_mac,
                                 OSDP_SC_MAC_LEN);
        /* The other direction's chain values stay equal too (we
         * haven't touched them). */
        TEST_ASSERT_EQUAL_MEMORY(a.last_inbound_mac, b.last_outbound_mac,
                                 OSDP_SC_MAC_LEN);
    }
}

static void test_unwrap_rejects_tampered_mac(void)
{
    osdp_sc_session_t a, b;
    make_paired_sessions(&a, &b);

    static const uint8_t payload[] = { 0xDE, 0xAD };
    osdp_frame_t tmpl;
    build_template(&tmpl, OSDP_SCS_15, 0x60, payload, sizeof(payload));

    uint8_t wire[64];
    size_t wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &a, &tmpl,
                           wire, sizeof(wire), &wire_len));

    /* Locate the MAC in the wire bytes and flip a bit. CRC then needs
     * recomputing or the frame won't decode at all. */
    const size_t crc_offset = wire_len - 2;
    const size_t mac_offset = crc_offset - OSDP_FRAME_MAC_LEN;
    wire[mac_offset] ^= 0x01;
    /* Recompute CRC over the frame only — exclude the leading marking
     * byte(s), matching what the decoder checks. */
    const uint16_t crc = osdp_crc16(wire + OSDP_FRAME_MARK_LEN,
                                    crc_offset - OSDP_FRAME_MARK_LEN);
    wire[crc_offset]     = (uint8_t)(crc & 0xFFu);
    wire[crc_offset + 1] = (uint8_t)((crc >> 8) & 0xFFu);

    osdp_frame_t decoded;
    TEST_ASSERT_EQUAL(OSDP_OK, decode_wire(wire, wire_len, &decoded));
    uint8_t recovered[64];
    size_t recovered_len = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CRC,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &b, &decoded,
                             recovered, sizeof(recovered), &recovered_len));
}

static void test_wrap_rejects_unestablished_session(void)
{
    osdp_sc_session_t s;
    init_session(&s);
    s.established = false;

    osdp_frame_t tmpl;
    build_template(&tmpl, OSDP_SCS_15, 0x60, NULL, 0);
    uint8_t wire[32]; size_t wire_len;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &s, &tmpl,
                           wire, sizeof(wire), &wire_len));
}

static void test_wrap_rejects_non_scs_15_through_18(void)
{
    osdp_sc_session_t s;
    init_session(&s);

    osdp_frame_t tmpl;
    build_template(&tmpl, OSDP_SCS_11, 0x76, NULL, 0);
    uint8_t wire[32]; size_t wire_len;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &s, &tmpl,
                           wire, sizeof(wire), &wire_len));
}

static void test_unwrap_rejects_non_scs_15_through_18(void)
{
    /* Build a frame manually with scb_type = SCS_11 and try to
     * unwrap it. */
    osdp_sc_session_t s;
    init_session(&s);

    /* osdp_frame_t with SCS_11. unwrap should reject. */
    osdp_frame_t f = {0};
    f.address    = 0x05;
    f.has_scb    = true;
    f.scb_length = OSDP_SCB_MIN_LEN;
    f.scb_type   = OSDP_SCS_11;
    f.integrity  = OSDP_INTEGRITY_CRC;
    f.code       = 0x76;
    /* mac fields zero — required to be rejected before we look at them. */

    uint8_t pt[16]; size_t pt_len;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &s, &f,
                             pt, sizeof(pt), &pt_len));
}

/* ---- Known-answer -------------------------------------------------------
 *
 * Every other wrap test here is a round-trip, which only proves wrap and
 * unwrap agree with each other — both could be wrong in the same way and
 * still pass. These pin the actual wire bytes.
 *
 * The vectors were captured from the implementation that encrypted through a
 * private 256-byte scratch, immediately before it was changed to encrypt
 * directly into the output buffer, and verified byte-identical across payload
 * lengths 0/1/15/16/17/31/32/100/200 (every AES-block boundary) plus the
 * rolling MAC chain. Keeping two of them means any future change to where or
 * how the ciphertext is produced has to reproduce the same frame, not merely
 * remain self-consistent. */
static void test_wrap_scs17_matches_known_bytes(void)
{
    /* 16-byte payload: pads to two AES blocks, since spec D.4.5 always adds
     * at least the 0x80 marker — the case most likely to break under a
     * padding change. */
    static const uint8_t kExpected[] = {
        0xFF, 0x53, 0x05, 0x2E, 0x00, 0x0E, 0x02, 0x17, 0x6B, 0x2F, 0x21,
        0x69, 0xA4, 0x31, 0x22, 0x31, 0x30, 0xE7, 0x67, 0x1A, 0xFA, 0x47,
        0x65, 0x3E, 0x07, 0x11, 0xD2, 0x71, 0x1F, 0xFF, 0x4F, 0x93, 0x40,
        0x91, 0x8C, 0x0F, 0xC3, 0xE8, 0x80, 0xE2, 0x43, 0x80, 0x6E, 0xAA,
        0x07, 0x25, 0x17,
    };
    static const uint8_t kExpectedMac[OSDP_SC_MAC_LEN] = {
        0x80, 0x6E, 0xAA, 0x07, 0x73, 0x33, 0xAB, 0x37,
        0xEF, 0x4B, 0x0A, 0x40, 0xAE, 0x67, 0x7A, 0xD4,
    };

    uint8_t body[16];
    for (size_t i = 0; i < sizeof(body); i++) {
        body[i] = (uint8_t)(i * 7u);
    }

    osdp_sc_session_t s;
    init_session(&s);

    osdp_frame_t t;
    (void)memset(&t, 0, sizeof(t));
    t.address     = 0x05;
    t.sequence    = 2;
    t.integrity   = OSDP_INTEGRITY_CRC;
    t.has_scb     = true;
    t.scb_length  = OSDP_SCB_MIN_LEN;
    t.scb_type    = OSDP_SCS_17;
    t.code        = 0x6B;               /* osdp_TEXT */
    t.payload     = body;
    t.payload_len = sizeof(body);

    uint8_t out[128];
    size_t  n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &s, &t,
                           out, sizeof(out), &n));

    TEST_ASSERT_EQUAL_size_t(sizeof(kExpected), n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kExpected, out, sizeof(kExpected));
    /* The rolling chain must advance identically too — a wrap that produced
     * the right bytes but the wrong outbound MAC would desync the next
     * message instead of failing here. */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kExpectedMac, s.last_outbound_mac,
                                 OSDP_SC_MAC_LEN);
}

/* An empty payload takes the SCS_17→SCS_15 downgrade path and carries no
 * ciphertext at all — the branch the in-place encryption skips entirely. */
static void test_wrap_empty_payload_matches_known_bytes(void)
{
    static const uint8_t kExpected[] = {
        0xFF, 0x53, 0x05, 0x0E, 0x00, 0x0E, 0x02, 0x15, 0x6B, 0x75, 0x67,
        0x29, 0xA9, 0x3D, 0xDC,
    };

    osdp_sc_session_t s;
    init_session(&s);

    osdp_frame_t t;
    (void)memset(&t, 0, sizeof(t));
    t.address     = 0x05;
    t.sequence    = 2;
    t.integrity   = OSDP_INTEGRITY_CRC;
    t.has_scb     = true;
    t.scb_length  = OSDP_SCB_MIN_LEN;
    t.scb_type    = OSDP_SCS_17;        /* coerced to SCS_15 when empty */
    t.code        = 0x6B;
    t.payload_len = 0;

    uint8_t out[64];
    size_t  n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &s, &t,
                           out, sizeof(out), &n));

    TEST_ASSERT_EQUAL_size_t(sizeof(kExpected), n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kExpected, out, sizeof(kExpected));
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_15, out[OSDP_FRAME_MARK_LEN + 6]);
}

/* ---- Sizing ---------------------------------------------------------------
 *
 * osdp_sc_max_payload tells a caller how much plaintext fits in one packet.
 * It has to be exactly right in both directions: under-report and every
 * fragment wastes capacity, over-report and the wrap fails at send time.
 *
 * The spec D.4.5 pad rule is the trap — padding always adds at least the
 * 0x80 marker and then rounds to an AES block, so a 16-byte payload takes 32
 * bytes of ciphertext. Rather than restate that arithmetic here (which would
 * only prove the test agrees with itself), each case asks the helper and then
 * checks the answer against what osdp_sc_wrap_frame actually accepts. */
static void test_sc_max_payload_is_exactly_what_wrap_accepts(void)
{
    static uint8_t body[512];
    (void)memset(body, 0x5A, sizeof(body));

    /* A spread of capacities, deliberately including values that do not land
     * on an AES block boundary once framing overhead is removed. */
    const size_t caps[] = { 32, 48, 55, 64, 100, 128, 200, 333, 512 };

    for (size_t c = 0; c < sizeof(caps) / sizeof(caps[0]); c++) {
        osdp_sc_session_t s;
        init_session(&s);

        osdp_frame_t f;
        (void)memset(&f, 0, sizeof(f));
        f.address    = 0x05;
        f.sequence   = 1;
        f.integrity  = OSDP_INTEGRITY_CRC;
        f.has_scb    = true;
        f.scb_length = OSDP_SCB_MIN_LEN;
        f.scb_type   = OSDP_SCS_17;    /* encrypted: padding applies */
        f.code       = 0x6B;           /* osdp_TEXT */

        size_t max = 0;
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_max_payload(&f, caps[c], &max));
        TEST_ASSERT_LESS_THAN_size_t(sizeof(body), max);
        if (max == 0) {
            continue;   /* capacity too small for any payload — valid answer */
        }

        uint8_t out[512];
        size_t  out_len = 0;

        /* The reported maximum must wrap successfully into that capacity. */
        osdp_sc_session_t s_max = s;
        f.payload     = body;
        f.payload_len = max;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &s_max, &f,
                               out, caps[c], &out_len));
        TEST_ASSERT_LESS_OR_EQUAL_size_t(caps[c], out_len);

        /* One byte more must not. This is where an off-by-one in the pad
         * rule shows up: max+1 crosses into another 16-byte block. */
        osdp_sc_session_t s_over = s;
        f.payload_len = max + 1U;
        TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
            osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &s_over, &f,
                               out, caps[c], &out_len));
    }
}

/* SCS_15/16 carry the payload in the clear under a MAC — no ciphertext
 * expansion — so the answer there is the plain framing answer. */
static void test_sc_max_payload_matches_framing_for_unencrypted_scb(void)
{
    osdp_frame_t f;
    (void)memset(&f, 0, sizeof(f));
    f.address    = 0x05;
    f.integrity  = OSDP_INTEGRITY_CRC;
    f.has_scb    = true;
    f.scb_length = OSDP_SCB_MIN_LEN;
    f.scb_type   = OSDP_SCS_15;
    f.code       = 0x60;

    size_t sc_max = 0, frame_max = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_max_payload(&f, 128, &sc_max));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_max_payload(&f, 128, &frame_max));
    TEST_ASSERT_EQUAL_size_t(frame_max, sc_max);

    /* And it is strictly less than the encrypted variant would allow,
     * confirming the padding deduction is actually being applied there. */
    f.scb_type = OSDP_SCS_17;
    size_t enc_max = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_sc_max_payload(&f, 128, &enc_max));
    TEST_ASSERT_LESS_THAN_size_t(sc_max, enc_max);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_wrap_scs17_matches_known_bytes);
    RUN_TEST(test_wrap_empty_payload_matches_known_bytes);
    RUN_TEST(test_sc_max_payload_is_exactly_what_wrap_accepts);
    RUN_TEST(test_sc_max_payload_matches_framing_for_unencrypted_scb);
    RUN_TEST(test_wrap_unwrap_scs15_round_trip);
    RUN_TEST(test_wrap_upgrades_scs15_to_scs17_when_payload_nonempty);
    RUN_TEST(test_wrap_upgrades_scs16_to_scs18_when_payload_nonempty);
    RUN_TEST(test_wrap_unwrap_scs17_encrypted_round_trip);
    RUN_TEST(test_chained_wraps_and_unwraps_advance_sessions_in_lockstep);
    RUN_TEST(test_unwrap_rejects_tampered_mac);
    RUN_TEST(test_wrap_rejects_unestablished_session);
    RUN_TEST(test_wrap_rejects_non_scs_15_through_18);
    RUN_TEST(test_unwrap_rejects_non_scs_15_through_18);
    return UNITY_END();
}
