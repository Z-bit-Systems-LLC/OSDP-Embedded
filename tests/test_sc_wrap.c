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

static void test_wrap_unwrap_scs15_round_trip(void)
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

    /* Decode the wire bytes from B's side and verify MAC. */
    osdp_frame_t decoded;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(wire, wire_len, &decoded));
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_15, decoded.scb_type);

    uint8_t recovered[64];
    size_t recovered_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &b, &decoded,
                             recovered, sizeof(recovered), &recovered_len));
    TEST_ASSERT_EQUAL_size_t(sizeof(cmd_payload), recovered_len);
    TEST_ASSERT_EQUAL_MEMORY(cmd_payload, recovered, sizeof(cmd_payload));

    /* Both sides' MAC chains advanced to the same value: A's
     * last_outbound == B's last_inbound. */
    TEST_ASSERT_EQUAL_MEMORY(a.last_outbound_mac, b.last_inbound_mac,
                             OSDP_SC_MAC_LEN);
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
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(wire, wire_len, &decoded));
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
    /* Send three SCS_15 frames from A→B, with each side advancing
     * its MAC chain on every operation. After each round, the chain
     * states must remain mirrored. */
    osdp_sc_session_t a, b;
    make_paired_sessions(&a, &b);

    for (int i = 0; i < 3; i++) {
        const uint8_t payload[] = { (uint8_t)i, 0xAA, 0xBB };
        osdp_frame_t tmpl;
        build_template(&tmpl, OSDP_SCS_15, 0x60, payload, sizeof(payload));

        uint8_t wire[64];
        size_t wire_len = 0;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &a, &tmpl,
                               wire, sizeof(wire), &wire_len));
        osdp_frame_t decoded;
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(wire, wire_len, &decoded));
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
    const uint16_t crc = osdp_crc16(wire, crc_offset);
    wire[crc_offset]     = (uint8_t)(crc & 0xFFu);
    wire[crc_offset + 1] = (uint8_t)((crc >> 8) & 0xFFu);

    osdp_frame_t decoded;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_decode(wire, wire_len, &decoded));
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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_wrap_unwrap_scs15_round_trip);
    RUN_TEST(test_wrap_unwrap_scs17_encrypted_round_trip);
    RUN_TEST(test_chained_wraps_and_unwraps_advance_sessions_in_lockstep);
    RUN_TEST(test_unwrap_rejects_tampered_mac);
    RUN_TEST(test_wrap_rejects_unestablished_session);
    RUN_TEST(test_wrap_rejects_non_scs_15_through_18);
    RUN_TEST(test_unwrap_rejects_non_scs_15_through_18);
    return UNITY_END();
}
