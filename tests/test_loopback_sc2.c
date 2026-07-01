// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* PD ↔ ACU in-process integration test, with Secure Channel 2.
 *
 * The SC2 sibling of test_loopback_sc.c: it wires a real osdp::pd and a
 * real osdp::acu through a shared in-memory wire, both SC2-configured,
 * and drives the SCS_21..24 handshake plus operational SCS_25..28
 * traffic in both directions. The PD half is already validated live
 * against OSDP.Net's SC2 ACU; this test uses it to exercise our ACU's
 * SC2 logic end-to-end and prove the two agree on cryptogram inputs,
 * KMAC key derivation, GCM framing, and the shared message counter.
 *
 * Asserts:
 *   - the four-frame handshake (CHLNG / CCRYPT / SCRYPT / RMAC_I)
 *     completes with both peers reporting SC2 "established",
 *   - POLL → ACK and ID → PDID round-trip under SCS_27/28,
 *   - an 8-command mix advances the shared counter without drift,
 *   - tampering with a GCM tag byte in flight tears the ACU's session
 *     down and fires SESSION_LOST,
 *   - offline silence past the threshold also ends the session. */

#include "osdp/osdp_acu.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_crc.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc2.h"
#include "sc2_test_crypto.h"
#include "unity.h"

#include <string.h>

void setUp(void)
{
    sc2_test_crypto_seed_prng(0xCAFEBABEu);
    sc2_test_crypto_set_fixed_rand(NULL, 0);
}
void tearDown(void) {}

/* ---- Wire ---------------------------------------------------------------*/

#define WIRE_BUF 8192U

typedef struct wire {
    uint8_t  a2p[WIRE_BUF];
    size_t   a2p_len;
    size_t   a2p_off;
    uint8_t  p2a[WIRE_BUF];
    size_t   p2a_len;
    size_t   p2a_off;
    uint32_t now_ms;
} wire_t;

static int read_from(uint8_t *src, size_t *len, size_t *off,
                     uint8_t *buf, size_t cap)
{
    if (*off > *len) return 0;
    const size_t available = *len - *off;
    const size_t n = (cap < available) ? cap : available;
    if (n > 0) {
        (void)memcpy(buf, &src[*off], n);
        *off += n;
    }
    return (int)n;
}

static int write_to(uint8_t *dst, size_t *len, const uint8_t *buf, size_t n)
{
    if (*len + n > WIRE_BUF) {
        n = WIRE_BUF - *len;
    }
    (void)memcpy(&dst[*len], buf, n);
    *len += n;
    return (int)n;
}

static int acu_read(void *user, uint8_t *buf, size_t cap)
{
    wire_t *w = (wire_t *)user;
    return read_from(w->p2a, &w->p2a_len, &w->p2a_off, buf, cap);
}
static int acu_write(void *user, const uint8_t *buf, size_t len)
{
    wire_t *w = (wire_t *)user;
    return write_to(w->a2p, &w->a2p_len, buf, len);
}
static int pd_read(void *user, uint8_t *buf, size_t cap)
{
    wire_t *w = (wire_t *)user;
    return read_from(w->a2p, &w->a2p_len, &w->a2p_off, buf, cap);
}
static int pd_write(void *user, const uint8_t *buf, size_t len)
{
    wire_t *w = (wire_t *)user;
    return write_to(w->p2a, &w->p2a_len, buf, len);
}
static uint32_t wire_now_ms(void *user)
{
    return ((const wire_t *)user)->now_ms;
}

/* ---- PD-side application handler -------------------------------------- */

static const uint8_t kSamplePdid[12] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0x01, 0x02, 0x03, 0x04,
};
static const uint8_t kSamplePdcap[12] = {
    1, 1, 1, 2, 1, 1, 3, 1, 1, 4, 1, 1,
};

static osdp_status_t pd_app_handler(void *user, uint8_t cmd_code,
                                    const uint8_t *payload, size_t payload_len,
                                    osdp_pd_reply_t *reply)
{
    (void)user; (void)payload; (void)payload_len;
    switch (cmd_code) {
    case OSDP_CMD_POLL:
        reply->code = OSDP_REPLY_ACK; reply->payload = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    case OSDP_CMD_ID:
        reply->code = OSDP_REPLY_PDID; reply->payload = kSamplePdid;
        reply->payload_len = sizeof(kSamplePdid);
        return OSDP_OK;
    case OSDP_CMD_CAP:
        reply->code = OSDP_REPLY_PDCAP; reply->payload = kSamplePdcap;
        reply->payload_len = sizeof(kSamplePdcap);
        return OSDP_OK;
    default:
        return OSDP_ERR_NOT_SUPPORTED;
    }
}

/* ---- ACU-side captures ------------------------------------------------- */

typedef struct {
    unsigned int           call_count;
    osdp_acu_reply_event_t last;
    uint8_t                last_payload[64];
    size_t                 last_payload_len;
} reply_capture_t;

static void on_reply(void *user, const osdp_acu_reply_event_t *e)
{
    reply_capture_t *c = (reply_capture_t *)user;
    c->call_count++;
    c->last = *e;
    c->last_payload_len = (e->payload_len < sizeof(c->last_payload))
                              ? e->payload_len : sizeof(c->last_payload);
    if (c->last_payload_len > 0) {
        (void)memcpy(c->last_payload, e->payload, c->last_payload_len);
    }
}

typedef struct {
    unsigned int        call_count;
    osdp_acu_sc_event_t last;
} sc_event_capture_t;

static void on_sc_event(void *user, const osdp_acu_sc_event_t *e)
{
    sc_event_capture_t *c = (sc_event_capture_t *)user;
    c->call_count++;
    c->last = *e;
}

/* ---- Test rig ---------------------------------------------------------- */

#define PD_ADDRESS 0x10U

static const uint8_t kSCBK[OSDP_SC2_KEY_LEN] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
};
static const uint8_t kCUID[OSDP_SC2_CUID_LEN] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
};

typedef struct rig {
    wire_t             wire;
    osdp_pd_t          pd;
    osdp_acu_t         acu;
    osdp_acu_pd_slot_t acu_slots[1];
    reply_capture_t    reply;
    sc_event_capture_t sc_event;
} rig_t;

static void rig_init(rig_t *r)
{
    (void)memset(r, 0, sizeof(*r));

    osdp_pd_transport_t pd_t = {
        .read = pd_read, .write = pd_write,
        .now_ms = wire_now_ms, .user = &r->wire,
    };
    osdp_acu_transport_t acu_t = {
        .read = acu_read, .write = acu_write,
        .now_ms = wire_now_ms, .user = &r->wire,
    };

    osdp_pd_init(&r->pd, PD_ADDRESS);
    osdp_pd_set_transport(&r->pd, &pd_t);
    osdp_pd_set_command_handler(&r->pd, pd_app_handler, NULL);
    osdp_pd_set_sc2_crypto(&r->pd, sc2_test_crypto());
    osdp_pd_set_sc2_scbk  (&r->pd, kSCBK);
    osdp_pd_set_sc2_cuid  (&r->pd, kCUID);

    osdp_acu_init(&r->acu, r->acu_slots,
                  sizeof(r->acu_slots) / sizeof(r->acu_slots[0]));
    osdp_acu_set_transport       (&r->acu, &acu_t);
    osdp_acu_set_reply_handler   (&r->acu, on_reply,    &r->reply);
    osdp_acu_set_sc_event_handler(&r->acu, on_sc_event, &r->sc_event);
    osdp_acu_set_sc2_crypto      (&r->acu, sc2_test_crypto());
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_acu_register_pd(&r->acu, 0, PD_ADDRESS));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_set_pd_sc2_scbk(&r->acu, PD_ADDRESS, kSCBK));
}

static void cycle(rig_t *r, int times)
{
    for (int i = 0; i < times; i++) {
        osdp_pd_tick(&r->pd);
        osdp_acu_tick(&r->acu);
    }
}

static void run_handshake(rig_t *r)
{
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_start_sc2_handshake(&r->acu, PD_ADDRESS));
    cycle(r, 8);

    TEST_ASSERT_TRUE(osdp_pd_sc2_established(&r->pd));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_sc2_established(&r->acu, PD_ADDRESS));
    TEST_ASSERT_EQUAL(1U, r->sc_event.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_ESTABLISHED, r->sc_event.last.kind);
    TEST_ASSERT_EQUAL_HEX8(PD_ADDRESS, r->sc_event.last.pd_address);
    TEST_ASSERT_EQUAL(0U, r->reply.call_count);
}

/* ---- Tests ------------------------------------------------------------- */

static void test_handshake_completes_in_loopback(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);
}

static void test_poll_round_trip_under_sc2(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&r.acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));
    cycle(&r, 4);

    TEST_ASSERT_EQUAL(1U, r.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(PD_ADDRESS,     r.reply.last.pd_address);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL,  r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, r.reply.last.reply_code);
    TEST_ASSERT_EQUAL_size_t(0, r.reply.last_payload_len);
    TEST_ASSERT_TRUE(osdp_pd_sc2_established(&r.pd));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_sc2_established(&r.acu, PD_ADDRESS));
}

static void test_id_round_trip_under_sc2(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);

    static const uint8_t id_payload = 0x00;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&r.acu, PD_ADDRESS, OSDP_CMD_ID, &id_payload, 1));
    cycle(&r, 4);

    TEST_ASSERT_EQUAL(1U, r.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_ID,     r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDID, r.reply.last.reply_code);
    TEST_ASSERT_EQUAL_size_t(sizeof(kSamplePdid), r.reply.last_payload_len);
    TEST_ASSERT_EQUAL_MEMORY(kSamplePdid, r.reply.last_payload,
                             sizeof(kSamplePdid));
}

static void test_mixed_sequence_advances_counter(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);

    static const uint8_t cap_payload[1] = { 0x00 };
    for (int i = 0; i < 8; i++) {
        if ((i & 1) == 0) {
            TEST_ASSERT_EQUAL(OSDP_OK,
                osdp_acu_send_command(&r.acu, PD_ADDRESS,
                                      OSDP_CMD_POLL, NULL, 0));
        } else {
            TEST_ASSERT_EQUAL(OSDP_OK,
                osdp_acu_send_command(&r.acu, PD_ADDRESS, OSDP_CMD_CAP,
                                      cap_payload, sizeof(cap_payload)));
        }
        cycle(&r, 4);
    }

    TEST_ASSERT_EQUAL(8U, r.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_CAP,     r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDCAP, r.reply.last.reply_code);
    TEST_ASSERT_EQUAL_MEMORY(kSamplePdcap, r.reply.last_payload,
                             sizeof(kSamplePdcap));
    TEST_ASSERT_TRUE(osdp_pd_sc2_established(&r.pd));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_sc2_established(&r.acu, PD_ADDRESS));
    /* Both peers advanced their shared counter identically: handshake
     * left it at 0, then 8 command+reply pairs = 16 increments each. */
    TEST_ASSERT_EQUAL_UINT32(r.pd.sc2.session.counter,
                             r.acu_slots[0].sc2_session.counter);
}

static void test_corrupted_tag_in_flight_terminates_acu_session(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);
    r.sc_event.call_count = 0;

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&r.acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));

    /* Tick PD only, so its SCS_28 reply sits in p2a un-consumed. */
    osdp_pd_tick(&r.pd);
    TEST_ASSERT_GREATER_THAN_size_t(0, r.wire.p2a_len);

    const size_t reply_start = r.wire.p2a_off;
    const size_t reply_end   = r.wire.p2a_len;
    TEST_ASSERT_GREATER_THAN_size_t(reply_start + OSDP_FRAME_MAC_LEN_SC2 + 2,
                                    reply_end);
    const size_t crc_off = reply_end - 2;
    const size_t tag_off = crc_off - OSDP_FRAME_MAC_LEN_SC2;
    r.wire.p2a[tag_off] ^= 0x10U;   /* flip a GCM tag byte */
    const uint16_t crc = osdp_crc16(
        &r.wire.p2a[reply_start + OSDP_FRAME_MARK_LEN],
        crc_off - reply_start - OSDP_FRAME_MARK_LEN);
    r.wire.p2a[crc_off]     = (uint8_t)(crc & 0xFFU);
    r.wire.p2a[crc_off + 1] = (uint8_t)((crc >> 8) & 0xFFU);

    osdp_acu_tick(&r.acu);

    TEST_ASSERT_EQUAL(0U, r.reply.call_count);
    TEST_ASSERT_EQUAL(1U, r.sc_event.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_SESSION_LOST, r.sc_event.last.kind);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc2_established(&r.acu, PD_ADDRESS));
}

static void test_offline_during_established_session_lost(void)
{
    rig_t r;
    rig_init(&r);
    r.wire.now_ms = 1000U;
    run_handshake(&r);
    r.sc_event.call_count = 0;

    TEST_ASSERT_TRUE(osdp_acu_is_pd_online(&r.acu, PD_ADDRESS));

    r.wire.now_ms = 1000U + OSDP_ACU_OFFLINE_TIMEOUT_MS + 1U;
    osdp_acu_tick(&r.acu);

    TEST_ASSERT_FALSE(osdp_acu_is_pd_online(&r.acu, PD_ADDRESS));
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc2_established(&r.acu, PD_ADDRESS));
    TEST_ASSERT_EQUAL(1U, r.sc_event.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_SESSION_LOST, r.sc_event.last.kind);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_handshake_completes_in_loopback);
    RUN_TEST(test_poll_round_trip_under_sc2);
    RUN_TEST(test_id_round_trip_under_sc2);
    RUN_TEST(test_mixed_sequence_advances_counter);
    RUN_TEST(test_corrupted_tag_in_flight_terminates_acu_session);
    RUN_TEST(test_offline_during_established_session_lost);
    return UNITY_END();
}
