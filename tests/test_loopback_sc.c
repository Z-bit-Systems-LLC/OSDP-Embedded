// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* PD ↔ ACU in-process integration test, with Secure Channel.
 *
 * Phase 6 of iteration 3. The non-SC sibling (test_loopback.c) wires
 * a real osdp::pd and a real osdp::acu through a shared in-memory wire
 * and exercises framing / SQN / online tracking. This file does the
 * same — but with both halves SC-configured, an actual handshake
 * negotiated over the wire, and operational SCS_15..18 traffic in
 * both directions.
 *
 * Why this exists: every other SC test stops at a known boundary —
 * test_pd_sc.c plays a "mock ACU" against the real PD; test_acu_sc.c
 * plays a "mock PD" against the real ACU; test_capture_replay.c drives
 * the real PD with bytes from a third-party ACU. None of them prove
 * that our PD and our ACU agree on the on-wire format end-to-end. This
 * test does, by linking the two real state machines through a single
 * byte buffer and asserting that:
 *
 *   - the four-frame handshake (CHLNG / CCRYPT / SCRYPT / RMAC_I)
 *     completes with both peers reporting "established",
 *   - operational POLL → ACK round-trips under SCS_15/16,
 *   - operational ID → PDID round-trips under SCS_17/18 (encrypted
 *     payload),
 *   - tampering with a MAC byte in flight tears the ACU's session
 *     down and fires SESSION_LOST, while the PD remains established
 *     until it sees the next inbound frame,
 *   - 8 s of silence past the offline threshold also ends the
 *     ACU's session.
 *
 * The same wire model as test_loopback.c: two append-only buffers,
 * `a2p` and `p2a`, with read offsets. Each tick of the PD or ACU
 * pulls some bytes through and may push reply bytes back. */

#include "osdp/osdp_acu.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_crc.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"
#include "sc_test_aes.h"
#include "unity.h"

#include <string.h>

void setUp(void)
{
    /* Reset the test PRNG so RND.A and RND.B are deterministic across
     * runs. Both peers share the same LCG, but they pull at different
     * times during the handshake, so the values they get are still
     * different from each other. */
    sc_test_crypto_seed_prng(0xCAFEBABEu);
    sc_test_crypto_set_fixed_rand(NULL, 0);
}

void tearDown(void) {}

/* ---- Wire ---------------------------------------------------------------*/

#define WIRE_BUF 8192U   /* a handshake + several round trips fits comfortably */

typedef struct wire {
    /* ACU → PD direction. */
    uint8_t  a2p[WIRE_BUF];
    size_t   a2p_len;
    size_t   a2p_off;
    /* PD → ACU direction. */
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

static int write_to(uint8_t *dst, size_t *len,
                    const uint8_t *buf, size_t n)
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

/* The fake-PD application: ACK on POLL, PDID on ID, PDCAP on CAP, NAK
 * 0x03 on anything else. PDID payload kept static so its pointer stays
 * valid past the handler's return. */

static const uint8_t kSamplePdid[12] = {
    0xCA, 0xFE, 0x00,        /* vendor                   */
    0x10,                    /* model                    */
    0x01,                    /* version                  */
    0xEF, 0xBE, 0xAD, 0xDE,  /* serial LE = 0xDEADBEEF   */
    0x01, 0x02, 0x03,        /* fw major / minor / build */
};

static const uint8_t kSamplePdcap[12] = {
    1, 1, 1,   /* contact monitor: 1 input,  compliance lvl 1 */
    2, 1, 1,   /* output:           1 output, compliance lvl 1 */
    3, 1, 1,   /* card data format: 1 entry,  compliance lvl 1 */
    4, 1, 1,   /* LED control:      1 LED,    compliance lvl 1 */
};

static osdp_status_t pd_app_handler(void *user,
                                    uint8_t cmd_code,
                                    const uint8_t *payload,
                                    size_t payload_len,
                                    osdp_pd_reply_t *reply)
{
    (void)user; (void)payload; (void)payload_len;
    switch (cmd_code) {
    case OSDP_CMD_POLL:
        reply->code        = OSDP_REPLY_ACK;
        reply->payload     = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    case OSDP_CMD_ID:
        reply->code        = OSDP_REPLY_PDID;
        reply->payload     = kSamplePdid;
        reply->payload_len = sizeof(kSamplePdid);
        return OSDP_OK;
    case OSDP_CMD_CAP:
        reply->code        = OSDP_REPLY_PDCAP;
        reply->payload     = kSamplePdcap;
        reply->payload_len = sizeof(kSamplePdcap);
        return OSDP_OK;
    default:
        return OSDP_ERR_NOT_SUPPORTED;
    }
}

/* ---- ACU-side captures ------------------------------------------------- */

typedef struct {
    unsigned int            call_count;
    osdp_acu_reply_event_t  last;
    uint8_t                 last_payload[64];
    size_t                  last_payload_len;
} reply_capture_t;

static void on_reply(void *user, const osdp_acu_reply_event_t *e)
{
    reply_capture_t *c = (reply_capture_t *)user;
    c->call_count++;
    c->last = *e;
    c->last_payload_len = (e->payload_len < sizeof(c->last_payload))
                              ? e->payload_len
                              : sizeof(c->last_payload);
    if (c->last_payload_len > 0) {
        (void)memcpy(c->last_payload, e->payload, c->last_payload_len);
    }
}

typedef struct {
    unsigned int             call_count;
    osdp_acu_timeout_event_t last;
} timeout_capture_t;

static void on_timeout(void *user, const osdp_acu_timeout_event_t *e)
{
    timeout_capture_t *c = (timeout_capture_t *)user;
    c->call_count++;
    c->last = *e;
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

/* Both halves use the same key + cUID. The PD's `cuid` is what it
 * embeds in CCRYPT; the ACU lifts it from CCRYPT to seed its own
 * key derivation, so we don't have to hand it to the ACU directly. */
static const uint8_t kSCBK[OSDP_SC_KEY_LEN] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
};
static const uint8_t kCUID[OSDP_SC_CUID_LEN] = {
    0xCA, 0xFE, 0x00, 0x10, 0x01, 0xEF, 0xBE, 0xAD,
};

typedef struct rig {
    wire_t              wire;
    osdp_pd_t           pd;
    osdp_acu_t          acu;
    osdp_acu_pd_slot_t  acu_slots[1];
    reply_capture_t     reply;
    timeout_capture_t   timeout;
    sc_event_capture_t  sc_event;
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

    /* PD setup: address, transport, command handler, full SC config. */
    osdp_pd_init(&r->pd, PD_ADDRESS);
    osdp_pd_set_transport(&r->pd, &pd_t);
    osdp_pd_set_command_handler(&r->pd, pd_app_handler, NULL);
    osdp_pd_set_sc_crypto(&r->pd, sc_test_crypto_tiny_aes());
    osdp_pd_set_sc_scbk  (&r->pd, kSCBK);
    osdp_pd_set_sc_cuid  (&r->pd, kCUID);

    /* ACU setup: one slot, callbacks, full SC config. */
    osdp_acu_init(&r->acu, r->acu_slots,
                  sizeof(r->acu_slots) / sizeof(r->acu_slots[0]));
    osdp_acu_set_transport         (&r->acu, &acu_t);
    osdp_acu_set_reply_handler     (&r->acu, on_reply,    &r->reply);
    osdp_acu_set_timeout_handler   (&r->acu, on_timeout,  &r->timeout);
    osdp_acu_set_sc_event_handler  (&r->acu, on_sc_event, &r->sc_event);
    osdp_acu_set_sc_crypto         (&r->acu, sc_test_crypto_tiny_aes());
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_register_pd(&r->acu, 0, PD_ADDRESS));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_set_pd_scbk(&r->acu, PD_ADDRESS, kSCBK));
}

/* Drive both state machines `times` rounds. PD first so an inbound
 * command produced by the previous ACU tick gets processed and replied
 * to before the ACU runs again. Two passes is enough for a single
 * command/reply round trip; a handshake takes four. */
static void cycle(rig_t *r, int times)
{
    for (int i = 0; i < times; i++) {
        osdp_pd_tick(&r->pd);
        osdp_acu_tick(&r->acu);
    }
}

/* Run the four-frame handshake to completion. Asserts that both peers
 * reach the "established" state and that no cmd/reply leaked into the
 * application's reply_cb. */
static void run_handshake(rig_t *r)
{
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_start_sc_handshake(&r->acu, PD_ADDRESS,
                                    /*use_default_key*/ false));
    /* CHLNG → CCRYPT → SCRYPT → RMAC_I = four frames; allow generously. */
    cycle(r, 8);

    TEST_ASSERT_TRUE(osdp_pd_sc_established(&r->pd));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_sc_established(&r->acu, PD_ADDRESS));
    TEST_ASSERT_EQUAL(1U, r->sc_event.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_ESTABLISHED, r->sc_event.last.kind);
    TEST_ASSERT_EQUAL_HEX8(PD_ADDRESS, r->sc_event.last.pd_address);
    /* Handshake replies are consumed internally — never delivered. */
    TEST_ASSERT_EQUAL(0U, r->reply.call_count);
}

/* ---- Tests ------------------------------------------------------------- */

/* The headline test: two real state machines complete a four-frame
 * Secure Channel handshake over a shared byte buffer and both report
 * "established". Any spec disagreement on cryptogram inputs, key
 * derivation, frame layout, or SCB encoding shows up here. */
static void test_handshake_completes_in_loopback(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);
}

/* POLL → ACK round trip after the session is established. ACU wraps
 * as SCS_15 (empty payload), PD unwraps, dispatches POLL through
 * `pd_app_handler`, wraps the empty ACK as SCS_16, ACU unwraps and
 * delivers a plaintext ACK to the application. */
static void test_poll_round_trip_under_sc(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&r.acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));
    cycle(&r, 4);

    TEST_ASSERT_EQUAL(1U, r.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(PD_ADDRESS,    r.reply.last.pd_address);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, r.reply.last.reply_code);
    TEST_ASSERT_EQUAL_size_t(0, r.reply.last_payload_len);
    /* Session must still be alive after a successful round trip. */
    TEST_ASSERT_TRUE(osdp_pd_sc_established(&r.pd));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_sc_established(&r.acu, PD_ADDRESS));
}

/* ID → PDID round trip. ID has a 1-byte payload, so the ACU wraps as
 * SCS_17 (encrypted command payload); PDID has a 12-byte payload, so
 * the PD wraps as SCS_18 (encrypted reply payload). The plaintext
 * PDID bytes arrive in the ACU's reply_cb. Same end-to-end check as
 * the POLL test, but exercising the data-bearing SC variants. */
static void test_id_round_trip_under_sc_with_encrypted_payload(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);

    static const uint8_t id_payload[1] = { 0x00 };
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&r.acu, PD_ADDRESS, OSDP_CMD_ID,
                              id_payload, sizeof(id_payload)));
    cycle(&r, 4);

    TEST_ASSERT_EQUAL(1U, r.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_ID,    r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDID, r.reply.last.reply_code);
    TEST_ASSERT_EQUAL_size_t(sizeof(kSamplePdid), r.reply.last_payload_len);
    TEST_ASSERT_EQUAL_MEMORY(kSamplePdid, r.reply.last_payload,
                             sizeof(kSamplePdid));
}

/* CAP → PDCAP round trip — second SCS_17/18 case, run in sequence
 * with POLL and ID to verify the rolling MAC chain stays in sync
 * across multiple commands. The PDCAP payload is exactly 12 bytes
 * (the payload length sent in the SC capture is the only thing the
 * spec formally requires here; the contents come from the app). */
static void test_mixed_sequence_under_sc_advances_mac_chain(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);

    /* Eight commands alternating POLL (SCS_15/16) and CAP (SCS_17/18).
     * If the rolling MAC chain were off by one, the second command
     * would already fail; eight is generous extra confidence. */
    static const uint8_t cap_payload[1] = { 0x00 };
    for (int i = 0; i < 8; i++) {
        if ((i & 1) == 0) {
            TEST_ASSERT_EQUAL(OSDP_OK,
                osdp_acu_send_command(&r.acu, PD_ADDRESS,
                                      OSDP_CMD_POLL, NULL, 0));
        } else {
            TEST_ASSERT_EQUAL(OSDP_OK,
                osdp_acu_send_command(&r.acu, PD_ADDRESS,
                                      OSDP_CMD_CAP,
                                      cap_payload, sizeof(cap_payload)));
        }
        cycle(&r, 4);
    }

    TEST_ASSERT_EQUAL(8U, r.reply.call_count);
    /* Last reply was CAP → PDCAP. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_CAP,    r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDCAP, r.reply.last.reply_code);
    TEST_ASSERT_EQUAL_size_t(sizeof(kSamplePdcap),
                             r.reply.last_payload_len);
    TEST_ASSERT_EQUAL_MEMORY(kSamplePdcap, r.reply.last_payload,
                             sizeof(kSamplePdcap));
    /* Both peers still established. */
    TEST_ASSERT_TRUE(osdp_pd_sc_established(&r.pd));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_sc_established(&r.acu, PD_ADDRESS));
}

/* Tamper with one MAC byte in the PD → ACU direction. The Layer-1 CRC
 * stays valid (we recompute it after the flip) so the frame reaches
 * the SC unwrap step, where the MAC mismatch triggers session loss
 * per spec D.1.4. The ACU fires SESSION_LOST and returns to IDLE. */
static void test_corrupted_mac_in_flight_terminates_acu_session(void)
{
    rig_t r;
    rig_init(&r);
    run_handshake(&r);
    /* Reset the established-event we already captured. */
    r.sc_event.call_count = 0;

    /* Issue a POLL: ACU writes SCS_15 to a2p. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&r.acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));

    /* PD picks it up, processes, and writes a SCS_16 ACK to p2a.
     * Tick PD only — we want the reply bytes sitting in p2a but not
     * yet consumed by the ACU. */
    osdp_pd_tick(&r.pd);
    TEST_ASSERT_GREATER_THAN_size_t(0, r.wire.p2a_len);

    /* Find the start of the most recent reply in p2a. The handshake
     * wrote bytes here too, but since we never tampered with them
     * those have already been consumed by the ACU. The new reply
     * starts at p2a_off. Flip a byte inside the MAC field (the four
     * bytes immediately before the 2-byte CRC) and recompute the
     * CRC over the modified frame. */
    const size_t reply_start = r.wire.p2a_off;
    const size_t reply_end   = r.wire.p2a_len;
    TEST_ASSERT_GREATER_THAN_size_t(reply_start + OSDP_FRAME_MAC_LEN + 2,
                                    reply_end);
    const size_t crc_off = reply_end - 2;
    const size_t mac_off = crc_off - OSDP_FRAME_MAC_LEN;
    r.wire.p2a[mac_off] ^= 0x10U;
    /* Recompute CRC over the frame only — the reply on the wire carries
     * the spec-5.7 marking byte(s) ahead of its SOM. */
    const uint16_t crc = osdp_crc16(&r.wire.p2a[reply_start + OSDP_FRAME_MARK_LEN],
                                    crc_off - reply_start - OSDP_FRAME_MARK_LEN);
    r.wire.p2a[crc_off]     = (uint8_t)(crc & 0xFFU);
    r.wire.p2a[crc_off + 1] = (uint8_t)((crc >> 8) & 0xFFU);

    /* Now let the ACU consume the corrupted reply. */
    osdp_acu_tick(&r.acu);

    /* Application got no plaintext reply; SESSION_LOST event fired;
     * ACU phase reset to IDLE. The PD still thinks it's established
     * — it will notice on the next inbound frame whose MAC chain
     * is out of step. That asymmetry is deliberate; the application
     * is expected to re-handshake on either side after a loss. */
    TEST_ASSERT_EQUAL(0U, r.reply.call_count);
    TEST_ASSERT_EQUAL(1U, r.sc_event.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_SESSION_LOST,
                      r.sc_event.last.kind);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&r.acu, PD_ADDRESS));
}

/* Spec 5.7: 8s of silence flips the PD slot offline. The ACU mirrors
 * this on its side, and if a Secure Channel session was active, that
 * session also ends and SESSION_LOST fires. Verifies the timer-driven
 * path against a real-state-machine PD on the other end (which stays
 * silent for the duration). */
static void test_offline_during_established_session_lost(void)
{
    rig_t r;
    rig_init(&r);
    r.wire.now_ms = 1000U;
    run_handshake(&r);
    r.sc_event.call_count = 0;

    TEST_ASSERT_TRUE(osdp_acu_is_pd_online(&r.acu, PD_ADDRESS));

    /* No traffic; advance the clock past the offline threshold. */
    r.wire.now_ms = 1000U + OSDP_ACU_OFFLINE_TIMEOUT_MS + 1U;
    osdp_acu_tick(&r.acu);

    TEST_ASSERT_FALSE(osdp_acu_is_pd_online(&r.acu, PD_ADDRESS));
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&r.acu, PD_ADDRESS));
    TEST_ASSERT_EQUAL(1U, r.sc_event.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_SESSION_LOST,
                      r.sc_event.last.kind);
}

/* After SESSION_LOST, the ACU must send subsequent commands as
 * plaintext (no SCB) until the application calls
 * osdp_acu_start_sc_handshake again. The PD will NAK plaintext
 * commands while it still thinks SC is up, but the framing on the
 * ACU side is the visible behavior we care about here. */
static void test_send_command_after_session_loss_is_plaintext(void)
{
    rig_t r;
    rig_init(&r);
    r.wire.now_ms = 1000U;
    run_handshake(&r);

    /* Trigger session loss the cheap way — bump past the offline
     * threshold without bus traffic. */
    r.wire.now_ms = 1000U + OSDP_ACU_OFFLINE_TIMEOUT_MS + 1U;
    osdp_acu_tick(&r.acu);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&r.acu, PD_ADDRESS));

    /* The next send_command must produce a frame without an SCB. */
    const size_t a2p_before = r.wire.a2p_len;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&r.acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));
    TEST_ASSERT_GREATER_THAN_size_t(a2p_before, r.wire.a2p_len);

    osdp_frame_t frame;
    /* The new command starts at a2p_before with the spec-5.7 marking
     * byte(s) ahead of its SOM; decode the SOM-aligned frame. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_decode(&r.wire.a2p[a2p_before + OSDP_FRAME_MARK_LEN],
                          r.wire.a2p_len - a2p_before - OSDP_FRAME_MARK_LEN,
                          &frame));
    TEST_ASSERT_FALSE(frame.has_scb);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, frame.code);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_handshake_completes_in_loopback);
    RUN_TEST(test_poll_round_trip_under_sc);
    RUN_TEST(test_id_round_trip_under_sc_with_encrypted_payload);
    RUN_TEST(test_mixed_sequence_under_sc_advances_mac_chain);
    RUN_TEST(test_corrupted_mac_in_flight_terminates_acu_session);
    RUN_TEST(test_offline_during_established_session_lost);
    RUN_TEST(test_send_command_after_session_loss_is_plaintext);
    return UNITY_END();
}
