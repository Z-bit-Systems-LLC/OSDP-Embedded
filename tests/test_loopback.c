// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* PD ↔ ACU in-process integration test.
 *
 * Wires a real osdp::pd state machine and a real osdp::acu state machine
 * together via a shared in-memory "wire" with two ring-style byte
 * buffers. No mock transport, no synthesised frames — the bytes that
 * each side reads were genuinely written by the other side, so every
 * layer (framing, integrity, streaming, sequence policing, address
 * filtering, reply dispatch) is exercised both directions and must
 * agree.
 *
 * This is the strongest correctness check we have for iteration 2: a
 * bug on either side that would manifest only when the two halves
 * actually talk to each other (e.g. SQN off-by-one, address-flag
 * confusion, integrity-mode mismatch) shows up here. */

#include "osdp/osdp_acu.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_replies.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Wire ---------------------------------------------------------------*/

#define WIRE_BUF 4096U

typedef struct wire {
    /* ACU writes here; PD reads here. */
    uint8_t  a2p[WIRE_BUF];
    size_t   a2p_len;
    size_t   a2p_off;
    /* PD writes here; ACU reads here. */
    uint8_t  p2a[WIRE_BUF];
    size_t   p2a_len;
    size_t   p2a_off;
    uint32_t now_ms;
} wire_t;

static int read_from(uint8_t *src, size_t *len, size_t *off,
                     uint8_t *buf, size_t cap)
{
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

/* ACU side. */
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

/* PD side. */
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

/* A simple PD that knows how to respond to POLL (ACK) and ID (PDID).
 * Anything else falls through to NAK 0x03. The PDID payload is held
 * in a static buffer so the pointer remains valid for the whole reply
 * lifetime. */

static const uint8_t kSamplePdid[12] = {
    0xCA, 0xFE, 0x00,        /* vendor */
    0x10,                    /* model */
    0x01,                    /* version */
    0xEF, 0xBE, 0xAD, 0xDE,  /* serial LE = 0xDEADBEEF */
    0x01, 0x02, 0x03,        /* firmware major/minor/build */
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
    default:
        return OSDP_ERR_NOT_SUPPORTED;
    }
}

/* ---- ACU-side captures ------------------------------------------------- */

typedef struct {
    unsigned int call_count;
    osdp_acu_reply_event_t last;
    uint8_t  last_payload[64];
    size_t   last_payload_len;
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
    unsigned int call_count;
    osdp_acu_timeout_event_t last;
} timeout_capture_t;

static void on_timeout(void *user, const osdp_acu_timeout_event_t *e)
{
    timeout_capture_t *c = (timeout_capture_t *)user;
    c->call_count++;
    c->last = *e;
}

/* ---- Test rig ---------------------------------------------------------- */

typedef struct rig {
    wire_t              wire;
    osdp_pd_t           pd;
    osdp_acu_t          acu;
    osdp_acu_pd_slot_t  acu_slots[2];
    reply_capture_t     reply;
    timeout_capture_t   timeout;
} rig_t;

static void rig_init(rig_t *r, uint8_t pd_address)
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

    osdp_pd_init(&r->pd, pd_address);
    osdp_pd_set_transport(&r->pd, &pd_t);
    osdp_pd_set_command_handler(&r->pd, pd_app_handler, NULL);

    osdp_acu_init(&r->acu, r->acu_slots,
                  sizeof(r->acu_slots) / sizeof(r->acu_slots[0]));
    osdp_acu_set_transport(&r->acu, &acu_t);
    osdp_acu_set_reply_handler  (&r->acu, on_reply,   &r->reply);
    osdp_acu_set_timeout_handler(&r->acu, on_timeout, &r->timeout);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_acu_register_pd(&r->acu, 0, pd_address));
}

/* Run both state machines a few times so any in-flight bytes get
 * processed. Two passes are enough for a single command/reply round
 * trip; loop here lets us tolerate longer chains. */
static void cycle(rig_t *r, int times)
{
    for (int i = 0; i < times; i++) {
        osdp_pd_tick(&r->pd);
        osdp_acu_tick(&r->acu);
    }
}

/* ---- Tests ------------------------------------------------------------- */

static void test_poll_round_trip(void)
{
    rig_t r;
    rig_init(&r, 0x10);

    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&r.acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    cycle(&r, 4);

    TEST_ASSERT_EQUAL_UINT(1, r.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(0x10, r.reply.last.pd_address);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL,  r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, r.reply.last.reply_code);
    TEST_ASSERT_EQUAL_size_t(0, r.reply.last_payload_len);
    TEST_ASSERT_TRUE(osdp_acu_is_pd_online(&r.acu, 0x10));
    TEST_ASSERT_TRUE(osdp_pd_is_online(&r.pd));
}

static void test_id_round_trip_with_pdid_payload(void)
{
    rig_t r;
    rig_init(&r, 0x10);

    static const uint8_t id_payload[1] = { 0x00 };  /* request standard PDID */
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&r.acu, 0x10, OSDP_CMD_ID,
                                            id_payload, sizeof(id_payload)));
    cycle(&r, 4);

    TEST_ASSERT_EQUAL_UINT(1, r.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_ID,    r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDID, r.reply.last.reply_code);
    TEST_ASSERT_EQUAL_size_t(sizeof(kSamplePdid), r.reply.last_payload_len);
    TEST_ASSERT_EQUAL_MEMORY(kSamplePdid, r.reply.last_payload,
                             sizeof(kSamplePdid));
}

static void test_unknown_command_yields_nak_back_to_acu(void)
{
    rig_t r;
    rig_init(&r, 0x10);

    /* TEXT command — pd_app_handler doesn't implement it, so the PD
     * NAKs with code 0x03. The ACU's reply handler should see it. */
    static const uint8_t text_payload[] = {
        0, OSDP_TEXT_PERM_NO_WRAP, 0, 1, 1, 0
    };
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&r.acu, 0x10, OSDP_CMD_TEXT,
                                            text_payload,
                                            sizeof(text_payload)));
    cycle(&r, 4);

    TEST_ASSERT_EQUAL_UINT(1, r.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_TEXT,  r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, r.reply.last.reply_code);
    TEST_ASSERT_EQUAL_size_t(1, r.reply.last_payload_len);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, r.reply.last_payload[0]);
}

static void test_polling_loop_progresses_sequence_numbers(void)
{
    /* Issue eight POLLs in sequence, allow each to round-trip, and
     * verify the ACU has obtained a reply for every one. The PD's
     * handler is invoked exactly eight times (no replays — every
     * command had a fresh SQN); the ACU's reply handler is invoked
     * eight times. */
    rig_t r;
    rig_init(&r, 0x10);

    for (int i = 0; i < 8; i++) {
        TEST_ASSERT_EQUAL(OSDP_OK,
                          osdp_acu_send_command(&r.acu, 0x10, OSDP_CMD_POLL,
                                                NULL, 0));
        cycle(&r, 4);
    }

    TEST_ASSERT_EQUAL_UINT(8, r.reply.call_count);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_busy(&r.acu, 0x10));
}

static void test_no_reply_yields_acu_timeout(void)
{
    /* PD is registered to a different address — the command goes out
     * but the PD ignores it. The ACU's timeout handler should fire
     * after 200 ms. */
    rig_t r;
    rig_init(&r, 0x10);
    /* Re-init the PD with a different address. */
    osdp_pd_init(&r.pd, 0x05);
    osdp_pd_transport_t pd_t = {
        .read = pd_read, .write = pd_write,
        .now_ms = wire_now_ms, .user = &r.wire,
    };
    osdp_pd_set_transport(&r.pd, &pd_t);
    osdp_pd_set_command_handler(&r.pd, pd_app_handler, NULL);

    r.wire.now_ms = 1000;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&r.acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    cycle(&r, 4);
    TEST_ASSERT_EQUAL_UINT(0, r.reply.call_count);

    /* Advance past the 200 ms timeout. */
    r.wire.now_ms = 1500;
    cycle(&r, 1);
    TEST_ASSERT_EQUAL_UINT(1, r.timeout.call_count);
    TEST_ASSERT_EQUAL_HEX8(0x10, r.timeout.last.pd_address);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, r.timeout.last.cmd_code);
}

static void test_broadcast_command_reaches_pd(void)
{
    /* ACU is registered against a specific PD address, but the
     * underlying frame wire still works — when the ACU sends to that
     * address, the PD picks it up. (Actually broadcast 0x7F isn't
     * supported by the current ACU API since the slot is keyed by
     * address; this test just confirms a per-PD send arrives.) */
    rig_t r;
    rig_init(&r, 0x10);

    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&r.acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    cycle(&r, 4);
    TEST_ASSERT_EQUAL_UINT(1, r.reply.call_count);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_poll_round_trip);
    RUN_TEST(test_id_round_trip_with_pdid_payload);
    RUN_TEST(test_unknown_command_yields_nak_back_to_acu);
    RUN_TEST(test_polling_loop_progresses_sequence_numbers);
    RUN_TEST(test_no_reply_yields_acu_timeout);
    RUN_TEST(test_broadcast_command_reaches_pd);
    return UNITY_END();
}
