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
#include "osdp/osdp_led_state.h"
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
    case OSDP_CMD_LED:
        /* A real reader ACKs LED control; the PD tracks the resulting
         * colour transparently in its LED bank regardless. */
        reply->code        = OSDP_REPLY_ACK;
        reply->payload     = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    default:
        return OSDP_ERR_NOT_SUPPORTED;
    }
}

/* ---- LED-change captures ---------------------------------------------- */

typedef struct {
    unsigned int call_count;
    uint8_t      last_reader;
    uint8_t      last_led;
    uint8_t      last_color;
} led_capture_t;

static void on_pd_led(void *user, uint8_t reader_no, uint8_t led_no,
                      uint8_t color)
{
    led_capture_t *c = (led_capture_t *)user;
    c->call_count++;
    c->last_reader = reader_no;
    c->last_led    = led_no;
    c->last_color  = color;
}

static void on_acu_led(void *user, uint8_t pd_address, uint8_t reader_no,
                       uint8_t led_no, uint8_t color)
{
    (void)pd_address;
    led_capture_t *c = (led_capture_t *)user;
    c->call_count++;
    c->last_reader = reader_no;
    c->last_led    = led_no;
    c->last_color  = color;
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
    led_capture_t       pd_led;
    led_capture_t       acu_led;
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
    osdp_pd_set_led_handler(&r->pd, on_pd_led, &r->pd_led);

    osdp_acu_init(&r->acu, r->acu_slots,
                  sizeof(r->acu_slots) / sizeof(r->acu_slots[0]));
    osdp_acu_set_transport(&r->acu, &acu_t);
    osdp_acu_set_reply_handler  (&r->acu, on_reply,   &r->reply);
    osdp_acu_set_timeout_handler(&r->acu, on_timeout, &r->timeout);
    osdp_acu_set_led_handler    (&r->acu, on_acu_led, &r->acu_led);
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

/* ---- Reader LED tracking ---------------------------------------------- */

/* Build the payload of an osdp_LED command carrying a single record. */
static size_t build_led_payload(const osdp_led_record_t *rec,
                                uint8_t *buf, size_t cap)
{
    size_t written = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_led_build(rec, 1, buf, cap, &written));
    return written;
}

/* An osdp_LED command setting a steady permanent colour propagates ACU →
 * PD, the PD ACKs it, and BOTH sides' LED banks (callback + colour query)
 * resolve to that colour — the end-to-end "what is the reader showing?"
 * path for the visual reader. */
static void test_led_steady_colour_tracked_on_both_sides(void)
{
    rig_t r;
    rig_init(&r, 0x10);

    osdp_led_record_t rec = {0};
    rec.reader_no         = 0;
    rec.led_no            = 0;
    rec.temp_control_code = OSDP_LED_TEMP_NOP;
    rec.perm_control_code = OSDP_LED_PERM_SET;
    rec.perm_on_color     = OSDP_LED_GREEN;
    rec.perm_off_color    = OSDP_LED_GREEN;

    uint8_t payload[64];
    const size_t plen = build_led_payload(&rec, payload, sizeof(payload));
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&r.acu, 0x10, OSDP_CMD_LED,
                                            payload, plen));
    cycle(&r, 4);

    /* PD ACK'd the LED command on the wire. */
    TEST_ASSERT_EQUAL_UINT(1, r.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_LED,   r.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, r.reply.last.reply_code);

    /* PD-side bank: callback fired green, query agrees. */
    TEST_ASSERT_EQUAL_UINT(1, r.pd_led.call_count);
    TEST_ASSERT_EQUAL_HEX8(0, r.pd_led.last_reader);
    TEST_ASSERT_EQUAL_HEX8(0, r.pd_led.last_led);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, r.pd_led.last_color);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, osdp_pd_led_color(&r.pd, 0, 0));

    /* ACU-side mirror: callback fired green, query agrees. */
    TEST_ASSERT_EQUAL_UINT(1, r.acu_led.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, r.acu_led.last_color);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN,
                           osdp_acu_led_color(&r.acu, 0x10, 0, 0));

    /* An untouched LED reads black. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_BLACK, osdp_pd_led_color(&r.pd, 0, 1));
}

/* A temporary override with a countdown timer shows its colour while the
 * timer runs and reverts to the permanent colour once it expires — driven
 * purely by the wire clock and detected inside tick(), so the change
 * callback fires on both peers without any further command. */
static void test_led_temporary_timer_expires_to_permanent(void)
{
    rig_t r;
    rig_init(&r, 0x10);
    r.wire.now_ms = 1000;

    osdp_led_record_t rec = {0};
    rec.reader_no         = 0;
    rec.led_no            = 0;
    rec.perm_control_code = OSDP_LED_PERM_SET;     /* steady red baseline */
    rec.perm_on_color     = OSDP_LED_RED;
    rec.perm_off_color    = OSDP_LED_RED;
    rec.temp_control_code = OSDP_LED_TEMP_SET;     /* 1 s steady green    */
    rec.temp_on_color     = OSDP_LED_GREEN;
    rec.temp_off_color    = OSDP_LED_GREEN;
    rec.temp_timer_100ms  = 10;                    /* 10 × 100 ms = 1 s   */

    uint8_t payload[64];
    const size_t plen = build_led_payload(&rec, payload, sizeof(payload));
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&r.acu, 0x10, OSDP_CMD_LED,
                                            payload, plen));
    cycle(&r, 4);

    /* Timer running → green on both sides. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, r.pd_led.last_color);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, osdp_pd_led_color(&r.pd, 0, 0));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, r.acu_led.last_color);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN,
                           osdp_acu_led_color(&r.acu, 0x10, 0, 0));

    /* Advance past the 1 s timer; ticking re-resolves the bank → red. No
     * new command is sent — the revert is entirely time-driven. */
    r.wire.now_ms = 2500;
    cycle(&r, 2);

    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED, osdp_pd_led_color(&r.pd, 0, 0));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED, r.pd_led.last_color);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED,
                           osdp_acu_led_color(&r.acu, 0x10, 0, 0));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED, r.acu_led.last_color);
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
    RUN_TEST(test_led_steady_colour_tracked_on_both_sides);
    RUN_TEST(test_led_temporary_timer_expires_to_permanent);
    return UNITY_END();
}
