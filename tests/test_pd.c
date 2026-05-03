// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"
#include "osdp/osdp_dispatch.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_replies.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Mock transport ------------------------------------------------------
 *
 * Two ring-style byte buffers: `incoming` is what the test pushes into
 * the PD (simulating bytes arriving from the ACU), `outgoing` captures
 * what the PD wrote (simulating bytes the PD sent back to the ACU). */

#define MOCK_BUF_LEN 1024U

typedef struct mock_transport {
    uint8_t  incoming[MOCK_BUF_LEN];
    size_t   incoming_len;
    size_t   incoming_off;
    uint8_t  outgoing[MOCK_BUF_LEN];
    size_t   outgoing_len;
    uint32_t now_ms;       /* bumped manually by tests */
} mock_transport_t;

static int mock_read(void *user, uint8_t *buf, size_t cap)
{
    mock_transport_t *m = (mock_transport_t *)user;
    /* Defensive: clamp before the unsigned subtraction so a test
     * that resets incoming_len without also clearing incoming_off
     * doesn't underflow into a huge avail and read past the buffer. */
    if (m->incoming_off > m->incoming_len) {
        return 0;
    }
    const size_t available = m->incoming_len - m->incoming_off;
    const size_t n = (cap < available) ? cap : available;
    if (n > 0) {
        (void)memcpy(buf, &m->incoming[m->incoming_off], n);
        m->incoming_off += n;
    }
    return (int)n;
}

static int mock_write(void *user, const uint8_t *buf, size_t len)
{
    mock_transport_t *m = (mock_transport_t *)user;
    const size_t free_room = MOCK_BUF_LEN - m->outgoing_len;
    const size_t n = (len < free_room) ? len : free_room;
    if (n > 0) {
        (void)memcpy(&m->outgoing[m->outgoing_len], buf, n);
        m->outgoing_len += n;
    }
    return (int)n;
}

static uint32_t mock_now_ms(void *user)
{
    return ((const mock_transport_t *)user)->now_ms;
}

static void mock_init(mock_transport_t *m, osdp_pd_transport_t *t)
{
    (void)memset(m, 0, sizeof(*m));
    t->read   = mock_read;
    t->write  = mock_write;
    t->now_ms = mock_now_ms;
    t->user   = m;
}

/* Append a built command frame to the mock transport's `incoming`
 * stream so the next osdp_pd_tick() will see it. */
static void inject_command(mock_transport_t *m, uint8_t addr,
                           uint8_t code, const uint8_t *payload,
                           size_t payload_len, osdp_integrity_t integrity,
                           uint8_t sequence)
{
    osdp_frame_t f = {0};
    f.address     = addr;
    f.reply       = false;
    f.sequence    = sequence;
    f.integrity   = integrity;
    f.code        = code;
    f.payload     = payload;
    f.payload_len = payload_len;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  written = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_build(&f, buf, sizeof(buf), &written));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(MOCK_BUF_LEN - m->incoming_len, written);
    (void)memcpy(&m->incoming[m->incoming_len], buf, written);
    m->incoming_len += written;
}

/* Decode the first frame in the mock transport's `outgoing` buffer. */
static void decode_first_outgoing(const mock_transport_t *m,
                                  osdp_frame_t *out)
{
    TEST_ASSERT_GREATER_OR_EQUAL(OSDP_FRAME_MIN_LEN_CKSUM,
                                 m->outgoing_len);
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_decode(m->outgoing, m->outgoing_len, out));
}

/* ---- Application handlers ----------------------------------------------*/

/* Default handler: ACK for POLL, otherwise unsupported. */
static osdp_status_t default_handler(void *user,
                                     uint8_t cmd_code,
                                     const uint8_t *payload,
                                     size_t payload_len,
                                     osdp_pd_reply_t *reply)
{
    (void)user; (void)payload; (void)payload_len;
    if (cmd_code == OSDP_CMD_POLL) {
        reply->code        = OSDP_REPLY_ACK;
        reply->payload     = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    }
    return OSDP_ERR_NOT_SUPPORTED;
}

/* Counts how many times it gets called and what the last command code
 * was — useful for verifying the PD does/doesn't dispatch in various
 * scenarios. */
typedef struct counting_handler {
    unsigned int call_count;
    uint8_t      last_code;
} counting_handler_t;

static osdp_status_t counting_cb(void *user,
                                 uint8_t cmd_code,
                                 const uint8_t *payload,
                                 size_t payload_len,
                                 osdp_pd_reply_t *reply)
{
    (void)payload; (void)payload_len;
    counting_handler_t *c = (counting_handler_t *)user;
    c->call_count++;
    c->last_code = cmd_code;
    reply->code        = OSDP_REPLY_ACK;
    reply->payload     = NULL;
    reply->payload_len = 0;
    return OSDP_OK;
}

/* ---- Tests --------------------------------------------------------------*/

static void test_init_zero_initializes_address_correctly(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    TEST_ASSERT_EQUAL_UINT8(0x05, pd.address);
}

static void test_init_strips_high_bit_of_address(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0xFF);   /* invalid; only low 7 bits should stick */
    TEST_ASSERT_EQUAL_UINT8(0x7F, pd.address);
}

static void test_poll_to_own_address_is_acked(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_TRUE(reply.reply);
    TEST_ASSERT_EQUAL_UINT8(0x05, reply.address);
    TEST_ASSERT_EQUAL_UINT8(1, reply.sequence);
    TEST_ASSERT_EQUAL(OSDP_INTEGRITY_CRC, reply.integrity);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_size_t(0, reply.payload_len);
}

static void test_poll_to_broadcast_is_acked_with_own_address(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x12);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    inject_command(&m, OSDP_BROADCAST_ADDR, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 0);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    /* PD replies with ITS OWN address, not the broadcast address. */
    TEST_ASSERT_EQUAL_UINT8(0x12, reply.address);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
}

static void test_poll_to_other_address_is_ignored(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    inject_command(&m, 0x07, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 0);
    osdp_pd_tick(&pd);

    /* No reply at all. */
    TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);
}

static void test_unknown_command_returns_nak_with_unknown_cmd_code(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    /* Send a TEXT command — default_handler returns NOT_SUPPORTED for
     * everything except POLL. */
    static const uint8_t text_payload[] = {
        0, OSDP_TEXT_PERM_NO_WRAP, 0, 1, 1, 0
    };
    inject_command(&m, 0x05, OSDP_CMD_TEXT, text_payload,
                   sizeof(text_payload), OSDP_INTEGRITY_CRC, 2);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_size_t(1, reply.payload_len);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, reply.payload[0]);
}

static void test_no_handler_attached_yields_nak_for_every_command(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    /* deliberately do NOT call osdp_pd_set_command_handler */

    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 0);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, reply.payload[0]);
}

static void test_scb_bearing_command_returns_nak_unsupported_scb(void)
{
    /* Hand-craft a frame with SCB present (CTRL bit 3 set) and check
     * the PD refuses with NAK 0x05. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    osdp_frame_t f = {0};
    f.address      = 0x05;
    f.reply        = false;
    f.sequence     = 1;
    f.integrity    = OSDP_INTEGRITY_CRC;
    f.has_scb      = true;
    f.scb_length   = 2;        /* SEC_BLK_LEN + SEC_BLK_TYPE only */
    f.scb_type     = 0x11;     /* SCS_11: ACU initiates SC handshake */
    f.scb_data     = NULL;
    f.scb_data_len = 0;
    f.code         = OSDP_CMD_CHLNG;
    uint8_t built[64]; size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, built, sizeof(built), &n));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(MOCK_BUF_LEN, n);
    (void)memcpy(m.incoming, built, n);
    m.incoming_len = n;

    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_FALSE(reply.has_scb);   /* PD's reply has no SCB */
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNSUPPORTED_SCB, reply.payload[0]);
}

static void test_handler_receives_command_payload(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);

    counting_handler_t counter = {0};
    osdp_pd_set_command_handler(&pd, counting_cb, &counter);

    /* Send three commands; expect three handler calls. */
    static const uint8_t buz[] = { 0, 2, 1, 1, 3 };
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    inject_command(&m, 0x05, OSDP_CMD_BUZ, buz, sizeof(buz),
                   OSDP_INTEGRITY_CRC, 2);
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CHECKSUM, 3);
    osdp_pd_tick(&pd);

    TEST_ASSERT_EQUAL_UINT(3, counter.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, counter.last_code);
}

static void test_bad_crc_command_is_silently_ignored(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    /* Build a valid POLL, then corrupt its CRC. The PD should drop it
     * silently — no reply, but also no crash. */
    osdp_frame_t f = {0};
    f.address = 0x05; f.integrity = OSDP_INTEGRITY_CRC; f.code = OSDP_CMD_POLL;
    uint8_t buf[16]; size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &n));
    buf[n - 1] ^= 0xFF;   /* corrupt CRC MSB */
    (void)memcpy(m.incoming, buf, n);
    m.incoming_len = n;

    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);
}

/* ---- Sequence number policing (spec 5.9 Table 2) ----------------------- */

static void test_retransmit_replays_cached_reply_without_handler_call(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);

    counting_handler_t counter = {0};
    osdp_pd_set_command_handler(&pd, counting_cb, &counter);

    /* First command at SQN=1: handler called, ACK sent. */
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_UINT(1, counter.call_count);
    const size_t first_reply_len = m.outgoing_len;
    TEST_ASSERT_GREATER_THAN(0, first_reply_len);

    /* Snapshot the first reply so we can compare. */
    uint8_t first_reply[64];
    TEST_ASSERT_LESS_OR_EQUAL_size_t(sizeof(first_reply), first_reply_len);
    (void)memcpy(first_reply, m.outgoing, first_reply_len);

    /* Retransmit: same SQN=1. Handler must NOT be called again. */
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(1, counter.call_count,
        "handler invoked twice on retransmit");

    /* The replayed reply bytes match the original. */
    TEST_ASSERT_EQUAL_size_t(first_reply_len * 2, m.outgoing_len);
    TEST_ASSERT_EQUAL_MEMORY(first_reply,
                             &m.outgoing[first_reply_len],
                             first_reply_len);
}

static void test_new_sequence_invokes_handler_again(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    counting_handler_t counter = {0};
    osdp_pd_set_command_handler(&pd, counting_cb, &counter);

    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 2);
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 3);
    osdp_pd_tick(&pd);

    TEST_ASSERT_EQUAL_UINT(3, counter.call_count);
}

static void test_sequence_zero_always_processes_fresh(void)
{
    /* Per spec: SQN zero is the session-reset sentinel; it must be
     * processed every time, not deduplicated. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    counting_handler_t counter = {0};
    osdp_pd_set_command_handler(&pd, counting_cb, &counter);

    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 0);
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 0);
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 0);
    osdp_pd_tick(&pd);

    TEST_ASSERT_EQUAL_UINT(3, counter.call_count);
}

static void test_retransmit_replays_nak_too(void)
{
    /* Caching applies to NAKs as well: if the first command got
     * NAK'd because the handler said NOT_SUPPORTED, the retransmit
     * should replay the same NAK without consulting the handler. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    counting_handler_t counter = {0};
    osdp_pd_set_command_handler(&pd, counting_cb, &counter);

    /* counting_cb always returns OK with ACK; we want NOT_SUPPORTED.
     * Use the default_handler instead, which only knows POLL. */
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    static const uint8_t buz[] = { 0, 2, 1, 1, 3 };
    inject_command(&m, 0x05, OSDP_CMD_BUZ, buz, sizeof(buz),
                   OSDP_INTEGRITY_CRC, 2);
    osdp_pd_tick(&pd);

    osdp_frame_t first_reply;
    decode_first_outgoing(&m, &first_reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, first_reply.code);
    const size_t len_first = m.outgoing_len;

    /* Retransmit. */
    inject_command(&m, 0x05, OSDP_CMD_BUZ, buz, sizeof(buz),
                   OSDP_INTEGRITY_CRC, 2);
    osdp_pd_tick(&pd);

    /* Outgoing buffer now contains the NAK twice. */
    TEST_ASSERT_EQUAL_size_t(len_first * 2, m.outgoing_len);
    TEST_ASSERT_EQUAL_MEMORY(m.outgoing, &m.outgoing[len_first], len_first);
}

/* ---- Online/offline tracking (spec 5.7) -------------------------------- */

static void test_freshly_initialized_pd_is_offline(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    TEST_ASSERT_FALSE(osdp_pd_is_online(&pd));
}

static void test_first_reply_transitions_pd_to_online(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    TEST_ASSERT_FALSE(osdp_pd_is_online(&pd));
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_TRUE(osdp_pd_is_online(&pd));
}

static void test_silence_beyond_eight_seconds_transitions_offline(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    /* Establish online with a reply at t=1000 ms. */
    m.now_ms = 1000;
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_TRUE(osdp_pd_is_online(&pd));

    /* Jump just past the 8-second window. No incoming traffic. The
     * tick should observe the timeout and transition offline. */
    m.now_ms = 1000 + OSDP_PD_OFFLINE_TIMEOUT_MS + 1;
    osdp_pd_tick(&pd);
    TEST_ASSERT_FALSE(osdp_pd_is_online(&pd));
}

static void test_offline_clears_sequence_cache(void)
{
    /* Simulate an ACU that polls, the PD goes offline, then a fresh
     * connection re-uses the same SQN. The PD must process the new
     * command, not replay the old reply. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    counting_handler_t counter = {0};
    osdp_pd_set_command_handler(&pd, counting_cb, &counter);

    m.now_ms = 1000;
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_UINT(1, counter.call_count);

    /* Long silence → offline → cache cleared. */
    m.now_ms = 1000 + OSDP_PD_OFFLINE_TIMEOUT_MS + 100;
    osdp_pd_tick(&pd);
    TEST_ASSERT_FALSE(osdp_pd_is_online(&pd));

    /* Same SQN comes in. Without cache clearing, this would replay the
     * old ACK without invoking the handler — which would be a bug. */
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(2, counter.call_count,
        "PD replayed cached reply across an offline transition");
    TEST_ASSERT_TRUE(osdp_pd_is_online(&pd));
}

static void test_continuous_traffic_keeps_pd_online(void)
{
    /* Steady-state polling: every reply refreshes the timeout, so the
     * PD never transitions to offline. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    for (uint8_t seq = 1; seq <= 3; seq++) {
        m.now_ms += 5000;   /* 5 seconds between commands; well inside 8 */
        inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                       OSDP_INTEGRITY_CRC, seq);
        osdp_pd_tick(&pd);
        TEST_ASSERT_TRUE(osdp_pd_is_online(&pd));
    }

    /* Bump 5 seconds further — still online because the most recent
     * reply was less than 8 seconds ago. */
    m.now_ms += 5000;
    osdp_pd_tick(&pd);
    TEST_ASSERT_TRUE(osdp_pd_is_online(&pd));
}

static void test_no_clock_callback_means_online_after_first_reply_forever(void)
{
    /* Without now_ms, the PD can't measure silence — degrade
     * gracefully by staying online once it has replied. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    t.now_ms = NULL;   /* explicitly disable the clock */

    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_TRUE(osdp_pd_is_online(&pd));

    /* Many ticks with no traffic — the PD stays online (no timeout
     * mechanism available). */
    for (int i = 0; i < 100; i++) {
        osdp_pd_tick(&pd);
    }
    TEST_ASSERT_TRUE(osdp_pd_is_online(&pd));
}

static void test_retransmit_after_other_seq_does_not_replay(void)
{
    /* Once a command at SQN=2 has been processed, a retransmit at SQN=1
     * (the previous one) should be treated as fresh — only the most
     * recent SQN is cached. (Spec 5.9 supports this: the ACU only ever
     * repeats the immediately-previous SQN.) */
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    counting_handler_t counter = {0};
    osdp_pd_set_command_handler(&pd, counting_cb, &counter);

    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 2);
    /* "Stale" retransmit of SQN=1 — should be processed fresh, since
     * our cache is now SQN=2. */
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);

    TEST_ASSERT_EQUAL_UINT(3, counter.call_count);
}

static void test_reply_direction_frames_are_ignored(void)
{
    /* A frame with the reply flag set is going the wrong direction —
     * the PD should never see something the ACU should be receiving.
     * Verify the PD silently drops it. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    osdp_frame_t f = {0};
    f.address = 0x05; f.reply = true; f.integrity = OSDP_INTEGRITY_CRC;
    f.code = OSDP_REPLY_ACK;
    uint8_t buf[16]; size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &n));
    (void)memcpy(m.incoming, buf, n);
    m.incoming_len = n;

    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_init_zero_initializes_address_correctly);
    RUN_TEST(test_init_strips_high_bit_of_address);
    RUN_TEST(test_poll_to_own_address_is_acked);
    RUN_TEST(test_poll_to_broadcast_is_acked_with_own_address);
    RUN_TEST(test_poll_to_other_address_is_ignored);
    RUN_TEST(test_unknown_command_returns_nak_with_unknown_cmd_code);
    RUN_TEST(test_no_handler_attached_yields_nak_for_every_command);
    RUN_TEST(test_scb_bearing_command_returns_nak_unsupported_scb);
    RUN_TEST(test_handler_receives_command_payload);
    RUN_TEST(test_bad_crc_command_is_silently_ignored);
    RUN_TEST(test_reply_direction_frames_are_ignored);
    RUN_TEST(test_retransmit_replays_cached_reply_without_handler_call);
    RUN_TEST(test_new_sequence_invokes_handler_again);
    RUN_TEST(test_sequence_zero_always_processes_fresh);
    RUN_TEST(test_retransmit_replays_nak_too);
    RUN_TEST(test_retransmit_after_other_seq_does_not_replay);
    /* Online/offline tracking */
    RUN_TEST(test_freshly_initialized_pd_is_offline);
    RUN_TEST(test_first_reply_transitions_pd_to_online);
    RUN_TEST(test_silence_beyond_eight_seconds_transitions_offline);
    RUN_TEST(test_offline_clears_sequence_cache);
    RUN_TEST(test_continuous_traffic_keeps_pd_online);
    RUN_TEST(test_no_clock_callback_means_online_after_first_reply_forever);
    return UNITY_END();
}
