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
    /* The builder prepends spec-5.7 marking byte(s) ahead of the SOM;
     * decode the SOM-aligned frame. */
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_decode(m->outgoing + OSDP_FRAME_MARK_LEN,
                                        m->outgoing_len - OSDP_FRAME_MARK_LEN,
                                        out));
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

static void test_poll_to_broadcast_is_acked_at_config_address(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x12);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    inject_command(&m, OSDP_CONFIG_ADDR, OSDP_CMD_POLL, NULL, 0,
                   OSDP_INTEGRITY_CRC, 0);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    /* A command addressed to 0x7F is answered at 0x7F + reply flag = 0xFF
     * (spec 5.9 Note 2), NOT at the PD's own address. */
    TEST_ASSERT_EQUAL_UINT8(OSDP_CONFIG_ADDR, reply.address);
    TEST_ASSERT_TRUE(reply.reply);
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

static void test_bad_crc_command_addressed_to_pd_naks_bad_check(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    /* Build a valid POLL to this PD, then corrupt its CRC. Because it is
     * addressed to us, the PD answers NAK 0x01 (bad check) so the ACU
     * retransmits with the same SQN — rather than dropping it silently. */
    osdp_frame_t f = {0};
    f.address = 0x05; f.integrity = OSDP_INTEGRITY_CRC; f.code = OSDP_CMD_POLL;
    uint8_t buf[16]; size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &n));
    buf[n - 1] ^= 0xFF;   /* corrupt CRC MSB */
    (void)memcpy(m.incoming, buf, n);
    m.incoming_len = n;

    osdp_pd_tick(&pd);
    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_size_t(1, reply.payload_len);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_BAD_CHECK, reply.payload[0]);
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

/* ---- osdp_COMSET --------------------------------------------------------*/

/* Captures the COMSET decide/applied hook activity and can optionally force
 * an override of the effective values (to exercise the "can't comply"
 * path). */
typedef struct comset_capture {
    bool     decide_called;
    uint8_t  req_addr;
    uint32_t req_baud;

    bool     force_override;
    uint8_t  override_addr;
    uint32_t override_baud;

    bool     applied_called;
    uint8_t  applied_addr;
    uint32_t applied_baud;
} comset_capture_t;

static void comset_decide(void *user, uint8_t req_a, uint32_t req_b,
                          uint8_t *eff_a, uint32_t *eff_b)
{
    comset_capture_t *c = (comset_capture_t *)user;
    c->decide_called = true;
    c->req_addr      = req_a;
    c->req_baud      = req_b;
    if (c->force_override) {
        *eff_a = c->override_addr;
        *eff_b = c->override_baud;
    }
}

static void comset_applied(void *user, uint8_t a, uint32_t b)
{
    comset_capture_t *c = (comset_capture_t *)user;
    c->applied_called = true;
    c->applied_addr   = a;
    c->applied_baud   = b;
}

/* Build a COMSET frame carrying (address, baud) and feed it to the PD. */
static void inject_comset(mock_transport_t *m, uint8_t to_addr,
                          uint8_t new_addr, uint32_t new_baud, uint8_t seq)
{
    const osdp_comset_cmd_t cs = { .address = new_addr, .baud_rate = new_baud };
    uint8_t payload[OSDP_COMSET_PAYLOAD_BYTES];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_comset_build(&cs, payload, sizeof(payload), &w));
    inject_command(m, to_addr, OSDP_CMD_COMSET, payload, w,
                   OSDP_INTEGRITY_CRC, seq);
}

/* A well-formed COMSET is answered with osdp_COM (reporting the new values)
 * at the OLD address, and the PD adopts the new address afterwards. */
static void test_comset_reports_com_and_changes_address(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    inject_comset(&m, 0x05, 0x0A, 38400u, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    /* Reply goes out at the OLD address (change takes effect afterwards). */
    TEST_ASSERT_EQUAL_UINT8(0x05, reply.address);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_COM, reply.code);

    osdp_com_t com;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_com_decode(reply.payload, reply.payload_len, &com));
    TEST_ASSERT_EQUAL_UINT8(0x0A, com.address);
    TEST_ASSERT_EQUAL_UINT32(38400u, com.baud_rate);

    /* The new address is now live. */
    TEST_ASSERT_EQUAL_UINT8(0x0A, pd.address);
}

/* After COMSET the PD answers on the new address and ignores the old one. */
static void test_comset_pd_moves_to_new_address(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    inject_comset(&m, 0x05, 0x0A, 9600u, 1);
    osdp_pd_tick(&pd);
    m.outgoing_len = 0;   /* discard the COM reply */

    /* A POLL to the OLD address is now ignored. */
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0, OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);

    /* A POLL to the NEW address is answered. */
    inject_command(&m, 0x0A, OSDP_CMD_POLL, NULL, 0, OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);
    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_UINT8(0x0A, reply.address);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
}

/* The decide hook sees the requested values and the applied hook fires with
 * the effective values after the reply is sent. */
static void test_comset_hooks_fire_with_effective_values(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    comset_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    osdp_pd_set_comset_handler(&pd, comset_decide, comset_applied, &cap);

    inject_comset(&m, 0x05, 0x0A, 115200u, 1);
    osdp_pd_tick(&pd);

    TEST_ASSERT_TRUE(cap.decide_called);
    TEST_ASSERT_EQUAL_UINT8(0x0A, cap.req_addr);
    TEST_ASSERT_EQUAL_UINT32(115200u, cap.req_baud);

    TEST_ASSERT_TRUE(cap.applied_called);
    TEST_ASSERT_EQUAL_UINT8(0x0A, cap.applied_addr);
    TEST_ASSERT_EQUAL_UINT32(115200u, cap.applied_baud);
    TEST_ASSERT_EQUAL_UINT8(0x0A, pd.address);
}

/* When the app can't comply, its override is what the PD reports in COM and
 * what it actually adopts (spec 6.13). */
static void test_comset_decide_override_is_reported_and_applied(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    comset_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    cap.force_override = true;
    cap.override_addr  = 0x07;      /* keep our address */
    cap.override_baud  = 9600u;     /* clamp the unsupported baud */
    osdp_pd_set_comset_handler(&pd, comset_decide, comset_applied, &cap);

    inject_comset(&m, 0x05, 0x0A, 921600u, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    osdp_com_t com;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_com_decode(reply.payload, reply.payload_len, &com));
    TEST_ASSERT_EQUAL_UINT8(0x07, com.address);
    TEST_ASSERT_EQUAL_UINT32(9600u, com.baud_rate);
    TEST_ASSERT_EQUAL_UINT8(0x07, pd.address);
    TEST_ASSERT_EQUAL_UINT32(9600u, cap.applied_baud);
}

/* An effective address of 0x7F (the configuration address) is rejected as a
 * COMSET assignment target: the current address is kept and reported, but the
 * baud change still applies. */
static void test_comset_out_of_range_address_keeps_current(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    /* Hand-build a COMSET whose address byte is 0x7F (config address) — an
     * invalid target the builder would refuse, so craft the 5-byte wire
     * payload directly to exercise the decoder/clamp path. */
    const uint8_t bad_addr_payload[OSDP_COMSET_PAYLOAD_BYTES] = {
        0x7F, 0x00, 0x4B, 0x00, 0x00,   /* addr 0x7F, baud 19200 (LE) */
    };
    inject_command(&m, 0x05, OSDP_CMD_COMSET, bad_addr_payload,
                   sizeof(bad_addr_payload), OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    osdp_com_t com;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_com_decode(reply.payload, reply.payload_len, &com));
    TEST_ASSERT_EQUAL_UINT8(0x05, com.address);       /* unchanged */
    TEST_ASSERT_EQUAL_UINT32(19200u, com.baud_rate);  /* baud still set */
    TEST_ASSERT_EQUAL_UINT8(0x05, pd.address);
}

/* Config-discovery flow: a COMSET addressed to 0x7F (the config address)
 * assigns the PD a real working address. Per spec 5.9 Note 2 the osdp_COM
 * reply goes out at 0x7F + reply flag = 0xFF, and per spec 6.13 the switch
 * to the new address takes effect only after that reply is sent. */
static void test_comset_at_config_address_assigns_and_replies_0xff(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x00);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    /* COMSET sent TO the broadcast/config address, assigning working
     * address 0x05 at 19200 baud. */
    inject_comset(&m, OSDP_CONFIG_ADDR, 0x05, 19200u, 0);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    /* Reply mirrors the 0x7F destination with the reply flag set (0xFF). */
    TEST_ASSERT_EQUAL_UINT8(OSDP_CONFIG_ADDR, reply.address);
    TEST_ASSERT_TRUE(reply.reply);
    osdp_com_t com;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_com_decode(reply.payload, reply.payload_len, &com));
    TEST_ASSERT_EQUAL_UINT8(0x05, com.address);       /* new address */
    TEST_ASSERT_EQUAL_UINT32(19200u, com.baud_rate);
    /* The switch to 0x05 has taken effect after the reply. */
    TEST_ASSERT_EQUAL_UINT8(0x05, pd.address);
}

/* A malformed COMSET (wrong payload length) is NAK'd with bad-length and
 * leaves the address unchanged; no hooks fire. */
static void test_comset_malformed_payload_naks(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    comset_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    osdp_pd_set_comset_handler(&pd, comset_decide, comset_applied, &cap);

    /* 4-byte payload — one short of the mandated 5. */
    const uint8_t bad[4] = { 0x0A, 0x80, 0x25, 0x00 };
    inject_command(&m, 0x05, OSDP_CMD_COMSET, bad, sizeof(bad),
                   OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_size_t(1, reply.payload_len);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_CMD_LENGTH, reply.payload[0]);

    TEST_ASSERT_EQUAL_UINT8(0x05, pd.address);   /* unchanged */
    TEST_ASSERT_FALSE(cap.decide_called);
    TEST_ASSERT_FALSE(cap.applied_called);
}

/* ---- File transfer (osdp_FILETRANSFER) ---------------------------------*/

typedef struct file_capture {
    int           calls;
    uint8_t       last_type;
    uint32_t      last_offset;
    uint32_t      last_received;
    uint32_t      last_total;
    bool          last_complete;
    bool          last_data_null;   /* was info->data NULL (streaming)?     */
    uint8_t       last_fragment[8];  /* snapshot of info->fragment           */
    size_t        last_fragment_len;
    osdp_status_t verdict;        /* what the callback returns by default   */
    int           reject_on_call; /* if >0, return BAD_PAYLOAD on this call# */
} file_capture_t;

static osdp_status_t file_eval(void *user, const osdp_pd_file_info_t *info)
{
    file_capture_t *c = (file_capture_t *)user;
    c->calls++;
    c->last_type      = info->ft_type;
    c->last_offset    = info->offset;
    c->last_received  = info->received;
    c->last_total     = info->total_size;
    c->last_complete  = info->complete;
    c->last_data_null = (info->data == NULL);
    c->last_fragment_len = info->fragment_len;
    if (info->fragment != NULL &&
        info->fragment_len <= sizeof(c->last_fragment)) {
        (void)memcpy(c->last_fragment, info->fragment, info->fragment_len);
    }
    if (c->reject_on_call != 0 && c->calls == c->reject_on_call) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return c->verdict;
}

/* Build a FILETRANSFER frame and feed it to the PD. */
static void inject_filetransfer(mock_transport_t *m, uint8_t to_addr,
                                uint8_t type, uint32_t total, uint32_t offset,
                                const uint8_t *frag, uint16_t frag_len,
                                uint8_t seq)
{
    const osdp_filetransfer_cmd_t ft = {
        .ft_type       = type,
        .total_size    = total,
        .offset        = offset,
        .fragment_size = frag_len,
        .data          = (frag_len > 0) ? frag : NULL,
        .data_len      = frag_len,
    };
    uint8_t payload[128];
    size_t  w = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_filetransfer_build(&ft, payload, sizeof(payload), &w));
    inject_command(m, to_addr, OSDP_CMD_FILETRANSFER, payload, w,
                   OSDP_INTEGRITY_CRC, seq);
}

/* Decode the FTSTAT carried by the first outgoing reply. */
static void decode_ftstat_reply(const mock_transport_t *m, osdp_ftstat_t *st)
{
    osdp_frame_t reply;
    decode_first_outgoing(m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_FTSTAT, reply.code);
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_ftstat_decode(reply.payload, reply.payload_len, st));
}

/* With no receiver registered the PD does not implement file transfer and
 * NAKs FILETRANSFER with Unknown Command Code (0x03). */
static void test_filetransfer_without_receiver_naks(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    static const uint8_t frag[4] = { 1, 2, 3, 4 };
    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 4, 0, frag, 4, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, reply.payload[0]);
}

/* A single fragment that is the whole file: the core reassembles it, the
 * callback sees complete==true, and the PD reports FtStatusDetail=processed. */
static void test_filetransfer_single_fragment_processed(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    uint8_t rxbuf[256];
    file_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    cap.verdict = OSDP_OK;
    osdp_pd_set_file_receiver(&pd, rxbuf, sizeof(rxbuf), file_eval, &cap);

    static const uint8_t frag[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 4, 0, frag, 4, 1);
    osdp_pd_tick(&pd);

    osdp_ftstat_t st;
    decode_ftstat_reply(&m, &st);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_PROCESSED, st.status_detail);

    TEST_ASSERT_EQUAL_INT(1, cap.calls);
    TEST_ASSERT_TRUE(cap.last_complete);
    TEST_ASSERT_EQUAL_UINT32(4, cap.last_received);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(frag, rxbuf, 4);
}

/* Two fragments reassemble contiguously: the first is answered proceed(0),
 * the second (which completes the file) processed(1), and the buffer holds
 * the concatenation. */
static void test_filetransfer_two_fragments_reassemble(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    uint8_t rxbuf[256];
    file_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    cap.verdict = OSDP_OK;
    osdp_pd_set_file_receiver(&pd, rxbuf, sizeof(rxbuf), file_eval, &cap);

    static const uint8_t f1[4] = { 1, 2, 3, 4 };
    static const uint8_t f2[2] = { 5, 6 };

    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 6, 0, f1, 4, 1);
    osdp_pd_tick(&pd);
    osdp_ftstat_t s1;
    decode_ftstat_reply(&m, &s1);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_OK, s1.status_detail);   /* proceed */
    TEST_ASSERT_FALSE(cap.last_complete);
    m.outgoing_len = 0;

    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 6, 4, f2, 2, 2);
    osdp_pd_tick(&pd);
    osdp_ftstat_t s2;
    decode_ftstat_reply(&m, &s2);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_PROCESSED, s2.status_detail);
    TEST_ASSERT_TRUE(cap.last_complete);

    static const uint8_t expect[6] = { 1, 2, 3, 4, 5, 6 };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, rxbuf, 6);
    TEST_ASSERT_EQUAL_INT(2, cap.calls);
}

/* A file bigger than the receiver buffer is aborted at the first fragment,
 * before the evaluation callback ever runs. */
static void test_filetransfer_too_large_aborts(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    uint8_t rxbuf[4];   /* only 4 bytes of capacity */
    file_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    cap.verdict = OSDP_OK;
    osdp_pd_set_file_receiver(&pd, rxbuf, sizeof(rxbuf), file_eval, &cap);

    static const uint8_t frag[2] = { 1, 2 };
    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 10, 0, frag, 2, 1);
    osdp_pd_tick(&pd);

    osdp_ftstat_t st;
    decode_ftstat_reply(&m, &st);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_ABORT, st.status_detail);
    TEST_ASSERT_EQUAL_INT(0, cap.calls);
}

/* A non-monotonic / gapped offset aborts the transfer. */
static void test_filetransfer_gap_offset_aborts(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    uint8_t rxbuf[256];
    file_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    cap.verdict = OSDP_OK;
    osdp_pd_set_file_receiver(&pd, rxbuf, sizeof(rxbuf), file_eval, &cap);

    static const uint8_t f1[4] = { 1, 2, 3, 4 };
    static const uint8_t f2[2] = { 5, 6 };
    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 8, 0, f1, 4, 1);
    osdp_pd_tick(&pd);
    m.outgoing_len = 0;

    /* Next fragment claims offset 6 but only 4 bytes have arrived. */
    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 8, 6, f2, 2, 2);
    osdp_pd_tick(&pd);
    osdp_ftstat_t st;
    decode_ftstat_reply(&m, &st);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_ABORT, st.status_detail);
    TEST_ASSERT_EQUAL_INT(1, cap.calls);   /* only the first fragment evaluated */
}

/* The consumer can reject a fragment mid-transfer; the core reports the
 * mapped negative status and ends the transfer. */
static void test_filetransfer_callback_rejects_mid_transfer(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    uint8_t rxbuf[256];
    file_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    cap.verdict        = OSDP_OK;
    cap.reject_on_call = 1;    /* reject the very first fragment as malformed */
    osdp_pd_set_file_receiver(&pd, rxbuf, sizeof(rxbuf), file_eval, &cap);

    static const uint8_t f1[4] = { 1, 2, 3, 4 };
    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 8, 0, f1, 4, 1);
    osdp_pd_tick(&pd);
    osdp_ftstat_t st;
    decode_ftstat_reply(&m, &st);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_MALFORMED, st.status_detail);

    /* Transfer was aborted: a continuation fragment now aborts (no active
     * transfer at a non-zero offset). */
    m.outgoing_len = 0;
    static const uint8_t f2[4] = { 5, 6, 7, 8 };
    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 8, 4, f2, 4, 2);
    osdp_pd_tick(&pd);
    osdp_ftstat_t st2;
    decode_ftstat_reply(&m, &st2);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_ABORT, st2.status_detail);
}

/* Streaming mode: no reassembly buffer. The core hands each fragment to the
 * callback (info->fragment set, info->data NULL) and there is NO capacity
 * ceiling — a total_size far larger than any buffer streams fine. */
static void test_filetransfer_streaming_no_buffer(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    file_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    cap.verdict = OSDP_OK;
    /* Streaming: no buffer supplied. */
    osdp_pd_set_file_stream(&pd, file_eval, &cap);

    /* Declare a 1 MiB total — larger than any reassembly buffer would be —
     * and stream it in two fragments. No abort: streaming has no cap. */
    static const uint8_t f1[4] = { 0x11, 0x22, 0x33, 0x44 };
    static const uint8_t f2[4] = { 0x55, 0x66, 0x77, 0x88 };
    const uint32_t total = 1024u * 1024u;

    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, total, 0, f1, 4, 1);
    osdp_pd_tick(&pd);
    osdp_ftstat_t s1;
    decode_ftstat_reply(&m, &s1);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_OK, s1.status_detail);   /* proceed */
    /* The callback saw this fragment's bytes, and data is NULL (no buffer). */
    TEST_ASSERT_TRUE(cap.last_data_null);
    TEST_ASSERT_EQUAL_size_t(4, cap.last_fragment_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(f1, cap.last_fragment, 4);
    TEST_ASSERT_EQUAL_UINT32(4, cap.last_received);
    m.outgoing_len = 0;

    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, total, 4, f2, 4, 2);
    osdp_pd_tick(&pd);
    osdp_ftstat_t s2;
    decode_ftstat_reply(&m, &s2);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_OK, s2.status_detail);   /* still mid-file */
    TEST_ASSERT_TRUE(cap.last_data_null);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(f2, cap.last_fragment, 4);
    TEST_ASSERT_EQUAL_UINT32(8, cap.last_received);
    TEST_ASSERT_FALSE(cap.last_complete);
    TEST_ASSERT_EQUAL_INT(2, cap.calls);
}

/* Streaming mode still enforces offset monotonicity: a gapped offset aborts,
 * exactly like reassembly mode. */
static void test_filetransfer_streaming_gap_aborts(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    file_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    cap.verdict = OSDP_OK;
    osdp_pd_set_file_stream(&pd, file_eval, &cap);

    static const uint8_t f1[4] = { 1, 2, 3, 4 };
    static const uint8_t f2[2] = { 5, 6 };
    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 8, 0, f1, 4, 1);
    osdp_pd_tick(&pd);
    m.outgoing_len = 0;

    inject_filetransfer(&m, 0x05, OSDP_FT_TYPE_OPAQUE, 8, 6, f2, 2, 2);
    osdp_pd_tick(&pd);
    osdp_ftstat_t st;
    decode_ftstat_reply(&m, &st);
    TEST_ASSERT_EQUAL_INT16(OSDP_FTSTAT_ABORT, st.status_detail);
    TEST_ASSERT_EQUAL_INT(1, cap.calls);   /* only the first fragment evaluated */
}

/* A structurally malformed FILETRANSFER (payload shorter than the 11-byte
 * header) is NAK'd with bad command length (0x02), not turned into FTSTAT. */
static void test_filetransfer_malformed_payload_naks(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, default_handler, NULL);

    uint8_t rxbuf[256];
    file_capture_t cap;
    (void)memset(&cap, 0, sizeof(cap));
    cap.verdict = OSDP_OK;
    osdp_pd_set_file_receiver(&pd, rxbuf, sizeof(rxbuf), file_eval, &cap);

    const uint8_t too_short[5] = { 0 };   /* < OSDP_FILETRANSFER_HEADER_BYTES */
    inject_command(&m, 0x05, OSDP_CMD_FILETRANSFER, too_short,
                   sizeof(too_short), OSDP_INTEGRITY_CRC, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_CMD_LENGTH, reply.payload[0]);
    TEST_ASSERT_EQUAL_INT(0, cap.calls);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_init_zero_initializes_address_correctly);
    RUN_TEST(test_init_strips_high_bit_of_address);
    RUN_TEST(test_poll_to_own_address_is_acked);
    RUN_TEST(test_poll_to_broadcast_is_acked_at_config_address);
    RUN_TEST(test_poll_to_other_address_is_ignored);
    RUN_TEST(test_unknown_command_returns_nak_with_unknown_cmd_code);
    RUN_TEST(test_no_handler_attached_yields_nak_for_every_command);
    RUN_TEST(test_scb_bearing_command_returns_nak_unsupported_scb);
    RUN_TEST(test_handler_receives_command_payload);
    RUN_TEST(test_bad_crc_command_addressed_to_pd_naks_bad_check);
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

    RUN_TEST(test_comset_reports_com_and_changes_address);
    RUN_TEST(test_comset_pd_moves_to_new_address);
    RUN_TEST(test_comset_hooks_fire_with_effective_values);
    RUN_TEST(test_comset_decide_override_is_reported_and_applied);
    RUN_TEST(test_comset_out_of_range_address_keeps_current);
    RUN_TEST(test_comset_at_config_address_assigns_and_replies_0xff);
    RUN_TEST(test_comset_malformed_payload_naks);

    RUN_TEST(test_filetransfer_without_receiver_naks);
    RUN_TEST(test_filetransfer_single_fragment_processed);
    RUN_TEST(test_filetransfer_two_fragments_reassemble);
    RUN_TEST(test_filetransfer_too_large_aborts);
    RUN_TEST(test_filetransfer_gap_offset_aborts);
    RUN_TEST(test_filetransfer_callback_rejects_mid_transfer);
    RUN_TEST(test_filetransfer_streaming_no_buffer);
    RUN_TEST(test_filetransfer_streaming_gap_aborts);
    RUN_TEST(test_filetransfer_malformed_payload_naks);
    return UNITY_END();
}
