// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_acu.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_replies.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Mock transport (mirrors test_pd's structure) ----------------------*/

#define MOCK_BUF_LEN 1024U

typedef struct mock_transport {
    uint8_t  incoming[MOCK_BUF_LEN];   /* what the bus delivers to ACU  */
    size_t   incoming_len;
    size_t   incoming_off;
    uint8_t  outgoing[MOCK_BUF_LEN];   /* what the ACU wrote            */
    size_t   outgoing_len;
    uint32_t now_ms;
} mock_transport_t;

static int mock_read(void *user, uint8_t *buf, size_t cap)
{
    mock_transport_t *m = (mock_transport_t *)user;
    /* Defensive: clamp before the unsigned subtraction so a test
     * that resets incoming_len without also clearing incoming_off
     * doesn't underflow into a huge avail. */
    if (m->incoming_off > m->incoming_len) {
        return 0;
    }
    const size_t avail = m->incoming_len - m->incoming_off;
    const size_t n = (cap < avail) ? cap : avail;
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

static void mock_init(mock_transport_t *m, osdp_acu_transport_t *t)
{
    (void)memset(m, 0, sizeof(*m));
    t->read   = mock_read;
    t->write  = mock_write;
    t->now_ms = mock_now_ms;
    t->user   = m;
}

/* Inject a reply frame into the mock transport's incoming buffer so
 * the ACU's next tick will see it. Builds the reply with the supplied
 * address (with reply flag), sequence, code, and payload. */
static void inject_reply(mock_transport_t *m, uint8_t pd_address,
                         uint8_t reply_code, uint8_t sequence,
                         const uint8_t *payload, size_t payload_len,
                         osdp_integrity_t integrity)
{
    osdp_frame_t f = {0};
    f.address     = pd_address;
    f.reply       = true;
    f.sequence    = sequence;
    f.integrity   = integrity;
    f.code        = reply_code;
    f.payload     = payload;
    f.payload_len = payload_len;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &built));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(MOCK_BUF_LEN - m->incoming_len, built);
    (void)memcpy(&m->incoming[m->incoming_len], buf, built);
    m->incoming_len += built;
}

/* ---- Reply / timeout capture ------------------------------------------*/

typedef struct reply_capture {
    unsigned int           call_count;
    osdp_acu_reply_event_t last;
    /* The reply payload pointer aliases into the stream buffer, which
     * gets reused — make a private copy for assertions. */
    uint8_t                last_payload[64];
    size_t                 last_payload_len;
} reply_capture_t;

static void capture_reply(void *user, const osdp_acu_reply_event_t *e)
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

typedef struct timeout_capture {
    unsigned int             call_count;
    osdp_acu_timeout_event_t last;
} timeout_capture_t;

static void capture_timeout(void *user, const osdp_acu_timeout_event_t *e)
{
    timeout_capture_t *c = (timeout_capture_t *)user;
    c->call_count++;
    c->last = *e;
}

/* Helper to set up a fully-wired ACU. Also gives the test a place to
 * stash both captures via a tiny user-pointer struct. */
typedef struct acu_test_ctx {
    reply_capture_t   reply;
    timeout_capture_t timeout;
} acu_test_ctx_t;

static void wire_callbacks(osdp_acu_t *acu, acu_test_ctx_t *ctx)
{
    osdp_acu_set_reply_handler  (acu, capture_reply,   &ctx->reply);
    osdp_acu_set_timeout_handler(acu, capture_timeout, &ctx->timeout);
}

/* Decode the most recent ACU output back into a frame. */
static void decode_outgoing(const mock_transport_t *m, osdp_frame_t *out)
{
    TEST_ASSERT_GREATER_OR_EQUAL(OSDP_FRAME_MIN_LEN_CKSUM, m->outgoing_len);
    /* The builder prepends spec-5.7 marking byte(s) ahead of the SOM;
     * decode the SOM-aligned frame. */
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_decode(m->outgoing + OSDP_FRAME_MARK_LEN,
                                        m->outgoing_len - OSDP_FRAME_MARK_LEN,
                                        out));
}

/* ---- Tests --------------------------------------------------------------*/

static void test_init_zeros_pd_slots(void)
{
    osdp_acu_pd_slot_t slots[3];
    (void)memset(slots, 0xAA, sizeof(slots));   /* poison */
    osdp_acu_t acu;
    osdp_acu_init(&acu, slots, 3);
    for (size_t i = 0; i < 3; i++) {
        TEST_ASSERT_FALSE(slots[i].in_use);
    }
}

static void test_send_command_to_unregistered_pd_fails(void)
{
    osdp_acu_pd_slot_t slots[2];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 2);
    osdp_acu_set_transport(&acu, &t);

    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
}

static void test_first_command_uses_sequence_zero(void)
{
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);

    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    osdp_frame_t cmd;
    decode_outgoing(&m, &cmd);
    TEST_ASSERT_FALSE(cmd.reply);
    TEST_ASSERT_EQUAL_HEX8(0x10, cmd.address);
    TEST_ASSERT_EQUAL_UINT8(0, cmd.sequence);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, cmd.code);
    TEST_ASSERT_TRUE(osdp_acu_is_pd_busy(&acu, 0x10));
}

static void test_sequence_progression_zero_one_two_three_one(void)
{
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);

    acu_test_ctx_t ctx = {0};
    wire_callbacks(&acu, &ctx);

    static const uint8_t expected_sqns[] = { 0, 1, 2, 3, 1, 2, 3, 1 };
    for (size_t i = 0; i < sizeof(expected_sqns); i++) {
        TEST_ASSERT_EQUAL(OSDP_OK,
                          osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                                NULL, 0));
        /* The most recently appended frame begins at offset
         * outgoing_len - last_frame_len. We can find it by re-decoding
         * the entire outgoing buffer record-by-record using the stream
         * decoder, but easier: reset the buffer between iterations. */
        osdp_frame_t cmd;
        TEST_ASSERT_EQUAL(OSDP_OK,
                          osdp_frame_decode(
                              &m.outgoing[m.outgoing_len -
                                          OSDP_FRAME_MIN_LEN_CRC],
                              OSDP_FRAME_MIN_LEN_CRC, &cmd));
        TEST_ASSERT_EQUAL_UINT8(expected_sqns[i], cmd.sequence);

        /* Inject the reply so the slot becomes free for the next
         * iteration. */
        inject_reply(&m, 0x10, OSDP_REPLY_ACK, expected_sqns[i],
                     NULL, 0, OSDP_INTEGRITY_CRC);
        osdp_acu_tick(&acu);
        TEST_ASSERT_FALSE(osdp_acu_is_pd_busy(&acu, 0x10));
    }
}

static void test_busy_send_during_outstanding_command_returns_error(void)
{
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);

    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
}

static void test_reply_dispatches_to_callback_with_command_context(void)
{
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);
    acu_test_ctx_t ctx = {0};
    wire_callbacks(&acu, &ctx);

    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_ID,
                                            (const uint8_t[]){0x00}, 1));

    static const uint8_t pdid_payload[12] = {
        0xCA, 0xFE, 0x00,    /* vendor */
        0x10,                /* model */
        0x01,                /* version */
        0xEF, 0xBE, 0xAD, 0xDE, /* serial LE */
        0x01, 0x02, 0x03,    /* firmware */
    };
    inject_reply(&m, 0x10, OSDP_REPLY_PDID, 0,
                 pdid_payload, sizeof(pdid_payload), OSDP_INTEGRITY_CRC);
    osdp_acu_tick(&acu);

    TEST_ASSERT_EQUAL_UINT(1, ctx.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(0x10, ctx.reply.last.pd_address);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_ID,    ctx.reply.last.cmd_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDID, ctx.reply.last.reply_code);
    TEST_ASSERT_EQUAL_size_t(sizeof(pdid_payload), ctx.reply.last_payload_len);
    TEST_ASSERT_EQUAL_MEMORY(pdid_payload, ctx.reply.last_payload,
                             sizeof(pdid_payload));
    TEST_ASSERT_FALSE(osdp_acu_is_pd_busy(&acu, 0x10));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_online(&acu, 0x10));
}

static void test_reply_with_wrong_sqn_is_ignored(void)
{
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);
    acu_test_ctx_t ctx = {0};
    wire_callbacks(&acu, &ctx);

    /* Send command at SQN=0; reply with SQN=1 (wrong). */
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    inject_reply(&m, 0x10, OSDP_REPLY_ACK, 1, NULL, 0,
                 OSDP_INTEGRITY_CRC);
    osdp_acu_tick(&acu);

    TEST_ASSERT_EQUAL_UINT(0, ctx.reply.call_count);
    TEST_ASSERT_TRUE(osdp_acu_is_pd_busy(&acu, 0x10));
}

static void test_reply_from_unknown_pd_is_ignored(void)
{
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);
    acu_test_ctx_t ctx = {0};
    wire_callbacks(&acu, &ctx);

    /* No command sent — reply from random PD on the bus. */
    inject_reply(&m, 0x05, OSDP_REPLY_ACK, 0, NULL, 0,
                 OSDP_INTEGRITY_CRC);
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(0, ctx.reply.call_count);
}

static void test_command_frames_inbound_are_ignored(void)
{
    /* The ACU should never react to a frame in the command direction
     * (no reply flag); those are for PDs to consume. */
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);
    acu_test_ctx_t ctx = {0};
    wire_callbacks(&acu, &ctx);

    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));

    /* Inject a command-direction frame (reply flag clear). */
    osdp_frame_t f = {0};
    f.address = 0x10; f.integrity = OSDP_INTEGRITY_CRC; f.code = OSDP_CMD_POLL;
    uint8_t buf[16]; size_t built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &built));
    (void)memcpy(&m.incoming[m.incoming_len], buf, built);
    m.incoming_len += built;

    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(0, ctx.reply.call_count);
    TEST_ASSERT_TRUE(osdp_acu_is_pd_busy(&acu, 0x10));
}

static void test_reply_timeout_fires_after_200ms(void)
{
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);
    acu_test_ctx_t ctx = {0};
    wire_callbacks(&acu, &ctx);

    m.now_ms = 1000;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_busy(&acu, 0x10));

    /* Advance just past the timeout. */
    m.now_ms = 1000 + OSDP_ACU_REPLY_TIMEOUT_MS + 1;
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(1, ctx.timeout.call_count);
    TEST_ASSERT_EQUAL_HEX8(0x10, ctx.timeout.last.pd_address);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, ctx.timeout.last.cmd_code);
    TEST_ASSERT_EQUAL_UINT8(0, ctx.timeout.last.cmd_seq);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_busy(&acu, 0x10));
}

static void test_timeout_then_retry_reuses_same_sqn(void)
{
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);
    acu_test_ctx_t ctx = {0};
    wire_callbacks(&acu, &ctx);

    m.now_ms = 1000;
    /* First command at SQN 0. */
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));

    /* Time out. */
    m.now_ms = 1300;
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(1, ctx.timeout.call_count);

    /* Retry: should re-use SQN 0 (not advance). */
    const size_t prev_outgoing = m.outgoing_len;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    osdp_frame_t cmd;
    /* The retry frame starts at prev_outgoing with the spec-5.7 marking
     * byte(s) ahead of its SOM; decode the SOM-aligned frame. */
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_decode(
                          &m.outgoing[prev_outgoing + OSDP_FRAME_MARK_LEN],
                          m.outgoing_len - prev_outgoing - OSDP_FRAME_MARK_LEN,
                          &cmd));
    TEST_ASSERT_EQUAL_UINT8(0, cmd.sequence);
}

static void test_multi_pd_isolated_state(void)
{
    osdp_acu_pd_slot_t slots[2];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 2);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);
    osdp_acu_register_pd(&acu, 1, 0x20);
    acu_test_ctx_t ctx = {0};
    wire_callbacks(&acu, &ctx);

    /* Send to both PDs. */
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x20, OSDP_CMD_POLL,
                                            NULL, 0));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_busy(&acu, 0x10));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_busy(&acu, 0x20));

    /* Reply only from 0x20. */
    inject_reply(&m, 0x20, OSDP_REPLY_ACK, 0, NULL, 0,
                 OSDP_INTEGRITY_CRC);
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(1, ctx.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(0x20, ctx.reply.last.pd_address);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_busy(&acu, 0x20));
    /* 0x10 still waiting. */
    TEST_ASSERT_TRUE(osdp_acu_is_pd_busy(&acu, 0x10));

    /* Now reply from 0x10. */
    inject_reply(&m, 0x10, OSDP_REPLY_ACK, 0, NULL, 0,
                 OSDP_INTEGRITY_CRC);
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(2, ctx.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(0x10, ctx.reply.last.pd_address);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_busy(&acu, 0x10));
}

static void test_pd_offline_after_eight_seconds_silence(void)
{
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_t acu;
    mock_transport_t m;
    osdp_acu_transport_t t;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_register_pd(&acu, 0, 0x10);
    acu_test_ctx_t ctx = {0};
    wire_callbacks(&acu, &ctx);

    /* Successful exchange marks PD online. */
    m.now_ms = 1000;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    inject_reply(&m, 0x10, OSDP_REPLY_ACK, 0, NULL, 0,
                 OSDP_INTEGRITY_CRC);
    osdp_acu_tick(&acu);
    TEST_ASSERT_TRUE(osdp_acu_is_pd_online(&acu, 0x10));

    /* Big silence — but no outstanding command (so no timeout fires). */
    m.now_ms = 1000 + OSDP_ACU_OFFLINE_TIMEOUT_MS + 1;
    osdp_acu_tick(&acu);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_online(&acu, 0x10));
}

/* ---- Inter-character timeout (spec 5.8), reply direction ----------------
 *
 * The ACU twin of the PD-side tests in test_pd.c. The failure it guards
 * against is a truncated reply's bytes sitting in the decoder forever: the
 * reply timeout clears slot->waiting but nothing empties acu->rx, so the
 * application's retry gets decoded onto the stale prefix and fails its CRC.
 */

/* Build a large reply, then hand over only its first `keep` bytes.
 *
 * The size matters. A reply cut one byte short is harmless: the decoder finds
 * the CRC bad, drops a byte, resyncs to the next SOM and recovers on its own.
 * The trap is a stale prefix that declares a LEN far bigger than what arrived
 * — the decoder is then not wrong, it is *waiting*, and it goes on waiting
 * while every subsequent reply is swallowed into the phantom frame. That is
 * what nothing but the inter-character abort can clear. */
static void inject_truncated_reply(mock_transport_t *m, uint8_t pd_address,
                                   uint8_t reply_code, uint8_t sequence,
                                   size_t keep)
{
    uint8_t payload[64];
    (void)memset(payload, 0xA5, sizeof(payload));

    osdp_frame_t f = {0};
    f.address     = pd_address;
    f.reply       = true;
    f.sequence    = sequence;
    f.integrity   = OSDP_INTEGRITY_CRC;
    f.code        = reply_code;
    f.payload     = payload;
    f.payload_len = sizeof(payload);

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &built));
    TEST_ASSERT_TRUE(keep < built);
    (void)memcpy(&m->incoming[m->incoming_len], buf, keep);
    m->incoming_len += keep;
}

static void test_a_truncated_reply_does_not_poison_the_retry(void)
{
    osdp_acu_pd_slot_t  slots[1];
    osdp_acu_t          acu;
    mock_transport_t    m;
    osdp_acu_transport_t t;
    acu_test_ctx_t      ctx = {0};

    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    wire_callbacks(&acu, &ctx);
    osdp_acu_register_pd(&acu, 0, 0x10);

    m.now_ms = 1000;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));

    /* The PD starts a ~73-byte reply and the line dies after 12 bytes. The
     * header is intact, so the decoder is correctly waiting for the other
     * 61 — it has no way to know they are never coming. */
    inject_truncated_reply(&m, 0x10, OSDP_REPLY_MFGREP, 0, 12);
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(0, ctx.reply.call_count);

    /* The line goes quiet past the inter-character timeout, so the receive
     * is aborted. The reply timeout then fires as usual. */
    m.now_ms = 1000 + OSDP_ACU_REPLY_TIMEOUT_MS + 1;
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(1, ctx.timeout.call_count);

    /* The application retries at the same SQN and the PD answers cleanly.
     * Without the abort the 12 stale bytes are still in front of it, the
     * decoder counts this reply toward the phantom frame's outstanding 61,
     * and it never surfaces — the link stays down while both ends behave
     * perfectly. */
    m.outgoing_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));
    inject_reply(&m, 0x10, OSDP_REPLY_ACK, 0, NULL, 0, OSDP_INTEGRITY_CRC);
    osdp_acu_tick(&acu);

    TEST_ASSERT_EQUAL_UINT(1, ctx.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, ctx.reply.last.reply_code);
}

/* The timeout must not fire on a reply that is merely arriving slowly, or a
 * batching transport would never complete a large reply at all.
 *
 * Exactly ONE over-timeout gap, unlike the PD-side twin which walks a byte at
 * a time. The ACU has its own reply timeout and this has to stay inside it,
 * and at the OSDP_BUFFERED_TRANSPORT default only one such gap fits: 150+1 is
 * under 200, two of them are not. Two chunks with one gap is also the shape a
 * batching transport actually delivers in, which is the case that motivated
 * the timeout being widened at all. */
_Static_assert(OSDP_ACU_INTERCHAR_TIMEOUT_MS + 1U < OSDP_ACU_REPLY_TIMEOUT_MS,
               "the slow-arrival test needs one over-timeout gap to fit "
               "inside the reply timeout");

static void test_a_reply_still_arriving_is_not_aborted(void)
{
    osdp_acu_pd_slot_t  slots[1];
    osdp_acu_t          acu;
    mock_transport_t    m;
    osdp_acu_transport_t t;
    acu_test_ctx_t      ctx = {0};

    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    wire_callbacks(&acu, &ctx);
    osdp_acu_register_pd(&acu, 0, 0x10);

    m.now_ms = 1000;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));

    osdp_frame_t f = {0};
    f.address   = 0x10;
    f.reply     = true;
    f.sequence  = 0;
    f.integrity = OSDP_INTEGRITY_CRC;
    f.code      = OSDP_REPLY_ACK;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &built));

    /* First chunk: everything but the last two bytes. */
    TEST_ASSERT_TRUE(built > 2);
    (void)memcpy(&m.incoming[m.incoming_len], buf, built - 2);
    m.incoming_len += built - 2;
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(0, ctx.reply.call_count);

    /* A gap longer than the inter-character timeout, then the rest. The
     * buffered count grows on this tick, so the receive is still making
     * progress and must not have been aborted. */
    m.now_ms += OSDP_ACU_INTERCHAR_TIMEOUT_MS + 1;
    (void)memcpy(&m.incoming[m.incoming_len], buf + (built - 2), 2);
    m.incoming_len += 2;
    osdp_acu_tick(&acu);

    TEST_ASSERT_EQUAL_UINT(1, ctx.reply.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, ctx.reply.last.reply_code);
    TEST_ASSERT_EQUAL_UINT(0, ctx.timeout.call_count);
}

/* Without a clock there is nothing to time, so the abort must not fire — and
 * must not discard a reply that is simply still arriving. */
static void test_acu_no_clock_leaves_a_partial_reply_alone(void)
{
    osdp_acu_pd_slot_t  slots[1];
    osdp_acu_t          acu;
    mock_transport_t    m;
    osdp_acu_transport_t t;
    acu_test_ctx_t      ctx = {0};

    mock_init(&m, &t);
    t.now_ms = NULL;              /* no clock */
    osdp_acu_init(&acu, slots, 1);
    osdp_acu_set_transport(&acu, &t);
    wire_callbacks(&acu, &ctx);
    osdp_acu_register_pd(&acu, 0, 0x10);
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acu_send_command(&acu, 0x10, OSDP_CMD_POLL,
                                            NULL, 0));

    osdp_frame_t f = {0};
    f.address   = 0x10;
    f.reply     = true;
    f.sequence  = 0;
    f.integrity = OSDP_INTEGRITY_CRC;
    f.code      = OSDP_REPLY_ACK;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &built));

    /* Deliver all but the last byte, tick a few times, then finish it. With
     * no clock the residue must still be there to complete. */
    (void)memcpy(&m.incoming[m.incoming_len], buf, built - 1);
    m.incoming_len += built - 1;
    osdp_acu_tick(&acu);
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(0, ctx.reply.call_count);

    m.incoming[m.incoming_len++] = buf[built - 1];
    osdp_acu_tick(&acu);
    TEST_ASSERT_EQUAL_UINT(1, ctx.reply.call_count);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_init_zeros_pd_slots);
    RUN_TEST(test_send_command_to_unregistered_pd_fails);
    RUN_TEST(test_first_command_uses_sequence_zero);
    RUN_TEST(test_sequence_progression_zero_one_two_three_one);
    RUN_TEST(test_busy_send_during_outstanding_command_returns_error);
    RUN_TEST(test_reply_dispatches_to_callback_with_command_context);
    RUN_TEST(test_reply_with_wrong_sqn_is_ignored);
    RUN_TEST(test_reply_from_unknown_pd_is_ignored);
    RUN_TEST(test_command_frames_inbound_are_ignored);
    RUN_TEST(test_reply_timeout_fires_after_200ms);
    RUN_TEST(test_timeout_then_retry_reuses_same_sqn);
    RUN_TEST(test_multi_pd_isolated_state);
    RUN_TEST(test_pd_offline_after_eight_seconds_silence);
    RUN_TEST(test_a_truncated_reply_does_not_poison_the_retry);
    RUN_TEST(test_a_reply_still_arriving_is_not_aborted);
    RUN_TEST(test_acu_no_clock_leaves_a_partial_reply_alone);
    return UNITY_END();
}
