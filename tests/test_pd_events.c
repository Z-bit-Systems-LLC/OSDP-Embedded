// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Poll-response event queue, osdp_BUSY, and the Table 47 NAK mapping.
 *
 * These three land together because they are the parts of Phase 4 that change
 * what comes back for an ordinary command rather than adding a new one, so
 * each test drives a real frame and decodes the wire bytes.
 */

#include "osdp/osdp_commands.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_replies.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Mock transport ----------------------------------------------------*/

#define MOCK_BUF_LEN 2048U

typedef struct mock_transport {
    uint8_t  incoming[MOCK_BUF_LEN];
    size_t   incoming_len;
    size_t   incoming_off;
    uint8_t  outgoing[MOCK_BUF_LEN];
    size_t   outgoing_len;
    uint32_t now_ms;
} mock_transport_t;

static int mock_read(void *user, uint8_t *buf, size_t cap)
{
    mock_transport_t *m = (mock_transport_t *)user;
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

static void inject(mock_transport_t *m, uint8_t code,
                   const uint8_t *payload, size_t payload_len, uint8_t seq)
{
    osdp_frame_t f = {0};
    f.address     = 0x05;
    f.sequence    = seq;
    f.integrity   = OSDP_INTEGRITY_CRC;
    f.code        = code;
    f.payload     = payload;
    f.payload_len = payload_len;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  written = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &written));
    (void)memcpy(&m->incoming[m->incoming_len], buf, written);
    m->incoming_len += written;
}

static void decode_reply(const mock_transport_t *m, osdp_frame_t *out)
{
    TEST_ASSERT_GREATER_OR_EQUAL(OSDP_FRAME_MIN_LEN_CKSUM, m->outgoing_len);
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_decode(m->outgoing + OSDP_FRAME_MARK_LEN,
                                        m->outgoing_len - OSDP_FRAME_MARK_LEN,
                                        out));
}

/* ---- Application handlers ----------------------------------------------*/

/* Returns whatever `next_status` says, so a test can exercise each Table 47
 * mapping without a bespoke handler per case. */
static osdp_status_t next_status = OSDP_OK;
static unsigned int  handler_calls;

static osdp_status_t status_handler(void *user, uint8_t cmd_code,
                                    const uint8_t *payload, size_t payload_len,
                                    osdp_pd_reply_t *reply)
{
    (void)user; (void)cmd_code; (void)payload; (void)payload_len;
    handler_calls++;
    reply->code        = OSDP_REPLY_ACK;
    reply->payload     = NULL;
    reply->payload_len = 0;
    return next_status;
}

static void setup(osdp_pd_t *pd, mock_transport_t *m, osdp_pd_transport_t *t)
{
    mock_init(m, t);
    osdp_pd_init(pd, 0x05);
    osdp_pd_set_transport(pd, t);
    handler_calls = 0;
    next_status   = OSDP_OK;
    osdp_pd_set_command_handler(pd, status_handler, NULL);
}

/* ---- Event queue -------------------------------------------------------*/

static void test_queued_event_answers_the_next_poll(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    static uint8_t q[256];
    setup(&pd, &m, &t);
    osdp_pd_set_event_queue(&pd, q, sizeof(q));

    /* A card read, encoded as the application would. */
    static const uint8_t raw_body[] = { 0x00, 0x01, 0x1A, 0x00,
                                        0xDE, 0xAD, 0xBE };
    TEST_ASSERT_FALSE(osdp_pd_event_pending(&pd));
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pd_enqueue_event(&pd, OSDP_REPLY_RAW,
                                            raw_body, sizeof(raw_body)));
    TEST_ASSERT_TRUE(osdp_pd_event_pending(&pd));

    inject(&m, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RAW, reply.code);
    TEST_ASSERT_EQUAL_size_t(sizeof(raw_body), reply.payload_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(raw_body, reply.payload, sizeof(raw_body));

    /* Answered from the queue, so the application never saw the poll. */
    TEST_ASSERT_EQUAL_UINT(0, handler_calls);
    TEST_ASSERT_FALSE(osdp_pd_event_pending(&pd));
}

/* FIFO, and the ordering survives the compaction the dequeue performs. */
static void test_events_are_delivered_in_order(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    static uint8_t q[256];
    setup(&pd, &m, &t);
    osdp_pd_set_event_queue(&pd, q, sizeof(q));

    static const uint8_t first[]  = { 0xA1, 0xA2 };
    static const uint8_t second[] = { 0xB1, 0xB2, 0xB3 };
    static const uint8_t third[]  = { 0xC1 };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_enqueue_event(&pd, OSDP_REPLY_RAW,
                                                     first, sizeof(first)));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_enqueue_event(&pd, OSDP_REPLY_KEYPAD,
                                                     second, sizeof(second)));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_enqueue_event(&pd, OSDP_REPLY_MFGREP,
                                                     third, sizeof(third)));

    struct { uint8_t code; const uint8_t *body; size_t len; } expect[] = {
        { OSDP_REPLY_RAW,    first,  sizeof(first)  },
        { OSDP_REPLY_KEYPAD, second, sizeof(second) },
        { OSDP_REPLY_MFGREP, third,  sizeof(third)  },
    };

    for (size_t i = 0; i < 3; i++) {
        m.outgoing_len = 0;
        inject(&m, OSDP_CMD_POLL, NULL, 0, (uint8_t)(1 + (i % 3)));
        osdp_pd_tick(&pd);

        osdp_frame_t reply;
        decode_reply(&m, &reply);
        TEST_ASSERT_EQUAL_HEX8(expect[i].code, reply.code);
        TEST_ASSERT_EQUAL_size_t(expect[i].len, reply.payload_len);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(expect[i].body, reply.payload,
                                     expect[i].len);
    }
    TEST_ASSERT_FALSE(osdp_pd_event_pending(&pd));
}

/* An empty queue must be invisible: the poll reaches the application exactly
 * as it did before the queue existed. */
static void test_empty_queue_falls_through_to_the_application(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    static uint8_t q[64];
    setup(&pd, &m, &t);
    osdp_pd_set_event_queue(&pd, q, sizeof(q));

    inject(&m, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_UINT(1, handler_calls);
}

static void test_full_queue_reports_buffer_too_small(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    static uint8_t q[16];
    setup(&pd, &m, &t);
    osdp_pd_set_event_queue(&pd, q, sizeof(q));

    static const uint8_t body[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    /* 3-byte header + 8 = 11 fits; a second would need 22. */
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pd_enqueue_event(&pd, OSDP_REPLY_RAW, body,
                                            sizeof(body)));
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pd_enqueue_event(&pd, OSDP_REPLY_RAW, body,
                                            sizeof(body)));
    /* The first is still intact — a rejected enqueue must not corrupt the
     * queue it declined to join. */
    TEST_ASSERT_TRUE(osdp_pd_event_pending(&pd));
}

static void test_enqueue_without_a_bound_queue_is_rejected(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);

    static const uint8_t body[2] = { 1, 2 };
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pd_enqueue_event(&pd, OSDP_REPLY_RAW, body, 2));
    TEST_ASSERT_FALSE(osdp_pd_event_pending(&pd));
}

/* Spec 7.11/7.12: unreported data is discarded on a communication loss.
 * Delivering a card read from before the outage would have the ACU act on a
 * presentation that happened minutes ago. */
static void test_going_offline_discards_queued_events(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    static uint8_t q[128];
    setup(&pd, &m, &t);
    osdp_pd_set_event_queue(&pd, q, sizeof(q));

    /* Get online first — the offline transition only fires from online. */
    inject(&m, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_TRUE(osdp_pd_is_online(&pd));

    static const uint8_t body[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pd_enqueue_event(&pd, OSDP_REPLY_RAW, body, 4));
    TEST_ASSERT_TRUE(osdp_pd_event_pending(&pd));

    /* Silence past the offline timeout. */
    m.now_ms += OSDP_PD_OFFLINE_TIMEOUT_MS + 1000U;
    osdp_pd_tick(&pd);

    TEST_ASSERT_FALSE(osdp_pd_is_online(&pd));
    TEST_ASSERT_FALSE(osdp_pd_event_pending(&pd));
}

static void test_clear_events_drops_everything(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    static uint8_t q[128];
    setup(&pd, &m, &t);
    osdp_pd_set_event_queue(&pd, q, sizeof(q));

    static const uint8_t body[2] = { 1, 2 };
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pd_enqueue_event(&pd, OSDP_REPLY_RAW, body, 2));
    osdp_pd_clear_events(&pd);
    TEST_ASSERT_FALSE(osdp_pd_event_pending(&pd));
}

/* ---- osdp_BUSY ---------------------------------------------------------*/

static void test_busy_reply_uses_sequence_zero(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);
    next_status = OSDP_ERR_BUSY;

    /* Sent at SQN 2, so mirroring would give 2 — spec 7.19 says always 0. */
    inject(&m, OSDP_CMD_POLL, NULL, 0, 2);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_BUSY, reply.code);
    TEST_ASSERT_EQUAL_UINT8(0, reply.sequence);
    TEST_ASSERT_EQUAL_size_t(0, reply.payload_len);
    TEST_ASSERT_FALSE(reply.has_scb);
}

/* The ACU repeats a BUSY'd command in its original form. If the PD cached the
 * BUSY as its retransmit answer it would keep replaying it even once ready,
 * and the exchange would never progress. */
static void test_busy_is_not_cached_as_the_retransmit_reply(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);

    next_status = OSDP_ERR_BUSY;
    inject(&m, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);
    osdp_frame_t first;
    decode_reply(&m, &first);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_BUSY, first.code);
    TEST_ASSERT_EQUAL_UINT(1, handler_calls);

    /* The PD is now ready. The ACU repeats the identical command. */
    next_status    = OSDP_OK;
    m.outgoing_len = 0;
    inject(&m, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t second;
    decode_reply(&m, &second);
    /* Processed fresh, not replayed: an ACK, and the handler ran again. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, second.code);
    TEST_ASSERT_EQUAL_UINT(2, handler_calls);
}

/* ---- Table 47 NAK mapping ----------------------------------------------*/

/* Before this mapping, anything other than OSDP_OK / NOT_SUPPORTED was
 * dropped silently and the ACU learned nothing until its timeout expired. */
static void test_handler_status_maps_onto_table_47_naks(void)
{
    const struct { osdp_status_t status; uint8_t nak; } cases[] = {
        { OSDP_ERR_NOT_SUPPORTED, OSDP_NAK_UNKNOWN_CMD    },
        { OSDP_ERR_BAD_PAYLOAD,   OSDP_NAK_CMD_LENGTH     },
        { OSDP_ERR_BAD_LENGTH,    OSDP_NAK_CMD_LENGTH     },
        { OSDP_ERR_INVALID_ARG,   OSDP_NAK_RECORD_INVALID },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
        setup(&pd, &m, &t);
        next_status = cases[i].status;

        inject(&m, OSDP_CMD_POLL, NULL, 0, 1);
        osdp_pd_tick(&pd);

        osdp_frame_t reply;
        decode_reply(&m, &reply);
        TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
        TEST_ASSERT_EQUAL_size_t(1, reply.payload_len);
        TEST_ASSERT_EQUAL_HEX8(cases[i].nak, reply.payload[0]);
    }
}

/* A status the mapping does not recognise still drops silently — the escape
 * hatch survives, it just is not the default any more. */
static void test_unrecognised_handler_status_still_drops_silently(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);
    next_status = OSDP_ERR_BAD_CRC;   /* nonsensical from a handler */

    inject(&m, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);

    TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);
}

/* ---- osdp_ABORT / osdp_ACURXSIZE / osdp_KEEPACTIVE --------------------
 *
 * All three are library-handled: they never reach cmd_cb, which is what the
 * handler_calls assertions below are checking.
 */

static unsigned int abort_calls;
static osdp_status_t abort_verdict = OSDP_OK;

static osdp_status_t abort_hook(void *user)
{
    (void)user;
    abort_calls++;
    return abort_verdict;
}

static void test_abort_is_acked_and_never_reaches_the_application(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);

    inject(&m, OSDP_CMD_ABORT, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_UINT(0, handler_calls);
}

/* Spec 6.22: the PD "shall terminate any multi-part message or file transfer
 * operation currently in progress". */
static osdp_status_t file_eval(void *user, const osdp_pd_file_info_t *info)
{
    (void)user; (void)info;
    return OSDP_OK;
}

static void test_abort_terminates_an_in_flight_file_transfer(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    static uint8_t rxbuf[64];
    setup(&pd, &m, &t);
    osdp_pd_set_file_receiver(&pd, rxbuf, sizeof(rxbuf), file_eval, NULL);

    /* First fragment of a 16-byte file: 4 bytes now, transfer left open. */
    static const uint8_t frag[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    osdp_filetransfer_cmd_t ft = { .ft_type = 1, .total_size = 16,
                                   .offset = 0, .fragment_size = sizeof(frag),
                                   .data = frag, .data_len = sizeof(frag) };
    uint8_t ftbuf[64]; size_t ftlen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_filetransfer_build(&ft, ftbuf, sizeof(ftbuf), &ftlen));

    inject(&m, OSDP_CMD_FILETRANSFER, ftbuf, ftlen, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_TRUE(pd.ft_active);

    m.outgoing_len = 0;
    inject(&m, OSDP_CMD_ABORT, NULL, 0, 2);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    /* The transfer is gone, so the ACU can restart cleanly at offset 0. */
    TEST_ASSERT_FALSE(pd.ft_active);
    TEST_ASSERT_EQUAL_UINT32(0, pd.ft_received);
}

/* Spec 6.22: "If a PD is not able to abort an operation ... it should return
 * an osdp_NAK." */
static void test_abort_hook_refusal_becomes_nak(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);
    abort_calls   = 0;
    abort_verdict = OSDP_ERR_NOT_SUPPORTED;
    osdp_pd_set_abort_handler(&pd, abort_hook, NULL);

    inject(&m, OSDP_CMD_ABORT, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, reply.payload[0]);
    TEST_ASSERT_EQUAL_UINT(1, abort_calls);

    abort_verdict = OSDP_OK;
}

static uint16_t notified_rx_size;
static unsigned int acurxsize_calls;

static void acurxsize_hook(void *user, uint16_t max_size)
{
    (void)user;
    acurxsize_calls++;
    notified_rx_size = max_size;
}

static void test_acurxsize_is_stored_and_acked(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);
    acurxsize_calls = 0;
    osdp_pd_set_acurxsize_handler(&pd, acurxsize_hook, NULL);

    /* Default until an ACU says otherwise (spec 6.26). */
    TEST_ASSERT_EQUAL_UINT16(OSDP_PD_DEFAULT_ACU_RX_SIZE,
                             osdp_pd_acu_rx_size(&pd));

    osdp_acurxsize_cmd_t cmd = { .max_size = 1024 };
    uint8_t body[OSDP_ACURXSIZE_PAYLOAD_BYTES]; size_t blen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_acurxsize_build(&cmd, body, sizeof(body), &blen));

    inject(&m, OSDP_CMD_ACURXSIZE, body, blen, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_UINT16(1024, osdp_pd_acu_rx_size(&pd));
    TEST_ASSERT_EQUAL_UINT(1, acurxsize_calls);
    TEST_ASSERT_EQUAL_UINT16(1024, notified_rx_size);
    TEST_ASSERT_EQUAL_UINT(0, handler_calls);
}

static void test_malformed_acurxsize_naks_bad_length(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);

    static const uint8_t one_byte[1] = { 0x10 };
    inject(&m, OSDP_CMD_ACURXSIZE, one_byte, 1, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_CMD_LENGTH, reply.payload[0]);
    /* A malformed command must not have moved the stored value. */
    TEST_ASSERT_EQUAL_UINT16(OSDP_PD_DEFAULT_ACU_RX_SIZE,
                             osdp_pd_acu_rx_size(&pd));
}

static uint16_t keepactive_ms;
static unsigned int keepactive_calls;
static osdp_status_t keepactive_verdict = OSDP_OK;

static osdp_status_t keepactive_hook(void *user, uint16_t time_ms)
{
    (void)user;
    keepactive_calls++;
    keepactive_ms = time_ms;
    return keepactive_verdict;
}

static void build_keepactive(uint8_t *buf, size_t cap, size_t *len,
                             uint16_t ms)
{
    osdp_keepactive_cmd_t cmd = { .time_ms = ms };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_keepactive_build(&cmd, buf, cap, len));
}

static void test_keepactive_reaches_the_handler_and_acks(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);
    keepactive_calls   = 0;
    keepactive_verdict = OSDP_OK;
    osdp_pd_set_keepactive_handler(&pd, keepactive_hook, NULL);

    uint8_t body[OSDP_KEEPACTIVE_PAYLOAD_BYTES]; size_t blen = 0;
    build_keepactive(body, sizeof(body), &blen, 3000);

    inject(&m, OSDP_CMD_KEEPACTIVE, body, blen, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_UINT(1, keepactive_calls);
    TEST_ASSERT_EQUAL_UINT16(3000, keepactive_ms);
    TEST_ASSERT_EQUAL_UINT(0, handler_calls);
}

/* Holding a reader field energised is physical. With no handler the honest
 * answer is "I don't implement that", not an ACK the PD cannot honour. */
static void test_keepactive_without_a_handler_naks(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);

    uint8_t body[OSDP_KEEPACTIVE_PAYLOAD_BYTES]; size_t blen = 0;
    build_keepactive(body, sizeof(body), &blen, 1000);

    inject(&m, OSDP_CMD_KEEPACTIVE, body, blen, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, reply.payload[0]);
}

/* ---- osdp_MFG -> osdp_MFGREP -------------------------------------------
 *
 * Not library-handled and deliberately so: the content is vendor-defined, so
 * the application answers it through the ordinary handler. This pins the
 * documented pattern — a handler returning a built osdp_MFGREP body.
 */

static const uint8_t kVendor[3] = { 0x5A, 0x42, 0x43 };
static uint8_t mfg_reply_buf[32];

static osdp_status_t mfg_handler(void *user, uint8_t cmd_code,
                                 const uint8_t *payload, size_t payload_len,
                                 osdp_pd_reply_t *reply)
{
    (void)user;
    if (cmd_code != OSDP_CMD_MFG) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    osdp_mfg_cmd_t req;
    if (osdp_mfg_decode(payload, payload_len, &req) != OSDP_OK) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    /* Only answer our own vendor code — the check the spec recommends. */
    if (memcmp(req.vendor_code, kVendor, sizeof(kVendor)) != 0) {
        return OSDP_ERR_INVALID_ARG;
    }

    static const uint8_t answer[] = { 0x01, 0x02, 0x03 };
    osdp_mfgrep_t rep = { .data = answer, .data_len = sizeof(answer) };
    (void)memcpy(rep.vendor_code, kVendor, sizeof(kVendor));
    size_t built = 0;
    if (osdp_mfgrep_build(&rep, mfg_reply_buf, sizeof(mfg_reply_buf),
                          &built) != OSDP_OK) {
        return OSDP_ERR_INVALID_ARG;
    }
    reply->code        = OSDP_REPLY_MFGREP;
    reply->payload     = mfg_reply_buf;
    reply->payload_len = built;
    return OSDP_OK;
}

static void test_mfg_round_trips_to_mfgrep_through_the_handler(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, mfg_handler, NULL);

    static const uint8_t req_data[] = { 0x10, 0x20 };
    osdp_mfg_cmd_t req = { .data = req_data, .data_len = sizeof(req_data) };
    (void)memcpy(req.vendor_code, kVendor, sizeof(kVendor));
    uint8_t body[32]; size_t blen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfg_build(&req, body, sizeof(body), &blen));

    inject(&m, OSDP_CMD_MFG, body, blen, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_MFGREP, reply.code);

    osdp_mfgrep_t got;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_mfgrep_decode(reply.payload, reply.payload_len, &got));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kVendor, got.vendor_code, sizeof(kVendor));
    TEST_ASSERT_EQUAL_size_t(3, got.data_len);
}

/* A foreign vendor code exercises the 4g mapping from a realistic handler:
 * OSDP_ERR_INVALID_ARG means "recognised but unusable record" = NAK 0x09. */
static void test_mfg_for_another_vendor_naks_record_invalid(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, mfg_handler, NULL);

    osdp_mfg_cmd_t req = { .vendor_code = { 0x00, 0x00, 0x01 },
                           .data = NULL, .data_len = 0 };
    uint8_t body[16]; size_t blen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfg_build(&req, body, sizeof(body), &blen));

    inject(&m, OSDP_CMD_MFG, body, blen, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_RECORD_INVALID, reply.payload[0]);
}

/* ---- Multi-part osdp_MFG (spec 5.10 + 6.19) ---------------------------
 *
 * Fragmented vendor data is  vendor[3] || Mp[6] || fragment , with the vendor
 * code outside the fragmentation so the PD can tell whether a transfer is
 * addressed to it before committing its buffer.
 *
 * Nothing on the wire distinguishes a multi-part header from six bytes of
 * ordinary vendor data, so binding a receiver is how a manufacturer declares
 * its protocol uses the standard format. The last test here pins the other
 * half of that: with no receiver bound, the payload stays opaque.
 */

static const uint8_t kMfgVendor[3] = { 0x5A, 0x42, 0x43 };

static uint8_t      mfg_asm_buf[256];
static unsigned int mfg_complete_calls;
static uint8_t      mfg_seen[256];
static size_t       mfg_seen_len;
static uint8_t      mfg_seen_vendor[3];
static osdp_status_t mfg_verdict = OSDP_OK;

static osdp_status_t mfg_receiver(void *user, const uint8_t *vendor_code,
                                  const uint8_t *data, size_t data_len,
                                  osdp_pd_reply_t *reply)
{
    (void)user; (void)reply;
    mfg_complete_calls++;
    (void)memcpy(mfg_seen_vendor, vendor_code, 3);
    mfg_seen_len = (data_len <= sizeof(mfg_seen)) ? data_len : sizeof(mfg_seen);
    (void)memcpy(mfg_seen, data, mfg_seen_len);
    return mfg_verdict;
}

/* Build one  vendor[3] || Mp[6] || fragment  payload. */
static size_t build_mfg_fragment(uint8_t *out, size_t out_cap,
                                 const uint8_t *vendor,
                                 uint16_t total, uint16_t offset,
                                 const uint8_t *data, size_t data_len)
{
    uint8_t frag_payload[128];
    const osdp_mp_fragment_t frag = {
        .total_size = total, .offset = offset,
        .data = (data_len > 0) ? data : NULL, .frag_len = data_len,
    };
    size_t frag_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_mp_fragment_build(&frag, frag_payload,
                                             sizeof(frag_payload), &frag_len));

    const osdp_mfg_cmd_t mfg = { .data = frag_payload, .data_len = frag_len };
    osdp_mfg_cmd_t m = mfg;
    (void)memcpy(m.vendor_code, vendor, 3);
    size_t written = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfg_build(&m, out, out_cap, &written));
    return written;
}

static void setup_mfg(osdp_pd_t *pd, mock_transport_t *m,
                      osdp_pd_transport_t *t)
{
    setup(pd, m, t);
    mfg_complete_calls = 0;
    mfg_seen_len       = 0;
    mfg_verdict        = OSDP_OK;
    osdp_pd_set_mfg_receiver(pd, mfg_asm_buf, sizeof(mfg_asm_buf),
                             mfg_receiver, NULL);
}

static void test_multipart_mfg_reassembles_across_fragments(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup_mfg(&pd, &m, &t);

    /* 30 bytes of vendor data in three 10-byte fragments. */
    uint8_t whole[30];
    for (size_t i = 0; i < sizeof(whole); i++) {
        whole[i] = (uint8_t)(0xA0 + i);
    }

    for (uint16_t off = 0; off < sizeof(whole); off += 10) {
        uint8_t body[64];
        const size_t blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                                               (uint16_t)sizeof(whole), off,
                                               &whole[off], 10);
        m.outgoing_len = 0;
        inject(&m, OSDP_CMD_MFG, body, blen, (uint8_t)(1 + (off / 10) % 3));
        osdp_pd_tick(&pd);

        osdp_frame_t reply;
        decode_reply(&m, &reply);
        /* Every fragment is ACKed; the callback fires only on the last. */
        TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    }

    TEST_ASSERT_EQUAL_UINT(1, mfg_complete_calls);
    TEST_ASSERT_EQUAL_size_t(sizeof(whole), mfg_seen_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(whole, mfg_seen, sizeof(whole));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kMfgVendor, mfg_seen_vendor, 3);
    /* The application never saw the raw fragments. */
    TEST_ASSERT_EQUAL_UINT(0, handler_calls);
}

/* A single-fragment transfer is the degenerate case and must still work —
 * a vendor protocol should not have to special-case short messages. */
static void test_single_fragment_multipart_mfg_completes_immediately(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup_mfg(&pd, &m, &t);

    static const uint8_t whole[5] = { 1, 2, 3, 4, 5 };
    uint8_t body[64];
    const size_t blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                                           sizeof(whole), 0, whole,
                                           sizeof(whole));
    inject(&m, OSDP_CMD_MFG, body, blen, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_UINT(1, mfg_complete_calls);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(whole, mfg_seen, sizeof(whole));
}

/* Spec 5.10.2: a gap is a violation, answered NAK 0x09 to abort the ACU's
 * sequence, and the reassembler resets so a restart at offset 0 works. */
static void test_gap_in_multipart_mfg_naks_and_allows_restart(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup_mfg(&pd, &m, &t);

    static const uint8_t whole[20] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

    uint8_t body[64];
    size_t  blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                                      sizeof(whole), 0, whole, 5);
    inject(&m, OSDP_CMD_MFG, body, blen, 1);
    osdp_pd_tick(&pd);

    /* Skip ahead to offset 10, leaving a hole after the 5 bytes held. */
    m.outgoing_len = 0;
    blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                              sizeof(whole), 10, &whole[10], 5);
    inject(&m, OSDP_CMD_MFG, body, blen, 2);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_RECORD_INVALID, reply.payload[0]);
    TEST_ASSERT_EQUAL_UINT(0, mfg_complete_calls);

    /* Restart from scratch and the whole message goes through. */
    for (uint16_t off = 0; off < sizeof(whole); off += 10) {
        m.outgoing_len = 0;
        blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                                  sizeof(whole), off, &whole[off], 10);
        inject(&m, OSDP_CMD_MFG, body, blen, (uint8_t)(1 + (off / 10) % 3));
        osdp_pd_tick(&pd);
    }
    TEST_ASSERT_EQUAL_UINT(1, mfg_complete_calls);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(whole, mfg_seen, sizeof(whole));
}

/* A transfer belongs to one vendor. A continuation under a different vendor
 * code must not be merged into the message already in the buffer. */
static void test_vendor_switch_mid_transfer_is_rejected(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup_mfg(&pd, &m, &t);

    static const uint8_t whole[20] = { 0 };
    uint8_t body[64];
    size_t  blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                                      sizeof(whole), 0, whole, 10);
    inject(&m, OSDP_CMD_MFG, body, blen, 1);
    osdp_pd_tick(&pd);

    static const uint8_t other_vendor[3] = { 0x00, 0x11, 0x22 };
    m.outgoing_len = 0;
    blen = build_mfg_fragment(body, sizeof(body), other_vendor,
                              sizeof(whole), 10, &whole[10], 10);
    inject(&m, OSDP_CMD_MFG, body, blen, 2);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_RECORD_INVALID, reply.payload[0]);
    TEST_ASSERT_EQUAL_UINT(0, mfg_complete_calls);
}

/* Spec 5.10.2 early termination: the ACU abandons the transfer, the PD
 * discards the partial message and ACKs. */
static void test_early_termination_discards_the_partial_mfg(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup_mfg(&pd, &m, &t);

    static const uint8_t whole[20] = { 0 };
    uint8_t body[64];
    size_t  blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                                      sizeof(whole), 0, whole, 10);
    inject(&m, OSDP_CMD_MFG, body, blen, 1);
    osdp_pd_tick(&pd);

    /* Marker: offset == total, fragment size 0. */
    m.outgoing_len = 0;
    blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                              sizeof(whole), sizeof(whole), NULL, 0);
    inject(&m, OSDP_CMD_MFG, body, blen, 2);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    /* Abandoned, so the callback must NOT have fired with a partial message. */
    TEST_ASSERT_EQUAL_UINT(0, mfg_complete_calls);
}

/* Spec 6.22: osdp_ABORT terminates a multi-part message as well as a file
 * transfer. A half-assembled message left behind would merge into the next. */
static void test_abort_terminates_a_multipart_mfg(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup_mfg(&pd, &m, &t);

    static const uint8_t whole[20] = { 0 };
    uint8_t body[64];
    size_t  blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                                      sizeof(whole), 0, whole, 10);
    inject(&m, OSDP_CMD_MFG, body, blen, 1);
    osdp_pd_tick(&pd);

    m.outgoing_len = 0;
    inject(&m, OSDP_CMD_ABORT, NULL, 0, 2);
    osdp_pd_tick(&pd);

    /* The continuation that would have completed the message is now an
     * orphan, so it is refused rather than silently merged. */
    m.outgoing_len = 0;
    blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                              sizeof(whole), 10, &whole[10], 10);
    inject(&m, OSDP_CMD_MFG, body, blen, 3);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_UINT(0, mfg_complete_calls);
}

/* A message larger than the bound buffer is refused rather than truncated. */
static void test_oversized_multipart_mfg_is_refused(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);
    static uint8_t small[16];
    mfg_complete_calls = 0;
    osdp_pd_set_mfg_receiver(&pd, small, sizeof(small), mfg_receiver, NULL);

    static const uint8_t data[4] = { 1, 2, 3, 4 };
    uint8_t body[64];
    const size_t blen = build_mfg_fragment(body, sizeof(body), kMfgVendor,
                                           1000, 0, data, sizeof(data));
    inject(&m, OSDP_CMD_MFG, body, blen, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_RECORD_INVALID, reply.payload[0]);
    TEST_ASSERT_EQUAL_UINT(0, mfg_complete_calls);
}

/* The compatibility guarantee. With no receiver bound, an osdp_MFG payload
 * is opaque vendor data and reaches the command handler unchanged — the PD
 * must NOT try to read six bytes of it as a multi-part header. */
static void test_without_a_receiver_mfg_stays_opaque(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t;
    setup(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, mfg_handler, NULL);

    /* Six bytes of vendor data that happen to look like a plausible
     * multi-part header. Without a receiver they must be passed through. */
    static const uint8_t looks_like_a_header[] = {
        0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    osdp_mfg_cmd_t req = { .data = looks_like_a_header,
                           .data_len = sizeof(looks_like_a_header) };
    (void)memcpy(req.vendor_code, kMfgVendor, 3);
    uint8_t body[64]; size_t blen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mfg_build(&req, body, sizeof(body), &blen));

    inject(&m, OSDP_CMD_MFG, body, blen, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    /* mfg_handler answers its own vendor code with an MFGREP. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_MFGREP, reply.code);
}

int main(void)
{
    UNITY_BEGIN();
    /* Event queue */
    RUN_TEST(test_queued_event_answers_the_next_poll);
    RUN_TEST(test_events_are_delivered_in_order);
    RUN_TEST(test_empty_queue_falls_through_to_the_application);
    RUN_TEST(test_full_queue_reports_buffer_too_small);
    RUN_TEST(test_enqueue_without_a_bound_queue_is_rejected);
    RUN_TEST(test_going_offline_discards_queued_events);
    RUN_TEST(test_clear_events_drops_everything);
    /* osdp_BUSY */
    RUN_TEST(test_busy_reply_uses_sequence_zero);
    RUN_TEST(test_busy_is_not_cached_as_the_retransmit_reply);
    /* Table 47 mapping */
    RUN_TEST(test_handler_status_maps_onto_table_47_naks);
    RUN_TEST(test_unrecognised_handler_status_still_drops_silently);
    /* Library-handled commands */
    RUN_TEST(test_abort_is_acked_and_never_reaches_the_application);
    RUN_TEST(test_abort_terminates_an_in_flight_file_transfer);
    RUN_TEST(test_abort_hook_refusal_becomes_nak);
    RUN_TEST(test_acurxsize_is_stored_and_acked);
    RUN_TEST(test_malformed_acurxsize_naks_bad_length);
    RUN_TEST(test_keepactive_reaches_the_handler_and_acks);
    RUN_TEST(test_keepactive_without_a_handler_naks);
    /* osdp_MFG -> osdp_MFGREP through the application handler */
    RUN_TEST(test_mfg_round_trips_to_mfgrep_through_the_handler);
    RUN_TEST(test_mfg_for_another_vendor_naks_record_invalid);
    /* Multi-part osdp_MFG (spec 5.10 + 6.19) */
    RUN_TEST(test_multipart_mfg_reassembles_across_fragments);
    RUN_TEST(test_single_fragment_multipart_mfg_completes_immediately);
    RUN_TEST(test_gap_in_multipart_mfg_naks_and_allows_restart);
    RUN_TEST(test_vendor_switch_mid_transfer_is_rejected);
    RUN_TEST(test_early_termination_discards_the_partial_mfg);
    RUN_TEST(test_abort_terminates_a_multipart_mfg);
    RUN_TEST(test_oversized_multipart_mfg_is_refused);
    RUN_TEST(test_without_a_receiver_mfg_stays_opaque);
    return UNITY_END();
}
