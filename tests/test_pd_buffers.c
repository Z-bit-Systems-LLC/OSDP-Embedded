// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* osdp_pd_set_buffers — binding caller-owned working storage.
 *
 * The PD ships with four embedded OSDP_PD_BUF_LEN arrays and works with no
 * configuration at all. osdp_pd_set_buffers lets an application swap any
 * subset for its own storage: a 1440-byte TX path for spec-maximum messages,
 * a shared pool, or (on the other end) a stripped-down PD that never uses
 * Secure Channel and doesn't want to pay for the plaintext region.
 *
 * These tests exercise the binding through real wire traffic rather than by
 * reading struct fields, because the thing that actually matters is whether
 * the state machine goes through the bindings everywhere. A path still
 * reaching for `pd->tx_buf` directly would keep passing a field-inspection
 * test while writing to the wrong memory in production. */

#include "osdp/osdp_commands.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_replies.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Mock transport ------------------------------------------------------*/

#define MOCK_BUF_LEN 4096U

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

static void inject_command(mock_transport_t *m, uint8_t addr, uint8_t code,
                           const uint8_t *payload, size_t payload_len,
                           uint8_t sequence)
{
    osdp_frame_t f = {0};
    f.address     = addr;
    f.reply       = false;
    f.sequence    = sequence;
    f.integrity   = OSDP_INTEGRITY_CRC;
    f.code        = code;
    f.payload     = payload;
    f.payload_len = payload_len;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  written = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &written));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(MOCK_BUF_LEN - m->incoming_len, written);
    (void)memcpy(&m->incoming[m->incoming_len], buf, written);
    m->incoming_len += written;
}

static void decode_first_outgoing(const mock_transport_t *m, osdp_frame_t *out)
{
    TEST_ASSERT_GREATER_OR_EQUAL(OSDP_FRAME_MIN_LEN_CKSUM, m->outgoing_len);
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_decode(m->outgoing + OSDP_FRAME_MARK_LEN,
                                        m->outgoing_len - OSDP_FRAME_MARK_LEN,
                                        out));
}

/* ---- Application handlers ----------------------------------------------*/

/* Answers osdp_POLL with an osdp_RAW carrying `big_payload_len` bytes of a
 * recognizable ramp. Tests set the length, then bind a TX region either large
 * enough to frame it or deliberately too small, and compare what reaches the
 * wire. */
static size_t  big_payload_len;
static uint8_t big_payload[1200];

static osdp_status_t big_reply_handler(void *user, uint8_t cmd_code,
                                       const uint8_t *payload,
                                       size_t payload_len,
                                       osdp_pd_reply_t *reply)
{
    (void)user; (void)payload; (void)payload_len;
    if (cmd_code != OSDP_CMD_POLL) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    reply->code        = OSDP_REPLY_RAW;
    reply->payload     = big_payload;
    reply->payload_len = big_payload_len;
    return OSDP_OK;
}

/* Echoes the inbound payload straight back as the reply payload — it returns
 * the very pointer the core handed it. Used to prove the reply-building path
 * does not overwrite the buffer the command payload lives in. */
static osdp_status_t echo_handler(void *user, uint8_t cmd_code,
                                  const uint8_t *payload, size_t payload_len,
                                  osdp_pd_reply_t *reply)
{
    (void)user; (void)cmd_code;
    reply->code        = OSDP_REPLY_RAW;
    reply->payload     = payload;
    reply->payload_len = payload_len;
    return OSDP_OK;
}

/* ACKs everything and counts its invocations. The call count is what
 * separates a cache replay from fresh processing: both put the same bytes on
 * the wire, so comparing frames alone proves nothing about the cache. */
static unsigned int ack_calls;

static osdp_status_t ack_handler(void *user, uint8_t cmd_code,
                                 const uint8_t *payload, size_t payload_len,
                                 osdp_pd_reply_t *reply)
{
    (void)user; (void)cmd_code; (void)payload; (void)payload_len;
    ack_calls++;
    reply->code        = OSDP_REPLY_ACK;
    reply->payload     = NULL;
    reply->payload_len = 0;
    return OSDP_OK;
}

static void fill_ramp(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i & 0xFFU);
    }
}

/* ---- Defaults ----------------------------------------------------------*/

/* OSDP_PD_BUF_LEN is the PD's one sizing knob and is build-overridable. This
 * test pins the relationships rather than the values, so a build that sets
 * -DOSDP_PD_BUF_LEN=64 still passes while a build where the constant has
 * drifted out of correspondence with the actual arrays does not.
 *
 * The correspondence matters beyond the arrays: the same constant is what an
 * application reports as PDCAP function code 10, so if it ever stopped
 * describing the real buffers the PD would be advertising a receive capacity
 * it doesn't have. */
static void test_sizing_constant_matches_the_embedded_arrays(void)
{
    osdp_pd_t pd;

    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN, sizeof(pd.tx_buf));
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN, sizeof(pd.rx_plain_buf));
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN, sizeof(pd.last_reply));
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN, sizeof(pd.last_cmd));
}

static void test_init_binds_every_region_to_its_embedded_array(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    /* A PD that never calls set_buffers must be pointing at its own arrays,
     * so the no-configuration path behaves exactly as it did before the
     * bindings existed. */
    TEST_ASSERT_EQUAL_PTR(pd.tx_buf,       pd.tx);
    TEST_ASSERT_EQUAL_PTR(pd.rx_plain_buf, pd.rx_plain);
    TEST_ASSERT_EQUAL_PTR(pd.last_reply,   pd.rpl_cache);
    TEST_ASSERT_EQUAL_PTR(pd.last_cmd,     pd.cmd_cache);

    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN,   pd.tx_cap);
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN, pd.rx_plain_cap);
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN,   pd.rpl_cache_cap);
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN,   pd.cmd_cache_cap);
}

/* ---- TX capacity is whatever is bound ---------------------------------*/

/* These two are each other's control: identical command, identical handler,
 * identical reply — only the bound TX capacity differs. Together they show
 * that TX capacity is genuinely the binding and not the embedded array.
 *
 * Both bind explicitly rather than leaning on the default, so the pair holds
 * at any -DOSDP_PD_BUF_LEN. An earlier version asserted "1000 bytes doesn't
 * fit the default 256" and duly broke the first time the constant was
 * overridden to 1024. */
#define TEST_REPLY_LEN   200U
#define TEST_TX_TOO_SMALL 64U

static void test_reply_too_large_for_the_bound_tx_buffer_is_dropped(void)
{
    mock_transport_t    m;
    osdp_pd_transport_t t;
    osdp_pd_t           pd;
    static uint8_t      tx[TEST_TX_TOO_SMALL];

    mock_init(&m, &t);
    osdp_pd_init(&pd, 0x05);

    const osdp_pd_buffers_t bufs = { .tx = tx, .tx_cap = sizeof(tx) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));

    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, big_reply_handler, NULL);

    big_payload_len = TEST_REPLY_LEN;
    fill_ramp(big_payload, big_payload_len);

    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);

    /* osdp_frame_build fails for want of room, so the PD sends nothing at
     * all rather than a truncated frame. */
    TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);
}

static void test_bound_tx_buffer_carries_a_reply_a_smaller_one_cannot(void)
{
    mock_transport_t    m;
    osdp_pd_transport_t t;
    osdp_pd_t           pd;
    static uint8_t      tx[OSDP_FRAME_MAX_LEN];

    mock_init(&m, &t);
    osdp_pd_init(&pd, 0x05);

    const osdp_pd_buffers_t bufs = { .tx = tx, .tx_cap = sizeof(tx) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));

    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, big_reply_handler, NULL);

    big_payload_len = TEST_REPLY_LEN;
    fill_ramp(big_payload, big_payload_len);

    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_TRUE(reply.reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RAW, reply.code);
    TEST_ASSERT_EQUAL_size_t(big_payload_len, reply.payload_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(big_payload, reply.payload, big_payload_len);
}

/* ---- Retransmit caches --------------------------------------------------*/

/* The SQN cache (spec 5.9) has to follow the binding too: a retransmit is
 * detected by memcmp against cmd_cache and answered by replaying rpl_cache.
 * Bind both to caller storage and the byte-identical-retransmit rule must
 * still hold end to end. */
static void test_retransmit_replays_from_bound_caches(void)
{
    mock_transport_t    m;
    osdp_pd_transport_t t;
    osdp_pd_t           pd;
    static uint8_t      tx[512], rpl[512], cmdc[512];

    mock_init(&m, &t);
    osdp_pd_init(&pd, 0x05);

    const osdp_pd_buffers_t bufs = {
        .tx = tx,   .tx_cap = sizeof(tx),
        .rpl_cache = rpl,  .rpl_cache_cap = sizeof(rpl),
        .cmd_cache = cmdc, .cmd_cache_cap = sizeof(cmdc),
    };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));

    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, ack_handler, NULL);
    ack_calls = 0;

    /* First delivery: processed fresh, reply cached into `rpl`. */
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);
    const size_t first_len = m.outgoing_len;
    TEST_ASSERT_GREATER_THAN_size_t(0, first_len);
    TEST_ASSERT_EQUAL_UINT(1, ack_calls);

    uint8_t first[MOCK_BUF_LEN];
    (void)memcpy(first, m.outgoing, first_len);

    /* Byte-identical repeat: must be recognised via `cmdc` and answered from
     * `rpl` with exactly the same bytes. */
    m.outgoing_len = 0;
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);

    TEST_ASSERT_EQUAL_size_t(first_len, m.outgoing_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(first, m.outgoing, first_len);
    /* The decisive assertion. An ACK replayed from the cache and an ACK
     * recomputed from scratch are the same bytes, so only the handler call
     * count reveals which happened — and a retransmit must not re-run the
     * application. If is_retransmit still read the embedded `last_cmd` while
     * cache_reply wrote to the bound `cmdc`, the memcmp would miss and this
     * would be 2. */
    TEST_ASSERT_EQUAL_UINT(1, ack_calls);
}

/* Rebinding a cache mid-life must drop what it recorded — the recorded
 * lengths describe bytes in storage the PD has just stopped reading. Costing
 * one replayed retransmit is correct; replaying stale bytes is not. */
static void test_rebinding_a_cache_clears_it(void)
{
    mock_transport_t    m;
    osdp_pd_transport_t t;
    osdp_pd_t           pd;
    static uint8_t      rpl[512];

    mock_init(&m, &t);
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, ack_handler, NULL);
    ack_calls = 0;

    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_TRUE(pd.have_last);
    TEST_ASSERT_GREATER_THAN_size_t(0, pd.last_reply_len);
    TEST_ASSERT_EQUAL_UINT(1, ack_calls);

    const osdp_pd_buffers_t bufs = { .rpl_cache = rpl,
                                     .rpl_cache_cap = sizeof(rpl) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));

    TEST_ASSERT_FALSE(pd.have_last);
    TEST_ASSERT_EQUAL_size_t(0, pd.last_reply_len);

    /* Observable consequence: the repeat that would have been replayed is now
     * processed fresh instead of answered from bytes the PD no longer reads. */
    m.outgoing_len = 0;
    inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0, 1);
    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_UINT(2, ack_calls);
}

/* ---- Partial binding and validation -------------------------------------*/

static void test_null_member_leaves_its_region_alone(void)
{
    osdp_pd_t      pd;
    static uint8_t tx[512];

    osdp_pd_init(&pd, 0x05);
    const uint8_t *const default_rx_plain  = pd.rx_plain;
    const uint8_t *const default_rpl_cache = pd.rpl_cache;

    const osdp_pd_buffers_t bufs = { .tx = tx, .tx_cap = sizeof(tx) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));

    TEST_ASSERT_EQUAL_PTR(tx, pd.tx);
    TEST_ASSERT_EQUAL_size_t(sizeof(tx), pd.tx_cap);
    /* The three regions the caller said nothing about keep their bindings. */
    TEST_ASSERT_EQUAL_PTR(default_rx_plain,  pd.rx_plain);
    TEST_ASSERT_EQUAL_PTR(default_rpl_cache, pd.rpl_cache);
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN, pd.rx_plain_cap);
}

static void test_undersized_region_is_rejected_and_nothing_is_applied(void)
{
    osdp_pd_t      pd;
    static uint8_t ok_tx[512];
    static uint8_t tiny[OSDP_PD_BUF_MIN_LEN - 1U];

    osdp_pd_init(&pd, 0x05);
    const uint8_t *const default_tx = pd.tx;

    /* One valid region and one too small in the same call. The call must be
     * all-or-nothing: a half-applied binding would leave the PD in a state
     * the caller never asked for and cannot easily detect. */
    const osdp_pd_buffers_t bufs = {
        .tx = ok_tx, .tx_cap = sizeof(ok_tx),
        .rx_plain = tiny, .rx_plain_cap = sizeof(tiny),
    };
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pd_set_buffers(&pd, &bufs));

    TEST_ASSERT_EQUAL_PTR(default_tx, pd.tx);
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN, pd.tx_cap);
}

static void test_null_arguments_are_rejected(void)
{
    osdp_pd_t               pd;
    const osdp_pd_buffers_t bufs = {0};

    osdp_pd_init(&pd, 0x05);
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pd_set_buffers(NULL, &bufs));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pd_set_buffers(&pd, NULL));
}

/* An all-NULL buffers struct is a legal no-op, not an error — it means
 * "change nothing", which is what a caller building the struct up
 * conditionally ends up passing when no override applies. */
static void test_all_null_members_is_a_successful_no_op(void)
{
    osdp_pd_t               pd;
    const osdp_pd_buffers_t bufs = {0};

    osdp_pd_init(&pd, 0x05);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));
    TEST_ASSERT_EQUAL_PTR(pd.tx_buf, pd.tx);
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_BUF_LEN, pd.tx_cap);
}

/* ---- Aliasing -----------------------------------------------------------*/

/* The reply an application hands back may point into the payload it was
 * given. On the plaintext path that payload lives in the stream buffer, but
 * on the SC paths it lives in rx_plain — which is why rx_plain must be a
 * distinct region from tx rather than a reuse of it. Prove the invariant
 * holds on the path this test can reach without a crypto vtable: framing the
 * reply must not disturb the bytes the reply points at. */
static void test_reply_pointing_at_the_inbound_payload_survives_framing(void)
{
    mock_transport_t    m;
    osdp_pd_transport_t t;
    osdp_pd_t           pd;
    static uint8_t      tx[512];

    mock_init(&m, &t);
    osdp_pd_init(&pd, 0x05);

    const osdp_pd_buffers_t bufs = { .tx = tx, .tx_cap = sizeof(tx) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));

    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, echo_handler, NULL);

    uint8_t sent[64];
    fill_ramp(sent, sizeof(sent));
    inject_command(&m, 0x05, OSDP_CMD_TEXT, sent, sizeof(sent), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RAW, reply.code);
    TEST_ASSERT_EQUAL_size_t(sizeof(sent), reply.payload_len);
    /* Byte-for-byte what the ACU sent. A tx/payload overlap would show up
     * here as framing bytes bleeding into the echoed data. */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(sent, reply.payload, sizeof(sent));
}

/* ---- Reply sizing -------------------------------------------------------*/

/* osdp_pd_max_reply_payload answers "how much fits in one packet", which is
 * the question a caller must answer before splitting a response across polls.
 * Checked against reality rather than against restated arithmetic: ask for
 * the maximum, have the handler return exactly that many bytes, and confirm
 * the frame reaches the wire intact — then one more byte and confirm it does
 * not. */
static void test_max_reply_payload_is_what_actually_fits(void)
{
    static uint8_t tx[300];

    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    const osdp_pd_buffers_t bufs = { .tx = tx, .tx_cap = sizeof(tx) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));

    const size_t max = osdp_pd_max_reply_payload(&pd);
    TEST_ASSERT_GREATER_THAN_size_t(0, max);
    TEST_ASSERT_LESS_THAN_size_t(sizeof(tx), max);
    TEST_ASSERT_LESS_THAN_size_t(sizeof(big_payload), max);

    /* Exactly `max` bytes must reach the wire. */
    {
        mock_transport_t    m;
        osdp_pd_transport_t t;
        mock_init(&m, &t);
        osdp_pd_set_transport(&pd, &t);
        osdp_pd_set_command_handler(&pd, big_reply_handler, NULL);

        big_payload_len = max;
        fill_ramp(big_payload, big_payload_len);

        inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0, 1);
        osdp_pd_tick(&pd);

        osdp_frame_t reply;
        decode_first_outgoing(&m, &reply);
        TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RAW, reply.code);
        TEST_ASSERT_EQUAL_size_t(max, reply.payload_len);
    }

    /* One more must not — otherwise the helper under-reports and every
     * fragment would waste a byte of capacity. */
    {
        mock_transport_t    m;
        osdp_pd_transport_t t;
        mock_init(&m, &t);
        osdp_pd_init(&pd, 0x05);
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));
        osdp_pd_set_transport(&pd, &t);
        osdp_pd_set_command_handler(&pd, big_reply_handler, NULL);

        big_payload_len = max + 1U;
        fill_ramp(big_payload, big_payload_len);

        inject_command(&m, 0x05, OSDP_CMD_POLL, NULL, 0, 1);
        osdp_pd_tick(&pd);
        TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);
    }
}

/* The answer tracks the bound capacity, so rebinding changes it — the whole
 * point of resolving against live state instead of a constant. */
static void test_max_reply_payload_follows_the_bound_capacity(void)
{
    static uint8_t small[64], large[OSDP_FRAME_MAX_LEN];

    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pd_buffers_t small_bufs = { .tx = small, .tx_cap = sizeof(small) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &small_bufs));
    const size_t with_small = osdp_pd_max_reply_payload(&pd);

    const osdp_pd_buffers_t large_bufs = { .tx = large, .tx_cap = sizeof(large) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &large_bufs));
    const size_t with_large = osdp_pd_max_reply_payload(&pd);

    TEST_ASSERT_GREATER_THAN_size_t(with_small, with_large);
    TEST_ASSERT_EQUAL_size_t(0, osdp_pd_max_reply_payload(NULL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_max_reply_payload_is_what_actually_fits);
    RUN_TEST(test_max_reply_payload_follows_the_bound_capacity);
    RUN_TEST(test_sizing_constant_matches_the_embedded_arrays);
    RUN_TEST(test_init_binds_every_region_to_its_embedded_array);
    RUN_TEST(test_reply_too_large_for_the_bound_tx_buffer_is_dropped);
    RUN_TEST(test_bound_tx_buffer_carries_a_reply_a_smaller_one_cannot);
    RUN_TEST(test_retransmit_replays_from_bound_caches);
    RUN_TEST(test_rebinding_a_cache_clears_it);
    RUN_TEST(test_null_member_leaves_its_region_alone);
    RUN_TEST(test_undersized_region_is_rejected_and_nothing_is_applied);
    RUN_TEST(test_null_arguments_are_rejected);
    RUN_TEST(test_all_null_members_is_a_successful_no_op);
    RUN_TEST(test_reply_pointing_at_the_inbound_payload_survives_framing);
    return UNITY_END();
}
