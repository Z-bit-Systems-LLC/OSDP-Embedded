// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Status providers: osdp_LSTAT / ISTAT / OSTAT / RSTAT answered by the
 * library from application-supplied values.
 *
 * The point of the feature is that the reply LAYOUT is the spec's business
 * and the VALUES are the application's. Before it existed every consumer
 * hand-built its own osdp_LSTATR — tools/osdp-mcp had one hard-coded — which
 * is how a PD ends up reporting a status byte in the wrong position.
 *
 * Every test here drives a real frame through osdp_pd_tick and decodes what
 * comes back off the wire, rather than inspecting the reply struct: it is the
 * bytes that have to be right.
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

#define MOCK_BUF_LEN 1024U

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

/* ---- Providers ---------------------------------------------------------*/

static bool     local_called;
static uint8_t  local_tamper = OSDP_LSTATR_TAMPER;
static uint8_t  local_power  = OSDP_LSTATR_POWER_FAILURE;

static void provide_local(void *user, uint8_t *tamper, uint8_t *power)
{
    (void)user;
    local_called = true;
    *tamper = local_tamper;
    *power  = local_power;
}

static const uint8_t kInputs[]  = { OSDP_ISTATR_ACTIVE, OSDP_ISTATR_INACTIVE,
                                    OSDP_ISTATR_SHORT,  OSDP_ISTATR_OPEN };
static const uint8_t kOutputs[] = { OSDP_OSTATR_ACTIVE, OSDP_OSTATR_INACTIVE };
static const uint8_t kReaders[] = { OSDP_RSTATR_NORMAL };

static size_t provide_inputs(void *user, uint8_t *out, size_t cap)
{
    (void)user;
    TEST_ASSERT_GREATER_OR_EQUAL(sizeof(kInputs), cap);
    (void)memcpy(out, kInputs, sizeof(kInputs));
    return sizeof(kInputs);
}

static size_t provide_outputs(void *user, uint8_t *out, size_t cap)
{
    (void)user;
    TEST_ASSERT_GREATER_OR_EQUAL(sizeof(kOutputs), cap);
    (void)memcpy(out, kOutputs, sizeof(kOutputs));
    return sizeof(kOutputs);
}

static size_t provide_readers(void *user, uint8_t *out, size_t cap)
{
    (void)user;
    TEST_ASSERT_GREATER_OR_EQUAL(sizeof(kReaders), cap);
    (void)memcpy(out, kReaders, sizeof(kReaders));
    return sizeof(kReaders);
}

/* Counts calls so a test can prove a command did NOT reach the app. */
typedef struct app_spy { unsigned int calls; uint8_t last_code; } app_spy_t;

static osdp_status_t spy_handler(void *user, uint8_t cmd_code,
                                 const uint8_t *payload, size_t payload_len,
                                 osdp_pd_reply_t *reply)
{
    (void)payload; (void)payload_len;
    app_spy_t *s = (app_spy_t *)user;
    s->calls++;
    s->last_code = cmd_code;
    reply->code        = OSDP_REPLY_ACK;
    reply->payload     = NULL;
    reply->payload_len = 0;
    return OSDP_OK;
}

static void setup(osdp_pd_t *pd, mock_transport_t *m, osdp_pd_transport_t *t,
                  app_spy_t *spy)
{
    mock_init(m, t);
    osdp_pd_init(pd, 0x05);
    osdp_pd_set_transport(pd, t);
    (void)memset(spy, 0, sizeof(*spy));
    osdp_pd_set_command_handler(pd, spy_handler, spy);
}

/* ---- Tests -------------------------------------------------------------*/

static void test_lstat_answered_from_provider(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy;
    setup(&pd, &m, &t, &spy);

    const osdp_pd_status_provider_t p = { .local = provide_local };
    osdp_pd_set_status_provider(&pd, &p, NULL);

    local_called = false;
    local_tamper = OSDP_LSTATR_TAMPER;
    local_power  = OSDP_LSTATR_NORMAL;

    inject(&m, OSDP_CMD_LSTAT, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_LSTATR, reply.code);

    osdp_lstatr_t got;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_lstatr_decode(reply.payload, reply.payload_len, &got));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LSTATR_TAMPER, got.tamper);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LSTATR_NORMAL, got.power);

    TEST_ASSERT_TRUE(local_called);
    /* The command must not have reached the application at all. */
    TEST_ASSERT_EQUAL_UINT(0, spy.calls);
}

static void test_istat_ostat_rstat_answered_from_providers(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy;
    setup(&pd, &m, &t, &spy);

    const osdp_pd_status_provider_t p = { .inputs  = provide_inputs,
                                          .outputs = provide_outputs,
                                          .readers = provide_readers };
    osdp_pd_set_status_provider(&pd, &p, NULL);

    struct { uint8_t cmd; uint8_t reply_code;
             const uint8_t *expect; size_t expect_len; } cases[] = {
        { OSDP_CMD_ISTAT, OSDP_REPLY_ISTATR, kInputs,  sizeof(kInputs)  },
        { OSDP_CMD_OSTAT, OSDP_REPLY_OSTATR, kOutputs, sizeof(kOutputs) },
        { OSDP_CMD_RSTAT, OSDP_REPLY_RSTATR, kReaders, sizeof(kReaders) },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        m.outgoing_len = 0;
        inject(&m, cases[i].cmd, NULL, 0, (uint8_t)(1 + i));
        osdp_pd_tick(&pd);

        osdp_frame_t reply;
        decode_reply(&m, &reply);
        TEST_ASSERT_EQUAL_HEX8(cases[i].reply_code, reply.code);
        TEST_ASSERT_EQUAL_size_t(cases[i].expect_len, reply.payload_len);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(cases[i].expect, reply.payload,
                                     cases[i].expect_len);
    }
    TEST_ASSERT_EQUAL_UINT(0, spy.calls);
}

/* Each provider member is independent: binding one must not capture the
 * others. An application that only knows its tamper switch should keep
 * handling osdp_ISTAT itself. */
static void test_unbound_members_fall_through_to_the_application(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy;
    setup(&pd, &m, &t, &spy);

    const osdp_pd_status_provider_t p = { .local = provide_local };
    osdp_pd_set_status_provider(&pd, &p, NULL);

    inject(&m, OSDP_CMD_ISTAT, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    /* The spy ACKs everything, so reaching it shows as an ACK rather than an
     * ISTATR — and the call count confirms which path ran. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_UINT(1, spy.calls);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_ISTAT, spy.last_code);
}

/* No provider at all: every status command behaves exactly as it did before
 * the feature existed. This is the compatibility guarantee. */
static void test_no_provider_leaves_all_four_with_the_application(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy;
    setup(&pd, &m, &t, &spy);

    const uint8_t cmds[] = { OSDP_CMD_LSTAT, OSDP_CMD_ISTAT,
                             OSDP_CMD_OSTAT, OSDP_CMD_RSTAT };
    for (size_t i = 0; i < sizeof(cmds); i++) {
        m.outgoing_len = 0;
        inject(&m, cmds[i], NULL, 0, (uint8_t)(1 + (i % 3)));
        osdp_pd_tick(&pd);

        osdp_frame_t reply;
        decode_reply(&m, &reply);
        TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    }
    TEST_ASSERT_EQUAL_UINT(sizeof(cmds), spy.calls);
}

/* Detaching restores the fall-through, so a provider can be swapped out at
 * run time without leaving the four commands stranded. */
static void test_detaching_the_provider_restores_fall_through(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy;
    setup(&pd, &m, &t, &spy);

    const osdp_pd_status_provider_t p = { .local = provide_local };
    osdp_pd_set_status_provider(&pd, &p, NULL);
    osdp_pd_set_status_provider(&pd, NULL, NULL);

    inject(&m, OSDP_CMD_LSTAT, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_UINT(1, spy.calls);
}

/* A provider with nothing to report is legal — a PD with no inputs. */
static size_t provide_nothing(void *user, uint8_t *out, size_t cap)
{
    (void)user; (void)out; (void)cap;
    return 0;
}

static void test_empty_status_report_is_legal(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy;
    setup(&pd, &m, &t, &spy);

    const osdp_pd_status_provider_t p = { .inputs = provide_nothing };
    osdp_pd_set_status_provider(&pd, &p, NULL);

    inject(&m, OSDP_CMD_ISTAT, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ISTATR, reply.code);
    TEST_ASSERT_EQUAL_size_t(0, reply.payload_len);
    TEST_ASSERT_EQUAL_UINT(0, spy.calls);
}

/* A provider that lies about how much it wrote must not make the PD read
 * past the buffer it was handed. The count is clamped to the capacity. */
static size_t provide_overlong(void *user, uint8_t *out, size_t cap)
{
    (void)user;
    (void)memset(out, OSDP_ISTATR_ACTIVE, cap);
    return cap + 100U;          /* deliberately impossible */
}

static void test_overreporting_provider_is_clamped(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy;
    setup(&pd, &m, &t, &spy);

    static uint8_t tx[OSDP_FRAME_MAX_LEN];
    const osdp_pd_buffers_t bufs = { .tx = tx, .tx_cap = sizeof(tx) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));

    const osdp_pd_status_provider_t p = { .inputs = provide_overlong };
    osdp_pd_set_status_provider(&pd, &p, NULL);

    inject(&m, OSDP_CMD_ISTAT, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ISTATR, reply.code);
    /* Clamped to what the PD actually offered the provider. */
    TEST_ASSERT_EQUAL_size_t(OSDP_PD_REPLY_SCRATCH_LEN, reply.payload_len);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_lstat_answered_from_provider);
    RUN_TEST(test_istat_ostat_rstat_answered_from_providers);
    RUN_TEST(test_unbound_members_fall_through_to_the_application);
    RUN_TEST(test_no_provider_leaves_all_four_with_the_application);
    RUN_TEST(test_detaching_the_provider_restores_fall_through);
    RUN_TEST(test_empty_status_report_is_legal);
    RUN_TEST(test_overreporting_provider_is_clamped);
    return UNITY_END();
}
