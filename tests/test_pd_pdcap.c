// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* osdp_pd_check_pdcap — advisory consistency check on an application's
 * osdp_PDCAP records.
 *
 * The failure this guards against is quiet: a PD that advertises more than it
 * can honour does not error, it drops frames the ACU believes were delivered.
 * So the tests are mostly about the checker noticing, and equally about it
 * NOT complaining when the configuration is genuinely fine — a check that
 * cries wolf gets switched off.
 */

#include "osdp/osdp_commands.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc_crypto.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Helpers -----------------------------------------------------------*/

/* Function codes 10 and 11 carry a 16-bit size as LSB-then-MSB across the two
 * bytes whose names suggest otherwise. Spelling it out once here keeps the
 * tests honest about the encoding they are asserting on. */
static osdp_pdcap_record_t size_record(uint8_t fn, uint16_t size)
{
    osdp_pdcap_record_t r;
    r.function_code    = fn;
    r.compliance_level = (uint8_t)(size & 0xFFU);
    r.num_objects      = (uint8_t)(size >> 8);
    return r;
}

#define FN_COMM_SECURITY 9U
#define FN_RECEIVE_SIZE  10U
#define FN_COMBINED_SIZE 11U

/* Minimal SC crypto vtable. The check only asks whether SC is *configured*,
 * never invokes the primitives, so these need to exist but not work. */
static osdp_status_t stub_enc(void *u, const uint8_t k[16], const uint8_t i[16],
                              uint8_t o[16])
{ (void)u; (void)k; (void)i; (void)o; return OSDP_OK; }
static osdp_status_t stub_dec(void *u, const uint8_t k[16], const uint8_t i[16],
                              uint8_t o[16])
{ (void)u; (void)k; (void)i; (void)o; return OSDP_OK; }
static osdp_status_t stub_rand(void *u, uint8_t *o, size_t n)
{ (void)u; (void)memset(o, 0, n); return OSDP_OK; }

static const osdp_sc_crypto_t kStubCrypto = {
    .aes128_ecb_encrypt = stub_enc,
    .aes128_ecb_decrypt = stub_dec,
    .rand_bytes         = stub_rand,
    .user               = NULL,
};

static void configure_sc(osdp_pd_t *pd)
{
    static const uint8_t key[OSDP_SC_KEY_LEN] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    static const uint8_t cuid[OSDP_SC_CUID_LEN] = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7 };
    osdp_pd_set_sc_crypto(pd, &kStubCrypto);
    osdp_pd_set_sc_scbk(pd, key);
    osdp_pd_set_sc_cuid(pd, cuid);
}

/* ---- Tests -------------------------------------------------------------*/

static void test_null_arguments_are_rejected(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    const osdp_pdcap_record_t r = size_record(FN_RECEIVE_SIZE, 128);

    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pd_check_pdcap(NULL, &r, 1, NULL));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pd_check_pdcap(&pd, NULL, 1, NULL));
    /* A zero-length list with a NULL pointer is not a contradiction. */
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_check_pdcap(&pd, NULL, 0, NULL));
}

/* Records the library knows nothing about must pass untouched — the check
 * has no opinion on how many inputs the device has. */
static void test_unknown_function_codes_are_left_alone(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pdcap_record_t records[] = {
        { .function_code = 1,  .compliance_level = 1, .num_objects = 16 },
        { .function_code = 2,  .compliance_level = 1, .num_objects = 4  },
        { .function_code = 13, .compliance_level = 0, .num_objects = 1  },
    };
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pd_check_pdcap(&pd, records, 3, NULL));
}

/* ---- Function code 9: communication security --------------------------*/

static void test_aes128_claim_without_sc_configured_is_flagged(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pdcap_record_t records[] = {
        { .function_code = 1, .compliance_level = 1, .num_objects = 8 },
        { .function_code = FN_COMM_SECURITY,
          .compliance_level = 0x01, .num_objects = 0x01 },
    };
    size_t bad = 999;
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
                      osdp_pd_check_pdcap(&pd, records, 2, &bad));
    /* The index points at the offending record, not just "something". */
    TEST_ASSERT_EQUAL_size_t(1, bad);
}

static void test_aes128_claim_with_sc_configured_passes(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    configure_sc(&pd);

    const osdp_pdcap_record_t r = { .function_code = FN_COMM_SECURITY,
                                    .compliance_level = 0x01,
                                    .num_objects = 0x01 };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_check_pdcap(&pd, &r, 1, NULL));
}

/* Advertising NO security on a PD with no SC is consistent, and must not be
 * flagged just because function code 9 is present. */
static void test_no_security_claim_is_fine_without_sc(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pdcap_record_t r = { .function_code = FN_COMM_SECURITY,
                                    .compliance_level = 0x00,
                                    .num_objects = 0x00 };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_check_pdcap(&pd, &r, 1, NULL));
}

/* ---- Function code 10: receive buffer size ----------------------------*/

static void test_receive_size_above_the_stream_buffer_is_flagged(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    /* One byte past what the stream decoder can ever reassemble. */
    const osdp_pdcap_record_t r =
        size_record(FN_RECEIVE_SIZE, (uint16_t)(OSDP_STREAM_BUFFER_LEN + 1U));
    size_t bad = 999;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pd_check_pdcap(&pd, &r, 1, &bad));
    TEST_ASSERT_EQUAL_size_t(0, bad);
}

static void test_receive_size_at_the_stream_buffer_passes(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    /* Exactly the limit is honest, not an over-claim — an off-by-one here
     * would make the checker reject a correct configuration. */
    const osdp_pdcap_record_t r =
        size_record(FN_RECEIVE_SIZE, (uint16_t)OSDP_STREAM_BUFFER_LEN);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_check_pdcap(&pd, &r, 1, NULL));
}

/* With SC configured the plaintext of the advertised message has to fit
 * rx_plain. This is the case a clear-text-only reading would miss: the frame
 * arrives fine and then fails to unwrap. */
static void test_receive_size_beyond_rx_plain_is_flagged_under_sc(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    configure_sc(&pd);

    /* Bind rx_plain explicitly rather than leaning on the default being
     * smaller than the stream buffer. It is at the defaults (512 vs 1440) but
     * not under -DOSDP_PD_BUF_LEN=1024 -DOSDP_STREAM_BUFFER_LEN=800, and an
     * earlier version of this test duly passed at the defaults and failed
     * there. Controlling both ends makes the case the same everywhere. */
    static uint8_t tiny_rx_plain[64];
    const osdp_pd_buffers_t small = { .rx_plain = tiny_rx_plain,
                                      .rx_plain_cap = sizeof(tiny_rx_plain) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &small));

    /* 512 bytes of message carries far more SC plaintext than 64. */
    const osdp_pdcap_record_t r = size_record(FN_RECEIVE_SIZE, 512);
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pd_check_pdcap(&pd, &r, 1, NULL));

    /* Binding a large enough rx_plain makes the same claim honest — the
     * actionable half: the checker tells you what to fix. */
    static uint8_t big_rx_plain[1024];
    const osdp_pd_buffers_t big = { .rx_plain = big_rx_plain,
                                    .rx_plain_cap = sizeof(big_rx_plain) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &big));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_check_pdcap(&pd, &r, 1, NULL));
}

/* The same claim on a clear-text PD is fine: the payload is handed out of the
 * stream buffer and rx_plain is never involved. */
static void test_large_receive_size_is_fine_without_sc(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pdcap_record_t r =
        size_record(FN_RECEIVE_SIZE, (uint16_t)OSDP_STREAM_BUFFER_LEN);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_check_pdcap(&pd, &r, 1, NULL));
}

/* ---- Function code 11: largest combined message ------------------------*/

/* Multi-part assembly exists now, so the question is no longer "is it
 * implemented" but "is a buffer bound, and is it big enough". */
static void test_combined_message_size_needs_a_bound_reassembly_buffer(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pdcap_record_t r = size_record(FN_COMBINED_SIZE, 512);

    /* No receiver bound: the PD cannot assemble anything. */
    size_t bad = 999;
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
                      osdp_pd_check_pdcap(&pd, &r, 1, &bad));
    TEST_ASSERT_EQUAL_size_t(0, bad);

    /* Bound but too small: the transfer would be refused at the first
     * fragment, after the ACU had committed to sending the whole thing. */
    static uint8_t small[64];
    osdp_pd_set_mfg_receiver(&pd, small, sizeof(small), NULL, NULL);
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pd_check_pdcap(&pd, &r, 1, NULL));

    /* Bound and large enough: the claim is honest. */
    static uint8_t big[512];
    osdp_pd_set_mfg_receiver(&pd, big, sizeof(big), NULL, NULL);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_check_pdcap(&pd, &r, 1, NULL));
}

/* Zero means "I do not do multi-part", which is exactly true today. */
static void test_zero_combined_message_size_passes(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pdcap_record_t r = size_record(FN_COMBINED_SIZE, 0);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_check_pdcap(&pd, &r, 1, NULL));
}

/* ---- A realistic, correct capability list ------------------------------*/

/* The check earns its keep only if a well-formed PDCAP passes cleanly. */
static void test_a_consistent_capability_list_passes(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    configure_sc(&pd);

    /* Bind a generous rx_plain and advertise a modest receive size, so the
     * list is consistent whatever OSDP_PD_BUF_LEN and OSDP_STREAM_BUFFER_LEN
     * are set to. Advertising OSDP_PD_BUF_LEN here looked reasonable and was
     * wrong: nothing says the TX-side constant fits the RX-side stream. */
    static uint8_t rx_plain[512];
    const osdp_pd_buffers_t bufs = { .rx_plain = rx_plain,
                                     .rx_plain_cap = sizeof(rx_plain) };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_buffers(&pd, &bufs));

    const osdp_pdcap_record_t records[] = {
        { .function_code = 1,  .compliance_level = 1,    .num_objects = 8 },
        { .function_code = 2,  .compliance_level = 1,    .num_objects = 4 },
        { .function_code = 4,  .compliance_level = 1,    .num_objects = 2 },
        { .function_code = 5,  .compliance_level = 1,    .num_objects = 1 },
        { .function_code = FN_COMM_SECURITY,
          .compliance_level = 0x01, .num_objects = 0x01 },
        size_record(FN_RECEIVE_SIZE,  256),
        size_record(FN_COMBINED_SIZE, 0),
        { .function_code = 16, .compliance_level = 2,    .num_objects = 0 },
    };
    size_t bad = 999;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pd_check_pdcap(&pd, records,
                                          sizeof(records) / sizeof(records[0]),
                                          &bad));
}

/* ========================================================================
 * osdp_pd_default_pdcap / osdp_pd_set_pdcap
 *
 * The reserved function codes (8, 9, 10, 17) are library-computed and
 * never accepted from the application; osdp_pd_default_pdcap's output
 * never includes them, and osdp_pd_set_pdcap rejects them from records[].
 * fn 11 stays consumer-settable and still goes through osdp_pd_check_pdcap.
 * ====================================================================== */

#define FN_CHECK_CHARACTER  8U
#define FN_SECURE_BIOMETRICS 17U

static const osdp_pdcap_record_t *find_record(const osdp_pdcap_record_t *recs,
                                              size_t count, uint8_t fc)
{
    for (size_t i = 0; i < count; i++) {
        if (recs[i].function_code == fc) {
            return &recs[i];
        }
    }
    return NULL;
}

static void test_default_pdcap_rejects_null(void)
{
    osdp_pdcap_record_t out[16];
    size_t count;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pd_default_pdcap(NULL, 16, &count));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pd_default_pdcap(out, 16, NULL));
}

static void test_default_pdcap_rejects_undersized_buffer(void)
{
    osdp_pdcap_record_t out[1];
    size_t count;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pd_default_pdcap(out, 1, &count));
}

/* The whole point of the split: the default set can always be handed
 * straight to osdp_pd_set_pdcap on a freshly-initialized PD without ever
 * touching a reserved function code — except fn 11, whose 0xFFFF
 * placeholder is a deliberate exception (see its own test below). */
static void test_default_pdcap_excludes_reserved_function_codes(void)
{
    osdp_pdcap_record_t out[OSDP_PD_MAX_PDCAP_RECORDS];
    size_t count;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pd_default_pdcap(out, OSDP_PD_MAX_PDCAP_RECORDS,
                                            &count));
    TEST_ASSERT_GREATER_THAN(0, count);
    for (size_t i = 0; i < count; i++) {
        const uint8_t fc = out[i].function_code;
        TEST_ASSERT_FALSE(fc == FN_CHECK_CHARACTER);
        TEST_ASSERT_FALSE(fc == FN_COMM_SECURITY);
        TEST_ASSERT_FALSE(fc == FN_RECEIVE_SIZE);
        TEST_ASSERT_FALSE(fc == FN_SECURE_BIOMETRICS);
    }
}

/* fn 11's 0xFFFF placeholder default is intentionally NOT self-consistent:
 * it must fail osdp_pd_set_pdcap (via osdp_pd_check_pdcap) until a
 * multi-part receiver is actually bound, so a consumer cannot ship it
 * unmodified and silently over-promise. */
static void test_default_pdcap_fn11_placeholder_needs_a_bound_receiver(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    osdp_pdcap_record_t out[OSDP_PD_MAX_PDCAP_RECORDS];
    size_t count;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pd_default_pdcap(out, OSDP_PD_MAX_PDCAP_RECORDS,
                                            &count));

    size_t bad = 999;
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
                      osdp_pd_set_pdcap(&pd, out, count, &bad));

    /* Binding a receiver alone is not enough — 0xFFFF also has to fit its
     * capacity. Lowering fn 11 to the receiver's real size is the
     * documented fix, not just binding the receiver. */
    static uint8_t mp_buf[512];
    osdp_pd_set_mfg_receiver(&pd, mp_buf, sizeof(mp_buf), NULL, NULL);
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pd_set_pdcap(&pd, out, count, NULL));

    osdp_pdcap_record_t *fn11 = (osdp_pdcap_record_t *)
        find_record(out, count, 11U);
    TEST_ASSERT_NOT_NULL(fn11);
    fn11->compliance_level = (uint8_t)(sizeof(mp_buf) & 0xFFU);
    fn11->num_objects      = (uint8_t)(sizeof(mp_buf) >> 8);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_pdcap(&pd, out, count, NULL));
}

static void test_set_pdcap_rejects_reserved_function_codes(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const uint8_t reserved[] = { FN_CHECK_CHARACTER, FN_COMM_SECURITY,
                                FN_RECEIVE_SIZE, FN_SECURE_BIOMETRICS };
    for (size_t i = 0; i < sizeof(reserved); i++) {
        const osdp_pdcap_record_t records[] = {
            { .function_code = 1, .compliance_level = 1, .num_objects = 1 },
            { .function_code = reserved[i],
              .compliance_level = 0, .num_objects = 0 },
        };
        size_t bad = 999;
        TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                          osdp_pd_set_pdcap(&pd, records, 2, &bad));
        TEST_ASSERT_EQUAL_size_t(1, bad);
    }
}

static void test_set_pdcap_rejects_spec_nonconformant_record(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    /* fn 4 (Reader LED Control) tops out at compliance 6 (B.5). */
    const osdp_pdcap_record_t records[] = {
        { .function_code = 4, .compliance_level = 7, .num_objects = 1 },
    };
    size_t bad = 999;
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pd_set_pdcap(&pd, records, 1, &bad));
    TEST_ASSERT_EQUAL_size_t(0, bad);
}

static void test_set_pdcap_rejects_oversized_count(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    /* The count ceiling is checked before any per-record validation, so a
     * non-NULL array (contents irrelevant) is what proves THIS check fired
     * rather than the NULL-argument one. */
    osdp_pdcap_record_t records[OSDP_PD_MAX_PDCAP_RECORDS + 1] = {0};
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_pd_set_pdcap(&pd, records,
                                        OSDP_PD_MAX_PDCAP_RECORDS + 1, NULL));
}

/* A rejected call must not disturb whatever was bound before it. */
static void test_set_pdcap_failure_leaves_previous_binding_intact(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pdcap_record_t good[] = {
        { .function_code = 1, .compliance_level = 1, .num_objects = 4 },
    };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_pdcap(&pd, good, 1, NULL));

    const osdp_pdcap_record_t bad_set[] = {
        { .function_code = 4, .compliance_level = 7, .num_objects = 1 },
    };
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
                      osdp_pd_set_pdcap(&pd, bad_set, 1, NULL));

    TEST_ASSERT_EQUAL_UINT(1, (unsigned)pd.pdcap_count);
    TEST_ASSERT_EQUAL_HEX8(1, pd.pdcap_records[0].function_code);
}

static void test_set_pdcap_zero_count_clears_the_binding(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pdcap_record_t records[] = {
        { .function_code = 1, .compliance_level = 1, .num_objects = 4 },
    };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_pdcap(&pd, records, 1, NULL));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_pdcap(&pd, NULL, 0, NULL));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)pd.pdcap_count);
}

/* ========================================================================
 * osdp_CMD_CAP dispatch end-to-end: drive a real frame through
 * osdp_pd_tick and decode what comes back, so it is the wire bytes that
 * get checked rather than internal state.
 * ====================================================================== */

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

typedef struct app_spy { unsigned int calls; } app_spy_t;

static osdp_status_t spy_handler(void *user, uint8_t cmd_code,
                                 const uint8_t *payload, size_t payload_len,
                                 osdp_pd_reply_t *reply)
{
    (void)cmd_code; (void)payload; (void)payload_len;
    ((app_spy_t *)user)->calls++;
    reply->code        = OSDP_REPLY_ACK;
    reply->payload     = NULL;
    reply->payload_len = 0;
    return OSDP_OK;
}

/* Nothing bound: osdp_CAP falls through to cmd_cb exactly as it did before
 * osdp_pd_set_pdcap existed. */
static void test_cap_falls_through_to_cmd_cb_when_nothing_bound(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy = {0};
    mock_init(&m, &t);
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, spy_handler, &spy);

    inject(&m, OSDP_CMD_CAP, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_UINT(1, spy.calls);
}

/* Once bound, the library answers osdp_CAP directly with the consumer's
 * records PLUS the four reserved records it computes itself, and cmd_cb is
 * never invoked. */
static void test_cap_answered_from_bound_records_plus_reserved(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy = {0};
    mock_init(&m, &t);
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, spy_handler, &spy);

    const osdp_pdcap_record_t bound[] = {
        { .function_code = 1, .compliance_level = 4, .num_objects = 8 },
        { .function_code = 4, .compliance_level = 4, .num_objects = 2 },
    };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_pdcap(&pd, bound, 2, NULL));

    inject(&m, OSDP_CMD_CAP, NULL, 0, 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_reply(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDCAP, reply.code);
    TEST_ASSERT_EQUAL_UINT(0, spy.calls);

    osdp_pdcap_record_t got[16];
    size_t n;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_pdcap_decode(reply.payload, reply.payload_len,
                                        got, 16, &n));
    TEST_ASSERT_EQUAL_size_t(2 + 4, n);   /* bound + the 4 reserved records */

    /* The bound records are present, verbatim. */
    const osdp_pdcap_record_t *r1 = find_record(got, n, 1);
    TEST_ASSERT_NOT_NULL(r1);
    TEST_ASSERT_EQUAL_HEX8(4, r1->compliance_level);
    TEST_ASSERT_EQUAL_HEX8(8, r1->num_objects);

    /* fn 8: always 0x01/0x00, per osdp_pd_internal_fill_reserved_pdcap. */
    const osdp_pdcap_record_t *r8 = find_record(got, n, FN_CHECK_CHARACTER);
    TEST_ASSERT_NOT_NULL(r8);
    TEST_ASSERT_EQUAL_HEX8(0x01, r8->compliance_level);
    TEST_ASSERT_EQUAL_HEX8(0x00, r8->num_objects);

    /* fn 9: compliance always claims AES128; num_objects reports "no
     * unique key" (0x01) since osdp_pd_set_sc_scbk was never called. */
    const osdp_pdcap_record_t *r9 = find_record(got, n, FN_COMM_SECURITY);
    TEST_ASSERT_NOT_NULL(r9);
    TEST_ASSERT_EQUAL_HEX8(0x01, r9->compliance_level);
    TEST_ASSERT_EQUAL_HEX8(0x01, r9->num_objects);

    /* fn 10: min(rx_plain_cap, OSDP_STREAM_BUFFER_LEN) at the defaults. */
    const osdp_pdcap_record_t *r10 = find_record(got, n, FN_RECEIVE_SIZE);
    TEST_ASSERT_NOT_NULL(r10);
    const uint16_t expect_rx =
        (pd.rx_plain_cap > OSDP_STREAM_BUFFER_LEN)
            ? (uint16_t)OSDP_STREAM_BUFFER_LEN : (uint16_t)pd.rx_plain_cap;
    TEST_ASSERT_EQUAL_HEX8((uint8_t)(expect_rx & 0xFFU), r10->compliance_level);
    TEST_ASSERT_EQUAL_HEX8((uint8_t)(expect_rx >> 8), r10->num_objects);

    /* fn 17: fixed 0x01/0x00. */
    const osdp_pdcap_record_t *r17 = find_record(got, n, FN_SECURE_BIOMETRICS);
    TEST_ASSERT_NOT_NULL(r17);
    TEST_ASSERT_EQUAL_HEX8(0x01, r17->compliance_level);
    TEST_ASSERT_EQUAL_HEX8(0x00, r17->num_objects);
}

/* fn 9's num_objects must reflect pd's key state at QUERY time, not at
 * osdp_pd_set_pdcap time — no re-binding needed after keying the PD. */
static void test_cap_fn9_num_objects_tracks_key_state_live(void)
{
    osdp_pd_t pd; mock_transport_t m; osdp_pd_transport_t t; app_spy_t spy = {0};
    mock_init(&m, &t);
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_command_handler(&pd, spy_handler, &spy);

    const osdp_pdcap_record_t bound[] = {
        { .function_code = 1, .compliance_level = 1, .num_objects = 1 },
    };
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pd_set_pdcap(&pd, bound, 1, NULL));

    inject(&m, OSDP_CMD_CAP, NULL, 0, 1);
    osdp_pd_tick(&pd);
    osdp_frame_t reply1;
    decode_reply(&m, &reply1);
    osdp_pdcap_record_t got1[16]; size_t n1;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_decode(reply1.payload,
                                                 reply1.payload_len,
                                                 got1, 16, &n1));
    TEST_ASSERT_EQUAL_HEX8(0x01,
                          find_record(got1, n1, FN_COMM_SECURITY)->num_objects);

    static const uint8_t key[OSDP_SC_KEY_LEN] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    osdp_pd_set_sc_scbk(&pd, key);

    m.outgoing_len = 0;
    inject(&m, OSDP_CMD_CAP, NULL, 0, 2);
    osdp_pd_tick(&pd);
    osdp_frame_t reply2;
    decode_reply(&m, &reply2);
    osdp_pdcap_record_t got2[16]; size_t n2;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pdcap_decode(reply2.payload,
                                                 reply2.payload_len,
                                                 got2, 16, &n2));
    TEST_ASSERT_EQUAL_HEX8(0x00,
                          find_record(got2, n2, FN_COMM_SECURITY)->num_objects);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_null_arguments_are_rejected);
    RUN_TEST(test_unknown_function_codes_are_left_alone);
    RUN_TEST(test_aes128_claim_without_sc_configured_is_flagged);
    RUN_TEST(test_aes128_claim_with_sc_configured_passes);
    RUN_TEST(test_no_security_claim_is_fine_without_sc);
    RUN_TEST(test_receive_size_above_the_stream_buffer_is_flagged);
    RUN_TEST(test_receive_size_at_the_stream_buffer_passes);
    RUN_TEST(test_receive_size_beyond_rx_plain_is_flagged_under_sc);
    RUN_TEST(test_large_receive_size_is_fine_without_sc);
    RUN_TEST(test_combined_message_size_needs_a_bound_reassembly_buffer);
    RUN_TEST(test_zero_combined_message_size_passes);
    RUN_TEST(test_a_consistent_capability_list_passes);

    RUN_TEST(test_default_pdcap_rejects_null);
    RUN_TEST(test_default_pdcap_rejects_undersized_buffer);
    RUN_TEST(test_default_pdcap_excludes_reserved_function_codes);
    RUN_TEST(test_default_pdcap_fn11_placeholder_needs_a_bound_receiver);
    RUN_TEST(test_set_pdcap_rejects_reserved_function_codes);
    RUN_TEST(test_set_pdcap_rejects_spec_nonconformant_record);
    RUN_TEST(test_set_pdcap_rejects_oversized_count);
    RUN_TEST(test_set_pdcap_failure_leaves_previous_binding_intact);
    RUN_TEST(test_set_pdcap_zero_count_clears_the_binding);

    RUN_TEST(test_cap_falls_through_to_cmd_cb_when_nothing_bound);
    RUN_TEST(test_cap_answered_from_bound_records_plus_reserved);
    RUN_TEST(test_cap_fn9_num_objects_tracks_key_state_live);
    return UNITY_END();
}
