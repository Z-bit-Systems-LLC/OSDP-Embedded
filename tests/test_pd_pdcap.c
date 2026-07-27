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

static void test_combined_message_size_is_flagged_while_multipart_is_absent(void)
{
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);

    const osdp_pdcap_record_t r = size_record(FN_COMBINED_SIZE, 4096);
    size_t bad = 999;
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
                      osdp_pd_check_pdcap(&pd, &r, 1, &bad));
    TEST_ASSERT_EQUAL_size_t(0, bad);
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
    RUN_TEST(test_combined_message_size_is_flagged_while_multipart_is_absent);
    RUN_TEST(test_zero_combined_message_size_passes);
    RUN_TEST(test_a_consistent_capability_list_passes);
    return UNITY_END();
}
