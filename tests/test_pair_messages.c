// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Phase 3 pairing message codec tests (Msg1/2/3/Result CBOR encode/parse).
 * No crypto — the key/signature/cert fields are opaque placeholder bytes. */

#include "osdp/osdp_pair.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static uint8_t s_nonce_a[OSDP_PAIR_NONCE_LEN];
static uint8_t s_nonce_p[OSDP_PAIR_NONCE_LEN];
static uint8_t s_ek[OSDP_MLKEM768_EK_LEN];
static uint8_t s_ct[OSDP_PAIR_CT_LEN];
static uint8_t s_sig[OSDP_PAIR_SIG_LEN];
static uint8_t s_mac[OSDP_PAIR_MAC_LEN];
static uint8_t s_cred[512];   /* stand-in for a cert credential */

static void fill(uint8_t *p, size_t n, uint8_t seed)
{
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(i * 31u + seed);
    }
}

static void init_material(void)
{
    fill(s_nonce_a, sizeof(s_nonce_a), 0xA0);
    fill(s_nonce_p, sizeof(s_nonce_p), 0xB0);
    fill(s_ek, sizeof(s_ek), 0x11);
    fill(s_ct, sizeof(s_ct), 0x22);
    fill(s_sig, sizeof(s_sig), 0x33);
    fill(s_mac, sizeof(s_mac), 0x44);
    fill(s_cred, sizeof(s_cred), 0x55);
}

/* ---- Message 1 ---------------------------------------------------------- */

static void test_msg1_round_trip(void)
{
    init_material();
    static uint8_t buf[4096];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_msg1_encode(s_nonce_a, sizeof(s_nonce_a), s_ek, sizeof(s_ek),
                              OSDP_PAIR_CRED_CERT, s_cred, sizeof(s_cred),
                              buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_HEX8(OSDP_PAIR_MSG_TYPE_1, buf[0]);

    osdp_pair_msg1_t m;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_msg1_decode(buf, n, &m));
    TEST_ASSERT_EQUAL_UINT64(OSDP_PAIR_PROTOCOL_VERSION, m.version);
    TEST_ASSERT_EQUAL_UINT64(OSDP_PAIR_CIPHER_SUITE, m.suite);
    TEST_ASSERT_EQUAL_MEMORY(s_nonce_a, m.nonce_a, sizeof(s_nonce_a));
    TEST_ASSERT_EQUAL_MEMORY(s_ek, m.ek, sizeof(s_ek));
    TEST_ASSERT_EQUAL_UINT64(OSDP_PAIR_CRED_CERT, m.cred_type);
    TEST_ASSERT_EQUAL_MEMORY(s_cred, m.cred, sizeof(s_cred));
    /* wire span aliases the input, for TH1. */
    TEST_ASSERT_EQUAL_PTR(buf, m.wire);
    TEST_ASSERT_EQUAL_size_t(n, m.wire_len);

    /* Deterministic re-encode. */
    static uint8_t buf2[4096];
    size_t n2 = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_msg1_encode(m.nonce_a, m.nonce_a_len, m.ek, m.ek_len,
                              m.cred_type, m.cred, m.cred_len,
                              buf2, sizeof(buf2), &n2));
    TEST_ASSERT_EQUAL_size_t(n, n2);
    TEST_ASSERT_EQUAL_MEMORY(buf, buf2, n);
}

static void test_msg1_decode_rejects_bad_ek_len(void)
{
    init_material();
    static uint8_t buf[4096];
    size_t n = 0;
    /* ek one byte short of 1184. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_msg1_encode(s_nonce_a, sizeof(s_nonce_a), s_ek, sizeof(s_ek) - 1,
                              OSDP_PAIR_CRED_CERT, s_cred, sizeof(s_cred),
                              buf, sizeof(buf), &n));
    osdp_pair_msg1_t m;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_pair_msg1_decode(buf, n, &m));
}

static void test_msg1_decode_rejects_wrong_tag(void)
{
    init_material();
    static uint8_t buf[4096];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_msg1_encode(s_nonce_a, sizeof(s_nonce_a), s_ek, sizeof(s_ek),
                              OSDP_PAIR_CRED_CERT, s_cred, sizeof(s_cred),
                              buf, sizeof(buf), &n));
    buf[0] = OSDP_PAIR_MSG_TYPE_2; /* corrupt the type tag */
    osdp_pair_msg1_t m;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_pair_msg1_decode(buf, n, &m));
}

/* ---- Message 2 (core + outer) ------------------------------------------- */

static void test_msg2_round_trip(void)
{
    init_material();
    static uint8_t core[4096];
    size_t core_n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_msg2_core_encode(s_nonce_p, sizeof(s_nonce_p), s_ct, sizeof(s_ct),
                                   OSDP_PAIR_CRED_THUMBPRINT, s_mac, sizeof(s_mac),
                                   core, sizeof(core), &core_n));

    static uint8_t buf[8192];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_msg2_encode(core, core_n, s_sig, sizeof(s_sig),
                              s_mac, sizeof(s_mac), buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_HEX8(OSDP_PAIR_MSG_TYPE_2, buf[0]);

    osdp_pair_msg2_t m;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_msg2_decode(buf, n, &m));
    /* The decoded core span equals the standalone core encoding (TH2 input). */
    TEST_ASSERT_EQUAL_size_t(core_n, m.core_len);
    TEST_ASSERT_EQUAL_MEMORY(core, m.core, core_n);
    TEST_ASSERT_EQUAL_MEMORY(s_nonce_p, m.nonce_p, sizeof(s_nonce_p));
    TEST_ASSERT_EQUAL_MEMORY(s_ct, m.ct, sizeof(s_ct));
    TEST_ASSERT_EQUAL_UINT64(OSDP_PAIR_CRED_THUMBPRINT, m.cred_type);
    TEST_ASSERT_EQUAL_MEMORY(s_mac, m.cred, sizeof(s_mac)); /* 32-byte thumbprint */
    TEST_ASSERT_EQUAL_MEMORY(s_sig, m.sig_p, sizeof(s_sig));
    TEST_ASSERT_EQUAL_MEMORY(s_mac, m.mac_p, sizeof(s_mac));
}

static void test_msg2_decode_rejects_bad_sig_len(void)
{
    init_material();
    static uint8_t core[4096];
    size_t core_n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_msg2_core_encode(s_nonce_p, sizeof(s_nonce_p), s_ct, sizeof(s_ct),
                                   OSDP_PAIR_CRED_THUMBPRINT, s_mac, sizeof(s_mac),
                                   core, sizeof(core), &core_n));
    static uint8_t buf[8192];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_msg2_encode(core, core_n, s_sig, sizeof(s_sig) - 1,
                              s_mac, sizeof(s_mac), buf, sizeof(buf), &n));
    osdp_pair_msg2_t m;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_pair_msg2_decode(buf, n, &m));
}

/* ---- Message 3 ---------------------------------------------------------- */

static void test_msg3_round_trip(void)
{
    init_material();
    static uint8_t buf[4096];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_msg3_encode(s_sig, sizeof(s_sig), s_mac, sizeof(s_mac),
                              buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_HEX8(OSDP_PAIR_MSG_TYPE_3, buf[0]);

    osdp_pair_msg3_t m;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_msg3_decode(buf, n, &m));
    TEST_ASSERT_EQUAL_MEMORY(s_sig, m.sig_a, sizeof(s_sig));
    TEST_ASSERT_EQUAL_MEMORY(s_mac, m.mac_a, sizeof(s_mac));
}

/* ---- Result ------------------------------------------------------------- */

static void test_result_round_trip_success(void)
{
    init_material();
    uint8_t buf[64];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_result_encode(0x00, s_mac, sizeof(s_mac), buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL_HEX8(OSDP_PAIR_MSG_TYPE_RESULT, buf[0]);

    osdp_pair_result_t m;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_result_decode(buf, n, &m));
    TEST_ASSERT_EQUAL_UINT64(0x00, m.status);
    TEST_ASSERT_EQUAL_size_t(OSDP_PAIR_MAC_LEN, m.mac_len);
    TEST_ASSERT_EQUAL_MEMORY(s_mac, m.mac, OSDP_PAIR_MAC_LEN);
}

static void test_result_round_trip_failure_empty_mac(void)
{
    uint8_t buf[16];
    size_t n = 0;
    /* status 0x01 (auth-fail), empty MAC. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_result_encode(0x01, NULL, 0, buf, sizeof(buf), &n));

    osdp_pair_result_t m;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_result_decode(buf, n, &m));
    TEST_ASSERT_EQUAL_UINT64(0x01, m.status);
    TEST_ASSERT_EQUAL_size_t(0, m.mac_len);
}

static void test_result_decode_rejects_bad_mac_len(void)
{
    /* Hand-craft a Result with a 5-byte MAC (neither 0 nor 32). */
    static const uint8_t bad[] = {
        OSDP_PAIR_MSG_TYPE_RESULT,
        0x82,             /* array(2) */
        0x00,             /* status 0 */
        0x45,             /* bstr len 5 */
        1, 2, 3, 4, 5,
    };
    osdp_pair_result_t m;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
                      osdp_pair_result_decode(bad, sizeof(bad), &m));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_msg1_round_trip);
    RUN_TEST(test_msg1_decode_rejects_bad_ek_len);
    RUN_TEST(test_msg1_decode_rejects_wrong_tag);
    RUN_TEST(test_msg2_round_trip);
    RUN_TEST(test_msg2_decode_rejects_bad_sig_len);
    RUN_TEST(test_msg3_round_trip);
    RUN_TEST(test_result_round_trip_success);
    RUN_TEST(test_result_round_trip_failure_empty_mac);
    RUN_TEST(test_result_decode_rejects_bad_mac_len);
    return UNITY_END();
}
