// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Phase 1 C509 certificate encode/decode tests. These exercise the pure
 * CBOR structure only — no crypto. The thumbprint (SHA-256) and signature
 * verification (ML-DSA-44) paths call the crypto HAL and are covered
 * separately once a backend is wired. */

#include "osdp/osdp_pair.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* A cert filled with recognizable placeholder key/signature material. */
static uint8_t s_pubkey[OSDP_MLDSA44_PK_LEN];
static uint8_t s_sig[OSDP_MLDSA44_SIG_LEN];
static const uint8_t s_serial[OSDP_C509_SERIAL_LEN] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
};

static osdp_c509_cert_t make_sample(void)
{
    for (size_t i = 0; i < sizeof(s_pubkey); i++) {
        s_pubkey[i] = (uint8_t)(i & 0xFFu);
    }
    for (size_t i = 0; i < sizeof(s_sig); i++) {
        s_sig[i] = (uint8_t)((i * 3u + 7u) & 0xFFu);
    }
    osdp_c509_cert_t c = {
        .version            = OSDP_C509_VERSION,
        .serial             = s_serial,
        .serial_len         = sizeof(s_serial),
        .issuer             = "OSDP-DEMO-CA",
        .issuer_len         = 12,
        .not_before         = 1700000000ULL,
        .not_after          = 2000000000ULL,
        .manufacturer       = "Z-bit Systems",
        .manufacturer_len   = 13,
        .model              = "R1",
        .model_len          = 2,
        .subject_serial     = "SN-00042",
        .subject_serial_len = 8,
        .public_key_alg     = OSDP_C509_ALG_MLDSA44,
        .public_key         = s_pubkey,
        .public_key_len     = sizeof(s_pubkey),
        .signature_alg      = OSDP_C509_ALG_MLDSA44,
        .signature          = s_sig,
        .signature_len      = sizeof(s_sig),
        .tbs                = NULL,
        .tbs_len            = 0,
    };
    return c;
}

static void test_cert_round_trip(void)
{
    osdp_c509_cert_t in = make_sample();

    uint8_t buf[4096];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&in, buf, sizeof(buf), &n));

    osdp_c509_cert_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_decode(buf, n, &got));

    TEST_ASSERT_EQUAL_UINT64(in.version, got.version);
    TEST_ASSERT_EQUAL_size_t(in.serial_len, got.serial_len);
    TEST_ASSERT_EQUAL_MEMORY(in.serial, got.serial, in.serial_len);
    TEST_ASSERT_EQUAL_size_t(in.issuer_len, got.issuer_len);
    TEST_ASSERT_EQUAL_MEMORY(in.issuer, got.issuer, in.issuer_len);
    TEST_ASSERT_EQUAL_UINT64(in.not_before, got.not_before);
    TEST_ASSERT_EQUAL_UINT64(in.not_after, got.not_after);
    TEST_ASSERT_EQUAL_MEMORY(in.manufacturer, got.manufacturer,
                             in.manufacturer_len);
    TEST_ASSERT_EQUAL_MEMORY(in.model, got.model, in.model_len);
    TEST_ASSERT_EQUAL_MEMORY(in.subject_serial, got.subject_serial,
                             in.subject_serial_len);
    TEST_ASSERT_EQUAL_UINT64(in.public_key_alg, got.public_key_alg);
    TEST_ASSERT_EQUAL_size_t(in.public_key_len, got.public_key_len);
    TEST_ASSERT_EQUAL_MEMORY(in.public_key, got.public_key, in.public_key_len);
    TEST_ASSERT_EQUAL_size_t(in.signature_len, got.signature_len);
    TEST_ASSERT_EQUAL_MEMORY(in.signature, got.signature, in.signature_len);
}

/* Encoding is deterministic: decode → re-encode is byte-identical. */
static void test_cert_encoding_is_deterministic(void)
{
    osdp_c509_cert_t in = make_sample();
    uint8_t buf1[4096];
    size_t n1 = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&in, buf1, sizeof(buf1), &n1));

    osdp_c509_cert_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_decode(buf1, n1, &got));

    uint8_t buf2[4096];
    size_t n2 = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&got, buf2, sizeof(buf2), &n2));

    TEST_ASSERT_EQUAL_size_t(n1, n2);
    TEST_ASSERT_EQUAL_MEMORY(buf1, buf2, n1);
}

/* The captured TBS slice equals a fresh standalone TBS encoding — this is
 * exactly the byte range the ML-DSA-44 signature covers. */
static void test_cert_tbs_slice_matches_encode_tbs(void)
{
    osdp_c509_cert_t in = make_sample();
    uint8_t full[4096];
    size_t full_n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&in, full, sizeof(full), &full_n));

    osdp_c509_cert_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_decode(full, full_n, &got));
    TEST_ASSERT_NOT_NULL(got.tbs);
    TEST_ASSERT_TRUE(got.tbs_len > 0);

    uint8_t tbs[2048];
    size_t tbs_n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode_tbs(&in, tbs, sizeof(tbs), &tbs_n));

    TEST_ASSERT_EQUAL_size_t(tbs_n, got.tbs_len);
    TEST_ASSERT_EQUAL_MEMORY(tbs, got.tbs, tbs_n);
}

static void test_cert_encode_rejects_small_buffer(void)
{
    osdp_c509_cert_t in = make_sample();
    uint8_t buf[64]; /* far too small for a 1312-byte key */
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
                      osdp_c509_encode(&in, buf, sizeof(buf), &n));
}

static void test_cert_decode_rejects_bad_version(void)
{
    osdp_c509_cert_t in = make_sample();
    in.version = 2; /* unsupported */
    uint8_t buf[4096];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&in, buf, sizeof(buf), &n));

    osdp_c509_cert_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_c509_decode(buf, n, &got));
}

static void test_cert_decode_rejects_bad_key_length(void)
{
    /* Encode with a short public key; decode must reject it. */
    osdp_c509_cert_t in = make_sample();
    in.public_key_len = 16;
    uint8_t buf[4096];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&in, buf, sizeof(buf), &n));

    osdp_c509_cert_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_c509_decode(buf, n, &got));
}

static void test_cert_decode_rejects_oversized_string(void)
{
    /* An identity string past OSDP_PAIR_STR_MAX is rejected. */
    static char big[OSDP_PAIR_STR_MAX + 8];
    (void)memset(big, 'x', sizeof(big));
    osdp_c509_cert_t in = make_sample();
    in.model     = big;
    in.model_len = sizeof(big);

    uint8_t buf[4096];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&in, buf, sizeof(buf), &n));

    osdp_c509_cert_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_c509_decode(buf, n, &got));
}

static void test_cert_decode_rejects_trailing_bytes(void)
{
    osdp_c509_cert_t in = make_sample();
    uint8_t buf[4096];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&in, buf, sizeof(buf), &n));

    osdp_c509_cert_t got;
    /* One extra byte beyond the cert. */
    buf[n] = 0x00;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_c509_decode(buf, n + 1, &got));
}

static void test_cert_decode_rejects_truncated(void)
{
    osdp_c509_cert_t in = make_sample();
    uint8_t buf[4096];
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&in, buf, sizeof(buf), &n));

    osdp_c509_cert_t got;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, osdp_c509_decode(buf, n - 1, &got));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cert_round_trip);
    RUN_TEST(test_cert_encoding_is_deterministic);
    RUN_TEST(test_cert_tbs_slice_matches_encode_tbs);
    RUN_TEST(test_cert_encode_rejects_small_buffer);
    RUN_TEST(test_cert_decode_rejects_bad_version);
    RUN_TEST(test_cert_decode_rejects_bad_key_length);
    RUN_TEST(test_cert_decode_rejects_oversized_string);
    RUN_TEST(test_cert_decode_rejects_trailing_bytes);
    RUN_TEST(test_cert_decode_rejects_truncated);
    return UNITY_END();
}
