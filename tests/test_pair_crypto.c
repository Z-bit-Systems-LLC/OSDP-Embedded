// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Phase 1 crypto KATs for OSDP-SC2 pairing, over the PQClean-backed test
 * HAL: SHA-256 / HKDF standard vectors, C509 thumbprint + signature verify,
 * KEM round trip, and fixed-seed ML-KEM/ML-DSA public-key cross-checks
 * against the OSDP.Net reference constants. */

#include "osdp/osdp_pair.h"
#include "pair_test_crypto.h"
#include "unity.h"

#include <string.h>

static osdp_pair_crypto_t   s_crypto;
static osdp_pair_test_ctx_t s_ctx;

void setUp(void)
{
    osdp_pair_test_crypto_init(&s_crypto, &s_ctx);
    osdp_pair_test_seed_clear();
}
void tearDown(void) {}

static void fill_iota(uint8_t *p, size_t n, uint8_t start)
{
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(start + i);
    }
}

/* ---- SHA-256 / HKDF standard vectors ------------------------------------ */

static void test_sha256_abc(void)
{
    static const uint8_t expect[32] = {
        0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,0x41,0x41,0x40,0xDE,0x5D,0xAE,
        0x22,0x23,0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,0xB4,0x10,0xFF,0x61,
        0xF2,0x00,0x15,0xAD,
    };
    uint8_t out[32];
    TEST_ASSERT_EQUAL(OSDP_OK,
        s_crypto.sha256(s_crypto.user, (const uint8_t *)"abc", 3, out));
    TEST_ASSERT_EQUAL_MEMORY(expect, out, 32);
}

/* RFC 5869 Test Case 1 (SHA-256). */
static void test_hkdf_rfc5869_tc1(void)
{
    uint8_t ikm[22];  (void)memset(ikm, 0x0B, sizeof(ikm));
    static const uint8_t salt[13] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,
    };
    static const uint8_t info[10] = {
        0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,
    };
    static const uint8_t okm[42] = {
        0x3C,0xB2,0x5F,0x25,0xFA,0xAC,0xD5,0x7A,0x90,0x43,0x4F,0x64,0xD0,0x36,
        0x2F,0x2A,0x2D,0x2D,0x0A,0x90,0xCF,0x1A,0x5A,0x4C,0x5D,0xB0,0x2D,0x56,
        0xEC,0xC4,0xC5,0xBF,0x34,0x00,0x72,0x08,0xD5,0xB8,0x87,0x18,0x58,0x65,
    };
    uint8_t out[42];
    TEST_ASSERT_EQUAL(OSDP_OK,
        s_crypto.hkdf_sha256(s_crypto.user, salt, sizeof(salt),
                             ikm, sizeof(ikm), info, sizeof(info),
                             out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(okm, out, sizeof(out));
}

/* ---- Fixed-seed public-key cross-checks vs OSDP.Net constants ----------- */

static void test_mldsa_demo_ca_pubkey_hash(void)
{
    /* Demo CA seed = 0x40..0x5F (32 bytes). SHA-256 of the resulting
     * ML-DSA-44 public key is the published demo-CA thumbprint. */
    uint8_t seed[32];
    fill_iota(seed, sizeof(seed), 0x40);
    osdp_pair_test_seed_push(seed, sizeof(seed));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_test_gen_dsa(&s_ctx));

    uint8_t hash[32];
    TEST_ASSERT_EQUAL(OSDP_OK,
        s_crypto.sha256(s_crypto.user, s_ctx.dsa_pk, OSDP_MLDSA44_PK_LEN, hash));

    static const uint8_t expect[32] = {
        0x6C,0x1C,0x65,0x07,0x19,0x79,0x22,0x5A,0x13,0x9B,0x3E,0xC8,0x46,0x88,
        0xE2,0x68,0x8E,0xC3,0x0F,0xAB,0xE8,0xCC,0x51,0x0C,0xB6,0x88,0xBC,0x43,
        0x5F,0x2D,0x3C,0xB9,
    };
    TEST_ASSERT_EQUAL_MEMORY(expect, hash, 32);
}

static void test_mlkem_seed_pubkey_hash(void)
{
    /* ML-KEM-768 keypair from seed 0x00..0x3F (64 bytes); SHA-256 of the
     * encapsulation (public) key matches the published constant. */
    uint8_t seed[64];
    fill_iota(seed, sizeof(seed), 0x00);
    osdp_pair_test_seed_push(seed, sizeof(seed));

    uint8_t ek[OSDP_MLKEM768_EK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK, s_crypto.ml_kem768_keygen(s_crypto.user, ek));

    uint8_t hash[32];
    TEST_ASSERT_EQUAL(OSDP_OK,
        s_crypto.sha256(s_crypto.user, ek, sizeof(ek), hash));

    static const uint8_t expect[32] = {
        0x0B,0x79,0x34,0xC8,0x31,0x25,0xC7,0x88,0x99,0x5E,0x2B,0xA6,0xBD,0x76,
        0x1E,0x33,0x04,0x6B,0x3E,0x40,0x57,0x1B,0xE5,0x3E,0x02,0x33,0x09,0xA2,
        0x9F,0x39,0x8C,0xC9,
    };
    TEST_ASSERT_EQUAL_MEMORY(expect, hash, 32);
}

/* ---- KEM round trip ----------------------------------------------------- */

static void test_kem_round_trip(void)
{
    /* ACU generates the ephemeral keypair; PD encapsulates to it; ACU
     * decapsulates — both must agree on the shared secret. */
    osdp_pair_crypto_t   acu_crypto;
    osdp_pair_test_ctx_t acu_ctx;
    osdp_pair_test_crypto_init(&acu_crypto, &acu_ctx);

    uint8_t ek[OSDP_MLKEM768_EK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK, acu_crypto.ml_kem768_keygen(acu_crypto.user, ek));

    uint8_t ct[OSDP_MLKEM768_CT_LEN];
    uint8_t ss_pd[OSDP_MLKEM_SS_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        s_crypto.ml_kem768_encaps(s_crypto.user, ek, ct, ss_pd));

    uint8_t ss_acu[OSDP_MLKEM_SS_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        acu_crypto.ml_kem768_decaps(acu_crypto.user, ct, ss_acu));

    TEST_ASSERT_EQUAL_MEMORY(ss_pd, ss_acu, OSDP_MLKEM_SS_LEN);
}

/* ---- C509 thumbprint + signature verify --------------------------------- */

/* Build a self-signed cert into `buf`; return its encoded length. */
static size_t build_self_signed(uint8_t *buf, size_t cap)
{
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_test_gen_dsa(&s_ctx));

    static const uint8_t serial[OSDP_C509_SERIAL_LEN] = {
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    osdp_c509_cert_t cert = {
        .version            = OSDP_C509_VERSION,
        .serial             = serial,
        .serial_len         = sizeof(serial),
        .issuer             = OSDP_C509_SELF_ISSUER,
        .issuer_len         = strlen(OSDP_C509_SELF_ISSUER),
        .not_before         = 1700000000ULL,
        .not_after          = 2000000000ULL,
        .manufacturer       = "Z-bit Systems",
        .manufacturer_len   = 13,
        .model              = "R1",
        .model_len          = 2,
        .subject_serial     = "SN-42",
        .subject_serial_len = 5,
        .public_key_alg     = OSDP_C509_ALG_MLDSA44,
        .public_key         = s_ctx.dsa_pk,
        .public_key_len     = OSDP_MLDSA44_PK_LEN,
        .signature_alg      = OSDP_C509_ALG_MLDSA44,
        .signature          = NULL,
        .signature_len      = 0,
    };

    /* Sign "OSDP-C509-v1" || TBS with the subject key. */
    uint8_t tbs[OSDP_C509_TBS_MAX];
    size_t  tbs_n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_c509_encode_tbs(&cert, tbs, sizeof(tbs), &tbs_n));

    static const char dom[] = OSDP_C509_SIG_DOMAIN;
    const size_t dom_len = sizeof(dom) - 1;
    uint8_t signed_msg[sizeof(dom) - 1 + OSDP_C509_TBS_MAX];
    (void)memcpy(signed_msg, dom, dom_len);
    (void)memcpy(&signed_msg[dom_len], tbs, tbs_n);

    static uint8_t sig[OSDP_MLDSA44_SIG_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        s_crypto.ml_dsa44_sign(s_crypto.user, signed_msg, dom_len + tbs_n, sig));
    cert.signature     = sig;
    cert.signature_len = sizeof(sig);

    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&cert, buf, cap, &n));
    return n;
}

static void test_cert_thumbprint_matches_sha256(void)
{
    static uint8_t buf[8192];
    const size_t n = build_self_signed(buf, sizeof(buf));

    uint8_t tp[32], direct[32];
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_thumbprint(&s_crypto, buf, n, tp));
    TEST_ASSERT_EQUAL(OSDP_OK, s_crypto.sha256(s_crypto.user, buf, n, direct));
    TEST_ASSERT_EQUAL_MEMORY(direct, tp, 32);
}

static void test_cert_verify_self_signed(void)
{
    static uint8_t buf[8192];
    const size_t n = build_self_signed(buf, sizeof(buf));

    osdp_c509_cert_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_decode(buf, n, &got));
    /* A self-signed cert verifies under its own public key. */
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_verify(&s_crypto, &got, got.public_key));
}

static void test_cert_verify_rejects_tamper(void)
{
    static uint8_t buf[8192];
    const size_t n = build_self_signed(buf, sizeof(buf));

    osdp_c509_cert_t got;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_decode(buf, n, &got));

    /* Flip one bit inside the public key (part of the signed TBS). Structure
     * stays valid; the signature must no longer verify. */
    uint8_t *pk = (uint8_t *)(uintptr_t)got.public_key;
    pk[0] ^= 0x01;
    TEST_ASSERT_NOT_EQUAL(OSDP_OK,
        osdp_c509_verify(&s_crypto, &got, got.public_key));
}

/* ---- Key schedule (fixed vectors from OSDP.Net PairingKeyScheduleTest) --- */

static void test_key_schedule_vectors(void)
{
    /* ss = 00..1F, TH2 = 20..3F, TH4 = 40..5F. */
    uint8_t ss[OSDP_PAIR_SS_LEN], th2[OSDP_PAIR_HASH_LEN], th4[OSDP_PAIR_HASH_LEN];
    fill_iota(ss,  sizeof(ss),  0x00);
    fill_iota(th2, sizeof(th2), 0x20);
    fill_iota(th4, sizeof(th4), 0x40);

    static const uint8_t exp_km2[32] = {
        0x94,0x15,0x1F,0x36,0xDE,0x9F,0xEB,0x1C,0xC8,0xC7,0x4D,0x7D,0x84,0x6F,
        0xBE,0x5E,0xA7,0xC5,0xCA,0x7F,0xC1,0x89,0x79,0x62,0x3D,0x94,0xC8,0x90,
        0xEC,0xEA,0xD7,0xAB,
    };
    static const uint8_t exp_km3[32] = {
        0xBA,0x43,0xE7,0x6D,0x88,0x70,0xED,0x58,0xD7,0x76,0x36,0xD3,0x97,0xD7,
        0xD7,0x22,0x51,0x3E,0x87,0x90,0x26,0xA3,0x02,0x1F,0x6F,0xDD,0x07,0xC0,
        0x23,0x38,0x48,0x29,
    };
    static const uint8_t exp_km4[32] = {
        0xE5,0x42,0xE5,0x94,0x44,0xC0,0x77,0x6C,0xE6,0x9D,0xEA,0x4F,0xAB,0xC8,
        0x62,0xF2,0xAB,0xD6,0x78,0x2A,0x3B,0x7D,0x72,0x97,0xF7,0xE5,0xF4,0x18,
        0xD5,0xDD,0xF8,0x7A,
    };
    static const uint8_t exp_scbk[32] = {
        0x8E,0xAF,0x7F,0xD9,0xDE,0x13,0x32,0xFD,0x2F,0x3F,0x18,0x37,0x8B,0x8A,
        0xFB,0x81,0xE9,0x0E,0x83,0x23,0x8B,0xA3,0x24,0xCB,0x7B,0xDC,0x3F,0x38,
        0x14,0x68,0x35,0xD4,
    };

    osdp_pair_confirm_keys_t ck;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_derive_confirm_keys(&s_crypto, ss, th2, &ck));
    TEST_ASSERT_EQUAL_MEMORY(exp_km2, ck.km2, 32);
    TEST_ASSERT_EQUAL_MEMORY(exp_km3, ck.km3, 32);
    TEST_ASSERT_EQUAL_MEMORY(exp_km4, ck.km4, 32);

    uint8_t scbk[OSDP_PAIR_SCBK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_derive_scbk(&s_crypto, ss, th4, scbk));
    TEST_ASSERT_EQUAL_MEMORY(exp_scbk, scbk, 32);
}

/* ---- Transcript hashes: match a direct concat+SHA256 ------------------- */

static void test_transcript_hashes(void)
{
    uint8_t th1[32], th2[32], th3[32], th4[32], expect[32];

    /* TH1 = SHA256(msg1_wire). */
    static uint8_t wire[128];
    fill_iota(wire, sizeof(wire), 0x01);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_th1(&s_crypto, wire, sizeof(wire), th1));
    TEST_ASSERT_EQUAL(OSDP_OK,
        s_crypto.sha256(s_crypto.user, wire, sizeof(wire), expect));
    TEST_ASSERT_EQUAL_MEMORY(expect, th1, 32);

    /* TH2 = SHA256(TH1 || core). */
    static uint8_t core[256];
    fill_iota(core, sizeof(core), 0x40);
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_th2(&s_crypto, th1, core, sizeof(core), th2));
    {
        static uint8_t cat[32 + sizeof(core)];
        (void)memcpy(cat, th1, 32);
        (void)memcpy(&cat[32], core, sizeof(core));
        TEST_ASSERT_EQUAL(OSDP_OK,
            s_crypto.sha256(s_crypto.user, cat, sizeof(cat), expect));
        TEST_ASSERT_EQUAL_MEMORY(expect, th2, 32);
    }

    /* TH3 = SHA256(TH2 || sig_p || mac_p). */
    static uint8_t sig[OSDP_PAIR_SIG_LEN];
    static uint8_t mac[OSDP_PAIR_MAC_LEN];
    fill_iota(sig, sizeof(sig), 0x11);
    fill_iota(mac, sizeof(mac), 0x22);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_th3(&s_crypto, th2, sig, mac, th3));
    {
        static uint8_t cat[32 + OSDP_PAIR_SIG_LEN + OSDP_PAIR_MAC_LEN];
        (void)memcpy(cat, th2, 32);
        (void)memcpy(&cat[32], sig, OSDP_PAIR_SIG_LEN);
        (void)memcpy(&cat[32 + OSDP_PAIR_SIG_LEN], mac, OSDP_PAIR_MAC_LEN);
        TEST_ASSERT_EQUAL(OSDP_OK,
            s_crypto.sha256(s_crypto.user, cat, sizeof(cat), expect));
        TEST_ASSERT_EQUAL_MEMORY(expect, th3, 32);
    }

    /* TH4 = SHA256(TH3 || sig_a || mac_a) — reuse sig/mac as stand-ins. */
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_th4(&s_crypto, th3, sig, mac, th4));
    {
        static uint8_t cat[32 + OSDP_PAIR_SIG_LEN + OSDP_PAIR_MAC_LEN];
        (void)memcpy(cat, th3, 32);
        (void)memcpy(&cat[32], sig, OSDP_PAIR_SIG_LEN);
        (void)memcpy(&cat[32 + OSDP_PAIR_SIG_LEN], mac, OSDP_PAIR_MAC_LEN);
        TEST_ASSERT_EQUAL(OSDP_OK,
            s_crypto.sha256(s_crypto.user, cat, sizeof(cat), expect));
        TEST_ASSERT_EQUAL_MEMORY(expect, th4, 32);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sha256_abc);
    RUN_TEST(test_hkdf_rfc5869_tc1);
    RUN_TEST(test_mldsa_demo_ca_pubkey_hash);
    RUN_TEST(test_mlkem_seed_pubkey_hash);
    RUN_TEST(test_kem_round_trip);
    RUN_TEST(test_cert_thumbprint_matches_sha256);
    RUN_TEST(test_cert_verify_self_signed);
    RUN_TEST(test_cert_verify_rejects_tamper);
    RUN_TEST(test_key_schedule_vectors);
    RUN_TEST(test_transcript_hashes);
    return UNITY_END();
}
