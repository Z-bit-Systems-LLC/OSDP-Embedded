// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Contract tests for the pairing half of ports/wolfcrypt, with the PQClean
 * port as the reference implementation:
 *
 *   - the docs/pairing-design.md §9 vectors (SHA-256 / HKDF / key schedule,
 *     demo-CA and ML-KEM fixed-seed public-key hashes);
 *   - byte-for-byte agreement with PQClean when both draw the same random
 *     bytes: ML-KEM keys, ciphertext and shared secret, ML-DSA keys and
 *     signatures;
 *   - loading the ML-DSA-44 key tools/osdp-pair-provision writes (PQClean
 *     format) and signing with it in a way PQClean verifies;
 *   - complete pairing handshakes with wolfCrypt on one side and PQClean on
 *     the other, in both directions;
 *   - the entropy-source contract and argument refusals. */

#include "osdp/osdp_pair.h"
#include "osdp_pair_pqclean.h"
#include "osdp_pair_wolfcrypt.h"
#include "unity.h"

#include <string.h>

/* ---- A replayable entropy source for the wolfCrypt side ------------------
 *
 * Serves queued bytes first, then a splitmix64 stream. The queue is how a
 * test hands wolfCrypt the same bytes it pushes into PQClean's seed queue;
 * the stream keeps long handshakes (nonces) supplied. */

static uint8_t  q_buf[256];
static size_t   q_len, q_pos;
static uint64_t q_prng = 0x5EED5EED5EED5EEDULL;
static bool     q_fail;

static void q_push(const uint8_t *bytes, size_t len)
{
    TEST_ASSERT_TRUE(len <= sizeof(q_buf));
    memcpy(q_buf, bytes, len);
    q_len = len;
    q_pos = 0;
}

static osdp_status_t q_rand(void *user, uint8_t *out, size_t len)
{
    (void)user;
    if (q_fail) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    size_t i = 0;
    while (i < len && q_pos < q_len) {
        out[i++] = q_buf[q_pos++];
    }
    for (; i < len; i++) {
        q_prng += 0x9E3779B97F4A7C15ULL;
        uint64_t z = q_prng;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        out[i] = (uint8_t)(z ^ (z >> 31));
    }
    return OSDP_OK;
}

static void fill_iota(uint8_t *p, size_t n, uint8_t start)
{
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(start + i);
    }
}

/* Contexts are large; keep them static. */
static osdp_pair_crypto_t      wc_crypto, wc2_crypto;
static osdp_pair_wolfcrypt_t   wc_ctx, wc2_ctx;
static osdp_pair_crypto_t      pq_crypto, pq2_crypto, ca_crypto;
static osdp_pair_pqclean_ctx_t pq_ctx, pq2_ctx, ca_ctx;

void setUp(void)
{
    q_len = q_pos = 0;
    q_fail = false;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_init(&wc_ctx, &wc_crypto));
    osdp_pair_wolfcrypt_set_rand(&wc_ctx, q_rand, NULL);
    osdp_pair_pqclean_crypto_init(&pq_crypto, &pq_ctx);
    osdp_pair_pqclean_seed_clear();
}

void tearDown(void)
{
    osdp_pair_wolfcrypt_free(&wc_ctx);
    osdp_pair_wolfcrypt_free(&wc2_ctx);
}

/* ---- Standard vectors ---------------------------------------------------- */

static void test_sha256_abc(void)
{
    static const uint8_t expect[32] = {
        0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,0x41,0x41,0x40,0xDE,0x5D,0xAE,
        0x22,0x23,0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,0xB4,0x10,0xFF,0x61,
        0xF2,0x00,0x15,0xAD,
    };
    uint8_t out[32];
    TEST_ASSERT_EQUAL(OSDP_OK,
        wc_crypto.sha256(wc_crypto.user, (const uint8_t *)"abc", 3, out));
    TEST_ASSERT_EQUAL_MEMORY(expect, out, 32);
}

/* RFC 4231 Test Case 2: a key shorter than the block. */
static void test_hmac_rfc4231_tc2(void)
{
    static const uint8_t expect[32] = {
        0x5B,0xDC,0xC1,0x46,0xBF,0x60,0x75,0x4E,0x6A,0x04,0x24,0x26,0x08,0x95,
        0x75,0xC7,0x5A,0x00,0x3F,0x08,0x9D,0x27,0x39,0x83,0x9D,0xEC,0x58,0xB9,
        0x64,0xEC,0x38,0x43,
    };
    static const char data[] = "what do ya want for nothing?";
    uint8_t out[32];
    TEST_ASSERT_EQUAL(OSDP_OK,
        wc_crypto.hmac_sha256(wc_crypto.user, (const uint8_t *)"Jefe", 4,
                              (const uint8_t *)data, sizeof(data) - 1, out));
    TEST_ASSERT_EQUAL_MEMORY(expect, out, 32);
}

/* RFC 5869 Test Case 1 (SHA-256). */
static void test_hkdf_rfc5869_tc1(void)
{
    uint8_t ikm[22];
    memset(ikm, 0x0B, sizeof(ikm));
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
        wc_crypto.hkdf_sha256(wc_crypto.user, salt, sizeof(salt),
                              ikm, sizeof(ikm), info, sizeof(info),
                              out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(okm, out, sizeof(out));
}

/* RFC 5869 Test Case 3: no salt and no info — both absent forms. */
static void test_hkdf_rfc5869_tc3_no_salt(void)
{
    uint8_t ikm[22];
    memset(ikm, 0x0B, sizeof(ikm));
    static const uint8_t okm[42] = {
        0x8D,0xA4,0xE7,0x75,0xA5,0x63,0xC1,0x8F,0x71,0x5F,0x80,0x2A,0x06,0x3C,
        0x5A,0x31,0xB8,0xA1,0x1F,0x5C,0x5E,0xE1,0x87,0x9E,0xC3,0x45,0x4E,0x5F,
        0x3C,0x73,0x8D,0x2D,0x9D,0x20,0x13,0x95,0xFA,0xA4,0xB6,0x1A,0x96,0xC8,
    };
    uint8_t out[42];
    TEST_ASSERT_EQUAL(OSDP_OK,
        wc_crypto.hkdf_sha256(wc_crypto.user, NULL, 0, ikm, sizeof(ikm),
                              NULL, 0, out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(okm, out, sizeof(out));

    static const uint8_t empty[1] = { 0 };
    TEST_ASSERT_EQUAL(OSDP_OK,
        wc_crypto.hkdf_sha256(wc_crypto.user, empty, 0, ikm, sizeof(ikm),
                              empty, 0, out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(okm, out, sizeof(out));
}

/* §9 key schedule (fixed ss / TH2 / TH4), through the library. */
static void test_key_schedule_vectors(void)
{
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
        osdp_pair_derive_confirm_keys(&wc_crypto, ss, th2, &ck));
    TEST_ASSERT_EQUAL_MEMORY(exp_km2, ck.km2, 32);
    TEST_ASSERT_EQUAL_MEMORY(exp_km3, ck.km3, 32);
    TEST_ASSERT_EQUAL_MEMORY(exp_km4, ck.km4, 32);

    uint8_t scbk[OSDP_PAIR_SCBK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_derive_scbk(&wc_crypto, ss, th4, scbk));
    TEST_ASSERT_EQUAL_MEMORY(exp_scbk, scbk, 32);
}

/* §9: demo CA = ML-DSA-44 from seed 0x40..0x5F; SHA-256 of its public key is
 * OSDP.Net's published thumbprint. */
static void test_demo_ca_pubkey_hash(void)
{
    uint8_t seed[32], pk[OSDP_MLDSA44_PK_LEN], hash[32];
    fill_iota(seed, sizeof(seed), 0x40);
    q_push(seed, sizeof(seed));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_gen_dsa(&wc_ctx, pk));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.sha256(wc_crypto.user, pk, sizeof(pk), hash));

    static const uint8_t expect[32] = {
        0x6C,0x1C,0x65,0x07,0x19,0x79,0x22,0x5A,0x13,0x9B,0x3E,0xC8,0x46,0x88,
        0xE2,0x68,0x8E,0xC3,0x0F,0xAB,0xE8,0xCC,0x51,0x0C,0xB6,0x88,0xBC,0x43,
        0x5F,0x2D,0x3C,0xB9,
    };
    TEST_ASSERT_EQUAL_MEMORY(expect, hash, 32);
}

/* §9: ML-KEM-768 from seed 0x00..0x3F; SHA-256 of the encapsulation key. */
static void test_mlkem_seed_pubkey_hash(void)
{
    uint8_t seed[64], ek[OSDP_MLKEM768_EK_LEN], hash[32];
    fill_iota(seed, sizeof(seed), 0x00);
    q_push(seed, sizeof(seed));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.ml_kem768_keygen(wc_crypto.user, ek));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.sha256(wc_crypto.user, ek, sizeof(ek), hash));

    static const uint8_t expect[32] = {
        0x0B,0x79,0x34,0xC8,0x31,0x25,0xC7,0x88,0x99,0x5E,0x2B,0xA6,0xBD,0x76,
        0x1E,0x33,0x04,0x6B,0x3E,0x40,0x57,0x1B,0xE5,0x3E,0x02,0x33,0x09,0xA2,
        0x9F,0x39,0x8C,0xC9,
    };
    TEST_ASSERT_EQUAL_MEMORY(expect, hash, 32);
}

/* ---- Byte-for-byte agreement with PQClean -------------------------------- */

static void test_mlkem_matches_pqclean(void)
{
    static uint8_t ek_wc[OSDP_MLKEM768_EK_LEN], ek_pq[OSDP_MLKEM768_EK_LEN];
    static uint8_t ct_wc[OSDP_MLKEM768_CT_LEN], ct_pq[OSDP_MLKEM768_CT_LEN];
    uint8_t ss_wc[32], ss_pq[32], ss_dec_wc[32], ss_dec_pq[32];
    uint8_t seed[64], m[32];

    fill_iota(seed, sizeof(seed), 0x91);
    fill_iota(m, sizeof(m), 0x17);

    /* Keygen from the same 64 bytes (d || z). */
    q_push(seed, sizeof(seed));
    osdp_pair_pqclean_seed_push(seed, sizeof(seed));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.ml_kem768_keygen(wc_crypto.user, ek_wc));
    TEST_ASSERT_EQUAL(OSDP_OK, pq_crypto.ml_kem768_keygen(pq_crypto.user, ek_pq));
    TEST_ASSERT_EQUAL_MEMORY(ek_pq, ek_wc, sizeof(ek_wc));

    /* Encaps to that key with the same 32-byte m, each in a second context
     * (a context's encaps would replace its own stashed decaps key). */
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_init(&wc2_ctx, &wc2_crypto));
    osdp_pair_wolfcrypt_set_rand(&wc2_ctx, q_rand, NULL);
    osdp_pair_pqclean_crypto_init(&pq2_crypto, &pq2_ctx);
    q_push(m, sizeof(m));
    osdp_pair_pqclean_seed_push(m, sizeof(m));
    TEST_ASSERT_EQUAL(OSDP_OK,
        wc2_crypto.ml_kem768_encaps(wc2_crypto.user, ek_wc, ct_wc, ss_wc));
    TEST_ASSERT_EQUAL(OSDP_OK,
        pq2_crypto.ml_kem768_encaps(pq2_crypto.user, ek_pq, ct_pq, ss_pq));
    TEST_ASSERT_EQUAL_MEMORY(ct_pq, ct_wc, sizeof(ct_wc));
    TEST_ASSERT_EQUAL_MEMORY(ss_pq, ss_wc, sizeof(ss_wc));

    /* Each side decapsulates the OTHER library's ciphertext. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        wc_crypto.ml_kem768_decaps(wc_crypto.user, ct_pq, ss_dec_wc));
    TEST_ASSERT_EQUAL(OSDP_OK,
        pq_crypto.ml_kem768_decaps(pq_crypto.user, ct_wc, ss_dec_pq));
    TEST_ASSERT_EQUAL_MEMORY(ss_pq, ss_dec_wc, 32);
    TEST_ASSERT_EQUAL_MEMORY(ss_wc, ss_dec_pq, 32);
}

static void test_mldsa_keys_and_signatures_match_pqclean(void)
{
    static uint8_t pk_wc[OSDP_MLDSA44_PK_LEN];
    static uint8_t sk_wc[OSDP_PAIR_WOLFCRYPT_DSA_SK_LEN];
    static uint8_t sig_wc[OSDP_MLDSA44_SIG_LEN], sig_pq[OSDP_MLDSA44_SIG_LEN];
    static const char msg[] = "OSDP-PAIR-v1-msg2 transcript stand-in";
    uint8_t seed[32], rnd[32];

    /* Keygen from the same 32-byte seed. */
    fill_iota(seed, sizeof(seed), 0x30);
    q_push(seed, sizeof(seed));
    osdp_pair_pqclean_seed_push(seed, sizeof(seed));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_gen_dsa(&wc_ctx, pk_wc));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&pq_ctx));
    TEST_ASSERT_EQUAL_MEMORY(pq_ctx.dsa_pk, pk_wc, sizeof(pk_wc));

    /* The private key encodings agree too — the import test below relies on
     * the same fact from the other direction. */
    word32 sk_len = sizeof(sk_wc);
    TEST_ASSERT_EQUAL(0, wc_dilithium_export_private(&wc_ctx.dsa, sk_wc, &sk_len));
    TEST_ASSERT_EQUAL(OSDP_PAIR_WOLFCRYPT_DSA_SK_LEN, sk_len);
    TEST_ASSERT_EQUAL_MEMORY(pq_ctx.dsa_sk, sk_wc, sizeof(sk_wc));

    /* Hedged signing with the same 32-byte rnd gives the same signature. */
    fill_iota(rnd, sizeof(rnd), 0xC0);
    q_push(rnd, sizeof(rnd));
    osdp_pair_pqclean_seed_push(rnd, sizeof(rnd));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.ml_dsa44_sign(wc_crypto.user,
        (const uint8_t *)msg, sizeof(msg) - 1, sig_wc));
    TEST_ASSERT_EQUAL(OSDP_OK, pq_crypto.ml_dsa44_sign(pq_crypto.user,
        (const uint8_t *)msg, sizeof(msg) - 1, sig_pq));
    TEST_ASSERT_EQUAL_MEMORY(sig_pq, sig_wc, sizeof(sig_wc));
}

/* ---- The provisioned credential ------------------------------------------
 *
 * tools/osdp-pair-provision derives the device key with PQClean from the
 * seed device_seed .. device_seed+31 (default 0x80) and writes the 1312-byte
 * public key and 2560-byte private key it produced. Reproduce that exactly,
 * load it into wolfCrypt, and check signatures cross both ways. */
static void test_loads_provisioned_pqclean_key(void)
{
    static uint8_t sig[OSDP_MLDSA44_SIG_LEN];
    static const char msg[] = "signed by a provisioned key";
    uint8_t dev_seed[32];

    fill_iota(dev_seed, sizeof(dev_seed), 0x80);
    osdp_pair_pqclean_seed_push(dev_seed, sizeof(dev_seed));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&pq_ctx));

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_wolfcrypt_set_dsa(&wc_ctx, pq_ctx.dsa_pk,
                                    pq_ctx.dsa_sk, sizeof(pq_ctx.dsa_sk)));

    /* wolfCrypt signs with the imported key; PQClean verifies. */
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.ml_dsa44_sign(wc_crypto.user,
        (const uint8_t *)msg, sizeof(msg) - 1, sig));
    TEST_ASSERT_EQUAL(OSDP_OK, pq_crypto.ml_dsa44_verify(pq_crypto.user,
        pq_ctx.dsa_pk, (const uint8_t *)msg, sizeof(msg) - 1, sig));

    /* PQClean signs; wolfCrypt verifies. */
    TEST_ASSERT_EQUAL(OSDP_OK, pq_crypto.ml_dsa44_sign(pq_crypto.user,
        (const uint8_t *)msg, sizeof(msg) - 1, sig));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.ml_dsa44_verify(wc_crypto.user,
        pq_ctx.dsa_pk, (const uint8_t *)msg, sizeof(msg) - 1, sig));
}

static void test_verify_rejects_tampering(void)
{
    static uint8_t sig[OSDP_MLDSA44_SIG_LEN];
    static uint8_t msg[64];
    uint8_t pk[OSDP_MLDSA44_PK_LEN];

    fill_iota(msg, sizeof(msg), 0x01);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_gen_dsa(&wc_ctx, pk));
    TEST_ASSERT_EQUAL(OSDP_OK,
        wc_crypto.ml_dsa44_sign(wc_crypto.user, msg, sizeof(msg), sig));
    TEST_ASSERT_EQUAL(OSDP_OK,
        wc_crypto.ml_dsa44_verify(wc_crypto.user, pk, msg, sizeof(msg), sig));

    sig[100] ^= 0x01;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CRC,
        wc_crypto.ml_dsa44_verify(wc_crypto.user, pk, msg, sizeof(msg), sig));
    sig[100] ^= 0x01;

    msg[0] ^= 0x01;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CRC,
        wc_crypto.ml_dsa44_verify(wc_crypto.user, pk, msg, sizeof(msg), sig));
    msg[0] ^= 0x01;

    pk[5] ^= 0x01;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_CRC,
        wc_crypto.ml_dsa44_verify(wc_crypto.user, pk, msg, sizeof(msg), sig));
    pk[5] ^= 0x01;

    /* And the scratch verify key recovers for the next, valid, call. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        wc_crypto.ml_dsa44_verify(wc_crypto.user, pk, msg, sizeof(msg), sig));
}

/* ---- Cross-implementation handshakes ------------------------------------- */

static uint8_t acu_cert[4096], pd_cert[4096];
static size_t  acu_cert_len, pd_cert_len;
static osdp_pair_acu_session_t acu;
static osdp_pair_pd_session_t  pd;
static uint8_t msg1[OSDP_PAIR_MSG_MAX], msg2[OSDP_PAIR_MSG_MAX];
static uint8_t msg3[OSDP_PAIR_MSG_MAX], result[128];

/* A CA-signed C509 binding `pk` to an identity, signed by the PQClean CA. */
static size_t make_cert(const uint8_t pk[OSDP_MLDSA44_PK_LEN],
                        const char *serial, uint8_t *out, size_t cap)
{
    static const uint8_t serial_no[OSDP_C509_SERIAL_LEN] = {
        8, 7, 6, 5, 4, 3, 2, 1,
    };
    osdp_c509_cert_t cert = {
        .version            = OSDP_C509_VERSION,
        .serial             = serial_no,
        .serial_len         = sizeof(serial_no),
        .issuer             = "OSDP-DEMO-CA",
        .issuer_len         = 12,
        .not_before         = 1700000000ULL,
        .not_after          = 2000000000ULL,
        .manufacturer       = "Z-bit",        .manufacturer_len   = 5,
        .model              = "WC",           .model_len          = 2,
        .subject_serial     = serial,         .subject_serial_len = strlen(serial),
        .public_key_alg     = OSDP_C509_ALG_MLDSA44,
        .public_key         = pk,
        .public_key_len     = OSDP_MLDSA44_PK_LEN,
        .signature_alg      = OSDP_C509_ALG_MLDSA44,
    };

    static uint8_t tbs[OSDP_C509_TBS_MAX];
    size_t tbs_n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode_tbs(&cert, tbs, sizeof(tbs), &tbs_n));

    static const char dom[] = OSDP_C509_SIG_DOMAIN;
    static uint8_t signed_msg[sizeof(dom) - 1 + OSDP_C509_TBS_MAX];
    memcpy(signed_msg, dom, sizeof(dom) - 1);
    memcpy(&signed_msg[sizeof(dom) - 1], tbs, tbs_n);

    static uint8_t sig[OSDP_MLDSA44_SIG_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK, ca_crypto.ml_dsa44_sign(ca_crypto.user,
        signed_msg, sizeof(dom) - 1 + tbs_n, sig));
    cert.signature     = sig;
    cert.signature_len = sizeof(sig);

    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&cert, out, cap, &n));
    return n;
}

/* Run a full exchange; both sides must derive the same SCBK. */
static void run_handshake(osdp_pair_crypto_t *acu_c, const uint8_t *acu_pk,
                          osdp_pair_crypto_t *pd_c,  const uint8_t *pd_pk)
{
    size_t n1 = 0, n2 = 0, n3 = 0, nr = 0;

    acu_cert_len = make_cert(acu_pk, "SN-ACU", acu_cert, sizeof(acu_cert));
    pd_cert_len  = make_cert(pd_pk,  "SN-PD",  pd_cert,  sizeof(pd_cert));

    osdp_pair_local_t acu_local = { acu_cert, acu_cert_len };
    osdp_pair_local_t pd_local  = { pd_cert,  pd_cert_len };
    osdp_pair_trust_t trust     = { .ca_pubkey = ca_ctx.dsa_pk };
    osdp_pair_acu_init(&acu, acu_c, &acu_local, &trust);
    osdp_pair_pd_init(&pd, pd_c, &pd_local, &trust);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_create_msg1(&acu, msg1, sizeof(msg1), &n1));
    bool is_reject = true;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_process_msg1(&pd, msg1, n1, msg2, sizeof(msg2), &n2,
                                  &is_reject));
    TEST_ASSERT_FALSE(is_reject);
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_msg2(&acu, msg2, n2, msg3, sizeof(msg3), &n3));

    bool ok = false;
    uint8_t pd_scbk[OSDP_PAIR_SCBK_LEN], acu_scbk[OSDP_PAIR_SCBK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_process_msg3(&pd, msg3, n3, &ok, pd_scbk));
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_build_result(&pd, OSDP_PAIR_STATUS_SUCCESS,
                                  result, sizeof(result), &nr));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_result(&acu, result, nr, acu_scbk));

    TEST_ASSERT_EQUAL_MEMORY(pd_scbk, acu_scbk, OSDP_PAIR_SCBK_LEN);
    TEST_ASSERT_EQUAL(OSDP_PAIR_PD_COMPLETE, pd.state);
    TEST_ASSERT_EQUAL(OSDP_PAIR_ACU_COMPLETE, acu.state);
    TEST_ASSERT_EQUAL_MEMORY("SN-ACU", pd.peer.serial, pd.peer.serial_len);
    TEST_ASSERT_EQUAL_MEMORY("SN-PD", acu.peer.serial, acu.peer.serial_len);
}

static void setup_ca(void)
{
    uint8_t seed[32];
    osdp_pair_pqclean_crypto_init(&ca_crypto, &ca_ctx);
    fill_iota(seed, sizeof(seed), 0x40);   /* the demo CA */
    osdp_pair_pqclean_seed_push(seed, sizeof(seed));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&ca_ctx));
}

/* The OpenReader shape: wolfCrypt PD with a provisioned key, PQClean ACU. */
static void test_handshake_wolfcrypt_pd_pqclean_acu(void)
{
    uint8_t dev_seed[32];
    setup_ca();

    fill_iota(dev_seed, sizeof(dev_seed), 0x80);
    osdp_pair_pqclean_seed_push(dev_seed, sizeof(dev_seed));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&pq2_ctx));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_wolfcrypt_set_dsa(&wc_ctx, pq2_ctx.dsa_pk,
                                    pq2_ctx.dsa_sk, sizeof(pq2_ctx.dsa_sk)));

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&pq_ctx));
    run_handshake(&pq_crypto, pq_ctx.dsa_pk, &wc_crypto, pq2_ctx.dsa_pk);
}

static void test_handshake_pqclean_pd_wolfcrypt_acu(void)
{
    static uint8_t acu_pk[OSDP_MLDSA44_PK_LEN];
    setup_ca();

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_gen_dsa(&wc_ctx, acu_pk));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&pq_ctx));
    run_handshake(&wc_crypto, acu_pk, &pq_crypto, pq_ctx.dsa_pk);
}

/* Both sides wolfCrypt, both on the real DRBG — the production setup. */
static void test_handshake_wolfcrypt_both_drbg(void)
{
    static uint8_t acu_pk[OSDP_MLDSA44_PK_LEN], pd_pk[OSDP_MLDSA44_PK_LEN];
    setup_ca();

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_rng(&wc_ctx));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_init(&wc2_ctx, &wc2_crypto));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_rng(&wc2_ctx));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_gen_dsa(&wc_ctx, acu_pk));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_gen_dsa(&wc2_ctx, pd_pk));
    run_handshake(&wc_crypto, acu_pk, &wc2_crypto, pd_pk);
}

/* ---- Entropy contract and refusals --------------------------------------- */

static void test_no_entropy_source_fails_loudly(void)
{
    static uint8_t ek[OSDP_MLKEM768_EK_LEN], sig[OSDP_MLDSA44_SIG_LEN];
    uint8_t pk[OSDP_MLDSA44_PK_LEN], buf[16];

    osdp_pair_wolfcrypt_set_rand(&wc_ctx, NULL, NULL);
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
        wc_crypto.rand_bytes(wc_crypto.user, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
        wc_crypto.ml_kem768_keygen(wc_crypto.user, ek));
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
        osdp_pair_wolfcrypt_gen_dsa(&wc_ctx, pk));

    /* A loaded key is not enough: hedged signing needs fresh bytes too. */
    uint8_t seed[32];
    fill_iota(seed, sizeof(seed), 0x80);
    osdp_pair_pqclean_seed_push(seed, sizeof(seed));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&pq_ctx));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_wolfcrypt_set_dsa(&wc_ctx, pq_ctx.dsa_pk,
                                    pq_ctx.dsa_sk, sizeof(pq_ctx.dsa_sk)));
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
        wc_crypto.ml_dsa44_sign(wc_crypto.user, buf, sizeof(buf), sig));

    /* A source that fails is a failure, not a zero-filled success. */
    osdp_pair_wolfcrypt_set_rand(&wc_ctx, q_rand, NULL);
    q_fail = true;
    memset(buf, 0xA5, sizeof(buf));
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
        wc_crypto.rand_bytes(wc_crypto.user, buf, sizeof(buf)));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL(OSDP_ERR_NOT_SUPPORTED,
        wc_crypto.ml_dsa44_sign(wc_crypto.user, buf, sizeof(buf), sig));
}

static void test_drbg_and_source_precedence(void)
{
    uint8_t a[32], b[32], q[32];

    osdp_pair_wolfcrypt_set_rand(&wc_ctx, NULL, NULL);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_wolfcrypt_rng(&wc_ctx));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.rand_bytes(wc_crypto.user, a, sizeof(a)));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.rand_bytes(wc_crypto.user, b, sizeof(b)));
    TEST_ASSERT_TRUE(memcmp(a, b, sizeof(a)) != 0);

    /* A caller source takes precedence over the seeded DRBG... */
    fill_iota(q, sizeof(q), 0x55);
    q_push(q, sizeof(q));
    osdp_pair_wolfcrypt_set_rand(&wc_ctx, q_rand, NULL);
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.rand_bytes(wc_crypto.user, a, sizeof(a)));
    TEST_ASSERT_EQUAL_MEMORY(q, a, sizeof(a));

    /* ...and removing it falls back to the DRBG, not to nothing. */
    osdp_pair_wolfcrypt_set_rand(&wc_ctx, NULL, NULL);
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.rand_bytes(wc_crypto.user, a, sizeof(a)));
}

static void test_refusals(void)
{
    static uint8_t ek[OSDP_MLKEM768_EK_LEN], ct[OSDP_MLKEM768_CT_LEN];
    static uint8_t sig[OSDP_MLDSA44_SIG_LEN];
    uint8_t pk[OSDP_MLDSA44_PK_LEN] = { 0 }, ss[32], sk[16] = { 0 };

    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pair_wolfcrypt_init(NULL, &wc2_crypto));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG, osdp_pair_wolfcrypt_init(&wc2_ctx, NULL));

    /* Wrong private-key length; and signing with no key loaded. */
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_pair_wolfcrypt_set_dsa(&wc_ctx, pk, sk, sizeof(sk)));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        wc_crypto.ml_dsa44_sign(wc_crypto.user, sk, sizeof(sk), sig));

    /* Decaps needs a stashed key; an encaps in between discards it. */
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        wc_crypto.ml_kem768_decaps(wc_crypto.user, ct, ss));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.ml_kem768_keygen(wc_crypto.user, ek));
    TEST_ASSERT_EQUAL(OSDP_OK, wc_crypto.ml_kem768_encaps(wc_crypto.user, ek, ct, ss));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        wc_crypto.ml_kem768_decaps(wc_crypto.user, ct, ss));

    /* After free the callbacks refuse. */
    osdp_pair_wolfcrypt_free(&wc_ctx);
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        wc_crypto.rand_bytes(wc_crypto.user, ss, sizeof(ss)));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        wc_crypto.ml_kem768_keygen(wc_crypto.user, ek));
    osdp_pair_wolfcrypt_free(&wc_ctx);   /* twice is fine */
    osdp_pair_wolfcrypt_free(NULL);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sha256_abc);
    RUN_TEST(test_hmac_rfc4231_tc2);
    RUN_TEST(test_hkdf_rfc5869_tc1);
    RUN_TEST(test_hkdf_rfc5869_tc3_no_salt);
    RUN_TEST(test_key_schedule_vectors);
    RUN_TEST(test_demo_ca_pubkey_hash);
    RUN_TEST(test_mlkem_seed_pubkey_hash);
    RUN_TEST(test_mlkem_matches_pqclean);
    RUN_TEST(test_mldsa_keys_and_signatures_match_pqclean);
    RUN_TEST(test_loads_provisioned_pqclean_key);
    RUN_TEST(test_verify_rejects_tampering);
    RUN_TEST(test_handshake_wolfcrypt_pd_pqclean_acu);
    RUN_TEST(test_handshake_pqclean_pd_wolfcrypt_acu);
    RUN_TEST(test_handshake_wolfcrypt_both_drbg);
    RUN_TEST(test_no_entropy_source_fails_loudly);
    RUN_TEST(test_drbg_and_source_precedence);
    RUN_TEST(test_refusals);
    return UNITY_END();
}
