// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Cross-implementation vector: a C509 certificate that OSDP.Net actually
 * emitted, decoded and verified by our code against the demo CA we regenerate
 * from the published seed.
 *
 * Everything else in the pairing suite round-trips our own encoder through our
 * own decoder, which cannot catch the failure that matters most here — the two
 * implementations agreeing on the encoding but not on what is signed, or on a
 * field's representation. This test is the only one that reads bytes we did
 * not write. */

#include "osdp/osdp_pair.h"
#include "osdp_pair_pqclean.h"
#include "vectors/osdp_net_acu_cert.h"
#include "unity.h"

#include <string.h>

static osdp_pair_pqclean_ctx_t s_ca_ctx;
static osdp_pair_crypto_t      s_crypto;

/* SHA-256 of the demo CA's ML-DSA-44 public key, as published by OSDP.Net.
 * Confirmed 2026-08-10 to equal CertificateAuthority.Demo().PublicKey. */
static const uint8_t k_demo_ca_pubkey_sha256[32] = {
    0x6C,0x1C,0x65,0x07,0x19,0x79,0x22,0x5A,0x13,0x9B,0x3E,0xC8,0x46,0x88,
    0xE2,0x68,0x8E,0xC3,0x0F,0xAB,0xE8,0xCC,0x51,0x0C,0xB6,0x88,0xBC,0x43,
    0x5F,0x2D,0x3C,0xB9,
};

void setUp(void)
{
    uint8_t seed[32];
    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (uint8_t)(0x40U + i);
    }
    osdp_pair_pqclean_crypto_init(&s_crypto, &s_ca_ctx);
    osdp_pair_pqclean_seed_clear();
    osdp_pair_pqclean_seed_push(seed, sizeof(seed));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&s_ca_ctx));
}
void tearDown(void) {}

/* Sanity: the CA we regenerate is the one that signed the vector. Without
 * this, a verify failure below would be ambiguous between "we cannot read
 * their certificate" and "we rebuilt the wrong CA". */
static void test_regenerated_demo_ca_matches_the_published_key(void)
{
    uint8_t hash[32];
    TEST_ASSERT_EQUAL(OSDP_OK,
        s_crypto.sha256(s_crypto.user, s_ca_ctx.dsa_pk,
                        OSDP_MLDSA44_PK_LEN, hash));
    TEST_ASSERT_EQUAL_MEMORY(k_demo_ca_pubkey_sha256, hash, sizeof(hash));
}

/* Their encoding must be readable by our decoder. */
static void test_osdp_net_certificate_decodes(void)
{
    osdp_c509_cert_t cert;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_c509_decode(k_osdp_net_acu_cert, sizeof(k_osdp_net_acu_cert),
                         &cert));

    TEST_ASSERT_EQUAL_size_t(OSDP_MLDSA44_PK_LEN, cert.public_key_len);
    TEST_ASSERT_EQUAL_size_t(OSDP_MLDSA44_SIG_LEN, cert.signature_len);
    TEST_ASSERT_EQUAL_MEMORY("OSDP-DEMO-CA", cert.issuer, 12);
    TEST_ASSERT_EQUAL_MEMORY("Z-bit Systems", cert.manufacturer, 13);
    TEST_ASSERT_EQUAL_MEMORY("ACU-Benchmark", cert.model, 13);
    TEST_ASSERT_EQUAL_MEMORY("BENCH-0001", cert.subject_serial, 10);
}

/* And our verifier must accept it under the CA that signed it. This is the
 * assertion that stands between us and a pairing exchange that gets all the
 * way to the credential check and then refuses every real ACU. */
static void test_osdp_net_certificate_verifies_under_the_demo_ca(void)
{
    osdp_c509_cert_t cert;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_c509_decode(k_osdp_net_acu_cert, sizeof(k_osdp_net_acu_cert),
                         &cert));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_c509_verify(&s_crypto, &cert, s_ca_ctx.dsa_pk));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_regenerated_demo_ca_matches_the_published_key);
    RUN_TEST(test_osdp_net_certificate_decodes);
    RUN_TEST(test_osdp_net_certificate_verifies_under_the_demo_ca);
    return UNITY_END();
}
