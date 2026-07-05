// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Phase 4/5 pure-session loopback: the real PD-responder and ACU-initiator
 * handshake state machines run against each other over the PQClean backend
 * and must derive an identical SCBK. Certificates are CA-signed; trust is a
 * CA public key. Plus untrusted-CA and tampered-message negatives. */

#include "osdp/osdp_pair.h"
#include "pair_test_crypto.h"
#include "unity.h"

#include <string.h>

/* Three crypto contexts: a CA (signs device certs), the ACU, and the PD. */
static osdp_pair_crypto_t   ca_crypto,  acu_crypto,  pd_crypto;
static osdp_pair_test_ctx_t ca_ctx,     acu_ctx,     pd_ctx;

/* Device certificates (CA-signed) presented during the handshake. */
static uint8_t acu_cert[4096]; static size_t acu_cert_len;
static uint8_t pd_cert[4096];  static size_t pd_cert_len;

/* Build a CA-signed C509 cert binding `subject_pubkey` to the identity. */
static size_t make_cert(osdp_pair_crypto_t *ca,
                        const uint8_t subject_pubkey[OSDP_MLDSA44_PK_LEN],
                        const char *mfr, const char *model, const char *serial,
                        uint8_t *out, size_t out_cap)
{
    static const uint8_t serial_no[OSDP_C509_SERIAL_LEN] = {
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    osdp_c509_cert_t cert = {
        .version            = OSDP_C509_VERSION,
        .serial             = serial_no,
        .serial_len         = sizeof(serial_no),
        .issuer             = "OSDP-DEMO-CA",
        .issuer_len         = 12,
        .not_before         = 1700000000ULL,
        .not_after          = 2000000000ULL,
        .manufacturer       = mfr,          .manufacturer_len   = strlen(mfr),
        .model              = model,        .model_len          = strlen(model),
        .subject_serial     = serial,       .subject_serial_len = strlen(serial),
        .public_key_alg     = OSDP_C509_ALG_MLDSA44,
        .public_key         = subject_pubkey,
        .public_key_len     = OSDP_MLDSA44_PK_LEN,
        .signature_alg      = OSDP_C509_ALG_MLDSA44,
        .signature          = NULL,
        .signature_len      = 0,
    };

    uint8_t tbs[OSDP_C509_TBS_MAX];
    size_t  tbs_n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode_tbs(&cert, tbs, sizeof(tbs), &tbs_n));

    static const char dom[] = OSDP_C509_SIG_DOMAIN;
    const size_t dom_len = sizeof(dom) - 1;
    uint8_t signed_msg[sizeof(dom) - 1 + OSDP_C509_TBS_MAX];
    (void)memcpy(signed_msg, dom, dom_len);
    (void)memcpy(&signed_msg[dom_len], tbs, tbs_n);

    static uint8_t sig[OSDP_MLDSA44_SIG_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        ca->ml_dsa44_sign(ca->user, signed_msg, dom_len + tbs_n, sig));
    cert.signature     = sig;
    cert.signature_len = sizeof(sig);

    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&cert, out, out_cap, &n));
    return n;
}

void setUp(void)
{
    osdp_pair_test_crypto_init(&ca_crypto,  &ca_ctx);
    osdp_pair_test_crypto_init(&acu_crypto, &acu_ctx);
    osdp_pair_test_crypto_init(&pd_crypto,  &pd_ctx);
    osdp_pair_test_seed_clear();

    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_test_gen_dsa(&ca_ctx));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_test_gen_dsa(&acu_ctx));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_test_gen_dsa(&pd_ctx));

    acu_cert_len = make_cert(&ca_crypto, acu_ctx.dsa_pk, "ACME", "ACU-1",
                             "SN-ACU", acu_cert, sizeof(acu_cert));
    pd_cert_len  = make_cert(&ca_crypto, pd_ctx.dsa_pk, "ACME", "PD-1",
                             "SN-PD", pd_cert, sizeof(pd_cert));
}
void tearDown(void) {}

/* Session state — static to keep them off the (large) stack frame. */
static osdp_pair_acu_session_t acu;
static osdp_pair_pd_session_t  pd;
static uint8_t msg1[8192], msg2[8192], msg3[4096], result[128];
static size_t  n1, n2, n3, nr;

static void setup_sessions(const uint8_t *pd_ca, const uint8_t *acu_ca)
{
    osdp_pair_local_t acu_local = { acu_cert, acu_cert_len };
    osdp_pair_local_t pd_local  = { pd_cert,  pd_cert_len };
    osdp_pair_trust_t acu_trust = { .ca_pubkey = acu_ca };
    osdp_pair_trust_t pd_trust  = { .ca_pubkey = pd_ca };

    osdp_pair_acu_init(&acu, &acu_crypto, &acu_local, &acu_trust);
    osdp_pair_pd_init(&pd, &pd_crypto, &pd_local, &pd_trust);
}

static void test_full_handshake_derives_matching_scbk(void)
{
    setup_sessions(ca_ctx.dsa_pk, ca_ctx.dsa_pk);

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
    uint8_t pd_scbk[OSDP_PAIR_SCBK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_process_msg3(&pd, msg3, n3, &ok, pd_scbk));
    TEST_ASSERT_TRUE(ok);

    /* Persistence succeeds -> success Result. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_build_result(&pd, OSDP_PAIR_STATUS_SUCCESS,
                                  result, sizeof(result), &nr));

    uint8_t acu_scbk[OSDP_PAIR_SCBK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_result(&acu, result, nr, acu_scbk));

    /* The whole point: both sides independently derive the same SCBK. */
    TEST_ASSERT_EQUAL_MEMORY(pd_scbk, acu_scbk, OSDP_PAIR_SCBK_LEN);
    TEST_ASSERT_EQUAL(OSDP_PAIR_PD_COMPLETE, pd.state);
    TEST_ASSERT_EQUAL(OSDP_PAIR_ACU_COMPLETE, acu.state);

    /* The PD authenticated the ACU's identity, and vice versa. */
    TEST_ASSERT_EQUAL_MEMORY("SN-ACU", pd.peer.serial, pd.peer.serial_len);
    TEST_ASSERT_EQUAL_MEMORY("SN-PD", acu.peer.serial, acu.peer.serial_len);
}

/* The PD trusts a different CA than signed the ACU cert -> PD rejects at
 * Message 1 with a rejection Result, and the ACU sees the failure. */
static void test_pd_rejects_untrusted_acu(void)
{
    /* PD trusts the PD-context key (not the CA) -> ACU cert won't verify. */
    setup_sessions(pd_ctx.dsa_pk, ca_ctx.dsa_pk);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_create_msg1(&acu, msg1, sizeof(msg1), &n1));

    bool is_reject = false;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_process_msg1(&pd, msg1, n1, msg2, sizeof(msg2), &n2,
                                  &is_reject));
    TEST_ASSERT_TRUE(is_reject);
    TEST_ASSERT_EQUAL(OSDP_PAIR_PD_FAILED, pd.state);

    /* The rejection Result is not a valid Message 2 for the ACU. */
    TEST_ASSERT_NOT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_msg2(&acu, msg2, n2, msg3, sizeof(msg3), &n3));
}

/* A tampered Message 3 must fail the PD's signature/MAC verification. */
static void test_pd_rejects_tampered_msg3(void)
{
    setup_sessions(ca_ctx.dsa_pk, ca_ctx.dsa_pk);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_create_msg1(&acu, msg1, sizeof(msg1), &n1));
    bool is_reject = true;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_process_msg1(&pd, msg1, n1, msg2, sizeof(msg2), &n2,
                                  &is_reject));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_msg2(&acu, msg2, n2, msg3, sizeof(msg3), &n3));

    /* Flip a byte inside Message 3's signature region. */
    msg3[10] ^= 0x01;

    bool ok = true;
    uint8_t pd_scbk[OSDP_PAIR_SCBK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_process_msg3(&pd, msg3, n3, &ok, pd_scbk));
    TEST_ASSERT_FALSE(ok);
}

/* The ACU must reject a Result whose MAC is wrong. */
static void test_acu_rejects_bad_result_mac(void)
{
    setup_sessions(ca_ctx.dsa_pk, ca_ctx.dsa_pk);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_create_msg1(&acu, msg1, sizeof(msg1), &n1));
    bool is_reject = true;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_process_msg1(&pd, msg1, n1, msg2, sizeof(msg2), &n2,
                                  &is_reject));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_msg2(&acu, msg2, n2, msg3, sizeof(msg3), &n3));
    bool ok = false;
    uint8_t pd_scbk[OSDP_PAIR_SCBK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_process_msg3(&pd, msg3, n3, &ok, pd_scbk));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_pd_build_result(&pd, OSDP_PAIR_STATUS_SUCCESS,
                                  result, sizeof(result), &nr));

    /* Corrupt the last byte (inside mac_R). */
    result[nr - 1] ^= 0x01;

    uint8_t acu_scbk[OSDP_PAIR_SCBK_LEN];
    TEST_ASSERT_NOT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_result(&acu, result, nr, acu_scbk));
    TEST_ASSERT_EQUAL(OSDP_PAIR_ACU_FAILED, acu.state);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_full_handshake_derives_matching_scbk);
    RUN_TEST(test_pd_rejects_untrusted_acu);
    RUN_TEST(test_pd_rejects_tampered_msg3);
    RUN_TEST(test_acu_rejects_bad_result_mac);
    return UNITY_END();
}
