// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* PD-side pairing driver integration test. A real osdp_pd with the pairing
 * driver attached runs on an in-memory wire; an ACU is simulated with the
 * pure ACU session plus manual OSDP framing. Exercises fragment reassembly,
 * Message 2 delivery over POLLs, the inline Result, and the post-Result
 * SC2 handoff (SCBK applied to pd->sc2). */

#include "osdp/osdp_pd_pair.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"
#include "pair_test_crypto.h"
#include "unity.h"

#include <string.h>

#define PD_ADDR 0x05u

/* ---- In-memory wire ----------------------------------------------------- */

typedef struct wire { uint8_t buf[65536]; size_t len; size_t rpos; } wire_t;
static wire_t a2p; /* ACU -> PD */
static wire_t p2a; /* PD -> ACU */
static uint32_t g_clock;

static int pd_read(void *u, uint8_t *buf, size_t cap)
{
    (void)u;
    size_t avail = a2p.len - a2p.rpos;
    size_t n = (avail < cap) ? avail : cap;
    if (n > 0) { (void)memcpy(buf, &a2p.buf[a2p.rpos], n); a2p.rpos += n; }
    return (int)n;
}
static int pd_write(void *u, const uint8_t *buf, size_t len)
{
    (void)u;
    (void)memcpy(&p2a.buf[p2a.len], buf, len);
    p2a.len += len;
    return (int)len;
}
static uint32_t pd_now(void *u) { (void)u; return g_clock; }

/* ---- Crypto contexts, certs (CA-signed, mutual) ------------------------- */

static osdp_pair_crypto_t   ca_crypto, acu_crypto, pd_crypto;
static osdp_pair_test_ctx_t ca_ctx, acu_ctx, pd_ctx;
static uint8_t acu_cert[4096]; static size_t acu_cert_len;
static uint8_t pd_cert[4096];  static size_t pd_cert_len;

static size_t make_cert(osdp_pair_crypto_t *ca,
                        const uint8_t subject_pubkey[OSDP_MLDSA44_PK_LEN],
                        const char *mfr, const char *model, const char *serial,
                        uint8_t *out, size_t out_cap)
{
    static const uint8_t serial_no[OSDP_C509_SERIAL_LEN] = {1,2,3,4,5,6,7,8};
    osdp_c509_cert_t cert = {
        .version = OSDP_C509_VERSION, .serial = serial_no,
        .serial_len = sizeof(serial_no), .issuer = "OSDP-DEMO-CA",
        .issuer_len = 12, .not_before = 1700000000ULL, .not_after = 2000000000ULL,
        .manufacturer = mfr, .manufacturer_len = strlen(mfr),
        .model = model, .model_len = strlen(model),
        .subject_serial = serial, .subject_serial_len = strlen(serial),
        .public_key_alg = OSDP_C509_ALG_MLDSA44, .public_key = subject_pubkey,
        .public_key_len = OSDP_MLDSA44_PK_LEN, .signature_alg = OSDP_C509_ALG_MLDSA44,
        .signature = NULL, .signature_len = 0,
    };
    uint8_t tbs[OSDP_C509_TBS_MAX]; size_t tbs_n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode_tbs(&cert, tbs, sizeof(tbs), &tbs_n));
    static const char dom[] = OSDP_C509_SIG_DOMAIN;
    const size_t dl = sizeof(dom) - 1;
    uint8_t sm[sizeof(dom) - 1 + OSDP_C509_TBS_MAX];
    (void)memcpy(sm, dom, dl); (void)memcpy(&sm[dl], tbs, tbs_n);
    static uint8_t sig[OSDP_MLDSA44_SIG_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK, ca->ml_dsa44_sign(ca->user, sm, dl + tbs_n, sig));
    cert.signature = sig; cert.signature_len = sizeof(sig);
    size_t n = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_c509_encode(&cert, out, out_cap, &n));
    return n;
}

/* ---- PD + pairing state ------------------------------------------------- */

static osdp_pd_t        pd;
static osdp_pd_pair_t   pair;
static osdp_pair_acu_session_t acu;

static bool    g_established;
static uint8_t g_peer_serial[OSDP_PAIR_STR_MAX];
static size_t  g_peer_serial_len;

static bool on_established(void *user, const osdp_pair_peer_t *peer,
                           const uint8_t scbk[OSDP_PAIR_SCBK_LEN])
{
    (void)user; (void)scbk;
    g_established = true;
    g_peer_serial_len = peer->serial_len;
    (void)memcpy(g_peer_serial, peer->serial, peer->serial_len);
    return true;   /* persist + accept */
}

void setUp(void)
{
    a2p.len = a2p.rpos = 0;
    p2a.len = p2a.rpos = 0;
    g_clock = 1000;
    g_established = false;
    g_peer_serial_len = 0;

    osdp_pair_test_crypto_init(&ca_crypto, &ca_ctx);
    osdp_pair_test_crypto_init(&acu_crypto, &acu_ctx);
    osdp_pair_test_crypto_init(&pd_crypto, &pd_ctx);
    osdp_pair_test_seed_clear();
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_test_gen_dsa(&ca_ctx));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_test_gen_dsa(&acu_ctx));
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_test_gen_dsa(&pd_ctx));
    acu_cert_len = make_cert(&ca_crypto, acu_ctx.dsa_pk, "ACME", "ACU-1", "SN-ACU",
                             acu_cert, sizeof(acu_cert));
    pd_cert_len = make_cert(&ca_crypto, pd_ctx.dsa_pk, "ACME", "PD-1", "SN-PD",
                            pd_cert, sizeof(pd_cert));

    /* PD */
    osdp_pd_init(&pd, PD_ADDR);
    osdp_pd_transport_t t = { pd_read, pd_write, pd_now, NULL };
    osdp_pd_set_transport(&pd, &t);

    osdp_pair_local_t pd_local = { pd_cert, pd_cert_len };
    osdp_pair_trust_t pd_trust = { .ca_pubkey = ca_ctx.dsa_pk };
    osdp_pd_pair_init(&pair, &pd_crypto, &pd_local, &pd_trust);
    osdp_pd_pair_set_established_handler(&pair, on_established, NULL);
    osdp_pd_attach_pair(&pd, &pair);

    /* ACU session */
    osdp_pair_local_t acu_local = { acu_cert, acu_cert_len };
    osdp_pair_trust_t acu_trust = { .ca_pubkey = ca_ctx.dsa_pk };
    osdp_pair_acu_init(&acu, &acu_crypto, &acu_local, &acu_trust);
}
void tearDown(void) {}

/* ---- OSDP command/reply harness ----------------------------------------- */

static uint8_t g_seq = 1;

static void send_cmd(uint8_t code, const uint8_t *payload, size_t plen,
                     uint8_t *out_code, uint8_t *out_pay, size_t out_cap,
                     size_t *out_plen)
{
    osdp_frame_t c;
    (void)memset(&c, 0, sizeof(c));
    c.address = PD_ADDR; c.reply = false; c.sequence = g_seq;
    c.integrity = OSDP_INTEGRITY_CRC; c.code = code;
    c.payload = payload; c.payload_len = plen;
    g_seq = (uint8_t)((g_seq % 3u) + 1u);

    static uint8_t fbuf[1024]; size_t flen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&c, fbuf, sizeof(fbuf), &flen));
    (void)memcpy(&a2p.buf[a2p.len], fbuf, flen); a2p.len += flen;

    p2a.len = 0; p2a.rpos = 0;
    osdp_pd_tick(&pd);

    /* osdp_frame_build emits a leading 0xFF mark byte; skip it before the
     * one-shot decoder, which expects to start at the SOM. */
    size_t off = 0;
    while (off < p2a.len && p2a.buf[off] == 0xFFu) { off++; }
    osdp_frame_t r;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_decode(&p2a.buf[off], p2a.len - off, &r));
    *out_code = r.code;
    *out_plen = r.payload_len;
    if (r.payload_len > 0) {
        TEST_ASSERT_TRUE(r.payload_len <= out_cap);
        (void)memcpy(out_pay, r.payload, r.payload_len);
    }
}

/* Fragment `msg` into osdp_PAIR commands; return the LAST reply. */
static void acu_send_message(const uint8_t *msg, size_t msg_len,
                             uint8_t *last_code, uint8_t *last_pay,
                             size_t cap, size_t *last_plen)
{
    osdp_mp_frag_iter_t it;
    osdp_mp_frag_iter_init(&it, msg, msg_len, 128);
    osdp_mp_fragment_t frag;
    while (osdp_mp_frag_iter_next(&it, &frag)) {
        uint8_t fbuf[OSDP_MP_HEADER_BYTES + 128]; size_t flen = 0;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_mp_fragment_build(&frag, fbuf, sizeof(fbuf), &flen));
        send_cmd(OSDP_CMD_PAIR, fbuf, flen, last_code, last_pay, cap, last_plen);
    }
}

/* Observed shape of the last Message-2 delivery: how many osdp_PAIRR
 * fragments it took and the largest fragment payload seen. Both are what the
 * ACU pays for in poll round-trips, so they are worth asserting on. */
static size_t g_msg2_frag_count;
static size_t g_msg2_frag_max;

/* POLL until the PD's queued Message 2 is fully reassembled. */
static size_t acu_recv_message(uint8_t *out, size_t out_cap)
{
    static uint8_t rbuf[OSDP_PAIR_MSG_MAX];
    osdp_mp_reasm_t r;
    osdp_mp_reasm_init(&r, rbuf, sizeof(rbuf));
    osdp_mp_state_t state = OSDP_MP_IN_PROGRESS;
    int guard = 0;
    g_msg2_frag_count = 0;
    g_msg2_frag_max   = 0;
    while (state != OSDP_MP_COMPLETE && guard++ < 300) {
        uint8_t code, pay[1024]; size_t plen = 0;
        send_cmd(OSDP_CMD_POLL, NULL, 0, &code, pay, sizeof(pay), &plen);
        if (code != OSDP_REPLY_PAIRR) { continue; }
        osdp_mp_fragment_t frag;
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_fragment_decode(pay, plen, &frag));
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_reasm_push(&r, &frag, &state));
        g_msg2_frag_count++;
        if (frag.frag_len > g_msg2_frag_max) { g_msg2_frag_max = frag.frag_len; }
    }
    TEST_ASSERT_EQUAL(OSDP_MP_COMPLETE, state);
    TEST_ASSERT_TRUE(r.total <= out_cap);
    (void)memcpy(out, rbuf, r.total);
    return r.total;
}

/* ---- Tests -------------------------------------------------------------- */

static void test_pd_completes_pairing_and_applies_scbk(void)
{
    static uint8_t msg1[8192], msg2[8192], msg3[8192];
    size_t n1 = 0, n2 = 0, n3 = 0;
    uint8_t code, pay[256]; size_t plen = 0;

    /* Msg1 -> PD (fragmented). All fragments ACK. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_create_msg1(&acu, msg1, sizeof(msg1), &n1));
    acu_send_message(msg1, n1, &code, pay, sizeof(pay), &plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, code);

    /* Pull Msg2 over POLLs. */
    n2 = acu_recv_message(msg2, sizeof(msg2));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_msg2(&acu, msg2, n2, msg3, sizeof(msg3), &n3));

    /* Msg3 -> PD. Last fragment returns the inline Result (osdp_PAIRR). */
    acu_send_message(msg3, n3, &code, pay, sizeof(pay), &plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PAIRR, code);

    osdp_mp_fragment_t frag;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_fragment_decode(pay, plen, &frag));
    uint8_t acu_scbk[OSDP_PAIR_SCBK_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_result(&acu, frag.data, frag.frag_len, acu_scbk));

    /* The PD applied the derived SCBK to its SC2 channel in place. */
    TEST_ASSERT_TRUE(pd.sc2.scbk_set);
    TEST_ASSERT_EQUAL_MEMORY(acu_scbk, pd.sc2.scbk, OSDP_SC2_KEY_LEN);

    /* The established callback fired with the authenticated ACU identity. */
    TEST_ASSERT_TRUE(g_established);
    TEST_ASSERT_EQUAL_MEMORY("SN-ACU", g_peer_serial, g_peer_serial_len);
}

/* Message-2 fragments are sized from what the ACU said it can receive, not
 * from a compile-time constant.
 *
 * Two halves, and the first is a correctness point rather than a speed one.
 * With no osdp_ACURXSIZE the peer limit is the conservative spec-6.26 default
 * of 128 bytes for the WHOLE packet, so a fragment payload has to leave room
 * for the OSDP framing and the 6-byte multi-part header inside it — the PD
 * must send strictly less than 128, not exactly 128. Measured: 113 bytes,
 * which the previously hard-coded 128 would have overrun.
 *
 * Then, once the ACU declares 1440, fragments grow to what this PD's own TX
 * buffer allows and the round-trip count collapses. Measured on the default
 * buffers: 113-byte fragments over 66 polls becomes 497-byte fragments over
 * 15. Asserted as relationships rather than those literals, so retuning a
 * buffer constant does not fail a test that is really about direction. */
static void test_msg2_fragments_follow_the_acu_declared_size(void)
{
    static uint8_t msg1[8192], msg2[8192], msg3[8192];
    size_t n1 = 0, n3 = 0;
    uint8_t code, pay[1024]; size_t plen = 0;

    /* --- Default peer limit: every fragment must fit a 128-byte packet. --- */
    TEST_ASSERT_EQUAL_UINT16(OSDP_PD_DEFAULT_ACU_RX_SIZE,
                             osdp_pd_acu_rx_size(&pd));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_create_msg1(&acu, msg1, sizeof(msg1), &n1));
    acu_send_message(msg1, n1, &code, pay, sizeof(pay), &plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, code);
    (void)acu_recv_message(msg2, sizeof(msg2));

    const size_t defaulted_max   = g_msg2_frag_max;
    const size_t defaulted_count = g_msg2_frag_count;
    TEST_ASSERT_GREATER_THAN_size_t(0, defaulted_max);
    TEST_ASSERT_LESS_THAN_size_t(OSDP_PD_DEFAULT_ACU_RX_SIZE, defaulted_max);

    /* --- Same exchange after the ACU declares 1440. --- */
    setUp();   /* fresh PD, ACU session and wire */

    const uint8_t rx1440[2] = { 0xA0, 0x05 };   /* 1440, little-endian */
    send_cmd(OSDP_CMD_ACURXSIZE, rx1440, sizeof(rx1440),
             &code, pay, sizeof(pay), &plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, code);
    TEST_ASSERT_EQUAL_UINT16(1440U, osdp_pd_acu_rx_size(&pd));

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_create_msg1(&acu, msg1, sizeof(msg1), &n1));
    acu_send_message(msg1, n1, &code, pay, sizeof(pay), &plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, code);
    const size_t n2 = acu_recv_message(msg2, sizeof(msg2));

    TEST_ASSERT_GREATER_THAN_size_t(defaulted_max, g_msg2_frag_max);
    TEST_ASSERT_LESS_THAN_size_t(defaulted_count, g_msg2_frag_count);
    /* Bounded by this PD's own TX capacity, not by the ACU's 1440. */
    TEST_ASSERT_LESS_OR_EQUAL_size_t(OSDP_PAIR_MAX_FRAGMENT_SIZE,
                                     g_msg2_frag_max);

    /* And the exchange still completes — a bigger fragment is not merely
     * emitted, it is accepted, reassembled and verified end to end. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_msg2(&acu, msg2, n2, msg3, sizeof(msg3), &n3));
    acu_send_message(msg3, n3, &code, pay, sizeof(pay), &plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PAIRR, code);
    TEST_ASSERT_TRUE(pd.sc2.scbk_set);
}

/* Run one full pairing exchange against the current PD. Returns the derived
 * SCBK through `scbk` so a caller can check a later attempt left it alone. */
static void run_pairing(uint8_t scbk[OSDP_PAIR_SCBK_LEN])
{
    static uint8_t msg1[8192], msg2[8192], msg3[8192];
    size_t n1 = 0, n2 = 0, n3 = 0;
    uint8_t code, pay[1024]; size_t plen = 0;

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_create_msg1(&acu, msg1, sizeof(msg1), &n1));
    acu_send_message(msg1, n1, &code, pay, sizeof(pay), &plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, code);

    n2 = acu_recv_message(msg2, sizeof(msg2));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_msg2(&acu, msg2, n2, msg3, sizeof(msg3), &n3));

    acu_send_message(msg3, n3, &code, pay, sizeof(pay), &plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PAIRR, code);
    osdp_mp_fragment_t frag;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_fragment_decode(pay, plen, &frag));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_process_result(&acu, frag.data, frag.frag_len, scbk));
}

/* Send a Message 1 and return the decoded Result the PD answered with.
 * Only valid when the PD is expected to reject inline rather than queue a
 * Message 2 for later polls. */
static uint64_t send_msg1_expect_result(void)
{
    static uint8_t msg1[8192];
    size_t n1 = 0;
    uint8_t code, pay[1024]; size_t plen = 0;

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_acu_create_msg1(&acu, msg1, sizeof(msg1), &n1));
    acu_send_message(msg1, n1, &code, pay, sizeof(pay), &plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PAIRR, code);

    osdp_mp_fragment_t frag;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_mp_fragment_decode(pay, plen, &frag));
    osdp_pair_result_t res;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_pair_result_decode(frag.data, frag.frag_len, &res));
    return res.status;
}

/* Re-pairing is allowed by default: a second exchange against an already-keyed
 * PD completes and installs the new key. */
static void test_repairing_is_allowed_by_default(void)
{
    uint8_t first[OSDP_PAIR_SCBK_LEN], second[OSDP_PAIR_SCBK_LEN];

    run_pairing(first);
    TEST_ASSERT_TRUE(pd.sc2.scbk_set);
    TEST_ASSERT_EQUAL_MEMORY(first, pd.sc2.scbk, OSDP_SC2_KEY_LEN);

    /* Fresh ACU session — a new pairing, not a replay of the first. */
    osdp_pair_local_t acu_local = { acu_cert, acu_cert_len };
    osdp_pair_trust_t acu_trust = { .ca_pubkey = ca_ctx.dsa_pk };
    osdp_pair_acu_init(&acu, &acu_crypto, &acu_local, &acu_trust);

    run_pairing(second);
    TEST_ASSERT_EQUAL_MEMORY(second, pd.sc2.scbk, OSDP_SC2_KEY_LEN);
}

/* With the policy set, an already-keyed PD answers POLICY (0x03) and keeps the
 * key it has. The benchmark depends on the permissive default, so this is the
 * behaviour that has to be asked for explicitly. */
static void test_deny_repair_rejects_an_already_keyed_pd(void)
{
    uint8_t first[OSDP_PAIR_SCBK_LEN], keep[OSDP_SC2_KEY_LEN];

    run_pairing(first);
    TEST_ASSERT_TRUE(pd.sc2.scbk_set);
    (void)memcpy(keep, pd.sc2.scbk, sizeof(keep));

    osdp_pd_pair_set_deny_repair(&pair, true);

    osdp_pair_local_t acu_local = { acu_cert, acu_cert_len };
    osdp_pair_trust_t acu_trust = { .ca_pubkey = ca_ctx.dsa_pk };
    osdp_pair_acu_init(&acu, &acu_crypto, &acu_local, &acu_trust);

    TEST_ASSERT_EQUAL_UINT64(OSDP_PAIR_STATUS_POLICY, send_msg1_expect_result());
    TEST_ASSERT_EQUAL_MEMORY(keep, pd.sc2.scbk, sizeof(keep));
}

/* The policy only bites once a key exists — setting it on a virgin PD must not
 * block the first pairing, or a device could never be provisioned. */
static void test_deny_repair_still_allows_the_first_pairing(void)
{
    uint8_t scbk[OSDP_PAIR_SCBK_LEN];

    osdp_pd_pair_set_deny_repair(&pair, true);
    TEST_ASSERT_FALSE(pd.sc2.scbk_set);

    run_pairing(scbk);
    TEST_ASSERT_TRUE(pd.sc2.scbk_set);
    TEST_ASSERT_EQUAL_MEMORY(scbk, pd.sc2.scbk, OSDP_SC2_KEY_LEN);
}

/* A credential the trust anchor will not accept is AUTH_FAIL (0x01), not
 * POLICY (0x03). The reference reserves 0x03 for policy declines such as the
 * re-pairing refusal above, and reporting a bad certificate as one sends the
 * ACU auditing its configuration instead of its credential. */
static void test_untrusted_acu_is_rejected_as_auth_failure(void)
{
    /* An ACU whose cert is signed by a CA this PD does not trust. */
    static osdp_pair_test_ctx_t rogue_ca_ctx;
    static osdp_pair_crypto_t   rogue_ca_crypto;
    static uint8_t              rogue_cert[4096];

    osdp_pair_test_crypto_init(&rogue_ca_crypto, &rogue_ca_ctx);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_test_gen_dsa(&rogue_ca_ctx));
    const size_t rogue_len = make_cert(&rogue_ca_crypto, acu_ctx.dsa_pk,
                                       "ACME", "ACU-X", "SN-ROGUE",
                                       rogue_cert, sizeof(rogue_cert));

    osdp_pair_local_t rogue_local = { rogue_cert, rogue_len };
    osdp_pair_trust_t acu_trust   = { .ca_pubkey = ca_ctx.dsa_pk };
    osdp_pair_acu_init(&acu, &acu_crypto, &rogue_local, &acu_trust);

    TEST_ASSERT_EQUAL_UINT64(OSDP_PAIR_STATUS_AUTH_FAIL,
                             send_msg1_expect_result());
    TEST_ASSERT_FALSE(pd.sc2.scbk_set);
}

/* An unconfigured PD (no pairing attached) NAKs osdp_PAIR. */
static void test_pd_without_pairing_naks(void)
{
    osdp_pd_t bare;
    osdp_pd_init(&bare, PD_ADDR);
    osdp_pd_transport_t t = { pd_read, pd_write, pd_now, NULL };
    osdp_pd_set_transport(&bare, &t);

    uint8_t frag[OSDP_MP_HEADER_BYTES + 4] = { 10,0, 0,0, 4,0, 1,2,3,4 };
    osdp_frame_t c;
    (void)memset(&c, 0, sizeof(c));
    c.address = PD_ADDR; c.sequence = 1; c.integrity = OSDP_INTEGRITY_CRC;
    c.code = OSDP_CMD_PAIR; c.payload = frag; c.payload_len = sizeof(frag);
    static uint8_t fbuf[128]; size_t flen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&c, fbuf, sizeof(fbuf), &flen));
    a2p.len = a2p.rpos = 0; p2a.len = p2a.rpos = 0;
    (void)memcpy(a2p.buf, fbuf, flen); a2p.len = flen;

    osdp_pd_tick(&bare);
    size_t off = 0;
    while (off < p2a.len && p2a.buf[off] == 0xFFu) { off++; }
    osdp_frame_t r;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_decode(&p2a.buf[off], p2a.len - off, &r));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, r.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, r.payload[0]);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pd_completes_pairing_and_applies_scbk);
    RUN_TEST(test_msg2_fragments_follow_the_acu_declared_size);
    RUN_TEST(test_repairing_is_allowed_by_default);
    RUN_TEST(test_deny_repair_rejects_an_already_keyed_pd);
    RUN_TEST(test_deny_repair_still_allows_the_first_pairing);
    RUN_TEST(test_untrusted_acu_is_rejected_as_auth_failure);
    RUN_TEST(test_pd_without_pairing_naks);
    return UNITY_END();
}
