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
    osdp_pair_frag_iter_t it;
    osdp_pair_frag_iter_init(&it, msg, msg_len, 128);
    osdp_pair_fragment_t frag;
    while (osdp_pair_frag_iter_next(&it, &frag)) {
        uint8_t fbuf[OSDP_PAIR_FRAG_HEADER_BYTES + 128]; size_t flen = 0;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_pair_fragment_build(&frag, fbuf, sizeof(fbuf), &flen));
        send_cmd(OSDP_CMD_PAIR, fbuf, flen, last_code, last_pay, cap, last_plen);
    }
}

/* POLL until the PD's queued Message 2 is fully reassembled. */
static size_t acu_recv_message(uint8_t *out, size_t out_cap)
{
    static uint8_t rbuf[OSDP_PAIR_MSG_MAX];
    osdp_pair_reasm_t r;
    osdp_pair_reasm_init(&r, rbuf, sizeof(rbuf));
    bool complete = false;
    int guard = 0;
    while (!complete && guard++ < 300) {
        uint8_t code, pay[256]; size_t plen = 0;
        send_cmd(OSDP_CMD_POLL, NULL, 0, &code, pay, sizeof(pay), &plen);
        if (code != OSDP_REPLY_PAIRR) { continue; }
        osdp_pair_fragment_t frag;
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_fragment_decode(pay, plen, &frag));
        TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_reasm_push(&r, &frag, &complete));
    }
    TEST_ASSERT_TRUE(complete);
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

    osdp_pair_fragment_t frag;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_fragment_decode(pay, plen, &frag));
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

/* An unconfigured PD (no pairing attached) NAKs osdp_PAIR. */
static void test_pd_without_pairing_naks(void)
{
    osdp_pd_t bare;
    osdp_pd_init(&bare, PD_ADDR);
    osdp_pd_transport_t t = { pd_read, pd_write, pd_now, NULL };
    osdp_pd_set_transport(&bare, &t);

    uint8_t frag[OSDP_PAIR_FRAG_HEADER_BYTES + 4] = { 10,0, 0,0, 4,0, 1,2,3,4 };
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
    RUN_TEST(test_pd_without_pairing_naks);
    return UNITY_END();
}
