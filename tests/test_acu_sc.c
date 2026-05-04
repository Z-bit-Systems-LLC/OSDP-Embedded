// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Tests for the ACU-side Secure Channel handshake (phase 5a).
 *
 * The ACU initiates the handshake via osdp_acu_start_sc_handshake;
 * subsequent ticks consume CCRYPT (SCS_12) and RMAC_I (SCS_14)
 * replies internally and fire the application's sc_event_cb on
 * either successful establishment or cryptographic failure. CCRYPT
 * and RMAC_I never appear in the application's reply_cb.
 *
 * Each test plays the role of a "mock PD": it decodes the CHLNG and
 * SCRYPT commands the ACU emits, computes the spec-mandated CCRYPT /
 * RMAC_I replies on its own, and injects them back through the mock
 * transport. The mock-PD-side keys are derived independently with
 * osdp_sc_derive_session_keys so a divergence in either implementation
 * shows up immediately. */

#include "osdp/osdp_acu.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_crc.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"
#include "sc_test_aes.h"
#include "unity.h"

#include <string.h>

void setUp(void)
{
    sc_test_crypto_seed_prng(0xABCD1234u);
    sc_test_crypto_set_fixed_rand(NULL, 0);
}

void tearDown(void) {}

/* ---- Mock transport ---------------------------------------------------- */

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
    if (m->incoming_off > m->incoming_len) return 0;
    const size_t avail = m->incoming_len - m->incoming_off;
    const size_t n = (cap < avail) ? cap : avail;
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

static void mock_init(mock_transport_t *m, osdp_acu_transport_t *t)
{
    (void)memset(m, 0, sizeof(*m));
    t->read   = mock_read;
    t->write  = mock_write;
    t->now_ms = mock_now_ms;
    t->user   = m;
}

static void mock_reset_incoming(mock_transport_t *m)
{
    m->incoming_len = 0;
    m->incoming_off = 0;
}

/* Inject a SCB-bearing reply frame into the mock transport. */
static void inject_sc_reply(mock_transport_t *m,
                            uint8_t           pd_address,
                            uint8_t           sequence,
                            uint8_t           scb_type,
                            uint8_t           scb_data_byte,
                            uint8_t           reply_code,
                            const uint8_t    *payload,
                            size_t            payload_len)
{
    osdp_frame_t f;
    (void)memset(&f, 0, sizeof(f));
    f.address      = pd_address;
    f.reply        = true;
    f.sequence     = sequence;
    f.integrity    = OSDP_INTEGRITY_CRC;
    f.has_scb      = true;
    f.scb_length   = (uint8_t)(OSDP_SCB_MIN_LEN + 1U);
    f.scb_type     = scb_type;
    f.scb_data     = &scb_data_byte;
    f.scb_data_len = 1U;
    f.code         = reply_code;
    f.payload      = payload;
    f.payload_len  = payload_len;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &built));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(MOCK_BUF_LEN - m->incoming_len, built);
    (void)memcpy(&m->incoming[m->incoming_len], buf, built);
    m->incoming_len += built;
}

/* Decode the next outgoing frame the ACU has written. */
static void decode_next_outgoing(mock_transport_t *m, osdp_frame_t *out,
                                 size_t *consumed_out)
{
    TEST_ASSERT_GREATER_OR_EQUAL(OSDP_FRAME_MIN_LEN_CKSUM, m->outgoing_len);
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_decode(m->outgoing, m->outgoing_len, out));
    if (consumed_out) {
        *consumed_out = out->raw_len;
    }
}

/* ---- SC event capture -------------------------------------------------- */

typedef struct sc_event_capture {
    unsigned int             call_count;
    osdp_acu_sc_event_t      last;
} sc_event_capture_t;

static void capture_sc_event(void *user, const osdp_acu_sc_event_t *e)
{
    sc_event_capture_t *c = (sc_event_capture_t *)user;
    c->call_count++;
    c->last = *e;
}

/* Reply-cb counter and payload-snapshot so we can assert plaintext
 * delivery for SC-unwrapped replies. The payload pointer in the event
 * may alias scratch memory, so we copy locally. */
typedef struct reply_capture {
    unsigned int           call_count;
    uint8_t                last_pd_address;
    uint8_t                last_cmd_code;
    uint8_t                last_reply_code;
    uint8_t                last_payload[64];
    size_t                 last_payload_len;
} reply_capture_t;

static void capture_reply(void *user, const osdp_acu_reply_event_t *e)
{
    reply_capture_t *c = (reply_capture_t *)user;
    c->call_count++;
    c->last_pd_address  = e->pd_address;
    c->last_cmd_code    = e->cmd_code;
    c->last_reply_code  = e->reply_code;
    c->last_payload_len = (e->payload_len < sizeof(c->last_payload))
                              ? e->payload_len : sizeof(c->last_payload);
    if (c->last_payload_len > 0) {
        (void)memcpy(c->last_payload, e->payload, c->last_payload_len);
    }
}

/* ---- Test fixtures ---------------------------------------------------- */

#define PD_ADDRESS 0x05U

static const uint8_t kSCBK[OSDP_SC_KEY_LEN] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
};
/* Mock-PD's claimed cUID (placed in the CCRYPT payload). */
static const uint8_t kPDCuid[OSDP_SC_CUID_LEN] = {
    0xCA, 0xFE, 0x00, 0x10, 0x01, 0xEF, 0xBE, 0xAD,
};
/* Mock-PD's RND.B — fixed via the test PRNG so we can reproduce. */
static const uint8_t kPDRndB[OSDP_SC_RND_LEN] = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
};

/* ---- Helpers: simulate the PD side of the handshake ------------------ */

/* Read the ACU's CHLNG, return RND.A so the test can derive keys etc.
 * Asserts the frame is well-formed SCS_11/CHLNG with the expected
 * key selector. */
static void consume_chlng(mock_transport_t *m,
                          uint8_t           expected_selector,
                          uint8_t           rnd_a_out[OSDP_SC_RND_LEN],
                          uint8_t          *seq_out)
{
    osdp_frame_t f;
    decode_next_outgoing(m, &f, NULL);
    TEST_ASSERT_FALSE(f.reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_CHLNG, f.code);
    TEST_ASSERT_TRUE(f.has_scb);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_11, f.scb_type);
    TEST_ASSERT_EQUAL_size_t(1, f.scb_data_len);
    TEST_ASSERT_EQUAL_HEX8(expected_selector, f.scb_data[0]);
    TEST_ASSERT_EQUAL_size_t(OSDP_SC_RND_LEN, f.payload_len);
    (void)memcpy(rnd_a_out, f.payload, OSDP_SC_RND_LEN);
    *seq_out = f.sequence;
}

/* Read the ACU's SCRYPT; return the Server Cryptogram so the mock PD
 * can verify and produce the right RMAC_I. */
static void consume_scrypt(mock_transport_t *m,
                           uint8_t           expected_selector,
                           uint8_t           server_crypto_out
                                              [OSDP_SC_CRYPTOGRAM_LEN],
                           uint8_t          *seq_out)
{
    osdp_frame_t f;
    decode_next_outgoing(m, &f, NULL);
    TEST_ASSERT_FALSE(f.reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_SCRYPT, f.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_13, f.scb_type);
    TEST_ASSERT_EQUAL_size_t(1, f.scb_data_len);
    TEST_ASSERT_EQUAL_HEX8(expected_selector, f.scb_data[0]);
    TEST_ASSERT_EQUAL_size_t(OSDP_SC_CRYPTOGRAM_LEN, f.payload_len);
    (void)memcpy(server_crypto_out, f.payload, OSDP_SC_CRYPTOGRAM_LEN);
    *seq_out = f.sequence;
}

/* Build a CCRYPT (SCS_12) reply that a real PD would compute, given
 * the ACU's RND.A and the chosen SCBK. */
static void build_and_inject_ccrypt(mock_transport_t *m,
                                    uint8_t           seq,
                                    uint8_t           selector,
                                    const uint8_t    *scbk,
                                    const uint8_t    *rnd_a,
                                    uint8_t           rnd_b_out[OSDP_SC_RND_LEN])
{
    osdp_sc_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(sc_test_crypto_tiny_aes(),
                                    scbk, rnd_a, &keys));
    uint8_t client_crypto[OSDP_SC_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_client_cryptogram(sc_test_crypto_tiny_aes(), keys.s_enc,
                                  rnd_a, kPDRndB, client_crypto));

    uint8_t payload[OSDP_SC_CUID_LEN + OSDP_SC_RND_LEN
                  + OSDP_SC_CRYPTOGRAM_LEN];
    (void)memcpy(&payload[0],                             kPDCuid,        OSDP_SC_CUID_LEN);
    (void)memcpy(&payload[OSDP_SC_CUID_LEN],              kPDRndB,        OSDP_SC_RND_LEN);
    (void)memcpy(&payload[OSDP_SC_CUID_LEN + OSDP_SC_RND_LEN],
                 client_crypto,                                            OSDP_SC_CRYPTOGRAM_LEN);

    if (rnd_b_out) {
        (void)memcpy(rnd_b_out, kPDRndB, OSDP_SC_RND_LEN);
    }
    inject_sc_reply(m, PD_ADDRESS, seq, OSDP_SCS_12, selector,
                    OSDP_REPLY_CCRYPT, payload, sizeof(payload));
}

/* Build an RMAC_I (SCS_14, status=0x01 ok) given the ACU's
 * ServerCryptogram. */
static void build_and_inject_rmac_i(mock_transport_t *m,
                                    uint8_t           seq,
                                    uint8_t           status,
                                    const uint8_t    *scbk,
                                    const uint8_t    *rnd_a,
                                    const uint8_t    *server_crypto)
{
    osdp_sc_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(sc_test_crypto_tiny_aes(),
                                    scbk, rnd_a, &keys));
    uint8_t initial_rmac[OSDP_SC_MAC_LEN];
    if (status == 0x01U) {
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc_initial_rmac(sc_test_crypto_tiny_aes(),
                                 keys.s_mac1, keys.s_mac2,
                                 server_crypto, initial_rmac));
        inject_sc_reply(m, PD_ADDRESS, seq, OSDP_SCS_14, status,
                        OSDP_REPLY_RMAC_I, initial_rmac, sizeof(initial_rmac));
    } else {
        /* Failure path: per spec, RMAC_I with status 0xFF carries no
         * R-MAC payload. */
        inject_sc_reply(m, PD_ADDRESS, seq, OSDP_SCS_14, status,
                        OSDP_REPLY_RMAC_I, NULL, 0);
    }
}

/* Set up an ACU with one PD slot, both keys configured, mock
 * transport bound, and the SC event handler hooked up to `events`. */
static void configure_acu_sc(osdp_acu_t           *acu,
                             osdp_acu_pd_slot_t   *slot,
                             osdp_acu_transport_t *t,
                             mock_transport_t     *m,
                             sc_event_capture_t   *events,
                             reply_capture_t      *replies)
{
    mock_init(m, t);
    osdp_acu_init(acu, slot, 1U);
    osdp_acu_set_transport(acu, t);
    osdp_acu_set_sc_crypto(acu, sc_test_crypto_tiny_aes());
    osdp_acu_set_sc_event_handler(acu, capture_sc_event, events);
    if (replies) {
        osdp_acu_set_reply_handler(acu, capture_reply, replies);
    }
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_register_pd(acu, 0U, PD_ADDRESS));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_set_pd_scbk(acu, PD_ADDRESS, kSCBK));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_set_pd_scbk_d(acu, PD_ADDRESS, OSDP_SCBK_DEFAULT));

    /* Pin the ACU's RND.A to the PRNG output so handshake math is
     * deterministic. (The mock-PD's RND.B is the value we hardcode
     * into kPDRndB and inject directly into the CCRYPT reply.) */
}

/* ---- Tests ------------------------------------------------------------- */

static void test_start_handshake_emits_chlng_with_scbkd_selector(void)
{
    osdp_acu_t acu;
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t;
    mock_transport_t m;
    sc_event_capture_t events = {0};
    configure_acu_sc(&acu, slots, &t, &m, &events, NULL);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_start_sc_handshake(&acu, PD_ADDRESS,
                                    /*use_default_key*/ true));

    /* CHLNG must be on the wire with selector=0 and SCS_11. */
    osdp_frame_t chlng;
    decode_next_outgoing(&m, &chlng, NULL);
    TEST_ASSERT_FALSE(chlng.reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_CHLNG, chlng.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_11, chlng.scb_type);
    TEST_ASSERT_EQUAL_HEX8(0U, chlng.scb_data[0]);  /* SCBK-D */
    TEST_ASSERT_EQUAL_size_t(OSDP_SC_RND_LEN, chlng.payload_len);

    /* Phase advanced; session not yet established. */
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));
    TEST_ASSERT_TRUE(osdp_acu_is_pd_busy(&acu, PD_ADDRESS));
    TEST_ASSERT_EQUAL(0U, events.call_count);
}

static void test_start_handshake_with_scbk_selector_one(void)
{
    osdp_acu_t acu;
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t;
    mock_transport_t m;
    sc_event_capture_t events = {0};
    configure_acu_sc(&acu, slots, &t, &m, &events, NULL);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_start_sc_handshake(&acu, PD_ADDRESS,
                                    /*use_default_key*/ false));
    osdp_frame_t chlng;
    decode_next_outgoing(&m, &chlng, NULL);
    TEST_ASSERT_EQUAL_HEX8(1U, chlng.scb_data[0]);  /* SCBK */
}

static void test_start_handshake_rejected_without_crypto(void)
{
    osdp_acu_t acu;
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t;
    mock_transport_t m;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1U);
    osdp_acu_set_transport(&acu, &t);
    /* Keys present but no crypto vtable. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_register_pd(&acu, 0U, PD_ADDRESS));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_set_pd_scbk_d(&acu, PD_ADDRESS, OSDP_SCBK_DEFAULT));
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_acu_start_sc_handshake(&acu, PD_ADDRESS, true));
}

static void test_start_handshake_rejected_without_key(void)
{
    osdp_acu_t acu;
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t;
    mock_transport_t m;
    mock_init(&m, &t);
    osdp_acu_init(&acu, slots, 1U);
    osdp_acu_set_transport(&acu, &t);
    osdp_acu_set_sc_crypto(&acu, sc_test_crypto_tiny_aes());
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_register_pd(&acu, 0U, PD_ADDRESS));
    /* SCBK-D not set */
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_acu_start_sc_handshake(&acu, PD_ADDRESS, true));
}

static void test_start_handshake_rejected_unknown_pd(void)
{
    osdp_acu_t acu;
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t;
    mock_transport_t m;
    sc_event_capture_t events = {0};
    configure_acu_sc(&acu, slots, &t, &m, &events, NULL);
    TEST_ASSERT_EQUAL(OSDP_ERR_INVALID_ARG,
        osdp_acu_start_sc_handshake(&acu, /*addr*/ 0x42U, true));
}

static void test_full_handshake_fires_established_event(void)
{
    osdp_acu_t acu;
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t;
    mock_transport_t m;
    sc_event_capture_t events = {0};
    reply_capture_t   replies = {0};
    configure_acu_sc(&acu, slots, &t, &m, &events, &replies);

    /* 1: ACU sends CHLNG. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_start_sc_handshake(&acu, PD_ADDRESS,
                                    /*use_default_key*/ false));
    uint8_t rnd_a[OSDP_SC_RND_LEN];
    uint8_t chlng_seq;
    consume_chlng(&m, /*selector*/ 1U, rnd_a, &chlng_seq);

    /* 2: Mock PD computes CCRYPT and injects it. */
    mock_reset_incoming(&m);
    build_and_inject_ccrypt(&m, chlng_seq, /*selector*/ 1U,
                            kSCBK, rnd_a, NULL);
    m.outgoing_len = 0;
    osdp_acu_tick(&acu);

    /* 3: ACU should have emitted SCRYPT. */
    uint8_t server_crypto[OSDP_SC_CRYPTOGRAM_LEN];
    uint8_t scrypt_seq;
    consume_scrypt(&m, /*selector*/ 1U, server_crypto, &scrypt_seq);

    /* 4: Mock PD verifies (here, just trusts) and emits RMAC_I. */
    mock_reset_incoming(&m);
    build_and_inject_rmac_i(&m, scrypt_seq, /*status ok*/ 0x01U,
                            kSCBK, rnd_a, server_crypto);
    m.outgoing_len = 0;
    osdp_acu_tick(&acu);

    /* 5: Session should be established and event fired. */
    TEST_ASSERT_EQUAL(1U, events.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_ESTABLISHED, events.last.kind);
    TEST_ASSERT_EQUAL_HEX8(PD_ADDRESS, events.last.pd_address);
    TEST_ASSERT_TRUE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));

    /* CCRYPT and RMAC_I must NOT have been delivered as ordinary
     * replies. */
    TEST_ASSERT_EQUAL(0U, replies.call_count);
}

static void test_handshake_fails_on_bad_client_cryptogram(void)
{
    osdp_acu_t acu;
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t;
    mock_transport_t m;
    sc_event_capture_t events = {0};
    configure_acu_sc(&acu, slots, &t, &m, &events, NULL);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_start_sc_handshake(&acu, PD_ADDRESS, false));
    uint8_t rnd_a[OSDP_SC_RND_LEN];
    uint8_t chlng_seq;
    consume_chlng(&m, 1U, rnd_a, &chlng_seq);

    /* Build a CCRYPT with a deliberately-corrupt Client Cryptogram. */
    uint8_t bad_payload[OSDP_SC_CUID_LEN + OSDP_SC_RND_LEN
                      + OSDP_SC_CRYPTOGRAM_LEN];
    (void)memcpy(&bad_payload[0],                                  kPDCuid,         OSDP_SC_CUID_LEN);
    (void)memcpy(&bad_payload[OSDP_SC_CUID_LEN],                   kPDRndB,         OSDP_SC_RND_LEN);
    (void)memset(&bad_payload[OSDP_SC_CUID_LEN + OSDP_SC_RND_LEN], 0xCC,            OSDP_SC_CRYPTOGRAM_LEN);

    mock_reset_incoming(&m);
    inject_sc_reply(&m, PD_ADDRESS, chlng_seq, OSDP_SCS_12, /*selector*/ 1U,
                    OSDP_REPLY_CCRYPT, bad_payload, sizeof(bad_payload));
    m.outgoing_len = 0;
    osdp_acu_tick(&acu);

    /* No SCRYPT emitted; failure event fired. */
    TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);
    TEST_ASSERT_EQUAL(1U, events.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED, events.last.kind);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));
}

static void test_handshake_fails_on_pd_status_0xff(void)
{
    osdp_acu_t acu;
    osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t;
    mock_transport_t m;
    sc_event_capture_t events = {0};
    configure_acu_sc(&acu, slots, &t, &m, &events, NULL);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_start_sc_handshake(&acu, PD_ADDRESS, false));
    uint8_t rnd_a[OSDP_SC_RND_LEN];
    uint8_t chlng_seq;
    consume_chlng(&m, 1U, rnd_a, &chlng_seq);

    /* Send a valid CCRYPT so the ACU advances to AWAITING_RMAC_I. */
    mock_reset_incoming(&m);
    build_and_inject_ccrypt(&m, chlng_seq, 1U, kSCBK, rnd_a, NULL);
    m.outgoing_len = 0;
    osdp_acu_tick(&acu);

    uint8_t server_crypto[OSDP_SC_CRYPTOGRAM_LEN];
    uint8_t scrypt_seq;
    consume_scrypt(&m, 1U, server_crypto, &scrypt_seq);

    /* Now respond with RMAC_I status=0xFF (PD rejected our cryptogram). */
    mock_reset_incoming(&m);
    build_and_inject_rmac_i(&m, scrypt_seq, /*status fail*/ 0xFFU,
                            kSCBK, rnd_a, server_crypto);
    m.outgoing_len = 0;
    osdp_acu_tick(&acu);

    TEST_ASSERT_EQUAL(1U, events.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED, events.last.kind);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));
}

/* ---- Phase 5b: operational SC ----------------------------------------- */

/* Drive the ACU through a full successful handshake using SCBK and
 * synthesize the matching mock-PD session so the caller can wrap
 * replies / unwrap commands on the PD side using the same key
 * material. */
static void run_handshake_and_mirror_pd(osdp_acu_t           *acu,
                                        osdp_acu_pd_slot_t   *slots,
                                        osdp_acu_transport_t *t,
                                        mock_transport_t     *m,
                                        sc_event_capture_t   *events,
                                        reply_capture_t      *replies,
                                        osdp_sc_session_t    *pd_session_out)
{
    configure_acu_sc(acu, slots, t, m, events, replies);

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_start_sc_handshake(acu, PD_ADDRESS,
                                    /*use_default_key*/ false));

    uint8_t rnd_a[OSDP_SC_RND_LEN];
    uint8_t chlng_seq;
    consume_chlng(m, /*selector*/ 1U, rnd_a, &chlng_seq);

    mock_reset_incoming(m);
    build_and_inject_ccrypt(m, chlng_seq, /*selector*/ 1U,
                            kSCBK, rnd_a, NULL);
    m->outgoing_len = 0;
    osdp_acu_tick(acu);

    uint8_t server_crypto[OSDP_SC_CRYPTOGRAM_LEN];
    uint8_t scrypt_seq;
    consume_scrypt(m, 1U, server_crypto, &scrypt_seq);

    mock_reset_incoming(m);
    build_and_inject_rmac_i(m, scrypt_seq, /*ok*/ 0x01U,
                            kSCBK, rnd_a, server_crypto);
    m->outgoing_len = 0;
    osdp_acu_tick(acu);

    TEST_ASSERT_TRUE(osdp_acu_is_pd_sc_established(acu, PD_ADDRESS));

    /* Build the mock PD's mirror session: same keys, both MAC chain
     * entries seeded with the same Initial R-MAC the real ACU just
     * settled on. */
    osdp_sc_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(sc_test_crypto_tiny_aes(),
                                    kSCBK, rnd_a, &keys));
    uint8_t initial_rmac[OSDP_SC_MAC_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_initial_rmac(sc_test_crypto_tiny_aes(),
                             keys.s_mac1, keys.s_mac2,
                             server_crypto, initial_rmac));

    osdp_sc_session_init(pd_session_out);
    pd_session_out->keys = keys;
    (void)memcpy(pd_session_out->last_outbound_mac,
                 initial_rmac, OSDP_SC_MAC_LEN);
    (void)memcpy(pd_session_out->last_inbound_mac,
                 initial_rmac, OSDP_SC_MAC_LEN);
    pd_session_out->established = true;
}

/* Build a SCS_16/SCS_18 reply on the mock PD side using `pd_session`
 * (which has chain state mirroring the ACU's), inject it into the
 * mock transport. The mock-PD's last_inbound_mac will be updated by
 * the wrap helper because we feed it through the inverse direction
 * of what the chain rules normally expect; do the bookkeeping here
 * so the test stays simple. */
static void mock_pd_inject_sc_reply(mock_transport_t  *m,
                                    osdp_sc_session_t *pd_session,
                                    uint8_t            cmd_we_replied_to_seq,
                                    uint8_t            reply_code,
                                    uint8_t            scb_type,
                                    const uint8_t     *plaintext,
                                    size_t             plaintext_len,
                                    /* The mock PD's "last_inbound_mac" was
                                     * updated when it (notionally) received
                                     * the ACU's command; pass that in so
                                     * the wrap uses the right ICV. */
                                    const uint8_t      acu_cmd_full_mac
                                                       [OSDP_SC_MAC_LEN])
{
    /* Sync the PD's last_inbound_mac with the ACU's last_outbound_mac
     * (= the ACU command's MAC). */
    (void)memcpy(pd_session->last_inbound_mac, acu_cmd_full_mac,
                 OSDP_SC_MAC_LEN);

    osdp_frame_t reply;
    (void)memset(&reply, 0, sizeof(reply));
    reply.address     = PD_ADDRESS;
    reply.reply       = true;
    reply.sequence    = cmd_we_replied_to_seq;
    reply.integrity   = OSDP_INTEGRITY_CRC;
    reply.has_scb     = true;
    reply.scb_length  = OSDP_SCB_MIN_LEN;
    reply.scb_type    = scb_type;
    reply.code        = reply_code;
    reply.payload     = plaintext;
    reply.payload_len = plaintext_len;

    uint8_t buf[OSDP_FRAME_MAX_LEN]; size_t built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), pd_session,
                           &reply, buf, sizeof(buf), &built));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(MOCK_BUF_LEN - m->incoming_len, built);
    (void)memcpy(&m->incoming[m->incoming_len], buf, built);
    m->incoming_len += built;
}

/* Decode the next outgoing frame the ACU sent under SC, and unwrap
 * it on the mock-PD side so the test can inspect the plaintext code +
 * payload. Updates pd_session->last_inbound_mac with the cmd's MAC. */
static void mock_pd_consume_sc_command(mock_transport_t   *m,
                                       osdp_sc_session_t  *pd_session,
                                       uint8_t            *out_plain,
                                       size_t              out_plain_cap,
                                       size_t             *out_plain_len,
                                       uint8_t            *out_seq,
                                       uint8_t            *out_scb_type,
                                       uint8_t            *out_code,
                                       uint8_t             out_full_mac
                                                           [OSDP_SC_MAC_LEN])
{
    osdp_frame_t frame;
    decode_next_outgoing(m, &frame, NULL);
    TEST_ASSERT_FALSE(frame.reply);
    TEST_ASSERT_TRUE(frame.has_scb);
    *out_seq      = frame.sequence;
    *out_scb_type = frame.scb_type;
    *out_code     = frame.code;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), pd_session,
                             &frame, out_plain, out_plain_cap, out_plain_len));
    /* Grab the MAC that wrap_frame just computed/verified — i.e. the
     * just-updated last_inbound_mac of the mock PD. */
    (void)memcpy(out_full_mac, pd_session->last_inbound_mac,
                 OSDP_SC_MAC_LEN);
}

static void test_send_command_after_handshake_empty_payload_uses_scs_15(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);
    m.outgoing_len = 0;

    /* POLL: no payload → must wrap as SCS_15 (per project convention). */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));

    uint8_t plain[16]; size_t plain_len = 0;
    uint8_t seq, scb_type, code, mac_full[OSDP_SC_MAC_LEN];
    mock_pd_consume_sc_command(&m, &pd_session, plain, sizeof(plain),
                               &plain_len, &seq, &scb_type, &code, mac_full);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_15, scb_type);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, code);
    TEST_ASSERT_EQUAL_size_t(0, plain_len);
}

static void test_send_command_after_handshake_with_payload_uses_scs_17(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);
    m.outgoing_len = 0;

    /* CAP request: 1-byte reply-type payload. Should wrap as SCS_17. */
    static const uint8_t cap_payload = 0x00U;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&acu, PD_ADDRESS, OSDP_CMD_CAP,
                              &cap_payload, 1));

    uint8_t plain[16]; size_t plain_len = 0;
    uint8_t seq, scb_type, code, mac_full[OSDP_SC_MAC_LEN];
    mock_pd_consume_sc_command(&m, &pd_session, plain, sizeof(plain),
                               &plain_len, &seq, &scb_type, &code, mac_full);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_17, scb_type);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_CAP, code);
    TEST_ASSERT_EQUAL_size_t(1, plain_len);
    TEST_ASSERT_EQUAL_HEX8(0x00U, plain[0]);
}

static void test_inbound_scs_16_ack_reaches_reply_cb_as_plaintext(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);
    m.outgoing_len = 0;
    replies.call_count = 0;

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));

    /* Mock PD side: read the SCS_15 POLL, capture its full MAC, build
     * a SCS_16 ACK reply, inject. */
    uint8_t plain[16]; size_t plain_len = 0;
    uint8_t seq, scb_type, code, cmd_mac[OSDP_SC_MAC_LEN];
    mock_pd_consume_sc_command(&m, &pd_session, plain, sizeof(plain),
                               &plain_len, &seq, &scb_type, &code, cmd_mac);

    mock_reset_incoming(&m);
    mock_pd_inject_sc_reply(&m, &pd_session, seq,
                            OSDP_REPLY_ACK, OSDP_SCS_16,
                            NULL, 0, cmd_mac);
    m.outgoing_len = 0;
    osdp_acu_tick(&acu);

    /* Application got a plain ACK, no payload. */
    TEST_ASSERT_EQUAL(1U, replies.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, replies.last_reply_code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, replies.last_cmd_code);
    TEST_ASSERT_EQUAL_size_t(0, replies.last_payload_len);
}

static void test_inbound_scs_18_reply_decrypts_into_reply_cb(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);
    m.outgoing_len = 0;
    replies.call_count = 0;

    /* Send CAP (SCS_17, 1-byte payload). */
    static const uint8_t cap_payload = 0x00U;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&acu, PD_ADDRESS, OSDP_CMD_CAP,
                              &cap_payload, 1));

    uint8_t cmd_plain[16]; size_t cmd_plain_len = 0;
    uint8_t seq, scb_type, code, cmd_mac[OSDP_SC_MAC_LEN];
    mock_pd_consume_sc_command(&m, &pd_session, cmd_plain, sizeof(cmd_plain),
                               &cmd_plain_len, &seq, &scb_type, &code, cmd_mac);

    /* Build a SCS_18 PDCAP-shaped reply with 12 bytes of payload. */
    static const uint8_t pdcap_payload[12] = {
        1, 1, 1, 2, 1, 1, 3, 1, 1, 4, 1, 1
    };
    mock_reset_incoming(&m);
    mock_pd_inject_sc_reply(&m, &pd_session, seq,
                            OSDP_REPLY_PDCAP, OSDP_SCS_18,
                            pdcap_payload, sizeof(pdcap_payload), cmd_mac);
    m.outgoing_len = 0;
    osdp_acu_tick(&acu);

    /* Application got plaintext PDCAP with the right payload. */
    TEST_ASSERT_EQUAL(1U, replies.call_count);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDCAP, replies.last_reply_code);
    TEST_ASSERT_EQUAL_size_t(sizeof(pdcap_payload), replies.last_payload_len);
    TEST_ASSERT_EQUAL_MEMORY(pdcap_payload, replies.last_payload,
                             sizeof(pdcap_payload));
}

static void test_mac_failure_terminates_session_and_fires_event(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);
    /* Reset the established-event we already captured. */
    events.call_count = 0;
    m.outgoing_len = 0;

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));

    uint8_t plain[16]; size_t plain_len = 0;
    uint8_t seq, scb_type, code, cmd_mac[OSDP_SC_MAC_LEN];
    mock_pd_consume_sc_command(&m, &pd_session, plain, sizeof(plain),
                               &plain_len, &seq, &scb_type, &code, cmd_mac);

    /* Build a valid SCS_16 ACK on the mock-PD side, then corrupt one
     * MAC byte and recompute CRC so it still passes Layer 1. */
    osdp_frame_t reply_template;
    (void)memset(&reply_template, 0, sizeof(reply_template));
    reply_template.address     = PD_ADDRESS;
    reply_template.reply       = true;
    reply_template.sequence    = seq;
    reply_template.integrity   = OSDP_INTEGRITY_CRC;
    reply_template.has_scb     = true;
    reply_template.scb_length  = OSDP_SCB_MIN_LEN;
    reply_template.scb_type    = OSDP_SCS_16;
    reply_template.code        = OSDP_REPLY_ACK;
    /* Mirror the chain manually: pd_session->last_inbound_mac was just
     * updated in mock_pd_consume_sc_command; that's the right ICV. */

    uint8_t buf[64]; size_t built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &pd_session,
                           &reply_template, buf, sizeof(buf), &built));
    /* Flip a MAC byte and recompute CRC. */
    const size_t crc_off = built - 2;
    const size_t mac_off = crc_off - OSDP_FRAME_MAC_LEN;
    buf[mac_off] ^= 0x10;
    const uint16_t crc = osdp_crc16(buf, crc_off);
    buf[crc_off]     = (uint8_t)(crc & 0xFFu);
    buf[crc_off + 1] = (uint8_t)((crc >> 8) & 0xFFu);

    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, buf, built);
    m.incoming_len = built;
    osdp_acu_tick(&acu);

    /* Session lost; no reply delivered to the application. */
    TEST_ASSERT_EQUAL(0U, replies.call_count);
    TEST_ASSERT_EQUAL(1U, events.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_SESSION_LOST, events.last.kind);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));
}

static void test_plain_reply_during_established_terminates_session(void)
{
    /* Spec D.1.4: a non-BUSY plaintext reply during an established
     * session terminates the session. */
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);
    events.call_count = 0;
    m.outgoing_len = 0;

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));

    /* Read the outbound POLL just so we know the SQN. */
    osdp_frame_t out_frame;
    decode_next_outgoing(&m, &out_frame, NULL);
    const uint8_t seq = out_frame.sequence;

    /* Now inject a plaintext ACK (no SCB) — spec violation. */
    osdp_frame_t plain_reply;
    (void)memset(&plain_reply, 0, sizeof(plain_reply));
    plain_reply.address   = PD_ADDRESS;
    plain_reply.reply     = true;
    plain_reply.sequence  = seq;
    plain_reply.integrity = OSDP_INTEGRITY_CRC;
    plain_reply.code      = OSDP_REPLY_ACK;
    uint8_t buf[16]; size_t built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_build(&plain_reply, buf, sizeof(buf), &built));

    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, buf, built);
    m.incoming_len = built;
    osdp_acu_tick(&acu);

    TEST_ASSERT_EQUAL(0U, replies.call_count);
    TEST_ASSERT_EQUAL(1U, events.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_SESSION_LOST, events.last.kind);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));
}

static void test_send_command_after_session_loss_uses_plaintext(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);

    /* Force a session loss the cheap way: inject a tampered SCS_16. */
    m.outgoing_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));
    uint8_t plain[16]; size_t plain_len = 0;
    uint8_t seq, scb_type, code, cmd_mac[OSDP_SC_MAC_LEN];
    mock_pd_consume_sc_command(&m, &pd_session, plain, sizeof(plain),
                               &plain_len, &seq, &scb_type, &code, cmd_mac);
    osdp_frame_t reply;
    (void)memset(&reply, 0, sizeof(reply));
    reply.address     = PD_ADDRESS;
    reply.reply       = true;
    reply.sequence    = seq;
    reply.integrity   = OSDP_INTEGRITY_CRC;
    reply.has_scb     = true;
    reply.scb_length  = OSDP_SCB_MIN_LEN;
    reply.scb_type    = OSDP_SCS_16;
    reply.code        = OSDP_REPLY_ACK;
    uint8_t bad_buf[64]; size_t bad_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &pd_session,
                           &reply, bad_buf, sizeof(bad_buf), &bad_len));
    const size_t crc_off = bad_len - 2;
    const size_t mac_off = crc_off - OSDP_FRAME_MAC_LEN;
    bad_buf[mac_off] ^= 0x10;
    const uint16_t crc = osdp_crc16(bad_buf, crc_off);
    bad_buf[crc_off]     = (uint8_t)(crc & 0xFFu);
    bad_buf[crc_off + 1] = (uint8_t)((crc >> 8) & 0xFFu);
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, bad_buf, bad_len);
    m.incoming_len = bad_len;
    osdp_acu_tick(&acu);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));

    /* Now send another command — should go plaintext (no SCB). */
    m.outgoing_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));
    osdp_frame_t outframe;
    decode_next_outgoing(&m, &outframe, NULL);
    TEST_ASSERT_FALSE(outframe.has_scb);
    TEST_ASSERT_EQUAL_HEX8(OSDP_CMD_POLL, outframe.code);
}

/* ---- Additional session-loss triggers (spec 5.9 + 5.7) --------------- */

/* Spec 5.9: a PD reply with SQN=0 signals "reset the sequence and
 * clear any active SC session". Verify a plaintext SQN=0 reply during
 * an established session tears it down. */
static void test_sqn_zero_plain_reply_during_established_resets(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);
    events.call_count = 0;
    m.outgoing_len = 0;

    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_send_command(&acu, PD_ADDRESS, OSDP_CMD_POLL, NULL, 0));
    /* Drain the SCS_15 POLL we just sent so we know the SQN advanced. */
    osdp_frame_t outframe;
    decode_next_outgoing(&m, &outframe, NULL);

    /* PD replies with SQN=0 (spec-defined reset signal). Build a
     * plaintext ACK with sequence=0 and inject it. */
    osdp_frame_t reply;
    (void)memset(&reply, 0, sizeof(reply));
    reply.address   = PD_ADDRESS;
    reply.reply     = true;
    reply.sequence  = 0U;          /* the reset sentinel */
    reply.integrity = OSDP_INTEGRITY_CRC;
    reply.code      = OSDP_REPLY_ACK;
    uint8_t buf[16]; size_t built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_build(&reply, buf, sizeof(buf), &built));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, buf, built);
    m.incoming_len = built;
    osdp_acu_tick(&acu);

    /* No reply delivered; SESSION_LOST event fired; phase reset. */
    TEST_ASSERT_EQUAL(0U, replies.call_count);
    TEST_ASSERT_EQUAL(1U, events.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_SESSION_LOST, events.last.kind);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));
}

/* Spec 5.9 also applies under SC: a SCS_16/18 reply with SQN=0 during
 * an established session must terminate the session. The MAC chain
 * has effectively desynchronized and we have no business continuing. */
static void test_sqn_zero_sc_reply_during_established_resets(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);
    events.call_count = 0;
    m.outgoing_len = 0;

    /* Forge a SCS_16 ACK with sequence=0. We don't bother computing a
     * matching MAC since we expect the SQN=0 check to fire first,
     * before MAC verification. */
    osdp_frame_t reply;
    (void)memset(&reply, 0, sizeof(reply));
    reply.address     = PD_ADDRESS;
    reply.reply       = true;
    reply.sequence    = 0U;
    reply.integrity   = OSDP_INTEGRITY_CRC;
    reply.has_scb     = true;
    reply.scb_length  = OSDP_SCB_MIN_LEN;
    reply.scb_type    = OSDP_SCS_16;
    reply.code        = OSDP_REPLY_ACK;
    static const uint8_t zero_mac[OSDP_FRAME_MAC_LEN] = {0};
    reply.mac         = zero_mac;
    reply.mac_len     = OSDP_FRAME_MAC_LEN;
    uint8_t buf[64]; size_t built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_frame_build(&reply, buf, sizeof(buf), &built));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, buf, built);
    m.incoming_len = built;
    osdp_acu_tick(&acu);

    TEST_ASSERT_EQUAL(0U, replies.call_count);
    TEST_ASSERT_EQUAL(1U, events.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_SESSION_LOST, events.last.kind);
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));
}

/* Spec 5.7: 8s without a reply marks the PD offline. If a Secure
 * Channel session was active, that session also ends and we fire
 * SESSION_LOST so the application knows to re-handshake. */
static void test_offline_during_established_fires_session_lost(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0}; reply_capture_t replies = {0};
    osdp_sc_session_t pd_session;
    run_handshake_and_mirror_pd(&acu, slots, &t, &m, &events, &replies,
                                &pd_session);
    events.call_count = 0;

    /* The mock transport's now_ms is read from m.now_ms; the run-
     * handshake helper above used now_ms == 0 throughout, so the
     * slot's last_reply_ms is 0. Advance the clock past the offline
     * threshold (8000 ms) and tick. */
    TEST_ASSERT_TRUE(osdp_acu_is_pd_online(&acu, PD_ADDRESS));
    m.now_ms = OSDP_ACU_OFFLINE_TIMEOUT_MS + 1U;
    osdp_acu_tick(&acu);

    TEST_ASSERT_FALSE(osdp_acu_is_pd_online(&acu, PD_ADDRESS));
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));
    TEST_ASSERT_EQUAL(1U, events.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_SESSION_LOST, events.last.kind);
}

/* If the line goes silent mid-handshake (after CHLNG, before CCRYPT
 * arrives), the timeout should fire HANDSHAKE_FAILED rather than
 * SESSION_LOST — there was nothing established to lose. */
static void test_offline_during_handshake_fires_handshake_failed(void)
{
    osdp_acu_t acu; osdp_acu_pd_slot_t slots[1];
    osdp_acu_transport_t t; mock_transport_t m;
    sc_event_capture_t events = {0};
    configure_acu_sc(&acu, slots, &t, &m, &events, NULL);

    /* Send CHLNG so phase becomes AWAITING_CCRYPT. */
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_acu_start_sc_handshake(&acu, PD_ADDRESS, false));
    /* Mark the slot online by faking a successful prior reply — the
     * offline scan only fires when the slot was online to begin with.
     * configure_acu_sc leaves online=false, but the handshake itself
     * doesn't transition us online (we haven't received any reply
     * yet). To exercise the offline path we need to flip online=true
     * directly. The test reaches into the slot here; that's fine for
     * an internal-state regression check. */
    slots[0].online        = true;
    slots[0].last_reply_ms = 0U;

    m.now_ms = OSDP_ACU_OFFLINE_TIMEOUT_MS + 1U;
    osdp_acu_tick(&acu);

    TEST_ASSERT_FALSE(osdp_acu_is_pd_online(&acu, PD_ADDRESS));
    TEST_ASSERT_FALSE(osdp_acu_is_pd_sc_established(&acu, PD_ADDRESS));
    TEST_ASSERT_EQUAL(1U, events.call_count);
    TEST_ASSERT_EQUAL(OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED, events.last.kind);
}

int main(void)
{
    UNITY_BEGIN();
    /* Phase 5a: handshake initiation. */
    RUN_TEST(test_start_handshake_emits_chlng_with_scbkd_selector);
    RUN_TEST(test_start_handshake_with_scbk_selector_one);
    RUN_TEST(test_start_handshake_rejected_without_crypto);
    RUN_TEST(test_start_handshake_rejected_without_key);
    RUN_TEST(test_start_handshake_rejected_unknown_pd);
    RUN_TEST(test_full_handshake_fires_established_event);
    RUN_TEST(test_handshake_fails_on_bad_client_cryptogram);
    RUN_TEST(test_handshake_fails_on_pd_status_0xff);
    /* Phase 5b: operational SC. */
    RUN_TEST(test_send_command_after_handshake_empty_payload_uses_scs_15);
    RUN_TEST(test_send_command_after_handshake_with_payload_uses_scs_17);
    RUN_TEST(test_inbound_scs_16_ack_reaches_reply_cb_as_plaintext);
    RUN_TEST(test_inbound_scs_18_reply_decrypts_into_reply_cb);
    RUN_TEST(test_mac_failure_terminates_session_and_fires_event);
    RUN_TEST(test_plain_reply_during_established_terminates_session);
    RUN_TEST(test_send_command_after_session_loss_uses_plaintext);
    /* Additional session-loss triggers (spec 5.9 + 5.7). */
    RUN_TEST(test_sqn_zero_plain_reply_during_established_resets);
    RUN_TEST(test_sqn_zero_sc_reply_during_established_resets);
    RUN_TEST(test_offline_during_established_fires_session_lost);
    RUN_TEST(test_offline_during_handshake_fires_handshake_failed);
    return UNITY_END();
}
