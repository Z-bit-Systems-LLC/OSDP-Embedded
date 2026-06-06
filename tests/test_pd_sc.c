// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Tests for the PD-side Secure Channel handshake (SCS_11..14).
 *
 * The PD's SC state lives in pd->sc; the application bootstraps it by
 * supplying a crypto vtable, an SCBK and/or SCBK-D, and a cUID. Once
 * configured, the PD answers inbound CHLNG/SCRYPT commands, generates
 * RND.B from the crypto vtable's RNG, computes the Client Cryptogram
 * and Initial R-MAC, and ends in `session.established = true` ready
 * for SCS_15..18 traffic in subsequent commits. */

#include "osdp/osdp_commands.h"
#include "osdp/osdp_crc.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"
#include "sc_test_aes.h"
#include "unity.h"

#include <string.h>

void setUp(void)
{
    /* Reset the test PRNG to a fixed seed so tests get the same RND.B. */
    sc_test_crypto_seed_prng(0xDEADBEEFu);
}
void tearDown(void) {}

/* ---- Mock transport ----------------------------------------------------*/

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
    /* Defensive: if a test resets incoming_len without resetting
     * incoming_off, the unsigned subtraction would wrap and we'd
     * read past the end of m->incoming. Clamp here. */
    if (m->incoming_off > m->incoming_len) {
        return 0;
    }
    const size_t avail = m->incoming_len - m->incoming_off;
    const size_t n = (cap < avail) ? cap : avail;
    if (n > 0) {
        (void)memcpy(buf, &m->incoming[m->incoming_off], n);
        m->incoming_off += n;
    }
    return (int)n;
}

/* Reset the mock's incoming buffer to a clean slate before pushing
 * fresh bytes for the next test step. */
static void mock_reset_incoming(mock_transport_t *m)
{
    m->incoming_len = 0;
    m->incoming_off = 0;
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

static void mock_init(mock_transport_t *m, osdp_pd_transport_t *t)
{
    (void)memset(m, 0, sizeof(*m));
    t->read   = mock_read;
    t->write  = mock_write;
    t->now_ms = mock_now_ms;
    t->user   = m;
}

/* ---- Test fixtures -----------------------------------------------------*/

static const uint8_t kSCBK_D[OSDP_SC_KEY_LEN] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};
static const uint8_t kSCBK[OSDP_SC_KEY_LEN] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
};
static const uint8_t kCUID[OSDP_SC_CUID_LEN] = {
    0xCA, 0xFE, 0x00, 0x10, 0x01, 0xEF, 0xBE, 0xAD,
};
static const uint8_t kRndA[OSDP_SC_RND_LEN] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
};

/* ---- Helpers -----------------------------------------------------------*/

/* Set up a PD with all SC config (both SCBK and SCBK-D) so tests can
 * pick which one to use via the CHLNG selector byte. */
static void configure_pd_sc(osdp_pd_t *pd, mock_transport_t *m,
                            osdp_pd_transport_t *t)
{
    mock_init(m, t);
    osdp_pd_init(pd, 0x05);
    osdp_pd_set_transport(pd, t);
    osdp_pd_set_sc_crypto(pd, sc_test_crypto_tiny_aes());
    osdp_pd_set_sc_scbk  (pd, kSCBK);
    osdp_pd_set_sc_scbk_d(pd, kSCBK_D);
    osdp_pd_set_sc_cuid  (pd, kCUID);
}

/* Inject a SCB-bearing command at the given SCB type / data byte
 * with the supplied payload. */
static void inject_sc_command(mock_transport_t *m,
                              uint8_t scb_type, uint8_t scb_data_byte,
                              uint8_t cmd_code,
                              const uint8_t *payload, size_t payload_len,
                              uint8_t sequence)
{
    osdp_frame_t f = {0};
    f.address      = 0x05;
    f.reply        = false;
    f.sequence     = sequence;
    f.integrity    = OSDP_INTEGRITY_CRC;
    f.has_scb      = true;
    f.scb_length   = (uint8_t)(OSDP_SCB_MIN_LEN + 1U);
    f.scb_type     = scb_type;
    f.scb_data     = &scb_data_byte;
    f.scb_data_len = 1;
    f.code         = cmd_code;
    f.payload      = payload;
    f.payload_len  = payload_len;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_build(&f, buf, sizeof(buf), &built));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(MOCK_BUF_LEN - m->incoming_len, built);
    (void)memcpy(&m->incoming[m->incoming_len], buf, built);
    m->incoming_len += built;
}

static void decode_first_outgoing(const mock_transport_t *m,
                                  osdp_frame_t *out)
{
    TEST_ASSERT_GREATER_OR_EQUAL(OSDP_FRAME_MIN_LEN_CKSUM, m->outgoing_len);
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_decode(m->outgoing, m->outgoing_len, out));
}

/* ---- Tests --------------------------------------------------------------*/

static void test_unconfigured_pd_still_naks_sc_frames(void)
{
    /* No SC configuration → existing NAK 0x05 behaviour. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);

    inject_sc_command(&m, OSDP_SCS_11, /*selector*/ 0,
                      OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNSUPPORTED_SCB, reply.payload[0]);
    TEST_ASSERT_FALSE(osdp_pd_sc_established(&pd));
}

static void test_chlng_yields_ccrypt_reply(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);

    inject_sc_command(&m, OSDP_SCS_11, /*selector*/ 0  /* SCBK-D */,
                      OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_TRUE(reply.reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_CCRYPT, reply.code);
    TEST_ASSERT_TRUE(reply.has_scb);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_12, reply.scb_type);
    TEST_ASSERT_EQUAL_size_t(1, reply.scb_data_len);
    TEST_ASSERT_EQUAL_HEX8(0, reply.scb_data[0]);  /* selector echoed */
    TEST_ASSERT_EQUAL_size_t(
        OSDP_SC_CUID_LEN + OSDP_SC_RND_LEN + OSDP_SC_CRYPTOGRAM_LEN,
        reply.payload_len);
    /* First 8 bytes of payload are our cUID. */
    TEST_ASSERT_EQUAL_MEMORY(kCUID, reply.payload, OSDP_SC_CUID_LEN);

    /* Verify the Client Cryptogram is exactly what the algorithm
     * predicts: derive S-ENC ourselves and run the cryptogram. */
    const uint8_t *rnd_b = &reply.payload[OSDP_SC_CUID_LEN];
    const uint8_t *got_client = &reply.payload[OSDP_SC_CUID_LEN +
                                               OSDP_SC_RND_LEN];
    osdp_sc_session_keys_t expected_keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(sc_test_crypto_tiny_aes(),
                                    kSCBK_D, kRndA, &expected_keys));
    uint8_t expected_client[OSDP_SC_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_client_cryptogram(sc_test_crypto_tiny_aes(),
                                  expected_keys.s_enc,
                                  kRndA, rnd_b, expected_client));
    TEST_ASSERT_EQUAL_MEMORY(expected_client, got_client,
                             OSDP_SC_CRYPTOGRAM_LEN);

    /* Session is not yet established — only after SCRYPT. */
    TEST_ASSERT_FALSE(osdp_pd_sc_established(&pd));
}

static void test_full_handshake_establishes_session(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);

    /* Step 1: CHLNG. */
    inject_sc_command(&m, OSDP_SCS_11, /*selector*/ 1 /* SCBK */,
                      OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(&pd);

    /* Decode CCRYPT. */
    osdp_frame_t ccrypt;
    decode_first_outgoing(&m, &ccrypt);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_CCRYPT, ccrypt.code);

    uint8_t rnd_b[OSDP_SC_RND_LEN];
    (void)memcpy(rnd_b, &ccrypt.payload[OSDP_SC_CUID_LEN], OSDP_SC_RND_LEN);

    /* Compute Server Cryptogram with SCBK to send to the PD. */
    osdp_sc_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(sc_test_crypto_tiny_aes(),
                                    kSCBK, kRndA, &keys));
    uint8_t server_crypto[OSDP_SC_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_server_cryptogram(sc_test_crypto_tiny_aes(),
                                  keys.s_enc,
                                  kRndA, rnd_b, server_crypto));

    /* Step 2: SCRYPT. Clear the outgoing buffer first so we see only
     * the new RMAC_I reply. */
    m.outgoing_len = 0;
    inject_sc_command(&m, OSDP_SCS_13, /*selector*/ 1,
                      OSDP_CMD_SCRYPT, server_crypto,
                      sizeof(server_crypto), 2);
    osdp_pd_tick(&pd);

    osdp_frame_t rmac_i;
    decode_first_outgoing(&m, &rmac_i);
    TEST_ASSERT_TRUE(rmac_i.reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RMAC_I, rmac_i.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_14, rmac_i.scb_type);
    TEST_ASSERT_EQUAL_HEX8(0x01, rmac_i.scb_data[0]);  /* status = ok */
    TEST_ASSERT_EQUAL_size_t(OSDP_SC_MAC_LEN, rmac_i.payload_len);

    /* Verify the R-MAC is what the algorithm predicts. */
    uint8_t expected_rmac[OSDP_SC_MAC_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_initial_rmac(sc_test_crypto_tiny_aes(),
                             keys.s_mac1, keys.s_mac2,
                             server_crypto, expected_rmac));
    TEST_ASSERT_EQUAL_MEMORY(expected_rmac, rmac_i.payload, OSDP_SC_MAC_LEN);

    /* Session is now established and seeded with the Initial R-MAC. */
    TEST_ASSERT_TRUE(osdp_pd_sc_established(&pd));
    TEST_ASSERT_EQUAL_MEMORY(expected_rmac, pd.sc.session.last_outbound_mac,
                             OSDP_SC_MAC_LEN);
    TEST_ASSERT_EQUAL_MEMORY(expected_rmac, pd.sc.session.last_inbound_mac,
                             OSDP_SC_MAC_LEN);
}

static void test_scrypt_without_chlng_naks(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);

    static const uint8_t fake_server_crypto[OSDP_SC_CRYPTOGRAM_LEN] = {0};
    inject_sc_command(&m, OSDP_SCS_13, 1, OSDP_CMD_SCRYPT,
                      fake_server_crypto, sizeof(fake_server_crypto), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_FALSE(osdp_pd_sc_established(&pd));
}

static void test_chlng_with_unconfigured_key_selector_naks(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x05);
    osdp_pd_set_transport(&pd, &t);
    osdp_pd_set_sc_crypto(&pd, sc_test_crypto_tiny_aes());
    /* Configure ONLY SCBK-D, not SCBK. */
    osdp_pd_set_sc_scbk_d(&pd, kSCBK_D);
    osdp_pd_set_sc_cuid  (&pd, kCUID);

    /* CHLNG with selector = 1 (SCBK) — but SCBK isn't set. */
    inject_sc_command(&m, OSDP_SCS_11, /*selector*/ 1,
                      OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNSUPPORTED_SCB, reply.payload[0]);
}

static void test_chlng_with_wrong_payload_length_naks(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);

    /* RND.A of 7 bytes (should be 8). */
    static const uint8_t short_rnd[7] = {1,2,3,4,5,6,7};
    inject_sc_command(&m, OSDP_SCS_11, 0, OSDP_CMD_CHLNG,
                      short_rnd, sizeof(short_rnd), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_CMD_LENGTH, reply.payload[0]);
}

static void test_scrypt_with_bad_cryptogram_yields_status_failure(void)
{
    /* Per spec D.1.3.4: if Server Cryptogram doesn't verify, the PD
     * sends RMAC_I with SCB data byte 0xFF and does not establish
     * the session. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);

    /* Step 1: CHLNG (so the PD gets to "got_chlng" state). */
    inject_sc_command(&m, OSDP_SCS_11, 0, OSDP_CMD_CHLNG,
                      kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(&pd);
    m.outgoing_len = 0;

    /* Step 2: SCRYPT with deliberately-wrong cryptogram. */
    static const uint8_t wrong[OSDP_SC_CRYPTOGRAM_LEN] = {0xFF};
    inject_sc_command(&m, OSDP_SCS_13, 0, OSDP_CMD_SCRYPT,
                      wrong, sizeof(wrong), 2);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RMAC_I, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_14, reply.scb_type);
    TEST_ASSERT_EQUAL_HEX8(0xFF, reply.scb_data[0]);  /* failure status */
    TEST_ASSERT_FALSE(osdp_pd_sc_established(&pd));
}

static void test_scs_15_pre_established_returns_unsupported(void)
{
    /* Without an established session, SCS_15..18 traffic NAKs (the
     * handshake must complete first). */
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);

    static const uint8_t mac_only[OSDP_FRAME_MAC_LEN] = {0};
    /* Build SCS_15 frame manually. */
    osdp_frame_t f = {0};
    f.address      = 0x05;
    f.integrity    = OSDP_INTEGRITY_CRC;
    f.sequence     = 1;
    f.has_scb      = true;
    f.scb_length   = OSDP_SCB_MIN_LEN;
    f.scb_type     = OSDP_SCS_15;
    f.code         = OSDP_CMD_POLL;
    f.mac          = mac_only;
    f.mac_len      = OSDP_FRAME_MAC_LEN;
    uint8_t buf[64]; size_t built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &built));
    (void)memcpy(m.incoming, buf, built);
    m.incoming_len = built;

    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNSUPPORTED_SCB, reply.payload[0]);
}

/* ---- Phase 3b: operational SCS_15..18 ---------------------------------- */

/* Run a full handshake on the PD and return the simulated ACU's
 * mirror session afterward. Useful as a setup for operational tests. */
static void perform_handshake(osdp_pd_t *pd, mock_transport_t *m,
                              uint8_t selector,
                              osdp_sc_session_t *acu_session_out)
{
    /* CHLNG → CCRYPT */
    inject_sc_command(m, OSDP_SCS_11, selector,
                      OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(pd);
    osdp_frame_t ccrypt;
    decode_first_outgoing(m, &ccrypt);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_CCRYPT, ccrypt.code);
    uint8_t rnd_b[OSDP_SC_RND_LEN];
    (void)memcpy(rnd_b, &ccrypt.payload[OSDP_SC_CUID_LEN], OSDP_SC_RND_LEN);

    /* Compute Server Cryptogram on the ACU side. */
    const uint8_t *key = (selector == 1) ? kSCBK : kSCBK_D;
    osdp_sc_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_derive_session_keys(sc_test_crypto_tiny_aes(),
                                    key, kRndA, &keys));
    uint8_t server_crypto[OSDP_SC_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_server_cryptogram(sc_test_crypto_tiny_aes(),
                                  keys.s_enc, kRndA, rnd_b, server_crypto));

    /* SCRYPT → RMAC_I */
    m->outgoing_len = 0;
    inject_sc_command(m, OSDP_SCS_13, selector,
                      OSDP_CMD_SCRYPT, server_crypto,
                      sizeof(server_crypto), 2);
    osdp_pd_tick(pd);
    osdp_frame_t rmac_i;
    decode_first_outgoing(m, &rmac_i);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RMAC_I, rmac_i.code);
    TEST_ASSERT_TRUE(osdp_pd_sc_established(pd));

    /* Build the ACU's mirror session: same keys, both MAC chain
     * entries seeded with the same Initial R-MAC. */
    osdp_sc_session_init(acu_session_out);
    acu_session_out->keys = keys;
    (void)memcpy(acu_session_out->last_outbound_mac,
                 rmac_i.payload, OSDP_SC_MAC_LEN);
    (void)memcpy(acu_session_out->last_inbound_mac,
                 rmac_i.payload, OSDP_SC_MAC_LEN);
    acu_session_out->established = true;

    /* Clear outgoing for clean per-test setup. */
    m->outgoing_len = 0;
}

/* Application handler for SC operational tests: ACK for POLL,
 * a fixed osdp_PDID-style payload for ID, otherwise NOT_SUPPORTED. */
static const uint8_t kSamplePdid[12] = {
    0xCA, 0xFE, 0x00, 0x10, 0x01,
    0xEF, 0xBE, 0xAD, 0xDE,
    0x01, 0x02, 0x03,
};

static osdp_status_t sc_app_handler(void *user, uint8_t cmd_code,
                                    const uint8_t *payload,
                                    size_t payload_len,
                                    osdp_pd_reply_t *reply)
{
    (void)user; (void)payload; (void)payload_len;
    switch (cmd_code) {
    case OSDP_CMD_POLL:
        reply->code        = OSDP_REPLY_ACK;
        reply->payload     = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    case OSDP_CMD_ID:
        reply->code        = OSDP_REPLY_PDID;
        reply->payload     = kSamplePdid;
        reply->payload_len = sizeof(kSamplePdid);
        return OSDP_OK;
    default:
        return OSDP_ERR_NOT_SUPPORTED;
    }
}

static void test_scs_15_round_trip_yields_scs_16_ack(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);

    /* ACU builds a SCS_15 POLL: empty payload, MAC over header+code. */
    osdp_frame_t cmd_template;
    (void)memset(&cmd_template, 0, sizeof(cmd_template));
    cmd_template.address     = 0x05;
    cmd_template.integrity   = OSDP_INTEGRITY_CRC;
    cmd_template.sequence    = 3;
    cmd_template.has_scb     = true;
    cmd_template.scb_length  = OSDP_SCB_MIN_LEN;
    cmd_template.scb_type    = OSDP_SCS_15;
    cmd_template.code        = OSDP_CMD_POLL;

    uint8_t cmd_wire[64]; size_t cmd_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &cmd_template,
                           cmd_wire, sizeof(cmd_wire), &cmd_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, cmd_wire, cmd_wire_len);
    m.incoming_len = cmd_wire_len;

    osdp_pd_tick(&pd);

    /* Decode the PD's reply and verify it's a well-formed SCS_16 ACK. */
    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_TRUE(reply.reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_16, reply.scb_type);
    TEST_ASSERT_EQUAL_size_t(OSDP_FRAME_MAC_LEN, reply.mac_len);

    /* Unwrap on the ACU side; expect the inner code to be ACK. */
    uint8_t plain[64]; size_t plain_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu, &reply,
                             plain, sizeof(plain), &plain_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_size_t(0, plain_len);
}

static void test_scs_17_encrypted_round_trip(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);

    /* ACU builds a SCS_17 ID command (1-byte ID type payload). */
    static const uint8_t id_payload = 0x00;
    osdp_frame_t cmd_template;
    (void)memset(&cmd_template, 0, sizeof(cmd_template));
    cmd_template.address     = 0x05;
    cmd_template.integrity   = OSDP_INTEGRITY_CRC;
    cmd_template.sequence    = 3;
    cmd_template.has_scb     = true;
    cmd_template.scb_length  = OSDP_SCB_MIN_LEN;
    cmd_template.scb_type    = OSDP_SCS_17;
    cmd_template.code        = OSDP_CMD_ID;
    cmd_template.payload     = &id_payload;
    cmd_template.payload_len = 1;

    uint8_t cmd_wire[64]; size_t cmd_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &cmd_template,
                           cmd_wire, sizeof(cmd_wire), &cmd_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, cmd_wire, cmd_wire_len);
    m.incoming_len = cmd_wire_len;

    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_18, reply.scb_type);

    uint8_t plain[64]; size_t plain_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu, &reply,
                             plain, sizeof(plain), &plain_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDID, reply.code);
    TEST_ASSERT_EQUAL_size_t(sizeof(kSamplePdid), plain_len);
    TEST_ASSERT_EQUAL_MEMORY(kSamplePdid, plain, sizeof(kSamplePdid));
}

static void test_scs_15_unknown_command_yields_scs_18_nak(void)
{
    /* Send a TEXT command under SCS_15. The default handler doesn't know
     * TEXT, so the PD replies NAK. The NAK carries a 1-byte reason
     * payload, so it is data-bearing and the wrap step picks the
     * encrypted variant SCS_18 (CLAUDE.md SC conventions; wrap.c coerces
     * only *empty* replies down to SCS_16). */
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 0, &acu);

    static const uint8_t text_payload[] = {0,1,0,1,1,0};
    osdp_frame_t cmd_template;
    (void)memset(&cmd_template, 0, sizeof(cmd_template));
    cmd_template.address     = 0x05;
    cmd_template.integrity   = OSDP_INTEGRITY_CRC;
    cmd_template.sequence    = 3;
    cmd_template.has_scb     = true;
    cmd_template.scb_length  = OSDP_SCB_MIN_LEN;
    cmd_template.scb_type    = OSDP_SCS_15;
    cmd_template.code        = OSDP_CMD_TEXT;
    cmd_template.payload     = text_payload;
    cmd_template.payload_len = sizeof(text_payload);

    uint8_t cmd_wire[64]; size_t cmd_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &cmd_template,
                           cmd_wire, sizeof(cmd_wire), &cmd_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, cmd_wire, cmd_wire_len);
    m.incoming_len = cmd_wire_len;

    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_18, reply.scb_type);

    uint8_t plain[16]; size_t plain_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu, &reply,
                             plain, sizeof(plain), &plain_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_size_t(1, plain_len);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, plain[0]);
}

static void test_scs_15_with_tampered_mac_drops_silently(void)
{
    /* Per spec D.6, MAC mismatch on inbound frames is recovered by
     * the ACU re-issuing — the PD shouldn't talk back with a wrong-
     * chain MAC. Verify: corrupt the inbound MAC byte; PD writes no
     * outgoing bytes. */
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);

    osdp_frame_t cmd_template;
    (void)memset(&cmd_template, 0, sizeof(cmd_template));
    cmd_template.address    = 0x05;
    cmd_template.integrity  = OSDP_INTEGRITY_CRC;
    cmd_template.sequence   = 3;
    cmd_template.has_scb    = true;
    cmd_template.scb_length = OSDP_SCB_MIN_LEN;
    cmd_template.scb_type   = OSDP_SCS_15;
    cmd_template.code       = OSDP_CMD_POLL;

    uint8_t cmd_wire[64]; size_t cmd_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &cmd_template,
                           cmd_wire, sizeof(cmd_wire), &cmd_wire_len));
    /* Flip a bit in the MAC and recompute CRC so the frame still
     * decodes at Layer 1. */
    const size_t crc_offset = cmd_wire_len - 2;
    const size_t mac_offset = crc_offset - OSDP_FRAME_MAC_LEN;
    cmd_wire[mac_offset] ^= 0x10;
    const uint16_t crc = osdp_crc16(cmd_wire, crc_offset);
    cmd_wire[crc_offset]     = (uint8_t)(crc & 0xFFu);
    cmd_wire[crc_offset + 1] = (uint8_t)((crc >> 8) & 0xFFu);

    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, cmd_wire, cmd_wire_len);
    m.incoming_len = cmd_wire_len;
    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);
}

/* ---- Regression: SQN-cache must compare bytes, not just SQN -------------
 *
 * Reproduces the failure observed against OSDP.Net's ACUConsole on
 * 2026-05-04: under certain conditions the ACU sends two consecutive
 * commands with the SAME SQN — once after the wraparound 3→1, then
 * again with 1 because its own state-reset path doesn't increment SQN.
 * The PD's retransmit cache (spec 5.9) was matching on SQN ALONE, so
 * the second frame (a different command with the same SQN) hit the
 * cache and replayed the stale reply from the previous command. The
 * ACU saw a wrong-type reply and the SC chain broke for ~8 seconds
 * until its offline timeout fired and it restarted the handshake.
 *
 * Spec 5.9: a retransmit has IDENTICAL wire bytes to the original.
 * Two different commands with the same SQN are NOT retransmits; the
 * PD must process the second one fresh. The cache must therefore
 * compare wire bytes (or at minimum the command code + SCB), not
 * just SQN. */
static void test_scs_15_different_cmd_same_sqn_processes_fresh(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);

    /* Command #1: POLL under SCS_15 with SQN=1. */
    osdp_frame_t poll1;
    (void)memset(&poll1, 0, sizeof(poll1));
    poll1.address    = 0x05;
    poll1.integrity  = OSDP_INTEGRITY_CRC;
    poll1.sequence   = 1;
    poll1.has_scb    = true;
    poll1.scb_length = OSDP_SCB_MIN_LEN;
    poll1.scb_type   = OSDP_SCS_15;
    poll1.code       = OSDP_CMD_POLL;

    uint8_t poll1_wire[64]; size_t poll1_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &poll1,
                           poll1_wire, sizeof(poll1_wire), &poll1_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, poll1_wire, poll1_wire_len);
    m.incoming_len = poll1_wire_len;
    osdp_pd_tick(&pd);
    /* Decode and verify-unwrap the ACK so the simulated ACU's chain
     * advances exactly as a real ACU's would. */
    osdp_frame_t poll1_reply;
    decode_first_outgoing(&m, &poll1_reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_16, poll1_reply.scb_type);
    uint8_t ack1_plain[16]; size_t ack1_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu,
                             &poll1_reply, ack1_plain, sizeof(ack1_plain),
                             &ack1_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, poll1_reply.code);
    m.outgoing_len = 0;

    /* Command #2: same SQN=1 but different code (LSTAT instead of POLL).
     * This simulates the ACUConsole behaviour: same SQN as the previous
     * command, but the bytes are clearly different. The PD must NOT
     * treat this as a retransmit — it must process LSTAT fresh and
     * emit a SCS_16 NAK 0x03. */
    osdp_frame_t lstat;
    (void)memset(&lstat, 0, sizeof(lstat));
    lstat.address    = 0x05;
    lstat.integrity  = OSDP_INTEGRITY_CRC;
    lstat.sequence   = 1;       /* same SQN as the prior POLL */
    lstat.has_scb    = true;
    lstat.scb_length = OSDP_SCB_MIN_LEN;
    lstat.scb_type   = OSDP_SCS_15;
    lstat.code       = OSDP_CMD_LSTAT;

    uint8_t lstat_wire[64]; size_t lstat_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &lstat,
                           lstat_wire, sizeof(lstat_wire), &lstat_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, lstat_wire, lstat_wire_len);
    m.incoming_len = lstat_wire_len;
    osdp_pd_tick(&pd);

    /* The PD must speak — and must not parrot the cached POLL/ACK. */
    TEST_ASSERT_GREATER_THAN_size_t(0, m.outgoing_len);
    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    /* NAK carries a 1-byte reason payload, so the wrap step picks
     * the encrypted variant (SCS_18) even though the inbound LSTAT
     * came in as SCS_15. See wrap.c — payload presence dictates the
     * SCB type. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_18, reply.scb_type);
    uint8_t plain[16]; size_t plain_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu, &reply,
                             plain, sizeof(plain), &plain_len));
    /* If the SQN-only cache fired, this would still be ACK (the cached
     * POLL reply). With the bytes-comparison fix, it's a fresh NAK 0x03
     * for the unknown LSTAT command. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK,        reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD,  plain[0]);
}

/* ---- Regression: empty reply to SCS_17 cmd uses SCS_16 ------------------
 *
 * Reproduces the failure observed against OSDP.Net's ACUConsole on
 * 2026-05-04: the ACU sends an osdp_OUT under SCS_17 (encrypted, with
 * the 16-byte output-control payload), expecting an osdp_ACK reply.
 * Our PD was wrapping the empty ACK as SCS_18, which produces 16 bytes
 * of all-padding ciphertext (one 0x80 byte plus 15 zero bytes,
 * encrypted). OSDP.Net's depad logic in IncomingMessage.cs treats that
 * 0-byte case as a depad failure and rejects the reply, freezing the
 * SCS chain at the previous SQN.
 *
 * Per spec D.1.4 ("SCS_17 and SCS_18 also include encrypted message
 * DATA"), the encrypted-payload SCB types are reserved for messages
 * with actual data to encrypt. Empty replies (ACK, etc.) belong under
 * SCS_16 even when the command came in under SCS_17. The PD's MAC
 * chain still rolls correctly either way, but SCS_16 is more spec-
 * aligned and interoperates with OSDP.Net. */
static void test_scs_17_cmd_with_empty_reply_uses_scs_16(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);

    /* SCS_17-wrapped POLL: SQN=3, no payload from the cmd side either,
     * but the SCB type is SCS_17 (encrypted). Our default test handler
     * returns ACK with no payload — the empty case. */
    osdp_frame_t cmd_template;
    (void)memset(&cmd_template, 0, sizeof(cmd_template));
    cmd_template.address    = 0x05;
    cmd_template.integrity  = OSDP_INTEGRITY_CRC;
    cmd_template.sequence   = 3;
    cmd_template.has_scb    = true;
    cmd_template.scb_length = OSDP_SCB_MIN_LEN;
    cmd_template.scb_type   = OSDP_SCS_17;
    cmd_template.code       = OSDP_CMD_POLL;

    uint8_t cmd_wire[64]; size_t cmd_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &cmd_template,
                           cmd_wire, sizeof(cmd_wire), &cmd_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, cmd_wire, cmd_wire_len);
    m.incoming_len = cmd_wire_len;
    osdp_pd_tick(&pd);

    /* Decode the reply. The PD must have used SCS_16 (not SCS_18) for
     * the empty ACK, even though the inbound was SCS_17. */
    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_16, reply.scb_type);
    /* Plain (no encryption): payload is right there as the wire bytes,
     * and for an ACK that means zero. */
    TEST_ASSERT_EQUAL_size_t(0, reply.payload_len);

    /* And the chain still works — verify the ACU side can unwrap it. */
    uint8_t plain[16]; size_t plain_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu, &reply,
                             plain, sizeof(plain), &plain_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_size_t(0, plain_len);
}

/* ---- Regression: post-NAK chain stays in sync ----------------------------
 *
 * Companion to the bytes-vs-SQN test above. After the PD emits a NAK
 * for an unknown command, the rolling MAC chain has to be in sync for
 * the NEXT (different) command — same scenario, different angle. */
static void test_scs_15_nak_then_valid_poll_chains_correctly(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);

    /* Step 1: send an unknown command — TEXT — under SCS_15 with SQN=3.
     * The handler does not implement TEXT, so we expect a SCS_16 NAK. */
    static const uint8_t text_payload[] = {0,1,0,1,1,0};
    osdp_frame_t bad_cmd;
    (void)memset(&bad_cmd, 0, sizeof(bad_cmd));
    bad_cmd.address     = 0x05;
    bad_cmd.integrity   = OSDP_INTEGRITY_CRC;
    bad_cmd.sequence    = 3;
    bad_cmd.has_scb     = true;
    bad_cmd.scb_length  = OSDP_SCB_MIN_LEN;
    bad_cmd.scb_type    = OSDP_SCS_15;
    bad_cmd.code        = OSDP_CMD_TEXT;
    bad_cmd.payload     = text_payload;
    bad_cmd.payload_len = sizeof(text_payload);

    uint8_t bad_wire[64]; size_t bad_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &bad_cmd,
                           bad_wire, sizeof(bad_wire), &bad_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, bad_wire, bad_wire_len);
    m.incoming_len = bad_wire_len;
    osdp_pd_tick(&pd);

    /* Decode and unwrap the NAK on the ACU side so its chain advances.
     * NAK has a 1-byte reason payload, so wrap picks the encrypted
     * variant (SCS_18) regardless of the inbound SCS_15. */
    osdp_frame_t nak_reply;
    decode_first_outgoing(&m, &nak_reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_18, nak_reply.scb_type);
    uint8_t nak_plain[16]; size_t nak_plain_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu, &nak_reply,
                             nak_plain, sizeof(nak_plain), &nak_plain_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK,        nak_reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD,  nak_plain[0]);

    /* Clear the outgoing buffer so the next assertion sees only the
     * follow-up reply, not the NAK we just consumed. */
    m.outgoing_len = 0;

    /* Step 2: send a valid POLL with SQN=0 (next SQN per spec wraparound
     * 3 → 0 → 1 ...; ACUConsole observed in the wild uses SQN bits
     * 0x0e here, which is SQN=2 — the absolute value doesn't matter
     * for this test, only that it differs from the NAK's SQN). The
     * PD must reply SCS_16 ACK and the wrap chain must verify. */
    osdp_frame_t poll_cmd;
    (void)memset(&poll_cmd, 0, sizeof(poll_cmd));
    poll_cmd.address    = 0x05;
    poll_cmd.integrity  = OSDP_INTEGRITY_CRC;
    poll_cmd.sequence   = 0;
    poll_cmd.has_scb    = true;
    poll_cmd.scb_length = OSDP_SCB_MIN_LEN;
    poll_cmd.scb_type   = OSDP_SCS_15;
    poll_cmd.code       = OSDP_CMD_POLL;

    uint8_t poll_wire[64]; size_t poll_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &poll_cmd,
                           poll_wire, sizeof(poll_wire), &poll_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, poll_wire, poll_wire_len);
    m.incoming_len = poll_wire_len;
    osdp_pd_tick(&pd);

    /* The PD must speak. If we silently drop here, the live ACU times
     * out and restarts the whole SC session. */
    TEST_ASSERT_GREATER_THAN_size_t(0, m.outgoing_len);

    osdp_frame_t ack_reply;
    decode_first_outgoing(&m, &ack_reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_16, ack_reply.scb_type);

    uint8_t ack_plain[16]; size_t ack_plain_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu, &ack_reply,
                             ack_plain, sizeof(ack_plain), &ack_plain_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, ack_reply.code);
    TEST_ASSERT_EQUAL_size_t(0, ack_plain_len);
}

/* ---- KEYSET runtime rotation -----------------------------------------*/

/* App handler that ACKs everything the spec baseline supports — including
 * KEYSET. The library applies the new SCBK after this returns OSDP_OK. */
static osdp_status_t keyset_friendly_handler(void                 *user,
                                             uint8_t               cmd_code,
                                             const uint8_t        *payload,
                                             size_t                payload_len,
                                             osdp_pd_reply_t      *reply)
{
    (void)user; (void)payload; (void)payload_len;
    switch (cmd_code) {
    case OSDP_CMD_POLL:
    case OSDP_CMD_KEYSET:
        reply->code        = OSDP_REPLY_ACK;
        reply->payload     = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    default:
        return OSDP_ERR_NOT_SUPPORTED;
    }
}

/* Send a SCS_17 KEYSET carrying a valid 16-byte SCBK under an
 * established session, expect SCS_16 ACK, and verify that:
 *   - pd->sc.scbk now equals the new key (rotation actually applied);
 *   - the live session keys are unchanged (no force-restart);
 *   - pd_sc_established() still returns true.
 *
 * This is the behavior the user asked for: rotate the stored SCBK
 * without forcing the ACU to re-handshake mid-session. */
static void test_keyset_under_sc_rotates_scbk_without_restart(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, keyset_friendly_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);
    TEST_ASSERT_TRUE(osdp_pd_sc_established(&pd));

    /* Capture session keys + counters before the KEYSET — they must
     * survive the rotation untouched. */
    uint8_t s_enc_before [OSDP_SC_KEY_LEN];
    uint8_t s_mac1_before[OSDP_SC_KEY_LEN];
    uint8_t s_mac2_before[OSDP_SC_KEY_LEN];
    (void)memcpy(s_enc_before,  pd.sc.session.keys.s_enc,  OSDP_SC_KEY_LEN);
    (void)memcpy(s_mac1_before, pd.sc.session.keys.s_mac1, OSDP_SC_KEY_LEN);
    (void)memcpy(s_mac2_before, pd.sc.session.keys.s_mac2, OSDP_SC_KEY_LEN);

    /* The new SCBK that the ACU is rotating us to. Deliberately
     * different from kSCBK / kSCBK_D so the assertion below is sharp. */
    static const uint8_t kNewSCBK[OSDP_SC_KEY_LEN] = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    };

    uint8_t keyset_payload[OSDP_KEYSET_HEADER_BYTES + OSDP_SC_KEY_LEN];
    keyset_payload[0] = OSDP_KEYSET_KEY_TYPE_SCBK;
    keyset_payload[1] = OSDP_SC_KEY_LEN;
    (void)memcpy(&keyset_payload[2], kNewSCBK, OSDP_SC_KEY_LEN);

    osdp_frame_t cmd_template;
    (void)memset(&cmd_template, 0, sizeof(cmd_template));
    cmd_template.address     = 0x05;
    cmd_template.integrity   = OSDP_INTEGRITY_CRC;
    cmd_template.sequence    = 3;
    cmd_template.has_scb     = true;
    cmd_template.scb_length  = OSDP_SCB_MIN_LEN;
    cmd_template.scb_type    = OSDP_SCS_17;
    cmd_template.code        = OSDP_CMD_KEYSET;
    cmd_template.payload     = keyset_payload;
    cmd_template.payload_len = sizeof(keyset_payload);

    uint8_t cmd_wire[128]; size_t cmd_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &cmd_template,
                           cmd_wire, sizeof(cmd_wire), &cmd_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, cmd_wire, cmd_wire_len);
    m.incoming_len = cmd_wire_len;

    osdp_pd_tick(&pd);

    /* Reply: SCS_16 ACK (empty payload → unencrypted SCS_16 variant). */
    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_16, reply.scb_type);
    uint8_t plain[16]; size_t plain_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu, &reply,
                             plain, sizeof(plain), &plain_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
    TEST_ASSERT_EQUAL_size_t(0, plain_len);

    /* The whole point of this test: the rotated key is in pd.sc.scbk
     * and the session state is unchanged. */
    TEST_ASSERT_TRUE(pd.sc.scbk_set);
    TEST_ASSERT_EQUAL_MEMORY(kNewSCBK, pd.sc.scbk, OSDP_SC_KEY_LEN);
    TEST_ASSERT_EQUAL_MEMORY(s_enc_before,  pd.sc.session.keys.s_enc,  OSDP_SC_KEY_LEN);
    TEST_ASSERT_EQUAL_MEMORY(s_mac1_before, pd.sc.session.keys.s_mac1, OSDP_SC_KEY_LEN);
    TEST_ASSERT_EQUAL_MEMORY(s_mac2_before, pd.sc.session.keys.s_mac2, OSDP_SC_KEY_LEN);
    TEST_ASSERT_TRUE(osdp_pd_sc_established(&pd));
}

/* If the ACU sends a KEYSET with a malformed payload (wrong length,
 * unsupported key_type, etc.), the library overrides the app handler's
 * ACK with a NAK so the ACU sees the failure. The stored SCBK must be
 * left untouched — corrupting it on a bad write would brick the PD. */
static void test_keyset_with_malformed_payload_naks_and_preserves_scbk(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, keyset_friendly_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);

    uint8_t scbk_before[OSDP_SC_KEY_LEN];
    (void)memcpy(scbk_before, pd.sc.scbk, OSDP_SC_KEY_LEN);

    /* Header says 16-byte key but payload only carries 4 bytes — the
     * decoder rejects this. */
    static const uint8_t lying_payload[6] = { 0x01, 0x10, 1, 2, 3, 4 };

    osdp_frame_t cmd_template;
    (void)memset(&cmd_template, 0, sizeof(cmd_template));
    cmd_template.address     = 0x05;
    cmd_template.integrity   = OSDP_INTEGRITY_CRC;
    cmd_template.sequence    = 3;
    cmd_template.has_scb     = true;
    cmd_template.scb_length  = OSDP_SCB_MIN_LEN;
    cmd_template.scb_type    = OSDP_SCS_17;
    cmd_template.code        = OSDP_CMD_KEYSET;
    cmd_template.payload     = lying_payload;
    cmd_template.payload_len = sizeof(lying_payload);

    uint8_t cmd_wire[64]; size_t cmd_wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_wrap_frame(sc_test_crypto_tiny_aes(), &acu, &cmd_template,
                           cmd_wire, sizeof(cmd_wire), &cmd_wire_len));
    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, cmd_wire, cmd_wire_len);
    m.incoming_len = cmd_wire_len;

    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    uint8_t plain[16]; size_t plain_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_unwrap_frame(sc_test_crypto_tiny_aes(), &acu, &reply,
                             plain, sizeof(plain), &plain_len));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_size_t(1, plain_len);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_RECORD_INVALID, plain[0]);

    /* Stored SCBK must NOT have changed. */
    TEST_ASSERT_EQUAL_MEMORY(scbk_before, pd.sc.scbk, OSDP_SC_KEY_LEN);
}

/* ---- Regression: clear-text SQN 0 drops a stale SC session -------------
 *
 * Mirrors OSDP.Net commit 02e478476. A clear-text command at sequence 0
 * means the ACU is (re)starting the connection, so any established Secure
 * Channel session is stale: the PD must drop it and answer the ACU's
 * rediscovery (osdp_CAP / osdp_ID) in the clear until a fresh handshake
 * runs. A *secure* frame at sequence 0 is part of a handshake and must
 * NOT trigger the drop; a non-zero-sequence clear-text command must leave
 * the session intact. */

static void inject_plaintext_command(mock_transport_t *m, uint8_t cmd_code,
                                     const uint8_t *payload, size_t payload_len,
                                     uint8_t sequence)
{
    osdp_frame_t f = {0};
    f.address     = 0x05;
    f.reply       = false;
    f.sequence    = sequence;
    f.integrity   = OSDP_INTEGRITY_CRC;
    f.has_scb     = false;
    f.code        = cmd_code;
    f.payload     = payload;
    f.payload_len = payload_len;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_frame_build(&f, buf, sizeof(buf), &built));
    mock_reset_incoming(m);
    (void)memcpy(m->incoming, buf, built);
    m->incoming_len = built;
}

static void test_cleartext_sqn0_drops_established_session(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);
    TEST_ASSERT_TRUE(osdp_pd_sc_established(&pd));

    /* Clear-text POLL at SQN 0 → ACU restart → drop the session. */
    m.outgoing_len = 0;
    inject_plaintext_command(&m, OSDP_CMD_POLL, NULL, 0, /*sequence*/ 0);
    osdp_pd_tick(&pd);

    TEST_ASSERT_FALSE(osdp_pd_sc_established(&pd));

    /* The PD still answers the POLL in the clear. */
    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_FALSE(reply.has_scb);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
}

static void test_cleartext_nonzero_sqn_keeps_session(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    osdp_sc_session_t acu;
    perform_handshake(&pd, &m, /*selector*/ 1, &acu);
    TEST_ASSERT_TRUE(osdp_pd_sc_established(&pd));

    /* Clear-text POLL at SQN 2 is NOT a restart signal; the session
     * stays established. */
    m.outgoing_len = 0;
    inject_plaintext_command(&m, OSDP_CMD_POLL, NULL, 0, /*sequence*/ 2);
    osdp_pd_tick(&pd);

    TEST_ASSERT_TRUE(osdp_pd_sc_established(&pd));
}

static void test_cleartext_sqn0_on_unsecured_is_noop(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc_app_handler, NULL);

    /* No handshake performed: session not established. A SQN-0 command
     * must be a clean no-op and still get its normal clear-text ACK. */
    TEST_ASSERT_FALSE(osdp_pd_sc_established(&pd));
    inject_plaintext_command(&m, OSDP_CMD_POLL, NULL, 0, /*sequence*/ 0);
    osdp_pd_tick(&pd);

    TEST_ASSERT_FALSE(osdp_pd_sc_established(&pd));
    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, reply.code);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_unconfigured_pd_still_naks_sc_frames);
    RUN_TEST(test_chlng_yields_ccrypt_reply);
    RUN_TEST(test_full_handshake_establishes_session);
    RUN_TEST(test_scrypt_without_chlng_naks);
    RUN_TEST(test_chlng_with_unconfigured_key_selector_naks);
    RUN_TEST(test_chlng_with_wrong_payload_length_naks);
    RUN_TEST(test_scrypt_with_bad_cryptogram_yields_status_failure);
    RUN_TEST(test_scs_15_pre_established_returns_unsupported);
    /* Phase 3b: operational SCS_15..18. */
    RUN_TEST(test_scs_15_round_trip_yields_scs_16_ack);
    RUN_TEST(test_scs_17_encrypted_round_trip);
    RUN_TEST(test_scs_15_unknown_command_yields_scs_18_nak);
    RUN_TEST(test_scs_15_with_tampered_mac_drops_silently);
    /* Regression: same-SQN-different-bytes must process fresh. */
    RUN_TEST(test_scs_15_different_cmd_same_sqn_processes_fresh);
    /* Regression: empty reply to SCS_17 cmd uses SCS_16, not SCS_18. */
    RUN_TEST(test_scs_17_cmd_with_empty_reply_uses_scs_16);
    /* Regression: post-NAK chain. */
    RUN_TEST(test_scs_15_nak_then_valid_poll_chains_correctly);
    /* KEYSET runtime rotation. */
    RUN_TEST(test_keyset_under_sc_rotates_scbk_without_restart);
    RUN_TEST(test_keyset_with_malformed_payload_naks_and_preserves_scbk);
    /* Regression: clear-text SQN 0 drops a stale SC session. */
    RUN_TEST(test_cleartext_sqn0_drops_established_session);
    RUN_TEST(test_cleartext_nonzero_sqn_keeps_session);
    RUN_TEST(test_cleartext_sqn0_on_unsecured_is_noop);
    return UNITY_END();
}
