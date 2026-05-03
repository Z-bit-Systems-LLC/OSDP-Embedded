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
    /* Until phase 3b lands, SCS_15..18 traffic returns NAK 0x05 even
     * when SC is configured but the session isn't established. This
     * keeps the PD's handshake-only first cut clean. */
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
    return UNITY_END();
}
