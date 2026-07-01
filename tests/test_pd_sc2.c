// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Tests for the PD-side Secure Channel 2 handshake (SCS_21..24) and
 * operational traffic (SCS_25..28). The PD's SC2 state lives in pd->sc2;
 * the application supplies a crypto vtable, a 32-byte SCBK, and a cUID.
 * The simulated ACU is built from the SC2 primitives (osdp_sc2_*), so
 * these tests exercise the real PD state machine end to end. */

#include "osdp/osdp_commands.h"
#include "osdp/osdp_crc.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc2.h"
#include "sc2_test_crypto.h"
#include "unity.h"

#include <string.h>

void setUp(void)
{
    sc2_test_crypto_seed_prng(0xA5A5F00Du);
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

/* ---- Fixtures ----------------------------------------------------------*/

static const uint8_t kSCBK[OSDP_SC2_KEY_LEN] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
};
static const uint8_t kCUID[OSDP_SC2_CUID_LEN] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
};
static const uint8_t kRndA[OSDP_SC2_RND_LEN] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
};

#define PD_ADDR 0x05u

static void configure_pd_sc2(osdp_pd_t *pd, mock_transport_t *m,
                             osdp_pd_transport_t *t)
{
    mock_init(m, t);
    osdp_pd_init(pd, PD_ADDR);
    osdp_pd_set_transport(pd, t);
    osdp_pd_set_sc2_crypto(pd, sc2_test_crypto());
    osdp_pd_set_sc2_scbk(pd, kSCBK);
    osdp_pd_set_sc2_cuid(pd, kCUID);
}

/* Inject an SC2 handshake command (SCB length 3: selector data byte). */
static void inject_sc2_handshake(mock_transport_t *m,
                                 uint8_t scb_type, uint8_t selector,
                                 uint8_t cmd_code,
                                 const uint8_t *payload, size_t payload_len,
                                 uint8_t sequence)
{
    osdp_frame_t f = {0};
    f.address      = PD_ADDR;
    f.sequence     = sequence;
    f.integrity    = OSDP_INTEGRITY_CRC;
    f.has_scb      = true;
    f.scb_length   = (uint8_t)(OSDP_SCB_MIN_LEN + 1U);
    f.scb_type     = scb_type;
    f.scb_data     = &selector;
    f.scb_data_len = 1;
    f.code         = cmd_code;
    f.payload      = payload;
    f.payload_len  = payload_len;

    uint8_t buf[OSDP_FRAME_MAX_LEN];
    size_t  built = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_build(&f, buf, sizeof(buf), &built));
    mock_reset_incoming(m);
    (void)memcpy(m->incoming, buf, built);
    m->incoming_len = built;
}

static void decode_first_outgoing(const mock_transport_t *m, osdp_frame_t *out)
{
    TEST_ASSERT_GREATER_OR_EQUAL(OSDP_FRAME_MIN_LEN_CKSUM, m->outgoing_len);
    TEST_ASSERT_EQUAL(OSDP_OK,
                      osdp_frame_decode(m->outgoing + OSDP_FRAME_MARK_LEN,
                                        m->outgoing_len - OSDP_FRAME_MARK_LEN,
                                        out));
}

/* ---- Handshake tests ---------------------------------------------------*/

static void test_unconfigured_pd_naks_sc2_frames(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    mock_init(&m, &t);
    osdp_pd_t pd;
    osdp_pd_init(&pd, PD_ADDR);
    osdp_pd_set_transport(&pd, &t);

    inject_sc2_handshake(&m, OSDP_SCS_21, OSDP_SC2_SELECTOR,
                         OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNSUPPORTED_SCB, reply.payload[0]);
    TEST_ASSERT_FALSE(osdp_pd_sc2_established(&pd));
}

static void test_chlng_yields_ccrypt(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);

    inject_sc2_handshake(&m, OSDP_SCS_21, OSDP_SC2_SELECTOR,
                         OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_TRUE(reply.reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_CCRYPT, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_22, reply.scb_type);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SC2_SELECTOR, reply.scb_data[0]);
    TEST_ASSERT_EQUAL_size_t(
        OSDP_SC2_CUID_LEN + OSDP_SC2_RND_LEN + OSDP_SC2_CRYPTOGRAM_LEN,
        reply.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(kCUID, reply.payload, OSDP_SC2_CUID_LEN);

    /* Client Cryptogram must match what the algorithm predicts. */
    const uint8_t *rnd_b = &reply.payload[OSDP_SC2_CUID_LEN];
    const uint8_t *got_client =
        &reply.payload[OSDP_SC2_CUID_LEN + OSDP_SC2_RND_LEN];
    osdp_sc2_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_derive_session_keys(sc2_test_crypto(), kSCBK, kRndA, rnd_b,
                                     &keys));
    uint8_t expected[OSDP_SC2_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_client_cryptogram(sc2_test_crypto(), keys.s_enc, kRndA, rnd_b,
                                   expected));
    TEST_ASSERT_EQUAL_MEMORY(expected, got_client, OSDP_SC2_CRYPTOGRAM_LEN);
    TEST_ASSERT_FALSE(osdp_pd_sc2_established(&pd));
}

static void test_chlng_wrong_selector_naks(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);

    /* Selector 0x01 is an SC1 device-key selector, not SC2. */
    inject_sc2_handshake(&m, OSDP_SCS_21, 0x01,
                         OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNSUPPORTED_SCB, reply.payload[0]);
}

/* Drive a full handshake, leaving the PD established and returning the
 * mirror ACU session (keys + cUID + counter 0). */
static void perform_sc2_handshake(osdp_pd_t *pd, mock_transport_t *m,
                                  osdp_sc2_session_t *acu_out)
{
    inject_sc2_handshake(m, OSDP_SCS_21, OSDP_SC2_SELECTOR,
                         OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(pd);
    osdp_frame_t ccrypt;
    decode_first_outgoing(m, &ccrypt);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_CCRYPT, ccrypt.code);

    uint8_t rnd_b[OSDP_SC2_RND_LEN];
    (void)memcpy(rnd_b, &ccrypt.payload[OSDP_SC2_CUID_LEN], OSDP_SC2_RND_LEN);

    osdp_sc2_session_keys_t keys;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_derive_session_keys(sc2_test_crypto(), kSCBK, kRndA, rnd_b,
                                     &keys));
    uint8_t server_crypto[OSDP_SC2_CRYPTOGRAM_LEN];
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_server_cryptogram(sc2_test_crypto(), keys.s_enc, kRndA, rnd_b,
                                   server_crypto));

    m->outgoing_len = 0;
    inject_sc2_handshake(m, OSDP_SCS_23, OSDP_SC2_SELECTOR,
                         OSDP_CMD_SCRYPT, server_crypto,
                         sizeof(server_crypto), 2);
    osdp_pd_tick(pd);
    osdp_frame_t rmac_i;
    decode_first_outgoing(m, &rmac_i);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RMAC_I, rmac_i.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_24, rmac_i.scb_type);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SC2_STATUS_OK, rmac_i.scb_data[0]);
    TEST_ASSERT_EQUAL_size_t(0, rmac_i.payload_len);
    TEST_ASSERT_TRUE(osdp_pd_sc2_established(pd));

    osdp_sc2_session_init(acu_out);
    acu_out->keys = keys;
    (void)memcpy(acu_out->cuid, kCUID, OSDP_SC2_CUID_LEN);
    acu_out->counter     = 0;
    acu_out->established  = true;

    m->outgoing_len = 0;
}

static void test_full_handshake_establishes_session(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);

    osdp_sc2_session_t acu;
    perform_sc2_handshake(&pd, &m, &acu);
    TEST_ASSERT_TRUE(osdp_pd_sc2_established(&pd));
    TEST_ASSERT_EQUAL_UINT32(0u, pd.sc2.session.counter);
    TEST_ASSERT_EQUAL_MEMORY(kCUID, pd.sc2.session.cuid, OSDP_SC2_CUID_LEN);
}

static void test_scrypt_bad_cryptogram_status_fail(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);

    inject_sc2_handshake(&m, OSDP_SCS_21, OSDP_SC2_SELECTOR,
                         OSDP_CMD_CHLNG, kRndA, sizeof(kRndA), 1);
    osdp_pd_tick(&pd);
    m.outgoing_len = 0;

    static const uint8_t wrong[OSDP_SC2_CRYPTOGRAM_LEN] = {0xFF};
    inject_sc2_handshake(&m, OSDP_SCS_23, OSDP_SC2_SELECTOR,
                         OSDP_CMD_SCRYPT, wrong, sizeof(wrong), 2);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_RMAC_I, reply.code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SC2_STATUS_FAIL, reply.scb_data[0]);
    TEST_ASSERT_FALSE(osdp_pd_sc2_established(&pd));
}

static void test_scrypt_without_chlng_naks(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);

    static const uint8_t fake[OSDP_SC2_CRYPTOGRAM_LEN] = {0};
    inject_sc2_handshake(&m, OSDP_SCS_23, OSDP_SC2_SELECTOR,
                         OSDP_CMD_SCRYPT, fake, sizeof(fake), 1);
    osdp_pd_tick(&pd);

    osdp_frame_t reply;
    decode_first_outgoing(&m, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, reply.code);
    TEST_ASSERT_FALSE(osdp_pd_sc2_established(&pd));
}

/* ---- Operational tests -------------------------------------------------*/

static const uint8_t kSamplePdid[12] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0x01, 0x02, 0x03, 0x04,
};

static osdp_status_t sc2_app_handler(void *user, uint8_t cmd_code,
                                     const uint8_t *payload,
                                     size_t payload_len,
                                     osdp_pd_reply_t *reply)
{
    (void)user; (void)payload; (void)payload_len;
    switch (cmd_code) {
    case OSDP_CMD_POLL:
        reply->code = OSDP_REPLY_ACK; reply->payload = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    case OSDP_CMD_ID:
        reply->code = OSDP_REPLY_PDID; reply->payload = kSamplePdid;
        reply->payload_len = sizeof(kSamplePdid);
        return OSDP_OK;
    default:
        return OSDP_ERR_NOT_SUPPORTED;
    }
}

/* Wrap a command on the ACU side, feed it to the PD, and decode the
 * PD's reply frame. */
static void acu_send(mock_transport_t *m, osdp_pd_t *pd,
                     osdp_sc2_session_t *acu, uint8_t scb_type,
                     uint8_t code, const uint8_t *payload, size_t plen,
                     uint8_t sequence, osdp_frame_t *reply_out)
{
    osdp_frame_t tmpl = {0};
    tmpl.address     = PD_ADDR;
    tmpl.sequence    = sequence;
    tmpl.integrity   = OSDP_INTEGRITY_CRC;
    tmpl.has_scb     = true;
    tmpl.scb_length  = OSDP_SCB_MIN_LEN;
    tmpl.scb_type    = scb_type;
    tmpl.code        = code;
    tmpl.payload     = plen ? payload : NULL;
    tmpl.payload_len = plen;

    uint8_t wire[128]; size_t wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_wrap_frame(sc2_test_crypto(), acu, &tmpl, wire, sizeof(wire),
                            &wire_len));
    mock_reset_incoming(m);
    (void)memcpy(m->incoming, wire, wire_len);
    m->incoming_len = wire_len;
    m->outgoing_len = 0;
    osdp_pd_tick(pd);
    decode_first_outgoing(m, reply_out);
}

static void test_operational_poll_yields_encrypted_ack(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc2_app_handler, NULL);

    osdp_sc2_session_t acu;
    perform_sc2_handshake(&pd, &m, &acu);

    osdp_frame_t reply;
    acu_send(&m, &pd, &acu, OSDP_SCS_27, OSDP_CMD_POLL, NULL, 0, 1, &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_28, reply.scb_type);

    uint8_t code = 0, plain[32]; size_t plen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_unwrap_frame(sc2_test_crypto(), &acu, &reply, &code,
                              plain, sizeof(plain), &plen));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, code);
    TEST_ASSERT_EQUAL_size_t(0, plen);
    /* Counters stayed in lockstep across the exchange. */
    TEST_ASSERT_EQUAL_UINT32(pd.sc2.session.counter, acu.counter);
}

static void test_operational_encrypted_id_round_trip(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc2_app_handler, NULL);

    osdp_sc2_session_t acu;
    perform_sc2_handshake(&pd, &m, &acu);

    static const uint8_t id_payload = 0x00;
    osdp_frame_t reply;
    acu_send(&m, &pd, &acu, OSDP_SCS_27, OSDP_CMD_ID, &id_payload, 1, 1,
             &reply);
    TEST_ASSERT_EQUAL_HEX8(OSDP_SCS_28, reply.scb_type);

    uint8_t code = 0, plain[32]; size_t plen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_unwrap_frame(sc2_test_crypto(), &acu, &reply, &code,
                              plain, sizeof(plain), &plen));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_PDID, code);
    TEST_ASSERT_EQUAL_size_t(sizeof(kSamplePdid), plen);
    TEST_ASSERT_EQUAL_MEMORY(kSamplePdid, plain, sizeof(kSamplePdid));
}

static void test_operational_unknown_cmd_yields_encrypted_nak(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc2_app_handler, NULL);

    osdp_sc2_session_t acu;
    perform_sc2_handshake(&pd, &m, &acu);

    static const uint8_t text_payload[] = {0, 1, 0, 1, 1, 0};
    osdp_frame_t reply;
    acu_send(&m, &pd, &acu, OSDP_SCS_27, OSDP_CMD_TEXT, text_payload,
             sizeof(text_payload), 1, &reply);

    uint8_t code = 0, plain[32]; size_t plen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_unwrap_frame(sc2_test_crypto(), &acu, &reply, &code,
                              plain, sizeof(plain), &plen));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, code);
    TEST_ASSERT_EQUAL_size_t(1, plen);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_UNKNOWN_CMD, plain[0]);
}

static void test_operational_tampered_tag_drops_silently(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, sc2_app_handler, NULL);

    osdp_sc2_session_t acu;
    perform_sc2_handshake(&pd, &m, &acu);

    osdp_frame_t tmpl = {0};
    tmpl.address    = PD_ADDR;
    tmpl.sequence   = 1;
    tmpl.integrity  = OSDP_INTEGRITY_CRC;
    tmpl.has_scb    = true;
    tmpl.scb_length = OSDP_SCB_MIN_LEN;
    tmpl.scb_type   = OSDP_SCS_27;
    tmpl.code       = OSDP_CMD_POLL;

    uint8_t wire[128]; size_t wire_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_wrap_frame(sc2_test_crypto(), &acu, &tmpl, wire, sizeof(wire),
                            &wire_len));
    /* Flip a tag byte and fix the CRC so the frame still decodes. */
    const size_t crc_off = wire_len - 2;
    wire[crc_off - 4] ^= 0x20;
    const uint16_t crc = osdp_crc16(wire + OSDP_FRAME_MARK_LEN,
                                    crc_off - OSDP_FRAME_MARK_LEN);
    wire[crc_off]     = (uint8_t)(crc & 0xFFu);
    wire[crc_off + 1] = (uint8_t)((crc >> 8) & 0xFFu);

    mock_reset_incoming(&m);
    (void)memcpy(m.incoming, wire, wire_len);
    m.incoming_len = wire_len;
    m.outgoing_len = 0;
    osdp_pd_tick(&pd);
    TEST_ASSERT_EQUAL_size_t(0, m.outgoing_len);
}

/* ---- KEYSET rotation under SC2 -----------------------------------------*/

static osdp_status_t keyset_handler(void *user, uint8_t cmd_code,
                                    const uint8_t *payload, size_t payload_len,
                                    osdp_pd_reply_t *reply)
{
    (void)user; (void)payload; (void)payload_len;
    switch (cmd_code) {
    case OSDP_CMD_POLL:
    case OSDP_CMD_KEYSET:
        reply->code = OSDP_REPLY_ACK; reply->payload = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    default:
        return OSDP_ERR_NOT_SUPPORTED;
    }
}

static void test_keyset_sc2_rotates_scbk_without_restart(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, keyset_handler, NULL);

    osdp_sc2_session_t acu;
    perform_sc2_handshake(&pd, &m, &acu);

    /* KEYSET payload: type 0x02, length 0x20, 32 new key bytes. */
    uint8_t new_key[OSDP_SC2_KEY_LEN];
    for (unsigned i = 0; i < OSDP_SC2_KEY_LEN; i++) {
        new_key[i] = (uint8_t)(0x50u + i);
    }
    uint8_t ks_payload[2 + OSDP_SC2_KEY_LEN];
    ks_payload[0] = OSDP_KEYSET_KEY_TYPE_SCBK_AES256;
    ks_payload[1] = OSDP_SC2_KEY_LEN;
    (void)memcpy(&ks_payload[2], new_key, OSDP_SC2_KEY_LEN);

    osdp_frame_t reply;
    acu_send(&m, &pd, &acu, OSDP_SCS_27, OSDP_CMD_KEYSET,
             ks_payload, sizeof(ks_payload), 1, &reply);

    uint8_t code = 0, plain[32]; size_t plen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_unwrap_frame(sc2_test_crypto(), &acu, &reply, &code,
                              plain, sizeof(plain), &plen));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_ACK, code);
    /* SCBK rotated in place; live session still up. */
    TEST_ASSERT_EQUAL_MEMORY(new_key, pd.sc2.scbk, OSDP_SC2_KEY_LEN);
    TEST_ASSERT_TRUE(osdp_pd_sc2_established(&pd));
}

static void test_keyset_sc2_wrong_length_naks(void)
{
    mock_transport_t m;
    osdp_pd_transport_t t;
    osdp_pd_t pd;
    configure_pd_sc2(&pd, &m, &t);
    osdp_pd_set_command_handler(&pd, keyset_handler, NULL);

    osdp_sc2_session_t acu;
    perform_sc2_handshake(&pd, &m, &acu);

    /* Type 0x02 but a 16-byte key — invalid for AES-256. */
    uint8_t ks_payload[2 + 16];
    ks_payload[0] = OSDP_KEYSET_KEY_TYPE_SCBK_AES256;
    ks_payload[1] = 16;
    (void)memset(&ks_payload[2], 0x11, 16);

    osdp_frame_t reply;
    acu_send(&m, &pd, &acu, OSDP_SCS_27, OSDP_CMD_KEYSET,
             ks_payload, sizeof(ks_payload), 1, &reply);

    uint8_t code = 0, plain[32]; size_t plen = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc2_unwrap_frame(sc2_test_crypto(), &acu, &reply, &code,
                              plain, sizeof(plain), &plen));
    TEST_ASSERT_EQUAL_HEX8(OSDP_REPLY_NAK, code);
    TEST_ASSERT_EQUAL_HEX8(OSDP_NAK_RECORD_INVALID, plain[0]);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_unconfigured_pd_naks_sc2_frames);
    RUN_TEST(test_chlng_yields_ccrypt);
    RUN_TEST(test_chlng_wrong_selector_naks);
    RUN_TEST(test_full_handshake_establishes_session);
    RUN_TEST(test_scrypt_bad_cryptogram_status_fail);
    RUN_TEST(test_scrypt_without_chlng_naks);
    RUN_TEST(test_operational_poll_yields_encrypted_ack);
    RUN_TEST(test_operational_encrypted_id_round_trip);
    RUN_TEST(test_operational_unknown_cmd_yields_encrypted_nak);
    RUN_TEST(test_operational_tampered_tag_drops_silently);
    RUN_TEST(test_keyset_sc2_rotates_scbk_without_restart);
    RUN_TEST(test_keyset_sc2_wrong_length_naks);
    return UNITY_END();
}
