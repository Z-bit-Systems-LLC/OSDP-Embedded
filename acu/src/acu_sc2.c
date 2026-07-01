// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* ACU-side OSDP-SC2 handshake + operational traffic, parallel to
 * acu_sc.c. Drives SCS_21..24 after osdp_acu_start_sc2_handshake and
 * transparently wraps/unwraps SCS_25..28 once ESTABLISHED.
 *
 *   SCS_21 osdp_CHLNG  (ACU→PD): RND.A[16], SCB selector 0x02.
 *   SCS_22 osdp_CCRYPT (PD→ACU): cUID[8] || RND.B[16] || ClientCrypto[32].
 *   SCS_23 osdp_SCRYPT (ACU→PD): ServerCryptogram[32].
 *   SCS_24 osdp_RMAC_I (PD→ACU): empty; SCB byte 0x02 ok / 0xFF fail.
 *
 * SC2 differs from SC1: keys derive from RND.A AND RND.B (so we derive
 * in the CCRYPT handler once RND.B is known); RMAC_I carries no payload;
 * the session is anti-replayed by a shared counter (seeded at 0), not a
 * rolling MAC chain; and the reply CODE is inside the GCM ciphertext, so
 * we deliver the DECRYPTED code, not frame->code. */

#include "acu_internal.h"

#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc2.h"

#include <string.h>

/* ---- Helpers ---------------------------------------------------------- */

static void reset_sc2_handshake(osdp_acu_pd_slot_t *slot, bool clear_session)
{
    slot->sc2_phase = OSDP_ACU_SC_IDLE;
    (void)memset(slot->sc2_rnd_a, 0, sizeof(slot->sc2_rnd_a));
    (void)memset(slot->sc2_rnd_b, 0, sizeof(slot->sc2_rnd_b));
    (void)memset(slot->sc2_cuid,  0, sizeof(slot->sc2_cuid));
    if (clear_session) {
        osdp_sc2_session_init(&slot->sc2_session);
    }
}

static void fire_sc_event(osdp_acu_t               *acu,
                          uint8_t                   pd_address,
                          osdp_acu_sc_event_kind_t  kind)
{
    if (acu->sc_event_cb == NULL) {
        return;
    }
    const osdp_acu_sc_event_t event = {
        .pd_address = pd_address,
        .kind       = kind,
    };
    acu->sc_event_cb(acu->sc_event_user, &event);
}

static uint32_t now_ms_or_zero(const osdp_acu_t *acu)
{
    if (acu->transport.now_ms == NULL) {
        return 0U;
    }
    return acu->transport.now_ms(acu->transport.user);
}

static uint8_t advance_sqn(uint8_t seq)
{
    return (seq >= 3U) ? 1U : (uint8_t)(seq + 1U);
}

/* Send a plaintext SC2 handshake command (CHLNG/SCRYPT): SCB length 3
 * with the 0x02 SC2 selector byte. */
static osdp_status_t send_sc2_cmd(osdp_acu_t          *acu,
                                  osdp_acu_pd_slot_t  *slot,
                                  uint8_t              scb_type,
                                  uint8_t              cmd_code,
                                  const uint8_t       *payload,
                                  size_t               payload_len)
{
    uint8_t selector = OSDP_SC2_SELECTOR;
    osdp_frame_t frame;
    (void)memset(&frame, 0, sizeof(frame));
    frame.address      = slot->address;
    frame.reply        = false;
    frame.sequence     = (uint8_t)(slot->next_seq & 0x03U);
    frame.integrity    = acu->integrity;
    frame.has_scb      = true;
    frame.scb_length   = (uint8_t)(OSDP_SCB_MIN_LEN + 1U);
    frame.scb_type     = scb_type;
    frame.scb_data     = &selector;
    frame.scb_data_len = 1U;
    frame.code         = cmd_code;
    frame.payload      = payload;
    frame.payload_len  = payload_len;

    size_t written = 0;
    osdp_status_t s = osdp_frame_build(&frame, acu->tx_buf,
                                       OSDP_ACU_TX_BUF_LEN, &written);
    if (s != OSDP_OK) {
        return s;
    }
    const int tx = acu->transport.write(acu->transport.user,
                                        acu->tx_buf, written);
    if (tx < 0 || (size_t)tx != written) {
        return OSDP_ERR_NOT_SUPPORTED;
    }

    slot->waiting         = true;
    slot->pending_seq     = frame.sequence;
    slot->pending_code    = cmd_code;
    slot->pending_sent_ms = now_ms_or_zero(acu);
    return OSDP_OK;
}

/* ---- Configuration check ---------------------------------------------- */

bool osdp_acu_internal_sc2_configured(const osdp_acu_t          *acu,
                                      const osdp_acu_pd_slot_t  *slot)
{
    if (acu == NULL || slot == NULL)             return false;
    if (!acu->sc2_crypto_set)                    return false;
    if (acu->sc2_crypto.kmac256 == NULL)         return false;
    if (acu->sc2_crypto.aes256_gcm_encrypt == NULL) return false;
    if (acu->sc2_crypto.aes256_gcm_decrypt == NULL) return false;
    if (acu->sc2_crypto.aes256_ecb_encrypt == NULL) return false;
    if (acu->sc2_crypto.rand_bytes == NULL)      return false;
    return slot->sc2_scbk_set;
}

/* ---- Step 1: send CHLNG (SCS_21) -------------------------------------- */

osdp_status_t osdp_acu_internal_send_chlng2(osdp_acu_t          *acu,
                                            osdp_acu_pd_slot_t  *slot)
{
    osdp_status_t s = acu->sc2_crypto.rand_bytes(acu->sc2_crypto.user,
                                                 slot->sc2_rnd_a,
                                                 OSDP_SC2_RND_LEN);
    if (s != OSDP_OK) {
        return s;
    }
    s = send_sc2_cmd(acu, slot, OSDP_SCS_21, OSDP_CMD_CHLNG,
                     slot->sc2_rnd_a, OSDP_SC2_RND_LEN);
    if (s != OSDP_OK) {
        return s;
    }
    slot->sc2_phase = OSDP_ACU_SC_AWAITING_CCRYPT;
    return OSDP_OK;
}

/* ---- Step 2: handle CCRYPT (SCS_22), send SCRYPT (SCS_23) ------------- */

void osdp_acu_internal_handle_ccrypt2(osdp_acu_t          *acu,
                                      osdp_acu_pd_slot_t  *slot,
                                      const osdp_frame_t  *frame)
{
    if (frame->sequence != slot->pending_seq) {
        return;  /* stale */
    }
    if (frame->code != OSDP_REPLY_CCRYPT ||
        frame->scb_data_len < 1U || frame->scb_data == NULL ||
        frame->scb_data[0] != OSDP_SC2_SELECTOR ||
        frame->payload_len !=
            (OSDP_SC2_CUID_LEN + OSDP_SC2_RND_LEN + OSDP_SC2_CRYPTOGRAM_LEN)) {
        slot->waiting = false;
        reset_sc2_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    const uint8_t *cuid  = &frame->payload[0];
    const uint8_t *rnd_b = &frame->payload[OSDP_SC2_CUID_LEN];
    const uint8_t *got_client =
        &frame->payload[OSDP_SC2_CUID_LEN + OSDP_SC2_RND_LEN];
    (void)memcpy(slot->sc2_cuid,  cuid,  OSDP_SC2_CUID_LEN);
    (void)memcpy(slot->sc2_rnd_b, rnd_b, OSDP_SC2_RND_LEN);

    osdp_sc2_session_keys_t keys;
    osdp_status_t s = osdp_sc2_derive_session_keys(
        &acu->sc2_crypto, slot->sc2_scbk,
        slot->sc2_rnd_a, slot->sc2_rnd_b, &keys);
    if (s != OSDP_OK) {
        slot->waiting = false;
        reset_sc2_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    uint8_t expected_client[OSDP_SC2_CRYPTOGRAM_LEN];
    s = osdp_sc2_client_cryptogram(&acu->sc2_crypto, keys.s_enc,
                                   slot->sc2_rnd_a, slot->sc2_rnd_b,
                                   expected_client);
    if (s != OSDP_OK ||
        memcmp(expected_client, got_client, OSDP_SC2_CRYPTOGRAM_LEN) != 0) {
        slot->waiting = false;
        reset_sc2_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    /* Stash keys for the operational path; session completes on RMAC_I. */
    slot->sc2_session.keys = keys;

    uint8_t server_crypto[OSDP_SC2_CRYPTOGRAM_LEN];
    s = osdp_sc2_server_cryptogram(&acu->sc2_crypto, keys.s_enc,
                                   slot->sc2_rnd_a, slot->sc2_rnd_b,
                                   server_crypto);
    if (s != OSDP_OK) {
        slot->waiting = false;
        reset_sc2_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    slot->next_seq = advance_sqn(slot->pending_seq);
    slot->waiting  = false;

    s = send_sc2_cmd(acu, slot, OSDP_SCS_23, OSDP_CMD_SCRYPT,
                     server_crypto, OSDP_SC2_CRYPTOGRAM_LEN);
    if (s != OSDP_OK) {
        reset_sc2_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }
    slot->sc2_phase = OSDP_ACU_SC_AWAITING_RMAC_I;
}

/* ---- Step 3: handle RMAC_I (SCS_24), fire ESTABLISHED ---------------- */

void osdp_acu_internal_handle_rmac_i2(osdp_acu_t          *acu,
                                      osdp_acu_pd_slot_t  *slot,
                                      const osdp_frame_t  *frame)
{
    if (frame->sequence != slot->pending_seq) {
        return;  /* stale */
    }
    if (frame->code != OSDP_REPLY_RMAC_I ||
        frame->scb_data_len < 1U || frame->scb_data == NULL ||
        frame->scb_data[0] != OSDP_SC2_STATUS_OK ||
        frame->payload_len != 0U) {
        slot->waiting = false;
        reset_sc2_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    /* Seed the shared session: counter 0, cUID for the nonce. */
    (void)memcpy(slot->sc2_session.cuid, slot->sc2_cuid, OSDP_SC2_CUID_LEN);
    slot->sc2_session.counter     = 0;
    slot->sc2_session.established  = true;

    slot->next_seq = advance_sqn(slot->pending_seq);
    slot->waiting  = false;
    slot->online        = true;
    slot->last_reply_ms = now_ms_or_zero(acu);

    slot->sc2_phase = OSDP_ACU_SC_ESTABLISHED;
    fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_ESTABLISHED);
}

/* ---- Session termination + operational reply handling ---------------- */

void osdp_acu_internal_terminate_sc2(osdp_acu_t          *acu,
                                     osdp_acu_pd_slot_t  *slot)
{
    if (slot == NULL) return;

    osdp_acu_sc_event_kind_t kind = OSDP_ACU_SC_EVENT_SESSION_LOST;
    bool fire = false;
    switch (slot->sc2_phase) {
    case OSDP_ACU_SC_ESTABLISHED:
        kind = OSDP_ACU_SC_EVENT_SESSION_LOST;
        fire = true;
        break;
    case OSDP_ACU_SC_AWAITING_CCRYPT:
    case OSDP_ACU_SC_AWAITING_RMAC_I:
        kind = OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED;
        fire = true;
        break;
    case OSDP_ACU_SC_IDLE:
    default:
        break;
    }

    slot->waiting  = false;
    slot->next_seq = 0U;
    reset_sc2_handshake(slot, /*clear_session*/ true);
    if (fire) {
        fire_sc_event(acu, slot->address, kind);
    }
}

void osdp_acu_internal_handle_sc2_reply(osdp_acu_t          *acu,
                                        osdp_acu_pd_slot_t  *slot,
                                        const osdp_frame_t  *frame)
{
    /* A SQN=0 reply during ESTABLISHED is a reset signal (spec 5.9). */
    if (frame->sequence == 0U) {
        osdp_acu_internal_terminate_sc2(acu, slot);
        return;
    }
    if (!slot->waiting || frame->sequence != slot->pending_seq) {
        return;
    }

    /* GCM-verify + decrypt. The reply code lives inside the ciphertext. */
    uint8_t reply_code = 0;
    uint8_t plaintext[OSDP_ACU_TX_BUF_LEN];
    size_t  plaintext_len = 0;
    osdp_status_t s = osdp_sc2_unwrap_frame(
        &acu->sc2_crypto, &slot->sc2_session, frame,
        &reply_code, plaintext, sizeof(plaintext), &plaintext_len);
    if (s != OSDP_OK) {
        /* Auth failure → encryption sync lost; tear down (spec D.1.4). */
        osdp_acu_internal_terminate_sc2(acu, slot);
        return;
    }

    /* Deliver via the shared path, but with the DECRYPTED reply code
     * (frame->code is a ciphertext byte for SCS_28). */
    osdp_frame_t decoded = *frame;
    decoded.code = reply_code;
    osdp_acu_internal_deliver_reply(acu, slot, &decoded,
                                    plaintext, plaintext_len);
}
