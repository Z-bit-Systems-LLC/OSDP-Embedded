// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* ACU-side Secure Channel handshake — phase 5a.
 *
 * Drives the SCS_11..14 sequence after the application calls
 * osdp_acu_start_sc_handshake. The handshake is fire-and-forget: the
 * caller doesn't block; the ACU consumes CCRYPT (SCS_12) and RMAC_I
 * (SCS_14) replies internally as they arrive on subsequent ticks, and
 * fires the application's sc_event_cb on either successful
 * establishment or cryptographic failure. CCRYPT and RMAC_I never
 * appear in the application's reply_cb stream.
 *
 * Spec references:
 *   D.1.3.1 SCS_11 (ACU→PD): osdp_CHLNG, payload = RND.A[8].
 *   D.1.3.2 SCS_12 (PD→ACU): osdp_CCRYPT, payload = cUID(8) ||
 *                            RND.B(8) || ClientCryptogram(16).
 *   D.1.3.3 SCS_13 (ACU→PD): osdp_SCRYPT, payload = ServerCryptogram.
 *   D.1.3.4 SCS_14 (PD→ACU): osdp_RMAC_I, payload = Initial R-MAC,
 *                            sec_blk_data[0] = 0x01 (ok) or 0xFF (fail). */

#include "acu_internal.h"

#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"

#include <string.h>

/* ---- Helpers ---------------------------------------------------------- */

/* Pick the active key for this slot's currently-requested handshake
 * mode. Returns NULL if the requested key hasn't been set. */
static const uint8_t *select_key(const osdp_acu_pd_slot_t *slot,
                                 bool                      use_default_key)
{
    if (use_default_key) {
        return slot->scbk_d_set ? slot->scbk_d : NULL;
    }
    return slot->scbk_set ? slot->scbk : NULL;
}

/* Reset a slot's SC handshake-in-progress fields (RND.A, RND.B, etc.)
 * back to IDLE. Leaves the configured keys + the established
 * sc_session intact unless `clear_session` is true. */
static void reset_sc_handshake(osdp_acu_pd_slot_t *slot, bool clear_session)
{
    slot->sc_phase = OSDP_ACU_SC_IDLE;
    (void)memset(slot->sc_rnd_a, 0, sizeof(slot->sc_rnd_a));
    (void)memset(slot->sc_rnd_b, 0, sizeof(slot->sc_rnd_b));
    (void)memset(slot->sc_cuid,  0, sizeof(slot->sc_cuid));
    if (clear_session) {
        osdp_sc_session_init(&slot->sc_session);
    }
}

static void fire_sc_event(osdp_acu_t                    *acu,
                          uint8_t                        pd_address,
                          osdp_acu_sc_event_kind_t       kind)
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

/* Build a SCB-bearing handshake command (SCS_11 or SCS_13) into
 * acu->tx_buf and write it to the transport. Marks the slot as
 * waiting on a reply with the given pending state. */
static osdp_status_t send_sc_cmd(osdp_acu_t          *acu,
                                 osdp_acu_pd_slot_t  *slot,
                                 uint8_t              scb_type,
                                 uint8_t              key_selector_byte,
                                 uint8_t              cmd_code,
                                 const uint8_t       *payload,
                                 size_t               payload_len)
{
    osdp_frame_t frame;
    (void)memset(&frame, 0, sizeof(frame));
    frame.address      = slot->address;
    frame.reply        = false;
    frame.sequence     = (uint8_t)(slot->next_seq & 0x03U);
    frame.integrity    = acu->integrity;
    frame.has_scb      = true;
    frame.scb_length   = (uint8_t)(OSDP_SCB_MIN_LEN + 1U);
    frame.scb_type     = scb_type;
    frame.scb_data     = &key_selector_byte;
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

    slot->waiting        = true;
    slot->pending_seq    = frame.sequence;
    slot->pending_code   = cmd_code;
    slot->pending_sent_ms = now_ms_or_zero(acu);
    return OSDP_OK;
}

/* ---- Configuration check ---------------------------------------------- */

bool osdp_acu_internal_sc_configured(const osdp_acu_t          *acu,
                                     const osdp_acu_pd_slot_t  *slot,
                                     bool                       use_default_key)
{
    if (acu == NULL || slot == NULL) return false;
    if (!acu->sc_crypto_set)         return false;
    if (acu->sc_crypto.aes128_ecb_encrypt == NULL) return false;
    if (acu->sc_crypto.rand_bytes == NULL)         return false;
    if (use_default_key) return slot->scbk_d_set;
    return slot->scbk_set;
}

/* ---- Step 1: send CHLNG ---------------------------------------------- */

osdp_status_t osdp_acu_internal_send_chlng(osdp_acu_t          *acu,
                                           osdp_acu_pd_slot_t  *slot,
                                           bool                 use_default_key)
{
    /* Generate RND.A. */
    osdp_status_t s = acu->sc_crypto.rand_bytes(acu->sc_crypto.user,
                                                slot->sc_rnd_a,
                                                OSDP_SC_RND_LEN);
    if (s != OSDP_OK) {
        return s;
    }
    slot->sc_key_selector = (uint8_t)(use_default_key ? 0U : 1U);

    s = send_sc_cmd(acu, slot,
                    OSDP_SCS_11,
                    slot->sc_key_selector,
                    OSDP_CMD_CHLNG,
                    slot->sc_rnd_a, OSDP_SC_RND_LEN);
    if (s != OSDP_OK) {
        return s;
    }
    slot->sc_phase = OSDP_ACU_SC_AWAITING_CCRYPT;
    return OSDP_OK;
}

/* ---- Step 2: handle CCRYPT, send SCRYPT ------------------------------ */

void osdp_acu_internal_handle_ccrypt(osdp_acu_t          *acu,
                                     osdp_acu_pd_slot_t  *slot,
                                     const osdp_frame_t  *frame)
{
    /* Reply must echo the CHLNG sequence number; otherwise it's a
     * stale frame from a previous handshake that we should ignore. */
    if (frame->sequence != slot->pending_seq) {
        return;
    }
    /* Frame layout sanity. */
    if (frame->code != OSDP_REPLY_CCRYPT ||
        frame->scb_data_len < 1U || frame->scb_data == NULL ||
        frame->payload_len !=
            (OSDP_SC_CUID_LEN + OSDP_SC_RND_LEN + OSDP_SC_CRYPTOGRAM_LEN)) {
        slot->waiting = false;
        reset_sc_handshake(slot, /*clear_session*/ true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }
    /* Key selector must echo what we sent with CHLNG. */
    if (frame->scb_data[0] != slot->sc_key_selector) {
        slot->waiting = false;
        reset_sc_handshake(slot, /*clear_session*/ true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    /* Pull cUID and RND.B from the payload. */
    const uint8_t *cuid  = &frame->payload[0];
    const uint8_t *rnd_b = &frame->payload[OSDP_SC_CUID_LEN];
    const uint8_t *got_client =
        &frame->payload[OSDP_SC_CUID_LEN + OSDP_SC_RND_LEN];
    (void)memcpy(slot->sc_cuid,  cuid,  OSDP_SC_CUID_LEN);
    (void)memcpy(slot->sc_rnd_b, rnd_b, OSDP_SC_RND_LEN);

    /* Derive session keys from the active SCBK + RND.A. */
    const uint8_t *key = (slot->sc_key_selector == 1U)
                            ? slot->scbk : slot->scbk_d;
    osdp_sc_session_keys_t keys;
    osdp_status_t s = osdp_sc_derive_session_keys(&acu->sc_crypto, key,
                                                  slot->sc_rnd_a, &keys);
    if (s != OSDP_OK) {
        slot->waiting = false;
        reset_sc_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    /* Verify the PD's Client Cryptogram matches what we'd compute. */
    uint8_t expected_client[OSDP_SC_CRYPTOGRAM_LEN];
    s = osdp_sc_client_cryptogram(&acu->sc_crypto, keys.s_enc,
                                  slot->sc_rnd_a, slot->sc_rnd_b,
                                  expected_client);
    if (s != OSDP_OK ||
        memcmp(expected_client, got_client, OSDP_SC_CRYPTOGRAM_LEN) != 0) {
        slot->waiting = false;
        reset_sc_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    /* Stash session keys for the operational path; we still need to
     * complete RMAC_I before the session is ESTABLISHED. */
    slot->sc_session.keys = keys;

    /* Compute Server Cryptogram and send SCRYPT. */
    uint8_t server_crypto[OSDP_SC_CRYPTOGRAM_LEN];
    s = osdp_sc_server_cryptogram(&acu->sc_crypto, keys.s_enc,
                                  slot->sc_rnd_a, slot->sc_rnd_b,
                                  server_crypto);
    if (s != OSDP_OK) {
        slot->waiting = false;
        reset_sc_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    /* Reply received; advance SQN. send_sc_cmd will set waiting again
     * for the SCRYPT we're about to issue. */
    slot->next_seq = (slot->pending_seq >= 3U) ? 1U
                     : (uint8_t)(slot->pending_seq + 1U);
    slot->waiting  = false;

    s = send_sc_cmd(acu, slot,
                    OSDP_SCS_13,
                    slot->sc_key_selector,
                    OSDP_CMD_SCRYPT,
                    server_crypto, OSDP_SC_CRYPTOGRAM_LEN);
    if (s != OSDP_OK) {
        reset_sc_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }
    slot->sc_phase = OSDP_ACU_SC_AWAITING_RMAC_I;
}

/* ---- Step 3: handle RMAC_I, fire ESTABLISHED ------------------------- */

void osdp_acu_internal_handle_rmac_i(osdp_acu_t          *acu,
                                     osdp_acu_pd_slot_t  *slot,
                                     const osdp_frame_t  *frame)
{
    if (frame->sequence != slot->pending_seq) {
        return;  /* stale */
    }
    if (frame->code != OSDP_REPLY_RMAC_I ||
        frame->scb_data_len < 1U || frame->scb_data == NULL) {
        slot->waiting = false;
        reset_sc_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    /* Per spec D.1.3.4, sec_blk_data[0] = 0x01 means ok, 0xFF means
     * the PD rejected the Server Cryptogram. */
    const uint8_t status = frame->scb_data[0];
    if (status != 0x01U) {
        slot->waiting = false;
        reset_sc_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }
    if (frame->payload_len != OSDP_SC_MAC_LEN) {
        slot->waiting = false;
        reset_sc_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    /* Compute expected Initial R-MAC ourselves and compare. The MAC is
     * Enc(S-MAC2, Enc(S-MAC1, ServerCryptogram)). We have the keys and
     * we recompute the Server Cryptogram from RND.A + RND.B + S-ENC. */
    uint8_t server_crypto[OSDP_SC_CRYPTOGRAM_LEN];
    osdp_status_t s = osdp_sc_server_cryptogram(
        &acu->sc_crypto, slot->sc_session.keys.s_enc,
        slot->sc_rnd_a, slot->sc_rnd_b, server_crypto);
    if (s != OSDP_OK) {
        slot->waiting = false;
        reset_sc_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }
    uint8_t expected_rmac[OSDP_SC_MAC_LEN];
    s = osdp_sc_initial_rmac(&acu->sc_crypto,
                             slot->sc_session.keys.s_mac1,
                             slot->sc_session.keys.s_mac2,
                             server_crypto, expected_rmac);
    if (s != OSDP_OK ||
        memcmp(expected_rmac, frame->payload, OSDP_SC_MAC_LEN) != 0) {
        slot->waiting = false;
        reset_sc_handshake(slot, true);
        fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED);
        return;
    }

    /* Seed the rolling chain on both sides with the Initial R-MAC. */
    (void)memcpy(slot->sc_session.last_outbound_mac,
                 expected_rmac, OSDP_SC_MAC_LEN);
    (void)memcpy(slot->sc_session.last_inbound_mac,
                 expected_rmac, OSDP_SC_MAC_LEN);
    slot->sc_session.established = true;

    /* Reply received; advance SQN past the SCRYPT one so the next
     * operational command starts cleanly. */
    slot->next_seq = (slot->pending_seq >= 3U) ? 1U
                     : (uint8_t)(slot->pending_seq + 1U);
    slot->waiting  = false;

    /* Refresh online tracking — the PD just answered. */
    slot->online        = true;
    slot->last_reply_ms = now_ms_or_zero(acu);

    slot->sc_phase = OSDP_ACU_SC_ESTABLISHED;
    fire_sc_event(acu, slot->address, OSDP_ACU_SC_EVENT_ESTABLISHED);
}

/* ---- Session termination + operational SC reply handling -------------- */

void osdp_acu_internal_terminate_sc(osdp_acu_t          *acu,
                                    osdp_acu_pd_slot_t  *slot)
{
    if (slot == NULL) return;

    /* Pick the right event for the slot's prior phase BEFORE we reset
     * sc_phase below:
     *
     *   ESTABLISHED            → SESSION_LOST     (D.1.4 conditions)
     *   AWAITING_CCRYPT/RMAC_I → HANDSHAKE_FAILED (handshake aborted)
     *   IDLE                   → no event         (nothing to lose)
     *
     * This makes osdp_acu_internal_terminate_sc safe to call from the
     * 8-second offline handler regardless of the slot's current state. */
    osdp_acu_sc_event_kind_t kind = OSDP_ACU_SC_EVENT_SESSION_LOST;
    bool fire = false;
    switch (slot->sc_phase) {
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

    /* Drop any in-flight command and reset the SQN cache. The next
     * command on this slot will go out plaintext (sc_phase == IDLE)
     * with SQN starting fresh, so the application can re-handshake
     * cleanly. */
    slot->waiting = false;
    slot->next_seq = 0U;
    reset_sc_handshake(slot, /*clear_session*/ true);
    if (fire) {
        fire_sc_event(acu, slot->address, kind);
    }
}

void osdp_acu_internal_handle_sc_reply(osdp_acu_t          *acu,
                                       osdp_acu_pd_slot_t  *slot,
                                       const osdp_frame_t  *frame)
{
    /* Spec 5.9: a SQN=0 reply during an established session signals
     * the PD wants the ACU to reset (both SQN counter and SC). The
     * pending_seq mismatch check below would otherwise silently drop
     * such a frame; catch it explicitly and terminate the session. */
    if (frame->sequence == 0U) {
        osdp_acu_internal_terminate_sc(acu, slot);
        return;
    }

    /* Must be the reply to the command we sent. */
    if (!slot->waiting || frame->sequence != slot->pending_seq) {
        return;
    }

    /* Verify MAC and (for SCS_18) decrypt the payload. */
    uint8_t plaintext[OSDP_ACU_TX_BUF_LEN];
    size_t  plaintext_len = 0;
    osdp_status_t s = osdp_sc_unwrap_frame(&acu->sc_crypto,
                                           &slot->sc_session, frame,
                                           plaintext, sizeof(plaintext),
                                           &plaintext_len);
    if (s != OSDP_OK) {
        /* Spec D.1.4: a SCB-bearing reply with valid CRC but invalid
         * MAC indicates encryption synchronization is lost — tear
         * down the session and let the application re-handshake. */
        osdp_acu_internal_terminate_sc(acu, slot);
        return;
    }

    /* Deliver plaintext through the same path a non-SC reply would. */
    osdp_acu_internal_deliver_reply(acu, slot, frame,
                                    plaintext, plaintext_len);
}
