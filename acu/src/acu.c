// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_acu.h"

#include "acu_internal.h"

#include "osdp/osdp_frame.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"

#include <string.h>

/* ---- Internal helpers --------------------------------------------------*/

static osdp_acu_pd_slot_t *find_slot_by_address(osdp_acu_t *acu,
                                                uint8_t address)
{
    for (size_t i = 0; i < acu->pd_count; i++) {
        if (acu->pds[i].in_use && acu->pds[i].address == address) {
            return &acu->pds[i];
        }
    }
    return NULL;
}

static const osdp_acu_pd_slot_t *find_slot_by_address_const(
    const osdp_acu_t *acu, uint8_t address)
{
    for (size_t i = 0; i < acu->pd_count; i++) {
        if (acu->pds[i].in_use && acu->pds[i].address == address) {
            return &acu->pds[i];
        }
    }
    return NULL;
}

/* Sequence number progression per spec 5.9 Table 2: 0, 1, 2, 3, 1, 2, 3,
 * ... — SQN zero used only for the very first command on a fresh slot. */
static uint8_t advance_sqn(uint8_t current)
{
    if (current >= 3U) {
        return 1U;
    }
    return (uint8_t)(current + 1U);
}

static uint32_t now_ms_or_zero(const osdp_acu_t *acu)
{
    if (acu->transport.now_ms == NULL) {
        return 0U;
    }
    return acu->transport.now_ms(acu->transport.user);
}

/* ---- Reply ingestion ---------------------------------------------------*/

void osdp_acu_internal_deliver_reply(osdp_acu_t           *acu,
                                     osdp_acu_pd_slot_t   *slot,
                                     const osdp_frame_t   *frame,
                                     const uint8_t        *payload,
                                     size_t                payload_len)
{
    slot->online        = true;
    slot->last_reply_ms = now_ms_or_zero(acu);
    const uint8_t cmd_code = slot->pending_code;
    slot->waiting   = false;
    slot->next_seq  = advance_sqn(slot->pending_seq);

    if (acu->reply_cb != NULL) {
        const osdp_acu_reply_event_t event = {
            .pd_address  = frame->address,
            .cmd_code    = cmd_code,
            .reply_code  = frame->code,
            .payload     = payload,
            .payload_len = payload_len,
        };
        acu->reply_cb(acu->reply_user, &event);
    }
}

static void process_reply(osdp_acu_t *acu, const osdp_frame_t *frame)
{
    /* Reply must be addressed to a registered PD. */
    osdp_acu_pd_slot_t *slot = find_slot_by_address(acu, frame->address);
    if (slot == NULL) {
        return;
    }

    /* Spec 5.9: "a PD may respond with SQN zero to indicate the ACU
     * shall reset the sequence including clearing any secure channel
     * session that is currently active." A SQN=0 reply during an
     * ESTABLISHED session is a session-reset signal; tear down. We
     * gate on ESTABLISHED so the handshake's own SQN=0 echo (CHLNG
     * → CCRYPT, both at SQN=0 on a fresh slot) doesn't loop back as
     * a reset. */
    if (frame->sequence == 0U &&
        slot->sc_phase == OSDP_ACU_SC_ESTABLISHED) {
        osdp_acu_internal_terminate_sc(acu, slot);
        return;
    }

    /* Spec D.1.4: once the secure channel is established, a non-BUSY
     * plaintext reply terminates the session. The PD is misbehaving
     * (or the session got out of sync); reset and let the application
     * re-handshake. BUSY (0x79) is exempted by the spec because the
     * PD signals "I can't reply right now" without exiting SC. */
    if (slot->sc_phase == OSDP_ACU_SC_ESTABLISHED &&
        frame->code != OSDP_REPLY_BUSY) {
        osdp_acu_internal_terminate_sc(acu, slot);
        return;
    }

    /* If we are not waiting for a reply from this PD, the reply is
     * unsolicited or stale — drop it. */
    if (!slot->waiting) {
        return;
    }

    /* Sequence number must match the command we sent. */
    if (frame->sequence != slot->pending_seq) {
        return;
    }

    osdp_acu_internal_deliver_reply(acu, slot, frame,
                                    frame->payload, frame->payload_len);
}

/* ---- Timeout / online tracking ----------------------------------------*/

static void scan_timeouts_and_offline(osdp_acu_t *acu)
{
    if (acu->transport.now_ms == NULL) {
        return;
    }
    const uint32_t now = acu->transport.now_ms(acu->transport.user);

    for (size_t i = 0; i < acu->pd_count; i++) {
        osdp_acu_pd_slot_t *slot = &acu->pds[i];
        if (!slot->in_use) {
            continue;
        }

        /* Reply timeout. */
        if (slot->waiting) {
            const uint32_t elapsed = now - slot->pending_sent_ms;
            if (elapsed > OSDP_ACU_REPLY_TIMEOUT_MS) {
                const uint8_t addr = slot->address;
                const uint8_t code = slot->pending_code;
                const uint8_t seq  = slot->pending_seq;
                slot->waiting = false;
                /* Per spec retry semantics: keep next_seq pointing at
                 * the same SQN so the caller's retry uses it. */
                slot->next_seq = seq;
                if (acu->timeout_cb != NULL) {
                    const osdp_acu_timeout_event_t event = {
                        .pd_address = addr,
                        .cmd_code   = code,
                        .cmd_seq    = seq,
                    };
                    acu->timeout_cb(acu->timeout_user, &event);
                }
            }
        }

        /* Online window. Spec 5.7: a PD that hasn't responded for
         * OSDP_ACU_OFFLINE_TIMEOUT_MS is considered offline. If a
         * Secure Channel session was active, that session also
         * terminates — encryption synchronization can't be assumed
         * after a multi-second silence — and we fire SESSION_LOST
         * (or HANDSHAKE_FAILED, if the slot was mid-handshake when
         * the line went silent) so the application knows to re-
         * initialize before resuming traffic. */
        if (slot->online) {
            const uint32_t since = now - slot->last_reply_ms;
            if (since > OSDP_ACU_OFFLINE_TIMEOUT_MS) {
                slot->online = false;
                if (slot->sc_phase != OSDP_ACU_SC_IDLE) {
                    osdp_acu_internal_terminate_sc(acu, slot);
                }
            }
        }
    }
}

/* ---- API ---------------------------------------------------------------*/

void osdp_acu_init(osdp_acu_t          *acu,
                   osdp_acu_pd_slot_t  *pd_slots,
                   size_t               pd_count)
{
    if (acu == NULL) {
        return;
    }
    (void)memset(acu, 0, sizeof(*acu));
    acu->pds       = pd_slots;
    acu->pd_count  = (pd_slots != NULL) ? pd_count : 0U;
    acu->integrity = OSDP_INTEGRITY_CRC;
    osdp_stream_init(&acu->rx);
    if (acu->pds != NULL) {
        (void)memset(acu->pds, 0, sizeof(*acu->pds) * acu->pd_count);
    }
}

void osdp_acu_set_transport(osdp_acu_t *acu,
                            const osdp_acu_transport_t *transport)
{
    if (acu == NULL || transport == NULL) {
        return;
    }
    acu->transport = *transport;
}

void osdp_acu_set_reply_handler(osdp_acu_t *acu,
                                osdp_acu_reply_cb cb, void *user)
{
    if (acu == NULL) {
        return;
    }
    acu->reply_cb   = cb;
    acu->reply_user = user;
}

void osdp_acu_set_timeout_handler(osdp_acu_t *acu,
                                  osdp_acu_timeout_cb cb, void *user)
{
    if (acu == NULL) {
        return;
    }
    acu->timeout_cb   = cb;
    acu->timeout_user = user;
}

void osdp_acu_set_integrity(osdp_acu_t *acu, osdp_integrity_t integrity)
{
    if (acu == NULL) {
        return;
    }
    acu->integrity = integrity;
}

osdp_status_t osdp_acu_register_pd(osdp_acu_t *acu,
                                   size_t      slot_index,
                                   uint8_t     pd_address)
{
    if (acu == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (slot_index >= acu->pd_count) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (pd_address > OSDP_BROADCAST_ADDR) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_acu_pd_slot_t *slot = &acu->pds[slot_index];
    (void)memset(slot, 0, sizeof(*slot));
    slot->in_use   = true;
    slot->address  = pd_address;
    slot->next_seq = 0U;       /* spec: first command on a fresh PD = 0 */
    return OSDP_OK;
}

osdp_status_t osdp_acu_send_command(osdp_acu_t    *acu,
                                    uint8_t        pd_address,
                                    uint8_t        cmd_code,
                                    const uint8_t *payload,
                                    size_t         payload_len)
{
    if (acu == NULL || (payload_len > 0 && payload == NULL)) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_acu_pd_slot_t *slot = find_slot_by_address(acu, pd_address);
    if (slot == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (slot->waiting) {
        return OSDP_ERR_NOT_SUPPORTED;  /* one outstanding cmd per PD */
    }
    if (acu->transport.write == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    osdp_frame_t frame = {0};
    frame.address     = pd_address;
    frame.reply       = false;
    frame.sequence    = (uint8_t)(slot->next_seq & 0x03U);
    frame.integrity   = acu->integrity;
    frame.code        = cmd_code;
    frame.payload     = payload;
    frame.payload_len = payload_len;

    size_t written = 0;
    osdp_status_t br;

    /* Once Secure Channel is established for this slot, every command
     * is automatically wrapped — no per-command opt-in. The SCB type
     * is keyed off the inbound payload: SCS_17 by default; the wrap
     * helper coerces SCS_17→SCS_15 for empty payloads (project
     * convention from spec D.1.4). */
    if (slot->sc_phase == OSDP_ACU_SC_ESTABLISHED) {
        frame.has_scb     = true;
        frame.scb_length  = OSDP_SCB_MIN_LEN;
        frame.scb_type    = OSDP_SCS_17;
        br = osdp_sc_wrap_frame(&acu->sc_crypto, &slot->sc_session,
                                &frame, acu->tx_buf, sizeof(acu->tx_buf),
                                &written);
    } else {
        br = osdp_frame_build(&frame, acu->tx_buf,
                              sizeof(acu->tx_buf), &written);
    }
    if (br != OSDP_OK) {
        return br;
    }
    const int tx = acu->transport.write(acu->transport.user,
                                        acu->tx_buf, written);
    if (tx < 0 || (size_t)tx != written) {
        return OSDP_ERR_NOT_SUPPORTED;  /* short write — TX layer issue */
    }

    slot->waiting        = true;
    slot->pending_seq    = frame.sequence;
    slot->pending_code   = cmd_code;
    slot->pending_sent_ms = now_ms_or_zero(acu);
    return OSDP_OK;
}

void osdp_acu_tick(osdp_acu_t *acu)
{
    if (acu == NULL || acu->transport.read == NULL) {
        return;
    }

    /* Examine timeouts before consuming new bytes — a reply that
     * arrives during this tick won't undo the timeout decision (we
     * already missed the deadline). */
    scan_timeouts_and_offline(acu);

    uint8_t chunk[128];
    for (;;) {
        const int n = acu->transport.read(acu->transport.user,
                                          chunk, sizeof(chunk));
        if (n <= 0) {
            break;
        }
        (void)osdp_stream_feed(&acu->rx, chunk, (size_t)n);
        if ((size_t)n < sizeof(chunk)) {
            break;
        }
    }

    for (;;) {
        osdp_frame_t frame;
        const osdp_status_t r = osdp_stream_next(&acu->rx, &frame);
        if (r == OSDP_ERR_TRUNCATED) {
            break;
        }
        if (r != OSDP_OK) {
            continue;  /* stream advanced past a bad frame */
        }
        /* ACU only consumes replies. */
        if (!frame.reply) {
            continue;
        }

        /* Route SCB-bearing replies. The SC handshake replies (SCS_12
         * CCRYPT, SCS_14 RMAC_I) are consumed internally and never
         * surface in the application's reply_cb. Operational SC
         * replies (SCS_16, SCS_18) are unwrapped and the plaintext
         * delivered through the normal reply_cb path. */
        if (frame.has_scb) {
            osdp_acu_pd_slot_t *slot = find_slot_by_address(acu,
                                                            frame.address);
            if (slot == NULL) continue;
            switch (frame.scb_type) {
            case OSDP_SCS_12:
                if (slot->sc_phase == OSDP_ACU_SC_AWAITING_CCRYPT) {
                    osdp_acu_internal_handle_ccrypt(acu, slot, &frame);
                }
                break;
            case OSDP_SCS_14:
                if (slot->sc_phase == OSDP_ACU_SC_AWAITING_RMAC_I) {
                    osdp_acu_internal_handle_rmac_i(acu, slot, &frame);
                }
                break;
            case OSDP_SCS_16:
            case OSDP_SCS_18:
                if (slot->sc_phase == OSDP_ACU_SC_ESTABLISHED) {
                    osdp_acu_internal_handle_sc_reply(acu, slot, &frame);
                }
                break;
            default:
                break;
            }
            continue;
        }
        process_reply(acu, &frame);
    }
}

bool osdp_acu_is_pd_online(const osdp_acu_t *acu, uint8_t pd_address)
{
    if (acu == NULL) {
        return false;
    }
    const osdp_acu_pd_slot_t *slot = find_slot_by_address_const(acu,
                                                                pd_address);
    return slot != NULL && slot->online;
}

bool osdp_acu_is_pd_busy(const osdp_acu_t *acu, uint8_t pd_address)
{
    if (acu == NULL) {
        return false;
    }
    const osdp_acu_pd_slot_t *slot = find_slot_by_address_const(acu,
                                                                pd_address);
    return slot != NULL && slot->waiting;
}

/* ---- Secure Channel API -------------------------------------------------*/

void osdp_acu_set_sc_crypto(osdp_acu_t              *acu,
                            const osdp_sc_crypto_t  *crypto)
{
    if (acu == NULL || crypto == NULL) {
        return;
    }
    acu->sc_crypto     = *crypto;
    acu->sc_crypto_set = true;
}

osdp_status_t osdp_acu_set_pd_scbk(osdp_acu_t   *acu,
                                   uint8_t       pd_address,
                                   const uint8_t scbk[OSDP_SC_KEY_LEN])
{
    if (acu == NULL || scbk == NULL) return OSDP_ERR_INVALID_ARG;
    osdp_acu_pd_slot_t *slot = find_slot_by_address(acu, pd_address);
    if (slot == NULL) return OSDP_ERR_INVALID_ARG;
    (void)memcpy(slot->scbk, scbk, OSDP_SC_KEY_LEN);
    slot->scbk_set = true;
    return OSDP_OK;
}

osdp_status_t osdp_acu_set_pd_scbk_d(osdp_acu_t   *acu,
                                     uint8_t       pd_address,
                                     const uint8_t scbk_d[OSDP_SC_KEY_LEN])
{
    if (acu == NULL || scbk_d == NULL) return OSDP_ERR_INVALID_ARG;
    osdp_acu_pd_slot_t *slot = find_slot_by_address(acu, pd_address);
    if (slot == NULL) return OSDP_ERR_INVALID_ARG;
    (void)memcpy(slot->scbk_d, scbk_d, OSDP_SC_KEY_LEN);
    slot->scbk_d_set = true;
    return OSDP_OK;
}

void osdp_acu_set_sc_event_handler(osdp_acu_t           *acu,
                                   osdp_acu_sc_event_cb  cb,
                                   void                 *user)
{
    if (acu == NULL) return;
    acu->sc_event_cb   = cb;
    acu->sc_event_user = user;
}

osdp_status_t osdp_acu_start_sc_handshake(osdp_acu_t *acu,
                                          uint8_t     pd_address,
                                          bool        use_default_key)
{
    if (acu == NULL) return OSDP_ERR_INVALID_ARG;
    osdp_acu_pd_slot_t *slot = find_slot_by_address(acu, pd_address);
    if (slot == NULL) return OSDP_ERR_INVALID_ARG;
    if (acu->transport.write == NULL) return OSDP_ERR_INVALID_ARG;
    if (!osdp_acu_internal_sc_configured(acu, slot, use_default_key)) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (slot->waiting) {
        return OSDP_ERR_NOT_SUPPORTED;
    }
    /* Reset any prior session state — we're starting fresh. */
    osdp_sc_session_init(&slot->sc_session);
    slot->sc_phase = OSDP_ACU_SC_IDLE;

    return osdp_acu_internal_send_chlng(acu, slot, use_default_key);
}

bool osdp_acu_is_pd_sc_established(const osdp_acu_t *acu,
                                   uint8_t           pd_address)
{
    if (acu == NULL) return false;
    const osdp_acu_pd_slot_t *slot = find_slot_by_address_const(acu,
                                                                pd_address);
    return slot != NULL && slot->sc_phase == OSDP_ACU_SC_ESTABLISHED;
}
