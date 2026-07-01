// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "pd_internal.h"

#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"

#include <string.h>

/* ---- Helpers ---------------------------------------------------------- */

bool osdp_pd_internal_sc_configured(const osdp_pd_t *pd)
{
    if (pd == NULL || !pd->sc.crypto_set || !pd->sc.cuid_set) {
        return false;
    }
    /* Must have at least one of SCBK or SCBK-D — otherwise we can't
     * complete a handshake regardless of which one the ACU asks for. */
    return pd->sc.scbk_set || pd->sc.scbk_d_set;
}

/* The active key for this handshake, or NULL if the requested
 * selector isn't configured. */
static const uint8_t *select_handshake_key(const osdp_pd_t *pd,
                                           uint8_t selector)
{
    if (selector == 1U && pd->sc.scbk_set) {
        return pd->sc.scbk;
    }
    if (selector == 0U && pd->sc.scbk_d_set) {
        return pd->sc.scbk_d;
    }
    return NULL;
}

/* Build a non-MAC handshake reply (SCS_12 or SCS_14) into pd->tx_buf.
 * Used by both CHLNG-handler and SCRYPT-handler. */
static osdp_status_t build_handshake_reply(osdp_pd_t          *pd,
                                           const osdp_frame_t *cmd,
                                           uint8_t             scb_type,
                                           uint8_t             scb_selector_or_status,
                                           uint8_t             reply_code,
                                           const uint8_t      *payload,
                                           size_t              payload_len,
                                           size_t             *out_len)
{
    osdp_frame_t reply;
    (void)memset(&reply, 0, sizeof(reply));
    reply.address      = pd->address;
    reply.reply        = true;
    reply.sequence     = cmd->sequence;
    reply.integrity    = cmd->integrity;
    reply.has_scb      = true;
    /* SCB structure: LEN + TYPE + 1 data byte (the selector or
     * status). SEC_BLK_LEN value is the total size including itself. */
    reply.scb_length   = (uint8_t)(OSDP_SCB_MIN_LEN + 1U);
    reply.scb_type     = scb_type;
    reply.scb_data     = &scb_selector_or_status;
    reply.scb_data_len = 1U;
    reply.code         = reply_code;
    reply.payload      = payload;
    reply.payload_len  = payload_len;
    return osdp_frame_build(&reply, pd->tx_buf, OSDP_PD_TX_BUF_LEN, out_len);
}

/* ---- SCS_11: osdp_CHLNG → SCS_12: osdp_CCRYPT ------------------------- */

static size_t handle_chlng(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    /* Frame validity. CHLNG always has command code osdp_CHLNG (0x76). */
    if (cmd->code != OSDP_CMD_CHLNG) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNKNOWN_CMD, &n);
        return n;
    }
    /* Payload must be exactly the 8-byte RND.A. */
    if (cmd->payload_len != OSDP_SC_RND_LEN) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_CMD_LENGTH, &n);
        return n;
    }
    /* SCB data must carry the 1-byte key selector. */
    if (cmd->scb_data_len < 1U || cmd->scb_data == NULL) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    const uint8_t selector = cmd->scb_data[0];
    const uint8_t *key = select_handshake_key(pd, selector);
    if (key == NULL) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }

    /* Generate RND.B. We need a working RNG callback. */
    if (pd->sc.crypto.rand_bytes == NULL) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    osdp_status_t s = pd->sc.crypto.rand_bytes(
        pd->sc.crypto.user, pd->sc.rnd_b, OSDP_SC_RND_LEN);
    if (s != OSDP_OK) {
        return 0;
    }
    (void)memcpy(pd->sc.rnd_a, cmd->payload, OSDP_SC_RND_LEN);
    pd->sc.key_selector = selector;

    /* Derive session keys, then compute Client Cryptogram. */
    s = osdp_sc_derive_session_keys(&pd->sc.crypto, key, pd->sc.rnd_a,
                                    &pd->sc.session.keys);
    if (s != OSDP_OK) {
        return 0;
    }
    uint8_t client_crypto[OSDP_SC_CRYPTOGRAM_LEN];
    s = osdp_sc_client_cryptogram(&pd->sc.crypto,
                                  pd->sc.session.keys.s_enc,
                                  pd->sc.rnd_a, pd->sc.rnd_b,
                                  client_crypto);
    if (s != OSDP_OK) {
        return 0;
    }

    /* CCRYPT payload: cUID(8) || RND.B(8) || ClientCryptogram(16). */
    uint8_t reply_payload[OSDP_SC_CUID_LEN + OSDP_SC_RND_LEN +
                          OSDP_SC_CRYPTOGRAM_LEN];
    (void)memcpy(&reply_payload[0],
                 pd->sc.cuid, OSDP_SC_CUID_LEN);
    (void)memcpy(&reply_payload[OSDP_SC_CUID_LEN],
                 pd->sc.rnd_b, OSDP_SC_RND_LEN);
    (void)memcpy(&reply_payload[OSDP_SC_CUID_LEN + OSDP_SC_RND_LEN],
                 client_crypto, OSDP_SC_CRYPTOGRAM_LEN);

    size_t built = 0;
    s = build_handshake_reply(pd, cmd,
                              OSDP_SCS_12, selector,
                              OSDP_REPLY_CCRYPT,
                              reply_payload, sizeof(reply_payload),
                              &built);
    if (s != OSDP_OK) {
        return 0;
    }
    pd->sc.got_chlng = true;
    pd->sc.session.established = false;  /* not yet — wait for SCRYPT */
    return built;
}

/* ---- SCS_13: osdp_SCRYPT → SCS_14: osdp_RMAC_I ------------------------ */

static size_t handle_scrypt(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    if (cmd->code != OSDP_CMD_SCRYPT) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNKNOWN_CMD, &n);
        return n;
    }
    if (cmd->payload_len != OSDP_SC_CRYPTOGRAM_LEN) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_CMD_LENGTH, &n);
        return n;
    }
    if (!pd->sc.got_chlng) {
        /* SCRYPT without prior CHLNG is a protocol violation. */
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    if (cmd->scb_data_len < 1U || cmd->scb_data == NULL) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }

    /* Verify the Server Cryptogram matches what we'd compute. */
    uint8_t expected[OSDP_SC_CRYPTOGRAM_LEN];
    osdp_status_t s = osdp_sc_server_cryptogram(
        &pd->sc.crypto, pd->sc.session.keys.s_enc,
        pd->sc.rnd_a, pd->sc.rnd_b, expected);
    if (s != OSDP_OK) {
        return 0;
    }
    /* Per spec D.1.3.4, mismatch → SEC_BLK_DATA[0] = 0xFF status, no
     * R-MAC, session not established. */
    const bool crypto_ok =
        memcmp(expected, cmd->payload, OSDP_SC_CRYPTOGRAM_LEN) == 0;

    if (!crypto_ok) {
        size_t built = 0;
        const uint8_t fail_status = 0xFFU;
        const uint8_t empty_payload[1] = {0};
        (void)build_handshake_reply(pd, cmd,
                                    OSDP_SCS_14, fail_status,
                                    OSDP_REPLY_RMAC_I,
                                    empty_payload, 0,
                                    &built);
        pd->sc.got_chlng = false;
        pd->sc.session.established = false;
        return built;
    }

    /* Compute Initial R-MAC. */
    uint8_t initial_rmac[OSDP_SC_MAC_LEN];
    s = osdp_sc_initial_rmac(&pd->sc.crypto,
                             pd->sc.session.keys.s_mac1,
                             pd->sc.session.keys.s_mac2,
                             cmd->payload,
                             initial_rmac);
    if (s != OSDP_OK) {
        return 0;
    }

    /* Send RMAC_I with status = 0x01 (ok) and payload = Initial R-MAC. */
    size_t built = 0;
    s = build_handshake_reply(pd, cmd,
                              OSDP_SCS_14, 0x01U,
                              OSDP_REPLY_RMAC_I,
                              initial_rmac, sizeof(initial_rmac),
                              &built);
    if (s != OSDP_OK) {
        return 0;
    }

    /* Seed the session: both directions of the rolling chain start
     * at the Initial R-MAC. */
    (void)memcpy(pd->sc.session.last_outbound_mac,
                 initial_rmac, OSDP_SC_MAC_LEN);
    (void)memcpy(pd->sc.session.last_inbound_mac,
                 initial_rmac, OSDP_SC_MAC_LEN);
    pd->sc.session.established = true;
    pd->sc.got_chlng = false;
    return built;
}

/* ---- SCS_15 / SCS_17: operational traffic ---------------------------- */

static size_t handle_operational(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    if (!pd->sc.session.established) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }

    /* Unwrap: verify MAC and (for SCS_17) decrypt the payload. */
    uint8_t plaintext[OSDP_PD_TX_BUF_LEN];
    size_t  plaintext_len = 0;
    osdp_status_t s = osdp_sc_unwrap_frame(
        &pd->sc.crypto, &pd->sc.session, cmd,
        plaintext, sizeof(plaintext), &plaintext_len);
    if (s != OSDP_OK) {
        /* MAC mismatch or decrypt failure: silent drop. The ACU will
         * time out and re-issue, which is the protocol's expected
         * recovery path (spec D.6). Sending a NAK with a wrong MAC
         * would only confuse the chain further. */
        return 0;
    }

    /* Dispatch the plaintext payload to the application handler. */
    osdp_pd_reply_t reply = {
        .code        = OSDP_REPLY_ACK,
        .payload     = NULL,
        .payload_len = 0,
    };
    osdp_status_t app_status = OSDP_ERR_NOT_SUPPORTED;
    if (pd->cmd_cb != NULL) {
        app_status = pd->cmd_cb(pd->cmd_user, cmd->code,
                                plaintext, plaintext_len, &reply);
    }

    /* Mirror reader-visible commands (osdp_LED) into the LED bank, same
     * as the plaintext path — the application sees identical LED state
     * whether the command arrived in the clear or under Secure Channel. */
    osdp_pd_internal_observe_command(pd, cmd->code, plaintext, plaintext_len);

    /* Reply SCB type picks the reply-direction encrypted variant
     * (SCS_18). `osdp_sc_wrap_frame` enforces the project-wide
     * convention that the SCB type is dictated by payload presence,
     * not by the inbound type — so an empty reply is coerced
     * SCS_18→SCS_16, and conversely a data-bearing event reply (RAW
     * / KEYPAD / LSTATR triggered by an empty POLL) stays as SCS_18
     * regardless of whether the inbound was SCS_15 or SCS_17. */
    osdp_frame_t reply_template;
    (void)memset(&reply_template, 0, sizeof(reply_template));
    reply_template.address     = pd->address;
    reply_template.reply       = true;
    reply_template.sequence    = cmd->sequence;
    reply_template.integrity   = cmd->integrity;
    reply_template.has_scb     = true;
    reply_template.scb_length  = OSDP_SCB_MIN_LEN;
    reply_template.scb_type    = OSDP_SCS_18;

    /* Stack storage that lives across the wrap call below; the wrap
     * routine copies the bytes into the output buffer so the lifetime
     * is sufficient. */
    uint8_t nak_byte = OSDP_NAK_UNKNOWN_CMD;
    if (app_status == OSDP_OK) {
        /* KEYSET hook: same shape as the plaintext path in pd.c —
         * if the app ACK'd a KEYSET arriving under SC, apply the
         * new SCBK before transmitting the ACK. On malformed input
         * we downgrade the wire reply to a NAK so the ACU sees it.
         * The live SC session is intentionally NOT torn down — the
         * rotated key only matters for the next handshake. */
        if (cmd->code == OSDP_CMD_KEYSET) {
            const osdp_status_t ks = osdp_pd_internal_apply_keyset(
                pd, plaintext, plaintext_len);
            if (ks != OSDP_OK) {
                /* Any malformed-but-recognized KEYSET is spec Table 47
                 * error 0x09 "Unable to process command record". */
                nak_byte = OSDP_NAK_RECORD_INVALID;
                reply_template.code        = OSDP_REPLY_NAK;
                reply_template.payload     = &nak_byte;
                reply_template.payload_len = 1;
                goto wrap;
            }
        }
        reply_template.code        = reply.code;
        reply_template.payload     = reply.payload;
        reply_template.payload_len = reply.payload_len;
    } else if (app_status == OSDP_ERR_NOT_SUPPORTED) {
        reply_template.code        = OSDP_REPLY_NAK;
        reply_template.payload     = &nak_byte;
        reply_template.payload_len = 1;
    } else {
        return 0;  /* internal handler error — drop */
    }

wrap:;

    size_t built = 0;
    s = osdp_sc_wrap_frame(&pd->sc.crypto, &pd->sc.session,
                           &reply_template,
                           pd->tx_buf, OSDP_PD_TX_BUF_LEN, &built);
    if (s != OSDP_OK) {
        return 0;
    }
    return built;
}

/* ---- Dispatch --------------------------------------------------------- */

size_t osdp_pd_internal_handle_sc_into_tx(osdp_pd_t          *pd,
                                          const osdp_frame_t *cmd)
{
    switch (cmd->scb_type) {
    case OSDP_SCS_11:
        return handle_chlng(pd, cmd);
    case OSDP_SCS_13:
        return handle_scrypt(pd, cmd);
    case OSDP_SCS_15:
    case OSDP_SCS_17:
        return handle_operational(pd, cmd);
    default: {
        /* SCB types we never expect on the ACU→PD direction
         * (SCS_12/14/16/18 are reply-direction; anything else is
         * out-of-spec). NAK with unsupported-SCB. */
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    }
}
