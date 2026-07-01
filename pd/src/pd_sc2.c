// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "pd_internal.h"

#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc2.h"

#include <string.h>

/* PD-side OSDP-SC2 state machine (SCS_21..28), parallel to pd_sc.c.
 *
 *   SCS_21 osdp_CHLNG  → SCS_22 osdp_CCRYPT   (challenge → client crypto)
 *   SCS_23 osdp_SCRYPT → SCS_24 osdp_RMAC_I   (server crypto → status)
 *   SCS_25/27 command  → SCS_26/28 reply      (operational, GCM)
 *
 * Differences from SC1 that matter here: session keys derive from BOTH
 * RND.A and RND.B (so we derive after generating RND.B); the CCRYPT
 * payload is 56 bytes (cUID||RND.B||ClientCryptogram); RMAC_I carries no
 * payload — only a status byte in the SCB (0x02 ok / 0xFF fail); and the
 * session is anti-replayed by a shared counter, not a rolling MAC. */

/* ---- Helpers ---------------------------------------------------------- */

bool osdp_pd_internal_sc2_configured(const osdp_pd_t *pd)
{
    if (pd == NULL || !pd->sc2.crypto_set || !pd->sc2.cuid_set) {
        return false;
    }
    return pd->sc2.scbk_set;
}

/* Build a handshake reply (SCS_22 or SCS_24) into pd->tx_buf. The SCB
 * carries a single data byte: the version selector (0x02) for CCRYPT,
 * or the status byte for RMAC_I. */
static osdp_status_t build_handshake_reply(osdp_pd_t          *pd,
                                           const osdp_frame_t *cmd,
                                           uint8_t             scb_type,
                                           uint8_t             scb_data_byte,
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
    reply.scb_length   = (uint8_t)(OSDP_SCB_MIN_LEN + 1U);
    reply.scb_type     = scb_type;
    reply.scb_data     = &scb_data_byte;
    reply.scb_data_len = 1U;
    reply.code         = reply_code;
    reply.payload      = payload;
    reply.payload_len  = payload_len;
    return osdp_frame_build(&reply, pd->tx_buf, OSDP_PD_TX_BUF_LEN, out_len);
}

/* Apply an SC2 KEYSET (KeyType 0x02, 32-byte AES-256 SCBK) arriving
 * under the secure channel. Like SC1, the rotated key takes effect on
 * the NEXT handshake; the live session keeps running. Returns
 * OSDP_ERR_BAD_PAYLOAD for a malformed / wrong-type / wrong-length
 * record so the caller can NAK 0x09; the stored SCBK is untouched on
 * failure. */
static osdp_status_t apply_sc2_keyset(osdp_pd_t     *pd,
                                      const uint8_t *payload,
                                      size_t         payload_len)
{
    osdp_keyset_cmd_t parsed;
    const osdp_status_t s = osdp_keyset_decode(payload, payload_len, &parsed);
    if (s != OSDP_OK) {
        return s;
    }
    if (parsed.key_type != OSDP_KEYSET_KEY_TYPE_SCBK_AES256) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (parsed.key_length != OSDP_SC2_KEY_LEN || parsed.key_data == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    (void)memcpy(pd->sc2.scbk, parsed.key_data, OSDP_SC2_KEY_LEN);
    pd->sc2.scbk_set = true;
    return OSDP_OK;
}

/* ---- SCS_21: osdp_CHLNG → SCS_22: osdp_CCRYPT ------------------------- */

static size_t handle_chlng(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    if (cmd->code != OSDP_CMD_CHLNG) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNKNOWN_CMD, &n);
        return n;
    }
    /* Payload must be exactly the 16-byte RND.A. */
    if (cmd->payload_len != OSDP_SC2_RND_LEN) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_CMD_LENGTH, &n);
        return n;
    }
    /* SCB data must select SC2 (0x02). Anything else: we don't support
     * that security block variant → NAK 0x05. */
    if (cmd->scb_data_len < 1U || cmd->scb_data == NULL ||
        cmd->scb_data[0] != OSDP_SC2_SELECTOR) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    if (pd->sc2.crypto.rand_bytes == NULL) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }

    /* Generate RND.B, then derive the session keys from both randoms. */
    osdp_status_t s = pd->sc2.crypto.rand_bytes(
        pd->sc2.crypto.user, pd->sc2.rnd_b, OSDP_SC2_RND_LEN);
    if (s != OSDP_OK) {
        return 0;
    }
    (void)memcpy(pd->sc2.rnd_a, cmd->payload, OSDP_SC2_RND_LEN);

    s = osdp_sc2_derive_session_keys(&pd->sc2.crypto, pd->sc2.scbk,
                                     pd->sc2.rnd_a, pd->sc2.rnd_b,
                                     &pd->sc2.session.keys);
    if (s != OSDP_OK) {
        return 0;
    }

    uint8_t client_crypto[OSDP_SC2_CRYPTOGRAM_LEN];
    s = osdp_sc2_client_cryptogram(&pd->sc2.crypto,
                                   pd->sc2.session.keys.s_enc,
                                   pd->sc2.rnd_a, pd->sc2.rnd_b,
                                   client_crypto);
    if (s != OSDP_OK) {
        return 0;
    }

    /* CCRYPT payload: cUID(8) || RND.B(16) || ClientCryptogram(32). */
    uint8_t reply_payload[OSDP_SC2_CUID_LEN + OSDP_SC2_RND_LEN +
                          OSDP_SC2_CRYPTOGRAM_LEN];
    (void)memcpy(&reply_payload[0], pd->sc2.cuid, OSDP_SC2_CUID_LEN);
    (void)memcpy(&reply_payload[OSDP_SC2_CUID_LEN],
                 pd->sc2.rnd_b, OSDP_SC2_RND_LEN);
    (void)memcpy(&reply_payload[OSDP_SC2_CUID_LEN + OSDP_SC2_RND_LEN],
                 client_crypto, OSDP_SC2_CRYPTOGRAM_LEN);

    size_t built = 0;
    s = build_handshake_reply(pd, cmd, OSDP_SCS_22, OSDP_SC2_SELECTOR,
                              OSDP_REPLY_CCRYPT,
                              reply_payload, sizeof(reply_payload), &built);
    if (s != OSDP_OK) {
        return 0;
    }
    pd->sc2.got_chlng = true;
    pd->sc2.session.established = false;   /* not until SCRYPT verifies */
    return built;
}

/* ---- SCS_23: osdp_SCRYPT → SCS_24: osdp_RMAC_I ----------------------- */

static size_t handle_scrypt(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    if (cmd->code != OSDP_CMD_SCRYPT) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNKNOWN_CMD, &n);
        return n;
    }
    if (cmd->payload_len != OSDP_SC2_CRYPTOGRAM_LEN) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_CMD_LENGTH, &n);
        return n;
    }
    if (!pd->sc2.got_chlng) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    if (cmd->scb_data_len < 1U || cmd->scb_data == NULL ||
        cmd->scb_data[0] != OSDP_SC2_SELECTOR) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }

    /* Verify the Server Cryptogram. */
    uint8_t expected[OSDP_SC2_CRYPTOGRAM_LEN];
    osdp_status_t s = osdp_sc2_server_cryptogram(
        &pd->sc2.crypto, pd->sc2.session.keys.s_enc,
        pd->sc2.rnd_a, pd->sc2.rnd_b, expected);
    if (s != OSDP_OK) {
        return 0;
    }
    const bool crypto_ok =
        memcmp(expected, cmd->payload, OSDP_SC2_CRYPTOGRAM_LEN) == 0;

    if (!crypto_ok) {
        /* Status 0xFF, no session. */
        size_t built = 0;
        (void)build_handshake_reply(pd, cmd, OSDP_SCS_24,
                                    OSDP_SC2_STATUS_FAIL,
                                    OSDP_REPLY_RMAC_I, NULL, 0, &built);
        pd->sc2.got_chlng = false;
        pd->sc2.session.established = false;
        return built;
    }

    /* Success: seed the session — counter 0, cUID stored for nonce
     * derivation, established. RMAC_I carries an empty payload; the
     * status byte 0x02 signals acceptance. */
    (void)memcpy(pd->sc2.session.cuid, pd->sc2.cuid, OSDP_SC2_CUID_LEN);
    pd->sc2.session.counter     = 0;
    pd->sc2.session.established  = true;
    pd->sc2.got_chlng           = false;

    size_t built = 0;
    s = build_handshake_reply(pd, cmd, OSDP_SCS_24, OSDP_SC2_STATUS_OK,
                              OSDP_REPLY_RMAC_I, NULL, 0, &built);
    if (s != OSDP_OK) {
        return 0;
    }
    return built;
}

/* ---- SCS_25 / SCS_27: operational traffic ---------------------------- */

static size_t handle_operational(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    if (!pd->sc2.session.established) {
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }

    /* Unwrap: verify the GCM tag and (for SCS_27) decrypt code||data. */
    uint8_t cmd_code = 0;
    uint8_t plaintext[OSDP_PD_TX_BUF_LEN];
    size_t  plaintext_len = 0;
    osdp_status_t s = osdp_sc2_unwrap_frame(
        &pd->sc2.crypto, &pd->sc2.session, cmd,
        &cmd_code, plaintext, sizeof(plaintext), &plaintext_len);
    if (s != OSDP_OK) {
        /* Tag mismatch / decrypt failure: silent drop, let the ACU
         * time out and recover (annex Error Recovery). */
        return 0;
    }

    /* Dispatch the decrypted command to the application handler. */
    osdp_pd_reply_t reply = {
        .code        = OSDP_REPLY_ACK,
        .payload     = NULL,
        .payload_len = 0,
    };
    osdp_status_t app_status = OSDP_ERR_NOT_SUPPORTED;
    if (pd->cmd_cb != NULL) {
        app_status = pd->cmd_cb(pd->cmd_user, cmd_code,
                                plaintext, plaintext_len, &reply);
    }

    /* Mirror reader-visible commands (osdp_LED) into the LED bank. */
    osdp_pd_internal_observe_command(pd, cmd_code, plaintext, plaintext_len);

    /* Reply is always the encrypted PD→ACU variant (SCS_28). */
    osdp_frame_t reply_template;
    (void)memset(&reply_template, 0, sizeof(reply_template));
    reply_template.address    = pd->address;
    reply_template.reply      = true;
    reply_template.sequence   = cmd->sequence;
    reply_template.integrity  = cmd->integrity;
    reply_template.has_scb    = true;
    reply_template.scb_length = OSDP_SCB_MIN_LEN;
    reply_template.scb_type   = OSDP_SCS_28;

    uint8_t nak_byte = OSDP_NAK_UNKNOWN_CMD;
    if (app_status == OSDP_OK) {
        if (cmd_code == OSDP_CMD_KEYSET) {
            const osdp_status_t ks =
                apply_sc2_keyset(pd, plaintext, plaintext_len);
            if (ks != OSDP_OK) {
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
    s = osdp_sc2_wrap_frame(&pd->sc2.crypto, &pd->sc2.session,
                            &reply_template,
                            pd->tx_buf, OSDP_PD_TX_BUF_LEN, &built);
    if (s != OSDP_OK) {
        return 0;
    }
    return built;
}

/* ---- Dispatch --------------------------------------------------------- */

size_t osdp_pd_internal_handle_sc2_into_tx(osdp_pd_t          *pd,
                                           const osdp_frame_t *cmd)
{
    switch (cmd->scb_type) {
    case OSDP_SCS_21:
        return handle_chlng(pd, cmd);
    case OSDP_SCS_23:
        return handle_scrypt(pd, cmd);
    case OSDP_SCS_25:
    case OSDP_SCS_27:
        return handle_operational(pd, cmd);
    default: {
        /* Reply-direction SC2 types (22/24/26/28) or anything else are
         * out of spec on the ACU→PD path. */
        size_t n = 0;
        (void)osdp_pd_internal_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    }
}
