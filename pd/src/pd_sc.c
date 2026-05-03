// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "pd_internal.h"

#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"

#include <string.h>

/* Forward decls of helpers defined in pd.c. We keep build_reply /
 * build_nak there since they're shared with the non-SC path. */
extern osdp_status_t pd_build_nak(osdp_pd_t          *pd,
                                  const osdp_frame_t *cmd,
                                  uint8_t             error_code,
                                  size_t             *out_len);

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
        (void)pd_build_nak(pd, cmd, OSDP_NAK_UNKNOWN_CMD, &n);
        return n;
    }
    /* Payload must be exactly the 8-byte RND.A. */
    if (cmd->payload_len != OSDP_SC_RND_LEN) {
        size_t n = 0;
        (void)pd_build_nak(pd, cmd, OSDP_NAK_CMD_LENGTH, &n);
        return n;
    }
    /* SCB data must carry the 1-byte key selector. */
    if (cmd->scb_data_len < 1U || cmd->scb_data == NULL) {
        size_t n = 0;
        (void)pd_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    const uint8_t selector = cmd->scb_data[0];
    const uint8_t *key = select_handshake_key(pd, selector);
    if (key == NULL) {
        size_t n = 0;
        (void)pd_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }

    /* Generate RND.B. We need a working RNG callback. */
    if (pd->sc.crypto.rand_bytes == NULL) {
        size_t n = 0;
        (void)pd_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
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
        (void)pd_build_nak(pd, cmd, OSDP_NAK_UNKNOWN_CMD, &n);
        return n;
    }
    if (cmd->payload_len != OSDP_SC_CRYPTOGRAM_LEN) {
        size_t n = 0;
        (void)pd_build_nak(pd, cmd, OSDP_NAK_CMD_LENGTH, &n);
        return n;
    }
    if (!pd->sc.got_chlng) {
        /* SCRYPT without prior CHLNG is a protocol violation. */
        size_t n = 0;
        (void)pd_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    if (cmd->scb_data_len < 1U || cmd->scb_data == NULL) {
        size_t n = 0;
        (void)pd_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
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

/* ---- Dispatch --------------------------------------------------------- */

size_t osdp_pd_internal_handle_sc_into_tx(osdp_pd_t          *pd,
                                          const osdp_frame_t *cmd)
{
    /* Only the ACU→PD SCB types should ever reach us. */
    switch (cmd->scb_type) {
    case OSDP_SCS_11:
        return handle_chlng(pd, cmd);
    case OSDP_SCS_13:
        return handle_scrypt(pd, cmd);
    case OSDP_SCS_15:
    case OSDP_SCS_17:
        /* Operational SC traffic — handler integration arrives in the
         * next commit. For now, NAK with unsupported-SCB so the ACU
         * sees a defined failure rather than silence. */
        /* fallthrough */
    default: {
        size_t n = 0;
        (void)pd_build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n);
        return n;
    }
    }
}
