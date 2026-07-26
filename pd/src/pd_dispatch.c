// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Unified command dispatch for the PD.
 *
 * Every inbound command — plaintext, Secure Channel 1 (SCS_15/17), or
 * Secure Channel 2 (SCS_25/27) — funnels through osdp_pd_internal_dispatch
 * once its payload is in the clear. This file owns what a command *means*:
 *
 *   - which commands the library answers itself (osdp_COMSET, osdp_FILETRANSFER)
 *   - when the application's command handler runs, and how its verdict maps
 *     onto the wire reply
 *   - the osdp_KEYSET hook
 *   - reader-state observation (LED / buzzer banks)
 *
 * What it deliberately does NOT own is framing: mirroring the inbound
 * address/sequence/integrity, appending a security block, encrypting, MACing.
 * Each caller does that its own way, and that is the only thing that
 * legitimately differs between the three paths.
 *
 * Before this existed the whole block above was written out three times —
 * pd.c, pd_sc.c, pd_sc2.c — and had already drifted: the SC2 copy intercepted
 * neither osdp_COMSET nor osdp_FILETRANSFER, so under SC2 a COMSET fell
 * through to the application handler and the PD never adopted the new address,
 * and a FILETRANSFER never reached the registered receiver. Keeping one copy
 * is what stops that recurring as more library-handled commands land. */

#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"
#include "pd_internal.h"

#include <string.h>

/* Fill *reply with an osdp_NAK carrying `error_code`, using the context's
 * reply scratch so the payload outlives this call. */
static void nak_into(osdp_pd_t *pd, uint8_t error_code, osdp_pd_reply_t *reply)
{
    pd->reply_scratch[0] = error_code;
    reply->code          = OSDP_REPLY_NAK;
    reply->payload       = pd->reply_scratch;
    reply->payload_len   = 1;
}

/* osdp_COMSET (6.13): library-handled. The reply is a mandated osdp_COM (not
 * an app-chosen ACK) and the command mutates pd->address, which only the
 * state machine owns — so it never reaches cmd_cb on any channel.
 *
 * The address change is STAGED, not applied: per spec 6.13 it takes effect
 * only after the reply has been sent, so process_frame applies it once the
 * osdp_COM has gone out at the OLD address. */
static void handle_comset(osdp_pd_t       *pd,
                          const uint8_t   *payload,
                          size_t           payload_len,
                          osdp_pd_reply_t *reply)
{
    uint8_t  eff_addr = pd->address;
    uint32_t eff_baud = 0;
    uint8_t  com_payload[OSDP_COM_PAYLOAD_BYTES];

    if (osdp_pd_internal_comset_effective(pd, payload, payload_len,
                                          &eff_addr, &eff_baud,
                                          com_payload) != OSDP_OK) {
        nak_into(pd, OSDP_NAK_CMD_LENGTH, reply);
        return;
    }

    (void)memcpy(pd->reply_scratch, com_payload, OSDP_COM_PAYLOAD_BYTES);
    reply->code        = OSDP_REPLY_COM;
    reply->payload     = pd->reply_scratch;
    reply->payload_len = OSDP_COM_PAYLOAD_BYTES;

    pd->comset_pending     = true;
    pd->comset_new_address = eff_addr;
    pd->comset_new_baud    = eff_baud;
}

/* osdp_FILETRANSFER (6.26): library-handled. The core decodes the fragment,
 * enforces the offset invariants, drives the application's per-fragment
 * evaluation callback, and builds the mandated osdp_FTSTAT — so this too
 * never reaches cmd_cb. Failure statuses (abort / malformed / unrecognized)
 * are still FTSTAT replies, not NAKs; only "no receiver bound" and an
 * undecodable frame degrade to a NAK. */
static void handle_filetransfer(osdp_pd_t       *pd,
                                const uint8_t   *payload,
                                size_t           payload_len,
                                osdp_pd_reply_t *reply)
{
    uint8_t ftstat_payload[OSDP_FTSTAT_PAYLOAD_BYTES];
    const osdp_status_t s = osdp_pd_internal_filetransfer(
        pd, payload, payload_len, ftstat_payload);

    if (s != OSDP_OK) {
        nak_into(pd,
                 (s == OSDP_ERR_NOT_SUPPORTED) ? OSDP_NAK_UNKNOWN_CMD
                                               : OSDP_NAK_CMD_LENGTH,
                 reply);
        return;
    }

    (void)memcpy(pd->reply_scratch, ftstat_payload, OSDP_FTSTAT_PAYLOAD_BYTES);
    reply->code        = OSDP_REPLY_FTSTAT;
    reply->payload     = pd->reply_scratch;
    reply->payload_len = OSDP_FTSTAT_PAYLOAD_BYTES;
}

/* Apply an osdp_KEYSET the application has just agreed to ACK. SC1 and SC2
 * rotate different keys, so the channel picks the variant. A malformed or
 * unusable key record downgrades the wire reply from ACK to NAK 0x09
 * ("unable to process command record") and leaves the stored key untouched. */
static bool apply_keyset_for_channel(osdp_pd_t        *pd,
                                     osdp_pd_channel_t channel,
                                     const uint8_t    *payload,
                                     size_t            payload_len)
{
    const osdp_status_t ks =
        (channel == OSDP_PD_CH_SC2)
            ? osdp_pd_internal_apply_sc2_keyset(pd, payload, payload_len)
            : osdp_pd_internal_apply_keyset(pd, payload, payload_len);
    return ks == OSDP_OK;
}

osdp_status_t osdp_pd_internal_dispatch(osdp_pd_t        *pd,
                                        osdp_pd_channel_t channel,
                                        uint8_t           cmd_code,
                                        const uint8_t    *payload,
                                        size_t            payload_len,
                                        osdp_pd_reply_t  *reply)
{
    if (pd == NULL || reply == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Library-handled commands first — these never reach the application. */
    if (cmd_code == OSDP_CMD_COMSET) {
        handle_comset(pd, payload, payload_len, reply);
        return OSDP_OK;
    }
    if (cmd_code == OSDP_CMD_FILETRANSFER) {
        handle_filetransfer(pd, payload, payload_len, reply);
        return OSDP_OK;
    }

    /* Everything else goes to the application. Default to ACK so a handler
     * that only inspects the code and returns OSDP_OK does the obvious thing. */
    reply->code        = OSDP_REPLY_ACK;
    reply->payload     = NULL;
    reply->payload_len = 0;

    osdp_status_t app_status = OSDP_ERR_NOT_SUPPORTED;
    if (pd->cmd_cb != NULL) {
        app_status = pd->cmd_cb(pd->cmd_user, cmd_code,
                                payload, payload_len, reply);
    }

    /* Mirror reader-visible commands (osdp_LED / osdp_BUZ) into their banks
     * whatever the handler chose to reply, so the application's change
     * callbacks and colour/sounding queries stay current on every channel. */
    osdp_pd_internal_observe_command(pd, cmd_code, payload, payload_len);

    if (app_status == OSDP_ERR_NOT_SUPPORTED) {
        nak_into(pd, OSDP_NAK_UNKNOWN_CMD, reply);
        return OSDP_OK;
    }
    if (app_status != OSDP_OK) {
        /* Internal handler error — send nothing at all. */
        return OSDP_ERR_INVALID_ARG;
    }

    /* The app would ACK: if this was a KEYSET, rotate the key before the
     * reply goes out, and downgrade to NAK 0x09 if the record is unusable. */
    if (cmd_code == OSDP_CMD_KEYSET &&
        !apply_keyset_for_channel(pd, channel, payload, payload_len)) {
        nak_into(pd, OSDP_NAK_RECORD_INVALID, reply);
    }

    return OSDP_OK;
}
