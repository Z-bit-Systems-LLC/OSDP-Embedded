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

/* ---- Status reports (osdp_LSTAT / ISTAT / OSTAT / RSTAT) --------------- */

/* Fill *reply from the bound status provider. Returns false when this PD has
 * no provider for that particular command, in which case the caller lets it
 * fall through to the application handler exactly as before this existed. */
static bool handle_status_request(osdp_pd_t       *pd,
                                  uint8_t          cmd_code,
                                  osdp_pd_reply_t *reply)
{
    size_t        written = 0;
    osdp_status_t s;

    if (cmd_code == OSDP_CMD_LSTAT) {
        if (pd->status.local == NULL) {
            return false;
        }
        osdp_lstatr_t lstatr = { .tamper = OSDP_LSTATR_NORMAL,
                                 .power  = OSDP_LSTATR_NORMAL };
        pd->status.local(pd->status_user, &lstatr.tamper, &lstatr.power);
        s = osdp_lstatr_build(&lstatr, pd->reply_scratch,
                              OSDP_PD_REPLY_SCRATCH_LEN, &written);
        if (s != OSDP_OK) {
            nak_into(pd, OSDP_NAK_RECORD_INVALID, reply);
            return true;
        }
        reply->code        = OSDP_REPLY_LSTATR;
        reply->payload     = pd->reply_scratch;
        reply->payload_len = written;
        return true;
    }

    /* The other three share a shape: the provider writes status bytes into
     * the scratch, and the matching builder turns the count into a payload.
     * Since every builder here is a straight copy of `count` bytes, the
     * provider can write directly into the scratch and the build step is a
     * length check — which is exactly what it is below. */
    size_t (*provider)(void *, uint8_t *, size_t) = NULL;
    uint8_t reply_code = 0;
    osdp_status_t (*build)(const uint8_t *, size_t, uint8_t *, size_t,
                           size_t *) = NULL;

    switch (cmd_code) {
    case OSDP_CMD_ISTAT:
        provider = pd->status.inputs;  reply_code = OSDP_REPLY_ISTATR;
        build = osdp_istatr_build;     break;
    case OSDP_CMD_OSTAT:
        provider = pd->status.outputs; reply_code = OSDP_REPLY_OSTATR;
        build = osdp_ostatr_build;     break;
    case OSDP_CMD_RSTAT:
        provider = pd->status.readers; reply_code = OSDP_REPLY_RSTATR;
        build = osdp_rstatr_build;     break;
    default:
        return false;
    }
    if (provider == NULL) {
        return false;
    }

    /* Gather into a local, then build into the scratch. Going via a local
     * rather than letting the provider write the scratch in place keeps the
     * builder's source and destination distinct, which is what its contract
     * assumes. */
    uint8_t statuses[OSDP_PD_REPLY_SCRATCH_LEN];
    size_t  count = provider(pd->status_user, statuses, sizeof(statuses));
    if (count > sizeof(statuses)) {
        /* A provider that over-reports would otherwise have us read past the
         * buffer we gave it. Clamp rather than trust the return value. */
        count = sizeof(statuses);
    }

    s = build(statuses, count, pd->reply_scratch,
              OSDP_PD_REPLY_SCRATCH_LEN, &written);
    if (s != OSDP_OK) {
        nak_into(pd, OSDP_NAK_RECORD_INVALID, reply);
        return true;
    }
    reply->code        = reply_code;
    reply->payload     = pd->reply_scratch;
    reply->payload_len = written;
    return true;
}

/* ---- osdp_ABORT (6.22) ------------------------------------------------- */

/* Library-handled: the core owns the file-transfer state the spec says must
 * be terminated, so it tears that down before the optional application hook
 * runs. A hook that cannot comply turns the ACK into NAK 0x03. */
static void handle_abort(osdp_pd_t *pd, osdp_pd_reply_t *reply)
{
    pd->ft_active   = false;
    pd->ft_total    = 0;
    pd->ft_received = 0;
    pd->ft_type     = 0;

    if (pd->abort_cb != NULL &&
        pd->abort_cb(pd->abort_user) != OSDP_OK) {
        nak_into(pd, OSDP_NAK_UNKNOWN_CMD, reply);
        return;
    }
    reply->code        = OSDP_REPLY_ACK;
    reply->payload     = NULL;
    reply->payload_len = 0;
}

/* ---- osdp_ACURXSIZE (6.20) --------------------------------------------- */

/* Library-handled: the value bounds what this PD may transmit, which is the
 * state machine's business, not the application's. The hook is a
 * notification — there is nothing to veto, since refusing to believe the ACU
 * about its own buffer would only produce replies it drops. */
static void handle_acurxsize(osdp_pd_t       *pd,
                             const uint8_t   *payload,
                             size_t           payload_len,
                             osdp_pd_reply_t *reply)
{
    osdp_acurxsize_cmd_t cmd;
    if (osdp_acurxsize_decode(payload, payload_len, &cmd) != OSDP_OK) {
        nak_into(pd, OSDP_NAK_CMD_LENGTH, reply);
        return;
    }
    pd->acu_rx_size = cmd.max_size;
    if (pd->acurxsize_cb != NULL) {
        pd->acurxsize_cb(pd->acurxsize_user, cmd.max_size);
    }
    reply->code        = OSDP_REPLY_ACK;
    reply->payload     = NULL;
    reply->payload_len = 0;
}

/* ---- osdp_KEEPACTIVE (6.21) -------------------------------------------- */

/* Decoded by the core, decided by the application: holding a reader field
 * energised is physical, so with no handler the honest answer is NAK 0x03
 * ("I don't implement that") rather than an ACK the PD cannot honour. */
static void handle_keepactive(osdp_pd_t       *pd,
                              const uint8_t   *payload,
                              size_t           payload_len,
                              osdp_pd_reply_t *reply)
{
    if (pd->keepactive_cb == NULL) {
        nak_into(pd, OSDP_NAK_UNKNOWN_CMD, reply);
        return;
    }
    osdp_keepactive_cmd_t cmd;
    if (osdp_keepactive_decode(payload, payload_len, &cmd) != OSDP_OK) {
        nak_into(pd, OSDP_NAK_CMD_LENGTH, reply);
        return;
    }
    if (pd->keepactive_cb(pd->keepactive_user, cmd.time_ms) != OSDP_OK) {
        nak_into(pd, OSDP_NAK_UNKNOWN_CMD, reply);
        return;
    }
    reply->code        = OSDP_REPLY_ACK;
    reply->payload     = NULL;
    reply->payload_len = 0;
}

/* ---- Application verdict -> wire reply --------------------------------- */

/* Map a command handler's return onto spec Table 47. Before this existed
 * anything other than OSDP_OK / OSDP_ERR_NOT_SUPPORTED was dropped silently,
 * which cost the ACU a full reply timeout to learn nothing. Every code with
 * a sensible Table 47 equivalent now gets one; the silent drop survives only
 * for a status the library does not recognise. */
static osdp_pd_dispatch_outcome_t apply_app_status(osdp_pd_t       *pd,
                                                   osdp_status_t    app_status,
                                                   osdp_pd_reply_t *reply)
{
    switch (app_status) {
    case OSDP_OK:
        return OSDP_PD_DISPATCH_SEND;

    case OSDP_ERR_NOT_SUPPORTED:
        nak_into(pd, OSDP_NAK_UNKNOWN_CMD, reply);
        return OSDP_PD_DISPATCH_SEND;

    case OSDP_ERR_BAD_PAYLOAD:
    case OSDP_ERR_BAD_LENGTH:
        nak_into(pd, OSDP_NAK_CMD_LENGTH, reply);
        return OSDP_PD_DISPATCH_SEND;

    case OSDP_ERR_INVALID_ARG:
        nak_into(pd, OSDP_NAK_RECORD_INVALID, reply);
        return OSDP_PD_DISPATCH_SEND;

    case OSDP_ERR_BUSY:
        /* Framed by the caller, not here: osdp_BUSY has to leave the Secure
         * Channel and reset the sequence number, neither of which the
         * dispatch owns. */
        return OSDP_PD_DISPATCH_BUSY;

    default:
        return OSDP_PD_DISPATCH_DROP;
    }
}

osdp_pd_dispatch_outcome_t osdp_pd_internal_dispatch(
    osdp_pd_t        *pd,
    osdp_pd_channel_t channel,
    uint8_t           cmd_code,
    const uint8_t    *payload,
    size_t            payload_len,
    osdp_pd_reply_t  *reply)
{
    if (pd == NULL || reply == NULL) {
        return OSDP_PD_DISPATCH_DROP;
    }

    /* Library-handled commands first — these never reach the application. */
    switch (cmd_code) {
    case OSDP_CMD_COMSET:
        handle_comset(pd, payload, payload_len, reply);
        return OSDP_PD_DISPATCH_SEND;
    case OSDP_CMD_FILETRANSFER:
        handle_filetransfer(pd, payload, payload_len, reply);
        return OSDP_PD_DISPATCH_SEND;
    case OSDP_CMD_ABORT:
        handle_abort(pd, reply);
        return OSDP_PD_DISPATCH_SEND;
    case OSDP_CMD_ACURXSIZE:
        handle_acurxsize(pd, payload, payload_len, reply);
        return OSDP_PD_DISPATCH_SEND;
    case OSDP_CMD_KEEPACTIVE:
        handle_keepactive(pd, payload, payload_len, reply);
        return OSDP_PD_DISPATCH_SEND;
    default:
        break;
    }

    /* Status requests, when a provider is bound for that specific one.
     * Otherwise they fall through to the application below. */
    if (handle_status_request(pd, cmd_code, reply)) {
        return OSDP_PD_DISPATCH_SEND;
    }

    /* An osdp_POLL with something queued is answered from the queue rather
     * than by the application — that is what "sent as a poll response" means
     * for osdp_RAW / KEYPAD / FMT / MFGREP. An empty queue falls through. */
    if (cmd_code == OSDP_CMD_POLL &&
        osdp_pd_internal_dequeue_event(pd, reply)) {
        return OSDP_PD_DISPATCH_SEND;
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

    const osdp_pd_dispatch_outcome_t outcome =
        apply_app_status(pd, app_status, reply);
    if (outcome != OSDP_PD_DISPATCH_SEND) {
        return outcome;
    }

    /* The app would ACK: if this was a KEYSET, rotate the key before the
     * reply goes out, and downgrade to NAK 0x09 if the record is unusable. */
    if (cmd_code == OSDP_CMD_KEYSET &&
        !apply_keyset_for_channel(pd, channel, payload, payload_len)) {
        nak_into(pd, OSDP_NAK_RECORD_INVALID, reply);
    }

    return OSDP_PD_DISPATCH_SEND;
}
