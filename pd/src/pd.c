// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pd.h"

#include "osdp/osdp_frame.h"
#include "osdp/osdp_replies.h"

#include <string.h>

/* ---- Helpers ------------------------------------------------------------*/

/* Build a reply frame in `pd->tx_buf` and return its length. Mirrors
 * the inbound frame's address (with the reply flag set), sequence
 * number, and integrity mode, per spec section 5.9. */
static osdp_status_t build_reply(osdp_pd_t                *pd,
                                 const osdp_frame_t       *cmd,
                                 const osdp_pd_reply_t    *reply,
                                 size_t                   *out_len)
{
    osdp_frame_t out;
    (void)memset(&out, 0, sizeof(out));
    out.address     = pd->address;
    out.reply       = true;
    out.sequence    = cmd->sequence;
    out.integrity   = cmd->integrity;
    /* Iteration 2 phase 1 does not transmit SCB-bearing replies. The
     * has_scb flag stays false; SCB-aware replies arrive with SC. */
    out.code        = reply->code;
    out.payload     = reply->payload;
    out.payload_len = reply->payload_len;
    return osdp_frame_build(&out, pd->tx_buf, sizeof(pd->tx_buf), out_len);
}

/* Build a NAK reply with the given error code. */
static osdp_status_t build_nak(osdp_pd_t          *pd,
                               const osdp_frame_t *cmd,
                               uint8_t             error_code,
                               size_t             *out_len)
{
    const osdp_pd_reply_t reply = {
        .code        = OSDP_REPLY_NAK,
        .payload     = &error_code,
        .payload_len = 1,
    };
    return build_reply(pd, cmd, &reply, out_len);
}

/* Send `len` bytes of pd->tx_buf via the transport, all at once. Short
 * writes are reported as send errors. */
static void send_tx(osdp_pd_t *pd, size_t len)
{
    if (pd->transport.write == NULL || len == 0) {
        return;
    }
    const int written = pd->transport.write(pd->transport.user,
                                             pd->tx_buf, len);
    /* For now we don't have a place to surface a partial-write error;
     * future iterations may queue, retry, or expose a status field. */
    (void)written;
}

/* Process one accepted command frame: dispatch to the application
 * handler, build the appropriate reply, transmit it. */
static void process_frame(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    /* Iteration 2 phase 1: refuse Secure Channel framing entirely.
     * The spec expects NAK with error code 0x05 (SCB unsupported). */
    if (cmd->has_scb) {
        size_t n = 0;
        if (build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n) == OSDP_OK) {
            send_tx(pd, n);
        }
        return;
    }

    osdp_pd_reply_t reply = { .code = OSDP_REPLY_ACK,
                              .payload = NULL, .payload_len = 0 };

    osdp_status_t app_status = OSDP_OK;
    if (pd->cmd_cb != NULL) {
        app_status = pd->cmd_cb(pd->cmd_user,
                                cmd->code,
                                cmd->payload, cmd->payload_len,
                                &reply);
    } else {
        /* No handler bound — treat every code as unsupported. */
        app_status = OSDP_ERR_NOT_SUPPORTED;
    }

    size_t built = 0;
    osdp_status_t br;
    if (app_status == OSDP_OK) {
        br = build_reply(pd, cmd, &reply, &built);
    } else if (app_status == OSDP_ERR_NOT_SUPPORTED) {
        br = build_nak(pd, cmd, OSDP_NAK_UNKNOWN_CMD, &built);
    } else {
        /* Internal handler error — drop silently in iteration 2.1. */
        return;
    }

    if (br == OSDP_OK) {
        send_tx(pd, built);
    }
}

/* ---- API ----------------------------------------------------------------*/

void osdp_pd_init(osdp_pd_t *pd, uint8_t address)
{
    if (pd == NULL) {
        return;
    }
    (void)memset(pd, 0, sizeof(*pd));
    pd->address = (uint8_t)(address & 0x7FU);
    osdp_stream_init(&pd->rx);
}

void osdp_pd_set_transport(osdp_pd_t *pd,
                           const osdp_pd_transport_t *transport)
{
    if (pd == NULL || transport == NULL) {
        return;
    }
    pd->transport = *transport;
}

void osdp_pd_set_command_handler(osdp_pd_t *pd,
                                 osdp_pd_command_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->cmd_cb   = cb;
    pd->cmd_user = user;
}

void osdp_pd_tick(osdp_pd_t *pd)
{
    if (pd == NULL || pd->transport.read == NULL) {
        return;
    }

    /* Drain everything the transport currently has. We pull in a
     * loop until the transport reports zero bytes, bounded by buffer
     * capacity to avoid hogging the CPU on a hostile peer. */
    uint8_t chunk[128];
    for (;;) {
        const int n = pd->transport.read(pd->transport.user,
                                         chunk, sizeof(chunk));
        if (n <= 0) {
            break;
        }
        (void)osdp_stream_feed(&pd->rx, chunk, (size_t)n);
        if ((size_t)n < sizeof(chunk)) {
            break; /* transport had less than a full chunk; done */
        }
    }

    /* Process every fully-received frame. */
    for (;;) {
        osdp_frame_t cmd;
        const osdp_status_t r = osdp_stream_next(&pd->rx, &cmd);
        if (r == OSDP_ERR_TRUNCATED) {
            break;
        }
        if (r != OSDP_OK) {
            /* Bad frame: stream has already advanced past it. Skip. */
            continue;
        }

        /* PD only responds to commands (reply flag clear). Frames in
         * the reply direction are ignored — they aren't addressed to
         * us in our role. */
        if (cmd.reply) {
            continue;
        }

        /* Address filtering: own address or broadcast. */
        const bool ours       = (cmd.address == pd->address);
        const bool broadcast  = (cmd.address == OSDP_BROADCAST_ADDR);
        if (!ours && !broadcast) {
            continue;
        }

        process_frame(pd, &cmd);
    }
}
