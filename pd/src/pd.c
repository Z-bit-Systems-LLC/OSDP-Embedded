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
    /* SCB-bearing replies are deferred to iteration 3 with SC. */
    out.code        = reply->code;
    out.payload     = reply->payload;
    out.payload_len = reply->payload_len;
    return osdp_frame_build(&out, pd->tx_buf, sizeof(pd->tx_buf), out_len);
}

/* Build a NAK reply with the given error code into pd->tx_buf. */
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

/* Send `len` bytes from `buf` via the bound transport. Short writes
 * are dropped on the floor for now; future iterations may queue or
 * report a transmission error. */
static void send_bytes(osdp_pd_t *pd, const uint8_t *buf, size_t len)
{
    if (pd->transport.write == NULL || len == 0) {
        return;
    }
    const int written = pd->transport.write(pd->transport.user, buf, len);
    (void)written;
}

/* Compute the reply for a fresh command into pd->tx_buf and return
 * the byte count (or 0 if the command should produce no reply at all
 * — e.g. an internal handler error). */
static size_t handle_command_into_tx(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    /* Refuse Secure Channel framing with NAK 0x05 until SC arrives. */
    if (cmd->has_scb) {
        size_t n = 0;
        if (build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n) != OSDP_OK) {
            return 0;
        }
        return n;
    }

    osdp_pd_reply_t reply = {
        .code        = OSDP_REPLY_ACK,
        .payload     = NULL,
        .payload_len = 0,
    };

    osdp_status_t app_status = OSDP_ERR_NOT_SUPPORTED;
    if (pd->cmd_cb != NULL) {
        app_status = pd->cmd_cb(pd->cmd_user,
                                cmd->code,
                                cmd->payload, cmd->payload_len,
                                &reply);
    }

    size_t built = 0;
    osdp_status_t br;
    if (app_status == OSDP_OK) {
        br = build_reply(pd, cmd, &reply, &built);
    } else if (app_status == OSDP_ERR_NOT_SUPPORTED) {
        br = build_nak(pd, cmd, OSDP_NAK_UNKNOWN_CMD, &built);
    } else {
        /* Internal handler error — drop silently. */
        return 0;
    }

    return (br == OSDP_OK) ? built : 0;
}

/* Cache `pd->tx_buf[0..len]` as the reply we just sent for sequence
 * number `seq`, so a retransmit can replay it. */
static void cache_reply(osdp_pd_t *pd, uint8_t seq, size_t len)
{
    if (len > sizeof(pd->last_reply)) {
        /* Should be impossible — tx_buf and last_reply are the same
         * size — but guard anyway. */
        len = sizeof(pd->last_reply);
    }
    if (len > 0) {
        (void)memcpy(pd->last_reply, pd->tx_buf, len);
    }
    pd->last_reply_len = len;
    pd->last_seq       = seq;
    pd->have_last      = true;
}

/* Process one accepted command frame: dispatch, build reply, cache,
 * transmit. Honours the SQN retransmit semantics from spec 5.9. */
static void process_frame(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    /* Retransmit detection: same non-zero SQN as the previous accepted
     * command means the ACU is asking us to repeat our last reply
     * without re-executing the command. SQN zero is the session-reset
     * sentinel and is always processed fresh. */
    if (cmd->sequence != 0 &&
        pd->have_last &&
        cmd->sequence == pd->last_seq)
    {
        if (pd->last_reply_len > 0) {
            send_bytes(pd, pd->last_reply, pd->last_reply_len);
        }
        return;
    }

    const size_t built = handle_command_into_tx(pd, cmd);
    cache_reply(pd, cmd->sequence, built);
    if (built > 0) {
        send_bytes(pd, pd->tx_buf, built);
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

    /* Drain whatever the transport has now. */
    uint8_t chunk[128];
    for (;;) {
        const int n = pd->transport.read(pd->transport.user,
                                         chunk, sizeof(chunk));
        if (n <= 0) {
            break;
        }
        (void)osdp_stream_feed(&pd->rx, chunk, (size_t)n);
        if ((size_t)n < sizeof(chunk)) {
            break;
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
            continue;  /* stream auto-advanced past the bad frame */
        }
        if (cmd.reply) {
            continue;  /* wrong direction for a PD */
        }
        const bool ours      = (cmd.address == pd->address);
        const bool broadcast = (cmd.address == OSDP_BROADCAST_ADDR);
        if (!ours && !broadcast) {
            continue;
        }

        process_frame(pd, &cmd);
    }
}
