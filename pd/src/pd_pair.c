// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pd_pair.h"

#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc2.h"

#include "pd_internal.h"

#include <string.h>

/* Outbound fragment size for osdp_PAIRR replies (matches the reference). */
#define PD_PAIR_FRAG_SIZE OSDP_PAIR_DEFAULT_FRAGMENT_SIZE

static uint32_t pair_now_ms(const osdp_pd_t *pd)
{
    if (pd->transport.now_ms != NULL) {
        return pd->transport.now_ms(pd->transport.user);
    }
    return 0U;
}

/* Reset the exchange (keep the configured crypto / credential / trust). */
static void pair_reset(osdp_pd_pair_t *p)
{
    const osdp_pair_crypto_t *cr = p->session.crypto;
    osdp_pair_local_t lo = p->session.local;   /* copy before re-init zeroes */
    osdp_pair_trust_t tr = p->session.trust;
    osdp_pair_pd_init(&p->session, cr, &lo, &tr);
    osdp_pair_reasm_reset(&p->reasm);
    p->delivering    = false;
    p->active        = false;
    p->pending_apply = false;
}

/* ---- Reply emitters ----------------------------------------------------- */

static size_t emit_ack(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    const osdp_pd_reply_t reply = { OSDP_REPLY_ACK, NULL, 0 };
    size_t n = 0;
    return (osdp_pd_internal_build_reply(pd, cmd, &reply, &n) == OSDP_OK) ? n : 0;
}

static size_t emit_nak(osdp_pd_t *pd, const osdp_frame_t *cmd, uint8_t err)
{
    size_t n = 0;
    return (osdp_pd_internal_build_nak(pd, cmd, err, &n) == OSDP_OK) ? n : 0;
}

/* Frame one fragment descriptor as an osdp_PAIRR reply into pd->tx_buf. */
static size_t emit_pairr(osdp_pd_t *pd, const osdp_frame_t *cmd,
                         const osdp_pair_fragment_t *frag)
{
    uint8_t fbuf[OSDP_PAIR_FRAG_HEADER_BYTES + PD_PAIR_FRAG_SIZE];
    size_t  flen = 0;
    if (osdp_pair_fragment_build(frag, fbuf, sizeof(fbuf), &flen) != OSDP_OK) {
        return 0;
    }
    const osdp_pd_reply_t reply = { OSDP_REPLY_PAIRR, fbuf, flen };
    size_t n = 0;
    return (osdp_pd_internal_build_reply(pd, cmd, &reply, &n) == OSDP_OK) ? n : 0;
}

/* A whole (small) message as a single osdp_PAIRR fragment — the Result. */
static size_t emit_single(osdp_pd_t *pd, const osdp_frame_t *cmd,
                          const uint8_t *msg, size_t msg_len)
{
    const osdp_pair_fragment_t frag = {
        .total_size = (uint16_t)msg_len,
        .offset     = 0,
        .data       = msg,
        .frag_len   = msg_len,
    };
    return emit_pairr(pd, cmd, &frag);
}

/* Deliver the next queued Message-2 fragment in response to a POLL. */
static size_t deliver_msg2(osdp_pd_t *pd, osdp_pd_pair_t *p,
                           const osdp_frame_t *cmd)
{
    osdp_pair_fragment_t frag;
    if (!osdp_pair_frag_iter_next(&p->out_iter, &frag)) {
        p->delivering = false;
        return emit_ack(pd, cmd);
    }
    const size_t n = emit_pairr(pd, cmd, &frag);
    if (p->out_iter.offset >= p->out_iter.msg_len) {
        p->delivering = false;   /* last fragment sent */
    }
    return n;
}

/* ---- Inbound complete-message handling ---------------------------------- */

/* Message 3 assembled: verify, (optionally persist), reply Result inline,
 * stage the SCBK for the post-send handoff. */
static size_t handle_msg3(osdp_pd_t *pd, osdp_pd_pair_t *p,
                          const osdp_frame_t *cmd,
                          const uint8_t *msg, size_t msg_len)
{
    bool    ok = false;
    uint8_t scbk[OSDP_PAIR_SCBK_LEN];
    osdp_pair_reasm_reset(&p->reasm);

    if (osdp_pair_pd_process_msg3(&p->session, msg, msg_len, &ok, scbk)
        != OSDP_OK) {
        pair_reset(p);
        return emit_nak(pd, cmd, OSDP_NAK_RECORD_INVALID);
    }

    uint64_t status;
    if (ok) {
        bool persisted = true;
        if (p->cb != NULL) {
            persisted = p->cb(p->cb_user, &p->session.peer, scbk);
        }
        if (persisted) {
            status = OSDP_PAIR_STATUS_SUCCESS;
            (void)memcpy(p->scbk, scbk, OSDP_PAIR_SCBK_LEN);
            p->pending_apply = true;   /* applied after the Result is sent */
        } else {
            status = OSDP_PAIR_STATUS_PERSIST_FAIL;
        }
    } else {
        status = OSDP_PAIR_STATUS_AUTH_FAIL;
    }

    size_t outlen = 0;
    if (osdp_pair_pd_build_result(&p->session, status,
                                  p->outbuf, sizeof(p->outbuf), &outlen)
        != OSDP_OK) {
        pair_reset(p);
        return 0;
    }
    p->active = false;   /* Result is terminal for this exchange */
    return emit_single(pd, cmd, p->outbuf, outlen);
}

/* Message 1 assembled: authenticate + build Message 2 (queued for POLLs) or
 * a rejection Result (inline). */
static size_t handle_msg1(osdp_pd_t *pd, osdp_pd_pair_t *p,
                          const osdp_frame_t *cmd,
                          const uint8_t *msg, size_t msg_len)
{
    osdp_pair_reasm_reset(&p->reasm);

    size_t outlen = 0;
    bool   is_reject = false;
    if (osdp_pair_pd_process_msg1(&p->session, msg, msg_len,
                                  p->outbuf, sizeof(p->outbuf), &outlen,
                                  &is_reject) != OSDP_OK) {
        pair_reset(p);
        return emit_nak(pd, cmd, OSDP_NAK_RECORD_INVALID);
    }

    if (is_reject) {
        p->active = false;
        return emit_single(pd, cmd, p->outbuf, outlen);
    }

    /* Message 2: deliver over subsequent POLLs; ACK this last Msg1 fragment. */
    osdp_pair_frag_iter_init(&p->out_iter, p->outbuf, outlen, PD_PAIR_FRAG_SIZE);
    p->delivering = true;
    return emit_ack(pd, cmd);
}

/* ---- Hook vtable -------------------------------------------------------- */

static bool pair_wants(struct osdp_pd *pd, const osdp_frame_t *cmd)
{
    const osdp_pd_pair_t *p = (const osdp_pd_pair_t *)pd->pair;
    if (cmd->has_scb) {
        return false;                 /* pairing is cleartext */
    }
    if (cmd->code == OSDP_CMD_PAIR) {
        return true;
    }
    return cmd->code == OSDP_CMD_POLL && p->delivering;
}

static size_t pair_handle(struct osdp_pd *pd, const osdp_frame_t *cmd)
{
    osdp_pd_pair_t *p = (osdp_pd_pair_t *)pd->pair;

    /* Drop a stalled exchange (30 s inactivity). */
    if (p->active) {
        const uint32_t t = pair_now_ms(pd);
        if ((uint32_t)(t - p->last_activity_ms) > OSDP_PAIR_SESSION_TIMEOUT_MS) {
            pair_reset(p);
        }
    }

    if (cmd->code == OSDP_CMD_POLL) {
        return deliver_msg2(pd, p, cmd);
    }

    /* osdp_PAIR: accumulate one inbound fragment. */
    p->last_activity_ms = pair_now_ms(pd);
    p->active           = true;

    osdp_pair_fragment_t frag;
    if (osdp_pair_fragment_decode(cmd->payload, cmd->payload_len, &frag)
        != OSDP_OK) {
        return emit_nak(pd, cmd, OSDP_NAK_RECORD_INVALID);
    }

    bool complete = false;
    if (osdp_pair_reasm_push(&p->reasm, &frag, &complete) != OSDP_OK) {
        pair_reset(p);
        return emit_nak(pd, cmd, OSDP_NAK_RECORD_INVALID);
    }
    if (!complete) {
        return emit_ack(pd, cmd);
    }

    /* Route the completed message by handshake state. `msg` aliases the
     * reassembly buffer, which reset() leaves intact. */
    const uint8_t *msg     = p->reasm.buf;
    const size_t   msg_len = p->reasm.total;
    if (p->session.state == OSDP_PAIR_PD_AWAIT_MSG3) {
        return handle_msg3(pd, p, cmd, msg, msg_len);
    }
    return handle_msg1(pd, p, cmd, msg, msg_len);
}

static void pair_post_send(struct osdp_pd *pd)
{
    osdp_pd_pair_t *p = (osdp_pd_pair_t *)pd->pair;
    if (!p->pending_apply) {
        return;
    }
    p->pending_apply = false;

    /* Apply the paired key to the SC2 channel in place and reset the SC2
     * session so the ACU's next CHLNG establishes with the new SCBK. The
     * SC2 crypto vtable + cUID must already be configured by the app. */
    (void)memcpy(pd->sc2.scbk, p->scbk, OSDP_SC2_KEY_LEN);
    pd->sc2.scbk_set = true;
    osdp_sc2_session_init(&pd->sc2.session);
    pd->sc2.got_chlng = false;
}

/* ---- Public API --------------------------------------------------------- */

void osdp_pd_pair_init(osdp_pd_pair_t           *pair,
                       const osdp_pair_crypto_t *crypto,
                       const osdp_pair_local_t  *local,
                       const osdp_pair_trust_t  *trust)
{
    if (pair == NULL) {
        return;
    }
    (void)memset(pair, 0, sizeof(*pair));
    pair->hook.wants     = pair_wants;
    pair->hook.handle    = pair_handle;
    pair->hook.post_send = pair_post_send;
    osdp_pair_pd_init(&pair->session, crypto, local, trust);
    osdp_pair_reasm_init(&pair->reasm, pair->inbuf, sizeof(pair->inbuf));
}

void osdp_pd_pair_set_established_handler(osdp_pd_pair_t             *pair,
                                          osdp_pd_pair_established_cb cb,
                                          void                      *user)
{
    if (pair == NULL) {
        return;
    }
    pair->cb      = cb;
    pair->cb_user = user;
}

void osdp_pd_attach_pair(osdp_pd_t *pd, osdp_pd_pair_t *pair)
{
    if (pd == NULL || pair == NULL) {
        return;
    }
    pd->pair = pair;
}
