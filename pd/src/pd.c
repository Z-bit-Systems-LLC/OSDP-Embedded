// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pd.h"

#include "osdp/osdp_commands.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"

#include "pd_internal.h"

#include <string.h>

/* ---- Helpers ------------------------------------------------------------*/

/* Build a reply frame in the bound TX buffer and return its length. Mirrors
 * the inbound frame's address (with the reply flag set), sequence
 * number, and integrity mode, per spec section 5.9. */
static osdp_status_t build_reply(osdp_pd_t                *pd,
                                 const osdp_frame_t       *cmd,
                                 const osdp_pd_reply_t    *reply,
                                 size_t                   *out_len)
{
    osdp_frame_t out;
    (void)memset(&out, 0, sizeof(out));
    /* Mirror the inbound destination address (spec 5.9 Note 2). A command
     * addressed to 0x7F (the configuration/broadcast address) is answered at
     * 0x7F + reply flag = 0xFF, not at the PD's own address; a command to the
     * configured address is answered there. cmd->address is the decoded 7-bit
     * value, so this is either pd->address or OSDP_CONFIG_ADDR. */
    out.address     = cmd->address;
    out.reply       = true;
    out.sequence    = cmd->sequence;
    out.integrity   = cmd->integrity;
    /* SCB-bearing replies are deferred to iteration 3 with SC. */
    out.code        = reply->code;
    out.payload     = reply->payload;
    out.payload_len = reply->payload_len;
    return osdp_frame_build(&out, pd->tx, pd->tx_cap, out_len);
}

osdp_status_t osdp_pd_internal_build_busy(osdp_pd_t          *pd,
                                          const osdp_frame_t *cmd,
                                          size_t             *out_len)
{
    if (pd == NULL || cmd == NULL || out_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Spec 7.19 puts three rules on osdp_BUSY, all of them exceptions to how
     * every other reply is framed, and all three live here so no caller has
     * to remember them:
     *
     *   1. The sequence number is always 0, not the inbound SQN. Mirroring
     *      the command's SQN — which build_reply does for everything else —
     *      would be wrong.
     *   2. It goes out PLAINTEXT even during an established Secure Channel,
     *      and must not advance the MAC chain. So this builds the frame
     *      directly instead of routing through osdp_sc_wrap_frame, and it is
     *      why the SC paths call this rather than framing BUSY themselves.
     *      osdp_BUSY is one of only three replies (with osdp_NAK 0x01 and
     *      0x06) the spec permits outside the SCS format.
     *   3. It must not be cached as the retransmit answer: the ACU repeats
     *      the command in its original form until it gets something else, so
     *      replaying a stale BUSY would answer a command the PD is by then
     *      ready to handle. process_frame honours pd->reply_cacheable. */
    pd->reply_cacheable = false;

    osdp_frame_t out;
    (void)memset(&out, 0, sizeof(out));
    out.address     = cmd->address;   /* mirror, as elsewhere (5.9 Note 2) */
    out.reply       = true;
    out.sequence    = 0;              /* rule 1 */
    out.integrity   = cmd->integrity;
    out.code        = OSDP_REPLY_BUSY;
    out.payload     = NULL;
    out.payload_len = 0;              /* Table 62: DATA omitted */
    return osdp_frame_build(&out, pd->tx, pd->tx_cap, out_len);
}

/* Build a NAK reply with the given error code into the bound TX buffer. */
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

/* Apply an incoming KEYSET payload to the PD's SCBK. Called from
 * both the plaintext (pd.c) and SC (pd_sc.c) dispatch paths after
 * the application handler has ACK'd the command.
 *
 * Spec semantic: the new SCBK takes effect on the *next* handshake.
 * The existing SC session (session keys, SQN, etc.) keeps running —
 * the ACU initiates a fresh handshake when it wants to switch to
 * the rotated key. This matches how real PDs behave: KEYSET is an
 * out-of-band write to persistent storage; SC continues until
 * either side decides to re-handshake. */
osdp_status_t osdp_pd_internal_apply_keyset(osdp_pd_t     *pd,
                                            const uint8_t *payload,
                                            size_t         payload_len)
{
    osdp_keyset_cmd_t parsed;
    const osdp_status_t s = osdp_keyset_decode(payload, payload_len, &parsed);
    if (s != OSDP_OK) {
        return s;  /* malformed envelope → caller NAK's */
    }
    if (parsed.key_type != OSDP_KEYSET_KEY_TYPE_SCBK) {
        /* v2.2 baseline defines only SCBK. A recognized command carrying
         * an unusable record parameter is spec Table 47 error 0x09
         * "Unable to process command record" — NOT 0x03, which the spec
         * reserves for command codes the PD does not implement (and
         * KEYSET *is* implemented). The caller maps this onto NAK 0x09. */
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (parsed.key_length != OSDP_SC_KEY_LEN || parsed.key_data == NULL) {
        /* Wrong key size is likewise an invalid record → NAK 0x09. */
        return OSDP_ERR_BAD_PAYLOAD;
    }

    /* Overwrite the stored SCBK and mark it set. The crypto vtable,
     * cuid, scbk_d, and the live session keys (s_enc / s_mac1 /
     * s_mac2 / counters in pd->sc.session) are all left alone. */
    (void)memcpy(pd->sc.scbk, parsed.key_data, OSDP_SC_KEY_LEN);
    pd->sc.scbk_set = true;
    return OSDP_OK;
}

/* Highest address a COMSET may assign (spec 6.13 Table 22: 0x00..0x7E).
 * 0x7F is the configuration/broadcast address (OSDP_CONFIG_ADDR): the PD
 * always responds to it, but it is never a valid COMSET assignment target,
 * so a request to set the working address to 0x7F is rejected. */
#define OSDP_PD_MAX_ADDR 0x7EU

osdp_status_t osdp_pd_internal_comset_effective(osdp_pd_t     *pd,
                                                const uint8_t *payload,
                                                size_t         payload_len,
                                                uint8_t       *eff_addr,
                                                uint32_t      *eff_baud,
                                                uint8_t       *com_payload)
{
    osdp_comset_cmd_t req;
    osdp_status_t s = osdp_comset_decode(payload, payload_len, &req);
    if (s != OSDP_OK) {
        return s;  /* malformed → caller NAK's with bad-length */
    }

    /* Seed the effective values with the request, then let the
     * application override them if it cannot comply (spec 6.13). */
    uint8_t  addr = req.address;
    uint32_t baud = req.baud_rate;
    if (pd->comset_cb != NULL) {
        pd->comset_cb(pd->comset_user, req.address, req.baud_rate,
                      &addr, &baud);
    }
    /* An out-of-range effective address means "can't comply" — keep the
     * current address rather than adopting an unaddressable value. */
    if (addr > OSDP_PD_MAX_ADDR) {
        addr = pd->address;
    }

    const osdp_com_t com = { .address = addr, .baud_rate = baud };
    size_t written = 0;
    s = osdp_com_build(&com, com_payload, OSDP_COM_PAYLOAD_BYTES, &written);
    if (s != OSDP_OK) {
        return s;
    }
    *eff_addr = addr;
    *eff_baud = baud;
    return OSDP_OK;
}

void osdp_pd_internal_apply_comset(osdp_pd_t *pd)
{
    pd->comset_pending = false;
    pd->address        = pd->comset_new_address;
    /* The address change invalidates the retransmit / SQN cache: a resend
     * of the COMSET would arrive at the old address and no longer match,
     * and the ACU will reset the sequence when it reconnects at the new
     * parameters. Drop the cache so the reconnect starts clean. */
    pd->have_last = false;
    if (pd->comset_applied_cb != NULL) {
        pd->comset_applied_cb(pd->comset_user,
                              pd->comset_new_address, pd->comset_new_baud);
    }
}

osdp_status_t osdp_pd_internal_filetransfer(osdp_pd_t     *pd,
                                            const uint8_t *payload,
                                            size_t         payload_len,
                                            uint8_t       *ftstat_payload)
{
    /* No handler bound → the PD does not implement file transfer. The
     * caller turns this into NAK 0x03 (Unknown Command Code). */
    if (pd->file_cb == NULL) {
        return OSDP_ERR_NOT_SUPPORTED;
    }

    /* Two modes, distinguished by whether a reassembly buffer was supplied:
     *   - reassembly (file_buf != NULL): the core copies each fragment into
     *     the buffer and hands the accumulated file to the callback. Bounded
     *     by file_cap.
     *   - streaming  (file_buf == NULL): the core hands each fragment to the
     *     callback as it arrives without accumulating (for RAM-constrained
     *     targets that persist fragments to flash). No capacity ceiling. */
    const bool streaming = (pd->file_buf == NULL);

    osdp_filetransfer_cmd_t ft;
    if (osdp_filetransfer_decode(payload, payload_len, &ft) != OSDP_OK) {
        return OSDP_ERR_BAD_PAYLOAD;  /* undecodable frame → caller NAKs 0x02 */
    }

    /* Reassembly bookkeeping. Any invariant violation aborts the transfer:
     * we report FtStatusDetail = -1 and drop the active state so the ACU can
     * restart from offset 0. */
    bool ok = true;
    if (ft.offset == 0) {
        /* First fragment: (re)start the transfer. */
        pd->ft_active   = true;
        pd->ft_type     = ft.ft_type;
        pd->ft_total    = ft.total_size;
        pd->ft_received = 0;
        if (!streaming && ft.total_size > pd->file_cap) {
            ok = false;  /* file won't fit the receiver buffer */
        }
    } else if (!pd->ft_active) {
        ok = false;      /* continuation with no transfer in progress */
    } else if (ft.offset != pd->ft_received) {
        ok = false;      /* gap / out-of-order / non-monotonic offset */
    } else if (ft.ft_type != pd->ft_type || ft.total_size != pd->ft_total) {
        ok = false;      /* transfer parameters changed mid-stream */
    }
    if (ok && ft.fragment_size > 0) {
        /* 64-bit math so a hostile offset+size can't wrap. */
        const uint64_t end = (uint64_t)ft.offset + ft.fragment_size;
        if (end > pd->ft_total) {
            ok = false;  /* fragment runs past the declared size */
        } else if (!streaming && end > pd->file_cap) {
            ok = false;  /* fragment runs past the receiver buffer */
        }
    }

    osdp_ftstat_t st = {
        .action         = 0,
        .delay_ms       = 0,
        .status_detail  = OSDP_FTSTAT_OK,
        .update_msg_max = 0,
    };

    if (!ok) {
        pd->ft_active     = false;
        st.status_detail  = OSDP_FTSTAT_ABORT;
    } else {
        /* Reassembly mode copies the fragment into the buffer; streaming mode
         * leaves it in place (the callback reads info->fragment). Either way
         * advance the running offset for progress + monotonicity. */
        if (ft.fragment_size > 0 && ft.data != NULL) {
            if (!streaming) {
                (void)memcpy(&pd->file_buf[ft.offset], ft.data,
                             ft.fragment_size);
            }
            pd->ft_received += ft.fragment_size;
        }
        const bool complete = (pd->ft_received >= pd->ft_total);

        const osdp_pd_file_info_t info = {
            .ft_type      = pd->ft_type,
            .total_size   = pd->ft_total,
            .offset       = ft.offset,
            .fragment     = ft.data,
            .fragment_len = ft.fragment_size,
            .data         = streaming ? NULL : pd->file_buf,
            .received     = pd->ft_received,
            .complete     = complete,
        };
        const osdp_status_t verdict = pd->file_cb(pd->file_user, &info);

        switch (verdict) {
        case OSDP_OK:
            st.status_detail = complete ? OSDP_FTSTAT_PROCESSED
                                        : OSDP_FTSTAT_OK;
            break;
        case OSDP_ERR_BAD_PAYLOAD:
            st.status_detail = OSDP_FTSTAT_MALFORMED;
            break;
        case OSDP_ERR_NOT_SUPPORTED:
            st.status_detail = OSDP_FTSTAT_UNRECOGNIZED;
            break;
        default:
            st.status_detail = OSDP_FTSTAT_ABORT;
            break;
        }

        /* A negative verdict or a clean completion ends the transfer. */
        if (st.status_detail < 0 || complete) {
            pd->ft_active = false;
        }
    }

    size_t written = 0;
    return osdp_ftstat_build(&st, ftstat_payload,
                             OSDP_FTSTAT_PAYLOAD_BYTES, &written);
}

/* Exposed under a stable name (declared in pd_internal.h) so the SC
 * handlers in pd_sc.c can build NAKs without duplicating the helper.
 * Same signature as the static `build_nak` above. */
osdp_status_t osdp_pd_internal_build_nak(osdp_pd_t          *pd,
                                         const osdp_frame_t *cmd,
                                         uint8_t             error_code,
                                         size_t             *out_len)
{
    return build_nak(pd, cmd, error_code, out_len);
}

/* Shared with the Secure Channel handler so it can frame replies the same way
 * the plaintext path does. */
osdp_status_t osdp_pd_internal_build_reply(osdp_pd_t             *pd,
                                           const osdp_frame_t    *cmd,
                                           const osdp_pd_reply_t *reply,
                                           size_t                *out_len)
{
    return build_reply(pd, cmd, reply, out_len);
}

/* Send `len` bytes from `buf` via the bound transport. Short writes
 * are dropped on the floor for now; future iterations may queue or
 * report a transmission error.
 *
 * On a successful (non-empty) send, the PD is considered to have just
 * communicated: refresh last_comm_ms and set online = true so spec
 * 5.7's 8-second silence window starts over. */
static void send_bytes(osdp_pd_t *pd, const uint8_t *buf, size_t len)
{
    if (pd->transport.write == NULL || len == 0) {
        return;
    }
    const int written = pd->transport.write(pd->transport.user, buf, len);
    (void)written;

    if (pd->transport.now_ms != NULL) {
        pd->last_comm_ms = pd->transport.now_ms(pd->transport.user);
    }
    pd->online = true;
}

/* If the PD has been online but no reply has been sent for longer than
 * OSDP_PD_OFFLINE_TIMEOUT_MS, transition to offline and clear the
 * sequence-number cache so the next reconnect starts cleanly. No-op
 * when the transport does not provide a now_ms callback. */
static void check_offline_timeout(osdp_pd_t *pd)
{
    if (!pd->online || pd->transport.now_ms == NULL) {
        return;
    }
    const uint32_t now = pd->transport.now_ms(pd->transport.user);
    /* Unsigned subtraction wraps cleanly modulo 2^32, so a 49.7-day
     * monotonic wraparound doesn't spuriously trigger an offline. */
    const uint32_t elapsed = now - pd->last_comm_ms;
    if (elapsed > OSDP_PD_OFFLINE_TIMEOUT_MS) {
        pd->online    = false;
        pd->have_last = false;  /* drop SQN cache; ACU will reset SQN */
        /* Spec 7.11/7.12: "unreported card/keypad data is deleted in case of,
         * or during, a communication loss." Delivering a credential read
         * minutes ago to an ACU that has since reconnected would be worse
         * than losing it — the ACU would act on a stale presentation. */
        osdp_pd_clear_events(pd);
    }
}

/* Clear-text (unsecured) commands a full-security PD still answers before a
 * Secure Channel session is established: the discovery and comms-config
 * commands the ACU legitimately needs to find the PD and bring SC up
 * (osdp_ID, osdp_CAP, osdp_COMSET). Every other clear-text command is
 * refused with NAK 0x06 until SC is established. The SCS_11..14 handshake
 * itself carries an SCB and never reaches this clear-text path, so it does
 * not need to be listed here. */
static bool clear_command_allowed_pre_sc(uint8_t code)
{
    return code == OSDP_CMD_ID ||
           code == OSDP_CMD_CAP ||
           code == OSDP_CMD_COMSET;
}

/* Compute the reply for a fresh command into the bound TX buffer and return
 * the byte count (or 0 if the command should produce no reply at all
 * — e.g. an internal handler error). */
static size_t handle_command_into_tx(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    /* Secure Channel: SCB-bearing frames (the SCS_11..14 handshake and the
     * SCS_15..18 operational traffic) go to the SC handler if the application
     * has supplied enough configuration; otherwise fall back to the
     * historical "NAK 0x05" behaviour. */
    if (cmd->has_scb) {
        if (osdp_pd_internal_sc_configured(pd)) {
            return osdp_pd_internal_handle_sc_into_tx(pd, cmd);
        }
        size_t n = 0;
        if (build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n) != OSDP_OK) {
            return 0;
        }
        return n;
    }

    /* Clear-text (unsecured, "USC") command. A *secure* (SCB-bearing) frame is
     * handled above and never reaches here, so this is the USC policy.
     *
     * Sequence 0 is the ACU's connection-restart sentinel (spec 5.9): it is
     * only sent when the link is being (re)started, so any Secure Channel
     * session the PD still believes in is stale and is dropped — SC1 and SC2
     * alike — WITHOUT that counting as an interleaving violation. Dropping the
     * session is all SQN 0 buys, though: the command still has to satisfy the
     * secure-mode allowlist below. Once a PD is keyed for full security only
     * the discovery/config commands are ever answered in the clear, whatever
     * the sequence number; SQN 0 is not an escape hatch around Secure Channel.
     *
     * Sequence != 0 during an established session IS an interleaving violation
     * (spec D "Interleaving USC packets during communication in a SCS is NOT
     * allowed"): drop the session and answer osdp_NAK 0x06 immediately, so the
     * ACU sees the refusal rather than a silently-processed command. */
    if (cmd->sequence == 0) {
        if (pd->sc.session.established) {
            osdp_sc_session_init(&pd->sc.session);
            pd->sc.got_chlng = false;
        }
    } else {
        if (pd->sc.session.established) {
            osdp_sc_session_init(&pd->sc.session);
            pd->sc.got_chlng = false;
            size_t n = 0;
            (void)build_nak(pd, cmd, OSDP_NAK_ENCRYPTION_REQUIRED, &n);
            return n;
        }
    }

    /* Secure-mode allowlist, applied at EVERY sequence number including 0.
     * A PD keyed for full security (an operational SCBK is set — not merely
     * SCBK-D) answers only the discovery/config
     * commands the ACU needs to find it and bring SC up: osdp_ID, osdp_CAP,
     * osdp_COMSET. Everything else is refused osdp_NAK 0x06 until a session
     * exists. A PD with no operational key (clear-only or install-only) is
     * not in secure mode and falls through, processing clear-text normally.
     *
     * NAK 0x06 is one of the few replies the spec permits in the clear, so
     * build_nak's plaintext frame is correct even when a session was active a
     * moment ago. */
    if (pd->sc.scbk_set && !clear_command_allowed_pre_sc(cmd->code)) {
        size_t n = 0;
        (void)build_nak(pd, cmd, OSDP_NAK_ENCRYPTION_REQUIRED, &n);
        return n;
    }

    /* Decide the reply. Everything that knows what a command MEANS —
     * library-handled osdp_COMSET / osdp_FILETRANSFER, the application
     * handler, the KEYSET hook, reader-state observation — lives in the
     * shared dispatch (pd_dispatch.c) so the plaintext, SC1 and SC2 paths
     * cannot drift apart. All that is left here is plaintext framing. */
    osdp_pd_reply_t reply;
    const osdp_pd_dispatch_outcome_t outcome =
        osdp_pd_internal_dispatch(pd, OSDP_PD_CH_PLAIN, cmd->code,
                                  cmd->payload, cmd->payload_len, &reply);
    size_t built = 0;
    switch (outcome) {
    case OSDP_PD_DISPATCH_BUSY:
        return (osdp_pd_internal_build_busy(pd, cmd, &built) == OSDP_OK)
                   ? built : 0;
    case OSDP_PD_DISPATCH_DROP:
        return 0;  /* unrecognised handler error — drop silently */
    case OSDP_PD_DISPATCH_SEND:
    default:
        return (build_reply(pd, cmd, &reply, &built) == OSDP_OK) ? built : 0;
    }
}

/* Cache the command we just accepted alongside the reply we just
 * built, so a future byte-identical retransmit can replay the reply
 * without re-executing the command (spec 5.9). Frames whose raw
 * bytes don't fit in our cache (oversized commands) are simply not
 * cached — they'll always be processed fresh, which is conservative
 * and correct. */
static void cache_reply(osdp_pd_t          *pd,
                        const osdp_frame_t *cmd,
                        size_t              reply_len)
{
    /* Cache the reply verbatim, but only if it fits. With the default
     * bindings the reply cache is the same size as the TX buffer so this
     * never bites; a caller that binds a smaller cache than TX gets no
     * replay for oversized replies rather than a truncated one — the ACU's
     * retransmit is then processed fresh, which is always correct. */
    if (reply_len > 0 && reply_len <= pd->rpl_cache_cap) {
        (void)memcpy(pd->rpl_cache, pd->tx, reply_len);
        pd->last_reply_len = reply_len;
    } else {
        pd->last_reply_len = 0;
    }

    /* Cache the inbound command's wire bytes for retransmit detection.
     * If raw isn't available or is too large, skip caching the cmd —
     * the next frame will then bypass the cache and process fresh. */
    if (cmd->raw != NULL && cmd->raw_len > 0 &&
        cmd->raw_len <= pd->cmd_cache_cap) {
        (void)memcpy(pd->cmd_cache, cmd->raw, cmd->raw_len);
        pd->last_cmd_len = cmd->raw_len;
    } else {
        pd->last_cmd_len = 0;
    }

    pd->last_seq  = cmd->sequence;
    pd->have_last = true;
}

/* True iff `cmd` is byte-identical to the previously accepted command,
 * which per spec 5.9 is the unambiguous marker of a retransmit. SQN
 * zero is the session-reset sentinel and never counts as a retransmit
 * regardless of cache contents. */
static bool is_retransmit(const osdp_pd_t    *pd,
                          const osdp_frame_t *cmd)
{
    if (cmd->sequence == 0 || !pd->have_last) {
        return false;
    }
    if (pd->last_cmd_len == 0 || cmd->raw == NULL) {
        return false;
    }
    if (cmd->raw_len != pd->last_cmd_len) {
        return false;
    }
    return memcmp(pd->cmd_cache, cmd->raw, cmd->raw_len) == 0;
}

/* Process one accepted command frame: dispatch, build reply, cache,
 * transmit. Honours the byte-identical retransmit rule from spec 5.9. */
static void process_frame(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    if (is_retransmit(pd, cmd)) {
        if (pd->last_reply_len > 0) {
            send_bytes(pd, pd->rpl_cache, pd->last_reply_len);
        }
        return;
    }

    /* Assume the reply is cacheable; the BUSY builder is the one thing that
     * clears this, since the ACU repeats a BUSY'd command in its original
     * form and would otherwise be answered from the cache forever. */
    pd->reply_cacheable = true;

    const size_t built = handle_command_into_tx(pd, cmd);
    if (pd->reply_cacheable) {
        cache_reply(pd, cmd, built);
    } else {
        /* Not cached, and the previous cache entry must go too: leaving it
         * would let an unrelated later retransmit match a stale command. */
        pd->have_last = false;
    }
    if (built > 0) {
        send_bytes(pd, pd->tx, built);
    }

    /* osdp_COMSET: the new comms parameters take effect only AFTER the
     * osdp_COM reply has been transmitted at the old parameters (spec
     * 6.13). Apply the staged change now — this also drops the SQN cache
     * populated by cache_reply() above. */
    if (pd->comset_pending) {
        osdp_pd_internal_apply_comset(pd);
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

    /* Point every working region at its embedded array. From here on the
     * library only ever goes through these pointers, so osdp_pd_set_buffers
     * can swap any of them for caller-owned storage without touching another
     * line of the state machine. */
    pd->tx            = pd->tx_buf;
    pd->tx_cap        = sizeof(pd->tx_buf);
    pd->rx_plain      = pd->rx_plain_buf;
    pd->rx_plain_cap  = sizeof(pd->rx_plain_buf);
    pd->rpl_cache     = pd->last_reply;
    pd->rpl_cache_cap = sizeof(pd->last_reply);
    pd->cmd_cache     = pd->last_cmd;
    pd->cmd_cache_cap = sizeof(pd->last_cmd);

    /* Until an ACU sends osdp_ACURXSIZE, assume the conservative default from
     * spec 6.26 rather than the protocol maximum — over-estimating the peer's
     * buffer produces replies it silently drops. */
    pd->acu_rx_size = OSDP_PD_DEFAULT_ACU_RX_SIZE;
}

osdp_status_t osdp_pd_set_buffers(osdp_pd_t *pd, const osdp_pd_buffers_t *bufs)
{
    if (pd == NULL || bufs == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Validate every supplied region before applying any of them, so a
     * rejected call is a no-op rather than a half-applied binding. A NULL
     * pointer means "leave this region alone", whatever its capacity field
     * says. */
    const uint8_t *const ptrs[] = { bufs->tx, bufs->rx_plain,
                                    bufs->rpl_cache, bufs->cmd_cache };
    const size_t         caps[] = { bufs->tx_cap, bufs->rx_plain_cap,
                                    bufs->rpl_cache_cap, bufs->cmd_cache_cap };
    for (size_t i = 0; i < sizeof(ptrs) / sizeof(ptrs[0]); i++) {
        if (ptrs[i] != NULL && caps[i] < OSDP_PD_BUF_MIN_LEN) {
            return OSDP_ERR_BUFFER_TOO_SMALL;
        }
    }

    if (bufs->tx != NULL) {
        pd->tx     = bufs->tx;
        pd->tx_cap = bufs->tx_cap;
    }
    if (bufs->rx_plain != NULL) {
        pd->rx_plain     = bufs->rx_plain;
        pd->rx_plain_cap = bufs->rx_plain_cap;
    }
    /* Rebinding a retransmit cache invalidates what it recorded: the lengths
     * describe bytes in storage the PD is about to stop reading. Drop the
     * whole cache entry rather than leave it pointing at a stale mixture. */
    if (bufs->rpl_cache != NULL) {
        pd->rpl_cache     = bufs->rpl_cache;
        pd->rpl_cache_cap = bufs->rpl_cache_cap;
        pd->last_reply_len = 0;
        pd->have_last      = false;
    }
    if (bufs->cmd_cache != NULL) {
        pd->cmd_cache     = bufs->cmd_cache;
        pd->cmd_cache_cap = bufs->cmd_cache_cap;
        pd->last_cmd_len  = 0;
        pd->have_last     = false;
    }

    return OSDP_OK;
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

size_t osdp_pd_max_reply_payload(const osdp_pd_t *pd)
{
    if (pd == NULL) {
        return 0;
    }

    /* Describe the reply this PD would send right now. Only the header
     * fields matter to the sizing helpers; the payload is what we're
     * solving for. A reply always mirrors the inbound integrity mode, and
     * CRC (2 bytes) is both the common case and the conservative one. */
    osdp_frame_t shape;
    (void)memset(&shape, 0, sizeof(shape));
    shape.address   = pd->address;
    shape.reply     = true;
    shape.integrity = OSDP_INTEGRITY_CRC;

    size_t        max = 0;
    osdp_status_t s;

    if (pd->sc.session.established) {
        shape.has_scb    = true;
        shape.scb_length = OSDP_SCB_MIN_LEN;
        shape.scb_type   = OSDP_SCS_18;   /* data-bearing PD→ACU */
        s = osdp_sc_max_payload(&shape, pd->tx_cap, &max);
    } else {
        s = osdp_frame_max_payload(&shape, pd->tx_cap, &max);
    }

    return (s == OSDP_OK) ? max : 0;
}

/* ---- Poll-response event queue -----------------------------------------
 *
 * Records are laid out back to back from offset 0:
 *
 *     [u16 payload_len LE][u8 reply_code][payload bytes]
 *
 * Deliberately NOT a wrapping ring. A wrap would split a payload across the
 * end of the buffer, and the dequeue hands the payload straight to the framer
 * as a contiguous slice. Compacting on dequeue costs a memmove of whatever is
 * still queued — bounded by the buffer, and queues here hold a handful of
 * events between polls ~50 ms apart — in exchange for every record staying in
 * one piece. */

#define EVENT_HEADER_BYTES 3U   /* u16 length + u8 reply code */

void osdp_pd_set_event_queue(osdp_pd_t *pd, uint8_t *buf, size_t cap)
{
    if (pd == NULL) {
        return;
    }
    pd->event_buf = buf;
    pd->event_cap = (buf != NULL) ? cap : 0;
    pd->event_len = 0;   /* rebinding discards whatever was queued */
}

void osdp_pd_clear_events(osdp_pd_t *pd)
{
    if (pd == NULL) {
        return;
    }
    pd->event_len = 0;
}

bool osdp_pd_event_pending(const osdp_pd_t *pd)
{
    return pd != NULL && pd->event_len > 0;
}

osdp_status_t osdp_pd_enqueue_event(osdp_pd_t *pd, uint8_t reply_code,
                                    const uint8_t *payload, size_t len)
{
    if (pd == NULL || pd->event_buf == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len > 0 && payload == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    /* The length is stored as a u16, so anything larger cannot be recorded
     * faithfully — reject rather than truncate. */
    if (len > 0xFFFFU) {
        return OSDP_ERR_INVALID_ARG;
    }

    const size_t need = EVENT_HEADER_BYTES + len;
    if (need > pd->event_cap - pd->event_len) {
        /* Full. The application decides whether this event mattered — only
         * it knows whether a dropped card read is recoverable. */
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t *at = &pd->event_buf[pd->event_len];
    at[0] = (uint8_t)(len & 0xFFU);
    at[1] = (uint8_t)((len >> 8) & 0xFFU);
    at[2] = reply_code;
    if (len > 0) {
        (void)memcpy(&at[EVENT_HEADER_BYTES], payload, len);
    }
    pd->event_len += need;
    return OSDP_OK;
}

bool osdp_pd_internal_dequeue_event(osdp_pd_t *pd, osdp_pd_reply_t *reply)
{
    if (pd == NULL || reply == NULL || pd->event_buf == NULL ||
        pd->event_len < EVENT_HEADER_BYTES) {
        return false;
    }

    const size_t len = (size_t)pd->event_buf[0] |
                       ((size_t)pd->event_buf[1] << 8);
    const uint8_t code   = pd->event_buf[2];
    const size_t  record = EVENT_HEADER_BYTES + len;
    if (record > pd->event_len) {
        /* Corrupt queue — impossible via the public API, but never read past
         * what we hold. Drop everything rather than emit garbage. */
        pd->event_len = 0;
        return false;
    }

    /* Copy the payload out before compacting: the memmove below is about to
     * overwrite the bytes it currently sits on. The scratch is also what
     * every other library-built reply points at, so its lifetime rule (valid
     * until the caller has framed the reply) already covers this. */
    if (len > OSDP_PD_REPLY_SCRATCH_LEN) {
        /* Enqueued larger than we can hand back. Drop this record and report
         * empty rather than truncate a card number. */
        (void)memmove(pd->event_buf, &pd->event_buf[record],
                      pd->event_len - record);
        pd->event_len -= record;
        return false;
    }
    if (len > 0) {
        (void)memcpy(pd->reply_scratch, &pd->event_buf[EVENT_HEADER_BYTES],
                     len);
    }

    (void)memmove(pd->event_buf, &pd->event_buf[record],
                  pd->event_len - record);
    pd->event_len -= record;

    reply->code        = code;
    reply->payload     = (len > 0) ? pd->reply_scratch : NULL;
    reply->payload_len = len;
    return true;
}

/* ---- Miscellaneous command hooks ---------------------------------------*/

void osdp_pd_set_status_provider(osdp_pd_t *pd,
                                 const osdp_pd_status_provider_t *p,
                                 void *user)
{
    if (pd == NULL) {
        return;
    }
    if (p != NULL) {
        pd->status = *p;
    } else {
        (void)memset(&pd->status, 0, sizeof(pd->status));
    }
    pd->status_user = user;
}

void osdp_pd_set_mfg_receiver(osdp_pd_t *pd, uint8_t *buf, size_t cap,
                              osdp_pd_mfg_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    osdp_mp_reasm_init(&pd->mfg_reasm, buf, cap);
    pd->mfg_cb   = cb;
    pd->mfg_user = user;
    (void)memset(pd->mfg_vendor, 0, sizeof(pd->mfg_vendor));
}

void osdp_pd_set_abort_handler(osdp_pd_t *pd, osdp_pd_abort_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->abort_cb   = cb;
    pd->abort_user = user;
}

void osdp_pd_set_acurxsize_handler(osdp_pd_t *pd, osdp_pd_acurxsize_cb cb,
                                   void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->acurxsize_cb   = cb;
    pd->acurxsize_user = user;
}

uint16_t osdp_pd_acu_rx_size(const osdp_pd_t *pd)
{
    return (pd != NULL) ? pd->acu_rx_size : 0;
}

void osdp_pd_set_keepactive_handler(osdp_pd_t *pd, osdp_pd_keepactive_cb cb,
                                    void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->keepactive_cb   = cb;
    pd->keepactive_user = user;
}

bool osdp_pd_is_online(const osdp_pd_t *pd)
{
    if (pd == NULL) {
        return false;
    }
    return pd->online;
}

/* ---- Reader LED bank -----------------------------------------------------*/

/* Monotonic clock helper. Falls back to time 0 when the transport doesn't
 * supply now_ms — in which case temporary-timer expiry and flashing simply
 * don't advance, but command-driven colour changes still resolve. */
static uint32_t pd_now_ms(const osdp_pd_t *pd)
{
    if (pd->transport.now_ms != NULL) {
        return pd->transport.now_ms(pd->transport.user);
    }
    return 0U;
}

/* Find the bank slot tracking (reader_no, led_no), claiming a free one on
 * first sighting. Returns NULL only when every slot is already in use by
 * other LEDs (oversized deployment — the extra LED is ACK'd but untracked). */
static osdp_pd_led_slot_t *pd_led_slot(osdp_pd_t *pd,
                                       uint8_t reader_no, uint8_t led_no)
{
    osdp_pd_led_slot_t *free_slot = NULL;
    for (size_t i = 0; i < OSDP_PD_MAX_LEDS; i++) {
        osdp_pd_led_slot_t *s = &pd->leds[i];
        if (s->used && s->reader_no == reader_no && s->led_no == led_no) {
            return s;
        }
        if (!s->used && free_slot == NULL) {
            free_slot = s;
        }
    }
    if (free_slot != NULL) {
        free_slot->used       = true;
        free_slot->reader_no  = reader_no;
        free_slot->led_no     = led_no;
        free_slot->last_color = OSDP_LED_BLACK;
        osdp_led_init(&free_slot->state);
    }
    return free_slot;
}

/* Recompute every tracked LED's displayed colour at `now` and fire the
 * change callback for any that flipped since the last report. Cheap and
 * idempotent; safe to call after every command and on every tick. */
static void pd_led_refresh(osdp_pd_t *pd, uint32_t now)
{
    if (pd->led_cb == NULL) {
        return;
    }
    for (size_t i = 0; i < OSDP_PD_MAX_LEDS; i++) {
        osdp_pd_led_slot_t *s = &pd->leds[i];
        if (!s->used) {
            continue;
        }
        const uint8_t color = osdp_led_color(&s->state, now);
        if (color != s->last_color) {
            s->last_color = color;
            pd->led_cb(pd->led_user, s->reader_no, s->led_no, color);
        }
    }
}

/* ---- Reader buzzer bank --------------------------------------------------*/

/* Find the buzzer slot for `reader_no`, claiming a free one on first
 * sighting. Returns NULL only when every slot is in use by other readers. */
static osdp_pd_buz_slot_t *pd_buz_slot(osdp_pd_t *pd, uint8_t reader_no)
{
    osdp_pd_buz_slot_t *free_slot = NULL;
    for (size_t i = 0; i < OSDP_PD_MAX_BUZZERS; i++) {
        osdp_pd_buz_slot_t *s = &pd->buzzers[i];
        if (s->used && s->reader_no == reader_no) {
            return s;
        }
        if (!s->used && free_slot == NULL) {
            free_slot = s;
        }
    }
    if (free_slot != NULL) {
        free_slot->used          = true;
        free_slot->reader_no     = reader_no;
        free_slot->last_sounding = false;
        osdp_buz_init(&free_slot->state);
    }
    return free_slot;
}

/* Recompute every tracked buzzer's sounding state at `now` and fire the
 * change callback for any that flipped since the last report — the beep /
 * silence edges of the pattern, including the final silence. */
static void pd_buz_refresh(osdp_pd_t *pd, uint32_t now)
{
    if (pd->buzzer_cb == NULL) {
        return;
    }
    for (size_t i = 0; i < OSDP_PD_MAX_BUZZERS; i++) {
        osdp_pd_buz_slot_t *s = &pd->buzzers[i];
        if (!s->used) {
            continue;
        }
        const bool sounding = osdp_buz_sounding(&s->state, now);
        if (sounding != s->last_sounding) {
            s->last_sounding = sounding;
            pd->buzzer_cb(pd->buzzer_user, s->reader_no, sounding,
                          s->state.tone);
        }
    }
}

/* Transparently fold an inbound command into the reader-LED / -buzzer banks.
 * A no-op for everything except osdp_LED and osdp_BUZ; for those it decodes
 * the command, applies it to the matching slot, then re-resolves state so
 * any change fires the callback. Declared in pd_internal.h so both the
 * plaintext (pd.c) and Secure Channel (pd_sc.c) dispatch paths can call it
 * with plaintext bytes. */
void osdp_pd_internal_observe_command(osdp_pd_t     *pd,
                                      uint8_t        cmd_code,
                                      const uint8_t *payload,
                                      size_t         payload_len)
{
    if (pd == NULL) {
        return;
    }

    if (cmd_code == OSDP_CMD_LED) {
        osdp_led_record_t recs[OSDP_PD_MAX_LEDS];
        size_t n = 0;
        if (osdp_led_decode(payload, payload_len, recs,
                            OSDP_PD_MAX_LEDS, &n) != OSDP_OK) {
            return;  /* malformed LED payload — leave the bank untouched */
        }
        const uint32_t now = pd_now_ms(pd);
        for (size_t i = 0; i < n; i++) {
            osdp_pd_led_slot_t *s =
                pd_led_slot(pd, recs[i].reader_no, recs[i].led_no);
            if (s != NULL) {
                osdp_led_apply(&s->state, &recs[i], now);
            }
        }
        pd_led_refresh(pd, now);
        return;
    }

    if (cmd_code == OSDP_CMD_BUZ) {
        osdp_buz_cmd_t buz;
        if (osdp_buz_decode(payload, payload_len, &buz) != OSDP_OK) {
            return;  /* malformed BUZ payload — ignore */
        }
        const uint32_t now = pd_now_ms(pd);
        osdp_pd_buz_slot_t *s = pd_buz_slot(pd, buz.reader_no);
        if (s != NULL) {
            osdp_buz_apply(&s->state, &buz, now);
        }
        pd_buz_refresh(pd, now);
        return;
    }
}

void osdp_pd_set_led_handler(osdp_pd_t *pd, osdp_pd_led_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->led_cb   = cb;
    pd->led_user = user;
}

void osdp_pd_set_buzzer_handler(osdp_pd_t *pd, osdp_pd_buzzer_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->buzzer_cb   = cb;
    pd->buzzer_user = user;
}

void osdp_pd_set_comset_handler(osdp_pd_t                *pd,
                                osdp_pd_comset_cb         decide,
                                osdp_pd_comset_applied_cb applied,
                                void                     *user)
{
    if (pd == NULL) {
        return;
    }
    pd->comset_cb         = decide;
    pd->comset_applied_cb = applied;
    pd->comset_user       = user;
}

void osdp_pd_set_file_receiver(osdp_pd_t *pd, uint8_t *buf, size_t cap,
                               osdp_pd_file_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->file_buf  = buf;
    pd->file_cap  = cap;
    pd->file_cb   = cb;
    pd->file_user = user;
    /* Rebinding a receiver discards any transfer that was mid-flight. */
    pd->ft_active   = false;
    pd->ft_received = 0;
}

void osdp_pd_set_file_stream(osdp_pd_t *pd, osdp_pd_file_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    /* Streaming mode: no reassembly buffer. file_buf == NULL is the mode
     * flag that osdp_pd_internal_filetransfer keys off. */
    pd->file_buf  = NULL;
    pd->file_cap  = 0;
    pd->file_cb   = cb;
    pd->file_user = user;
    pd->ft_active   = false;
    pd->ft_received = 0;
}

bool osdp_pd_buzzer_sounding(const osdp_pd_t *pd, uint8_t reader_no)
{
    if (pd == NULL) {
        return false;
    }
    const uint32_t now = pd_now_ms(pd);
    for (size_t i = 0; i < OSDP_PD_MAX_BUZZERS; i++) {
        const osdp_pd_buz_slot_t *s = &pd->buzzers[i];
        if (s->used && s->reader_no == reader_no) {
            return osdp_buz_sounding(&s->state, now);
        }
    }
    return false;
}

uint8_t osdp_pd_led_color(const osdp_pd_t *pd,
                          uint8_t reader_no, uint8_t led_no)
{
    if (pd == NULL) {
        return OSDP_LED_BLACK;
    }
    const uint32_t now = pd_now_ms(pd);
    for (size_t i = 0; i < OSDP_PD_MAX_LEDS; i++) {
        const osdp_pd_led_slot_t *s = &pd->leds[i];
        if (s->used && s->reader_no == reader_no && s->led_no == led_no) {
            return osdp_led_color(&s->state, now);
        }
    }
    return OSDP_LED_BLACK;
}

/* ---- Secure Channel configuration ---------------------------------------*/

void osdp_pd_set_sc_crypto(osdp_pd_t              *pd,
                           const osdp_sc_crypto_t *crypto)
{
    if (pd == NULL || crypto == NULL) {
        return;
    }
    pd->sc.crypto     = *crypto;
    pd->sc.crypto_set = true;
    osdp_sc_session_init(&pd->sc.session);
    pd->sc.got_chlng  = false;
}

void osdp_pd_set_sc_scbk(osdp_pd_t       *pd,
                         const uint8_t    scbk[OSDP_SC_KEY_LEN])
{
    if (pd == NULL || scbk == NULL) {
        return;
    }
    (void)memcpy(pd->sc.scbk, scbk, OSDP_SC_KEY_LEN);
    pd->sc.scbk_set = true;
}

void osdp_pd_set_sc_scbk_d(osdp_pd_t     *pd,
                           const uint8_t  scbk_d[OSDP_SC_KEY_LEN])
{
    if (pd == NULL || scbk_d == NULL) {
        return;
    }
    (void)memcpy(pd->sc.scbk_d, scbk_d, OSDP_SC_KEY_LEN);
    pd->sc.scbk_d_set = true;
}

void osdp_pd_set_sc_cuid(osdp_pd_t     *pd,
                         const uint8_t  cuid[OSDP_SC_CUID_LEN])
{
    if (pd == NULL || cuid == NULL) {
        return;
    }
    (void)memcpy(pd->sc.cuid, cuid, OSDP_SC_CUID_LEN);
    pd->sc.cuid_set = true;
}

bool osdp_pd_sc_established(const osdp_pd_t *pd)
{
    if (pd == NULL) {
        return false;
    }
    return pd->sc.session.established;
}

void osdp_pd_tick(osdp_pd_t *pd)
{
    if (pd == NULL || pd->transport.read == NULL) {
        return;
    }

    /* Check the offline timeout BEFORE consuming new bytes — keeps
     * is_online() honest even when the caller is ticking only to
     * check timing without expecting incoming traffic. */
    check_offline_timeout(pd);

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
            /* A frame that failed its integrity check but is addressed to
             * this PD gets an explicit osdp_NAK 0x01 (spec Table 47 / §5)
             * so the ACU retransmits with the same SQN instead of waiting
             * out the reply timeout. It goes out PLAINTEXT even during an
             * established Secure Channel: NAK 0x01 (and osdp_BUSY) are the
             * only replies the spec permits outside the SCS packet format
             * (§ "Interleaving USC packets"). Only integrity failures earn
             * a reply — the frame's structure and address bytes are sound,
             * just its check characters aren't. Other decode errors (bad
             * SOM/length/ctrl, truncation, line noise) can't be trusted to
             * be addressed to us, so they stay silent. Broadcast/config
             * traffic is likewise left alone: a corrupt frame is too weak a
             * basis to answer on an address shared with other PDs. */
            if ((r == OSDP_ERR_BAD_CRC || r == OSDP_ERR_BAD_CHECKSUM) &&
                !cmd.reply && cmd.address == pd->address) {
                size_t nak_len = 0;
                if (osdp_pd_internal_build_nak(pd, &cmd, OSDP_NAK_BAD_CHECK,
                                               &nak_len) == OSDP_OK &&
                    nak_len > 0) {
                    send_bytes(pd, pd->tx, nak_len);
                }
            }
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

    /* Re-resolve the LED and buzzer banks so time-driven changes (LED
     * timer expiry / flash edges, buzzer beep/silence edges and end-of-
     * pattern) reach the change callbacks even on ticks that processed no
     * command. No-op without a now_ms clock. */
    const uint32_t now = pd_now_ms(pd);
    pd_led_refresh(pd, now);
    pd_buz_refresh(pd, now);
}
