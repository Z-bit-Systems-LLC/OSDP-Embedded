// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PD_INTERNAL_H
#define OSDP_PD_INTERNAL_H

/* Cross-file declarations private to the osdp::pd library. Not part
 * of the public API. */

#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"

/* Which channel an accepted command arrived on. The unified dispatch is
 * otherwise channel-agnostic; this only selects the KEYSET variant, because
 * a future Secure Channel version rotating a different key size needs to be
 * told apart from SC1's 16-byte AES-128 SCBK (key_type 0x01). A plaintext
 * KEYSET rotates the SC1 key, which is what the pre-refactor code did. */
typedef enum osdp_pd_channel {
    OSDP_PD_CH_PLAIN = 0,
    OSDP_PD_CH_SC1
} osdp_pd_channel_t;

/* What the caller should do with the result of a dispatch.
 *
 * Most commands produce a reply to frame on the channel that carried them,
 * which is OSDP_PD_DISPATCH_SEND. The other two exist because a couple of
 * outcomes cannot be expressed as "a reply on this channel":
 *
 *   DROP  the command produces no reply at all, and the ACU waits out its
 *         timeout. Reserved for an unrecognised application error.
 *   BUSY  osdp_BUSY, which the spec (7.19) requires to go out at sequence 0
 *         and OUTSIDE the Secure Channel even during an established session.
 *         The dispatch cannot frame that itself — it does not own framing —
 *         so it says "BUSY" and each caller routes to the plaintext builder
 *         instead of its own wrap. */
typedef enum osdp_pd_dispatch_outcome {
    OSDP_PD_DISPATCH_SEND = 0,
    OSDP_PD_DISPATCH_DROP,
    OSDP_PD_DISPATCH_BUSY
} osdp_pd_dispatch_outcome_t;

/* Build osdp_BUSY into the bound TX buffer for `cmd`: plaintext framing with
 * sequence number 0, whatever channel the command arrived on. Centralises the
 * three spec-7.19 rules so no caller has to remember them; the "do not cache"
 * half is handled by pd->reply_cacheable, which this clears. Defined in pd.c. */
osdp_status_t osdp_pd_internal_build_busy(osdp_pd_t          *pd,
                                          const osdp_frame_t *cmd,
                                          size_t             *out_len);

/* Decide the reply for ONE accepted command, whatever channel carried it.
 *
 * This is the single place that knows what a command *means*: which commands
 * the library handles itself (osdp_COMSET, osdp_FILETRANSFER), when to call
 * the application handler, the KEYSET hook, and the reader-state observation.
 * It knows nothing about framing, Secure Channel wrapping, or the SQN cache —
 * each caller frames the result its own way (plaintext build_reply, Secure
 * Channel osdp_sc_wrap_frame), which is the ONLY thing that legitimately
 * differs between the paths.
 *
 * `payload` is always plaintext: the SC callers unwrap before calling.
 *
 * On OSDP_OK, *reply holds the code and payload to send. A library-built
 * payload points into pd->reply_scratch, so it stays valid until the caller
 * has framed it (and until the next dispatch call). An application-supplied
 * payload points into whatever buffer cmd_cb handed back, whose lifetime the
 * existing osdp_pd_command_cb contract already guarantees for that window.
 *
 * Refusals are ordinary results: they come back as _SEND with *reply set to
 * the appropriate osdp_NAK. Only the two cases that cannot be framed as a
 * reply on this channel get their own outcome — see
 * osdp_pd_dispatch_outcome_t. */
osdp_pd_dispatch_outcome_t osdp_pd_internal_dispatch(
    osdp_pd_t        *pd,
    osdp_pd_channel_t channel,
    uint8_t           cmd_code,
    const uint8_t    *payload,
    size_t            payload_len,
    osdp_pd_reply_t  *reply);

/* Pop the head of the poll-response event queue into *reply, with the payload
 * copied into pd->reply_scratch so it survives the dequeue. Returns false
 * when the queue is empty or unbound, in which case *reply is untouched and
 * the caller falls through to the application handler. Defined in pd.c. */
bool osdp_pd_internal_dequeue_event(osdp_pd_t *pd, osdp_pd_reply_t *reply);

/* Whether the PD has enough Secure Channel configuration to even
 * attempt the handshake. */
bool osdp_pd_internal_sc_configured(const osdp_pd_t *pd);

/* Build a NAK reply into the bound TX buffer for `cmd` carrying `error_code`,
 * writing the frame length to *out_len. Defined in pd.c (wrapping the
 * static build_nak helper) and shared with the SC handlers in pd_sc.c. */
osdp_status_t osdp_pd_internal_build_nak(osdp_pd_t          *pd,
                                         const osdp_frame_t *cmd,
                                         uint8_t             error_code,
                                         size_t             *out_len);

/* Build an arbitrary reply (code + payload) into the bound TX buffer,
 * mirroring inbound frame's address/sequence/integrity. Shared with the
 * Secure Channel handler in pd_sc.c so both paths frame replies
 * identically. */
osdp_status_t osdp_pd_internal_build_reply(osdp_pd_t             *pd,
                                           const osdp_frame_t    *cmd,
                                           const osdp_pd_reply_t *reply,
                                           size_t                *out_len);

/* Process a SCB-bearing inbound frame: handshake messages produce
 * inline replies (built into the bound TX buffer), operational SCS_15..18
 * traffic dispatches into the existing application handler with
 * plaintext (in subsequent commits). Returns the byte count written
 * into the bound TX buffer, or 0 if no reply should be transmitted. */
size_t osdp_pd_internal_handle_sc_into_tx(osdp_pd_t          *pd,
                                          const osdp_frame_t *cmd);

/* Fold a (plaintext) inbound command into the reader-LED bank. A no-op
 * for everything except osdp_LED; for that it decodes the records, applies
 * each to its (reader_no, led_no) slot, and re-resolves displayed colours
 * so any change fires the registered LED callback. Shared by the plaintext
 * dispatch (pd.c) and the Secure Channel operational dispatch (pd_sc.c) so
 * LED state tracks identically on either path. Defined in pd.c. */
void osdp_pd_internal_observe_command(osdp_pd_t     *pd,
                                      uint8_t        cmd_code,
                                      const uint8_t *payload,
                                      size_t         payload_len);

/* Decode a KEYSET payload and, if it carries a valid 16-byte SCBK,
 * copy the new key into pd->sc.scbk (and set the `scbk_set` flag).
 * Called by both the plaintext and SC dispatch paths after the
 * application handler has indicated it would ACK — so the agreed-
 * upon semantic is "the PD ACKs the KEYSET, then the next handshake
 * uses the rotated key".
 *
 * Crucially, the existing SC session (s_enc / s_mac1 / s_mac2,
 * SQN counters, etc.) is left intact. The ACU is responsible for
 * initiating a fresh handshake when it wants the new key to take
 * effect on the wire.
 *
 * Returns:
 *   OSDP_OK                    — key applied successfully.
 *   OSDP_ERR_BAD_PAYLOAD       — wire layout malformed (caller
 *                                should override the ACK with NAK
 *                                0x09 so the ACU sees the failure).
 *   OSDP_ERR_NOT_SUPPORTED     — key_type other than SCBK (0x01)
 *                                or key_length other than 16
 *                                (caller should override with NAK
 *                                0x03).
 */
osdp_status_t osdp_pd_internal_apply_keyset(osdp_pd_t      *pd,
                                            const uint8_t  *payload,
                                            size_t          payload_len);

/* Decode an inbound osdp_COMSET payload, run it through the application's
 * `decide` hook (if any), clamp an out-of-range address to the current one,
 * and emit the 5-byte osdp_COM report body. On success writes the effective
 * address/baud to *eff_addr / *eff_baud and OSDP_COM_PAYLOAD_BYTES into
 * com_payload. Returns OSDP_ERR_BAD_PAYLOAD if the COMSET is malformed (the
 * caller then NAKs). Shared by the plaintext (pd.c) and Secure Channel
 * (pd_sc.c) dispatch paths; defined in pd.c. */
osdp_status_t osdp_pd_internal_comset_effective(osdp_pd_t     *pd,
                                                const uint8_t *payload,
                                                size_t         payload_len,
                                                uint8_t       *eff_addr,
                                                uint32_t      *eff_baud,
                                                uint8_t       *com_payload);

/* Apply the COMSET change staged in pd->comset_{new_address,new_baud}:
 * adopt the new address, drop the SQN/retransmit cache, clear the pending
 * flag, and fire the application's `applied` hook. Called by process_frame
 * AFTER the osdp_COM reply has been transmitted. Defined in pd.c. */
void osdp_pd_internal_apply_comset(osdp_pd_t *pd);

/* Process an inbound (plaintext) osdp_FILETRANSFER payload: reassemble the
 * fragment into the registered receiver buffer, run the evaluation callback,
 * update the running transfer state, and emit the 7-byte osdp_FTSTAT reply
 * body into `ftstat_payload` (must hold OSDP_FTSTAT_PAYLOAD_BYTES).
 *
 * Returns:
 *   OSDP_OK                — ftstat_payload holds the FTSTAT body to send
 *                            (including abort / malformed / unrecognized
 *                            statuses — those are still FTSTAT replies).
 *   OSDP_ERR_NOT_SUPPORTED — no receiver registered (caller NAKs 0x03).
 *   OSDP_ERR_BAD_PAYLOAD   — the frame will not decode (caller NAKs 0x02).
 *
 * Shared by the plaintext (pd.c) and Secure Channel (pd_sc.c) dispatch
 * paths; defined in pd.c. */
osdp_status_t osdp_pd_internal_filetransfer(osdp_pd_t     *pd,
                                            const uint8_t *payload,
                                            size_t         payload_len,
                                            uint8_t       *ftstat_payload);

#endif /* OSDP_PD_INTERNAL_H */
