// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PD_INTERNAL_H
#define OSDP_PD_INTERNAL_H

/* Cross-file declarations private to the osdp::pd library. Not part
 * of the public API. */

#include "osdp/osdp_frame.h"
#include "osdp/osdp_pd.h"

/* Whether the PD has enough Secure Channel configuration to even
 * attempt the handshake. */
bool osdp_pd_internal_sc_configured(const osdp_pd_t *pd);

/* Whether the PD has enough Secure Channel 2 configuration (crypto
 * vtable + 32-byte SCBK + cUID) to attempt the SC2 handshake. */
bool osdp_pd_internal_sc2_configured(const osdp_pd_t *pd);

/* Process an SC2 SCB-bearing inbound frame (SCS_21..28): handshake
 * messages produce inline replies into pd->tx_buf; operational
 * SCS_25/27 traffic unwraps, dispatches to the application handler
 * with plaintext, and wraps the reply as SCS_28. Returns the byte
 * count written into pd->tx_buf, or 0 if no reply should be sent. */
size_t osdp_pd_internal_handle_sc2_into_tx(osdp_pd_t          *pd,
                                           const osdp_frame_t *cmd);

/* Build a NAK reply into pd->tx_buf for `cmd` carrying `error_code`,
 * writing the frame length to *out_len. Defined in pd.c (wrapping the
 * static build_nak helper) and shared with the SC handlers in pd_sc.c. */
osdp_status_t osdp_pd_internal_build_nak(osdp_pd_t          *pd,
                                         const osdp_frame_t *cmd,
                                         uint8_t             error_code,
                                         size_t             *out_len);

/* Build an arbitrary reply (code + payload) into pd->tx_buf, mirroring the
 * inbound frame's address/sequence/integrity. Shared with the pairing driver
 * in pd_pair.c (osdp::pd_pair) so it can emit ACK / osdp_PAIRR frames. */
osdp_status_t osdp_pd_internal_build_reply(osdp_pd_t             *pd,
                                           const osdp_frame_t    *cmd,
                                           const osdp_pd_reply_t *reply,
                                           size_t                *out_len);

/* Process a SCB-bearing inbound frame: handshake messages produce
 * inline replies (built into pd->tx_buf), operational SCS_15..18
 * traffic dispatches into the existing application handler with
 * plaintext (in subsequent commits). Returns the byte count written
 * into pd->tx_buf, or 0 if no reply should be transmitted. */
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
