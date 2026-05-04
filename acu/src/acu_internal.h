// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_ACU_INTERNAL_H
#define OSDP_ACU_INTERNAL_H

/* Cross-file declarations private to the osdp::acu library. Not part
 * of the public API. */

#include "osdp/osdp_acu.h"
#include "osdp/osdp_frame.h"

#include <stdbool.h>

/* Whether `slot` has the configuration needed to start an SC
 * handshake using the requested key mode. */
bool osdp_acu_internal_sc_configured(const osdp_acu_t          *acu,
                                     const osdp_acu_pd_slot_t  *slot,
                                     bool                       use_default_key);

/* Build CHLNG into acu->tx_buf and write it to the transport. On
 * success, populates slot->sc_phase = AWAITING_CCRYPT, slot->sc_rnd_a,
 * slot->sc_key_selector, slot->next_seq, slot->waiting, etc. The
 * caller is osdp_acu_start_sc_handshake. */
osdp_status_t osdp_acu_internal_send_chlng(osdp_acu_t          *acu,
                                           osdp_acu_pd_slot_t  *slot,
                                           bool                 use_default_key);

/* Consume an inbound CCRYPT (SCS_12) reply for the given PD slot,
 * validate the Client Cryptogram, and (on success) build + send
 * SCRYPT advancing the slot to AWAITING_RMAC_I. On any cryptographic
 * failure fires the application's sc_event_cb with HANDSHAKE_FAILED
 * and resets the slot to IDLE. */
void osdp_acu_internal_handle_ccrypt(osdp_acu_t          *acu,
                                     osdp_acu_pd_slot_t  *slot,
                                     const osdp_frame_t  *frame);

/* Consume an inbound RMAC_I (SCS_14) reply, validate the Initial
 * R-MAC, and on success transition the slot to ESTABLISHED with the
 * session keys + rolling MAC chain seeded. Fires sc_event_cb with
 * either ESTABLISHED or HANDSHAKE_FAILED. */
void osdp_acu_internal_handle_rmac_i(osdp_acu_t          *acu,
                                     osdp_acu_pd_slot_t  *slot,
                                     const osdp_frame_t  *frame);

#endif /* OSDP_ACU_INTERNAL_H */
