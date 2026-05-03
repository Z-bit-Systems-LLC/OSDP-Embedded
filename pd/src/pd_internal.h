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

/* Process a SCB-bearing inbound frame: handshake messages produce
 * inline replies (built into pd->tx_buf), operational SCS_15..18
 * traffic dispatches into the existing application handler with
 * plaintext (in subsequent commits). Returns the byte count written
 * into pd->tx_buf, or 0 if no reply should be transmitted. */
size_t osdp_pd_internal_handle_sc_into_tx(osdp_pd_t          *pd,
                                          const osdp_frame_t *cmd);

#endif /* OSDP_PD_INTERNAL_H */
