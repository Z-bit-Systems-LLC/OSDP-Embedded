// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

/* osdp_BUSY (0x79) — spec 7.19, Table 62. DATA omitted.
 *
 * "The PD is still working on the previous command; ask again." Two framing
 * rules attach to it that this codec cannot express, because they belong to
 * the layer that builds the frame rather than the payload — see the PD state
 * machine:
 *
 *   - its sequence number is always 0, not the inbound SQN;
 *   - it is sent in the clear even during an established Secure Channel, and
 *     must not disturb the MAC chain — one of only three replies (with
 *     osdp_NAK 0x01 and 0x06) the spec permits outside the SCS format.
 *
 * The ACU repeats the command in its original form until it gets something
 * other than osdp_BUSY, so the PD must also not cache it as the retransmit
 * reply. */

osdp_status_t osdp_busy_decode(const uint8_t *payload, size_t len)
{
    (void)payload;
    if (len != 0) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return OSDP_OK;
}

osdp_status_t osdp_busy_build(uint8_t *buf, size_t buf_cap, size_t *written)
{
    (void)buf;
    (void)buf_cap;
    if (written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    return OSDP_OK;
}
