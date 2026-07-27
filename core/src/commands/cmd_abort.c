// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

/* osdp_ABORT (0xA2) — spec 6.22, Table 30.
 *
 * Instructs the PD to terminate any multi-part message or file transfer in
 * progress. DATA is omitted.
 *
 * The reply carries the outcome: osdp_ACK when the operation was cancelled,
 * osdp_NAK when the PD cannot abort — the spec's example being a
 * firmware-update osdp_FILETRANSFER that has passed the point of no return. */

osdp_status_t osdp_abort_decode(const uint8_t *payload, size_t len)
{
    (void)payload;
    if (len != 0) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return OSDP_OK;
}

osdp_status_t osdp_abort_build(uint8_t *buf, size_t buf_cap, size_t *written)
{
    (void)buf;
    (void)buf_cap;
    if (written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    return OSDP_OK;
}
