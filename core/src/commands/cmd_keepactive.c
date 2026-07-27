// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

#include "shared/pack.h"

/* osdp_KEEPACTIVE (0xA7) — spec 6.21, Table 29.
 *
 * Instructs the PD to keep reader operations alive for the given number of
 * milliseconds, so communication with a credential still in the field is not
 * dropped. Payload is a single little-endian uint16.
 *
 * A time of 0 is a meaningful value, not an omission: it cancels a
 * previously-granted extension and lets the reader return to normal
 * operation, so the codec accepts it. */

osdp_status_t osdp_keepactive_decode(const uint8_t *payload, size_t len,
                                     osdp_keepactive_cmd_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len != OSDP_KEEPACTIVE_PAYLOAD_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->time_ms = osdp_pack_read_u16le(payload);
    return OSDP_OK;
}

osdp_status_t osdp_keepactive_build(const osdp_keepactive_cmd_t *in,
                                    uint8_t *buf, size_t buf_cap,
                                    size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (buf_cap < OSDP_KEEPACTIVE_PAYLOAD_BYTES) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    osdp_pack_write_u16le(buf, in->time_ms);
    *written = OSDP_KEEPACTIVE_PAYLOAD_BYTES;
    return OSDP_OK;
}
