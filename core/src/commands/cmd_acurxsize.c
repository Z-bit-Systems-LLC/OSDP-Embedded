// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

#include "shared/pack.h"

/* osdp_ACURXSIZE (0x7B) — spec 6.21, Table 28.
 *
 * The ACU tells the PD how large a reply it is able to receive. Payload is a
 * single little-endian uint16 (ACURX_BUFSIZE_LSB then _MSB), so it is the
 * mirror image of the PD advertising PDCAP function code 10.
 *
 * Note the direction: this bounds what the PD may SEND, not what it may
 * receive. A PD that honours it caps its outbound messages at the smaller of
 * this value and its own transmit capacity. */

osdp_status_t osdp_acurxsize_decode(const uint8_t *payload, size_t len,
                                    osdp_acurxsize_cmd_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len != OSDP_ACURXSIZE_PAYLOAD_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->max_size = osdp_pack_read_u16le(payload);
    return OSDP_OK;
}

osdp_status_t osdp_acurxsize_build(const osdp_acurxsize_cmd_t *in,
                                   uint8_t *buf, size_t buf_cap,
                                   size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (buf_cap < OSDP_ACURXSIZE_PAYLOAD_BYTES) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    osdp_pack_write_u16le(buf, in->max_size);
    *written = OSDP_ACURXSIZE_PAYLOAD_BYTES;
    return OSDP_OK;
}
