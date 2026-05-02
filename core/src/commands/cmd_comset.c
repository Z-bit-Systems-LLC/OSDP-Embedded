// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

#include "shared/pack.h"

#define OSDP_COMSET_MAX_ADDR 0x7EU

osdp_status_t osdp_comset_decode(const uint8_t *payload, size_t len,
                                 osdp_comset_cmd_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len != OSDP_COMSET_PAYLOAD_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->address   = payload[0];
    out->baud_rate = osdp_pack_read_u32le(&payload[1]);
    return OSDP_OK;
}

osdp_status_t osdp_comset_build(const osdp_comset_cmd_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (in->address > OSDP_COMSET_MAX_ADDR) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (buf_cap < OSDP_COMSET_PAYLOAD_BYTES) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->address;
    osdp_pack_write_u32le(&buf[1], in->baud_rate);
    *written = OSDP_COMSET_PAYLOAD_BYTES;
    return OSDP_OK;
}
