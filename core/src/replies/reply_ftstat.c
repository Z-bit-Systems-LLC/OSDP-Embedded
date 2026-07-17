// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

#include "shared/pack.h"

/* osdp_FTSTAT byte layout (spec 7.25, Table 68):
 *   0        FtAction         control flags
 *   1..2     FtDelay          (uint16 LE)
 *   3..4     FtStatusDetail   (int16  LE, signed)
 *   5..6     FtUpdateMsgMax   (uint16 LE)
 *
 * FtStatusDetail is a signed little-endian value; it round-trips through
 * the unsigned u16 pack helpers by a two's-complement reinterpret cast. */

osdp_status_t osdp_ftstat_decode(const uint8_t *payload, size_t len,
                                 osdp_ftstat_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len != OSDP_FTSTAT_PAYLOAD_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->action         = payload[0];
    out->delay_ms       = osdp_pack_read_u16le(&payload[1]);
    out->status_detail  = (int16_t)osdp_pack_read_u16le(&payload[3]);
    out->update_msg_max = osdp_pack_read_u16le(&payload[5]);
    return OSDP_OK;
}

osdp_status_t osdp_ftstat_build(const osdp_ftstat_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (buf_cap < OSDP_FTSTAT_PAYLOAD_BYTES) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->action;
    osdp_pack_write_u16le(&buf[1], in->delay_ms);
    osdp_pack_write_u16le(&buf[3], (uint16_t)in->status_detail);
    osdp_pack_write_u16le(&buf[5], in->update_msg_max);
    *written = OSDP_FTSTAT_PAYLOAD_BYTES;
    return OSDP_OK;
}
