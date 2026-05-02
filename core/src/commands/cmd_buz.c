// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

osdp_status_t osdp_buz_decode(const uint8_t *payload, size_t len,
                              osdp_buz_cmd_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len != OSDP_BUZ_PAYLOAD_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->reader_no       = payload[0];
    out->tone_code       = payload[1];
    out->on_time_100ms   = payload[2];
    out->off_time_100ms  = payload[3];
    out->count           = payload[4];
    return OSDP_OK;
}

osdp_status_t osdp_buz_build(const osdp_buz_cmd_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (buf_cap < OSDP_BUZ_PAYLOAD_BYTES) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->reader_no;
    buf[1] = in->tone_code;
    buf[2] = in->on_time_100ms;
    buf[3] = in->off_time_100ms;
    buf[4] = in->count;
    *written = OSDP_BUZ_PAYLOAD_BYTES;
    return OSDP_OK;
}
