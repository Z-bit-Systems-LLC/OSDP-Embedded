// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

osdp_status_t osdp_lstatr_decode(const uint8_t *payload, size_t len,
                                 osdp_lstatr_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len != OSDP_LSTATR_PAYLOAD_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->tamper = payload[0];
    out->power  = payload[1];
    return OSDP_OK;
}

osdp_status_t osdp_lstatr_build(const osdp_lstatr_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (buf_cap < OSDP_LSTATR_PAYLOAD_BYTES) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->tamper;
    buf[1] = in->power;
    *written = OSDP_LSTATR_PAYLOAD_BYTES;
    return OSDP_OK;
}
