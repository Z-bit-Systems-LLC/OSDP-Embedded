// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

osdp_status_t osdp_cap_decode(const uint8_t *payload, size_t len,
                              osdp_cap_cmd_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len != 1 || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->reply_type = payload[0];
    return OSDP_OK;
}

osdp_status_t osdp_cap_build(const osdp_cap_cmd_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (buf_cap < 1) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->reply_type;
    *written = 1;
    return OSDP_OK;
}
