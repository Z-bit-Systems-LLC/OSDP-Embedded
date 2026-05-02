// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

#include <string.h>

osdp_status_t osdp_nak_decode(const uint8_t *payload, size_t len,
                              osdp_nak_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len < 1 || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->error_code  = payload[0];
    out->details_len = len - 1u;
    out->details     = (out->details_len > 0) ? &payload[1] : NULL;
    return OSDP_OK;
}

osdp_status_t osdp_nak_build(const osdp_nak_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (in->details_len > 0 && in->details == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = 1u + in->details_len;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->error_code;
    if (in->details_len > 0) {
        (void)memcpy(&buf[1], in->details, in->details_len);
    }
    *written = total;
    return OSDP_OK;
}
