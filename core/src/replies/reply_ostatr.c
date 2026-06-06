// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

#include <string.h>

osdp_status_t osdp_ostatr_decode(const uint8_t *payload, size_t len,
                                 uint8_t *statuses, size_t statuses_cap,
                                 size_t *statuses_written)
{
    if (statuses_written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *statuses_written = 0;

    /* Spec 7.8: one status byte per output; the array length is the whole
     * message length. An empty list is a valid (if unusual) encoding. */
    if (len > 0 && payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (len > 0 && (statuses == NULL || statuses_cap < len)) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    if (len > 0) {
        (void)memcpy(statuses, payload, len);
    }
    *statuses_written = len;
    return OSDP_OK;
}

osdp_status_t osdp_ostatr_build(const uint8_t *statuses, size_t count,
                                uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (count > 0 && (statuses == NULL || buf == NULL)) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (count > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    if (count > 0) {
        (void)memcpy(buf, statuses, count);
    }
    *written = count;
    return OSDP_OK;
}
