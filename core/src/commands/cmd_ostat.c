// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

/* osdp_OSTAT (0x66) — spec 6.7, Table 11.
 *
 * Request for a output status report. DATA is omitted, so the codec is purely a
 * length assertion on decode and a no-op on build; the interesting half of
 * this exchange is the reply, osdp_OSTATR (7.8). */

osdp_status_t osdp_ostat_decode(const uint8_t *payload, size_t len)
{
    (void)payload;
    if (len != 0) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return OSDP_OK;
}

osdp_status_t osdp_ostat_build(uint8_t *buf, size_t buf_cap, size_t *written)
{
    (void)buf;
    (void)buf_cap;
    if (written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    return OSDP_OK;
}
