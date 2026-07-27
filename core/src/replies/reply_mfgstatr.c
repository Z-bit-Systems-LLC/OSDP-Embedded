// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

/* osdp_MFGSTATR (0x83) — spec 7.23, Table 66. One vendor-defined byte.
 *
 * **Deprecated.** The spec states outright that this reply "has been found to
 * be incomplete or incorrect" and that command 0x83 will be redefined in
 * OSDP v2.3.0. It is implemented so a Monitor can decode existing traffic and
 * so the reply code is not a silent hole; new PD code should not emit it.
 *
 * Sent when there is a status condition requiring a manufacturer-specific response.
 * The single byte carries no spec-defined meaning — it is whatever the vendor
 * assigns, which is precisely why the definition is considered incomplete. */

osdp_status_t osdp_mfgstatr_decode(const uint8_t *payload, size_t len,
                              osdp_mfgstatr_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len != OSDP_MFGSTATR_PAYLOAD_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->data = payload[0];
    return OSDP_OK;
}

osdp_status_t osdp_mfgstatr_build(const osdp_mfgstatr_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (buf_cap < OSDP_MFGSTATR_PAYLOAD_BYTES) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->data;
    *written = OSDP_MFGSTATR_PAYLOAD_BYTES;
    return OSDP_OK;
}
