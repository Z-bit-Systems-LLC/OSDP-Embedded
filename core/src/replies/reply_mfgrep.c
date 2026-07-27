// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

#include <string.h>

/* osdp_MFGREP (0x90) — spec 7.18, Table 61.
 *
 * The reply counterpart of osdp_MFG, and byte-identical in shape:
 *   0..2   Vendor Code (IEEE MA-L, 24 bits)
 *   3..n   vendor-defined data
 *
 * (Table 61 describes the data column as "Keypad data represented as ASCII
 * characters" — a copy-paste artefact from Table 57; the surrounding text is
 * explicit that the content is not defined by the spec.)
 *
 * Sent either in response to an osdp_MFG or unprompted as a poll response,
 * which is why the PD's event queue needs to be able to carry it. */

osdp_status_t osdp_mfgrep_decode(const uint8_t *payload, size_t len,
                                 osdp_mfgrep_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len < OSDP_MFGREP_HEADER_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    (void)memcpy(out->vendor_code, payload, OSDP_MFGREP_VENDOR_CODE_BYTES);
    out->data_len = len - OSDP_MFGREP_HEADER_BYTES;
    out->data     = (out->data_len > 0) ? &payload[OSDP_MFGREP_HEADER_BYTES]
                                        : NULL;
    return OSDP_OK;
}

osdp_status_t osdp_mfgrep_build(const osdp_mfgrep_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (in->data_len > 0 && in->data == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = (size_t)OSDP_MFGREP_HEADER_BYTES + in->data_len;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    (void)memcpy(buf, in->vendor_code, OSDP_MFGREP_VENDOR_CODE_BYTES);
    if (in->data_len > 0) {
        (void)memcpy(&buf[OSDP_MFGREP_HEADER_BYTES], in->data, in->data_len);
    }
    *written = total;
    return OSDP_OK;
}
