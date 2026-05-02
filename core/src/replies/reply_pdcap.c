// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

osdp_status_t osdp_pdcap_decode(const uint8_t *payload, size_t len,
                                osdp_pdcap_record_t *records,
                                size_t records_cap,
                                size_t *records_written)
{
    if (records_written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *records_written = 0;

    /* Spec 7.5: variable number of 3-byte capability records.
     * The list may be empty in principle (no caps reported) — that's
     * a valid encoding even if unusual on the wire. */
    if ((len % OSDP_PDCAP_RECORD_BYTES) != 0) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (len > 0 && payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    const size_t count = len / OSDP_PDCAP_RECORD_BYTES;
    if (count > 0 && (records == NULL || records_cap < count)) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < count; i++) {
        const uint8_t *r = &payload[i * OSDP_PDCAP_RECORD_BYTES];
        records[i].function_code    = r[0];
        records[i].compliance_level = r[1];
        records[i].num_objects      = r[2];
    }
    *records_written = count;
    return OSDP_OK;
}

osdp_status_t osdp_pdcap_build(const osdp_pdcap_record_t *records,
                               size_t record_count,
                               uint8_t *buf, size_t buf_cap,
                               size_t *written)
{
    if (buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (record_count > 0 && records == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = record_count * OSDP_PDCAP_RECORD_BYTES;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < record_count; i++) {
        uint8_t *r = &buf[i * OSDP_PDCAP_RECORD_BYTES];
        r[0] = records[i].function_code;
        r[1] = records[i].compliance_level;
        r[2] = records[i].num_objects;
    }
    *written = total;
    return OSDP_OK;
}
