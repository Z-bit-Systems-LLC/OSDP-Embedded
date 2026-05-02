// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

#include "shared/pack.h"

osdp_status_t osdp_out_decode(const uint8_t *payload, size_t len,
                              osdp_out_record_t *records,
                              size_t records_cap,
                              size_t *records_written)
{
    if (records_written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *records_written = 0;

    /* Spec 6.9: at least one record is required, and the payload must be
     * an integer multiple of OSDP_OUT_RECORD_BYTES. */
    if (len == 0 || (len % OSDP_OUT_RECORD_BYTES) != 0) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    const size_t count = len / OSDP_OUT_RECORD_BYTES;
    if (records == NULL || records_cap < count) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < count; i++) {
        const uint8_t *r = &payload[i * OSDP_OUT_RECORD_BYTES];
        records[i].output_no    = r[0];
        records[i].control_code = r[1];
        records[i].timer_100ms  = osdp_pack_read_u16le(&r[2]);
    }
    *records_written = count;
    return OSDP_OK;
}

osdp_status_t osdp_out_build(const osdp_out_record_t *records,
                             size_t record_count,
                             uint8_t *buf, size_t buf_cap,
                             size_t *written)
{
    if (buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (record_count == 0 || records == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = record_count * OSDP_OUT_RECORD_BYTES;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < record_count; i++) {
        uint8_t *r = &buf[i * OSDP_OUT_RECORD_BYTES];
        r[0] = records[i].output_no;
        r[1] = records[i].control_code;
        osdp_pack_write_u16le(&r[2], records[i].timer_100ms);
    }
    *written = total;
    return OSDP_OK;
}
