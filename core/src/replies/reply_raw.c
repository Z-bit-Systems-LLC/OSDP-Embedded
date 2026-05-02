// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

#include "shared/pack.h"

#include <string.h>

/* osdp_RAW byte layout (spec section 7.10, Table 55):
 *   0      reader_no
 *   1      format_code
 *   2..3   bit_count (16-bit LE)
 *   4..n   bit data (left-justified, MSB first per byte)
 */

osdp_status_t osdp_raw_decode(const uint8_t *payload, size_t len,
                              osdp_raw_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len < OSDP_RAW_HEADER_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->reader_no    = payload[0];
    out->format_code  = payload[1];
    out->bit_count    = osdp_pack_read_u16le(&payload[2]);
    out->bit_data_len = len - OSDP_RAW_HEADER_BYTES;
    out->bit_data     = (out->bit_data_len > 0)
                            ? &payload[OSDP_RAW_HEADER_BYTES]
                            : NULL;
    /* Sanity: spec says bit_count is left-justified and packed 8 bits per
     * byte. The trailing data should be exactly ceil(bit_count / 8) bytes. */
    const size_t expected = (size_t)((out->bit_count + 7u) / 8u);
    if (out->bit_data_len != expected) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return OSDP_OK;
}

osdp_status_t osdp_raw_build(const osdp_raw_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    const size_t expected = (size_t)((in->bit_count + 7u) / 8u);
    if (in->bit_data_len != expected) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->bit_data_len > 0 && in->bit_data == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = (size_t)OSDP_RAW_HEADER_BYTES + in->bit_data_len;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->reader_no;
    buf[1] = in->format_code;
    osdp_pack_write_u16le(&buf[2], in->bit_count);
    if (in->bit_data_len > 0) {
        (void)memcpy(&buf[OSDP_RAW_HEADER_BYTES], in->bit_data,
                     in->bit_data_len);
    }
    *written = total;
    return OSDP_OK;
}
