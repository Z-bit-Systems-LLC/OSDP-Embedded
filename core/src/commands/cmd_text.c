// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

#include <string.h>

/* osdp_TEXT byte layout (spec section 6.12, Table 20):
 *   0  reader_no
 *   1  text_command       (Table 21)
 *   2  temp_text_time_s
 *   3  row                (1-based)
 *   4  column             (1-based)
 *   5  text_length        (number of characters that follow)
 *   6..6+text_length-1    ASCII text bytes (0x20-0x7E per spec)
 */

osdp_status_t osdp_text_decode(const uint8_t *payload, size_t len,
                               osdp_text_cmd_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len < OSDP_TEXT_HEADER_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    const uint8_t text_length = payload[5];
    if ((size_t)OSDP_TEXT_HEADER_BYTES + text_length != len) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    out->reader_no        = payload[0];
    out->text_command     = payload[1];
    out->temp_text_time_s = payload[2];
    out->row              = payload[3];
    out->column           = payload[4];
    out->text_length      = text_length;
    out->text             = (text_length > 0) ? &payload[OSDP_TEXT_HEADER_BYTES]
                                              : NULL;
    out->text_len         = text_length;
    return OSDP_OK;
}

osdp_status_t osdp_text_build(const osdp_text_cmd_t *in,
                              uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (in->text_length != in->text_len) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->text_len > 0 && in->text == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = (size_t)OSDP_TEXT_HEADER_BYTES + in->text_len;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->reader_no;
    buf[1] = in->text_command;
    buf[2] = in->temp_text_time_s;
    buf[3] = in->row;
    buf[4] = in->column;
    buf[5] = in->text_length;
    if (in->text_len > 0) {
        (void)memcpy(&buf[OSDP_TEXT_HEADER_BYTES], in->text, in->text_len);
    }
    *written = total;
    return OSDP_OK;
}
