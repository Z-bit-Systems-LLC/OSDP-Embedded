// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

#include <string.h>

/* osdp_FMT (0x51) — spec 7.11, Table 56.
 *
 * Byte layout:
 *   0      reader_no
 *   1      direction      (0x01 = forward read; see the header enum)
 *   2      char_count     number of ASCII characters that follow
 *   3..n   the characters
 *
 * **Deprecated by the spec**, and implemented anyway: a Monitor has to decode
 * whatever is on the wire, and existing readers still emit it. New PD code
 * should report card data as osdp_RAW instead.
 *
 * Table 56 survives PDF extraction badly — its Value and Description columns
 * are shifted relative to the field names, so the legend reads as though
 * "0x01-0x7F" were the "Default Reader Number value". The field list itself is
 * unambiguous (three header bytes then the data), and it matches the shape of
 * osdp_KEYPAD in the adjacent Table 57, which is the layout implemented here.
 *
 * `char_count` is validated against the actual byte count, exactly as
 * osdp_KEYPAD validates its digit count, so a truncated or padded frame is
 * rejected rather than silently mis-parsed. */

osdp_status_t osdp_fmt_decode(const uint8_t *payload, size_t len,
                              osdp_fmt_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len < OSDP_FMT_HEADER_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    const uint8_t char_count = payload[2];
    if ((size_t)OSDP_FMT_HEADER_BYTES + char_count != len) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->reader_no  = payload[0];
    out->direction  = payload[1];
    out->char_count = char_count;
    out->chars_len  = char_count;
    out->chars      = (char_count > 0) ? &payload[OSDP_FMT_HEADER_BYTES]
                                       : NULL;
    return OSDP_OK;
}

osdp_status_t osdp_fmt_build(const osdp_fmt_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (in->char_count != in->chars_len) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->chars_len > 0 && in->chars == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = (size_t)OSDP_FMT_HEADER_BYTES + in->chars_len;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->reader_no;
    buf[1] = in->direction;
    buf[2] = in->char_count;
    if (in->chars_len > 0) {
        (void)memcpy(&buf[OSDP_FMT_HEADER_BYTES], in->chars, in->chars_len);
    }
    *written = total;
    return OSDP_OK;
}
