// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

#include <string.h>

/* osdp_KEYPAD byte layout (spec section 7.12, Table 57):
 *   0      reader_no
 *   1      digit_count
 *   2..n   ASCII digit bytes (n = digit_count)
 */

osdp_status_t osdp_keypad_decode(const uint8_t *payload, size_t len,
                                 osdp_keypad_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len < OSDP_KEYPAD_HEADER_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    const uint8_t digit_count = payload[1];
    if ((size_t)OSDP_KEYPAD_HEADER_BYTES + digit_count != len) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->reader_no   = payload[0];
    out->digit_count = digit_count;
    out->digits_len  = digit_count;
    out->digits      = (digit_count > 0) ? &payload[OSDP_KEYPAD_HEADER_BYTES]
                                         : NULL;
    return OSDP_OK;
}

osdp_status_t osdp_keypad_build(const osdp_keypad_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (in->digit_count != in->digits_len) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->digits_len > 0 && in->digits == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = (size_t)OSDP_KEYPAD_HEADER_BYTES + in->digits_len;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0] = in->reader_no;
    buf[1] = in->digit_count;
    if (in->digits_len > 0) {
        (void)memcpy(&buf[OSDP_KEYPAD_HEADER_BYTES], in->digits,
                     in->digits_len);
    }
    *written = total;
    return OSDP_OK;
}
