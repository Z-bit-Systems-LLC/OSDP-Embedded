// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

#include <stdint.h>
#include <string.h>

osdp_status_t osdp_keyset_decode(const uint8_t *payload, size_t len,
                                 osdp_keyset_cmd_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (payload == NULL || len < OSDP_KEYSET_HEADER_BYTES) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    const uint8_t key_type   = payload[0];
    const uint8_t key_length = payload[1];

    /* The on-wire `key_length` field MUST match the bytes that follow.
     * A mismatch is malformed and should be rejected — applying a
     * truncated or padded key would silently corrupt the rotation. */
    const size_t data_len = len - OSDP_KEYSET_HEADER_BYTES;
    if ((size_t)key_length != data_len) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    out->key_type     = key_type;
    out->key_length   = key_length;
    out->key_data     = (data_len > 0) ? &payload[OSDP_KEYSET_HEADER_BYTES]
                                       : NULL;
    out->key_data_len = data_len;
    return OSDP_OK;
}

osdp_status_t osdp_keyset_build(const osdp_keyset_cmd_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;

    /* Builder is the inverse of the decoder: refuse to emit a frame
     * whose header `key_length` disagrees with the supplied data. The
     * builder also caps at 255 bytes since key_length is a single
     * octet on the wire. */
    if (in->key_data_len > (size_t)UINT8_MAX) {
        return OSDP_ERR_INVALID_ARG;
    }
    if ((size_t)in->key_length != in->key_data_len) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->key_data_len > 0 && in->key_data == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    const size_t total = OSDP_KEYSET_HEADER_BYTES + in->key_data_len;
    if (buf_cap < total) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    buf[0] = in->key_type;
    buf[1] = in->key_length;
    if (in->key_data_len > 0) {
        (void)memcpy(&buf[OSDP_KEYSET_HEADER_BYTES], in->key_data,
                     in->key_data_len);
    }
    *written = total;
    return OSDP_OK;
}
