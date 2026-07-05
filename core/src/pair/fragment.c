// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pair.h"

#include "shared/pack.h"

#include <stdint.h>
#include <string.h>

osdp_status_t osdp_pair_fragment_decode(const uint8_t *payload, size_t len,
                                        osdp_pair_fragment_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (payload == NULL || len < OSDP_PAIR_FRAG_HEADER_BYTES) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    const uint16_t total_size = osdp_pack_read_u16le(&payload[0]);
    const uint16_t offset     = osdp_pack_read_u16le(&payload[2]);
    const uint16_t frag_size  = osdp_pack_read_u16le(&payload[4]);

    /* The on-wire fragmentSize field MUST match the bytes that follow. */
    const size_t data_len = len - OSDP_PAIR_FRAG_HEADER_BYTES;
    if ((size_t)frag_size != data_len) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    /* A fragment cannot extend past the declared whole-message length.
     * (offset + frag_size is computed in 32-bit space; both are u16 so it
     * cannot overflow.) */
    if ((uint32_t)offset + (uint32_t)frag_size > (uint32_t)total_size) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    out->total_size = total_size;
    out->offset     = offset;
    out->data       = (data_len > 0) ? &payload[OSDP_PAIR_FRAG_HEADER_BYTES]
                                     : NULL;
    out->frag_len   = data_len;
    return OSDP_OK;
}

osdp_status_t osdp_pair_fragment_build(const osdp_pair_fragment_t *in,
                                       uint8_t *buf, size_t buf_cap,
                                       size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;

    /* fragmentSize is a single u16 on the wire. */
    if (in->frag_len > (size_t)UINT16_MAX) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->frag_len > 0 && in->data == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    /* Refuse to emit a fragment that overruns its own declared message. */
    if ((uint32_t)in->offset + (uint32_t)in->frag_len
        > (uint32_t)in->total_size) {
        return OSDP_ERR_INVALID_ARG;
    }

    const size_t total = OSDP_PAIR_FRAG_HEADER_BYTES + in->frag_len;
    if (buf_cap < total) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    osdp_pack_write_u16le(&buf[0], in->total_size);
    osdp_pack_write_u16le(&buf[2], in->offset);
    osdp_pack_write_u16le(&buf[4], (uint16_t)in->frag_len);
    if (in->frag_len > 0) {
        (void)memcpy(&buf[OSDP_PAIR_FRAG_HEADER_BYTES], in->data,
                     in->frag_len);
    }
    *written = total;
    return OSDP_OK;
}
