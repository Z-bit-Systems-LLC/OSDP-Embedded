// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

#include "shared/pack.h"

#include <string.h>

/* osdp_FILETRANSFER byte layout (spec 6.26, Table 34):
 *   0        FtType
 *   1..4     FtSizeTotal      (uint32 LE)
 *   5..8     FtOffset         (uint32 LE)
 *   9..10    FtFragmentSize   (uint16 LE)
 *   11..     FtData           (FtFragmentSize bytes; optional)
 */

osdp_status_t osdp_filetransfer_decode(const uint8_t *payload, size_t len,
                                       osdp_filetransfer_cmd_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len < OSDP_FILETRANSFER_HEADER_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    const uint16_t fragment_size = osdp_pack_read_u16le(&payload[9]);
    if ((size_t)OSDP_FILETRANSFER_HEADER_BYTES + fragment_size != len) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    out->ft_type       = payload[0];
    out->total_size    = osdp_pack_read_u32le(&payload[1]);
    out->offset        = osdp_pack_read_u32le(&payload[5]);
    out->fragment_size = fragment_size;
    out->data          = (fragment_size > 0)
                             ? &payload[OSDP_FILETRANSFER_HEADER_BYTES]
                             : NULL;
    out->data_len      = fragment_size;
    return OSDP_OK;
}

osdp_status_t osdp_filetransfer_build(const osdp_filetransfer_cmd_t *in,
                                      uint8_t *buf, size_t buf_cap,
                                      size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (in->fragment_size != in->data_len) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->data_len > 0 && in->data == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = (size_t)OSDP_FILETRANSFER_HEADER_BYTES + in->data_len;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    buf[0] = in->ft_type;
    osdp_pack_write_u32le(&buf[1], in->total_size);
    osdp_pack_write_u32le(&buf[5], in->offset);
    osdp_pack_write_u16le(&buf[9], in->fragment_size);
    if (in->data_len > 0) {
        (void)memcpy(&buf[OSDP_FILETRANSFER_HEADER_BYTES], in->data,
                     in->data_len);
    }
    *written = total;
    return OSDP_OK;
}
