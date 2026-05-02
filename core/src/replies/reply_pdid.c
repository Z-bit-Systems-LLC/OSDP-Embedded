// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

#include "shared/pack.h"

/* osdp_PDID byte layout (spec section 7.4, Table 48):
 *   0..2   vendor_code (3 octets, transmission order)
 *   3      model
 *   4      version
 *   5..8   serial number (32-bit LE)
 *   9      firmware major
 *   10     firmware minor
 *   11     firmware build
 */

osdp_status_t osdp_pdid_decode(const uint8_t *payload, size_t len,
                               osdp_pdid_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len != OSDP_PDID_PAYLOAD_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->vendor_code[0] = payload[0];
    out->vendor_code[1] = payload[1];
    out->vendor_code[2] = payload[2];
    out->model          = payload[3];
    out->version        = payload[4];
    out->serial         = osdp_pack_read_u32le(&payload[5]);
    out->firmware_major = payload[9];
    out->firmware_minor = payload[10];
    out->firmware_build = payload[11];
    return OSDP_OK;
}

osdp_status_t osdp_pdid_build(const osdp_pdid_t *in,
                              uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (buf_cap < OSDP_PDID_PAYLOAD_BYTES) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    buf[0]  = in->vendor_code[0];
    buf[1]  = in->vendor_code[1];
    buf[2]  = in->vendor_code[2];
    buf[3]  = in->model;
    buf[4]  = in->version;
    osdp_pack_write_u32le(&buf[5], in->serial);
    buf[9]  = in->firmware_major;
    buf[10] = in->firmware_minor;
    buf[11] = in->firmware_build;
    *written = OSDP_PDID_PAYLOAD_BYTES;
    return OSDP_OK;
}
