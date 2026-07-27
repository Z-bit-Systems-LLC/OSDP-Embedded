// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

#include <string.h>

/* osdp_MFG (0x80) — spec 6.19, Table 27.
 *
 * Byte layout:
 *   0..2   Vendor Code, the manufacturer's IEEE MA-L (24 bits)
 *   3..n   vendor-defined data
 *
 * The vendor code is transmitted first octet first. The spec does not call it
 * big- or little-endian because it is not a number — it is the same 24 bits a
 * manufacturer uses to form its Ethernet MAC addresses — so it is modelled
 * here as a 3-byte array rather than a uint32, which keeps the wire order
 * unambiguous and avoids inventing a byte order the spec never states.
 *
 * The data beyond the vendor code is entirely vendor-defined; spec note 1
 * describes the PD keying off "the four bytes formed by the three byte
 * VendorCode and the Command_ID", so by convention the first data byte is
 * often a vendor command selector — but that is a convention, not a field the
 * spec defines, so the codec does not carve it out.
 *
 * A zero-length data section is legal: vendor code alone is a well-formed
 * osdp_MFG. */

osdp_status_t osdp_mfg_decode(const uint8_t *payload, size_t len,
                              osdp_mfg_cmd_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len < OSDP_MFG_HEADER_BYTES || payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    (void)memcpy(out->vendor_code, payload, OSDP_MFG_VENDOR_CODE_BYTES);
    out->data_len = len - OSDP_MFG_HEADER_BYTES;
    out->data     = (out->data_len > 0) ? &payload[OSDP_MFG_HEADER_BYTES]
                                        : NULL;
    return OSDP_OK;
}

osdp_status_t osdp_mfg_build(const osdp_mfg_cmd_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (in->data_len > 0 && in->data == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = (size_t)OSDP_MFG_HEADER_BYTES + in->data_len;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    (void)memcpy(buf, in->vendor_code, OSDP_MFG_VENDOR_CODE_BYTES);
    if (in->data_len > 0) {
        (void)memcpy(&buf[OSDP_MFG_HEADER_BYTES], in->data, in->data_len);
    }
    *written = total;
    return OSDP_OK;
}
