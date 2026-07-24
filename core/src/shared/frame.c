// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_frame.h"

#include "osdp/osdp_checksum.h"
#include "osdp/osdp_crc.h"

#include <string.h>

/* ---- Decoder ------------------------------------------------------------*/

osdp_status_t osdp_frame_decode(const uint8_t *buf, size_t len,
                                osdp_frame_t *out)
{
    if (buf == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Need at least the fixed header, the code byte, and one integrity
     * byte to make any decoding decision. */
    if (len < OSDP_FRAME_MIN_LEN_CKSUM) {
        return OSDP_ERR_TRUNCATED;
    }

    if (buf[0] != OSDP_SOM) {
        return OSDP_ERR_BAD_SOM;
    }

    const uint8_t addr_byte = buf[1];
    const uint16_t len_field = (uint16_t)((uint16_t)buf[2] |
                                          ((uint16_t)buf[3] << 8));

    if (len_field != len) {
        return OSDP_ERR_BAD_LENGTH;
    }
    if (len_field > OSDP_FRAME_MAX_LEN) {
        return OSDP_ERR_BAD_LENGTH;
    }

    const uint8_t ctrl = buf[4];
    if ((ctrl & OSDP_CTRL_RESERVED) != 0) {
        return OSDP_ERR_BAD_CTRL;
    }

    const bool use_crc = (ctrl & OSDP_CTRL_USE_CRC) != 0;
    const bool has_scb = (ctrl & OSDP_CTRL_SCB)     != 0;

    const size_t integrity_size = use_crc ? 2u : 1u;
    const size_t min_required   = use_crc ? OSDP_FRAME_MIN_LEN_CRC
                                          : OSDP_FRAME_MIN_LEN_CKSUM;
    if (len < min_required) {
        return OSDP_ERR_TRUNCATED;
    }

    /* Optional Security Control Block. */
    size_t cursor = OSDP_FRAME_HEADER_LEN;
    uint8_t scb_length = 0;
    uint8_t scb_type   = 0;
    const uint8_t *scb_data = NULL;
    size_t scb_data_len = 0;

    if (has_scb) {
        /* Need SEC_BLK_LEN + SEC_BLK_TYPE bytes to even read the SCB
         * header; validate before indexing. */
        if (cursor + OSDP_SCB_MIN_LEN > len) {
            return OSDP_ERR_TRUNCATED;
        }
        scb_length = buf[cursor];
        scb_type   = buf[cursor + 1];
        if (scb_length < OSDP_SCB_MIN_LEN) {
            return OSDP_ERR_BAD_LENGTH;
        }
        /* SCB must fit before the code byte and integrity bytes. */
        if (cursor + scb_length + 1u + integrity_size > len) {
            return OSDP_ERR_BAD_LENGTH;
        }
        scb_data_len = (size_t)scb_length - OSDP_SCB_MIN_LEN;
        scb_data = (scb_data_len > 0) ? &buf[cursor + OSDP_SCB_MIN_LEN]
                                      : NULL;
        cursor += scb_length;
    }

    /* Code byte must exist. */
    if (cursor + 1u + integrity_size > len) {
        return OSDP_ERR_TRUNCATED;
    }
    const uint8_t code = buf[cursor];
    cursor += 1u;

    /* Remaining bytes (excluding integrity, and excluding any
     * trailing truncated MAC for SCS_15..18) are the payload. */
    const size_t payload_start = cursor;
    const size_t payload_end   = len - integrity_size;
    if (payload_end < payload_start) {
        /* Should be unreachable given the checks above, but be explicit. */
        return OSDP_ERR_TRUNCATED;
    }
    size_t payload_len = payload_end - payload_start;

    const uint8_t *mac = NULL;
    size_t         mac_len = 0;
    if (has_scb && osdp_scb_has_mac(scb_type)) {
        if (payload_len < OSDP_FRAME_MAC_LEN) {
            /* SCS_15..18 require at least a 4-byte MAC after the
             * code byte. Anything shorter is a malformed frame. */
            return OSDP_ERR_BAD_PAYLOAD;
        }
        payload_len -= OSDP_FRAME_MAC_LEN;
        mac     = &buf[payload_end - OSDP_FRAME_MAC_LEN];
        mac_len = OSDP_FRAME_MAC_LEN;
    }
    const uint8_t *payload = (payload_len > 0) ? &buf[payload_start] : NULL;

    /* Surface the frame's identity BEFORE the integrity check so a caller
     * can act on a frame that fails it. On OSDP_ERR_BAD_CRC and
     * OSDP_ERR_BAD_CHECKSUM these six fields — address, reply, sequence,
     * integrity, raw, raw_len — are valid; every other field of *out is
     * meaningful only on OSDP_OK. This lets a PD answer a bad-check command
     * addressed to it with osdp_NAK 0x01 (spec Table 47 / §5) instead of
     * dropping it silently. The SOM/length/ctrl/structure checks above have
     * already passed, so the header bytes these read are well-formed even
     * though the payload integrity is not. */
    out->address   = (uint8_t)(addr_byte & OSDP_ADDR_MASK);
    out->reply     = (addr_byte & OSDP_REPLY_FLAG) != 0;
    out->sequence  = (uint8_t)(ctrl & OSDP_CTRL_SQN_MASK);
    out->integrity = use_crc ? OSDP_INTEGRITY_CRC : OSDP_INTEGRITY_CHECKSUM;
    out->raw       = buf;
    out->raw_len   = len;

    /* Integrity check. */
    if (use_crc) {
        const uint16_t expected = osdp_crc16(buf, payload_end);
        const uint16_t actual   = (uint16_t)((uint16_t)buf[payload_end] |
                                             ((uint16_t)buf[payload_end + 1] << 8));
        if (actual != expected) {
            return OSDP_ERR_BAD_CRC;
        }
    } else {
        /* Defining property: sum of (message bytes + cksum) ≡ 0 mod 256.
         * Equivalent to: cksum == 0x100 - (sum of message bytes mod 256). */
        const uint8_t expected = osdp_checksum(buf, payload_end);
        if (buf[payload_end] != expected) {
            return OSDP_ERR_BAD_CHECKSUM;
        }
    }

    /* Populate output. */
    out->address      = (uint8_t)(addr_byte & OSDP_ADDR_MASK);
    out->reply        = (addr_byte & OSDP_REPLY_FLAG) != 0;
    out->sequence     = (uint8_t)(ctrl & OSDP_CTRL_SQN_MASK);
    out->integrity    = use_crc ? OSDP_INTEGRITY_CRC : OSDP_INTEGRITY_CHECKSUM;
    out->has_scb      = has_scb;
    out->scb_length   = scb_length;
    out->scb_type     = scb_type;
    out->scb_data     = scb_data;
    out->scb_data_len = scb_data_len;
    out->code         = code;
    out->payload      = payload;
    out->payload_len  = payload_len;
    out->mac          = mac;
    out->mac_len      = mac_len;
    out->raw          = buf;
    out->raw_len      = len;

    return OSDP_OK;
}

/* ---- Builder ------------------------------------------------------------*/

osdp_status_t osdp_frame_build(const osdp_frame_t *in,
                               uint8_t *buf, size_t buf_cap,
                               size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;

    if (in->address > OSDP_BROADCAST_ADDR) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->sequence > OSDP_CTRL_SQN_MASK) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->integrity != OSDP_INTEGRITY_CHECKSUM &&
        in->integrity != OSDP_INTEGRITY_CRC) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Validate SCB consistency. */
    size_t scb_total = 0;
    if (in->has_scb) {
        if (in->scb_length < OSDP_SCB_MIN_LEN) {
            return OSDP_ERR_INVALID_ARG;
        }
        const size_t expected_data_len =
            (size_t)in->scb_length - OSDP_SCB_MIN_LEN;
        if (in->scb_data_len != expected_data_len) {
            return OSDP_ERR_INVALID_ARG;
        }
        if (in->scb_data_len > 0 && in->scb_data == NULL) {
            return OSDP_ERR_INVALID_ARG;
        }
        scb_total = in->scb_length;
    }

    if (in->payload_len > 0 && in->payload == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Validate MAC presence vs SCB type. SCS_15..18 require a MAC;
     * other SCB types (or no SCB at all) must not carry one. */
    const bool need_mac = in->has_scb && osdp_scb_has_mac(in->scb_type);
    if (need_mac) {
        if (in->mac_len != OSDP_FRAME_MAC_LEN || in->mac == NULL) {
            return OSDP_ERR_INVALID_ARG;
        }
    } else if (in->mac_len != 0) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t mac_total = need_mac ? OSDP_FRAME_MAC_LEN : 0u;

    const size_t integrity_size =
        (in->integrity == OSDP_INTEGRITY_CRC) ? 2u : 1u;

    /* Total frame length = header + SCB + code + payload + MAC + integrity. */
    const size_t total = OSDP_FRAME_HEADER_LEN + scb_total + 1u +
                         in->payload_len + mac_total + integrity_size;

    if (total > OSDP_FRAME_MAX_LEN) {
        return OSDP_ERR_INVALID_ARG;
    }
    /* The transmitted buffer is the marking byte(s) plus the OSDP
     * frame; the LEN field and the CRC/checksum still cover only the
     * frame (SOM..integrity), so the cap must hold both. */
    if (OSDP_FRAME_MARK_LEN + total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    /* Spec 5.7 line marking: drive the line to a marking state for one
     * character time before the SOM (sent as a 0xFF byte) so the
     * receiver's signal converter locks on before the message starts.
     * Lives ahead of the SOM — excluded from LEN and integrity. */
    for (size_t m = 0; m < OSDP_FRAME_MARK_LEN; m++) {
        buf[m] = OSDP_FRAME_MARK;
    }

    /* Build the frame just past the marking byte(s). Every offset
     * below, the LEN field, and the integrity computation are relative
     * to this SOM-aligned base `f`, so the marking never enters the
     * frame body. */
    uint8_t *const f = buf + OSDP_FRAME_MARK_LEN;

    /* Write header. */
    size_t off = 0;
    f[off++] = OSDP_SOM;
    f[off++] = (uint8_t)((in->address & OSDP_ADDR_MASK) |
                         (in->reply ? OSDP_REPLY_FLAG : 0u));
    f[off++] = (uint8_t)(total & 0xFFu);
    f[off++] = (uint8_t)((total >> 8) & 0xFFu);
    f[off++] = (uint8_t)((in->sequence & OSDP_CTRL_SQN_MASK) |
                         ((in->integrity == OSDP_INTEGRITY_CRC)
                              ? OSDP_CTRL_USE_CRC : 0u) |
                         (in->has_scb ? OSDP_CTRL_SCB : 0u));

    /* SCB. */
    if (in->has_scb) {
        f[off++] = in->scb_length;
        f[off++] = in->scb_type;
        if (in->scb_data_len > 0) {
            (void)memcpy(&f[off], in->scb_data, in->scb_data_len);
            off += in->scb_data_len;
        }
    }

    /* Code + payload. */
    f[off++] = in->code;
    if (in->payload_len > 0) {
        (void)memcpy(&f[off], in->payload, in->payload_len);
        off += in->payload_len;
    }

    /* Truncated MAC for SCS_15..18, before integrity bytes. */
    if (mac_total > 0) {
        (void)memcpy(&f[off], in->mac, mac_total);
        off += mac_total;
    }

    /* Integrity. */
    if (in->integrity == OSDP_INTEGRITY_CRC) {
        const uint16_t crc = osdp_crc16(f, off);
        f[off++] = (uint8_t)(crc & 0xFFu);
        f[off++] = (uint8_t)((crc >> 8) & 0xFFu);
    } else {
        /* Compute into a temp on its own statement, exactly like the CRC
         * branch above. Folding this into `f[off++] = osdp_checksum(f,
         * off)` is undefined behaviour (C11 6.5p2): the read of `off` in
         * the argument is unsequenced relative to the `off++` side effect,
         * so a compiler may pass `off + 1` and checksum the (stale)
         * integrity slot itself. */
        const uint8_t cksum = osdp_checksum(f, off);
        f[off++] = cksum;
    }

    *written = OSDP_FRAME_MARK_LEN + off;
    return OSDP_OK;
}
