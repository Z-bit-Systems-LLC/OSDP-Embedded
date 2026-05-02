// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_FRAME_H
#define OSDP_FRAME_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Constants from SIA OSDP v2.2.2 section 5.9 -------------------------*/

#define OSDP_SOM             0x53U   /* Start-Of-Message marker          */
#define OSDP_BROADCAST_ADDR  0x7FU   /* Broadcast address                */
#define OSDP_REPLY_FLAG      0x80U   /* Set in ADDR for replies (PD->ACU)*/
#define OSDP_ADDR_MASK       0x7FU   /* Mask for the 7-bit address       */

#define OSDP_CTRL_SQN_MASK   0x03U   /* CTRL bits 0-1: sequence number   */
#define OSDP_CTRL_USE_CRC    0x04U   /* CTRL bit 2: 0=cksum, 1=CRC-16    */
#define OSDP_CTRL_SCB        0x08U   /* CTRL bit 3: SCB present          */
#define OSDP_CTRL_RESERVED   0xF0U   /* CTRL bits 4-7: must be zero      */

#define OSDP_FRAME_HEADER_LEN     5U   /* SOM + ADDR + LEN(2) + CTRL     */
#define OSDP_FRAME_MIN_LEN_CKSUM  7U   /* hdr + code + cksum             */
#define OSDP_FRAME_MIN_LEN_CRC    8U   /* hdr + code + crc(2)            */
#define OSDP_FRAME_MAX_LEN     1440U   /* spec 5.6 (other-device limit)  */

#define OSDP_SCB_MIN_LEN          2U   /* SEC_BLK_LEN + SEC_BLK_TYPE     */

/* ---- Frame model --------------------------------------------------------*/

/* Whether the trailing integrity bytes are an 8-bit checksum or a
 * 16-bit CRC. Determined by CTRL bit 2 (OSDP_CTRL_USE_CRC). */
typedef enum osdp_integrity {
    OSDP_INTEGRITY_CHECKSUM = 0,
    OSDP_INTEGRITY_CRC      = 1
} osdp_integrity_t;

/* Decoded representation of a single OSDP frame. The pointer fields
 * (`scb_data`, `payload`, `raw`) reference slices inside the input
 * buffer when produced by `osdp_frame_decode`; the input buffer must
 * outlive the frame. They are ignored by `osdp_frame_build`.
 *
 * NOTE: For Secure Channel frames whose security block carries a MAC
 * (SCB types SCS_15..18), the `payload` slice currently INCLUDES the
 * trailing 4-byte MAC. Iteration 1 does not split the MAC out — the
 * dedicated SC support in iteration 3 will. */
typedef struct osdp_frame {
    /* Header fields. */
    uint8_t           address;       /* 7-bit address (0x00-0x7E, 0x7F=bcast) */
    bool              reply;         /* true if ADDR bit 7 (REPLY_FLAG) set   */
    uint8_t           sequence;      /* 0..3 from CTRL bits 0-1               */
    osdp_integrity_t  integrity;     /* checksum or CRC                       */
    bool              has_scb;       /* true if CTRL bit 3 set                */

    /* Security Control Block — valid only when `has_scb` is true. */
    uint8_t           scb_length;    /* total SCB length, including itself    */
    uint8_t           scb_type;
    const uint8_t    *scb_data;      /* may be NULL when scb_data_len == 0    */
    size_t            scb_data_len;

    /* Command or reply identifier, plus the bytes that follow it. */
    uint8_t           code;
    const uint8_t    *payload;       /* may be NULL when payload_len == 0     */
    size_t            payload_len;

    /* Decode-only: the full frame slice within the input buffer.
     * Ignored by `osdp_frame_build`. */
    const uint8_t    *raw;
    size_t            raw_len;
} osdp_frame_t;

/* ---- API ----------------------------------------------------------------*/

/* Decode a single OSDP frame from `buf` (`len` bytes) into `*out`.
 *
 * The decoder validates SOM, length, control byte (including reserved
 * bits), the optional SCB header, and the trailing integrity bytes
 * (CRC-16 or 8-bit checksum, auto-selected from CTRL bit 2). On success
 * the slice pointers in `*out` reference the bytes of `buf` directly;
 * `buf` must remain valid as long as the frame is used. */
osdp_status_t osdp_frame_decode(const uint8_t *buf, size_t len,
                                osdp_frame_t *out);

/* Build an OSDP frame from `*in` into `buf` (`buf_cap` bytes capacity).
 *
 * The caller fills in: address, reply, sequence, integrity, has_scb,
 * (if has_scb) scb_length / scb_type / scb_data / scb_data_len, code,
 * payload, payload_len. The builder writes SOM, the LEN field, and the
 * trailing integrity bytes. `*written` receives the byte count actually
 * produced. The `raw` / `raw_len` fields of `*in` are ignored.
 *
 * Returns OSDP_ERR_BUFFER_TOO_SMALL if `buf_cap` is insufficient, or
 * OSDP_ERR_INVALID_ARG if any field is out of range (address > 0x7F,
 * sequence > 3, scb_length < 2, scb_data_len mismatched with
 * scb_length, payload size pushes the frame past OSDP_FRAME_MAX_LEN). */
osdp_status_t osdp_frame_build(const osdp_frame_t *in,
                               uint8_t *buf, size_t buf_cap,
                               size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_FRAME_H */
