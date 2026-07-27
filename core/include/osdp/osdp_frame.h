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
/* 0x7F is the configuration address (spec 5.9 Note 2). Every PD accepts a
 * frame directed to 0x7F in addition to its own configured address, and
 * answers it at 0x7F | reply-flag = 0xFF. 0x7F is never assigned as a PD's
 * working address (0x00..0x7E). The spec historically names 0x7F
 * "broadcast"; OSDP_BROADCAST_ADDR remains as a wire-context alias.        */
#define OSDP_CONFIG_ADDR     0x7FU   /* Configuration / broadcast address */
#define OSDP_BROADCAST_ADDR  OSDP_CONFIG_ADDR /* broadcast-context alias  */
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

/* Driver "marking" byte and how many of them precede the SOM in a
 * transmitted frame. Per spec 5.7: before the first character of a
 * message the transmitter must drive the line to a marking state for
 * a minimum of one character time, "which can be achieved by sending
 * a character with all bits set to '1'" — i.e. one 0xFF byte. It lets
 * the receiver's RS-485 signal converter / multiplexer lock onto the
 * line before the SOM arrives. The marking byte is NOT part of the
 * OSDP message: it sits ahead of the SOM, is excluded from the LEN
 * field and the CRC/checksum, and is stripped on receive by the
 * stream decoder's SOM resync. osdp_frame_build emits it so every
 * consumer is wire-conformant; osdp_frame_decode still expects its
 * input to start at the SOM. (The companion 5.7 requirement — >=2
 * character-times of idle BEFORE transmitting — is wall-clock timing
 * and belongs to the transport layer, not this builder.) */
#define OSDP_FRAME_MARK         0xFFU
#define OSDP_FRAME_MARK_LEN        1U

#define OSDP_SCB_MIN_LEN          2U   /* SEC_BLK_LEN + SEC_BLK_TYPE     */

/* Security Block (SB) type values from SIA OSDP v2.2.2 Annex D.1.3.
 * Only the byte values are defined here — the framing layer needs
 * them to decide whether to split a 4-byte MAC out of the payload
 * (and, eventually, whether the data block is encrypted). The actual
 * crypto and session-state handling lives in osdp::core's SC code. */
#define OSDP_SCS_11  0x11U   /* ACU→PD: SC initiation challenge   */
#define OSDP_SCS_12  0x12U   /* PD→ACU: client cryptogram         */
#define OSDP_SCS_13  0x13U   /* ACU→PD: server cryptogram         */
#define OSDP_SCS_14  0x14U   /* PD→ACU: initial R-MAC             */
#define OSDP_SCS_15  0x15U   /* ACU→PD: plain data + MAC          */
#define OSDP_SCS_16  0x16U   /* PD→ACU: plain data + MAC          */
#define OSDP_SCS_17  0x17U   /* ACU→PD: encrypted data + MAC      */
#define OSDP_SCS_18  0x18U   /* PD→ACU: encrypted data + MAC      */

/* Secure Channel 2 (OSDP-SC2) Security Block types, occupying the 0x2X
 * range parallel to SC1's 0x1X. SC2 is a quantum-resistant channel
 * built on AES-256-GCM + KMAC256 key derivation; SEC_BLK_DATA[0] = 0x02
 * selects it during the handshake. The crypto lives in osdp::core's
 * SC2 code (core/src/sc2/); the framing layer only needs the byte
 * values and the size of the trailing GCM tag. */
#define OSDP_SCS_21  0x21U   /* ACU→PD: SC2 initiation challenge   */
#define OSDP_SCS_22  0x22U   /* PD→ACU: SC2 client cryptogram      */
#define OSDP_SCS_23  0x23U   /* ACU→PD: SC2 server cryptogram      */
#define OSDP_SCS_24  0x24U   /* PD→ACU: SC2 handshake status       */
#define OSDP_SCS_25  0x25U   /* ACU→PD: SC2 plain data + tag       */
#define OSDP_SCS_26  0x26U   /* PD→ACU: SC2 plain data + tag       */
#define OSDP_SCS_27  0x27U   /* ACU→PD: SC2 encrypted data + tag   */
#define OSDP_SCS_28  0x28U   /* PD→ACU: SC2 encrypted data + tag   */

/* Truncated MAC byte count appended to SCS_15..18 frames before the
 * trailing CRC/checksum (spec D.5.1 step 1). */
#define OSDP_FRAME_MAC_LEN  4U

/* Full AES-256-GCM authentication tag appended to SCS_25..28 frames
 * before the trailing CRC/checksum. Unlike SC1's truncated MAC, the
 * SC2 tag is sent in full (16 bytes) and is the sole authenticator. */
#define OSDP_FRAME_MAC_LEN_SC2  16U

/* Size, in bytes, of the trailing MAC / authentication tag that a
 * given SCB type carries at the end of its data area: 4 for the SC1
 * types (SCS_15..18), 16 for the SC2 types (SCS_25..28), 0 for
 * handshake or non-SC frames. This is the single source of truth the
 * framing layer uses to split (decode) or reserve (build) the tail. */
static inline size_t osdp_scb_mac_len(uint8_t scb_type)
{
    if (scb_type >= OSDP_SCS_15 && scb_type <= OSDP_SCS_18) {
        return OSDP_FRAME_MAC_LEN;
    }
    if (scb_type >= OSDP_SCS_25 && scb_type <= OSDP_SCS_28) {
        return OSDP_FRAME_MAC_LEN_SC2;
    }
    return 0U;
}

/* SCB type carries a trailing MAC / GCM tag at the end of the data
 * area. True for SCS_15..18 (4-byte MAC) and SCS_25..28 (16-byte tag). */
static inline bool osdp_scb_has_mac(uint8_t scb_type)
{
    return osdp_scb_mac_len(scb_type) != 0U;
}

/* SCB type indicates the data block is encrypted. For SC1 (SCS_17/18)
 * the data is AES-128-CBC encrypted; for SC2 (SCS_27/28) it is
 * AES-256-GCM encrypted, and note the command/reply CODE byte is part
 * of the ciphertext (so a decoded frame's `code` field is the first
 * ciphertext byte, not a meaningful command code, until the SC2 layer
 * decrypts it). */
static inline bool osdp_scb_is_encrypted(uint8_t scb_type)
{
    return scb_type == OSDP_SCS_17 || scb_type == OSDP_SCS_18 ||
           scb_type == OSDP_SCS_27 || scb_type == OSDP_SCS_28;
}

/* ---- Frame model --------------------------------------------------------*/

/* Whether the trailing integrity bytes are an 8-bit checksum or a
 * 16-bit CRC. Determined by CTRL bit 2 (OSDP_CTRL_USE_CRC). */
typedef enum osdp_integrity {
    OSDP_INTEGRITY_CHECKSUM = 0,
    OSDP_INTEGRITY_CRC      = 1
} osdp_integrity_t;

/* Decoded representation of a single OSDP frame. The pointer fields
 * (`scb_data`, `payload`, `mac`, `raw`) reference slices inside the
 * input buffer when produced by `osdp_frame_decode`; the input buffer
 * must outlive the frame. The pointer fields are read by
 * `osdp_frame_build` from caller-supplied storage. The `raw` /
 * `raw_len` decode-only fields are ignored by build.
 *
 * For Secure Channel frames whose security block carries a MAC (SCB
 * types SCS_15..18), the trailing 4 bytes of the post-code area are
 * exposed via `mac` / `mac_len` and are NOT included in the
 * `payload` slice. Higher-level SC code in osdp::core consumes the
 * MAC and (for SCS_17/18) decrypts the payload. */
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

    /* Trailing MAC / authentication tag for MAC-bearing SCB types.
     * mac_len is OSDP_FRAME_MAC_LEN (4) for SC1 SCS_15..18,
     * OSDP_FRAME_MAC_LEN_SC2 (16) for SC2 SCS_25..28, and 0 otherwise
     * (see osdp_scb_mac_len). The build path requires a non-NULL `mac`
     * of the matching length whenever the SCB type implies a MAC; the
     * decode path always populates it for those SCB types. */
    const uint8_t    *mac;
    size_t            mac_len;

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
 * `buf` must remain valid as long as the frame is used.
 *
 * Partial output on an integrity failure: when the frame is structurally
 * valid but its check characters don't match — the decoder returns
 * OSDP_ERR_BAD_CRC or OSDP_ERR_BAD_CHECKSUM — `*out` still carries the
 * frame's identity (`address`, `reply`, `sequence`, `integrity`, `raw`,
 * `raw_len`); all other fields are indeterminate. This lets a PD answer a
 * bad-check command addressed to it with osdp_NAK 0x01 (spec Table 47 / §5)
 * rather than dropping it silently. For every other error code `*out` is
 * left untouched. */
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

/* Byte offset, within the buffer handed to osdp_frame_build, at which that
 * function will place the payload of a frame shaped like `*in`. Depends only
 * on the header fields (marking, header length, SCB presence and length, the
 * code byte) — `in->payload` and `in->payload_len` are not read.
 *
 * This exists so a caller can produce the payload *directly into its final
 * position* in the output buffer and then hand osdp_frame_build a template
 * whose `payload` already points there, instead of staging the bytes in a
 * separate scratch buffer that has to be sized for the largest message the
 * device will ever send. osdp_frame_build detects that case and skips the
 * copy. `osdp_sc_wrap_frame` uses this to encrypt straight into the output,
 * which is what lets a Secure Channel message be as large as the caller's
 * buffer rather than as large as a fixed internal array.
 *
 * Returns OSDP_ERR_INVALID_ARG for a NULL argument or an inconsistent SCB
 * (the same validation osdp_frame_build applies), so a caller that gets
 * OSDP_OK here can rely on the offset it was given. */
osdp_status_t osdp_frame_payload_offset(const osdp_frame_t *in,
                                        size_t *out_offset);

/* Largest `payload_len` that osdp_frame_build will accept into `buf_cap`
 * bytes for a frame shaped like `*shape`, also honouring the spec 5.6
 * maximum frame length. As with osdp_frame_payload_offset, only the header
 * fields of `*shape` are read — set `has_scb`, `scb_length`, `scb_type` and
 * `integrity` to what the real frame will carry and leave `payload` alone.
 *
 * This is the sizing question a sender has to answer before it can split a
 * message across packets: subtract framing overhead (marking byte, header,
 * security block, code byte, MAC/tag, CRC or checksum) from the capacity it
 * actually has, and what remains is one fragment. Guessing the overhead is
 * how off-by-a-few-bytes truncation bugs happen, so ask instead.
 *
 * `*out_max_payload` is 0 when the buffer cannot even hold an empty frame —
 * that is a valid answer, not an error. OSDP_ERR_INVALID_ARG is returned only
 * for a NULL argument or an inconsistent SCB.
 *
 * Under Secure Channel the answer is smaller still, because the ciphertext
 * carries padding (SC1) or an encrypted code byte (SC2). Use
 * osdp_sc_max_payload / osdp_sc2_max_payload for those; each accounts for
 * its own transform on top of this. */
osdp_status_t osdp_frame_max_payload(const osdp_frame_t *shape,
                                     size_t buf_cap,
                                     size_t *out_max_payload);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_FRAME_H */
