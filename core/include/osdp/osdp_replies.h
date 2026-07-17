// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_REPLIES_H
#define OSDP_REPLIES_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Reply codes from SIA OSDP v2.2.2 Annex A.2. Iteration 1 implements
 * the baseline subset (ACK, NAK, PDID, PDCAP, RAW, KEYPAD, COM); other
 * codes are listed for completeness. */
#define OSDP_REPLY_ACK       0x40U
#define OSDP_REPLY_NAK       0x41U
#define OSDP_REPLY_PDID      0x45U
#define OSDP_REPLY_PDCAP     0x46U
#define OSDP_REPLY_LSTATR    0x48U
#define OSDP_REPLY_ISTATR    0x49U
#define OSDP_REPLY_OSTATR    0x4AU
#define OSDP_REPLY_RSTATR    0x4BU
#define OSDP_REPLY_RAW       0x50U
#define OSDP_REPLY_FMT       0x51U
#define OSDP_REPLY_KEYPAD    0x53U
#define OSDP_REPLY_COM       0x54U
#define OSDP_REPLY_BIOREADR  0x57U
#define OSDP_REPLY_BIOMATCHR 0x58U
#define OSDP_REPLY_CCRYPT    0x76U
#define OSDP_REPLY_RMAC_I    0x78U
#define OSDP_REPLY_BUSY      0x79U
#define OSDP_REPLY_FTSTAT    0x7AU
#define OSDP_REPLY_PIVDATAR  0x80U
#define OSDP_REPLY_GENAUTHR  0x81U
#define OSDP_REPLY_CRAUTHR   0x82U
#define OSDP_REPLY_MFGSTATR  0x83U
#define OSDP_REPLY_MFGERRR   0x84U
#define OSDP_REPLY_MFGREP    0x90U
#define OSDP_REPLY_XRD       0xB1U
/* osdp_PAIRR — SC2 asymmetric device pairing (PD -> ACU). Experimental /
 * NOT SIA-assigned; see osdp_pair.h and docs/pairing-design.md. */
#define OSDP_REPLY_PAIRR     0x8AU

/* NAK error codes per spec Table 47. */
#define OSDP_NAK_NO_ERROR              0x00U
#define OSDP_NAK_BAD_CHECK             0x01U
#define OSDP_NAK_CMD_LENGTH            0x02U
#define OSDP_NAK_UNKNOWN_CMD           0x03U
#define OSDP_NAK_UNEXPECTED_SEQUENCE   0x04U
#define OSDP_NAK_UNSUPPORTED_SCB       0x05U
#define OSDP_NAK_ENCRYPTION_REQUIRED   0x06U
#define OSDP_NAK_BIO_TYPE_UNSUPPORTED  0x07U
#define OSDP_NAK_BIO_FORMAT_UNSUPPORTED 0x08U
#define OSDP_NAK_RECORD_INVALID        0x09U

/* ========================================================================
 * osdp_ACK (0x40) — empty payload
 * ====================================================================== */

osdp_status_t osdp_ack_decode(const uint8_t *payload, size_t len);
osdp_status_t osdp_ack_build(uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_NAK (0x41) — 1 byte error code + optional details
 * ====================================================================== */

typedef struct osdp_nak {
    uint8_t        error_code;  /* see OSDP_NAK_* */
    const uint8_t *details;     /* may be NULL when details_len == 0 */
    size_t         details_len;
} osdp_nak_t;

osdp_status_t osdp_nak_decode(const uint8_t *payload, size_t len,
                              osdp_nak_t *out);
osdp_status_t osdp_nak_build(const osdp_nak_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_PDID (0x45) — 12-byte PD identification report
 * ====================================================================== */

#define OSDP_PDID_PAYLOAD_BYTES 12U

typedef struct osdp_pdid {
    uint8_t  vendor_code[3];   /* IEEE OUI, octets in transmission order */
    uint8_t  model;
    uint8_t  version;
    uint32_t serial;           /* 32-bit LE on the wire */
    uint8_t  firmware_major;
    uint8_t  firmware_minor;
    uint8_t  firmware_build;
} osdp_pdid_t;

osdp_status_t osdp_pdid_decode(const uint8_t *payload, size_t len,
                               osdp_pdid_t *out);
osdp_status_t osdp_pdid_build(const osdp_pdid_t *in,
                              uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_PDCAP (0x46) — list of 3-byte capability records
 * ====================================================================== */

#define OSDP_PDCAP_RECORD_BYTES 3U

typedef struct osdp_pdcap_record {
    uint8_t function_code;
    uint8_t compliance_level;
    uint8_t num_objects;
} osdp_pdcap_record_t;

osdp_status_t osdp_pdcap_decode(const uint8_t *payload, size_t len,
                                osdp_pdcap_record_t *records,
                                size_t records_cap,
                                size_t *records_written);

osdp_status_t osdp_pdcap_build(const osdp_pdcap_record_t *records,
                               size_t record_count,
                               uint8_t *buf, size_t buf_cap,
                               size_t *written);

/* ========================================================================
 * osdp_LSTATR (0x48) — local status report, 2 bytes (tamper, power)
 * ====================================================================== */

#define OSDP_LSTATR_PAYLOAD_BYTES 2U

/* Status byte values (spec Table 50). The same 0x00/0x01 convention
 * applies to both bytes: 0x00 is the healthy state. */
#define OSDP_LSTATR_NORMAL        0x00U  /* tamper or power: normal        */
#define OSDP_LSTATR_TAMPER        0x01U  /* tamper byte: tamper detected   */
#define OSDP_LSTATR_POWER_FAILURE 0x01U  /* power byte: power failure       */

typedef struct osdp_lstatr {
    uint8_t tamper;   /* 0x00 normal, 0x01 tamper detected   */
    uint8_t power;    /* 0x00 normal, 0x01 power failure      */
} osdp_lstatr_t;

osdp_status_t osdp_lstatr_decode(const uint8_t *payload, size_t len,
                                 osdp_lstatr_t *out);
osdp_status_t osdp_lstatr_build(const osdp_lstatr_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_ISTATR (0x49) — input status report, one status byte per input
 * ====================================================================== */

/* Input status values (spec Table 52). */
#define OSDP_ISTATR_INACTIVE  0x00U
#define OSDP_ISTATR_ACTIVE    0x01U
#define OSDP_ISTATR_SHORT     0x02U
#define OSDP_ISTATR_OPEN      0x03U
#define OSDP_ISTATR_FAULT     0x04U
#define OSDP_ISTATR_UNKNOWN   0x05U

osdp_status_t osdp_istatr_decode(const uint8_t *payload, size_t len,
                                 uint8_t *statuses, size_t statuses_cap,
                                 size_t *statuses_written);
osdp_status_t osdp_istatr_build(const uint8_t *statuses, size_t count,
                                uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_OSTATR (0x4A) — output status report, one status byte per output
 * ====================================================================== */

/* Output status values (spec Table 53). */
#define OSDP_OSTATR_INACTIVE  0x00U
#define OSDP_OSTATR_ACTIVE    0x01U

osdp_status_t osdp_ostatr_decode(const uint8_t *payload, size_t len,
                                 uint8_t *statuses, size_t statuses_cap,
                                 size_t *statuses_written);
osdp_status_t osdp_ostatr_build(const uint8_t *statuses, size_t count,
                                uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_RSTATR (0x4B) — reader tamper status report, one byte per reader
 * ====================================================================== */

/* Reader tamper status values (spec Table 54). */
#define OSDP_RSTATR_NORMAL         0x00U
#define OSDP_RSTATR_NOT_CONNECTED  0x01U
#define OSDP_RSTATR_TAMPER         0x02U

osdp_status_t osdp_rstatr_decode(const uint8_t *payload, size_t len,
                                 uint8_t *statuses, size_t statuses_cap,
                                 size_t *statuses_written);
osdp_status_t osdp_rstatr_build(const uint8_t *statuses, size_t count,
                                uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_RAW (0x50) — card data, 4-byte header + bit-packed data
 * ====================================================================== */

#define OSDP_RAW_HEADER_BYTES 4U

typedef enum osdp_raw_format {
    OSDP_RAW_FORMAT_RAW           = 0x00U,
    OSDP_RAW_FORMAT_WIEGAND       = 0x01U,
    OSDP_RAW_FORMAT_UID           = 0x02U,
    OSDP_RAW_FORMAT_OSS_SID       = 0x03U
} osdp_raw_format_t;

typedef struct osdp_raw {
    uint8_t        reader_no;
    uint8_t        format_code;     /* see osdp_raw_format_t */
    uint16_t       bit_count;
    const uint8_t *bit_data;        /* may be NULL when bit_data_len == 0 */
    size_t         bit_data_len;    /* (bit_count + 7) / 8 expected       */
} osdp_raw_t;

osdp_status_t osdp_raw_decode(const uint8_t *payload, size_t len,
                              osdp_raw_t *out);
osdp_status_t osdp_raw_build(const osdp_raw_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_KEYPAD (0x53) — keypad data, 2-byte header + ASCII digits
 * ====================================================================== */

#define OSDP_KEYPAD_HEADER_BYTES 2U

typedef struct osdp_keypad {
    uint8_t        reader_no;
    uint8_t        digit_count;
    const uint8_t *digits;       /* ASCII; may be NULL when digit_count==0 */
    size_t         digits_len;   /* must equal digit_count                */
} osdp_keypad_t;

osdp_status_t osdp_keypad_decode(const uint8_t *payload, size_t len,
                                 osdp_keypad_t *out);
osdp_status_t osdp_keypad_build(const osdp_keypad_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_COM (0x54) — comm-config report, 5 bytes (address + 32-bit LE baud)
 * ====================================================================== */

#define OSDP_COM_PAYLOAD_BYTES 5U

typedef struct osdp_com {
    uint8_t  address;     /* 0x00..0x7E */
    uint32_t baud_rate;
} osdp_com_t;

osdp_status_t osdp_com_decode(const uint8_t *payload, size_t len,
                              osdp_com_t *out);
osdp_status_t osdp_com_build(const osdp_com_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_FTSTAT (0x7A) — file-transfer status, sent in reply to every
 * osdp_FILETRANSFER, 7-byte payload.
 *
 * Wire layout (spec 7.25, Table 68):
 *   0        FtAction        — control flags (see OSDP_FTSTAT_ACTION_*)
 *   1..2     FtDelay         — ms the ACU should wait before the next
 *                             osdp_FILETRANSFER, uint16 LE (0 = no delay)
 *   3..4     FtStatusDetail  — SIGNED int16 LE status (see OSDP_FTSTAT_*)
 *   5..6     FtUpdateMsgMax  — alternate max fragment size for subsequent
 *                             messages, uint16 LE (0 = no change requested)
 * ==================================================================== */

#define OSDP_FTSTAT_PAYLOAD_BYTES 7U

/* FtStatusDetail values (spec Table 68). Signed: negative = failure. */
#define OSDP_FTSTAT_MALFORMED     (-3)  /* file data unacceptable (malformed) */
#define OSDP_FTSTAT_UNRECOGNIZED  (-2)  /* unrecognized file contents         */
#define OSDP_FTSTAT_ABORT         (-1)  /* abort file transfer                */
#define OSDP_FTSTAT_OK             (0)  /* ok to proceed                      */
#define OSDP_FTSTAT_PROCESSED      (1)  /* file contents processed            */
#define OSDP_FTSTAT_REBOOTING      (2)  /* rebooting now; expect comms reset  */
#define OSDP_FTSTAT_FINISHING      (3)  /* PD finishing; ACU sends idle msgs  */

/* FtAction control-flag bits (spec Table 68). */
#define OSDP_FTSTAT_ACTION_INTERLEAVE_OK 0x01U  /* bit0: ok to interleave     */
#define OSDP_FTSTAT_ACTION_LEAVE_SC      0x02U  /* bit1: leave SC for transfer */
#define OSDP_FTSTAT_ACTION_POLL_AVAIL    0x04U  /* bit2: separate poll response */

typedef struct osdp_ftstat {
    uint8_t   action;          /* FtAction flags (OSDP_FTSTAT_ACTION_*)      */
    uint16_t  delay_ms;        /* FtDelay before next osdp_FILETRANSFER      */
    int16_t   status_detail;   /* FtStatusDetail, signed (OSDP_FTSTAT_*)     */
    uint16_t  update_msg_max;  /* FtUpdateMsgMax (0 = no change)             */
} osdp_ftstat_t;

osdp_status_t osdp_ftstat_decode(const uint8_t *payload, size_t len,
                                 osdp_ftstat_t *out);
osdp_status_t osdp_ftstat_build(const osdp_ftstat_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_REPLIES_H */
