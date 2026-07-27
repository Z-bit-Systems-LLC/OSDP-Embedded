// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_COMMANDS_H
#define OSDP_COMMANDS_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Command codes from SIA OSDP v2.2.2 Annex A.1. Iteration 1 implements
 * the baseline subset (POLL, ID, CAP, OUT, LED, BUZ, TEXT, COMSET);
 * other codes are listed for completeness so dispatch can identify
 * them but their per-message codecs are not yet implemented. */
#define OSDP_CMD_POLL     0x60U
#define OSDP_CMD_ID       0x61U
#define OSDP_CMD_CAP      0x62U
#define OSDP_CMD_LSTAT    0x64U
#define OSDP_CMD_ISTAT    0x65U
#define OSDP_CMD_OSTAT    0x66U
#define OSDP_CMD_RSTAT    0x67U
#define OSDP_CMD_OUT      0x68U
#define OSDP_CMD_LED      0x69U
#define OSDP_CMD_BUZ      0x6AU
#define OSDP_CMD_TEXT     0x6BU
#define OSDP_CMD_COMSET   0x6EU
#define OSDP_CMD_BIOREAD      0x73U
#define OSDP_CMD_BIOMATCH     0x74U
#define OSDP_CMD_KEYSET       0x75U
#define OSDP_CMD_CHLNG        0x76U
#define OSDP_CMD_SCRYPT       0x77U
#define OSDP_CMD_ACURXSIZE    0x7BU
#define OSDP_CMD_FILETRANSFER 0x7CU
#define OSDP_CMD_MFG          0x80U
#define OSDP_CMD_XWR          0xA1U
#define OSDP_CMD_ABORT        0xA2U
#define OSDP_CMD_PIVDATA      0xA3U
#define OSDP_CMD_GENAUTH      0xA4U
#define OSDP_CMD_CRAUTH       0xA5U
#define OSDP_CMD_KEEPACTIVE   0xA7U

/* ========================================================================
 * osdp_POLL (0x60) — empty payload
 * ====================================================================== */

osdp_status_t osdp_poll_decode(const uint8_t *payload, size_t len);
osdp_status_t osdp_poll_build(uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_ID (0x61) — 1-byte ID type request
 * ====================================================================== */

typedef struct osdp_id_cmd {
    uint8_t id_type;     /* 0x00 = standard PD ID block; rest reserved */
} osdp_id_cmd_t;

osdp_status_t osdp_id_decode(const uint8_t *payload, size_t len,
                             osdp_id_cmd_t *out);
osdp_status_t osdp_id_build(const osdp_id_cmd_t *in,
                            uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_CAP (0x62) — 1-byte reply-type request
 * ====================================================================== */

typedef struct osdp_cap_cmd {
    uint8_t reply_type;  /* 0x00 = standard, 0x01 = extended */
} osdp_cap_cmd_t;

osdp_status_t osdp_cap_decode(const uint8_t *payload, size_t len,
                              osdp_cap_cmd_t *out);
osdp_status_t osdp_cap_build(const osdp_cap_cmd_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_OUT (0x68) — output control, N records of 4 bytes
 * ====================================================================== */

#define OSDP_OUT_RECORD_BYTES 4U

typedef struct osdp_out_record {
    uint8_t  output_no;       /* 0x00 = first */
    uint8_t  control_code;    /* see spec Table 14 */
    uint16_t timer_100ms;     /* 16-bit timer in units of 100 ms */
} osdp_out_record_t;

osdp_status_t osdp_out_decode(const uint8_t *payload, size_t len,
                              osdp_out_record_t *records,
                              size_t records_cap,
                              size_t *records_written);

osdp_status_t osdp_out_build(const osdp_out_record_t *records,
                             size_t record_count,
                             uint8_t *buf, size_t buf_cap,
                             size_t *written);

/* ========================================================================
 * osdp_LED (0x69) — LED control, N records of 14 bytes
 * ====================================================================== */

#define OSDP_LED_RECORD_BYTES 14U

/* Color values per spec Table 18. */
typedef enum osdp_led_color {
    OSDP_LED_BLACK   = 0x00U,
    OSDP_LED_RED     = 0x01U,
    OSDP_LED_GREEN   = 0x02U,
    OSDP_LED_AMBER   = 0x03U,
    OSDP_LED_BLUE    = 0x04U,
    OSDP_LED_MAGENTA = 0x05U,
    OSDP_LED_CYAN    = 0x06U,
    OSDP_LED_WHITE   = 0x07U
} osdp_led_color_t;

typedef struct osdp_led_record {
    uint8_t  reader_no;
    uint8_t  led_no;

    /* Temporary settings (spec Table 16). */
    uint8_t  temp_control_code;   /* 0x00 NOP, 0x01 cancel, 0x02 set */
    uint8_t  temp_on_time;        /* 100 ms units */
    uint8_t  temp_off_time;       /* 100 ms units */
    uint8_t  temp_on_color;
    uint8_t  temp_off_color;
    uint16_t temp_timer_100ms;

    /* Permanent settings (spec Table 17). */
    uint8_t  perm_control_code;   /* 0x00 NOP, 0x01 set */
    uint8_t  perm_on_time;
    uint8_t  perm_off_time;
    uint8_t  perm_on_color;
    uint8_t  perm_off_color;
} osdp_led_record_t;

osdp_status_t osdp_led_decode(const uint8_t *payload, size_t len,
                              osdp_led_record_t *records,
                              size_t records_cap,
                              size_t *records_written);

osdp_status_t osdp_led_build(const osdp_led_record_t *records,
                             size_t record_count,
                             uint8_t *buf, size_t buf_cap,
                             size_t *written);

/* ========================================================================
 * osdp_BUZ (0x6A) — buzzer control, single 5-byte record
 * ====================================================================== */

#define OSDP_BUZ_PAYLOAD_BYTES 5U

typedef struct osdp_buz_cmd {
    uint8_t reader_no;
    uint8_t tone_code;       /* 0x01 off, 0x02 default tone */
    uint8_t on_time_100ms;
    uint8_t off_time_100ms;
    uint8_t count;           /* 0x00 = continuous */
} osdp_buz_cmd_t;

osdp_status_t osdp_buz_decode(const uint8_t *payload, size_t len,
                              osdp_buz_cmd_t *out);
osdp_status_t osdp_buz_build(const osdp_buz_cmd_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_TEXT (0x6B) — text output, 6-byte header + variable-length string
 * ====================================================================== */

#define OSDP_TEXT_HEADER_BYTES 6U

typedef enum osdp_text_command {
    OSDP_TEXT_PERM_NO_WRAP   = 0x01U,
    OSDP_TEXT_PERM_WRAP      = 0x02U,
    OSDP_TEXT_TEMP_NO_WRAP   = 0x03U,
    OSDP_TEXT_TEMP_WRAP      = 0x04U
} osdp_text_command_t;

typedef struct osdp_text_cmd {
    uint8_t        reader_no;
    uint8_t        text_command;     /* see osdp_text_command_t           */
    uint8_t        temp_text_time_s; /* duration of temp text             */
    uint8_t        row;              /* 1-based                           */
    uint8_t        column;           /* 1-based                           */
    uint8_t        text_length;      /* spec value; must equal text_len   */
    const uint8_t *text;             /* may be NULL when text_length == 0 */
    size_t         text_len;         /* size of `text` (must == text_length) */
} osdp_text_cmd_t;

osdp_status_t osdp_text_decode(const uint8_t *payload, size_t len,
                               osdp_text_cmd_t *out);
osdp_status_t osdp_text_build(const osdp_text_cmd_t *in,
                              uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_COMSET (0x6E) — comm config, 5 bytes (address + 32-bit LE baud)
 * ====================================================================== */

#define OSDP_COMSET_PAYLOAD_BYTES 5U

typedef struct osdp_comset_cmd {
    uint8_t  address;     /* 0x00..0x7E */
    uint32_t baud_rate;   /* 32-bit LE on the wire */
} osdp_comset_cmd_t;

osdp_status_t osdp_comset_decode(const uint8_t *payload, size_t len,
                                 osdp_comset_cmd_t *out);
osdp_status_t osdp_comset_build(const osdp_comset_cmd_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_KEYSET (0x75) — rotate the PD's Secure Channel Base Key.
 *
 * Wire layout (spec 6.x / Annex B):
 *   byte 0    : key_type   — 0x01 = SCBK; other values reserved.
 *   byte 1    : key_length — must match the payload bytes that follow.
 *   bytes 2.. : key_data   — `key_length` bytes of new key material.
 *
 * For v2.2 baseline the only meaningful key_type is SCBK and key_length
 * is always 16 (matches OSDP_SC_KEY_LEN). The decoder accepts the
 * envelope generically; consumers MUST validate key_type / key_length
 * against what they're prepared to apply.
 *
 * The PD-side state machine in `osdp::pd` applies a well-formed
 * SCBK KEYSET inline (writes pd->sc.scbk, keeps the existing SC
 * session running) — the next handshake will use the rotated key.
 * ====================================================================== */

#define OSDP_KEYSET_HEADER_BYTES 2U

/* Key-type values per spec Annex A.1. SCBK (0x01) is the AES-128 SC1
 * base key; SCBK_AES256 (0x02) is the 32-byte AES-256 base key used by
 * OSDP-SC2. The enum is here so callers can write the names rather than
 * magic byte values. */
typedef enum osdp_keyset_key_type {
    OSDP_KEYSET_KEY_TYPE_SCBK        = 0x01U,
    OSDP_KEYSET_KEY_TYPE_SCBK_AES256 = 0x02U
} osdp_keyset_key_type_t;

typedef struct osdp_keyset_cmd {
    uint8_t        key_type;       /* OSDP_KEYSET_KEY_TYPE_SCBK = 0x01 */
    uint8_t        key_length;     /* must equal key_data_len           */
    const uint8_t *key_data;       /* may be NULL when key_data_len==0  */
    size_t         key_data_len;
} osdp_keyset_cmd_t;

osdp_status_t osdp_keyset_decode(const uint8_t *payload, size_t len,
                                 osdp_keyset_cmd_t *out);
osdp_status_t osdp_keyset_build(const osdp_keyset_cmd_t *in,
                                uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_FILETRANSFER (0x7C) — a fragment of a file (firmware image, config
 * blob, ...) streamed ACU → PD, 11-byte header + optional fragment bytes.
 *
 * Wire layout (spec 6.26, Table 34):
 *   0        FtType         — file content type (see osdp_ft_type_t)
 *   1..4     FtSizeTotal    — total file size, uint32 little-endian
 *   5..8     FtOffset       — offset of this fragment, uint32 LE; must be
 *                             monotonically increasing across a transfer
 *   9..10    FtFragmentSize — fragment byte count, uint16 LE
 *   11..     FtData         — `FtFragmentSize` fragment bytes (optional; an
 *                             "idle" fragment during PD "finishing" is 0)
 *
 * (Table 34 labels the header "DATA (12 bytes)" but the fields sum to 11;
 * that label is a PDF-extraction artifact. libosdp uses the same 11-byte
 * header.)
 * ==================================================================== */

#define OSDP_FILETRANSFER_HEADER_BYTES 11U

/* FtType values (spec Table 34). 0x04-0x7F reserved, 0x80-0xFF private. */
typedef enum osdp_ft_type {
    OSDP_FT_TYPE_OPAQUE   = 0x01U,  /* opaque file contents            */
    OSDP_FT_TYPE_BIOMATCH = 0x02U,  /* template for next osdp_BIOMATCH  */
    OSDP_FT_TYPE_DISPLAY  = 0x03U   /* PD-specific "display" data       */
} osdp_ft_type_t;

typedef struct osdp_filetransfer_cmd {
    uint8_t        ft_type;         /* see osdp_ft_type_t                    */
    uint32_t       total_size;      /* FtSizeTotal                           */
    uint32_t       offset;          /* FtOffset (monotonically increasing)   */
    uint16_t       fragment_size;   /* FtFragmentSize; must equal data_len   */
    const uint8_t *data;            /* fragment bytes; NULL when size == 0   */
    size_t         data_len;        /* size of `data`; must equal fragment_size */
} osdp_filetransfer_cmd_t;

osdp_status_t osdp_filetransfer_decode(const uint8_t *payload, size_t len,
                                       osdp_filetransfer_cmd_t *out);
osdp_status_t osdp_filetransfer_build(const osdp_filetransfer_cmd_t *in,
                                      uint8_t *buf, size_t buf_cap,
                                      size_t *written);

/* ========================================================================
 * Status report requests — all empty payload
 *
 * osdp_LSTAT (0x64) local     -> osdp_LSTATR   (spec 6.5, Table 9)
 * osdp_ISTAT (0x65) inputs    -> osdp_ISTATR   (spec 6.6, Table 10)
 * osdp_OSTAT (0x66) outputs   -> osdp_OSTATR   (spec 6.7, Table 11)
 * osdp_RSTAT (0x67) readers   -> osdp_RSTATR   (spec 6.8, Table 12)
 * ====================================================================== */

osdp_status_t osdp_lstat_decode(const uint8_t *payload, size_t len);
osdp_status_t osdp_lstat_build(uint8_t *buf, size_t buf_cap, size_t *written);

osdp_status_t osdp_istat_decode(const uint8_t *payload, size_t len);
osdp_status_t osdp_istat_build(uint8_t *buf, size_t buf_cap, size_t *written);

osdp_status_t osdp_ostat_decode(const uint8_t *payload, size_t len);
osdp_status_t osdp_ostat_build(uint8_t *buf, size_t buf_cap, size_t *written);

osdp_status_t osdp_rstat_decode(const uint8_t *payload, size_t len);
osdp_status_t osdp_rstat_build(uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_ACURXSIZE (0x7B) — ACU receive capacity, 2 bytes (16-bit LE)
 *
 * Spec 6.20, Table 28. Bounds what the PD may SEND — the mirror of the PD
 * advertising PDCAP function code 10. A PD honouring it caps outbound
 * messages at the lesser of this and its own transmit capacity
 * (osdp_pd_max_reply_payload).
 * ====================================================================== */

#define OSDP_ACURXSIZE_PAYLOAD_BYTES 2U

typedef struct osdp_acurxsize_cmd {
    uint16_t max_size;    /* ACURX_BUFSIZE, 16-bit LE on the wire */
} osdp_acurxsize_cmd_t;

osdp_status_t osdp_acurxsize_decode(const uint8_t *payload, size_t len,
                                    osdp_acurxsize_cmd_t *out);
osdp_status_t osdp_acurxsize_build(const osdp_acurxsize_cmd_t *in,
                                   uint8_t *buf, size_t buf_cap,
                                   size_t *written);

/* ========================================================================
 * osdp_MFG (0x80) — manufacturer-specific command
 *
 * Spec 6.19, Table 27: a 3-byte Vendor Code (the manufacturer's IEEE MA-L,
 * the same 24 bits it uses for Ethernet MAC addresses) followed by
 * vendor-defined data of any length, including none.
 *
 * The vendor code is a byte array rather than a uint32 because the spec
 * describes it as three octets in transmission order and never assigns it an
 * endianness. Convention puts a vendor command selector in the first data
 * byte, but the spec defines no such field, so the codec does not split it
 * out.
 *
 * A PD may answer with osdp_ACK, osdp_NAK, or osdp_MFGREP.
 * ====================================================================== */

#define OSDP_MFG_VENDOR_CODE_BYTES 3U
#define OSDP_MFG_HEADER_BYTES      OSDP_MFG_VENDOR_CODE_BYTES

typedef struct osdp_mfg_cmd {
    uint8_t        vendor_code[OSDP_MFG_VENDOR_CODE_BYTES];
    const uint8_t *data;       /* vendor-defined; NULL when data_len == 0 */
    size_t         data_len;
} osdp_mfg_cmd_t;

osdp_status_t osdp_mfg_decode(const uint8_t *payload, size_t len,
                              osdp_mfg_cmd_t *out);
osdp_status_t osdp_mfg_build(const osdp_mfg_cmd_t *in,
                             uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_ABORT (0xA2) — abort current operation, empty payload
 *
 * Spec 6.22, Table 30. Terminates any multi-part message or file transfer in
 * progress. osdp_ACK when cancelled; osdp_NAK when the PD cannot comply.
 * ====================================================================== */

osdp_status_t osdp_abort_decode(const uint8_t *payload, size_t len);
osdp_status_t osdp_abort_build(uint8_t *buf, size_t buf_cap, size_t *written);

/* ========================================================================
 * osdp_KEEPACTIVE (0xA7) — keep reader active, 2 bytes (16-bit LE ms)
 *
 * Spec 6.21, Table 29. Holds reader operations open for the given time so
 * communication with a credential still in the field is not dropped. A time
 * of 0 cancels a previous extension and is a legal value.
 * ====================================================================== */

#define OSDP_KEEPACTIVE_PAYLOAD_BYTES 2U

typedef struct osdp_keepactive_cmd {
    uint16_t time_ms;     /* milliseconds, 16-bit LE on the wire */
} osdp_keepactive_cmd_t;

osdp_status_t osdp_keepactive_decode(const uint8_t *payload, size_t len,
                                     osdp_keepactive_cmd_t *out);
osdp_status_t osdp_keepactive_build(const osdp_keepactive_cmd_t *in,
                                    uint8_t *buf, size_t buf_cap,
                                    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_COMMANDS_H */
