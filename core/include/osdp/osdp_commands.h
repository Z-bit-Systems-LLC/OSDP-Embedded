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

#ifdef __cplusplus
}
#endif

#endif /* OSDP_COMMANDS_H */
