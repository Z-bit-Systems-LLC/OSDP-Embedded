// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"

#include "shared/pack.h"

/* osdp_LED record byte layout (spec section 6.10, Table 15):
 *   0  reader_no
 *   1  led_no
 *   2  temp_control_code     (Table 16: 0x00 NOP, 0x01 cancel, 0x02 set)
 *   3  temp_on_time          (100 ms units)
 *   4  temp_off_time
 *   5  temp_on_color         (Table 18)
 *   6  temp_off_color
 *   7  temp_timer_lsb
 *   8  temp_timer_msb
 *   9  perm_control_code     (Table 17: 0x00 NOP, 0x01 set)
 *  10  perm_on_time
 *  11  perm_off_time
 *  12  perm_on_color
 *  13  perm_off_color
 */

osdp_status_t osdp_led_decode(const uint8_t *payload, size_t len,
                              osdp_led_record_t *records,
                              size_t records_cap,
                              size_t *records_written)
{
    if (records_written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *records_written = 0;

    if (len == 0 || (len % OSDP_LED_RECORD_BYTES) != 0) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    const size_t count = len / OSDP_LED_RECORD_BYTES;
    if (records == NULL || records_cap < count) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < count; i++) {
        const uint8_t *r = &payload[i * OSDP_LED_RECORD_BYTES];
        osdp_led_record_t *o = &records[i];
        o->reader_no         = r[0];
        o->led_no            = r[1];
        o->temp_control_code = r[2];
        o->temp_on_time      = r[3];
        o->temp_off_time     = r[4];
        o->temp_on_color     = r[5];
        o->temp_off_color    = r[6];
        o->temp_timer_100ms  = osdp_pack_read_u16le(&r[7]);
        o->perm_control_code = r[9];
        o->perm_on_time      = r[10];
        o->perm_off_time     = r[11];
        o->perm_on_color     = r[12];
        o->perm_off_color    = r[13];
    }
    *records_written = count;
    return OSDP_OK;
}

osdp_status_t osdp_led_build(const osdp_led_record_t *records,
                             size_t record_count,
                             uint8_t *buf, size_t buf_cap,
                             size_t *written)
{
    if (buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (record_count == 0 || records == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = record_count * OSDP_LED_RECORD_BYTES;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < record_count; i++) {
        uint8_t *r = &buf[i * OSDP_LED_RECORD_BYTES];
        const osdp_led_record_t *in = &records[i];
        r[0]  = in->reader_no;
        r[1]  = in->led_no;
        r[2]  = in->temp_control_code;
        r[3]  = in->temp_on_time;
        r[4]  = in->temp_off_time;
        r[5]  = in->temp_on_color;
        r[6]  = in->temp_off_color;
        osdp_pack_write_u16le(&r[7], in->temp_timer_100ms);
        r[9]  = in->perm_control_code;
        r[10] = in->perm_on_time;
        r[11] = in->perm_off_time;
        r[12] = in->perm_on_color;
        r[13] = in->perm_off_color;
    }
    *written = total;
    return OSDP_OK;
}
