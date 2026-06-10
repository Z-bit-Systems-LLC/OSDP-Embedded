// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_led_state.h"

#include <string.h>

void osdp_led_init(osdp_led_t *led)
{
    if (led == NULL) {
        return;
    }
    (void)memset(led, 0, sizeof(*led));
    /* OSDP_LED_BLACK == 0x00, so a zeroed struct is already "steady
     * off": both flash blocks black, no temporary loaded. The explicit
     * memset documents that intent and survives any future field added
     * with a non-zero resting value. */
}

void osdp_led_apply(osdp_led_t *led, const osdp_led_record_t *rec,
                    uint32_t now_ms)
{
    if (led == NULL || rec == NULL) {
        return;
    }

    /* Permanent block: only touched when the ACU asks us to set it. */
    if (rec->perm_control_code == OSDP_LED_PERM_SET) {
        led->permanent.on_color       = rec->perm_on_color;
        led->permanent.off_color      = rec->perm_off_color;
        led->permanent.on_time_100ms  = rec->perm_on_time;
        led->permanent.off_time_100ms = rec->perm_off_time;
    }

    /* Temporary block: NOP leaves it as-is, CANCEL drops it, SET (re)arms
     * it from `now_ms`. */
    switch (rec->temp_control_code) {
    case OSDP_LED_TEMP_CANCEL:
        led->temp_active = false;
        break;
    case OSDP_LED_TEMP_SET:
        led->temporary.on_color       = rec->temp_on_color;
        led->temporary.off_color      = rec->temp_off_color;
        led->temporary.on_time_100ms  = rec->temp_on_time;
        led->temporary.off_time_100ms = rec->temp_off_time;
        led->temp_active      = true;
        led->temp_started_ms  = now_ms;
        led->temp_duration_ms = (uint32_t)rec->temp_timer_100ms * 100U;
        break;
    case OSDP_LED_TEMP_NOP:
    default:
        break;
    }
}

/* Resolve a single flash block to the colour shown `elapsed_ms` into its
 * cycle. on_time + off_time == 0 is treated as steady on_color. */
static uint8_t flash_color(const osdp_led_flash_t *f, uint32_t elapsed_ms)
{
    const uint32_t on     = (uint32_t)f->on_time_100ms  * 100U;
    const uint32_t off    = (uint32_t)f->off_time_100ms * 100U;
    const uint32_t period = on + off;
    if (period == 0U) {
        return f->on_color;        /* steady — no flashing configured */
    }
    const uint32_t phase = elapsed_ms % period;
    return (phase < on) ? f->on_color : f->off_color;
}

uint8_t osdp_led_color(const osdp_led_t *led, uint32_t now_ms)
{
    if (led == NULL) {
        return OSDP_LED_BLACK;
    }

    if (led->temp_active) {
        /* Unsigned subtraction is wrap-safe across the 49.7-day 32-bit
         * rollover. A zero-length timer is already expired. */
        const uint32_t elapsed = now_ms - led->temp_started_ms;
        if (led->temp_duration_ms != 0U && elapsed < led->temp_duration_ms) {
            return flash_color(&led->temporary, elapsed);
        }
        /* Expired — fall through to the permanent block. */
    }
    return flash_color(&led->permanent, now_ms);
}
