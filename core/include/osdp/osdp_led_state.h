// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_LED_STATE_H
#define OSDP_LED_STATE_H

#include "osdp/osdp_commands.h"   /* osdp_led_record_t, osdp_led_color_t */
#include "osdp/osdp_types.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_led_state — resolve "what colour is this LED showing right now?"
 * from the OSDP LED control command (osdp_LED, 0x69).
 *
 * The LED command (spec Tables 16-18) carries, per physical LED, a
 * PERMANENT setting and an optional TEMPORARY override that runs for a
 * countdown timer and then reverts to the permanent setting. Each
 * setting is a two-phase flasher: an `on_color` shown for `on_time` and
 * an `off_color` shown for `off_time` (both in 100 ms units), repeating.
 *
 * This component owns none of that policy plumbing — it is a pure,
 * caller-owned value type (no malloc, no globals, no clock of its own):
 * you fold command records in with osdp_led_apply() and ask for the
 * displayed colour at a given monotonic timestamp with osdp_led_color().
 * Because the flash phase and the temporary-timer expiry are both
 * derived from the `now_ms` you pass to osdp_led_color(), the resolver
 * never needs a background timer or an OS tick — a single instance
 * models one physical LED and a consumer holds an array of them.
 *
 * The PD and ACU state machines embed an array of these and emit a
 * change callback when the resolved colour flips; see osdp_pd_*led* /
 * osdp_acu_*led* for that higher-level "tell me when the reader's LED
 * changes" API. */

/* ---- Control codes (spec Tables 16/17) ---------------------------------*/

/* `temp_control_code` values. */
#define OSDP_LED_TEMP_NOP    0x00U  /* leave any temporary state as-is      */
#define OSDP_LED_TEMP_CANCEL 0x01U  /* cancel temporary; revert to permanent*/
#define OSDP_LED_TEMP_SET    0x02U  /* set temporary state + start the timer*/

/* `perm_control_code` values. */
#define OSDP_LED_PERM_NOP    0x00U  /* leave the permanent state as-is      */
#define OSDP_LED_PERM_SET    0x01U  /* set the permanent state              */

/* ---- State -------------------------------------------------------------*/

/* One two-phase flash specification (a permanent or a temporary block of
 * an LED record). `on_time`/`off_time` are in 100 ms units, mirroring the
 * wire. When `on_time + off_time == 0` the LED is steady `on_color`. */
typedef struct osdp_led_flash {
    uint8_t on_color;        /* osdp_led_color_t shown during the ON phase  */
    uint8_t off_color;       /* osdp_led_color_t shown during the OFF phase */
    uint8_t on_time_100ms;   /* ON duration, 100 ms units                   */
    uint8_t off_time_100ms;  /* OFF duration, 100 ms units                  */
} osdp_led_flash_t;

/* Resolved state of a single physical LED. Caller-owned; zero-initialise
 * with osdp_led_init() (which leaves it steady-black = OSDP_LED_BLACK). */
typedef struct osdp_led {
    osdp_led_flash_t permanent;
    osdp_led_flash_t temporary;
    bool             temp_active;       /* a temporary override is loaded   */
    uint32_t         temp_started_ms;   /* timestamp passed to osdp_led_apply*/
    uint32_t         temp_duration_ms;  /* temp_timer_100ms × 100; 0 ⇒ off  */
} osdp_led_t;

/* Initialise to the power-on state: steady OSDP_LED_BLACK (off), no
 * temporary override. */
void osdp_led_init(osdp_led_t *led);

/* Fold one LED command record into `led` at monotonic time `now_ms`.
 *   - perm_control_code == OSDP_LED_PERM_SET updates the permanent block.
 *   - temp_control_code == OSDP_LED_TEMP_SET loads the temporary block and
 *     (re)starts its countdown from `now_ms`; a timer of 0 means the
 *     temporary expires immediately (so it never masks the permanent
 *     state indefinitely).
 *   - temp_control_code == OSDP_LED_TEMP_CANCEL drops any temporary now.
 *   - the NOP codes leave the corresponding block untouched.
 * The record's reader_no / led_no are NOT inspected here — slot routing is
 * the caller's job. */
void osdp_led_apply(osdp_led_t *led, const osdp_led_record_t *rec,
                    uint32_t now_ms);

/* Resolve the colour displayed at `now_ms` as an osdp_led_color_t value
 * (0x00..0x07). Pure: it does not mutate `led`, so the flash phase and
 * the temporary-timer expiry are recomputed from `now_ms` each call.
 * While a temporary override is active and unexpired the temporary block
 * drives the result; otherwise the permanent block does. 32-bit clock
 * wraparound is handled via unsigned subtraction. */
uint8_t osdp_led_color(const osdp_led_t *led, uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_LED_STATE_H */
