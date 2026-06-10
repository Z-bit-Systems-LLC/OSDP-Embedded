// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_BUZ_STATE_H
#define OSDP_BUZ_STATE_H

#include "osdp/osdp_commands.h"   /* osdp_buz_cmd_t */
#include "osdp/osdp_types.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_buz_state — resolve "is the reader's buzzer sounding right now?"
 * from the OSDP buzzer command (osdp_BUZ, 0x6A).
 *
 * The buzzer command (spec) carries a `tone_code` (0x01 off / 0x02 default
 * tone), an `on_time` / `off_time` (100 ms units), and a `count` of on/off
 * cycles (0 = continuous). Like the LED resolver, this is a pure,
 * caller-owned value type: fold a command in with osdp_buz_apply() and ask
 * whether the buzzer is making sound at a given timestamp with
 * osdp_buz_sounding(). The on/off pattern (and the moment it finishes after
 * `count` cycles) is derived from `now_ms`, so a consumer that polls it on a
 * tick sees the same beep/silence edges a real buzzer produces — no
 * background timer needed.
 *
 * The PD and ACU embed a small bank of these and emit a change callback when
 * the resolved sounding state flips; see osdp_pd_*buzzer* /
 * osdp_acu_*buzzer* for that "tell me when the reader beeps / falls silent"
 * API. */

/* `tone_code` values (spec). */
#define OSDP_BUZ_TONE_OFF     0x01U  /* silence the buzzer */
#define OSDP_BUZ_TONE_DEFAULT 0x02U  /* the reader's default tone */

/* Resolved state of one reader's buzzer. Caller-owned; zero-initialise with
 * osdp_buz_init() (which leaves it silent). */
typedef struct osdp_buz {
    uint8_t  tone;            /* tone_code from the last command          */
    uint8_t  on_time_100ms;   /* ON duration per cycle, 100 ms units      */
    uint8_t  off_time_100ms;  /* OFF duration per cycle, 100 ms units     */
    uint8_t  count;           /* number of on/off cycles; 0 = continuous  */
    uint32_t started_ms;      /* timestamp passed to osdp_buz_apply        */
    bool     active;          /* a non-off command is loaded              */
} osdp_buz_t;

/* Initialise to silent: no command loaded. */
void osdp_buz_init(osdp_buz_t *buz);

/* Fold one buzzer command into `buz` at monotonic time `now_ms`. A
 * `tone_code` of OSDP_BUZ_TONE_OFF silences it; any other tone (re)starts
 * the on/off pattern from `now_ms`. */
void osdp_buz_apply(osdp_buz_t *buz, const osdp_buz_cmd_t *cmd,
                    uint32_t now_ms);

/* True iff the buzzer is producing sound at `now_ms`. Pure: the on/off
 * phase and the end-of-pattern (after `count` cycles) are recomputed from
 * `now_ms` each call. A continuous command (count == 0) sounds in its on
 * phase forever until silenced. 32-bit clock wraparound is handled via
 * unsigned subtraction. */
bool osdp_buz_sounding(const osdp_buz_t *buz, uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_BUZ_STATE_H */
