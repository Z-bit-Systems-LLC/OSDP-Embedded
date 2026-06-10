// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_buz_state.h"

#include <string.h>

void osdp_buz_init(osdp_buz_t *buz)
{
    if (buz == NULL) {
        return;
    }
    (void)memset(buz, 0, sizeof(*buz));
    /* A zeroed struct is "silent": active == false. */
}

void osdp_buz_apply(osdp_buz_t *buz, const osdp_buz_cmd_t *cmd,
                    uint32_t now_ms)
{
    if (buz == NULL || cmd == NULL) {
        return;
    }
    buz->tone           = cmd->tone_code;
    buz->on_time_100ms  = cmd->on_time_100ms;
    buz->off_time_100ms = cmd->off_time_100ms;
    buz->count          = cmd->count;
    buz->started_ms     = now_ms;
    /* An "off" command loads but never sounds; any other tone arms the
     * pattern from now. */
    buz->active = (cmd->tone_code != OSDP_BUZ_TONE_OFF);
}

bool osdp_buz_sounding(const osdp_buz_t *buz, uint32_t now_ms)
{
    if (buz == NULL || !buz->active || buz->tone == OSDP_BUZ_TONE_OFF) {
        return false;
    }

    const uint32_t on    = (uint32_t)buz->on_time_100ms  * 100U;
    const uint32_t off   = (uint32_t)buz->off_time_100ms * 100U;
    const uint32_t cycle = on + off;
    if (cycle == 0U) {
        /* Degenerate command with no timing: sound only if there's an
         * on-time, otherwise treat as silent. */
        return on > 0U;
    }

    /* Unsigned subtraction is wrap-safe across the 49.7-day rollover. */
    const uint32_t elapsed = now_ms - buz->started_ms;
    if (buz->count > 0U) {
        const uint32_t total = (uint32_t)buz->count * cycle;
        if (elapsed >= total) {
            return false;  /* the finite pattern has finished */
        }
    }
    /* count == 0 is continuous: the modulo keeps cycling forever. */
    const uint32_t phase = elapsed % cycle;
    return phase < on;
}
