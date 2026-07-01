// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_sc2.h"

#include <string.h>

void osdp_sc2_session_init(osdp_sc2_session_t *session)
{
    if (session == NULL) {
        return;
    }
    (void)memset(session, 0, sizeof(*session));
}
