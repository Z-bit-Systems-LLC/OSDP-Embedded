// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_checksum.h"

uint8_t osdp_checksum(const uint8_t *data, size_t len)
{
    uint8_t sum = 0;
    if (data == NULL) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        sum = (uint8_t)(sum + data[i]);
    }
    /* 8 LSBs of the two's complement of the sum (per spec 5.9 Table 2). */
    return (uint8_t)(-(int8_t)sum);
}
