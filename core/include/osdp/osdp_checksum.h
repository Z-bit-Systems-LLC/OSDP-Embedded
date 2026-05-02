// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_CHECKSUM_H
#define OSDP_CHECKSUM_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OSDP 8-bit checksum, defined in SIA OSDP v2.2.2 section 5.9 Table 2:
 *
 *     "The CKSUM value is the 8 least significant bits of the 2's complement
 *      value of the sum of all previous characters of the message."
 *
 * In other words: cksum = (uint8_t)(- sum_of_bytes), so the byte sum of
 * (message_bytes ++ cksum) is congruent to 0 mod 256.
 *
 * `data` may be NULL only if `len` is 0. */
uint8_t osdp_checksum(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_CHECKSUM_H */
