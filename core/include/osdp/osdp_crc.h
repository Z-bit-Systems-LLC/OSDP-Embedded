// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_CRC_H
#define OSDP_CRC_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OSDP CRC-16, defined in SIA OSDP v2.2.2 Annex C.
 *
 *   Polynomial:    x^16 + x^12 + x^5 + x^0 (0x1021), CCITT.
 *   Initial value: 0x1D0F (table-based; equivalent to 0xFFFF augmented
 *                  with 16 zero bits in the shift-and-XOR formulation).
 *   Reflection:    none. Bytes processed MSB first.
 *   Final XOR:     none.
 *
 * The OSDP frame's CRC field covers SOM through the byte preceding the
 * CRC itself (i.e. all of the message except the trailing 2 CRC bytes).
 * The CRC is transmitted little-endian (LSB first, then MSB).
 */
#define OSDP_CRC16_INIT ((uint16_t)0x1D0FU)

/* Compute the OSDP CRC-16 over `data` (`len` bytes), starting from the
 * standard OSDP initial value 0x1D0F.
 *
 * `data` may be NULL only if `len` is 0. */
uint16_t osdp_crc16(const uint8_t *data, size_t len);

/* Streaming variant: continue an existing CRC computation from a previous
 * register value `crc`. Pass OSDP_CRC16_INIT for the first chunk. */
uint16_t osdp_crc16_update(uint16_t crc, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_CRC_H */
