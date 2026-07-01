// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef TINY_KMAC_H
#define TINY_KMAC_H

#include <stddef.h>
#include <stdint.h>

/* Compact, test-only KMAC256 (NIST SP 800-185) built on a self-contained
 * Keccak-f[1600] permutation. Used ONLY by the SC2 test / tool crypto
 * backend to derive session keys — it is never linked into the
 * freestanding core, which takes KMAC from the consumer's HAL.
 *
 * KMAC256 with an EMPTY customization string S, matching OSDP-SC2's
 * key derivation. Computes an `out_len`-byte MAC over `data` keyed by
 * `key`. Not constant-time; not for production use. */
void tiny_kmac256(const uint8_t *key,  size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t       *out,  size_t out_len);

#endif /* TINY_KMAC_H */
