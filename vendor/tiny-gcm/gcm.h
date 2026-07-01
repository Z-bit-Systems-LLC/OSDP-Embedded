// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef TINY_GCM_H
#define TINY_GCM_H

#include <stddef.h>
#include <stdint.h>

/* Compact, test/tool-only AES-256-GCM built on the AES-256 build of
 * tiny-AES-c (CTR + GHASH). Used by the OSDP-SC2 test crypto backend
 * and the osdp-pd-mock / osdp-acu-mock SC2 adapters — NEVER by the
 * freestanding core, which takes AES-256-GCM from the consumer's HAL.
 * Not constant-time; not for production. */

/* Encrypt `pt_len` plaintext bytes into `ct` (same length; CTR-based,
 * no padding) with a 32-byte key and 12-byte nonce, authenticating
 * `aad`. Writes the 16-byte tag. `ct` may alias `pt`. */
void tiny_gcm256_encrypt(const uint8_t  key[32],
                         const uint8_t  nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt,  size_t pt_len,
                         uint8_t       *ct,
                         uint8_t        tag[16]);

/* Verify `tag` over (`aad`, `ct`) and, iff valid, decrypt `ct_len`
 * bytes into `pt`. Returns 0 on success, -1 on tag mismatch. `pt` may
 * alias `ct`. */
int tiny_gcm256_decrypt(const uint8_t  key[32],
                        const uint8_t  nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct,  size_t ct_len,
                        const uint8_t  tag[16],
                        uint8_t       *pt);

#endif /* TINY_GCM_H */
