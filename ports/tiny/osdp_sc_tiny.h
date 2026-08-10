// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_SC_TINY_H
#define OSDP_SC_TINY_H

/* Reference osdp_sc_crypto_t backend: AES-128 ECB over tiny-AES-c
 * (vendor/tiny-aes/, Unlicense).
 *
 * Host-side reference code, NOT part of the freestanding library. A shipping
 * PD or ACU is expected to bind its own primitives — mbedTLS, a hardware AES
 * block, BCryptGenRandom, /dev/urandom — behind this same vtable. What lives
 * here is the part that is genuinely the same everywhere: two stateless
 * key-and-block calls with no policy in them.
 *
 * The RNG is deliberately NOT supplied. rand_bytes is where the consumer's
 * requirements actually differ — a test needs a reproducible sequence, an
 * interop tool wants something cheap, a product needs a CSPRNG — and a
 * default here would be the wrong one for at least two of the three, silently.
 * Fill it in after calling osdp_sc_tiny_aes128(). */

#include "osdp/osdp_sc_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Populate `out`'s aes128_ecb_encrypt / aes128_ecb_decrypt members with the
 * tiny-AES implementations. Every other member — rand_bytes and user — is
 * left exactly as the caller had it, so this composes with a partially
 * initialised vtable and can be called on one that is already in use.
 *
 * Both callbacks are stateless and reentrant; a single vtable may be shared
 * across contexts. They tolerate `out == in` for in-place operation.
 *
 * No-op for a NULL `out`. */
void osdp_sc_tiny_aes128(osdp_sc_crypto_t *out);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_SC_TINY_H */
