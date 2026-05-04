// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef SC_TEST_AES_H
#define SC_TEST_AES_H

#include <stddef.h>
#include <stdint.h>

#include "osdp/osdp_sc_crypto.h"

/* Adapter: presents tiny-AES-c (vendored under tests/vendor/tiny-aes)
 * as an osdp_sc_crypto_t vtable. Used in every SC test that needs a
 * working AES implementation. The vtable has no internal state, so a
 * single instance can be reused freely across tests. */
const osdp_sc_crypto_t *sc_test_crypto_tiny_aes(void);

/* Reset the deterministic PRNG used by the tiny-AES adapter's
 * rand_bytes callback. After this, the PRNG produces a fixed,
 * reproducible sequence. Tests that depend on specific RND values
 * call this in setUp. */
void sc_test_crypto_seed_prng(uint32_t seed);

/* Switch the rand_bytes callback into "fixed bytes" mode: every
 * subsequent call copies bytes from `buf` into the caller's output,
 * cycling through `buf` if the request length exceeds `len`. Used by
 * the capture-replay test to make the PD generate the exact RND.B
 * value present in a recorded session. Pass len=0 (or buf=NULL) to
 * revert to LCG mode. The buffer pointer is captured by reference so
 * it must remain valid for the life of the test. */
void sc_test_crypto_set_fixed_rand(const uint8_t *buf, size_t len);

#endif /* SC_TEST_AES_H */
