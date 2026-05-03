// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef SC_TEST_AES_H
#define SC_TEST_AES_H

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

#endif /* SC_TEST_AES_H */
