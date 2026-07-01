// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef SC2_TEST_CRYPTO_H
#define SC2_TEST_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "osdp/osdp_sc2_crypto.h"

/* Adapter: presents a test-only AES-256 (tiny-AES-c compiled for
 * AES-256), a self-contained AES-256-GCM (CTR + GHASH over that block
 * cipher), and a self-contained KMAC256 as an osdp_sc2_crypto_t vtable.
 * Used by every SC2 test that needs working crypto. Stateless vtable —
 * a single instance can be reused across tests. Never linked into the
 * production core. */
const osdp_sc2_crypto_t *sc2_test_crypto(void);

/* Reset the deterministic PRNG used by the adapter's rand_bytes
 * callback so it produces a fixed, reproducible sequence. */
void sc2_test_crypto_seed_prng(uint32_t seed);

/* Switch rand_bytes into "fixed bytes" mode: subsequent calls copy from
 * `buf` (cycling if shorter than the request). Pass len=0 / buf=NULL to
 * revert to PRNG mode. The buffer is captured by reference. */
void sc2_test_crypto_set_fixed_rand(const uint8_t *buf, size_t len);

#endif /* SC2_TEST_CRYPTO_H */
