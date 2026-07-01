// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_ACU_MOCK_SC2_ADAPTER_H
#define OSDP_ACU_MOCK_SC2_ADAPTER_H

/* Wraps the shared vendored AES-256-GCM (vendor/tiny-gcm), AES-256 block
 * (vendor/tiny-aes256), and KMAC256 (vendor/tiny-kmac) as an
 * osdp_sc2_crypto_t so the ACU's Secure Channel 2 state machine has the
 * primitives it needs for a live interop test.
 *
 * The RNG uses the C stdlib rand() seeded once from time(), fine for a
 * developer interop tool but NOT for production — a real PD binds a
 * CSPRNG. acu_mock_sc2_seed_rand(seed) makes RND.B deterministic for
 * reproducible handshake debugging. */

#include "osdp/osdp_sc2_crypto.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Long-lived osdp_sc2_crypto_t suitable for osdp_pd_set_sc2_crypto(). */
const osdp_sc2_crypto_t *acu_mock_sc2_crypto(void);

/* Re-seed the stdlib rand() used by rand_bytes. Pass 0 to seed from
 * time(NULL); any other value is used verbatim. */
void acu_mock_sc2_seed_rand(uint32_t seed);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_ACU_MOCK_SC2_ADAPTER_H */
