// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PD_MOCK_AES_ADAPTER_H
#define OSDP_PD_MOCK_AES_ADAPTER_H

/* Wraps tiny-AES-c (vendored at vendor/tiny-aes/) as an
 * osdp_sc_crypto_t so the PD's Secure Channel state machine has the
 * AES-128 ECB primitive it needs. The vtable is stateless and may be
 * shared freely.
 *
 * The RNG callback uses the C stdlib rand() seeded once from time(),
 * which is fine for a developer interop tool but not for production
 * use. A real PD should bind a CSPRNG (BCryptGenRandom on Windows,
 * /dev/urandom on POSIX, hardware TRNG on MCU). Calling
 * pd_mock_aes_seed_rand(seed) before any handshake makes RND.B
 * deterministic — handy when diagnosing a failing handshake. */

#include "osdp/osdp_sc_crypto.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns a pointer to a long-lived osdp_sc_crypto_t suitable for
 * binding via osdp_pd_set_sc_crypto(). */
const osdp_sc_crypto_t *pd_mock_aes_crypto(void);

/* Re-seed the stdlib rand() used by the rand_bytes callback. Pass 0
 * to seed from time(NULL); any other value is used verbatim. Useful
 * for reproducible RND.B during interop debugging. */
void pd_mock_aes_seed_rand(uint32_t seed);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PD_MOCK_AES_ADAPTER_H */
