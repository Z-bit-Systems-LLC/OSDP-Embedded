// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_ACU_MOCK_AES_ADAPTER_H
#define OSDP_ACU_MOCK_AES_ADAPTER_H

/* tiny-AES-c → osdp_sc_crypto_t adapter for osdp-acu-mock. Sibling of
 * tools/osdp-pd-mock/aes_adapter.h; the implementation is byte-for-
 * byte identical except for the public symbol names. The RNG is the
 * stdlib rand() seeded from time() — fine for an interop tool, NOT
 * for production. */

#include "osdp/osdp_sc_crypto.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const osdp_sc_crypto_t *acu_mock_aes_crypto(void);
void acu_mock_aes_seed_rand(uint32_t seed);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_ACU_MOCK_AES_ADAPTER_H */
