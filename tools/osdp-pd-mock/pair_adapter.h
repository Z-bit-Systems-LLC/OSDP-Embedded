// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PD_MOCK_PAIR_ADAPTER_H
#define OSDP_PD_MOCK_PAIR_ADAPTER_H

/* Binds SC2 asymmetric pairing for osdp-pd-mock: an OS CSPRNG into the
 * PQClean port, and the generated demo credential into a pairing driver.
 *
 * The credential is produced at build time by osdp-pair-provision, so this
 * tool ships no key material of its own. It is demonstration material — the
 * trust anchor is the published OSDP.Net demo CA — which is what makes
 * interop testing possible and what makes it unfit for a real device. */

#include "osdp/osdp_pd_pair.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Install an OS-backed CSPRNG as the PQClean port's entropy source, init the
 * pairing state with the generated credential and demo-CA trust anchor, and
 * attach it to `pd`.
 *
 * `pair` is caller-owned and large (~14 KB of message buffers); give it
 * static storage. `pd` must already have its SC2 crypto vtable and cUID set,
 * since pairing's whole output is the SCBK that channel will use.
 *
 * Returns false if entropy is unavailable — pairing without a CSPRNG would
 * derive a predictable key, so it is refused rather than downgraded. */
bool pd_mock_pair_attach(osdp_pd_t *pd, osdp_pd_pair_t *pair);

/* Subject identity of the built-in credential, for logging. */
const char *pd_mock_pair_subject(void);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PD_MOCK_PAIR_ADAPTER_H */
