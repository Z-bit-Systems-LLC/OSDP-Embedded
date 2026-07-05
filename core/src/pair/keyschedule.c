// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pair.h"

#include <string.h>

/* One HKDF-SHA256 step: Expand(Extract(salt=`th`, ikm=`ss`), info). The HAL
 * hkdf_sha256 performs extract-then-expand, so passing the same (th, ss) with
 * different info labels reproduces the shared-PRK schedule. */
static osdp_status_t derive(const osdp_pair_crypto_t *crypto,
                            const uint8_t th[OSDP_PAIR_HASH_LEN],
                            const uint8_t ss[OSDP_PAIR_SS_LEN],
                            const char *info, size_t info_len,
                            uint8_t *out, size_t out_len)
{
    return crypto->hkdf_sha256(crypto->user,
                               th, OSDP_PAIR_HASH_LEN,
                               ss, OSDP_PAIR_SS_LEN,
                               (const uint8_t *)info, info_len,
                               out, out_len);
}

osdp_status_t osdp_pair_derive_confirm_keys(
    const osdp_pair_crypto_t *crypto,
    const uint8_t             ss [OSDP_PAIR_SS_LEN],
    const uint8_t             th2[OSDP_PAIR_HASH_LEN],
    osdp_pair_confirm_keys_t *out)
{
    if (crypto == NULL || crypto->hkdf_sha256 == NULL
        || ss == NULL || th2 == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    osdp_status_t st = derive(crypto, th2, ss,
                              OSDP_PAIR_INFO_CONFIRM2,
                              sizeof(OSDP_PAIR_INFO_CONFIRM2) - 1,
                              out->km2, sizeof(out->km2));
    if (st != OSDP_OK) {
        return st;
    }
    st = derive(crypto, th2, ss,
                OSDP_PAIR_INFO_CONFIRM3, sizeof(OSDP_PAIR_INFO_CONFIRM3) - 1,
                out->km3, sizeof(out->km3));
    if (st != OSDP_OK) {
        return st;
    }
    return derive(crypto, th2, ss,
                  OSDP_PAIR_INFO_CONFIRM4, sizeof(OSDP_PAIR_INFO_CONFIRM4) - 1,
                  out->km4, sizeof(out->km4));
}

osdp_status_t osdp_pair_derive_scbk(
    const osdp_pair_crypto_t *crypto,
    const uint8_t             ss [OSDP_PAIR_SS_LEN],
    const uint8_t             th4[OSDP_PAIR_HASH_LEN],
    uint8_t                   out_scbk[OSDP_PAIR_SCBK_LEN])
{
    if (crypto == NULL || crypto->hkdf_sha256 == NULL
        || ss == NULL || th4 == NULL || out_scbk == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    return derive(crypto, th4, ss,
                  OSDP_PAIR_INFO_SCBK, sizeof(OSDP_PAIR_INFO_SCBK) - 1,
                  out_scbk, OSDP_PAIR_SCBK_LEN);
}
