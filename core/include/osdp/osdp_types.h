// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_TYPES_H
#define OSDP_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Build configuration ------------------------------------------------
 *
 * OSDP_BUFFERED_TRANSPORT — define for a transport that does NOT hand the
 * library bytes as they arrive on the wire, but batches them and delivers in
 * clumps. A USB-serial bridge is the common case (the adapter's latency timer
 * decides when a clump ships), as is OSDP-over-TCP, as is any driver whose RX
 * path is a DMA or FIFO threshold rather than a per-byte interrupt.
 *
 * Leave it undefined for a directly-attached UART. That is what the spec's
 * timing values are written for, and where a fast abort is genuinely wanted.
 *
 * It describes the wire, not the role, so it lives here rather than in
 * osdp_pd.h / osdp_acu.h and a build sets it once for both. It is a
 * whole-build switch for the same reason: a device is attached one way or the
 * other, and a build that mixed them would be describing two devices.
 *
 * Today it selects only OSDP_PD_INTERCHAR_TIMEOUT_MS (osdp_pd.h), which is
 * where the batching bites — see that comment for the measurements. Any other
 * timing that has to tolerate a delivery clump belongs behind this same flag
 * rather than a second one. */
/* #define OSDP_BUFFERED_TRANSPORT */

/* Status / error codes returned from any OSDP function that can fail.
 * OSDP_OK is the only success value; everything else is an error. */
typedef enum osdp_status {
    OSDP_OK = 0,

    /* Argument / contract violations from the caller. */
    OSDP_ERR_INVALID_ARG,        /* NULL pointer, zero-length output, etc. */
    OSDP_ERR_BUFFER_TOO_SMALL,   /* output buffer cannot hold the result   */

    /* Wire-format / decoder errors. */
    OSDP_ERR_TRUNCATED,          /* not enough bytes to decode the frame   */
    OSDP_ERR_BAD_SOM,            /* first byte was not OSDP_SOM (0x53)     */
    OSDP_ERR_BAD_LENGTH,         /* LEN field is impossible or inconsistent*/
    OSDP_ERR_BAD_CTRL,           /* CTRL byte has reserved bits set        */
    OSDP_ERR_BAD_CRC,            /* CRC-16 mismatch                        */
    OSDP_ERR_BAD_CHECKSUM,       /* 8-bit checksum mismatch                */
    OSDP_ERR_BAD_PAYLOAD,        /* payload length wrong for command/reply */

    /* Capability errors. */
    OSDP_ERR_NOT_SUPPORTED,      /* feature recognised but not implemented */

    /* Temporary refusal. Appended rather than grouped so every value above
     * keeps its number — the Rust mirror in rust/osdp/src/sys.rs pins these
     * as explicit integers.
     *
     * Returned by an application command handler that cannot answer yet:
     * the PD emits osdp_BUSY (spec 7.19) and the ACU repeats the command in
     * its original form. Distinct from an error — the command was valid and
     * will be answered on a later attempt. */
    OSDP_ERR_BUSY                /* not ready; retry the same command      */
} osdp_status_t;

#ifdef __cplusplus
}
#endif

#endif /* OSDP_TYPES_H */
