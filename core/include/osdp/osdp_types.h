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
    OSDP_ERR_NOT_SUPPORTED       /* feature recognised but not implemented */
} osdp_status_t;

#ifdef __cplusplus
}
#endif

#endif /* OSDP_TYPES_H */
