// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_ACU_MOCK_SERIAL_H
#define OSDP_ACU_MOCK_SERIAL_H

/* Platform-abstracted serial-port adapter for osdp-acu-mock.
 *
 * Mirror of tools/osdp-pd-mock/serial.h, retargeted at
 * osdp_acu_transport_t. The PD-mock and ACU-mock copies are nearly
 * line-for-line identical; the OSDP transport types share the same
 * callback signatures, so a future refactor can lift these into a
 * shared `tools/lib-serial/` library if the duplication starts to
 * hurt. For now they're kept side-by-side so the two tools stay
 * independently buildable. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "osdp/osdp_acu.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct serial_ctx serial_ctx_t;

/* Open the named port at the requested baud (e.g. 9600, 115200) and
 * fill in `transport->read`, `->write`, `->now_ms`, and `->user`. On
 * success returns a non-NULL `serial_ctx_t *` the caller passes to
 * serial_close() at the end. On failure returns NULL and writes a
 * human-readable error to `errbuf` (NUL-terminated, never overflows).
 *
 *   port_name examples:
 *     Windows: "COM3" or "\\\\.\\COM23" (the latter for COM10+)
 *     POSIX:   "/dev/ttyUSB0", "/dev/tty.usbserial-A1234"
 */
serial_ctx_t *serial_open(const char *port_name,
                          unsigned int baud,
                          osdp_acu_transport_t *transport,
                          char *errbuf, size_t errbuf_cap);

void serial_close(serial_ctx_t *ctx);
void serial_sleep_ms(unsigned int ms);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_ACU_MOCK_SERIAL_H */
