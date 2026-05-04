// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PD_MOCK_SERIAL_H
#define OSDP_PD_MOCK_SERIAL_H

/* Platform-abstracted serial-port adapter for osdp-pd-mock.
 *
 * Implementations live in serial_win.c (Win32) and serial_posix.c
 * (Linux / macOS); CMake selects exactly one based on the host OS.
 * Both fill in the same internal contract:
 *
 *   - serial_open()  — open a port at a given baud, configure 8N1,
 *                      put it into non-blocking mode (ReadFile returns
 *                      immediately on Win32 via SetCommTimeouts;
 *                      O_NONBLOCK on POSIX), and bind read/write
 *                      callbacks on the supplied osdp_pd_transport_t.
 *   - serial_close() — release the OS handle.
 *   - serial_now_ms()— monotonic millisecond clock for the PD's
 *                      online-tracking timer.
 *   - serial_sleep_ms() — caller's main-loop pacer.
 *
 * The pd transport's user pointer is set to an opaque `serial_ctx_t *`
 * the platform file owns. The osdp_pd library never sees the OS
 * handle directly. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "osdp/osdp_pd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle. Definition is platform-private. */
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
                          osdp_pd_transport_t *transport,
                          char *errbuf, size_t errbuf_cap);

/* Close and free. Safe to call with NULL. */
void serial_close(serial_ctx_t *ctx);

/* Sleep for approximately `ms` milliseconds. Used by the main loop so
 * the PD tick doesn't spin. */
void serial_sleep_ms(unsigned int ms);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PD_MOCK_SERIAL_H */
