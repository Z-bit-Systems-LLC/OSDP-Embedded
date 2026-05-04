// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Win32 serial-port adapter for osdp-pd-mock.
 *
 * Uses the classic "polling" timeout configuration so ReadFile() never
 * blocks: ReadIntervalTimeout = MAXDWORD with both totals zeroed
 * causes ReadFile to return immediately with whatever bytes were
 * already in the driver's queue (zero is a valid result). That matches
 * the osdp_pd_transport_t contract (read returns 0 on idle, never
 * negative).
 *
 * For COM ports beyond COM9, callers should pass "\\\\.\\COM23" — the
 * UNC-prefixed form that Win32 requires for two-digit COMs. We accept
 * either form; the user's CLI value is forwarded verbatim. */

#include "serial.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

struct serial_ctx {
    HANDLE handle;
};

/* ---- Transport callbacks --------------------------------------------- */

static int win_read(void *user, uint8_t *buf, size_t cap)
{
    serial_ctx_t *ctx = (serial_ctx_t *)user;
    if (ctx == NULL || ctx->handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    DWORD got = 0;
    /* SetCommTimeouts has been configured so this returns immediately
     * with whatever's available (0 if nothing). */
    if (!ReadFile(ctx->handle, buf, (DWORD)cap, &got, NULL)) {
        return 0;
    }
    return (int)got;
}

static int win_write(void *user, const uint8_t *buf, size_t len)
{
    serial_ctx_t *ctx = (serial_ctx_t *)user;
    if (ctx == NULL || ctx->handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    DWORD written = 0;
    if (!WriteFile(ctx->handle, buf, (DWORD)len, &written, NULL)) {
        return 0;
    }
    return (int)written;
}

static uint32_t win_now_ms(void *user)
{
    (void)user;
    /* GetTickCount64 is monotonic on Win32 and unaffected by the
     * system clock. Cast to 32-bit; the PD's wraparound handling uses
     * unsigned subtraction. */
    return (uint32_t)GetTickCount64();
}

/* ---- Public API ------------------------------------------------------ */

serial_ctx_t *serial_open(const char *port_name,
                          unsigned int baud,
                          osdp_pd_transport_t *transport,
                          char *errbuf, size_t errbuf_cap)
{
    if (port_name == NULL || transport == NULL) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "internal: bad arguments");
        return NULL;
    }

    HANDLE h = CreateFileA(port_name,
                           GENERIC_READ | GENERIC_WRITE,
                           0,             /* exclusive               */
                           NULL,
                           OPEN_EXISTING,
                           0,             /* synchronous handle      */
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        if (errbuf && errbuf_cap) {
            snprintf(errbuf, errbuf_cap,
                     "CreateFile('%s') failed: %lu",
                     port_name, (unsigned long)GetLastError());
        }
        return NULL;
    }

    DCB dcb;
    (void)memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(h, &dcb)) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "GetCommState: %lu",
                                           (unsigned long)GetLastError());
        CloseHandle(h);
        return NULL;
    }
    dcb.BaudRate    = baud;
    dcb.ByteSize    = 8;
    dcb.Parity      = NOPARITY;
    dcb.StopBits    = ONESTOPBIT;
    dcb.fBinary     = TRUE;
    dcb.fParity     = FALSE;
    dcb.fOutxCtsFlow= FALSE;
    dcb.fOutxDsrFlow= FALSE;
    dcb.fDtrControl = DTR_CONTROL_DISABLE;
    dcb.fRtsControl = RTS_CONTROL_DISABLE;
    if (!SetCommState(h, &dcb)) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "SetCommState: %lu",
                                           (unsigned long)GetLastError());
        CloseHandle(h);
        return NULL;
    }

    /* Polling-mode timeouts: ReadFile returns immediately. */
    COMMTIMEOUTS to;
    (void)memset(&to, 0, sizeof(to));
    to.ReadIntervalTimeout         = MAXDWORD;
    to.ReadTotalTimeoutMultiplier  = 0;
    to.ReadTotalTimeoutConstant    = 0;
    to.WriteTotalTimeoutMultiplier = 0;
    to.WriteTotalTimeoutConstant   = 100;
    if (!SetCommTimeouts(h, &to)) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "SetCommTimeouts: %lu",
                                           (unsigned long)GetLastError());
        CloseHandle(h);
        return NULL;
    }
    (void)PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);

    serial_ctx_t *ctx = (serial_ctx_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "out of memory");
        CloseHandle(h);
        return NULL;
    }
    ctx->handle = h;

    transport->read   = win_read;
    transport->write  = win_write;
    transport->now_ms = win_now_ms;
    transport->user   = ctx;
    return ctx;
}

void serial_close(serial_ctx_t *ctx)
{
    if (ctx == NULL) return;
    if (ctx->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->handle);
    }
    free(ctx);
}

void serial_sleep_ms(unsigned int ms)
{
    Sleep((DWORD)ms);
}
