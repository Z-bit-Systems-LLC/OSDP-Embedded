// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* POSIX serial-port adapter for osdp-acu-mock. Sibling of
 * tools/osdp-pd-mock/serial_posix.c — see that file for rationale on
 * O_NONBLOCK reads and the cfmakeraw/cfsetispeed configuration. */

#include "serial.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

struct serial_ctx {
    int fd;
};

static int posix_read(void *user, uint8_t *buf, size_t cap)
{
    serial_ctx_t *ctx = (serial_ctx_t *)user;
    if (ctx == NULL || ctx->fd < 0) return 0;
    ssize_t n = read(ctx->fd, buf, cap);
    if (n < 0) return 0;
    return (int)n;
}

static int posix_write(void *user, const uint8_t *buf, size_t len)
{
    serial_ctx_t *ctx = (serial_ctx_t *)user;
    if (ctx == NULL || ctx->fd < 0) return 0;
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(ctx->fd, buf + total, len - total);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct timespec ts = { 0, 1000000 };
                (void)nanosleep(&ts, NULL);
                continue;
            }
            break;
        }
        total += (size_t)n;
    }
    return (int)total;
}

static uint32_t posix_now_ms(void *user)
{
    (void)user;
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000U +
                      (uint64_t)ts.tv_nsec / 1000000U);
}

static speed_t baud_to_speed(unsigned int baud)
{
    switch (baud) {
    case 1200:    return B1200;
    case 2400:    return B2400;
    case 4800:    return B4800;
    case 9600:    return B9600;
    case 19200:   return B19200;
    case 38400:   return B38400;
    case 57600:   return B57600;
    case 115200:  return B115200;
    case 230400:  return B230400;
    default:      return B0;
    }
}

serial_ctx_t *serial_open(const char *port_name,
                          unsigned int baud,
                          osdp_acu_transport_t *transport,
                          char *errbuf, size_t errbuf_cap)
{
    if (port_name == NULL || transport == NULL) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "internal: bad arguments");
        return NULL;
    }
    speed_t speed = baud_to_speed(baud);
    if (speed == B0) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "unsupported baud %u", baud);
        return NULL;
    }

    int fd = open(port_name, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "open('%s'): %s",
                                           port_name, strerror(errno));
        return NULL;
    }

    struct termios tio;
    if (tcgetattr(fd, &tio) != 0) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "tcgetattr: %s", strerror(errno));
        close(fd);
        return NULL;
    }
    cfmakeraw(&tio);
    cfsetispeed(&tio, speed);
    cfsetospeed(&tio, speed);
    tio.c_cflag |= (CLOCAL | CREAD);
    tio.c_cflag &= (tcflag_t)~CRTSCTS;
    tio.c_cflag &= (tcflag_t)~PARENB;
    tio.c_cflag &= (tcflag_t)~CSTOPB;
    tio.c_cflag &= (tcflag_t)~CSIZE;
    tio.c_cflag |= CS8;
    tio.c_cc[VMIN]  = 0;
    tio.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &tio) != 0) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap,
                                           "tcsetattr: %s", strerror(errno));
        close(fd);
        return NULL;
    }
    (void)tcflush(fd, TCIOFLUSH);

    serial_ctx_t *ctx = (serial_ctx_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        if (errbuf && errbuf_cap) snprintf(errbuf, errbuf_cap, "out of memory");
        close(fd);
        return NULL;
    }
    ctx->fd = fd;

    transport->read   = posix_read;
    transport->write  = posix_write;
    transport->now_ms = posix_now_ms;
    transport->user   = ctx;
    return ctx;
}

void serial_close(serial_ctx_t *ctx)
{
    if (ctx == NULL) return;
    if (ctx->fd >= 0) close(ctx->fd);
    free(ctx);
}

void serial_sleep_ms(unsigned int ms)
{
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
    (void)nanosleep(&ts, NULL);
}
