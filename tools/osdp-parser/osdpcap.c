// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdpcap.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ---- Tiny JSON-ish field extractor --------------------------------------
 *
 * The OSDPCAP format only carries a handful of named string fields;
 * pulling in a real JSON parser is overkill. We scan for `"name"`
 * occurrences whose immediate context is a JSON key (preceded and
 * followed by quote characters), then read the value as either a
 * quoted string or a bare token.
 */

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static const char *skip_ws(const char *p)
{
    while (*p && is_ws(*p)) {
        p++;
    }
    return p;
}

/* Find a JSON key of the form "name" inside `line`, return a pointer to
 * the byte immediately following the closing quote of the key, or NULL
 * if no such key is found. */
static const char *find_key(const char *line, const char *name)
{
    const size_t name_len = strlen(name);
    const char *p = line;
    while ((p = strstr(p, name)) != NULL) {
        const char *before = p - 1;
        const char *after  = p + name_len;
        if (p > line && *before == '"' && *after == '"') {
            return after + 1;
        }
        p++;
    }
    return NULL;
}

/* Locate the value associated with key `name`. Returns a pointer to the
 * first byte of the value (after `:` and whitespace), or NULL. */
static const char *find_value(const char *line, const char *name)
{
    const char *p = find_key(line, name);
    if (p == NULL) {
        return NULL;
    }
    p = skip_ws(p);
    if (*p != ':') {
        return NULL;
    }
    p = skip_ws(p + 1);
    return p;
}

/* Read a string value (with surrounding quotes) at `p` into `out`,
 * truncating to `out_cap - 1` bytes if necessary and always
 * NUL-terminating. Returns a pointer past the closing quote, or NULL on
 * malformed input. Backslash-escapes are passed through verbatim — the
 * OSDPCAP source strings never contain them in practice. */
static const char *read_string(const char *p, char *out, size_t out_cap)
{
    if (*p != '"') {
        return NULL;
    }
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        if (i + 1 < out_cap) {
            out[i++] = *p;
        }
        p++;
    }
    if (*p != '"') {
        return NULL;
    }
    out[(i < out_cap) ? i : out_cap - 1] = '\0';
    return p + 1;
}

/* Read either a quoted string or a bare token at `p`, decoded as
 * unsigned 64-bit integer. Returns OSDPCAP_OK on success. */
static osdpcap_status_t read_uint(const char *p, uint64_t *out)
{
    char buf[32];
    size_t i = 0;

    if (*p == '"') {
        p++;
        while (*p && *p != '"') {
            if (i + 1 < sizeof(buf)) {
                buf[i++] = *p;
            }
            p++;
        }
        if (*p != '"') {
            return OSDPCAP_ERR_PARSE;
        }
    } else {
        while (*p && !is_ws(*p) && *p != ',' && *p != '}') {
            if (i + 1 < sizeof(buf)) {
                buf[i++] = *p;
            }
            p++;
        }
    }
    buf[i] = '\0';
    if (i == 0) {
        return OSDPCAP_ERR_PARSE;
    }

    char *end = NULL;
    const unsigned long long v = strtoull(buf, &end, 10);
    if (end == buf) {
        return OSDPCAP_ERR_PARSE;
    }
    *out = (uint64_t)v;
    return OSDPCAP_OK;
}

/* ---- Hex decoder --------------------------------------------------------*/

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/* Decode a hex-with-interspersed-whitespace string into raw bytes.
 * Each byte is exactly two hex digits adjacent to each other; arbitrary
 * whitespace is allowed between bytes (including leading/trailing). */
static osdpcap_status_t decode_hex(const char *src,
                                   uint8_t *dst, size_t cap,
                                   size_t *written)
{
    *written = 0;
    const char *p = src;
    for (;;) {
        while (*p && is_ws(*p)) {
            p++;
        }
        if (!*p) {
            return OSDPCAP_OK;
        }
        const int hi = hex_digit(p[0]);
        const int lo = (hi >= 0 && p[1]) ? hex_digit(p[1]) : -1;
        if (hi < 0 || lo < 0) {
            return OSDPCAP_ERR_BAD_HEX;
        }
        if (*written >= cap) {
            return OSDPCAP_ERR_DATA_TOO_LARGE;
        }
        dst[(*written)++] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
}

/* ---- Public API ---------------------------------------------------------*/

osdpcap_status_t osdpcap_parse_line(const char *line, osdpcap_record_t *out)
{
    if (line == NULL || out == NULL) {
        return OSDPCAP_ERR_INVALID_ARG;
    }

    /* Quick reject: blank lines, or lines that contain no `{`. */
    const char *p = skip_ws(line);
    if (*p == '\0' || *p == '#') {
        return OSDPCAP_ERR_EMPTY_LINE;
    }
    if (strchr(line, '{') == NULL) {
        return OSDPCAP_ERR_EMPTY_LINE;
    }

    /* Initialise the output. */
    out->time_sec   = 0;
    out->time_nano  = 0;
    out->io         = OSDPCAP_IO_UNKNOWN;
    out->data_len   = 0;
    out->version[0] = '\0';
    out->source[0]  = '\0';

    /* Required: data. */
    const char *data_val = find_value(line, "data");
    if (data_val == NULL) {
        return OSDPCAP_ERR_MISSING_DATA;
    }
    char data_str[OSDPCAP_MAX_DATA_LEN * 3 + 16]; /* hex+spaces upper bound */
    if (read_string(data_val, data_str, sizeof(data_str)) == NULL) {
        return OSDPCAP_ERR_PARSE;
    }
    const osdpcap_status_t hex_s = decode_hex(data_str, out->data,
                                              OSDPCAP_MAX_DATA_LEN,
                                              &out->data_len);
    if (hex_s != OSDPCAP_OK) {
        return hex_s;
    }

    /* Optional metadata. */
    const char *t = find_value(line, "timeSec");
    if (t != NULL) {
        (void)read_uint(t, &out->time_sec);
    }
    t = find_value(line, "timeNano");
    if (t != NULL) {
        (void)read_uint(t, &out->time_nano);
    }

    char tmp[16];
    const char *io_val = find_value(line, "io");
    if (io_val != NULL && read_string(io_val, tmp, sizeof(tmp)) != NULL) {
        if      (strcmp(tmp, "input")  == 0) out->io = OSDPCAP_IO_INPUT;
        else if (strcmp(tmp, "output") == 0) out->io = OSDPCAP_IO_OUTPUT;
        else if (strcmp(tmp, "trace")  == 0) out->io = OSDPCAP_IO_TRACE;
        else                                  out->io = OSDPCAP_IO_UNKNOWN;
    }

    const char *ver_val = find_value(line, "osdpTraceVersion");
    if (ver_val != NULL) {
        (void)read_string(ver_val, out->version, sizeof(out->version));
    }
    const char *src_val = find_value(line, "osdpSource");
    if (src_val != NULL) {
        (void)read_string(src_val, out->source, sizeof(out->source));
    }

    return OSDPCAP_OK;
}

const char *osdpcap_status_str(osdpcap_status_t s)
{
    switch (s) {
    case OSDPCAP_OK:                 return "ok";
    case OSDPCAP_ERR_INVALID_ARG:    return "invalid argument";
    case OSDPCAP_ERR_EMPTY_LINE:     return "empty line";
    case OSDPCAP_ERR_PARSE:          return "parse error";
    case OSDPCAP_ERR_MISSING_DATA:   return "missing data field";
    case OSDPCAP_ERR_BAD_HEX:        return "bad hex digit";
    case OSDPCAP_ERR_DATA_TOO_LARGE: return "data exceeds buffer";
    }
    return "unknown";
}

const char *osdpcap_io_str(osdpcap_io_t io)
{
    switch (io) {
    case OSDPCAP_IO_INPUT:  return "input";
    case OSDPCAP_IO_OUTPUT: return "output";
    case OSDPCAP_IO_TRACE:  return "trace";
    case OSDPCAP_IO_UNKNOWN:
    default:                return "unknown";
    }
}
