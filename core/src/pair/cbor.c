// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_cbor.h"

#include <stdint.h>
#include <string.h>

/* CBOR major types (RFC 8949 §3.1) used by pairing. */
#define CBOR_MT_UINT   0U
#define CBOR_MT_BSTR   2U
#define CBOR_MT_TSTR   3U
#define CBOR_MT_ARRAY  4U

/* ---- Writer ------------------------------------------------------------- */

void osdp_cbor_writer_init(osdp_cbor_writer_t *w, uint8_t *buf, size_t cap)
{
    if (w == NULL) {
        return;
    }
    w->buf   = buf;
    w->cap   = cap;
    w->len   = 0;
    w->error = false;
}

/* Append `n` raw bytes, tripping the sticky error on overflow. */
static void put_bytes(osdp_cbor_writer_t *w, const uint8_t *b, size_t n)
{
    if (w->error) {
        return;
    }
    if (n > w->cap - w->len) {
        w->error = true;
        return;
    }
    if (n > 0) {
        (void)memcpy(&w->buf[w->len], b, n);
        w->len += n;
    }
}

/* Emit the canonical (shortest-form) head for `major` with argument `val`. */
static void put_head(osdp_cbor_writer_t *w, uint8_t major, uint64_t val)
{
    const uint8_t mt = (uint8_t)(major << 5);
    uint8_t head[9];

    if (val < 24U) {
        head[0] = (uint8_t)(mt | (uint8_t)val);
        put_bytes(w, head, 1);
    } else if (val <= 0xFFU) {
        head[0] = (uint8_t)(mt | 24U);
        head[1] = (uint8_t)val;
        put_bytes(w, head, 2);
    } else if (val <= 0xFFFFU) {
        head[0] = (uint8_t)(mt | 25U);
        head[1] = (uint8_t)(val >> 8);
        head[2] = (uint8_t)val;
        put_bytes(w, head, 3);
    } else if (val <= 0xFFFFFFFFU) {
        head[0] = (uint8_t)(mt | 26U);
        head[1] = (uint8_t)(val >> 24);
        head[2] = (uint8_t)(val >> 16);
        head[3] = (uint8_t)(val >> 8);
        head[4] = (uint8_t)val;
        put_bytes(w, head, 5);
    } else {
        head[0] = (uint8_t)(mt | 27U);
        head[1] = (uint8_t)(val >> 56);
        head[2] = (uint8_t)(val >> 48);
        head[3] = (uint8_t)(val >> 40);
        head[4] = (uint8_t)(val >> 32);
        head[5] = (uint8_t)(val >> 24);
        head[6] = (uint8_t)(val >> 16);
        head[7] = (uint8_t)(val >> 8);
        head[8] = (uint8_t)val;
        put_bytes(w, head, 9);
    }
}

void osdp_cbor_write_uint(osdp_cbor_writer_t *w, uint64_t v)
{
    if (w == NULL) {
        return;
    }
    put_head(w, CBOR_MT_UINT, v);
}

void osdp_cbor_write_bstr(osdp_cbor_writer_t *w, const uint8_t *data, size_t n)
{
    if (w == NULL) {
        return;
    }
    put_head(w, CBOR_MT_BSTR, (uint64_t)n);
    put_bytes(w, data, n);
}

void osdp_cbor_write_tstr(osdp_cbor_writer_t *w, const char *s, size_t n)
{
    if (w == NULL) {
        return;
    }
    put_head(w, CBOR_MT_TSTR, (uint64_t)n);
    put_bytes(w, (const uint8_t *)s, n);
}

void osdp_cbor_write_array_header(osdp_cbor_writer_t *w, size_t count)
{
    if (w == NULL) {
        return;
    }
    put_head(w, CBOR_MT_ARRAY, (uint64_t)count);
}

osdp_status_t osdp_cbor_writer_finish(const osdp_cbor_writer_t *w,
                                      size_t *out_len)
{
    if (w == NULL || out_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (w->error) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    *out_len = w->len;
    return OSDP_OK;
}

/* ---- Reader ------------------------------------------------------------- */

void osdp_cbor_reader_init(osdp_cbor_reader_t *r,
                           const uint8_t *buf, size_t len)
{
    if (r == NULL) {
        return;
    }
    r->buf   = buf;
    r->len   = len;
    r->pos   = 0;
    r->error = false;
}

/* Consume one head: the major type and its integer argument. Rejects
 * indefinite-length and reserved additional-info values (28..31). */
static bool get_head(osdp_cbor_reader_t *r, uint8_t *major, uint64_t *val)
{
    if (r->error || r->pos >= r->len) {
        r->error = true;
        return false;
    }

    const uint8_t initial = r->buf[r->pos++];
    const uint8_t mt = (uint8_t)(initial >> 5);
    const uint8_t ai = (uint8_t)(initial & 0x1FU);

    size_t nbytes;
    if (ai < 24U) {
        *major = mt;
        *val   = ai;
        return true;
    } else if (ai == 24U) {
        nbytes = 1;
    } else if (ai == 25U) {
        nbytes = 2;
    } else if (ai == 26U) {
        nbytes = 4;
    } else if (ai == 27U) {
        nbytes = 8;
    } else {
        /* 28..30 reserved, 31 indefinite — unsupported. */
        r->error = true;
        return false;
    }

    if (nbytes > r->len - r->pos) {
        r->error = true;
        return false;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < nbytes; i++) {
        v = (v << 8) | (uint64_t)r->buf[r->pos++];
    }
    *major = mt;
    *val   = v;
    return true;
}

bool osdp_cbor_read_uint(osdp_cbor_reader_t *r, uint64_t *v)
{
    if (r == NULL || v == NULL) {
        if (r != NULL) {
            r->error = true;
        }
        return false;
    }
    uint8_t major;
    uint64_t val;
    if (!get_head(r, &major, &val) || major != CBOR_MT_UINT) {
        r->error = true;
        return false;
    }
    *v = val;
    return true;
}

/* Shared body for bstr/tstr: read a length head of `want` major type and
 * return a zero-copy slice. */
static bool read_string(osdp_cbor_reader_t *r, uint8_t want,
                        const uint8_t **data, size_t *n)
{
    uint8_t major;
    uint64_t len64;
    if (!get_head(r, &major, &len64) || major != want) {
        r->error = true;
        return false;
    }
    /* Guard the size_t cast on 32-bit targets and bound to the buffer. */
    if (len64 > (uint64_t)(r->len - r->pos)) {
        r->error = true;
        return false;
    }
    const size_t n_bytes = (size_t)len64;
    *data = &r->buf[r->pos];
    *n    = n_bytes;
    r->pos += n_bytes;
    return true;
}

bool osdp_cbor_read_bstr(osdp_cbor_reader_t *r,
                         const uint8_t **data, size_t *n)
{
    if (r == NULL || data == NULL || n == NULL) {
        if (r != NULL) {
            r->error = true;
        }
        return false;
    }
    return read_string(r, CBOR_MT_BSTR, data, n);
}

bool osdp_cbor_read_tstr(osdp_cbor_reader_t *r, const char **s, size_t *n)
{
    if (r == NULL || s == NULL || n == NULL) {
        if (r != NULL) {
            r->error = true;
        }
        return false;
    }
    const uint8_t *data;
    if (!read_string(r, CBOR_MT_TSTR, &data, n)) {
        return false;
    }
    *s = (const char *)data;
    return true;
}

bool osdp_cbor_read_array_header(osdp_cbor_reader_t *r, size_t *count)
{
    if (r == NULL || count == NULL) {
        if (r != NULL) {
            r->error = true;
        }
        return false;
    }
    uint8_t major;
    uint64_t val;
    if (!get_head(r, &major, &val) || major != CBOR_MT_ARRAY) {
        r->error = true;
        return false;
    }
    /* Element count must be representable as size_t; the caller drives that
     * many reads, each of which is independently bounds-checked. */
    if (val > (uint64_t)SIZE_MAX) {
        r->error = true;
        return false;
    }
    *count = (size_t)val;
    return true;
}

bool osdp_cbor_reader_done(const osdp_cbor_reader_t *r)
{
    if (r == NULL) {
        return false;
    }
    return !r->error && r->pos == r->len;
}
