// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_CBOR_H
#define OSDP_CBOR_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_cbor — a minimal canonical-CBOR (RFC 8949) writer/reader.
 *
 * Just enough CBOR for OSDP-SC2 pairing: unsigned integers, byte strings,
 * text strings, and definite-length arrays. No maps, tags, negatives,
 * floats, or indefinite-length items are produced or accepted. Encoding is
 * deterministic/canonical — definite lengths and shortest-form integer
 * heads — so the same values always yield the same bytes (required: the
 * pairing transcript is hashed over exact encoded bytes, and frames must be
 * byte-identical to the OSDP.Net reference).
 *
 * Pure: no allocation, no globals, no I/O; all buffers caller-owned. Both
 * the writer and reader use a sticky error flag so a caller can emit or
 * parse a whole structure and check once at the end rather than after every
 * call. The reader returns pointers into the input buffer (zero-copy). */

/* ---- Writer ------------------------------------------------------------- */

typedef struct osdp_cbor_writer {
    uint8_t *buf;    /* caller-owned output buffer                     */
    size_t   cap;    /* capacity of buf                                */
    size_t   len;    /* bytes written so far                           */
    bool     error;  /* sticky: set on overflow (buffer exhausted)     */
} osdp_cbor_writer_t;

void osdp_cbor_writer_init(osdp_cbor_writer_t *w, uint8_t *buf, size_t cap);

/* Emit one canonical item. On overflow the writer sets its sticky error and
 * stops advancing; subsequent writes are no-ops. */
void osdp_cbor_write_uint(osdp_cbor_writer_t *w, uint64_t v);
void osdp_cbor_write_bstr(osdp_cbor_writer_t *w, const uint8_t *data, size_t n);
void osdp_cbor_write_tstr(osdp_cbor_writer_t *w, const char *s, size_t n);
void osdp_cbor_write_array_header(osdp_cbor_writer_t *w, size_t count);

/* Finalise: OSDP_OK and *out_len = bytes written if no overflow occurred,
 * else OSDP_ERR_BUFFER_TOO_SMALL. */
osdp_status_t osdp_cbor_writer_finish(const osdp_cbor_writer_t *w,
                                      size_t *out_len);

/* ---- Reader ------------------------------------------------------------- */

typedef struct osdp_cbor_reader {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;    /* next byte to consume        */
    bool           error;  /* sticky: set on any bad read */
} osdp_cbor_reader_t;

void osdp_cbor_reader_init(osdp_cbor_reader_t *r,
                           const uint8_t *buf, size_t len);

/* Each reader returns true and advances on a well-formed item of the
 * expected type, or false (and sets the sticky error) on type mismatch,
 * truncation, an unsupported/indefinite head, or a prior error. bstr/tstr
 * hand back a pointer into the input buffer. */
bool osdp_cbor_read_uint(osdp_cbor_reader_t *r, uint64_t *v);
bool osdp_cbor_read_bstr(osdp_cbor_reader_t *r,
                         const uint8_t **data, size_t *n);
bool osdp_cbor_read_tstr(osdp_cbor_reader_t *r,
                         const char **s, size_t *n);
bool osdp_cbor_read_array_header(osdp_cbor_reader_t *r, size_t *count);

/* True iff every byte was consumed with no error — a clean full parse. */
bool osdp_cbor_reader_done(const osdp_cbor_reader_t *r);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_CBOR_H */
