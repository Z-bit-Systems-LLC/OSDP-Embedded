// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDPCAP_H
#define OSDPCAP_H

/* OSDPCAP file format reader.
 *
 * OSDPCAP is the JSON-Lines capture format defined by SIA's
 * libosdp-conformance project (see osdpcap-format.md in
 * Security-Industry-Association/libosdp-conformance). One JSON object
 * per line, each carrying a slice of bytes observed on the wire plus
 * timing / origin metadata:
 *
 *   { "timeSec":"1580342115", "timeNano":"984691851", "io":"trace",
 *     "data":" ff ff 53 80 08 00 01 4b 01 d8",
 *     "osdpTraceVersion":"1", "osdpSource":"libosdp-conformance 0.91-5" }
 *
 * The `data` field is "bytes right off the wire" and per the spec
 * "usually but not always a whole OSDP message" — the streaming
 * decoder in osdp::core (osdp_stream_*) is the right thing to feed
 * these into; it auto-resyncs past leading 0xFF marking bytes and
 * tolerates partial frames split across records.
 *
 * This reader lives inside the host-side `osdp-parser` tool; it uses
 * stdio-friendly types and is NOT intended to be linked into the
 * embedded core. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generous upper bound on a single record's decoded byte count. The
 * OSDP packet limit is 1440 bytes; allow extra slack for FF marking
 * bytes, multiple frames concatenated into one record, etc. */
#define OSDPCAP_MAX_DATA_LEN 2048U
#define OSDPCAP_VERSION_LEN    16U
#define OSDPCAP_SOURCE_LEN    128U

typedef enum osdpcap_status {
    OSDPCAP_OK = 0,
    OSDPCAP_ERR_INVALID_ARG,
    OSDPCAP_ERR_EMPTY_LINE,        /* line had no JSON content; skip it   */
    OSDPCAP_ERR_PARSE,             /* malformed JSON-ish structure        */
    OSDPCAP_ERR_MISSING_DATA,      /* "data" field absent                 */
    OSDPCAP_ERR_BAD_HEX,           /* invalid hex character in data       */
    OSDPCAP_ERR_DATA_TOO_LARGE     /* exceeds OSDPCAP_MAX_DATA_LEN bytes  */
} osdpcap_status_t;

typedef enum osdpcap_io {
    OSDPCAP_IO_UNKNOWN = 0,
    OSDPCAP_IO_INPUT,
    OSDPCAP_IO_OUTPUT,
    OSDPCAP_IO_TRACE
} osdpcap_io_t;

typedef struct osdpcap_record {
    uint64_t      time_sec;
    uint64_t      time_nano;
    osdpcap_io_t  io;
    uint8_t       data[OSDPCAP_MAX_DATA_LEN];
    size_t        data_len;
    char          version[OSDPCAP_VERSION_LEN];
    char          source[OSDPCAP_SOURCE_LEN];
} osdpcap_record_t;

/* Parse a single OSDPCAP record from `line` (a NUL-terminated JSON-ish
 * line). Lines that contain only whitespace return OSDPCAP_ERR_EMPTY_LINE
 * so the caller can simply `continue` without treating them as failures.
 *
 * On OSDPCAP_OK, every field of `*out` is populated; the `data[]` buffer
 * holds the decoded raw bytes and `data_len` is its length. On any
 * non-OK return, `*out` is left in an undefined state — do not use. */
osdpcap_status_t osdpcap_parse_line(const char *line, osdpcap_record_t *out);

/* Static, NUL-terminated, human-readable name for a status code. */
const char *osdpcap_status_str(osdpcap_status_t s);

/* Static, NUL-terminated string ("input"/"output"/"trace"/"unknown"). */
const char *osdpcap_io_str(osdpcap_io_t io);

#ifdef __cplusplus
}
#endif

#endif /* OSDPCAP_H */
