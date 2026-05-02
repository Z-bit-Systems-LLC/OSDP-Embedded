// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* osdp-parser — CLI consumer of OSDPCAP-format captures.
 *
 * Reads JSON-Lines OSDPCAP records (from a file argument or stdin),
 * pushes the contained bytes through the streaming decoder in
 * osdp::core, classifies each emitted frame via osdp::dispatch, and
 * prints a one-line-per-record-or-frame summary. Functions as both a
 * developer tool for inspecting captures and as the first end-to-end
 * smoke test of the decoder against real-world traffic.
 *
 * Exit code: 0 if every line parsed as a valid OSDPCAP record (frame-
 * level decode errors are reported but do not change the exit status,
 * since intentionally-malformed frames are a legitimate thing to
 * capture). Non-zero if any line failed to parse as OSDPCAP. */

#include "osdp/osdp_dispatch.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_stream.h"
#include "osdp/osdp_types.h"
#include "osdpcap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_CAP 16384U

static const char *err_name(osdp_status_t s)
{
    switch (s) {
    case OSDP_OK:                   return "ok";
    case OSDP_ERR_INVALID_ARG:      return "invalid_arg";
    case OSDP_ERR_BUFFER_TOO_SMALL: return "buffer_too_small";
    case OSDP_ERR_TRUNCATED:        return "truncated";
    case OSDP_ERR_BAD_SOM:          return "bad_som";
    case OSDP_ERR_BAD_LENGTH:       return "bad_length";
    case OSDP_ERR_BAD_CTRL:         return "bad_ctrl";
    case OSDP_ERR_BAD_CRC:          return "bad_crc";
    case OSDP_ERR_BAD_CHECKSUM:     return "bad_checksum";
    case OSDP_ERR_BAD_PAYLOAD:      return "bad_payload";
    case OSDP_ERR_NOT_SUPPORTED:    return "not_supported";
    }
    return "unknown";
}

static void print_record_header(const osdpcap_record_t *r)
{
    printf("[%llu.%09llu] %-6s %3zu byte%s",
           (unsigned long long)r->time_sec,
           (unsigned long long)r->time_nano,
           osdpcap_io_str(r->io),
           r->data_len,
           r->data_len == 1 ? " " : "s");
    /* Print the wire bytes inline for short records, omit for long. */
    if (r->data_len > 0 && r->data_len <= 32) {
        printf("  ");
        for (size_t i = 0; i < r->data_len; i++) {
            printf("%02x ", r->data[i]);
        }
    }
    printf("\n");
}

static void print_frame(const osdp_frame_t *f)
{
    const osdp_message_kind_t kind = osdp_dispatch_classify(f);
    printf("    %s  addr=0x%02x  seq=%u  %s  code=0x%02x  %s",
           f->reply ? "PD->ACU" : "ACU->PD",
           f->address,
           (unsigned)f->sequence,
           f->integrity == OSDP_INTEGRITY_CRC ? "crc  " : "cksum",
           f->code,
           osdp_dispatch_name(kind));
    if (f->payload_len > 0) {
        printf("  payload=%zu", f->payload_len);
    }
    if (f->has_scb) {
        printf("  scb_type=0x%02x", f->scb_type);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    FILE *in = stdin;
    if (argc > 2) {
        fprintf(stderr, "usage: %s [capture.osdpcap]\n", argv[0]);
        return 2;
    }
    if (argc == 2) {
        in = fopen(argv[1], "r");
        if (in == NULL) {
            fprintf(stderr, "%s: cannot open '%s'\n", argv[0], argv[1]);
            return 2;
        }
    }

    osdp_stream_t stream;
    osdp_stream_init(&stream);

    char line[LINE_CAP];
    unsigned long records = 0;
    unsigned long frames  = 0;
    unsigned long parse_errors = 0;
    unsigned long decode_errors = 0;

    while (fgets(line, sizeof(line), in) != NULL) {
        osdpcap_record_t rec;
        const osdpcap_status_t s = osdpcap_parse_line(line, &rec);
        if (s == OSDPCAP_ERR_EMPTY_LINE) {
            continue;
        }
        if (s != OSDPCAP_OK) {
            fprintf(stderr, "parse error: %s\n", osdpcap_status_str(s));
            parse_errors++;
            continue;
        }
        records++;
        print_record_header(&rec);

        const osdp_status_t fs = osdp_stream_feed(&stream, rec.data,
                                                  rec.data_len);
        if (fs != OSDP_OK) {
            fprintf(stderr, "  ! feed error: %s\n", err_name(fs));
            continue;
        }

        for (;;) {
            osdp_frame_t f;
            const osdp_status_t r = osdp_stream_next(&stream, &f);
            if (r == OSDP_OK) {
                print_frame(&f);
                frames++;
            } else if (r == OSDP_ERR_TRUNCATED) {
                break;
            } else {
                printf("    ! decode error: %s\n", err_name(r));
                decode_errors++;
            }
        }
    }

    if (in != stdin) {
        (void)fclose(in);
    }

    fprintf(stderr,
            "\nSummary: %lu records, %lu frames, %lu decode errors, "
            "%lu parse errors\n",
            records, frames, decode_errors, parse_errors);
    return (parse_errors == 0) ? 0 : 1;
}
