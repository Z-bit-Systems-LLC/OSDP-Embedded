// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Integration test: feed every record of a real OSDPCAP capture through
 * the streaming decoder and assert the parser stays in well-defined
 * states. The capture path is supplied as argv[1] so a single test
 * executable can be reused for any number of capture files via CTest's
 * `add_test(NAME ... COMMAND ... <path>)` mechanism. */

#include "osdp/osdp_dispatch.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_stream.h"
#include "osdp/osdp_types.h"
#include "osdpcap.h"
#include "unity.h"

#include <stdio.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static const char *g_capture_path = NULL;

/* Walk the capture file and verify that:
 *  - Every line either parses as a valid OSDPCAP record, or is empty
 *    (whitespace / comment).
 *  - The streaming decoder accepts every byte without an INVALID_ARG
 *    return (which would indicate we mis-fed it).
 *  - Frame-level decode errors (bad CRC, bad length, etc) are
 *    permitted: real captures legitimately contain malformed bytes
 *    (e.g. line-idle 0xFF runs, partial frames split across records,
 *    deliberately corrupt test traffic). The test reports the counts
 *    via stderr but does not fail on them. */
static void test_capture_file_can_be_consumed(void)
{
    TEST_ASSERT_NOT_NULL_MESSAGE(g_capture_path,
                                 "capture path missing — pass as argv[1]");

    FILE *f = fopen(g_capture_path, "r");
    TEST_ASSERT_NOT_NULL_MESSAGE(f, "could not open capture file");

    osdp_stream_t stream;
    osdp_stream_init(&stream);

    char line[16384];
    unsigned long parse_errors = 0;
    unsigned long records      = 0;
    unsigned long frames       = 0;
    unsigned long decode_errs  = 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        osdpcap_record_t rec;
        const osdpcap_status_t s = osdpcap_parse_line(line, &rec);
        if (s == OSDPCAP_ERR_EMPTY_LINE) {
            continue;
        }
        if (s != OSDPCAP_OK) {
            fprintf(stderr, "  parse error on line: %s\n",
                    osdpcap_status_str(s));
            parse_errors++;
            continue;
        }
        records++;

        const osdp_status_t fs = osdp_stream_feed(&stream, rec.data,
                                                  rec.data_len);
        TEST_ASSERT_EQUAL_MESSAGE(OSDP_OK, fs,
            "stream rejected well-formed bytes");

        for (;;) {
            osdp_frame_t fr;
            const osdp_status_t r = osdp_stream_next(&stream, &fr);
            if (r == OSDP_OK) {
                frames++;
                /* Sanity: the classifier must always return SOMETHING. */
                const osdp_message_kind_t k = osdp_dispatch_classify(&fr);
                TEST_ASSERT_NOT_NULL(osdp_dispatch_name(k));
            } else if (r == OSDP_ERR_TRUNCATED) {
                break;
            } else {
                decode_errs++;
            }
        }
    }
    (void)fclose(f);

    fprintf(stderr,
            "\n  capture summary: %lu records, %lu frames, %lu decode "
            "errors, %lu parse errors\n",
            records, frames, decode_errs, parse_errors);

    /* The hard requirement: every non-blank line was a valid OSDPCAP
     * record. Frame-level decode errors are permitted. */
    TEST_ASSERT_EQUAL_UINT(0, parse_errors);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <capture.osdpcap>\n", argv[0]);
        return 2;
    }
    g_capture_path = argv[1];

    UNITY_BEGIN();
    RUN_TEST(test_capture_file_can_be_consumed);
    return UNITY_END();
}
