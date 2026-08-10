// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_STREAM_H
#define OSDP_STREAM_H

#include "osdp/osdp_frame.h"
#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Streaming/push wrapper around osdp_frame_decode().
 *
 * Typical use (e.g. UART RX in an ISR/main-loop split):
 *
 *     static osdp_stream_t s;
 *     osdp_stream_init(&s);
 *     ...
 *     // ISR:
 *     osdp_stream_feed(&s, &byte, 1);
 *
 *     // Main loop:
 *     osdp_frame_t f;
 *     osdp_status_t r;
 *     while ((r = osdp_stream_next(&s, &f)) != OSDP_ERR_TRUNCATED) {
 *         if (r == OSDP_OK) {
 *             handle(&f);
 *         } else {
 *             // Bad frame; the stream has already resynced past it.
 *             log(r);
 *         }
 *     }
 *
 * The frame slice pointers returned by osdp_stream_next() reference the
 * stream's internal buffer. They are valid until the *next* call to
 * osdp_stream_next() or osdp_stream_feed() on the same stream — process
 * the frame fully before calling either again, or copy the bytes out.
 *
 * The stream auto-resyncs on garbage bytes by skipping forward to the
 * next SOM. It auto-skips and reports a single error on a frame that
 * fails to decode (bad CRC, bad length, etc.), so a corrupted byte in
 * the middle of a real frame loses at most one frame, not the
 * connection. */

/* Inbound reassembly capacity. Defaults to the spec 5.6 maximum (1440) so the
 * decoder can resync through any legal frame on the wire, including ones
 * addressed to other devices. Override at build time
 * (-DOSDP_STREAM_BUFFER_LEN=..., or CMake target_compile_definitions) when
 * the deployment's traffic is bounded well below that and the RAM matters —
 * this array is the single largest field in both osdp_pd_t and osdp_acu_t.
 *
 * This is wire-level buffering, distinct from what a role can process: see
 * OSDP_PD_BUF_LEN / OSDP_ACU_BUF_LEN for the message size a PD or ACU
 * actually handles and advertises to its peer. */
#ifndef OSDP_STREAM_BUFFER_LEN
#define OSDP_STREAM_BUFFER_LEN OSDP_FRAME_MAX_LEN
#endif

typedef struct osdp_stream {
    uint8_t  buffer[OSDP_STREAM_BUFFER_LEN];
    size_t   fill;             /* bytes currently buffered             */
    size_t   pending_consume;  /* bytes to drop on next next/feed call */
} osdp_stream_t;

/* Initialize a stream to empty. Required before first use. */
void osdp_stream_init(osdp_stream_t *s);

/* Drop all buffered bytes. Equivalent to re-init. */
void osdp_stream_reset(osdp_stream_t *s);

/* Append `len` bytes from `data` into the stream buffer.
 *
 * Returns OSDP_OK on success. If the incoming data would push the
 * buffered bytes past OSDP_STREAM_BUFFER_LEN, the oldest unparseable
 * bytes are silently dropped to make room — this only happens when an
 * adversarial peer claims a maximum-length frame that isn't actually
 * arriving, and is preferable to permanently wedging the decoder. */
osdp_status_t osdp_stream_feed(osdp_stream_t *s,
                               const uint8_t *data, size_t len);

/* Try to extract the next decoded frame.
 *
 *   OSDP_OK             — *out populated; valid until the next
 *                         osdp_stream_next/_feed call on this stream.
 *   OSDP_ERR_TRUNCATED  — no complete frame available yet; caller
 *                         should feed more data.
 *   OSDP_ERR_*          — the stream has consumed and resynced past a
 *                         bad frame; the error code identifies what
 *                         was wrong. Call again to extract any further
 *                         frames already buffered. */
osdp_status_t osdp_stream_next(osdp_stream_t *s, osdp_frame_t *out);

/* Bytes retained because they do not yet form a complete frame.
 *
 * Zero after osdp_stream_next has returned OSDP_ERR_TRUNCATED means the
 * decoder is idle; non-zero means a receive is in progress and the stream is
 * waiting for the rest of a frame that may never arrive.
 *
 * This exists so a caller that owns a clock can implement spec 5.8's
 * inter-character timeout, which the core cannot do for itself: it is
 * freestanding and has no notion of time. Poll this after draining
 * osdp_stream_next; if the count is non-zero and has not changed for the
 * timeout, the sender stopped mid-frame and the retained bytes are stale.
 * Call osdp_stream_reset to abort the receive sequence.
 *
 * Leaving them in place is not a harmless "wait longer": the retained bytes
 * sit in front of whatever arrives next, so the decoder counts a following
 * frame's bytes toward the abandoned frame's length, decodes across the
 * boundary and reports a CRC failure for a frame that was transmitted
 * perfectly. One lost byte then desynchronizes the link indefinitely, since
 * every retransmission meets the same misalignment. */
size_t osdp_stream_pending(const osdp_stream_t *s);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_STREAM_H */
