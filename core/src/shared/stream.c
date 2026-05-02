// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_stream.h"

#include <string.h>

/* ---- Internal helpers ---------------------------------------------------*/

static void osdp_stream_consume(osdp_stream_t *s, size_t n)
{
    if (n == 0) {
        return;
    }
    if (n >= s->fill) {
        s->fill = 0;
        return;
    }
    (void)memmove(s->buffer, s->buffer + n, s->fill - n);
    s->fill -= n;
}

/* Drop the bytes flagged by the previous successful osdp_stream_next so
 * that the just-returned frame's slice pointers are no longer aliased
 * by a fresh feed/next call. */
static void osdp_stream_apply_pending(osdp_stream_t *s)
{
    if (s->pending_consume > 0) {
        osdp_stream_consume(s, s->pending_consume);
        s->pending_consume = 0;
    }
}

/* Skip non-SOM bytes at the front. Returns the number of bytes dropped. */
static size_t osdp_stream_resync_to_som(osdp_stream_t *s)
{
    size_t i = 0;
    while (i < s->fill && s->buffer[i] != OSDP_SOM) {
        i++;
    }
    if (i > 0) {
        osdp_stream_consume(s, i);
    }
    return i;
}

/* ---- API ----------------------------------------------------------------*/

void osdp_stream_init(osdp_stream_t *s)
{
    if (s == NULL) {
        return;
    }
    s->fill = 0;
    s->pending_consume = 0;
}

void osdp_stream_reset(osdp_stream_t *s)
{
    osdp_stream_init(s);
}

osdp_status_t osdp_stream_feed(osdp_stream_t *s,
                               const uint8_t *data, size_t len)
{
    if (s == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return OSDP_OK;
    }
    if (data == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    osdp_stream_apply_pending(s);

    while (len > 0) {
        size_t free_room = OSDP_STREAM_BUFFER_LEN - s->fill;
        if (free_room == 0) {
            /* Buffer is full and we still have data to deliver. Drop
             * the oldest byte (it cannot be a valid frame start anyway
             * if the buffer didn't already yield one) and retry. */
            osdp_stream_consume(s, 1);
            free_room = OSDP_STREAM_BUFFER_LEN - s->fill;
        }
        const size_t to_copy = (len < free_room) ? len : free_room;
        (void)memcpy(s->buffer + s->fill, data, to_copy);
        s->fill += to_copy;
        data += to_copy;
        len -= to_copy;
    }
    return OSDP_OK;
}

osdp_status_t osdp_stream_next(osdp_stream_t *s, osdp_frame_t *out)
{
    if (s == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    osdp_stream_apply_pending(s);
    (void)osdp_stream_resync_to_som(s);

    if (s->fill == 0) {
        return OSDP_ERR_TRUNCATED;
    }
    if (s->fill < OSDP_FRAME_HEADER_LEN) {
        return OSDP_ERR_TRUNCATED;
    }

    const uint16_t frame_len = (uint16_t)((uint16_t)s->buffer[2] |
                                          ((uint16_t)s->buffer[3] << 8));

    if (frame_len < OSDP_FRAME_MIN_LEN_CKSUM ||
        frame_len > OSDP_FRAME_MAX_LEN) {
        /* LEN field is bogus. Drop the SOM byte and let the next call
         * resync to the next plausible SOM. */
        osdp_stream_consume(s, 1);
        return OSDP_ERR_BAD_LENGTH;
    }

    if (s->fill < frame_len) {
        return OSDP_ERR_TRUNCATED;
    }

    const osdp_status_t r = osdp_frame_decode(s->buffer, frame_len, out);
    if (r != OSDP_OK) {
        /* Frame failed to decode. Skip past the SOM so a later resync
         * doesn't re-evaluate the same bad frame. */
        osdp_stream_consume(s, 1);
        return r;
    }

    /* Frame is valid. Defer dropping its bytes from the buffer until
     * the caller next interacts with the stream — that keeps the slice
     * pointers in *out valid for the duration of the caller's
     * processing of the frame. */
    s->pending_consume = frame_len;
    return OSDP_OK;
}
