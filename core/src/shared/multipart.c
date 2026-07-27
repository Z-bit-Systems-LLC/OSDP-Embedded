// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Multi-part message transport (spec 5.10).
 *
 * Lifted from core/src/pair/, which needed exactly this and got there first:
 * the SC2 pairing exchange sends certificates and key material that do not
 * fit one frame, and its fragment header turned out to be byte-identical to
 * the spec's Table 4 rather than merely similar. Rather than keep a second
 * copy for the credential messages that will need it (osdp_PIVDATAR 7.20,
 * osdp_GENAUTHR 7.21, osdp_CRAUTHR, transparent-mode osdp_XWR / osdp_XRD),
 * the pairing code now uses this one.
 *
 * What is new here beyond the pairing version is the 5.10.2 early-
 * termination rule, which pairing never needed because its message sizes are
 * known up front. */

#include "osdp/osdp_multipart.h"

#include "shared/pack.h"

#include <stdint.h>
#include <string.h>

/* ---- Fragment codec ----------------------------------------------------- */

bool osdp_mp_is_early_termination(const osdp_mp_fragment_t *f)
{
    /* Spec 5.10.2: "terminated by the sender early by setting MpOffset to
     * equal or greater than MpSizeTotal and setting MpFragmentSize to 0x00."
     * Both halves are required — an offset past the end WITH data is a
     * malformed fragment, not a termination.
     *
     * MpSizeTotal must also be non-zero. Read literally, an all-zero header
     * satisfies "offset >= total" and would count as a termination, but a
     * transfer declaring no bytes has nothing to terminate; treating it as a
     * valid marker would turn an all-zeros payload — the shape a truncated or
     * mis-parsed frame most often takes — into a silent ACK instead of the
     * NAK 0x09 it deserves. */
    return f != NULL && f->frag_len == 0 &&
           f->total_size > 0 && f->offset >= f->total_size;
}

osdp_status_t osdp_mp_fragment_decode(const uint8_t *payload, size_t len,
                                      osdp_mp_fragment_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (payload == NULL || len < OSDP_MP_HEADER_BYTES) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    const uint16_t total_size = osdp_pack_read_u16le(&payload[0]);
    const uint16_t offset     = osdp_pack_read_u16le(&payload[2]);
    const uint16_t frag_size  = osdp_pack_read_u16le(&payload[4]);

    /* MpFragmentSize must match the bytes actually present. This is the
     * check a truncated frame fails, and accepting a mismatch would
     * reassemble whatever happened to follow in the buffer. */
    const size_t data_len = len - OSDP_MP_HEADER_BYTES;
    if ((size_t)frag_size != data_len) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    out->total_size = total_size;
    out->offset     = offset;
    out->data       = (data_len > 0) ? &payload[OSDP_MP_HEADER_BYTES] : NULL;
    out->frag_len   = data_len;

    /* The early-termination marker is deliberately checked before the
     * bounds rule below, because being at or past the end is exactly what
     * makes it a termination rather than an overrun. */
    if (osdp_mp_is_early_termination(out)) {
        return OSDP_OK;
    }

    /* A fragment must not extend past the declared message. Computed in
     * 32-bit space; both operands are u16 so it cannot overflow. */
    if ((uint32_t)offset + (uint32_t)frag_size > (uint32_t)total_size) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return OSDP_OK;
}

osdp_status_t osdp_mp_fragment_build(const osdp_mp_fragment_t *in,
                                     uint8_t *buf, size_t buf_cap,
                                     size_t *written)
{
    if (in == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;

    /* MpFragmentSize is a single u16 on the wire. */
    if (in->frag_len > (size_t)UINT16_MAX) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (in->frag_len > 0 && in->data == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    /* Refuse a fragment that overruns its own declared message — unless it
     * is the early-termination marker, whose whole point is to sit at or
     * past the end. */
    if (!osdp_mp_is_early_termination(in) &&
        (uint32_t)in->offset + (uint32_t)in->frag_len
            > (uint32_t)in->total_size) {
        return OSDP_ERR_INVALID_ARG;
    }

    const size_t total = OSDP_MP_HEADER_BYTES + in->frag_len;
    if (buf_cap < total) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    osdp_pack_write_u16le(&buf[0], in->total_size);
    osdp_pack_write_u16le(&buf[2], in->offset);
    osdp_pack_write_u16le(&buf[4], (uint16_t)in->frag_len);
    if (in->frag_len > 0) {
        (void)memcpy(&buf[OSDP_MP_HEADER_BYTES], in->data, in->frag_len);
    }
    *written = total;
    return OSDP_OK;
}

/* ---- Inbound reassembly ------------------------------------------------- */

void osdp_mp_reasm_init(osdp_mp_reasm_t *r, uint8_t *buf, size_t cap)
{
    if (r == NULL) {
        return;
    }
    r->buf      = buf;
    r->cap      = cap;
    r->total    = 0;
    r->received = 0;
    r->active   = false;
}

void osdp_mp_reasm_reset(osdp_mp_reasm_t *r)
{
    if (r == NULL) {
        return;
    }
    r->total    = 0;
    r->received = 0;
    r->active   = false;
}

osdp_status_t osdp_mp_reasm_push(osdp_mp_reasm_t *r,
                                 const osdp_mp_fragment_t *frag,
                                 osdp_mp_state_t *state)
{
    if (r == NULL || frag == NULL || state == NULL || r->buf == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *state = OSDP_MP_IN_PROGRESS;

    /* Early termination first: the sender has abandoned the transfer, so
     * whatever arrived is incomplete and must not be handed on. Resetting
     * here is what keeps the next transfer clean. */
    if (osdp_mp_is_early_termination(frag)) {
        osdp_mp_reasm_reset(r);
        *state = OSDP_MP_TERMINATED;
        return OSDP_OK;
    }

    if (frag->offset == 0) {
        /* Offset 0 (re)starts the message. Restarting rather than rejecting
         * makes a retry after a lost reply idempotent — the sender has no
         * way to know we got the first fragment. */
        if (frag->total_size == 0) {
            return OSDP_ERR_BAD_PAYLOAD;
        }
        if ((size_t)frag->total_size > r->cap) {
            return OSDP_ERR_BUFFER_TOO_SMALL;
        }
        r->total    = frag->total_size;
        r->received = 0;
        r->active   = true;
    } else {
        /* Continuations need a transfer in progress whose declared length
         * agrees, and must not skip ahead of what we hold — spec 5.10.2
         * requires sequential order with no gaps. Re-sending an already
         * received span (offset < received) is allowed and idempotent. */
        if (!r->active || frag->total_size != r->total) {
            return OSDP_ERR_BAD_PAYLOAD;
        }
        if (frag->offset > r->received) {
            return OSDP_ERR_BAD_PAYLOAD;
        }
    }

    /* decode guaranteed offset + frag_len <= total_size == total, and
     * total <= cap, so this copy is in bounds. */
    if (frag->frag_len > 0) {
        (void)memcpy(&r->buf[frag->offset], frag->data, frag->frag_len);
    }

    const uint16_t end = (uint16_t)(frag->offset + frag->frag_len);
    if (end > r->received) {
        r->received = end;
    }
    if (r->received == r->total) {
        *state = OSDP_MP_COMPLETE;
    }
    return OSDP_OK;
}

/* ---- Outbound fragmentation --------------------------------------------- */

void osdp_mp_frag_iter_init(osdp_mp_frag_iter_t *it,
                            const uint8_t *msg, size_t msg_len,
                            size_t max_frag)
{
    if (it == NULL) {
        return;
    }
    it->msg      = msg;
    it->msg_len  = msg_len;
    it->max_frag = (max_frag > 0) ? max_frag : OSDP_MP_DEFAULT_FRAGMENT_SIZE;
    it->offset   = 0;
}

bool osdp_mp_frag_iter_next(osdp_mp_frag_iter_t *it,
                            osdp_mp_fragment_t *frag)
{
    if (it == NULL || frag == NULL || it->msg == NULL) {
        return false;
    }
    if (it->offset >= it->msg_len) {
        return false;
    }

    const size_t remaining = it->msg_len - it->offset;
    const size_t this_len  = (remaining < it->max_frag) ? remaining
                                                        : it->max_frag;

    frag->total_size = (uint16_t)it->msg_len;
    frag->offset     = (uint16_t)it->offset;
    frag->data       = &it->msg[it->offset];
    frag->frag_len   = this_len;

    it->offset += this_len;
    return true;
}

void osdp_mp_frag_terminate(osdp_mp_fragment_t *frag, size_t msg_len)
{
    if (frag == NULL) {
        return;
    }
    frag->total_size = (uint16_t)msg_len;
    frag->offset     = (uint16_t)msg_len;  /* == total, so "at or past" */
    frag->data       = NULL;
    frag->frag_len   = 0;
}
