// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_MULTIPART_H
#define OSDP_MULTIPART_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Multi-part message transport — spec 5.10.
 *
 * Some messages carry more data than one OSDP frame can hold, so they define
 * a fragment header and are sent as a sequence. The header is the same six
 * bytes everywhere it appears (Table 4):
 *
 *     0..1  MpSizeTotal     total bytes across all fragments  (u16 LE)
 *     2..3  MpOffset        byte offset of this fragment      (u16 LE)
 *     4..5  MpFragmentSize  bytes of data in this fragment    (u16 LE)
 *     6..   the fragment data
 *
 * This module owns that header and the sequencing rules, nothing else: the
 * caller supplies the OSDP framing and the message code around it. Which
 * messages use it is the messages' business — in v2.2 that is osdp_PIVDATAR
 * (7.20), osdp_GENAUTHR (7.21), osdp_CRAUTHR, and the transparent-mode
 * osdp_XWR / osdp_XRD, plus the SC2 pairing exchange, which is the only
 * current consumer and where this code was originally written.
 *
 * Reassembly is caller-owned: bind a buffer, push decoded fragments, and the
 * whole message appears in that buffer. No allocation. */

#define OSDP_MP_HEADER_BYTES 6U

/* One fragment, decoded. `data` points into the payload it was decoded from
 * and is valid only as long as that buffer is. */
typedef struct osdp_mp_fragment {
    uint16_t       total_size;  /* whole reassembled message length (bytes) */
    uint16_t       offset;      /* byte offset of this fragment             */
    const uint8_t *data;        /* fragment bytes; NULL iff frag_len == 0   */
    size_t         frag_len;    /* fragment byte count (MpFragmentSize)     */
} osdp_mp_fragment_t;

/* True when this fragment is the sender's early-termination marker: spec
 * 5.10.2 lets a sender abandon a transfer by setting MpOffset at or past
 * MpSizeTotal with MpFragmentSize zero, and requires the receiver to
 * recognise it. Distinct from a completed transfer — the message is
 * incomplete and must be discarded, not processed.
 *
 * MpSizeTotal of zero does NOT count: a transfer declaring no bytes has
 * nothing to terminate, and an all-zero header is what a truncated or
 * mis-parsed frame usually looks like. */
bool osdp_mp_is_early_termination(const osdp_mp_fragment_t *f);

/* Decode a fragment payload (everything after the message code byte).
 *
 * Rejects a short header, and an on-wire MpFragmentSize that disagrees with
 * the number of bytes actually present — that mismatch is the one a
 * truncated frame produces, and accepting it would reassemble silent
 * garbage. A fragment extending past MpSizeTotal is rejected too, EXCEPT the
 * early-termination marker above, which is legal precisely because its
 * offset is at or beyond the total. */
osdp_status_t osdp_mp_fragment_decode(const uint8_t *payload, size_t len,
                                      osdp_mp_fragment_t *out);

/* Build a fragment payload into `buf`. Refuses an inconsistent descriptor:
 * frag_len beyond a u16, a data/length mismatch, or a fragment overrunning
 * its own declared message (again excepting the early-termination marker).
 * Writes OSDP_MP_HEADER_BYTES + frag_len bytes. */
osdp_status_t osdp_mp_fragment_build(const osdp_mp_fragment_t *in,
                                     uint8_t *buf, size_t buf_cap,
                                     size_t *written);

/* ---- Inbound reassembly ------------------------------------------------ */

/* What a pushed fragment did to the transfer. */
typedef enum osdp_mp_state {
    OSDP_MP_IN_PROGRESS = 0,  /* more fragments expected                   */
    OSDP_MP_COMPLETE,         /* whole message is in the bound buffer      */
    OSDP_MP_TERMINATED        /* sender abandoned it; discard what arrived */
} osdp_mp_state_t;

typedef struct osdp_mp_reasm {
    uint8_t *buf;       /* caller-owned reassembly buffer         */
    size_t   cap;       /* capacity of buf                        */
    uint16_t total;     /* declared message length (0 while idle) */
    uint16_t received;  /* contiguous bytes received so far       */
    bool     active;    /* a message is in progress               */
} osdp_mp_reasm_t;

/* Bind a caller-owned buffer and clear the reassembler. The buffer must
 * outlive it and hold the largest message expected — a transfer declaring
 * more than `cap` is refused rather than truncated. */
void osdp_mp_reasm_init(osdp_mp_reasm_t *r, uint8_t *buf, size_t cap);

/* Return to idle, keeping the bound buffer. Call after consuming a completed
 * message, on an early termination, and on any error — an abandoned transfer
 * left active would corrupt the next one. */
void osdp_mp_reasm_reset(osdp_mp_reasm_t *r);

/* Feed one decoded fragment; `*state` reports what it did.
 *
 * Sequencing follows spec 5.10.2: fragments arrive in order with no gaps,
 * and the first has MpOffset 0. A fragment at offset 0 (re)starts the
 * transfer, which makes a retry after a lost reply idempotent rather than a
 * protocol violation. Re-sending a span already received is likewise
 * idempotent. An early-termination marker resets the reassembler and reports
 * OSDP_MP_TERMINATED.
 *
 * On OSDP_MP_COMPLETE the message is `r->buf[0 .. r->total)`.
 *
 * Returns OSDP_ERR_BUFFER_TOO_SMALL when the declared message exceeds the
 * bound buffer, OSDP_ERR_BAD_PAYLOAD on a gap, a changed total, or a
 * continuation with no transfer in progress, and OSDP_ERR_INVALID_ARG for a
 * NULL argument or an unbound reassembler. A receiver answers any of these
 * with osdp_NAK 0x09, which spec 5.10.2 says aborts the sender's sequence. */
osdp_status_t osdp_mp_reasm_push(osdp_mp_reasm_t *r,
                                 const osdp_mp_fragment_t *frag,
                                 osdp_mp_state_t *state);

/* ---- Outbound fragmentation -------------------------------------------- */

/* Splits a whole message into successive fragment descriptors of at most
 * `max_frag` bytes; each descriptor's `data` points into the original
 * message, so nothing is copied and the message must outlive the iterator. */
typedef struct osdp_mp_frag_iter {
    const uint8_t *msg;
    size_t         msg_len;
    size_t         max_frag;
    size_t         offset;   /* offset of the next fragment */
} osdp_mp_frag_iter_t;

/* Default fragment payload size when a caller has no better figure. Modest
 * on purpose: a sender that knows the receiver's capacity (PDCAP function
 * code 10, or osdp_ACURXSIZE in the other direction) should pass it. */
#define OSDP_MP_DEFAULT_FRAGMENT_SIZE 128U

void osdp_mp_frag_iter_init(osdp_mp_frag_iter_t *it,
                            const uint8_t *msg, size_t msg_len,
                            size_t max_frag);

/* Fill `*frag` with the next fragment and advance. Returns false once the
 * message is exhausted. */
bool osdp_mp_frag_iter_next(osdp_mp_frag_iter_t *it,
                            osdp_mp_fragment_t *frag);

/* Fill `*frag` with the early-termination marker for a message of
 * `msg_len` bytes (spec 5.10.2), so a sender abandoning a transfer does not
 * have to hand-assemble the sentinel. */
void osdp_mp_frag_terminate(osdp_mp_fragment_t *frag, size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_MULTIPART_H */
