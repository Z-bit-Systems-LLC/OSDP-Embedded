// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PAIR_H
#define OSDP_PAIR_H

#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_pair — OSDP-SC2 asymmetric device pairing.
 *
 * Pairing is a cleartext, pre-secure-channel exchange whose only output is
 * the 32-byte SC2 SCBK; after it completes, the existing SCS_21..28
 * handshake + record layer run unchanged with that key. It mirrors
 * OSDP.Net feature/osdp-sc2 (src/OSDP.Net/Pairing/) byte-for-byte and is a
 * self-contained, opt-in module (CMake target osdp::pair) — nothing in the
 * baseline codecs or the SC2 record layer depends on it.
 *
 * See docs/pairing-design.md for the full protocol, crypto, and plan. This
 * header grows across the implementation phases; this file currently
 * exposes only the Phase 0 transport layer:
 *
 *   - The fragment carrier codec for osdp_PAIR (0xB0) / osdp_PAIRR (0x8A).
 *   - A minimal, in-order multipart reassembler and its outbound
 *     fragmentation counterpart.
 *
 * Everything here is pure: no allocation, no globals, no I/O; all buffers
 * are caller-owned. */

/* ---- Provisional wire constants ----------------------------------------
 *
 * The pairing profile is experimental / NOT SIA-assigned; these values
 * mirror OSDP.Net feature/osdp-sc2 exactly and are centralized here so a
 * future spec reassignment is a one-file change. The OSDP command/reply
 * codes themselves live with the rest of the code set (OSDP_CMD_PAIR in
 * osdp_commands.h, OSDP_REPLY_PAIRR in osdp_replies.h). */

/* Reassembled-message type tags (first byte of the reassembled payload). */
#define OSDP_PAIR_MSG_TYPE_1       0x01U   /* Message 1  (ACU -> PD) */
#define OSDP_PAIR_MSG_TYPE_2       0x02U   /* Message 2  (PD -> ACU) */
#define OSDP_PAIR_MSG_TYPE_3       0x03U   /* Message 3  (ACU -> PD) */
#define OSDP_PAIR_MSG_TYPE_RESULT  0x04U   /* Result     (PD -> ACU) */

/* Default outbound fragment payload size and the session inactivity
 * timeout, both per the reference. */
#define OSDP_PAIR_DEFAULT_FRAGMENT_SIZE  128U
#define OSDP_PAIR_SESSION_TIMEOUT_MS     30000U

/* Recommended reassembly-buffer size. The largest pairing message
 * (Message 2, PD -> ACU) is ~7.7 KB; this bounds an integrator's single
 * caller-owned arena with headroom and is used as the on-wire sanity
 * ceiling by the reassembler. (Exact per-message sizes are pinned in the
 * message-codec phase.) */
#define OSDP_PAIR_MSG_MAX  8192U

/* ---- Fragment carrier ---------------------------------------------------
 *
 * Both osdp_PAIR and osdp_PAIRR carry an identical 6-byte header followed
 * by the fragment bytes (CRAUTH-style multipart, 2-byte little-endian
 * fields):
 *
 *   total_size    u16 LE   whole reassembled message length
 *   offset        u16 LE   byte offset of this fragment within the message
 *   fragmentSize  u16 LE   number of fragment bytes that follow (== frag_len)
 *   data ...               `fragmentSize` bytes
 *
 * The two directions share one codec because the layout is identical; the
 * caller supplies the OSDP framing and the 0xB0 / 0x8A code byte around the
 * DATA this codec produces/consumes. */

#define OSDP_PAIR_FRAG_HEADER_BYTES 6U

typedef struct osdp_pair_fragment {
    uint16_t       total_size;  /* whole reassembled message length (bytes) */
    uint16_t       offset;      /* byte offset of this fragment              */
    const uint8_t *data;        /* fragment bytes; NULL iff frag_len == 0    */
    size_t         frag_len;    /* fragment byte count (on-wire fragmentSize)*/
} osdp_pair_fragment_t;

/* Decode a single PAIR/PAIRR fragment payload (the command/reply DATA field,
 * i.e. everything after the 0xB0 / 0x8A code byte). Rejects a short header,
 * an on-wire fragmentSize that disagrees with the trailing byte count, and
 * a fragment that would extend past the declared total_size. `out->data`
 * points into `payload`. */
osdp_status_t osdp_pair_fragment_decode(const uint8_t *payload, size_t len,
                                        osdp_pair_fragment_t *out);

/* Build a single PAIR/PAIRR fragment payload into `buf`. Refuses an
 * inconsistent descriptor (fragment exceeding total_size, frag_len beyond a
 * u16, non-NULL/NULL data mismatch). On success writes 6 + frag_len bytes
 * and sets *written. */
osdp_status_t osdp_pair_fragment_build(const osdp_pair_fragment_t *in,
                                       uint8_t *buf, size_t buf_cap,
                                       size_t *written);

/* ---- Multipart reassembly (inbound) -------------------------------------
 *
 * Accumulates decoded fragments into a caller-owned buffer. Fragmentation
 * is sequential: a fragment at offset 0 (re)starts the message (retry-
 * friendly), and later fragments must be contiguous (no gaps). An exact
 * retransmit of an already-received span is idempotent. */

typedef struct osdp_pair_reasm {
    uint8_t *buf;       /* caller-owned reassembly buffer         */
    size_t   cap;       /* capacity of buf                        */
    uint16_t total;     /* declared message length (0 while idle) */
    uint16_t received;  /* contiguous bytes received so far       */
    bool     active;    /* a message is in progress               */
} osdp_pair_reasm_t;

/* Bind a caller-owned buffer to a reassembler and clear it. */
void osdp_pair_reasm_init(osdp_pair_reasm_t *r, uint8_t *buf, size_t cap);

/* Reset the reassembler to idle (keeps the bound buffer). */
void osdp_pair_reasm_reset(osdp_pair_reasm_t *r);

/* Feed one decoded fragment. Sets *complete = true once the whole message
 * has arrived (then `r->buf[0 .. r->total)` is the reassembled payload).
 * Returns OSDP_ERR_BUFFER_TOO_SMALL if the declared message exceeds the
 * bound buffer, OSDP_ERR_BAD_PAYLOAD on an inconsistent/out-of-order
 * fragment, OSDP_ERR_INVALID_ARG on a NULL argument. */
osdp_status_t osdp_pair_reasm_push(osdp_pair_reasm_t *r,
                                   const osdp_pair_fragment_t *frag,
                                   bool *complete);

/* ---- Multipart fragmentation (outbound) ---------------------------------
 *
 * Splits a whole message into successive fragment descriptors of at most
 * `max_frag` bytes each; each descriptor's `data` points into `msg`. */

typedef struct osdp_pair_frag_iter {
    const uint8_t *msg;
    size_t         msg_len;
    size_t         max_frag;
    size_t         offset;   /* offset of the next fragment */
} osdp_pair_frag_iter_t;

/* Initialise an iterator over `msg`. A zero `max_frag` is treated as the
 * default fragment size. */
void osdp_pair_frag_iter_init(osdp_pair_frag_iter_t *it,
                              const uint8_t *msg, size_t msg_len,
                              size_t max_frag);

/* Fill `frag` with the next fragment and advance; returns false when the
 * whole message has been emitted (or if `msg_len` is 0). */
bool osdp_pair_frag_iter_next(osdp_pair_frag_iter_t *it,
                              osdp_pair_fragment_t *frag);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PAIR_H */
