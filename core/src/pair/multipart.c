// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pair.h"

#include <stdint.h>
#include <string.h>

/* ---- Inbound reassembly ------------------------------------------------- */

void osdp_pair_reasm_init(osdp_pair_reasm_t *r, uint8_t *buf, size_t cap)
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

void osdp_pair_reasm_reset(osdp_pair_reasm_t *r)
{
    if (r == NULL) {
        return;
    }
    r->total    = 0;
    r->received = 0;
    r->active   = false;
}

osdp_status_t osdp_pair_reasm_push(osdp_pair_reasm_t *r,
                                   const osdp_pair_fragment_t *frag,
                                   bool *complete)
{
    if (r == NULL || frag == NULL || complete == NULL || r->buf == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *complete = false;

    /* A fragment at offset 0 (re)starts the message — retry-friendly. */
    if (frag->offset == 0) {
        if (frag->total_size == 0
            || frag->total_size > OSDP_PAIR_MSG_MAX) {
            return OSDP_ERR_BAD_PAYLOAD;
        }
        if ((size_t)frag->total_size > r->cap) {
            return OSDP_ERR_BUFFER_TOO_SMALL;
        }
        r->total    = frag->total_size;
        r->received = 0;
        r->active   = true;
    } else {
        /* Continuation fragments require an in-progress message whose
         * declared length matches, and must be contiguous (no gap past
         * what we've already received). An exact retransmit of an earlier
         * span (offset < received) is allowed and idempotent. */
        if (!r->active || frag->total_size != r->total) {
            return OSDP_ERR_BAD_PAYLOAD;
        }
        if (frag->offset > r->received) {
            return OSDP_ERR_BAD_PAYLOAD;
        }
    }

    /* decode already guaranteed offset + frag_len <= total_size == total,
     * and total <= cap, so this copy is in-bounds. */
    if (frag->frag_len > 0) {
        (void)memcpy(&r->buf[frag->offset], frag->data, frag->frag_len);
    }

    const uint16_t end = (uint16_t)(frag->offset + frag->frag_len);
    if (end > r->received) {
        r->received = end;
    }

    if (r->received == r->total) {
        *complete = true;
    }
    return OSDP_OK;
}

/* ---- Outbound fragmentation --------------------------------------------- */

void osdp_pair_frag_iter_init(osdp_pair_frag_iter_t *it,
                              const uint8_t *msg, size_t msg_len,
                              size_t max_frag)
{
    if (it == NULL) {
        return;
    }
    it->msg      = msg;
    it->msg_len  = msg_len;
    it->max_frag = (max_frag > 0) ? max_frag : OSDP_PAIR_DEFAULT_FRAGMENT_SIZE;
    it->offset   = 0;
}

bool osdp_pair_frag_iter_next(osdp_pair_frag_iter_t *it,
                              osdp_pair_fragment_t *frag)
{
    if (it == NULL || frag == NULL || it->msg == NULL) {
        return false;
    }
    if (it->offset >= it->msg_len) {
        return false;
    }

    size_t remaining = it->msg_len - it->offset;
    size_t this_len  = (remaining < it->max_frag) ? remaining : it->max_frag;

    frag->total_size = (uint16_t)it->msg_len;
    frag->offset     = (uint16_t)it->offset;
    frag->data       = &it->msg[it->offset];
    frag->frag_len   = this_len;

    it->offset += this_len;
    return true;
}
