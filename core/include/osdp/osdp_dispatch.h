// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_DISPATCH_H
#define OSDP_DISPATCH_H

#include "osdp/osdp_frame.h"
#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Identifier for every OSDP message type recognised by this library.
 * Iteration 1 implements typed decoders only for the baseline subset;
 * the remaining values are still reported by the classifier so a
 * Monitor application can display a human-readable name for any frame.
 *
 * The two UNKNOWN_* values are used when the code byte is not one of
 * those listed in spec Annex A.1 / A.2. The classifier disambiguates
 * commands from replies by inspecting the frame's reply flag, so the
 * 0x53 collision (osdp_KEYPAD reply vs SOM marker) and the 0x76
 * collision (osdp_CHLNG command vs osdp_CCRYPT reply) resolve
 * correctly. */
typedef enum osdp_message_kind {
    OSDP_MSG_UNKNOWN_COMMAND = 0,
    OSDP_MSG_UNKNOWN_REPLY,

    /* Commands (ACU → PD) */
    OSDP_MSG_CMD_POLL,
    OSDP_MSG_CMD_ID,
    OSDP_MSG_CMD_CAP,
    OSDP_MSG_CMD_LSTAT,
    OSDP_MSG_CMD_ISTAT,
    OSDP_MSG_CMD_OSTAT,
    OSDP_MSG_CMD_RSTAT,
    OSDP_MSG_CMD_OUT,
    OSDP_MSG_CMD_LED,
    OSDP_MSG_CMD_BUZ,
    OSDP_MSG_CMD_TEXT,
    OSDP_MSG_CMD_COMSET,
    OSDP_MSG_CMD_BIOREAD,
    OSDP_MSG_CMD_BIOMATCH,
    OSDP_MSG_CMD_KEYSET,
    OSDP_MSG_CMD_CHLNG,
    OSDP_MSG_CMD_SCRYPT,
    OSDP_MSG_CMD_ACURXSIZE,
    OSDP_MSG_CMD_FILETRANSFER,
    OSDP_MSG_CMD_MFG,
    OSDP_MSG_CMD_XWR,
    OSDP_MSG_CMD_ABORT,
    OSDP_MSG_CMD_PIVDATA,
    OSDP_MSG_CMD_GENAUTH,
    OSDP_MSG_CMD_CRAUTH,
    OSDP_MSG_CMD_KEEPACTIVE,

    /* Replies (PD → ACU) */
    OSDP_MSG_REPLY_ACK,
    OSDP_MSG_REPLY_NAK,
    OSDP_MSG_REPLY_PDID,
    OSDP_MSG_REPLY_PDCAP,
    OSDP_MSG_REPLY_LSTATR,
    OSDP_MSG_REPLY_ISTATR,
    OSDP_MSG_REPLY_OSTATR,
    OSDP_MSG_REPLY_RSTATR,
    OSDP_MSG_REPLY_RAW,
    OSDP_MSG_REPLY_FMT,
    OSDP_MSG_REPLY_KEYPAD,
    OSDP_MSG_REPLY_COM,
    OSDP_MSG_REPLY_BIOREADR,
    OSDP_MSG_REPLY_BIOMATCHR,
    OSDP_MSG_REPLY_CCRYPT,
    OSDP_MSG_REPLY_RMAC_I,
    OSDP_MSG_REPLY_BUSY,
    OSDP_MSG_REPLY_FTSTAT,
    OSDP_MSG_REPLY_PIVDATAR,
    OSDP_MSG_REPLY_GENAUTHR,
    OSDP_MSG_REPLY_CRAUTHR,
    OSDP_MSG_REPLY_MFGSTATR,
    OSDP_MSG_REPLY_MFGERRR,
    OSDP_MSG_REPLY_MFGREP,
    OSDP_MSG_REPLY_XRD
} osdp_message_kind_t;

/* Classify a decoded frame to its message kind based on the code byte
 * and the reply flag in the frame header.
 *
 * Pure function: no allocations, no I/O, no static state. Crucially,
 * does NOT reference any per-message decoder symbol — linking
 * osdp::dispatch alone does not pull every codec into the binary.
 * Callers can use the returned `osdp_message_kind_t` to dispatch to
 * whichever per-message decoder they care about; codecs they don't
 * call are still subject to linker garbage-collection. */
osdp_message_kind_t osdp_dispatch_classify(const osdp_frame_t *frame);

/* Return a static, NUL-terminated, human-readable name for `kind`,
 * e.g. "osdp_LED" or "osdp_PDID". Useful for logs/sniffer UIs.
 * Never returns NULL; for unknown kinds it returns "unknown". */
const char *osdp_dispatch_name(osdp_message_kind_t kind);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_DISPATCH_H */
