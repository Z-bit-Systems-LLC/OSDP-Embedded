// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PD_H
#define OSDP_PD_H

#include "osdp/osdp_stream.h"
#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_pd — Peripheral Device-side state machine and reply pipeline.
 *
 * This is the role-specific layer that sits on top of `osdp::core`.
 * The library remains freestanding: no malloc, no globals, no I/O of
 * its own. The consumer supplies a transport (RS-485 UART, TCP socket,
 * test loopback, ...) via a callback vtable, and an application-level
 * command handler that turns inbound commands into outbound replies.
 *
 * Lifecycle:
 *
 *     osdp_pd_t pd;
 *     osdp_pd_init(&pd, my_address);
 *     osdp_pd_set_transport(&pd, &my_transport);
 *     osdp_pd_set_command_handler(&pd, my_handler, my_user_ptr);
 *     for (;;) {
 *         osdp_pd_tick(&pd);
 *         // ... cooperative scheduling / sleep / wfi
 *     }
 *
 * Iteration 2 phase 1 scope:
 *   - Address filtering (accept own address + broadcast 0x7F).
 *   - Stream-decoder integration (auto-resync, CRC/checksum validation).
 *   - Application command handler invoked on each accepted command.
 *   - Reply built and emitted via transport.write().
 *   - Echoes inbound sequence number / address / integrity mode in
 *     the reply, per spec section 5.9.
 *   - Refuses Secure Channel frames with NAK 0x05 (SC arrives in
 *     iteration 3).
 *
 * Iteration 2 phase 2 scope (this commit):
 *   - Sequence number policing per spec 5.9 Table 2: when the ACU
 *     retransmits a command with the same non-zero SQN, the PD
 *     resends its cached reply without re-invoking the application
 *     handler. SQN zero always processes fresh (session reset).
 *
 * Deferred for subsequent commits:
 *   - Online / offline state tracking + 8-second-without-comm reset.
 *   - Inter-character timeout policing.
 *   - Multi-record reply convenience helpers (currently the app
 *     flat-buffers).
 */

/* ---- Transport HAL ------------------------------------------------------*/

/* User-supplied I/O callbacks. All are non-blocking; PD will call them
 * repeatedly from osdp_pd_tick(). */
typedef struct osdp_pd_transport {
    /* Read up to `cap` bytes into `buf`. Returns the number of bytes
     * actually read (0 if no data is available right now). Negative
     * return values are reserved for future error reporting; for now,
     * implementations should return 0 on idle and never negative. */
    int (*read)(void *user, uint8_t *buf, size_t cap);

    /* Write all `len` bytes from `buf`. Implementations may block
     * briefly to enqueue into a UART driver, but should not stall the
     * caller indefinitely. Returns the number of bytes accepted; the
     * PD treats a short write as a transmission error. */
    int (*write)(void *user, const uint8_t *buf, size_t len);

    /* Opaque pointer threaded back into every callback. */
    void *user;
} osdp_pd_transport_t;

/* ---- Application handler ------------------------------------------------*/

/* The reply produced by an application-level command handler. The
 * application sets `code` to the desired osdp_REPLY_* value (e.g.
 * OSDP_REPLY_ACK, OSDP_REPLY_PDID) and points `payload` at a buffer of
 * `payload_len` bytes containing the body of that reply. The buffer
 * must remain valid until the handler returns; the PD copies the bytes
 * into its own TX scratch before transport.write() is called. */
typedef struct osdp_pd_reply {
    uint8_t        code;
    const uint8_t *payload;
    size_t         payload_len;
} osdp_pd_reply_t;

/* Command handler. The PD has already validated the inbound frame
 * (CRC/checksum, address match, length sanity) before invoking this.
 *
 * The handler may inspect `cmd_code` and `payload` and produce a reply.
 * Three return policies:
 *
 *   - OSDP_OK: fill in *reply and the PD will frame and transmit it.
 *   - OSDP_ERR_NOT_SUPPORTED: the PD will send NAK with error code
 *     0x03 (Unknown Command Code). Use this for command codes the
 *     application doesn't implement.
 *   - any other osdp_status_t: treated as an internal error; the PD
 *     drops the command silently. (Future iterations may emit a NAK
 *     with a different error code instead.)
 */
typedef osdp_status_t (*osdp_pd_command_cb)(
    void           *user,
    uint8_t         cmd_code,
    const uint8_t  *payload,
    size_t          payload_len,
    osdp_pd_reply_t *reply);

/* ---- Context ------------------------------------------------------------*/

/* Outbound TX scratch sized for any baseline reply. Bumped in later
 * iterations if/when extended replies (file transfer chunks, biometric
 * templates) become first-class. */
#define OSDP_PD_TX_BUF_LEN 256U

typedef struct osdp_pd {
    uint8_t                    address;     /* this PD's 7-bit addr  */
    osdp_stream_t              rx;          /* inbound byte buffer   */
    osdp_pd_transport_t        transport;   /* I/O callbacks         */
    osdp_pd_command_cb         cmd_cb;      /* app command handler   */
    void                      *cmd_user;
    uint8_t                    tx_buf[OSDP_PD_TX_BUF_LEN];

    /* Sequence-number policing cache (spec 5.9 Table 2). When a
     * retransmit arrives with the same non-zero SQN, the PD resends
     * `last_reply[0..last_reply_len]` without invoking cmd_cb. */
    uint8_t                    last_reply[OSDP_PD_TX_BUF_LEN];
    size_t                     last_reply_len;
    uint8_t                    last_seq;     /* 0..3 */
    bool                       have_last;
} osdp_pd_t;

/* ---- API ----------------------------------------------------------------*/

/* Initialize a PD context. `address` is the 7-bit physical address
 * (0x00..0x7E) the PD should respond to. The broadcast address 0x7F is
 * always accepted in addition. */
void osdp_pd_init(osdp_pd_t *pd, uint8_t address);

/* Bind a transport. The supplied vtable is copied into the context;
 * the source may be on the stack or read-only. */
void osdp_pd_set_transport(osdp_pd_t *pd,
                           const osdp_pd_transport_t *transport);

/* Bind the application's command handler. May be called with cb=NULL
 * to detach (every command will then NAK with code 0x03). */
void osdp_pd_set_command_handler(osdp_pd_t *pd,
                                 osdp_pd_command_cb cb, void *user);

/* Pump the PD state machine: read available bytes, process any complete
 * frames addressed to this PD or to the broadcast, dispatch to the
 * command handler, and send any reply. Idempotent and non-blocking;
 * call from your main loop. */
void osdp_pd_tick(osdp_pd_t *pd);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PD_H */
