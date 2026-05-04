// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PD_H
#define OSDP_PD_H

#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc_crypto.h"
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
 * Capabilities:
 *   - Address filtering (accept own address + broadcast 0x7F).
 *   - Stream-decoder integration (auto-resync, CRC/checksum validation).
 *   - Application command handler invoked on each accepted command;
 *     reply is built and emitted via transport.write().
 *   - Echoes inbound sequence number / address / integrity mode in
 *     the reply, per spec section 5.9.
 *   - Sequence number policing per spec 5.9 Table 2: a frame BYTE-
 *     IDENTICAL to the previous accepted command is treated as a
 *     retransmit and the cached reply is replayed without re-invoking
 *     the application handler. SQN-only matching is insufficient
 *     because of OSDP's 1→2→3→1 cyclic counter; comparing wire bytes
 *     handles wraparound and the OSDP.Net-style "ACU resets state but
 *     reuses SQN" edge case correctly.
 *   - Online / offline state tracking per spec 5.7: the PD considers
 *     itself offline after OSDP_PD_OFFLINE_TIMEOUT_MS without a
 *     successfully transmitted reply. On the offline transition the
 *     sequence-number cache is cleared so a reconnect begins cleanly.
 *     Requires the transport to provide a `now_ms` callback; without
 *     one the timeout is disabled and the PD is "online" after first
 *     successful reply.
 *   - Optional Secure Channel: when the application supplies a crypto
 *     vtable, an SCBK and/or SCBK-D, and a cUID via osdp_pd_set_sc_*,
 *     the PD accepts inbound CHLNG / SCRYPT and drives the SCS_11..14
 *     handshake. After SCS_14 the session struct's `established` flag
 *     flips true and both MAC chain entries are seeded with the
 *     Initial R-MAC. SCS_15 and SCS_17 commands are then unwrapped
 *     (MAC verified, payload decrypted for SCS_17) and dispatched
 *     through the same osdp_pd_command_cb the non-SC path uses — the
 *     application sees plaintext command codes and payload bytes
 *     either way. Replies are wrapped under SCS_16 by default,
 *     SCS_18 when the reply has a non-empty payload (the encryption
 *     decision is keyed off payload length per spec D.1.4 and is
 *     enforced inside osdp_sc_wrap_frame). Without SC configuration
 *     the PD continues to NAK SCB-bearing frames with code 0x05.
 *
 * Deferred for subsequent commits:
 *   - Inter-character timeout policing.
 *   - Multi-record reply convenience helpers (currently the app
 *     flat-buffers).
 *   - PD-side session-loss tracking (the ACU side handles spec D.1.4
 *     conditions today; the PD currently relies on the offline
 *     timeout to notice when something went wrong). */

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

    /* Monotonic millisecond clock. Optional; if NULL, online/offline
     * timeout tracking is disabled (the PD is considered "online" as
     * soon as it has sent a reply, and stays so forever). 32-bit wrap
     * (every ~49.7 days) is handled via unsigned subtraction. */
    uint32_t (*now_ms)(void *user);

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

/* Spec 5.7: PD considers itself offline if the gap between messages
 * to which it responds exceeds 8 seconds. */
#define OSDP_PD_OFFLINE_TIMEOUT_MS 8000U

/* ---- Secure Channel state (embedded in osdp_pd_t) ----------------------
 *
 * The PD treats SC as fully optional: leave the fields below at their
 * zeroed defaults and the PD continues to refuse SCB-bearing frames
 * with NAK 0x05 exactly as before. Configure them via the
 * osdp_pd_set_sc_* setters and the PD will accept the SCS_11..14
 * handshake and (in subsequent commits) SCS_15..18 operational
 * traffic. The crypto callbacks remain caller-supplied — `osdp::core`
 * never vendors a crypto implementation. */
typedef struct osdp_pd_sc {
    osdp_sc_crypto_t       crypto;
    bool                   crypto_set;

    uint8_t                scbk  [OSDP_SC_KEY_LEN];
    bool                   scbk_set;
    uint8_t                scbk_d[OSDP_SC_KEY_LEN];
    bool                   scbk_d_set;
    uint8_t                cuid  [OSDP_SC_CUID_LEN];
    bool                   cuid_set;

    osdp_sc_session_t      session;

    /* Mid-handshake state: populated by SCS_11 (CHLNG) handler and
     * consumed by SCS_13 (SCRYPT) handler. */
    bool                   got_chlng;
    uint8_t                rnd_a       [OSDP_SC_RND_LEN];
    uint8_t                rnd_b       [OSDP_SC_RND_LEN];
    uint8_t                key_selector; /* 0 = SCBK-D, 1 = SCBK */
} osdp_pd_sc_t;

typedef struct osdp_pd {
    uint8_t                    address;     /* this PD's 7-bit addr  */
    osdp_stream_t              rx;          /* inbound byte buffer   */
    osdp_pd_transport_t        transport;   /* I/O callbacks         */
    osdp_pd_command_cb         cmd_cb;      /* app command handler   */
    void                      *cmd_user;
    uint8_t                    tx_buf[OSDP_PD_TX_BUF_LEN];

    /* Sequence-number policing cache (spec 5.9 Table 2). When a
     * retransmit arrives — defined by the spec as a frame BYTE-
     * IDENTICAL to the previous accepted command — the PD resends
     * `last_reply[0..last_reply_len]` without invoking cmd_cb.
     *
     * SQN ALONE is not a sufficient discriminator: the cyclic
     * progression 1→2→3→1 plus certain ACU error-recovery paths
     * (observed in OSDP.Net's ACUConsole on a SC MAC-validation
     * failure) can re-use the same SQN for a NEW command. We
     * therefore also cache the previous command's wire bytes and
     * memcmp them on every incoming frame. */
    uint8_t                    last_reply[OSDP_PD_TX_BUF_LEN];
    size_t                     last_reply_len;
    uint8_t                    last_cmd  [OSDP_PD_TX_BUF_LEN];
    size_t                     last_cmd_len;
    uint8_t                    last_seq;     /* 0..3 */
    bool                       have_last;

    /* Online/offline tracking (spec 5.7). `online` flips false when
     * `now_ms - last_comm_ms` exceeds OSDP_PD_OFFLINE_TIMEOUT_MS, and
     * back true on the next successful reply. */
    bool                       online;
    uint32_t                   last_comm_ms;

    /* Secure Channel state (optional; opt-in via the set_sc_* APIs). */
    osdp_pd_sc_t               sc;
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

/* True iff the PD has successfully replied within the past
 * OSDP_PD_OFFLINE_TIMEOUT_MS. Always false for a freshly-initialized
 * PD; flips true after the first reply is transmitted. If the
 * transport doesn't supply a now_ms callback, the timeout is disabled
 * and the PD remains online once it has sent a reply. */
bool osdp_pd_is_online(const osdp_pd_t *pd);

/* ---- Secure Channel configuration --------------------------------------
 *
 * All four setters are independent and opt-in. The PD only accepts
 * SCB-bearing frames once the crypto vtable has been bound AND at
 * least one of (SCBK, SCBK-D) has been set AND the cUID is known. */

/* Bind the crypto HAL the PD will use for AES + RNG during SC. */
void osdp_pd_set_sc_crypto(osdp_pd_t              *pd,
                           const osdp_sc_crypto_t *crypto);

/* Set the per-PD Secure Channel Base Key (SCBK), used when the ACU
 * requests SCS_11 with the SCBK selector (1). */
void osdp_pd_set_sc_scbk(osdp_pd_t       *pd,
                         const uint8_t    scbk[OSDP_SC_KEY_LEN]);

/* Set the default install key (SCBK-D), used when the ACU requests
 * SCS_11 with the SCBK-D selector (0). */
void osdp_pd_set_sc_scbk_d(osdp_pd_t     *pd,
                           const uint8_t  scbk_d[OSDP_SC_KEY_LEN]);

/* Set the PD's cUID — the first 8 bytes of the PDID byte stream
 * (vendor[3] + model + version + serial[0..2]) per spec D.4.3. */
void osdp_pd_set_sc_cuid(osdp_pd_t     *pd,
                         const uint8_t  cuid[OSDP_SC_CUID_LEN]);

/* True iff the SCS_11..14 handshake has completed successfully and
 * the PD is ready to handle SCS_15..18 operational traffic. */
bool osdp_pd_sc_established(const osdp_pd_t *pd);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PD_H */
