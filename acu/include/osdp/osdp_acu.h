// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_ACU_H
#define OSDP_ACU_H

#include "osdp/osdp_frame.h"
#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc_crypto.h"
#include "osdp/osdp_stream.h"
#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_acu — Access Control Unit (controller) state machine.
 *
 * Counterpart of osdp::pd. The ACU initiates commands toward one or
 * more PDs sharing a half-duplex bus, manages per-PD sequence numbers,
 * times out unanswered commands, and routes accepted replies to the
 * application via a callback.
 *
 * Like osdp::pd, this layer remains freestanding: no malloc, no
 * globals, no I/O of its own. The consumer supplies a transport (RS-485
 * UART, TCP, in-process loopback for tests) via a callback vtable plus
 * a reply handler.
 *
 * Iteration 2 phase 4 scope (this commit):
 *   - Caller-allocated PD slot array (no allocation, multi-PD supported).
 *   - Explicit send_command API; the application drives polling.
 *   - One outstanding command per PD at a time. Issuing a second
 *     command while a reply is pending returns OSDP_ERR_BUSY-like
 *     INVALID_ARG; future iterations may queue.
 *   - Sequence number management per spec 5.9 Table 2: starts at 0
 *     for the first command on a fresh PD slot, then 1->2->3->1->...
 *     Successful reply advances; timeout retains the SQN so a retry
 *     re-uses it.
 *   - Reply timeout = REPLY_DELAY_MS (default 200, per spec 5.7).
 *     On timeout the application's timeout handler is invoked and the
 *     PD's pending state is cleared so a retry can be issued.
 *   - Per-PD online tracking: PD is online while it has produced a
 *     reply within OSDP_ACU_OFFLINE_TIMEOUT_MS.
 *
 * Iteration 3 phase 5a scope:
 *   - Optional Secure Channel handshake initiation. With one shared
 *     crypto vtable bound on the ACU and per-PD key material (SCBK or
 *     SCBK-D), the application can call osdp_acu_start_sc_handshake()
 *     to drive the SCS_11..14 sequence. The ACU sends CHLNG, consumes
 *     the CCRYPT reply (validates Client Cryptogram, captures cUID +
 *     RND.B), sends SCRYPT, consumes the RMAC_I reply (validates the
 *     Initial R-MAC), and fires the application's sc_event callback
 *     with OSDP_ACU_SC_EVENT_ESTABLISHED on success or
 *     OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED on any cryptographic
 *     mismatch. CCRYPT and RMAC_I never reach the reply_cb — they're
 *     consumed by the handshake state machine internally.
 *
 * Iteration 3 phase 5b scope (this commit):
 *   - Operational SCS_15..18 traffic. Once a slot's handshake has
 *     completed, every osdp_acu_send_command toward that PD is
 *     automatically wrapped: under SCS_17 when the command carries a
 *     payload, under SCS_15 when it's empty (the SCB selection is
 *     enforced by osdp_sc_wrap_frame). The application sends and
 *     receives plaintext; the SCB type, MAC, and payload encryption
 *     are transparent. Inbound SCS_16 / SCS_18 replies are unwrapped
 *     before being delivered via reply_cb.
 *   - Session-loss detection. Per spec D.1.4, an established session
 *     terminates if a reply arrives with a valid CRC but a MAC
 *     mismatch, or if a non-BUSY plaintext reply arrives. The slot
 *     transitions back to IDLE and OSDP_ACU_SC_EVENT_SESSION_LOST
 *     fires; the application may re-handshake at will.
 *
 * Deferred for subsequent commits:
 *   - Auto-poll scheduling (ACU sending POLL on a per-PD interval).
 *   - In-process PD<->ACU integration tests (phase 6).
 *   - Multi-command queueing per PD. */

/* ---- Tuning constants ---------------------------------------------------*/

/* Spec 5.7: REPLY_DELAY shall not exceed 200 ms. */
#define OSDP_ACU_REPLY_TIMEOUT_MS    200U

/* Spec 5.7: PD considered offline after 8 s of silence. The ACU mirrors
 * this so application code can ask "is PD X online from the controller's
 * perspective right now?". */
#define OSDP_ACU_OFFLINE_TIMEOUT_MS  8000U

/* TX scratch sized for any baseline command payload + framing overhead. */
#define OSDP_ACU_TX_BUF_LEN          256U

/* ---- Transport HAL ------------------------------------------------------*/

typedef struct osdp_acu_transport {
    int      (*read)(void *user, uint8_t *buf, size_t cap);
    int      (*write)(void *user, const uint8_t *buf, size_t len);
    /* Optional. If NULL, timeout/online-tracking is disabled and replies
     * are processed eagerly without any deadline. */
    uint32_t (*now_ms)(void *user);
    void     *user;
} osdp_acu_transport_t;

/* ---- Per-PD slot --------------------------------------------------------
 *
 * The application allocates an array of these and hands ownership to the
 * ACU at init. Slots are addressed by index for register/unregister and
 * by PD address for command dispatch. Storing this on the application
 * side (rather than malloc'ing inside the ACU) keeps the library
 * freestanding and lets the caller decide where the per-PD state lives
 * (e.g. in a static array sized by deployment). */

/* Secure Channel handshake phase tracker. IDLE = no handshake active;
 * the other states are intermediate steps the tick() state machine
 * walks through internally. */
typedef enum osdp_acu_sc_phase {
    OSDP_ACU_SC_IDLE = 0,
    OSDP_ACU_SC_AWAITING_CCRYPT,   /* sent CHLNG, waiting on CCRYPT (SCS_12) */
    OSDP_ACU_SC_AWAITING_RMAC_I,   /* sent SCRYPT, waiting on RMAC_I (SCS_14) */
    OSDP_ACU_SC_ESTABLISHED        /* handshake complete; SCS_15..18 OK     */
} osdp_acu_sc_phase_t;

typedef struct osdp_acu_pd_slot {
    bool     in_use;
    uint8_t  address;          /* 7-bit PD address                       */
    uint8_t  next_seq;         /* SQN of the next command to issue       */
    bool     waiting;          /* true while a command awaits its reply  */
    uint8_t  pending_seq;      /* SQN of the outstanding command         */
    uint8_t  pending_code;     /* command code awaiting reply            */
    uint32_t pending_sent_ms;  /* timestamp at which command was written */
    bool     online;           /* PD has answered within timeout window  */
    uint32_t last_reply_ms;    /* timestamp of most recent valid reply   */

    /* ---- Secure Channel state (opt-in via osdp_acu_set_pd_sc_*) ---- */
    bool                  scbk_set;
    uint8_t               scbk  [OSDP_SC_KEY_LEN];
    bool                  scbk_d_set;
    uint8_t               scbk_d[OSDP_SC_KEY_LEN];

    /* Phase + mid-handshake scratch. */
    osdp_acu_sc_phase_t   sc_phase;
    uint8_t               sc_key_selector;   /* 0 = SCBK-D, 1 = SCBK    */
    uint8_t               sc_rnd_a[OSDP_SC_RND_LEN];
    uint8_t               sc_rnd_b[OSDP_SC_RND_LEN];
    uint8_t               sc_cuid [OSDP_SC_CUID_LEN];

    /* Operational session. Populated when sc_phase becomes ESTABLISHED;
     * keys + rolling MAC chain live in here. Phase 5b will use it. */
    osdp_sc_session_t     sc_session;
} osdp_acu_pd_slot_t;

/* ---- Reply / timeout events --------------------------------------------*/

typedef struct osdp_acu_reply_event {
    uint8_t        pd_address;     /* PD that replied                     */
    uint8_t        cmd_code;       /* command code we had sent            */
    uint8_t        reply_code;     /* osdp_REPLY_* received               */
    const uint8_t *payload;        /* slice into stream buffer            */
    size_t         payload_len;
} osdp_acu_reply_event_t;

typedef struct osdp_acu_timeout_event {
    uint8_t pd_address;
    uint8_t cmd_code;
    uint8_t cmd_seq;
} osdp_acu_timeout_event_t;

typedef void (*osdp_acu_reply_cb)(
    void                          *user,
    const osdp_acu_reply_event_t  *event);

typedef void (*osdp_acu_timeout_cb)(
    void                            *user,
    const osdp_acu_timeout_event_t  *event);

/* ---- Secure Channel events ---------------------------------------------
 *
 * When a handshake started by osdp_acu_start_sc_handshake() resolves —
 * either successfully or with a cryptographic mismatch — the ACU fires
 * an event of this type to the application, separate from the normal
 * reply_cb / timeout_cb stream. CCRYPT (SCS_12) and RMAC_I (SCS_14)
 * replies are consumed by the handshake state machine and never
 * delivered as ordinary replies. */

typedef enum osdp_acu_sc_event_kind {
    /* Handshake completed successfully; the PD slot's sc_session is
     * established and SCS_15..18 traffic is now permitted. */
    OSDP_ACU_SC_EVENT_ESTABLISHED = 0,

    /* Handshake failed cryptographically. Either:
     *   - the PD's Client Cryptogram in CCRYPT didn't match what we
     *     would compute from RND.A + RND.B + the chosen key, or
     *   - the PD's RMAC_I came back with the failure status byte
     *     (sec_blk_data[0] == 0xFF), per spec D.1.3.4.
     * The PD slot remains in the IDLE phase; the application may
     * retry by calling osdp_acu_start_sc_handshake again. */
    OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED,

    /* An established session was lost mid-flight. Per spec D.1.4 the
     * session terminates whenever:
     *   - a SCB-bearing reply has a valid CRC but a MAC mismatch
     *     (encryption synchronization lost), or
     *   - a non-BUSY plaintext reply arrives while the session is
     *     active ("any message sent without a SCB other than
     *     osdp_BUSY terminates the session").
     * The slot transitions back to IDLE; the application may
     * re-handshake by calling osdp_acu_start_sc_handshake again. */
    OSDP_ACU_SC_EVENT_SESSION_LOST,
} osdp_acu_sc_event_kind_t;

typedef struct osdp_acu_sc_event {
    uint8_t                  pd_address;
    osdp_acu_sc_event_kind_t kind;
} osdp_acu_sc_event_t;

typedef void (*osdp_acu_sc_event_cb)(
    void                       *user,
    const osdp_acu_sc_event_t  *event);

/* ---- Context -----------------------------------------------------------*/

typedef struct osdp_acu {
    osdp_acu_transport_t        transport;
    osdp_acu_pd_slot_t         *pds;       /* caller-allocated array      */
    size_t                      pd_count;
    osdp_acu_reply_cb           reply_cb;
    void                       *reply_user;
    osdp_acu_timeout_cb         timeout_cb;
    void                       *timeout_user;
    osdp_stream_t               rx;
    uint8_t                     tx_buf[OSDP_ACU_TX_BUF_LEN];
    osdp_integrity_t            integrity; /* CRC by default; CKSUM legacy */

    /* Secure Channel HAL — one shared crypto vtable across all PD slots.
     * The ACU process has one AES implementation; per-PD state lives in
     * the slot. */
    osdp_sc_crypto_t            sc_crypto;
    bool                        sc_crypto_set;

    /* SC event callback — fires on handshake completion or failure. */
    osdp_acu_sc_event_cb        sc_event_cb;
    void                       *sc_event_user;
} osdp_acu_t;

/* ---- API ---------------------------------------------------------------*/

/* Initialize an ACU context. `pd_slots` must point to `pd_count` slots
 * the caller has allocated; the ACU clears them and treats the array as
 * its property until osdp_acu_init() is called again. */
void osdp_acu_init(osdp_acu_t          *acu,
                   osdp_acu_pd_slot_t  *pd_slots,
                   size_t               pd_count);

void osdp_acu_set_transport(osdp_acu_t *acu,
                            const osdp_acu_transport_t *transport);

void osdp_acu_set_reply_handler(osdp_acu_t *acu,
                                osdp_acu_reply_cb cb, void *user);

void osdp_acu_set_timeout_handler(osdp_acu_t *acu,
                                  osdp_acu_timeout_cb cb, void *user);

/* Set the integrity mode used for outgoing commands. Defaults to CRC-16. */
void osdp_acu_set_integrity(osdp_acu_t *acu, osdp_integrity_t integrity);

/* Bind a PD address to slot `slot_index` (0..pd_count-1). The slot's
 * sequence number is reset to 0 (per spec, the first command on a new
 * connection uses SQN zero). Returns INVALID_ARG for an out-of-range
 * slot or address. */
osdp_status_t osdp_acu_register_pd(osdp_acu_t *acu,
                                   size_t      slot_index,
                                   uint8_t     pd_address);

/* Send a command to a registered PD. Builds the OSDP frame in the
 * shared TX scratch and writes it to the transport.
 *
 * If the slot's Secure Channel session is ESTABLISHED, the frame is
 * automatically wrapped under SCS_17 (or SCS_15 for empty payloads,
 * per the spec D.1.4 convention enforced inside osdp_sc_wrap_frame).
 * The application always passes plaintext bytes; encryption + MAC
 * are transparent. Once SC is established, every command on that
 * slot uses the secure channel — there is no per-command opt-out.
 *
 * If the slot's session is not yet established (pre-handshake or
 * after a session-lost event), the command is sent without an SCB,
 * matching the original phase 4 behaviour.
 *
 * Returns:
 *   OSDP_OK           — frame transmitted, awaiting reply.
 *   OSDP_ERR_INVALID_ARG  — pd_address not registered.
 *   OSDP_ERR_NOT_SUPPORTED — slot already has an outstanding reply
 *                            (caller must wait for it to land or time
 *                            out before issuing the next command). */
osdp_status_t osdp_acu_send_command(osdp_acu_t    *acu,
                                    uint8_t        pd_address,
                                    uint8_t        cmd_code,
                                    const uint8_t *payload,
                                    size_t         payload_len);

/* Pump the ACU state machine: drain incoming bytes, dispatch any
 * accepted reply to the reply handler, fire timeout events for stale
 * pending commands, update online flags. Idempotent and non-blocking. */
void osdp_acu_tick(osdp_acu_t *acu);

bool osdp_acu_is_pd_online(const osdp_acu_t *acu, uint8_t pd_address);
bool osdp_acu_is_pd_busy  (const osdp_acu_t *acu, uint8_t pd_address);

/* ---- Secure Channel API -------------------------------------------------
 *
 * All four setters are independent and opt-in. The ACU only initiates
 * SC handshakes for PDs that have at least one of (SCBK, SCBK-D)
 * configured AND a crypto vtable bound. Calling these before
 * osdp_acu_register_pd is OK as long as the PD address is registered
 * before the handshake starts. */

/* Bind the AES + RNG primitives the ACU uses for every SC operation
 * across every PD it manages. The vtable is copied; the source can be
 * stack-allocated or read-only. */
void osdp_acu_set_sc_crypto(osdp_acu_t              *acu,
                            const osdp_sc_crypto_t  *crypto);

/* Set the per-PD Secure Channel Base Key (SCBK). Used when the
 * application calls osdp_acu_start_sc_handshake with use_default_key
 * = false. */
osdp_status_t osdp_acu_set_pd_scbk  (osdp_acu_t   *acu,
                                     uint8_t       pd_address,
                                     const uint8_t scbk  [OSDP_SC_KEY_LEN]);

/* Set the per-PD default install key (SCBK-D). Used when the
 * application calls osdp_acu_start_sc_handshake with use_default_key
 * = true. */
osdp_status_t osdp_acu_set_pd_scbk_d(osdp_acu_t   *acu,
                                     uint8_t       pd_address,
                                     const uint8_t scbk_d[OSDP_SC_KEY_LEN]);

/* Bind the SC event handler. Called when a handshake completes or
 * fails cryptographically. May be NULL to detach. */
void osdp_acu_set_sc_event_handler(osdp_acu_t           *acu,
                                   osdp_acu_sc_event_cb  cb,
                                   void                 *user);

/* Initiate a Secure Channel handshake with the given PD. Sends CHLNG
 * (SCS_11) immediately; subsequent ticks drive the rest of the
 * handshake (CCRYPT consumed → SCRYPT sent → RMAC_I consumed → event
 * fired). The PD slot's sc_phase advances through the IDLE →
 * AWAITING_CCRYPT → AWAITING_RMAC_I → ESTABLISHED states.
 *
 * Returns:
 *   OSDP_OK                — CHLNG sent, awaiting CCRYPT.
 *   OSDP_ERR_INVALID_ARG   — pd_address not registered, or no crypto
 *                            vtable bound, or no key configured for
 *                            the requested mode.
 *   OSDP_ERR_NOT_SUPPORTED — slot already has an outstanding command
 *                            (a non-SC reply, or a handshake already
 *                            in progress). Caller must wait. */
osdp_status_t osdp_acu_start_sc_handshake(osdp_acu_t *acu,
                                          uint8_t     pd_address,
                                          bool        use_default_key);

/* True iff the PD slot's SC session has reached the ESTABLISHED
 * phase (both peers have valid keys and a matching Initial R-MAC). */
bool osdp_acu_is_pd_sc_established(const osdp_acu_t *acu,
                                   uint8_t           pd_address);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_ACU_H */
