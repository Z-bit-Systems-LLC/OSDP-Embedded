// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_ACU_H
#define OSDP_ACU_H

#include "osdp/osdp_buz_state.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_led_state.h"
#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc2.h"
#include "osdp/osdp_sc2_crypto.h"
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
 * application via callbacks.
 *
 * Like osdp::pd, this layer remains freestanding: no malloc, no
 * globals, no I/O of its own. The consumer supplies a transport (RS-485
 * UART, TCP, in-process loopback for tests) via a callback vtable plus
 * reply / timeout / SC-event handlers.
 *
 * Capabilities:
 *
 *   - Caller-allocated PD slot array (no allocation, multi-PD supported).
 *   - Explicit send_command API; the application drives polling.
 *   - One outstanding command per PD at a time. Issuing a second
 *     command while a reply is pending returns OSDP_ERR_NOT_SUPPORTED
 *     (the current "busy" sentinel; future iterations may queue).
 *   - Sequence number management per spec 5.9 Table 2: starts at 0
 *     for the first command on a fresh PD slot, then 1→2→3→1→…
 *     Successful reply advances; timeout retains the SQN so a retry
 *     re-uses it.
 *   - Reply timeout = OSDP_ACU_REPLY_TIMEOUT_MS (200 ms, spec 5.7).
 *   - Per-PD online tracking: a PD is online while it has produced a
 *     reply within OSDP_ACU_OFFLINE_TIMEOUT_MS (8 s, spec 5.7).
 *   - Optional Secure Channel: per-PD opt-in via osdp_acu_set_pd_scbk*
 *     plus a shared AES + RNG vtable bound on the ACU. See "Secure
 *     Channel lifecycle" below.
 *
 * ---- Secure Channel lifecycle ------------------------------------------
 *
 * Each PD slot has an `sc_phase` field tracking the handshake state:
 *
 *     IDLE → AWAITING_CCRYPT → AWAITING_RMAC_I → ESTABLISHED
 *      ↑__________________________________________|
 *                   (on session loss)
 *
 * The application drives the transition IDLE → AWAITING_CCRYPT by
 * calling osdp_acu_start_sc_handshake(pd_addr, use_default_key). The
 * ACU sends osdp_CHLNG immediately and tick() drives the rest:
 *
 *   start_sc_handshake → emits SCS_11 CHLNG with RND.A
 *   tick consumes SCS_12 CCRYPT
 *     ⊕ validates Client Cryptogram
 *     ⊕ on match, emits SCS_13 SCRYPT with Server Cryptogram
 *     ⊕ on mismatch, fires HANDSHAKE_FAILED, returns to IDLE
 *   tick consumes SCS_14 RMAC_I
 *     ⊕ checks sec_blk_data[0] (0x01 ok / 0xFF PD-rejected SCRYPT)
 *     ⊕ validates Initial R-MAC against locally-derived expected
 *     ⊕ on success: seeds session.last_outbound_mac =
 *                   session.last_inbound_mac = Initial R-MAC,
 *                   transitions to ESTABLISHED, fires ESTABLISHED
 *     ⊕ on any failure: fires HANDSHAKE_FAILED, returns to IDLE
 *
 * CCRYPT and RMAC_I are consumed silently by the handshake state
 * machine — they never appear in the application's reply_cb. The
 * application only learns the outcome through sc_event_cb.
 *
 * Once ESTABLISHED, every osdp_acu_send_command on that slot is
 * automatically wrapped — there is no per-command opt-out. Inbound
 * SCS_16 / SCS_18 replies are unwrapped before being delivered via
 * reply_cb (always plaintext to the application).
 *
 * ---- Session-loss conditions -------------------------------------------
 *
 * An established session terminates (slot returns to IDLE; the next
 * command on that slot goes plaintext until the application
 * re-handshakes) on any of these events:
 *
 *   • A SCS_16 / SCS_18 reply has a valid CRC but its MAC fails to
 *     verify (spec D.1.4: "encryption synchronization has been lost").
 *   • A non-BUSY plaintext reply arrives during ESTABLISHED (D.1.4:
 *     "any message sent without a SCB other than osdp_BUSY terminates
 *     the session").
 *   • A reply arrives with sequence number 0 during ESTABLISHED (5.9:
 *     "a PD may respond with SQN zero to indicate the ACU shall reset
 *     the sequence including clearing any secure channel session").
 *   • The PD goes silent for OSDP_ACU_OFFLINE_TIMEOUT_MS (5.7).
 *     Encryption synchronization can't be assumed across multi-second
 *     silence.
 *
 * Each fires OSDP_ACU_SC_EVENT_SESSION_LOST. If the same offline
 * timeout fires while the slot is mid-handshake (AWAITING_CCRYPT or
 * AWAITING_RMAC_I) the event is OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED
 * instead — there was nothing established to lose.
 *
 * ---- Deferred ----------------------------------------------------------
 *
 *   - Auto-poll scheduling (ACU sending POLL on a per-PD interval).
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

    /* ---- Secure Channel 2 state (opt-in via osdp_acu_set_pd_sc2_scbk).
     * Parallel to the SC1 fields above but for OSDP-SC2 (AES-256-GCM /
     * KMAC256). SC2 is device-key only — no SCBK-D. A slot uses either
     * SC1 or SC2, never both at once; sc2_phase reuses the SC1 phase
     * enum (IDLE → AWAITING_CCRYPT → AWAITING_RMAC_I → ESTABLISHED). */
    bool                  sc2_scbk_set;
    uint8_t               sc2_scbk[OSDP_SC2_KEY_LEN];
    osdp_acu_sc_phase_t   sc2_phase;
    uint8_t               sc2_rnd_a[OSDP_SC2_RND_LEN];
    uint8_t               sc2_rnd_b[OSDP_SC2_RND_LEN];
    uint8_t               sc2_cuid [OSDP_SC2_CUID_LEN];
    osdp_sc2_session_t    sc2_session;
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

/* ---- Reader LED observation --------------------------------------------
 *
 * The ACU is the side that *drives* reader LEDs: every osdp_LED command it
 * sends is folded into an internal bank of osdp_led_t resolvers, keyed by
 * (pd_address, reader_no, led_no). This lets a controller application — or
 * a visualiser — ask "what colour should PD X's reader LED be right now?"
 * without re-parsing the commands it issued, and get a callback whenever
 * that resolved colour changes (including temporary-timer expiry and flash
 * transitions, which are evaluated inside osdp_acu_tick()). */

/* Number of distinct (pd_address, reader_no, led_no) LEDs the ACU tracks.
 * Sized for a small multi-PD bus; commands for LEDs beyond this are still
 * sent on the wire but not mirrored locally. */
#define OSDP_ACU_MAX_LEDS 16U

/* Fired when a driven reader LED's resolved colour changes. `color` is an
 * osdp_led_color_t value (0x00 black/off .. 0x07 white). The callback must
 * not re-enter the ACU API. */
typedef void (*osdp_acu_led_cb)(void   *user,
                                uint8_t pd_address,
                                uint8_t reader_no,
                                uint8_t led_no,
                                uint8_t color);

/* Fired when a driven reader buzzer's sounding state changes — the
 * controller's view of "PD X's reader is beeping / fell silent". `sounding`
 * true while making sound; `tone` is the driving tone_code. The on/off
 * edges and end-of-pattern are resolved inside osdp_acu_tick(). Must not
 * re-enter the ACU API. */
typedef void (*osdp_acu_buzzer_cb)(void   *user,
                                   uint8_t pd_address,
                                   uint8_t reader_no,
                                   bool    sounding,
                                   uint8_t tone);

/* One tracked physical LED on some PD, plus the last colour reported so
 * the ACU fires the callback only on an actual change. */
typedef struct osdp_acu_led_slot {
    bool       used;
    uint8_t    pd_address;
    uint8_t    reader_no;
    uint8_t    led_no;
    uint8_t    last_color;   /* osdp_led_color_t last handed to led_cb */
    osdp_led_t state;
} osdp_acu_led_slot_t;

/* Number of distinct (pd_address, reader_no) buzzers the ACU tracks. */
#define OSDP_ACU_MAX_BUZZERS 8U

/* One tracked reader buzzer on some PD, plus the last sounding flag
 * reported so the ACU fires the callback only on an actual change. */
typedef struct osdp_acu_buz_slot {
    bool       used;
    uint8_t    pd_address;
    uint8_t    reader_no;
    bool       last_sounding;
    osdp_buz_t state;
} osdp_acu_buz_slot_t;

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

    /* Secure Channel 2 HAL — one shared SC2 crypto vtable across slots. */
    osdp_sc2_crypto_t           sc2_crypto;
    bool                        sc2_crypto_set;

    /* SC event callback — fires on handshake completion or failure.
     * Shared by SC1 and SC2 (the event carries only the PD address and
     * kind, not which channel version). */
    osdp_acu_sc_event_cb        sc_event_cb;
    void                       *sc_event_user;

    /* Reader LED bank (populated from outbound osdp_LED commands) plus the
     * optional change callback. */
    osdp_acu_led_slot_t         leds[OSDP_ACU_MAX_LEDS];
    osdp_acu_led_cb             led_cb;
    void                       *led_user;

    /* Reader buzzer bank (from outbound osdp_BUZ commands) plus the
     * optional sounding-change callback. */
    osdp_acu_buz_slot_t         buzzers[OSDP_ACU_MAX_BUZZERS];
    osdp_acu_buzzer_cb          buzzer_cb;
    void                       *buzzer_user;
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

/* ---- Reader LED observation --------------------------------------------*/

/* Bind the reader-LED change handler. `cb` fires whenever a driven LED's
 * resolved colour changes (see osdp_acu_led_cb). Pass cb=NULL to detach. */
void osdp_acu_set_led_handler(osdp_acu_t *acu, osdp_acu_led_cb cb, void *user);

/* Current resolved colour of the given PD's reader LED as an
 * osdp_led_color_t (0x00 black/off .. 0x07 white). Returns OSDP_LED_BLACK
 * for an LED the ACU has never driven. Resolved against the transport's
 * now_ms clock (or time 0 if none) so flashing LEDs return the current
 * phase. */
uint8_t osdp_acu_led_color(const osdp_acu_t *acu, uint8_t pd_address,
                           uint8_t reader_no, uint8_t led_no);

/* Bind the reader-buzzer handler. `cb` fires when a driven buzzer's
 * sounding state changes (see osdp_acu_buzzer_cb). Pass cb=NULL to detach. */
void osdp_acu_set_buzzer_handler(osdp_acu_t *acu, osdp_acu_buzzer_cb cb,
                                 void *user);

/* True iff the given PD reader's buzzer is sounding right now (per the ACU's
 * model of what it commanded). False for an unaddressed buzzer. */
bool osdp_acu_buzzer_sounding(const osdp_acu_t *acu, uint8_t pd_address,
                             uint8_t reader_no);

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

/* ---- Secure Channel 2 configuration ------------------------------------
 *
 * Parallel to the SC1 setters, independent and opt-in. SC2 is
 * device-key only (no SCBK-D). Bind the SC2 crypto vtable + a per-PD
 * 32-byte SCBK, then call osdp_acu_start_sc2_handshake. The shared
 * sc_event handler reports the result. */

/* Bind the SC2 crypto HAL (KMAC256 + AES-256-GCM + AES-256 block +
 * RNG) used for every SC2 operation across every PD. Copied. */
void osdp_acu_set_sc2_crypto(osdp_acu_t               *acu,
                             const osdp_sc2_crypto_t  *crypto);

/* Set the per-PD 32-byte AES-256 SCBK for SC2. */
osdp_status_t osdp_acu_set_pd_sc2_scbk(osdp_acu_t   *acu,
                                       uint8_t       pd_address,
                                       const uint8_t scbk[OSDP_SC2_KEY_LEN]);

/* Initiate an OSDP-SC2 handshake with the given PD: sends CHLNG
 * (SCS_21) immediately; subsequent ticks drive CCRYPT → SCRYPT →
 * RMAC_I and fire the sc_event handler. Same return contract as
 * osdp_acu_start_sc_handshake. */
osdp_status_t osdp_acu_start_sc2_handshake(osdp_acu_t *acu,
                                           uint8_t     pd_address);

/* True iff the PD slot's SC2 session has reached ESTABLISHED. */
bool osdp_acu_is_pd_sc2_established(const osdp_acu_t *acu,
                                   uint8_t           pd_address);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_ACU_H */
