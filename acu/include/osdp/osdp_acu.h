// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_ACU_H
#define OSDP_ACU_H

#include "osdp/osdp_frame.h"
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
 * Deferred for subsequent commits:
 *   - Auto-poll scheduling (ACU sending POLL on a per-PD interval).
 *   - In-process PD<->ACU integration tests.
 *   - Multi-command queueing per PD.
 *   - Secure Channel session management. */

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
 * shared TX scratch and writes it to the transport. Returns:
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

#ifdef __cplusplus
}
#endif

#endif /* OSDP_ACU_H */
