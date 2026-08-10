// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PD_PAIR_H
#define OSDP_PD_PAIR_H

#include "osdp/osdp_pair.h"
#include "osdp/osdp_pd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_pd_pair — PD-side driver for SC2 asymmetric device pairing
 * (osdp::pd_pair, opt-in).
 *
 * Wraps the transport-free PD responder (osdp::pair) with the OSDP wire
 * plumbing: reassembles inbound osdp_PAIR fragments, drives the handshake,
 * delivers Message 2 as osdp_PAIRR fragments over successive POLLs, returns
 * the single-fragment Result inline on the Message-3-completing PAIR, and —
 * strictly after that Result is transmitted — applies the derived SCBK to
 * the PD's SC2 channel in place (the deterministic cleartext->SC2 handoff).
 * No reconnect: the ACU's next CHLNG establishes SC2 with the paired key.
 *
 * Usage:
 *
 *     static osdp_pd_pair_t pair;             // ~22 KB, caller-owned
 *     osdp_pd_pair_init(&pair, &pair_crypto, &my_creds, &trust);
 *     osdp_pd_pair_set_established_handler(&pair, on_paired, ctx);
 *     osdp_pd_set_sc2_crypto(&pd, &sc2_crypto);   // handoff target
 *     osdp_pd_set_sc2_cuid(&pd, my_cuid);
 *     osdp_pd_attach_pair(&pd, &pair);
 *
 * The PD must have its SC2 crypto vtable + cUID configured (the SCBK is what
 * pairing supplies). A PD with no pairing attached NAKs osdp_PAIR as an
 * unknown command, exactly as before. */

/* Invoked once Message 3 verifies and the SCBK is derived, before the
 * success Result is built. `peer` is the authenticated ACU identity; `scbk`
 * is the derived key. Return true to persist and accept (Result = success,
 * key applied to SC2); false to signal a persistence failure (Result =
 * PersistenceFailed, key discarded). May be NULL — then pairing always
 * accepts. Must not re-enter the PD API. */
typedef bool (*osdp_pd_pair_established_cb)(
    void                   *user,
    const osdp_pair_peer_t *peer,
    const uint8_t           scbk[OSDP_PAIR_SCBK_LEN]);

/* Caller-owned pairing state. Its first member is the dispatch hook pd.c
 * routes through; the rest is private. Allocate one (static / .bss) and bind
 * it with osdp_pd_attach_pair. */
typedef struct osdp_pd_pair {
    osdp_pd_pair_hook_t        hook;    /* MUST be first */

    osdp_pair_pd_session_t     session;

    /* Inbound fragment reassembly (Message 1, then Message 3). */
    osdp_mp_reasm_t          reasm;
    uint8_t                    inbuf[OSDP_PAIR_MSG_MAX];

    /* Outbound message held for fragmented delivery: Message 2 over POLLs, or
     * a single-fragment Result. */
    uint8_t                    outbuf[OSDP_PAIR_MSG_MAX];
    osdp_mp_frag_iter_t      out_iter;
    bool                       delivering;   /* Message 2 fragments pending */

    /* Deterministic handoff: SCBK staged during Msg3, applied post-send. */
    bool                       pending_apply;
    uint8_t                    scbk[OSDP_PAIR_SCBK_LEN];

    /* 30 s inactivity guard. */
    uint32_t                   last_activity_ms;
    bool                       active;

    osdp_pd_pair_established_cb cb;
    void                      *cb_user;

    /* Re-pairing policy; see osdp_pd_pair_set_deny_repair. Default false
     * (allow), which is what osdp_pd_pair_init's zeroing gives. */
    bool                       deny_repair;
} osdp_pd_pair_t;

/* Initialise pairing state with the PD's credential and the trust anchor
 * used to authenticate the ACU. The crypto HAL's `user` context holds the
 * PD's ML-DSA-44 signing key. */
void osdp_pd_pair_init(osdp_pd_pair_t           *pair,
                       const osdp_pair_crypto_t *crypto,
                       const osdp_pair_local_t  *local,
                       const osdp_pair_trust_t  *trust);

/* Bind the "pairing established" / persistence callback (optional). */
void osdp_pd_pair_set_established_handler(osdp_pd_pair_t             *pair,
                                          osdp_pd_pair_established_cb cb,
                                          void                      *user);

/* Refuse to pair again once this PD already holds an SC2 SCBK. A Message 1
 * arriving in that state is answered with a Result of
 * OSDP_PAIR_STATUS_POLICY (0x03) and the exchange goes no further; the
 * existing key is untouched.
 *
 * Default is ALLOW (deny = false), which is the permissive choice and is
 * deliberate: pairing is already gated by mutual certificate authentication,
 * so an attacker who can re-pair could have paired in the first place. Denial
 * protects against a *trusted* ACU displacing another trusted ACU's key,
 * which is a fleet-management concern rather than an attack, and it is the
 * kind of policy that should be switched on knowingly. Note that a PD which
 * denies re-pairing and has persisted a key cannot be re-provisioned over
 * OSDP at all — there is no unpair command in the protocol, so the key must
 * be cleared by some out-of-band means.
 *
 * The check needs a key to see: it keys off pd->sc2.scbk_set, so a PD that
 * derives an SCBK but does not persist it is pairable again after a reboot
 * whatever this is set to. */
void osdp_pd_pair_set_deny_repair(osdp_pd_pair_t *pair, bool deny);

/* Attach the pairing driver to a PD (sets pd->pair). Pass a PD that already
 * has its SC2 crypto + cUID configured so the handoff can complete. */
void osdp_pd_attach_pair(osdp_pd_t *pd, osdp_pd_pair_t *pair);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PD_PAIR_H */
