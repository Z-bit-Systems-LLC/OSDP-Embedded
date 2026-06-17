// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Event queue — pending PD-initiated reports waiting for the next
//! POLL to surface them.
//!
//! OSDP is master-slave: a PD never spontaneously transmits. When a
//! real card-read happens at the reader, the PD stashes the data and
//! reports it on the next inbound POLL (as RAW instead of ACK).
//! Same shape for keypad presses (KEYPAD) and for the device status
//! reports (LSTATR / ISTATR / OSTATR / RSTATR).
//!
//! `inject_*` tools enqueue pre-baked [`OverrideReply`] values; the
//! handler pops one per POLL after the override table misses, so an
//! agent can mix scripted replies with realistic events without
//! either stomping on the other.
//!
//! **Freshness.** Reports split into two kinds:
//!
//! - *Credential reads* (RAW card, KEYPAD entry) are momentary. A real
//!   reader reports them on the very next poll (sub-second) or the read
//!   is gone — it never buffers one for minutes. If we let them live
//!   forever, an ACU that stopped polling and reconnected later would
//!   receive a *stale* card-read and could grant access for a credential
//!   presented minutes ago. So they carry an enqueue time and are
//!   dropped once older than [`EVENT_TTL`].
//! - *Status reports* (osdp_LSTATR / ISTATR / OSTATR / RSTATR, spec
//!   §7.6–7.9) describe a monitored condition — tamper, power, input,
//!   output, reader-tamper — that persists until it next changes. The
//!   ACU must learn the current condition on its next POLL however
//!   delayed (e.g. a power-cycle report queued at boot, before the ACU
//!   starts polling). These are therefore **exempt** from the freshness
//!   window: delivered whenever the next POLL arrives, never dropped for
//!   age.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use osdp_embedded::messages::{
    OSDP_REPLY_ISTATR, OSDP_REPLY_LSTATR, OSDP_REPLY_OSTATR, OSDP_REPLY_RSTATR,
};

use crate::overrides::OverrideReply;

/// How long a *staleable* queued event (a credential read) stays
/// deliverable. A POLL that arrives later than this discards it instead
/// of surfacing it, so a stale card-read can never be reported after a
/// polling gap (e.g. the ACU disconnecting and reconnecting). Kept in
/// step with `pd_actor::POLLING_WINDOW_MS` — a read is deliverable
/// exactly while the link still counts as actively polled. Status
/// reports ignore this window entirely (see module docs).
pub const EVENT_TTL: Duration = Duration::from_millis(2_000);

/// True for PD status reports (osdp_LSTATR / ISTATR / OSTATR / RSTATR).
/// Per spec §7.6–7.9 these are "poll responses" announcing a change of a
/// monitored condition (tamper/power, inputs, outputs, reader tamper). A
/// status condition persists until it next changes, so — unlike a
/// momentary card-read or keypad entry — the ACU must still learn it on
/// the next POLL however delayed. Such events are exempt from the
/// freshness window.
fn is_status_report(code: u8) -> bool {
    matches!(
        code,
        OSDP_REPLY_LSTATR | OSDP_REPLY_ISTATR | OSDP_REPLY_OSTATR | OSDP_REPLY_RSTATR
    )
}

/// A queued report. Credential reads record their enqueue time so they
/// can be aged out; status reports are marked non-staleable and kept
/// until delivered.
pub struct Pending {
    reply: OverrideReply,
    enqueued_at: Instant,
    staleable: bool,
}

/// FIFO of pending PD-initiated reports. Drains one (still-deliverable)
/// entry per POLL; stale credential reads are discarded rather than
/// delivered, while status reports are kept regardless of age.
pub type EventQueue = Arc<Mutex<VecDeque<Pending>>>;

pub fn new_queue() -> EventQueue {
    Arc::new(Mutex::new(VecDeque::new()))
}

/// Enqueue a PD-initiated report. Whether it can go stale is decided
/// from its reply code: status reports (LSTATR / ISTATR / OSTATR /
/// RSTATR) never expire; everything else (RAW / KEYPAD) is subject to
/// [`EVENT_TTL`]. Callers don't choose — the classification is intrinsic
/// to the message, so any future status-report inject path inherits the
/// right behavior.
pub fn enqueue(q: &EventQueue, e: OverrideReply) {
    let staleable = !is_status_report(e.code);
    q.lock().expect("event queue mutex").push_back(Pending {
        reply: e,
        enqueued_at: Instant::now(),
        staleable,
    });
}

/// Discard every staleable entry that has aged past `ttl` as of `now`,
/// wherever it sits in the queue. Non-staleable status reports and
/// still-fresh reads are retained.
fn drop_stale(dq: &mut VecDeque<Pending>, now: Instant, ttl: Duration) {
    dq.retain(|p| !p.staleable || now.saturating_duration_since(p.enqueued_at) <= ttl);
}

/// Pop the oldest still-deliverable report. Called from the handler on
/// POLL after the override table has missed. Aged-out credential reads
/// are dropped first, so a card-read is reported promptly or not at all,
/// while a status report waits as long as it takes.
pub fn pop(q: &EventQueue) -> Option<OverrideReply> {
    let mut dq = q.lock().expect("event queue mutex");
    drop_stale(&mut dq, Instant::now(), EVENT_TTL);
    dq.pop_front().map(|p| p.reply)
}

/// Number of still-deliverable events. Prunes aged credential reads
/// first so the depth reported by `pd_status` reflects what a POLL would
/// actually surface, not reads that will be silently dropped.
pub fn len(q: &EventQueue) -> usize {
    let mut dq = q.lock().expect("event queue mutex");
    drop_stale(&mut dq, Instant::now(), EVENT_TTL);
    dq.len()
}

pub fn clear(q: &EventQueue) {
    q.lock().expect("event queue mutex").clear()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(code: u8, payload: &[u8]) -> OverrideReply {
        OverrideReply {
            code,
            payload: payload.to_vec(),
        }
    }

    /// Enqueue a report as if it had arrived `age` ago, for exercising
    /// the freshness window without sleeping.
    fn enqueue_aged(q: &EventQueue, e: OverrideReply, age: Duration) {
        let at = Instant::now()
            .checked_sub(age)
            .expect("test instant underflow");
        let staleable = !is_status_report(e.code);
        q.lock().expect("event queue mutex").push_back(Pending {
            reply: e,
            enqueued_at: at,
            staleable,
        });
    }

    #[test]
    fn fifo() {
        let q = new_queue();
        enqueue(&q, r(0x50, b"raw1"));
        enqueue(&q, r(0x53, b"kp"));
        assert_eq!(len(&q), 2);
        let a = pop(&q).unwrap();
        assert_eq!(a.code, 0x50);
        let b = pop(&q).unwrap();
        assert_eq!(b.code, 0x53);
        assert!(pop(&q).is_none());
        assert_eq!(len(&q), 0);
    }

    #[test]
    fn clear_drops_all() {
        let q = new_queue();
        enqueue(&q, r(0x50, &[]));
        enqueue(&q, r(0x53, &[]));
        clear(&q);
        assert!(pop(&q).is_none());
    }

    #[test]
    fn stale_card_read_is_dropped_on_pop() {
        let q = new_queue();
        // A card-read (RAW) that arrived well outside the freshness
        // window — e.g. queued while the ACU was disconnected.
        enqueue_aged(
            &q,
            r(0x50, b"stale"),
            EVENT_TTL + Duration::from_millis(500),
        );
        // Nothing deliverable: the stale read is discarded, not surfaced.
        assert!(pop(&q).is_none());
        assert_eq!(len(&q), 0);
    }

    #[test]
    fn fresh_card_read_survives_a_stale_one_ahead_of_it() {
        let q = new_queue();
        enqueue_aged(
            &q,
            r(0x50, b"stale"),
            EVENT_TTL + Duration::from_millis(500),
        );
        enqueue(&q, r(0x53, b"fresh"));
        // Depth counts only the fresh one.
        assert_eq!(len(&q), 1);
        // The stale head is dropped; the fresh report is delivered.
        let got = pop(&q).expect("fresh event");
        assert_eq!(got.code, 0x53);
        assert!(pop(&q).is_none());
    }

    #[test]
    fn status_reports_never_go_stale() {
        let q = new_queue();
        // LSTATR / ISTATR / OSTATR / RSTATR queued long ago (e.g. a
        // power-cycle report sitting from boot until the ACU first
        // polls) must all still be deliverable.
        let ancient = EVENT_TTL * 1000;
        enqueue_aged(&q, r(OSDP_REPLY_LSTATR, &[0, 1]), ancient);
        enqueue_aged(&q, r(OSDP_REPLY_ISTATR, &[0]), ancient);
        enqueue_aged(&q, r(OSDP_REPLY_OSTATR, &[0]), ancient);
        enqueue_aged(&q, r(OSDP_REPLY_RSTATR, &[0]), ancient);
        assert_eq!(len(&q), 4, "no status report should be aged out");
        assert_eq!(pop(&q).unwrap().code, OSDP_REPLY_LSTATR);
        assert_eq!(pop(&q).unwrap().code, OSDP_REPLY_ISTATR);
        assert_eq!(pop(&q).unwrap().code, OSDP_REPLY_OSTATR);
        assert_eq!(pop(&q).unwrap().code, OSDP_REPLY_RSTATR);
    }

    #[test]
    fn just_fresh_read_is_kept() {
        let q = new_queue();
        // Comfortably inside the window — a normal inject-then-poll.
        enqueue_aged(&q, r(0x50, b"ok"), EVENT_TTL / 2);
        assert_eq!(len(&q), 1);
        assert_eq!(pop(&q).expect("fresh event").code, 0x50);
    }
}
