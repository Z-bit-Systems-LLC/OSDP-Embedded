// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Event queue — pending PD-initiated reports waiting for the next
//! POLL to surface them.
//!
//! OSDP is master-slave: a PD never spontaneously transmits. When a
//! real card-read happens at the reader, the PD stashes the data and
//! reports it on the next inbound POLL (as RAW instead of ACK).
//! Same shape for keypad presses (KEYPAD) and tamper/power changes
//! (LSTATR).
//!
//! `inject_*` tools enqueue pre-baked [`OverrideReply`] values; the
//! handler pops one per POLL after the override table misses, so an
//! agent can mix scripted replies with realistic events without
//! either stomping on the other.
//!
//! **Freshness.** A credential report is only meaningful right after
//! the card is presented. A real reader reports on the very next poll
//! (sub-second) or the read is gone — it never buffers a card-read for
//! minutes. If we let queued events live forever, an ACU that stopped
//! polling and reconnected later would receive a *stale* card-read and
//! could grant access for a credential presented minutes ago. So each
//! event carries its enqueue time and is discarded once it is older
//! than [`EVENT_TTL`]: delivered immediately while the link is actively
//! polled, otherwise dropped. The window matches `pd_actor`'s
//! "actively polling" definition (a command within ~2 s).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::overrides::OverrideReply;

/// How long a queued PD-initiated event stays deliverable. A POLL that
/// arrives later than this discards the event instead of surfacing it,
/// so a stale card-read can never be reported after a polling gap (e.g.
/// the ACU disconnecting and reconnecting). Kept in step with
/// `pd_actor::POLLING_WINDOW_MS` — an event is deliverable exactly while
/// the link still counts as actively polled.
pub const EVENT_TTL: Duration = Duration::from_millis(2_000);

/// A queued report plus the instant it was enqueued, so the queue can
/// drop it once it ages past [`EVENT_TTL`].
pub struct Pending {
    reply: OverrideReply,
    enqueued_at: Instant,
}

/// FIFO of pending PD-initiated reports. Drains one (still-fresh) entry
/// per POLL; stale entries are discarded rather than delivered.
pub type EventQueue = Arc<Mutex<VecDeque<Pending>>>;

pub fn new_queue() -> EventQueue {
    Arc::new(Mutex::new(VecDeque::new()))
}

pub fn enqueue(q: &EventQueue, e: OverrideReply) {
    q.lock().expect("event queue mutex").push_back(Pending {
        reply: e,
        enqueued_at: Instant::now(),
    });
}

/// Discard every entry at the front of the queue that has aged past
/// `ttl` as of `now`. FIFO order with a uniform TTL means once we reach
/// a fresh entry the rest are fresher still, so a front-scan suffices.
fn drop_stale(dq: &mut VecDeque<Pending>, now: Instant, ttl: Duration) {
    while let Some(front) = dq.front() {
        if now.saturating_duration_since(front.enqueued_at) > ttl {
            dq.pop_front();
        } else {
            break;
        }
    }
}

/// Pop the oldest still-fresh report. Called from the handler on POLL
/// after the override table has missed. Any entries that have aged past
/// [`EVENT_TTL`] are dropped first, so a card-read is reported promptly
/// or not at all.
pub fn pop(q: &EventQueue) -> Option<OverrideReply> {
    let mut dq = q.lock().expect("event queue mutex");
    drop_stale(&mut dq, Instant::now(), EVENT_TTL);
    dq.pop_front().map(|p| p.reply)
}

/// Number of still-deliverable events. Prunes aged entries first so the
/// depth reported by `pd_status` reflects what a POLL would actually
/// surface, not events that will be silently dropped.
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
        q.lock()
            .expect("event queue mutex")
            .push_back(Pending {
                reply: e,
                enqueued_at: at,
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
    fn stale_event_is_dropped_on_pop() {
        let q = new_queue();
        // A card-read that arrived well outside the freshness window —
        // e.g. queued while the ACU was disconnected.
        enqueue_aged(&q, r(0x50, b"stale"), EVENT_TTL + Duration::from_millis(500));
        // Nothing deliverable: the stale read is discarded, not surfaced.
        assert!(pop(&q).is_none());
        assert_eq!(len(&q), 0);
    }

    #[test]
    fn fresh_event_survives_a_stale_one_ahead_of_it() {
        let q = new_queue();
        enqueue_aged(&q, r(0x50, b"stale"), EVENT_TTL + Duration::from_millis(500));
        enqueue(&q, r(0x53, b"fresh"));
        // Depth counts only the fresh one.
        assert_eq!(len(&q), 1);
        // The stale head is dropped; the fresh report is delivered.
        let got = pop(&q).expect("fresh event");
        assert_eq!(got.code, 0x53);
        assert!(pop(&q).is_none());
    }

    #[test]
    fn just_fresh_event_is_kept() {
        let q = new_queue();
        // Comfortably inside the window — a normal inject-then-poll.
        enqueue_aged(&q, r(0x50, b"ok"), EVENT_TTL / 2);
        assert_eq!(len(&q), 1);
        assert_eq!(pop(&q).expect("fresh event").code, 0x50);
    }
}
